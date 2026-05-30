"""
Continuous droidot repair loop runner.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

from loguru import logger


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src import vars as global_vars
from src.droidot.runner import DroidotBaselineRunner, load_profile
from src.llm.llm import CodexProcessClient


def _default_codex_args() -> list[str]:
    return [
        "exec",
        "--model",
        "{MODEL}",
        "--sandbox",
        "{SANDBOX_MODE}",
        "--output-schema",
        "{SCHEMA_JSON}",
        "-o",
        "{RESULT_TXT}",
        "-",
    ]


def _build_codex_client(args: argparse.Namespace) -> CodexProcessClient:
    work_root = Path(args.codex_work_root)
    if not work_root.is_absolute():
        work_root = REPO_ROOT / work_root
    return CodexProcessClient(
        executable=args.codex_executable,
        args=_default_codex_args(),
        model=args.model,
        work_root=str(work_root),
        timeout=args.codex_timeout,
        retry_times=args.codex_retry_times,
        sandbox_mode=args.codex_sandbox_mode,
        approval_mode=args.codex_approval_mode,
        verbosity=args.codex_verbosity,
        reasoning_effort=args.codex_reasoning_effort,
        capture_stdout=True,
        keep_task_dirs=True,
    )


def _append_jsonl(path: Path, payload: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, ensure_ascii=True) + "\n")


def _is_retryable_remote_error(exc: BaseException) -> bool:
    if isinstance(exc, subprocess.CalledProcessError):
        stderr = exc.stderr
        if isinstance(stderr, bytes):
            stderr_text = stderr.decode("utf-8", errors="replace")
        else:
            stderr_text = str(stderr or "")
        stdout = exc.output
        if isinstance(stdout, bytes):
            stdout_text = stdout.decode("utf-8", errors="replace")
        else:
            stdout_text = str(stdout or "")
        combined = f"{stdout_text}\n{stderr_text}".lower()
        return exc.returncode == 255 or "connection timed out" in combined or "ssh:" in combined
    return False


def _failure_record(
    round_idx: int,
    elapsed_seconds: float,
    exc: BaseException,
    *,
    phase: str,
) -> dict:
    stderr_text = ""
    stdout_text = ""
    returncode = None
    if isinstance(exc, subprocess.CalledProcessError):
        returncode = exc.returncode
        if isinstance(exc.stderr, bytes):
            stderr_text = exc.stderr.decode("utf-8", errors="replace")
        else:
            stderr_text = str(exc.stderr or "")
        if isinstance(exc.output, bytes):
            stdout_text = exc.output.decode("utf-8", errors="replace")
        else:
            stdout_text = str(exc.output or "")
    return {
        "round": round_idx,
        "elapsed_seconds": elapsed_seconds,
        "status": "remote_retryable_failure",
        "phase": phase,
        "error_type": type(exc).__name__,
        "returncode": returncode,
        "error": str(exc),
        "stderr": stderr_text,
        "stdout": stdout_text,
    }


def _find_latest_pending_local_attempt(session_dir: Path) -> Path | None:
    repairs_root = session_dir / "repair_attempts"
    if not repairs_root.is_dir():
        return None
    attempt_dirs = sorted(repairs_root.glob("attempt_*"))
    for attempt_dir in reversed(attempt_dirs):
        result_path = attempt_dir / "repair.result.json"
        if not result_path.is_file():
            continue
        try:
            result = json.loads(result_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if result.get("status") == "proposed_local_patch":
            return attempt_dir
    return None


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True)
    parser.add_argument("--input", required=True)
    parser.add_argument("--session-name", default="")
    parser.add_argument("--rounds", type=int, default=-1)
    parser.add_argument("--sleep-seconds", type=float, default=2.0)
    parser.add_argument("--stop-on-verified", action="store_true")
    parser.add_argument("--remote-sync-interval-seconds", type=float, default=900.0)
    parser.add_argument("--refresh-remote-cache", action="store_true")
    parser.add_argument("--model", default="gpt-5.3-codex")
    parser.add_argument("--codex-executable", default="codex")
    parser.add_argument("--codex-work-root", default="logs/codex_tasks")
    parser.add_argument("--codex-timeout", type=int, default=120)
    parser.add_argument("--codex-retry-times", type=int, default=3)
    parser.add_argument("--codex-sandbox-mode", default="workspace-write")
    parser.add_argument("--codex-approval-mode", default="never")
    parser.add_argument("--codex-verbosity", default="medium")
    parser.add_argument("--codex-reasoning-effort", default="medium")
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()
    global_vars.promefuzz_path = REPO_ROOT
    global_vars.library_language = global_vars.SupportedLanguages.CPP

    profile_path = Path(args.profile)
    if not profile_path.is_absolute():
        profile_path = (REPO_ROOT / profile_path).resolve(strict=False)
    input_path = Path(args.input)
    if not input_path.is_absolute():
        input_path = (REPO_ROOT / input_path).resolve(strict=False)

    profile = load_profile(profile_path)
    runner = DroidotBaselineRunner(profile)
    llm_client = _build_codex_client(args)

    session_name = args.session_name or f"{profile.name}_repair_loop"
    session_dir = runner._local_session_dir(session_name)
    session_dir.mkdir(parents=True, exist_ok=True)
    loop_log_path = session_dir / "repair_loop.history.jsonl"
    last_remote_sync_started_at = time.time()

    round_idx = 0
    try:
        while args.rounds < 0 or round_idx < args.rounds:
            round_idx += 1
            logger.info(
                "droidot repair loop round={} profile={} session={}",
                round_idx,
                profile.name,
                session_name,
            )
            started_at = time.time()
            pending_attempt_dir = _find_latest_pending_local_attempt(session_dir)
            now = time.time()
            sync_due = (
                pending_attempt_dir is not None
                and now - last_remote_sync_started_at >= max(args.remote_sync_interval_seconds, 0.0)
            )
            try:
                if pending_attempt_dir is not None and not sync_due:
                    wait_seconds = max(
                        args.remote_sync_interval_seconds - (now - last_remote_sync_started_at),
                        0.0,
                    )
                    result = {
                        "status": "waiting_remote_sync",
                        "attempt_dir": str(pending_attempt_dir),
                        "patched_target_file": "",
                        "repair_scope": {},
                        "repair_decision": {},
                        "wait_seconds": wait_seconds,
                    }
                elif pending_attempt_dir is not None and sync_due:
                    last_remote_sync_started_at = time.time()
                    result = runner.verify_repair_attempt(
                        session_name,
                        pending_attempt_dir,
                        input_path,
                    )
                else:
                    result = runner.repair_input_local_only(
                        session_name,
                        input_path,
                        llm_client,
                        refresh_remote_cache=args.refresh_remote_cache and round_idx == 1,
                    )
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                elapsed = time.time() - started_at
                if _is_retryable_remote_error(exc):
                    failure = _failure_record(
                        round_idx,
                        elapsed,
                        exc,
                        phase="remote_sync" if pending_attempt_dir is not None else "local_prepare",
                    )
                    _append_jsonl(loop_log_path, failure)
                    logger.warning(
                        "droidot repair loop round={} hit retryable remote failure; "
                        "sleeping {}s before retry.\n{}",
                        round_idx,
                        max(args.sleep_seconds, 0.0),
                        failure["error"],
                    )
                    if args.rounds < 0 or round_idx < args.rounds:
                        time.sleep(max(args.sleep_seconds, 0.0))
                        continue
                    break
                raise
            elapsed = time.time() - started_at
            loop_record = {
                "round": round_idx,
                "elapsed_seconds": elapsed,
                "status": result.get("status", ""),
                "attempt_dir": result.get("attempt_dir", ""),
                "patched_target_file": result.get("patched_target_file", ""),
                "repair_scope": result.get("repair_scope", {}),
                "repair_decision": result.get("repair_decision", {}),
            }
            if "wait_seconds" in result:
                loop_record["wait_seconds"] = result["wait_seconds"]
            _append_jsonl(loop_log_path, loop_record)
            if result.get("status") == "proposed_local_patch":
                last_remote_sync_started_at = time.time()
            logger.info(
                "droidot repair loop round={} status={} patched_target_file={}",
                round_idx,
                result.get("status", ""),
                result.get("patched_target_file", ""),
            )
            if args.stop_on_verified and result.get("verified"):
                logger.success("repair loop stopping because a verified patch was produced")
                break
            if args.rounds < 0 or round_idx < args.rounds:
                time.sleep(max(args.sleep_seconds, 0.0))
    except KeyboardInterrupt:
        logger.warning("droidot repair loop interrupted by user")
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
