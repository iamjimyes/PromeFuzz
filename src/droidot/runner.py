"""
Droidot JNI baseline runner.
"""

from __future__ import annotations

import io
import json
import re
import shlex
import subprocess
import tarfile
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from loguru import logger

from src.analyzer.fallback import CrashLogClassifier


def _now_utc() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _json_default(value: Any):
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"Object of type {type(value)!r} is not JSON serializable")


def _ensure_parent(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)


def _sanitize_windows_tar_part(part: str) -> str:
    return re.sub(r'[<>:"/\\\\|?*]', "_", part)


def _safe_extract_tar_windows(archive: tarfile.TarFile, destination: Path):
    destination = destination.resolve()
    for member in archive.getmembers():
        safe_parts = [_sanitize_windows_tar_part(part) for part in Path(member.name).parts]
        safe_parts = [part for part in safe_parts if part not in {"", ".", ".."}]
        if not safe_parts:
            continue
        target_path = destination.joinpath(*safe_parts)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        if member.isdir():
            target_path.mkdir(parents=True, exist_ok=True)
            continue
        source = archive.extractfile(member)
        if source is None:
            continue
        with source, target_path.open("wb") as fh:
            fh.write(source.read())


@dataclass(slots=True)
class DroidotProfile:
    name: str
    ssh_target: str
    container_name: str
    device_serial: str
    host_work_root: str
    container_work_root: str
    host_harness_dir: str
    host_libharness_path: str
    host_app_root: str
    host_afl_dir: str
    device_runtime_root: str
    device_app_root: str
    target_library_basename: str
    class0: str
    afl_binary_path: str
    afl_showmap_path: str = ""
    seconds: int = 35
    cmplog: bool = True
    afl_timeout_ms: int = 5000
    forkserver_init_timeout_ms: int = 90000
    results_dir_name: str = "output_fg"
    harness_binary_name: str = "harness"
    seed_subdir: str = "seeds"
    synthetic_seed_name: str = "seed-empty"
    remote_compile_dir: str = "/data/local/tmp/fuzzing_compile"
    androlib_memory_name: str = "memory"
    afl_preload_paths: list[str] = field(default_factory=list)
    extra_env: dict[str, str] = field(default_factory=dict)
    droidot_allow_null_caller: bool = False
    droidot_skip_target_call: bool = False
    droidot_mask_target_crash: bool = False
    droidot_class_apk: str = ""
    host_frida_script: str = ""
    host_seed_dir: str = ""
    host_runtime_libcpp_path: str = ""
    local_results_root: str = "android_runs/promefuzz-bigemu"

    @property
    def host_harness_path(self) -> Path:
        return Path(self.host_harness_dir)

    @property
    def host_seed_path(self) -> Path | None:
        if not self.host_seed_dir:
            return None
        return Path(self.host_seed_dir)

    @property
    def host_libharness(self) -> Path:
        return Path(self.host_libharness_path)

    @property
    def host_app_path(self) -> Path:
        return Path(self.host_app_root)

    @property
    def host_afl_path(self) -> Path:
        return Path(self.host_afl_dir)

    @property
    def host_runtime_libcpp(self) -> Path | None:
        if not self.host_runtime_libcpp_path:
            return None
        return Path(self.host_runtime_libcpp_path)

    @property
    def device_target_library(self) -> str:
        return f"{self.device_app_root}/lib/arm64-v8a/{self.target_library_basename}"

    @property
    def device_app_lib_dir(self) -> str:
        return f"{self.device_app_root}/lib/arm64-v8a"

    @property
    def local_results_path(self) -> Path:
        return Path(self.local_results_root) / self.name

    def container_path_for_host(self, host_path: str | Path) -> str:
        host_path = Path(host_path)
        work_root = Path(self.host_work_root)
        try:
            relative = host_path.relative_to(work_root)
        except ValueError as exc:
            raise ValueError(
                f"{host_path} is outside the declared host_work_root {work_root}"
            ) from exc
        return str(Path(self.container_work_root) / relative).replace("\\", "/")


def load_profile(profile_path: Path) -> DroidotProfile:
    data = json.loads(profile_path.read_text(encoding="utf-8"))
    profile = DroidotProfile(**data)
    if not profile.afl_preload_paths:
        profile.afl_preload_paths = [
            "/data/data/com.termux/files/usr/lib/libc++_shared.so",
            f"{profile.device_app_lib_dir}/libc++_shared.so",
        ]
    return profile


class DroidotBaselineRunner:
    """
    Minimal runner for the droidot JNI baseline.
    """

    def __init__(self, profile: DroidotProfile):
        self.profile = profile
        self.repo_root = Path(__file__).resolve().parents[2]
        self._last_prepare_checks: dict[str, Any] | None = None
        self._ssh_base_command = [
            "ssh",
            "-o",
            "ConnectTimeout=15",
            "-o",
            "ServerAliveInterval=15",
            "-o",
            "ServerAliveCountMax=3",
            self.profile.ssh_target,
        ]

    def prepare_existing(self) -> dict[str, Any]:
        checks = self._collect_prepare_checks()
        all_ok = all(item["exists"] for item in checks.values())
        if not all_ok:
            missing = [name for name, item in checks.items() if not item["exists"]]
            raise RuntimeError(
                "prepare-existing failed; missing required inputs: " + ", ".join(missing)
            )
        result = {
            "status": "ready",
            "prepared_at": _now_utc(),
            "checks": checks,
        }
        self._last_prepare_checks = checks
        logger.success("droidot baseline prepare-existing checks passed")
        return result

    def prepare_build(self, debug_build: bool = False) -> dict[str, Any]:
        harness_parent = str(Path(self.profile.host_harness_dir).parent).replace("\\", "/")
        harness_folder = Path(self.profile.host_harness_dir).name
        remote_compile_dir = (
            f"{self.profile.remote_compile_dir.rstrip('/')}/{self.profile.name}"
        )
        debug_value = "True" if debug_build else "False"
        inline = f"""
from harness.compile_harness import init_compilation, compile_harness
remote_folder = {remote_compile_dir!r}
device_id = {self.profile.device_serial!r}
harness_parent = {harness_parent!r}
harness_folder = {harness_folder!r}
init_compilation(remote_folder, debug={debug_value}, path="harness", device_id=device_id)
compile_harness(
    harness_folder,
    harness_parent,
    remote_folder,
    debug={debug_value},
    device_id=device_id,
)
"""
        command = (
            f"cd {shlex.quote(self.profile.host_work_root)} && "
            f"python3 - <<'PY'\n{inline}\nPY"
        )
        result = self._run_remote(command, check=True)
        logger.success("droidot remote compile completed")
        return {
            "status": "built",
            "prepared_at": _now_utc(),
            "stdout": result.stdout,
            "stderr": result.stderr,
            "remote_compile_dir": remote_compile_dir,
        }

    def run_session(
        self,
        session_name: str,
        seconds: int | None = None,
        cmplog: bool | None = None,
        pull_back: bool = True,
        max_replays: int = 10,
    ) -> dict[str, Any]:
        local_session_dir = self._local_session_dir(session_name)
        local_session_dir.mkdir(parents=True, exist_ok=True)
        self._write_json(
            local_session_dir / "profile.snapshot.json",
            asdict(self.profile),
        )

        device_session_root = self._stage_session(session_name)
        seconds = seconds if seconds is not None else self.profile.seconds
        cmplog = self.profile.cmplog if cmplog is None else cmplog
        run_command = self._render_run_command(device_session_root, seconds, cmplog)
        stdout_path = local_session_dir / "run.stdout.log"
        stderr_path = local_session_dir / "run.stderr.log"
        result = self._run_device_root_command(
            run_command,
            capture_output=True,
            allow_timeout=True,
        )
        stdout_path.write_text(result.stdout, encoding="utf-8", errors="replace")
        stderr_path.write_text(result.stderr, encoding="utf-8", errors="replace")

        record: dict[str, Any] = {
            "profile_name": self.profile.name,
            "session_name": session_name,
            "started_at": _now_utc(),
            "device_session_root": device_session_root,
            "local_session_dir": str(local_session_dir),
            "duration_seconds": seconds,
            "cmplog": cmplog,
            "returncode": result.returncode,
            "run_command": run_command,
        }
        if pull_back:
            record["pullback"] = self.pull_and_normalize(
                session_name=session_name,
                max_replays=max_replays,
            )
        self._write_json(local_session_dir / "run_record.json", record)
        return record

    def pull_and_normalize(
        self,
        session_name: str,
        max_replays: int = 10,
    ) -> dict[str, Any]:
        local_session_dir = self._local_session_dir(session_name)
        local_session_dir.mkdir(parents=True, exist_ok=True)
        device_session_root = self._device_session_root(session_name)
        raw_dir = local_session_dir / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)

        tar_path = raw_dir / "output_fg.tar"
        self._pull_results_tar(device_session_root, tar_path)
        extracted_root = raw_dir / self.profile.results_dir_name
        if extracted_root.exists():
            self._remove_tree(extracted_root)
        extracted_root.mkdir(parents=True, exist_ok=True)
        with tarfile.open(tar_path, "r") as archive:
            _safe_extract_tar_windows(archive, raw_dir)

        normalized_dir = local_session_dir / "normalized_crashes"
        if normalized_dir.exists():
            self._remove_tree(normalized_dir)
        normalized_dir.mkdir(parents=True, exist_ok=True)

        crash_dir = raw_dir / self.profile.results_dir_name / "default" / "crashes"
        crash_files = []
        if crash_dir.exists():
            crash_files = [
                path
                for path in sorted(crash_dir.iterdir())
                if path.is_file() and not path.name.startswith("README")
            ]

        replayed = []
        for idx, crash_file in enumerate(crash_files):
            input_path = normalized_dir / f"{idx}.input"
            input_path.write_bytes(crash_file.read_bytes())
            log_path = normalized_dir / f"{idx}.log"
            if idx < max_replays:
                replay = self._replay_crash(
                    device_session_root=device_session_root,
                    crash_file=crash_file.name,
                )
                log_path.write_text(replay, encoding="utf-8", errors="replace")
                replayed.append({"index": idx, "crash_file": crash_file.name})
            else:
                log_path.write_text(
                    "Replay skipped because max_replays was reached.\n",
                    encoding="utf-8",
                )

        triage = self.triage_local_session(local_session_dir)
        result = {
            "pulled_at": _now_utc(),
            "device_session_root": device_session_root,
            "local_session_dir": str(local_session_dir),
            "crash_count": len(crash_files),
            "replayed": replayed,
            "triage_summary_path": str(local_session_dir / "triage" / "summary.json"),
            "triage": triage,
        }
        self._write_json(local_session_dir / "pull_record.json", result)
        return result

    @staticmethod
    def triage_local_session(session_dir: Path) -> dict[str, Any]:
        normalized_dir = session_dir / "normalized_crashes"
        triage_dir = session_dir / "triage"
        triage_dir.mkdir(parents=True, exist_ok=True)

        entries = []
        counts = {
            "target-crash": 0,
            "setup-failure": 0,
            "unknown": 0,
        }
        classifier = CrashLogClassifier()
        for log_path in sorted(normalized_dir.glob("*.log")):
            text = log_path.read_text(encoding="utf-8", errors="replace")
            if not text.strip():
                summary = {
                    "file": log_path.name,
                    "kind": "unknown",
                    "signature": "empty-log@unknown",
                    "summary": "No replay log was collected.",
                }
            else:
                summary = classifier.classify(text)
                summary["file"] = log_path.name
            counts[summary["kind"]] = counts.get(summary["kind"], 0) + 1
            entries.append(summary)

        summary = {
            "generated_at": _now_utc(),
            "session_dir": str(session_dir),
            "counts": counts,
            "entries": entries,
        }
        (triage_dir / "summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        lines = [
            "# Droidot JNI Triage",
            "",
            f"- Session: `{session_dir}`",
            f"- Generated at: `{summary['generated_at']}`",
            f"- Target crashes: `{counts['target-crash']}`",
            f"- Setup failures: `{counts['setup-failure']}`",
            f"- Unknown: `{counts['unknown']}`",
            "",
        ]
        for entry in entries:
            lines.extend(
                [
                    f"## {entry['file']}",
                    "",
                    f"- Kind: `{entry['kind']}`",
                    f"- Signature: `{entry['signature']}`",
                    f"- Summary: {entry['summary']}",
                    "",
                ]
            )
        (triage_dir / "summary.md").write_text("\n".join(lines), encoding="utf-8")
        return summary

    def _stage_session(self, session_name: str) -> str:
        if self._last_prepare_checks is None:
            self.prepare_existing()
        device_session_root = self._device_session_root(session_name)
        container_harness_dir = self.profile.container_path_for_host(
            self.profile.host_harness_dir
        )
        container_libharness_path = self.profile.container_path_for_host(
            self.profile.host_libharness_path
        )
        container_app_root = self.profile.container_path_for_host(
            self.profile.host_app_root
        )
        container_afl_root = self.profile.container_path_for_host(
            self.profile.host_afl_dir
        )
        container_base_apk = container_app_root + "/base.apk"
        container_lib_dir = container_app_root + "/lib/arm64-v8a"
        runtime_libcpp_host = (
            self.profile.host_runtime_libcpp_path
            or f"{self.profile.host_app_root}/lib/arm64-v8a/libc++_shared.so"
        )
        container_runtime_libcpp = self.profile.container_path_for_host(runtime_libcpp_host)
        device_afl_dir = str(Path(self.profile.afl_binary_path).parent).replace("\\", "/")
        compat_termux_lib_dir = "/data/data/com.termux/files/usr/lib"
        initial_device_setup = (
            f"rm -rf {shlex.quote(device_session_root)} && "
            f"mkdir -p {shlex.quote(device_session_root)} "
            f"{shlex.quote(self.profile.device_app_root + '/lib')} "
            f"{shlex.quote(compat_termux_lib_dir)} "
            f"{shlex.quote(device_afl_dir)}"
        )
        script_lines = [
            "set -e",
            self._render_container_adb_shell_root(initial_device_setup),
            (
                f"docker exec -i {shlex.quote(self.profile.container_name)} "
                f"adb -s {shlex.quote(self.profile.device_serial)} push "
                f"{shlex.quote(container_base_apk)} "
                f"{shlex.quote(self.profile.device_app_root + '/base.apk')}"
            ),
            (
                f"docker exec -i {shlex.quote(self.profile.container_name)} "
                f"adb -s {shlex.quote(self.profile.device_serial)} push "
                f"{shlex.quote(container_lib_dir)} "
                f"{shlex.quote(self.profile.device_app_root + '/lib/')}"
            ),
            (
                f"docker exec -i {shlex.quote(self.profile.container_name)} "
                f"adb -s {shlex.quote(self.profile.device_serial)} push "
                f"{shlex.quote(container_afl_root + '/afl-fuzz')} "
                f"{shlex.quote(self.profile.afl_binary_path)}"
            ),
            (
                f"docker exec -i {shlex.quote(self.profile.container_name)} "
                f"adb -s {shlex.quote(self.profile.device_serial)} push "
                f"{shlex.quote(container_afl_root + '/afl-frida-trace.so')} "
                f"{shlex.quote(device_afl_dir + '/afl-frida-trace.so')}"
            ),
            (
                f"docker exec -i {shlex.quote(self.profile.container_name)} "
                f"adb -s {shlex.quote(self.profile.device_serial)} push "
                f"{shlex.quote(container_harness_dir + '/' + self.profile.harness_binary_name)} "
                f"{shlex.quote(device_session_root + '/' + self.profile.harness_binary_name)}"
            ),
            (
                f"docker exec -i {shlex.quote(self.profile.container_name)} "
                f"adb -s {shlex.quote(self.profile.device_serial)} push "
                f"{shlex.quote(container_libharness_path)} "
                f"{shlex.quote(device_session_root + '/libharness.so')}"
            ),
            (
                f"docker exec -i {shlex.quote(self.profile.container_name)} "
                f"adb -s {shlex.quote(self.profile.device_serial)} push "
                f"{shlex.quote(container_runtime_libcpp)} "
                f"{shlex.quote(device_session_root + '/libc++_shared.so')}"
            ),
            (
                f"docker exec -i {shlex.quote(self.profile.container_name)} "
                f"adb -s {shlex.quote(self.profile.device_serial)} push "
                f"{shlex.quote(container_runtime_libcpp)} "
                f"{shlex.quote(compat_termux_lib_dir + '/libc++_shared.so')}"
            ),
        ]
        if self.profile.afl_showmap_path:
            script_lines.append(
                f"docker exec -i {shlex.quote(self.profile.container_name)} "
                f"adb -s {shlex.quote(self.profile.device_serial)} push "
                f"{shlex.quote(container_afl_root + '/afl-showmap')} "
                f"{shlex.quote(self.profile.afl_showmap_path)}"
            )
        seed_dir = self.profile.host_seed_dir
        if (
            seed_dir
            and self._last_prepare_checks
            and self._last_prepare_checks.get("host_seed_dir", {}).get("exists", False)
        ):
            container_seed_dir = self.profile.container_path_for_host(seed_dir)
            script_lines.append(
                f"docker exec -i {shlex.quote(self.profile.container_name)} "
                f"adb -s {shlex.quote(self.profile.device_serial)} push "
                f"{shlex.quote(container_seed_dir)} "
                f"{shlex.quote(device_session_root + '/seeds')}"
            )
        else:
            synthetic_seed_setup = (
                f"mkdir -p {shlex.quote(device_session_root + '/seeds')} && "
                f": > {shlex.quote(device_session_root + '/seeds/' + self.profile.synthetic_seed_name)}"
            )
            script_lines.append(
                self._render_container_adb_shell_root(synthetic_seed_setup)
            )
        if self.profile.host_frida_script:
            container_frida_script = self.profile.container_path_for_host(
                self.profile.host_frida_script
            )
            script_lines.append(
                f"docker exec -i {shlex.quote(self.profile.container_name)} "
                f"adb -s {shlex.quote(self.profile.device_serial)} push "
                f"{shlex.quote(container_frida_script)} "
                f"{shlex.quote(device_session_root + '/afl.js')}"
            )
        chmod_targets = [
            shlex.quote(device_session_root + '/' + self.profile.harness_binary_name),
            shlex.quote(device_session_root + '/libharness.so'),
            shlex.quote(device_session_root + '/libc++_shared.so'),
            shlex.quote(compat_termux_lib_dir + '/libc++_shared.so'),
            shlex.quote(self.profile.afl_binary_path),
            shlex.quote(device_afl_dir + '/afl-frida-trace.so'),
        ]
        if self.profile.afl_showmap_path:
            chmod_targets.append(shlex.quote(self.profile.afl_showmap_path))
        script_lines.append(
            self._render_container_adb_shell_root(
                "chmod 755 " + " ".join(chmod_targets)
            )
        )
        self._run_remote("\n".join(script_lines), check=True, capture_output=True)
        return device_session_root

    def _render_run_command(
        self,
        device_session_root: str,
        seconds: int,
        cmplog: bool,
    ) -> str:
        device_afl_dir = str(Path(self.profile.afl_binary_path).parent).replace("\\", "/")
        env_map = {
            "PATH": (
                "/data/data/com.termux/files/usr/bin:/system/bin:/system/xbin:"
                "/vendor/bin:/apex/com.android.runtime/bin"
            ),
            "AFL_PRELOAD": " ".join(self.profile.afl_preload_paths),
            "LD_LIBRARY_PATH": (
                f"/apex/com.android.art/lib64:/system/lib64:{device_session_root}:"
                f"/data/data/com.termux/files/usr/lib:{self.profile.device_app_lib_dir}:"
                f"{device_afl_dir}"
            ),
            "AFL_FORKSRV_INIT_TMOUT": str(self.profile.forkserver_init_timeout_ms),
            "AFL_NO_AFFINITY": "1",
            "AFL_SKIP_CPUFREQ": "1",
            "AFL_DEBUG": "1",
            "AFL_DEBUG_CHILD": "1",
            "ANDROLIB_APP_PATH": self.profile.device_app_root,
            "ANDROLIB_TARGET_LIBRARY": self.profile.device_target_library,
            "ANDROLIB_CLASS0": self.profile.class0,
            "ANDROLIB_MEMORY": self.profile.androlib_memory_name,
            "AFL_SKIP_CPUFREQ": "1",
            "DROIDOT_ALLOW_NULL_CALLER": "1"
            if self.profile.droidot_allow_null_caller
            else "0",
            "DROIDOT_SKIP_TARGET_CALL": "1"
            if self.profile.droidot_skip_target_call
            else "0",
            "DROIDOT_MASK_TARGET_CRASH": "1"
            if self.profile.droidot_mask_target_crash
            else "0",
        }
        if self.profile.host_frida_script:
            env_map["AFL_FRIDA_JS_SCRIPT"] = f"{device_session_root}/afl.js"
        if self.profile.droidot_class_apk:
            env_map["DROIDOT_CLASS_APK"] = self.profile.droidot_class_apk
        env_map.update(self.profile.extra_env)
        exports = " ".join(
            f"export {key}={shlex.quote(value)};" for key, value in env_map.items()
        )
        cmplog_args = "-c 0 " if cmplog else ""
        timeout_bin = "/system/bin/timeout"
        run_line = (
            f"{timeout_bin} {seconds} {self.profile.afl_binary_path} -O {cmplog_args}"
            f"-t {self.profile.afl_timeout_ms} -i seeds -o {self.profile.results_dir_name} "
            f"./{self.profile.harness_binary_name}"
        )
        root_cmd = (
            f"cd {shlex.quote(device_session_root)} && "
            f"rm -rf {shlex.quote(self.profile.results_dir_name)} && "
            f"mkdir {shlex.quote(self.profile.results_dir_name)} && "
            f"{exports} {run_line}"
        )
        return root_cmd

    def _replay_crash(self, device_session_root: str, crash_file: str) -> str:
        device_afl_dir = str(Path(self.profile.afl_binary_path).parent).replace("\\", "/")
        env_map = {
            "PATH": (
                "/data/data/com.termux/files/usr/bin:/system/bin:/system/xbin:"
                "/vendor/bin:/apex/com.android.runtime/bin"
            ),
            "AFL_PRELOAD": " ".join(self.profile.afl_preload_paths),
            "LD_LIBRARY_PATH": (
                f"/apex/com.android.art/lib64:/system/lib64:{device_session_root}:"
                f"/data/data/com.termux/files/usr/lib:{self.profile.device_app_lib_dir}:"
                f"{device_afl_dir}"
            ),
            "ANDROLIB_APP_PATH": self.profile.device_app_root,
            "ANDROLIB_TARGET_LIBRARY": self.profile.device_target_library,
            "ANDROLIB_CLASS0": self.profile.class0,
            "ANDROLIB_MEMORY": self.profile.androlib_memory_name,
            "DROIDOT_ALLOW_NULL_CALLER": "1"
            if self.profile.droidot_allow_null_caller
            else "0",
            "DROIDOT_SKIP_TARGET_CALL": "1"
            if self.profile.droidot_skip_target_call
            else "0",
            "DROIDOT_MASK_TARGET_CRASH": "1"
            if self.profile.droidot_mask_target_crash
            else "0",
        }
        if self.profile.host_frida_script:
            env_map["AFL_FRIDA_JS_SCRIPT"] = f"{device_session_root}/afl.js"
        if self.profile.droidot_class_apk:
            env_map["DROIDOT_CLASS_APK"] = self.profile.droidot_class_apk
        env_map.update(self.profile.extra_env)
        exports = " ".join(
            f"export {key}={shlex.quote(value)};" for key, value in env_map.items()
        )
        timeout_bin = "/system/bin/timeout"
        crash_device_path = (
            f"{device_session_root}/{self.profile.results_dir_name}/default/crashes/{crash_file}"
        )
        replay_driver = self.profile.afl_showmap_path or self.profile.afl_binary_path
        replay_cmd = (
            f"cd {shlex.quote(device_session_root)} && "
            f"{exports} {timeout_bin} 20 {shlex.quote(replay_driver)} -O -o /dev/null -- "
            f"./{self.profile.harness_binary_name} < {shlex.quote(crash_device_path)}"
        )
        result = self._run_device_root_command(
            replay_cmd,
            capture_output=True,
            allow_timeout=True,
        )
        return (
            f"[replay-returncode] {result.returncode}\n"
            f"[command] {replay_cmd}\n\n"
            f"{result.stdout}\n{result.stderr}"
        ).strip()

    def _pull_results_tar(self, device_session_root: str, tar_path: Path):
        remote_script = (
            f"docker exec -i {shlex.quote(self.profile.container_name)} "
            f"adb -s {shlex.quote(self.profile.device_serial)} exec-out "
            f"sh -c {shlex.quote(f'cd {device_session_root} && tar -cf - {self.profile.results_dir_name}')}"
        )
        _ensure_parent(tar_path)
        self._run_remote_to_file(remote_script, tar_path)

    def _check_remote_path(self, path: str, kind: str) -> dict[str, Any]:
        return self._collect_remote_exists_map(
            {"requested": {"path": path, "kind": kind}}
        )["requested"]

    def _check_device_path(self, path: str, kind: str) -> dict[str, Any]:
        flag = "-d" if kind == "dir" else "-f"
        command = f"if [ {flag} {shlex.quote(path)} ]; then printf 'exists'; else printf 'missing'; fi"
        result = self._run_device_root_command(command, capture_output=True)
        return {
            "path": path,
            "kind": kind,
            "exists": result.stdout.strip() == "exists",
        }

    def _run_remote(
        self,
        script: str,
        *,
        check: bool,
        capture_output: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        logger.debug(f"[remote] {script}")
        command = self._ssh_base_command + [f"bash -lc {shlex.quote(script)}"]
        last_result: subprocess.CompletedProcess[str] | None = None
        for attempt in range(1, 6):
            result = subprocess.run(
                command,
                cwd=self.repo_root,
                check=False,
                capture_output=capture_output,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            last_result = result
            if result.returncode == 0:
                return result
            should_retry = result.returncode == 255 and attempt < 5
            if should_retry:
                logger.warning(
                    "remote command failed with ssh rc=255 on attempt "
                    f"{attempt}/5; retrying.\nSTDERR:\n{result.stderr}"
                )
                time.sleep(min(2 * attempt, 8))
                continue
            if check:
                raise subprocess.CalledProcessError(
                    result.returncode,
                    command,
                    output=result.stdout,
                    stderr=result.stderr,
                )
            return result
        assert last_result is not None
        if check:
            raise subprocess.CalledProcessError(
                last_result.returncode,
                command,
                output=last_result.stdout,
                stderr=last_result.stderr,
            )
        return last_result

    def _run_remote_to_file(self, script: str, output_path: Path):
        logger.debug(f"[remote-stream] {script}")
        command = self._ssh_base_command + [f"bash -lc {shlex.quote(script)}"]
        last_error: subprocess.CalledProcessError | None = None
        for attempt in range(1, 6):
            with output_path.open("wb") as fh:
                result = subprocess.run(
                    command,
                    cwd=self.repo_root,
                    check=False,
                    stdout=fh,
                    stderr=subprocess.PIPE,
                )
            if result.returncode == 0:
                return
            should_retry = result.returncode == 255 and attempt < 5
            if should_retry:
                logger.warning(
                    "remote stream command failed with ssh rc=255 on attempt "
                    f"{attempt}/5; retrying.\nSTDERR:\n"
                    f"{result.stderr.decode('utf-8', errors='replace')}"
                )
                time.sleep(min(2 * attempt, 8))
                continue
            last_error = subprocess.CalledProcessError(
                result.returncode,
                command,
                stderr=result.stderr,
            )
            break
        if last_error is not None:
            raise last_error

    def _run_container_command(self, command: str):
        script = f"docker exec -i {shlex.quote(self.profile.container_name)} {command}"
        self._run_remote(script, check=True, capture_output=True)

    def _render_container_adb_shell_root(self, device_command: str) -> str:
        adb_shell_command = f"su 0 sh -c {shlex.quote(device_command)}"
        return (
            f"docker exec -i {shlex.quote(self.profile.container_name)} "
            f"adb -s {shlex.quote(self.profile.device_serial)} shell "
            f"{shlex.quote(adb_shell_command)}"
        )

    def _collect_prepare_checks(self) -> dict[str, Any]:
        remote_specs = {
            "host_harness_dir": {"path": self.profile.host_harness_dir, "kind": "dir"},
            "host_harness_binary": {
                "path": f"{self.profile.host_harness_dir}/{self.profile.harness_binary_name}",
                "kind": "file",
            },
            "host_libharness": {
                "path": self.profile.host_libharness_path,
                "kind": "file",
            },
            "host_app_root": {"path": self.profile.host_app_root, "kind": "dir"},
            "host_base_apk": {
                "path": f"{self.profile.host_app_root}/base.apk",
                "kind": "file",
            },
            "host_app_lib_dir": {
                "path": f"{self.profile.host_app_root}/lib/arm64-v8a",
                "kind": "dir",
            },
            "host_target_library": {
                "path": (
                    f"{self.profile.host_app_root}/lib/arm64-v8a/"
                    f"{self.profile.target_library_basename}"
                ),
                "kind": "file",
            },
            "host_afl_dir": {"path": self.profile.host_afl_dir, "kind": "dir"},
            "host_afl_binary": {
                "path": f"{self.profile.host_afl_dir}/afl-fuzz",
                "kind": "file",
            },
            "host_afl_trace_so": {
                "path": f"{self.profile.host_afl_dir}/afl-frida-trace.so",
                "kind": "file",
            },
        }
        if self.profile.host_seed_dir:
            remote_specs["host_seed_dir"] = {
                "path": self.profile.host_seed_dir,
                "kind": "dir",
            }
        if self.profile.host_runtime_libcpp_path:
            remote_specs["host_runtime_libcpp"] = {
                "path": self.profile.host_runtime_libcpp_path,
                "kind": "file",
            }
        if self.profile.host_frida_script:
            remote_specs["host_frida_script"] = {
                "path": self.profile.host_frida_script,
                "kind": "file",
            }
        checks = self._collect_remote_exists_map(remote_specs)
        checks["device_tmp_root"] = self._check_device_path("/data/local/tmp", "dir")
        return checks

    def _collect_remote_exists_map(
        self,
        specs: dict[str, dict[str, str]],
    ) -> dict[str, dict[str, Any]]:
        payload = json.dumps(specs, sort_keys=True)
        inline = f"""
import json
import os

specs = json.loads({payload!r})
result = {{}}
for name, spec in specs.items():
    path = spec["path"]
    kind = spec["kind"]
    exists = os.path.isdir(path) if kind == "dir" else os.path.isfile(path)
    result[name] = {{
        "path": path,
        "kind": kind,
        "exists": exists,
    }}
print(json.dumps(result, sort_keys=True))
"""
        command = f"python3 - <<'PY'\n{inline}\nPY"
        result = self._run_remote(command, check=True)
        return json.loads(result.stdout)

    def _run_device_root_command(
        self,
        device_command: str,
        *,
        capture_output: bool,
        allow_timeout: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        script = self._render_container_adb_shell_root(device_command)
        result = self._run_remote(script, check=False, capture_output=capture_output)
        if result.returncode not in {0, 124}:
            raise RuntimeError(
                f"Device command failed with rc={result.returncode}\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
            )
        if result.returncode == 124 and not allow_timeout:
            raise RuntimeError("Device command timed out unexpectedly")
        return result

    def _local_session_dir(self, session_name: str) -> Path:
        return self.repo_root / self.profile.local_results_path / session_name

    def _device_session_root(self, session_name: str) -> str:
        return f"{self.profile.device_runtime_root.rstrip('/')}/{session_name}"

    @staticmethod
    def _remove_tree(path: Path):
        for child in sorted(path.rglob("*"), reverse=True):
            if child.is_file() or child.is_symlink():
                child.unlink()
            else:
                child.rmdir()
        path.rmdir()

    @staticmethod
    def _write_json(path: Path, payload: dict[str, Any]):
        _ensure_parent(path)
        path.write_text(
            json.dumps(payload, indent=2, sort_keys=True, default=_json_default),
            encoding="utf-8",
        )
