"""
Droidot JNI baseline orchestration commands.
"""

from __future__ import annotations

import json
from pathlib import Path

import click
from loguru import logger

from src.droidot.runner import DroidotBaselineRunner, load_profile
from src import vars as global_vars
from src.utils import setup_llm


def _make_runner(profile_path: Path) -> DroidotBaselineRunner:
    profile = load_profile(profile_path)
    return DroidotBaselineRunner(profile)


def _resolve_repair_input(session_dir: Path, input_file: Path | None, crash_index: int | None) -> Path:
    if input_file is not None:
        return input_file
    normalized_dir = session_dir / "normalized_crashes"
    index = 0 if crash_index is None else crash_index
    candidate = normalized_dir / f"{index}.input"
    if candidate.is_file():
        return candidate
    raise click.ClickException(
        f"Could not resolve replay input. Expected {candidate} or provide --input-file."
    )


def _require_llm(llm_name: str | None):
    if not global_vars.config:
        raise click.ClickException(
            "No PromeFuzz config is loaded for droidot repair. Create config.toml first."
        )
    if "analyzer" not in global_vars.config:
        raise click.ClickException("config.toml is missing the [analyzer] section.")
    selected = llm_name or global_vars.config["analyzer"].get("analysis_llm", "")
    if not selected:
        raise click.ClickException(
            "No analyzer.analysis_llm is configured. Pass --llm or configure one."
        )
    return setup_llm(selected)


@click.group(help="Run the droidot JNI baseline workflow.")
def droidot():
    """
    Droidot JNI baseline commands.
    """


@droidot.command("prepare", help="Validate or build a droidot JNI harness.")
@click.option(
    "--profile",
    "profile_path",
    required=True,
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    help="Path to the droidot baseline profile JSON.",
)
@click.option(
    "--build",
    "build_mode",
    flag_value="build",
    default=False,
    help="Use the droidot remote compile flow if the harness binary is missing.",
)
@click.option(
    "--debug-build",
    "debug_build",
    is_flag=True,
    help="Build the debug harness variant when using --build.",
)
def prepare(profile_path: Path, build_mode: str | bool, debug_build: bool):
    runner = _make_runner(profile_path)
    if build_mode == "build":
        result = runner.prepare_build(debug_build=debug_build)
    else:
        result = runner.prepare_existing()
    click.echo(json.dumps(result, indent=2, sort_keys=True))


@droidot.command("run", help="Stage, run, pull back, normalize, and triage a session.")
@click.option(
    "--profile",
    "profile_path",
    required=True,
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    help="Path to the droidot baseline profile JSON.",
)
@click.option(
    "--session",
    "session_name",
    required=True,
    help="Session name used for local and remote result folders.",
)
@click.option(
    "--seconds",
    "seconds",
    type=int,
    default=None,
    help="Override the profile duration for this run.",
)
@click.option(
    "--cmplog/--no-cmplog",
    "cmplog",
    default=None,
    help="Override the profile cmplog toggle for this run.",
)
@click.option(
    "--build-if-missing",
    "build_if_missing",
    is_flag=True,
    help="Invoke the droidot remote compile flow if the harness binary is missing.",
)
@click.option(
    "--skip-pull",
    "skip_pull",
    is_flag=True,
    help="Do not pull back raw outputs after the bounded run.",
)
@click.option(
    "--max-replays",
    "max_replays",
    type=int,
    default=10,
    show_default=True,
    help="Maximum number of crash inputs to replay for log collection.",
)
def run(
    profile_path: Path,
    session_name: str,
    seconds: int | None,
    cmplog: bool | None,
    build_if_missing: bool,
    skip_pull: bool,
    max_replays: int,
):
    runner = _make_runner(profile_path)
    if build_if_missing:
        runner.prepare_build(debug_build=False)
    else:
        runner.prepare_existing()
    result = runner.run_session(
        session_name=session_name,
        seconds=seconds,
        cmplog=cmplog,
        pull_back=not skip_pull,
        max_replays=max_replays,
    )
    click.echo(json.dumps(result, indent=2, sort_keys=True))


@droidot.command("pull", help="Pull back and normalize a prior droidot session.")
@click.option(
    "--profile",
    "profile_path",
    required=True,
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    help="Path to the droidot baseline profile JSON.",
)
@click.option(
    "--session",
    "session_name",
    required=True,
    help="Session name to pull back.",
)
@click.option(
    "--max-replays",
    "max_replays",
    type=int,
    default=10,
    show_default=True,
    help="Maximum number of crash inputs to replay for log collection.",
)
def pull(profile_path: Path, session_name: str, max_replays: int):
    runner = _make_runner(profile_path)
    result = runner.pull_and_normalize(
        session_name=session_name,
        max_replays=max_replays,
    )
    click.echo(json.dumps(result, indent=2, sort_keys=True))


@droidot.command("triage", help="Run lightweight crash triage on a local session.")
@click.argument(
    "session_dir",
    type=click.Path(path_type=Path, exists=True, file_okay=False),
)
def triage(session_dir: Path):
    summary = DroidotBaselineRunner.triage_local_session(session_dir)
    logger.info(f"Triage summary written under {session_dir / 'triage'}")
    click.echo(json.dumps(summary, indent=2, sort_keys=True))


@droidot.command("replay", help="Replay one explicit input with the staged JNI harness.")
@click.option(
    "--profile",
    "profile_path",
    required=True,
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    help="Path to the droidot baseline profile JSON.",
)
@click.option(
    "--session",
    "session_name",
    required=True,
    help="Session name used for local and remote replay folders.",
)
@click.option(
    "--input-file",
    "input_file",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    default=None,
    help="Local replay input to push and execute.",
)
@click.option(
    "--crash-index",
    "crash_index",
    type=int,
    default=None,
    help="If input-file is omitted, read normalized_crashes/{index}.input from the local session.",
)
@click.option(
    "--build-if-missing",
    "build_if_missing",
    is_flag=True,
    help="Invoke the droidot remote compile flow if the harness binary is missing.",
)
def replay(
    profile_path: Path,
    session_name: str,
    input_file: Path | None,
    crash_index: int | None,
    build_if_missing: bool,
):
    runner = _make_runner(profile_path)
    if build_if_missing:
        runner.prepare_build(debug_build=False)
    else:
        runner.prepare_existing()
    session_dir = runner._local_session_dir(session_name)
    resolved_input = _resolve_repair_input(session_dir, input_file, crash_index)
    result = runner.replay_input(session_name=session_name, input_path=resolved_input)
    click.echo(json.dumps(result, indent=2, sort_keys=True))


@droidot.command("repair", help="Classify one replayed crash and attempt a harness-side repair.")
@click.option(
    "--profile",
    "profile_path",
    required=True,
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    help="Path to the droidot baseline profile JSON.",
)
@click.option(
    "--session",
    "session_name",
    required=True,
    help="Local session folder used for repair artifacts.",
)
@click.option(
    "--input-file",
    "input_file",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    default=None,
    help="Local replay input to push and repair against.",
)
@click.option(
    "--crash-index",
    "crash_index",
    type=int,
    default=None,
    help="If input-file is omitted, read normalized_crashes/{index}.input from the local session.",
)
@click.option(
    "--build-if-missing",
    "build_if_missing",
    is_flag=True,
    help="Invoke the droidot remote compile flow if the original harness binary is missing.",
)
@click.option(
    "--llm",
    "llm_name",
    default=None,
    help="Override analyzer.analysis_llm from config.toml.",
)
def repair(
    profile_path: Path,
    session_name: str,
    input_file: Path | None,
    crash_index: int | None,
    build_if_missing: bool,
    llm_name: str | None,
):
    runner = _make_runner(profile_path)
    if build_if_missing:
        runner.prepare_build(debug_build=False)
    else:
        runner.prepare_existing()
    session_dir = runner._local_session_dir(session_name)
    resolved_input = _resolve_repair_input(session_dir, input_file, crash_index)
    llm_client = _require_llm(llm_name)
    result = runner.repair_input(
        session_name=session_name,
        input_path=resolved_input,
        llm_client=llm_client,
    )
    click.echo(json.dumps(result, indent=2, sort_keys=True))
