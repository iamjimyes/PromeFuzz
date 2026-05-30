# Droidot Long Remote Repair

This note defines the recommended PromeFuzz operating mode for long-running
remote `droidot` repair against unstable or rate-limited SSH gateways.

## Goal

Prefer:

- many local-only repair proposal rounds
- infrequent remote sync and verification windows
- resumable local state under one stable session directory

Avoid:

- per-round remote prepare / push / verify
- tight SSH polling loops
- frequent background restarts with new session names

## Recommended Mode

Use `src/droidot/repair_loop.py` with:

- one stable `--session-name`
- `--rounds -1`
- short local `--sleep-seconds`
- long `--remote-sync-interval-seconds`

Recommended starting point:

```powershell
python src/droidot/repair_loop.py `
  --profile profiles/promefuzz_bigemu_xhs_caseinj_reif.json `
  --input android_runs/promefuzz-bigemu/xhs_caseinj_reif/reif_replay_20260529c/replay.input `
  --session-name reif_repair_loop_20260530_live `
  --rounds -1 `
  --sleep-seconds 5 `
  --remote-sync-interval-seconds 1800
```

This means:

- local proposal rounds can continue every 5 seconds
- remote sync is attempted at most once every 30 minutes

## Session State

All long-run state stays under one session root:

- `android_runs/promefuzz-bigemu/<profile>/<session>/`

Important files:

- `repair_loop.history.jsonl`
  - per-round status ledger
- `repair_attempts/attempt_*/repair.result.json`
  - attempt-level result
- `repair_attempts/attempt_*/repair.scope.json`
  - current repair allowlist and bootstrap-stall heuristic
- `repair_cache/original_harness/`
  - locally cached baseline harness tree
- `replay.log`
  - cached pre-replay baseline log
- `replay.summary.json`
  - cached pre-replay baseline classification

## Status Meanings

- `proposed_local_patch`
  - a new local candidate was created without remote verification
- `waiting_remote_sync`
  - a candidate exists but the remote sync window has not opened yet
- `patched_and_verified`
  - remote verify completed and changed the classification
- `verification_failed`
  - remote verify completed but did not improve the classification
- `verification_incomplete`
  - remote verify started but did not complete
- `remote_retryable_failure`
  - SSH/gateway failure; the loop should sleep and continue later
- `analysis_only`
  - the model did not produce an allowed concrete file patch

## Health Check

Recommended quick checks:

```powershell
Get-Content android_runs/promefuzz-bigemu/xhs_caseinj_reif/reif_repair_loop_20260530_live/repair_loop.history.jsonl -Tail 20
```

```powershell
Get-CimInstance Win32_Process |
  Where-Object { $_.Name -eq 'python.exe' -and $_.CommandLine -like '*repair_loop.py*reif_repair_loop_20260530_live*' } |
  Select-Object ProcessId, CommandLine
```

## Current Policy for Bootstrap-Only Timeouts

If replay times out while still inside `libharness` bootstrap and never gets
past `JNI_CreateJavaVM`, PromeFuzz narrows repair scope away from `harness.cpp`
and prefers runtime-only analysis or `runtime_overrides.env` edits.

This protects the `droidot` driver contract:

- `harness.cpp` owns input placement, API sequence, and target invocation
- `libharness.so` owns ART/JNI bootstrap

## Practical Advice

- keep one session name alive for a long run instead of rotating names
- do not force `--refresh-remote-cache` unless you intentionally changed the
  upstream remote harness tree
- when the gateway is especially fragile, raise
  `--remote-sync-interval-seconds` beyond 1800
- if remote sync must be fully manual for a while, run only a bounded number of
  local rounds and inspect the newest `proposed_local_patch`
