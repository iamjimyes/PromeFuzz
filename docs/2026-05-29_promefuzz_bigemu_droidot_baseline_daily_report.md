# 2026-05-29 PromeFuzz Bigemu Droidot Baseline Daily Report

## Objective

Use `PromeFuzz` as a baseline lane for existing `droidot` JNI fuzz drivers on
bigemu, without importing `granzon`'s standalone-JNI assumptions.

## What Landed

- added `PromeFuzz droidot` commands for:
  - `prepare`
  - `run`
  - `pull`
  - `triage`
- separated PromeFuzz baseline governance from `granzon`
- established dedicated device-side namespace:
  - `/data/local/tmp/promefuzz-bigemu/...`
- established dedicated local result root:
  - `PromeFuzz/android_runs/promefuzz-bigemu/...`
- added fallback crash triage for non-ASan Android replay logs

## Generalized Contract Extracted

The following pieces are now treated as reusable baseline contract, not as
one-off XHS hacks:

- profile-selectable C++ runtime via `host_runtime_libcpp_path`
- compatibility staging into:
  - session-local `libc++_shared.so`
  - `/data/data/com.termux/files/usr/lib/libc++_shared.so`
- Windows-safe pullback:
  - preserve raw tarball
  - sanitize invalid local filenames during extraction
- PromeFuzz-owned bigemu namespace for apps, runtime, sessions, and build temp

These are documented in:

- `docs/promefuzz_bigemu_directory_contract.md`
- `profiles/droidot_jni.template.json`

## Concrete Validation Run

Validated profile:

- `profiles/promefuzz_bigemu_xhs_xylog_nativeinit.json`

Concrete target:

- package: `com.xingin.xhs`
- JNI entry: `Java_com_xingin_xhs_xylog_XyLog_nativeInit@@0`
- target library: `libxylog.so`

Smoke session:

- session: `smoke_001`
- duration: 20 seconds

Observed outcome:

- `prepare` passed
- AFL++ Frida mode launched
- `load_art` succeeded
- `load_targetLibrary` succeeded
- `load_class0_object` succeeded
- `output_fg` was produced and pulled back

Pulled stats:

- `execs_done: 69`
- `edges_found: 335`
- `saved_crashes: 0`
- `saved_hangs: 0`

## Key Technical Findings

- the original `droidot` `harness/libharness.so` pair is compiled against a
  Termux-style runtime expectation
- app-bundled `libc++_shared.so` is not always ABI-compatible with that pair
- selecting a compatible external `libc++_shared.so` is sometimes necessary
- Windows cannot directly extract AFL queue/crash filenames because of `:`
  characters, so pullback must normalize local filenames

## Current Residual Risk

- this baseline is proven as a smoke lane, not yet as a long-running stable lane
- the current XHS smoke logs still show substantial AFL/Frida instrumentation
  noise such as `Patch out of range ...`
- that noise did not prevent session startup or basic execution, but it still
  needs longer-run stability validation before claiming production-quality use

## Recommended Next Steps

1. Run a longer bounded session on the same profile to validate stability.
2. Add one more app profile using the same contract to prove the contract is
   actually reusable, not merely XHS-shaped.
3. If repeated profiles need the same runtime workaround, promote runtime
   selection guidance into an explicit profile authoring checklist.
