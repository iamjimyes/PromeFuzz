# PromeFuzz AGENTS

## Role

`PromeFuzz` in this repository is a comparative and baseline lane.

It is not the canonical maintained framework. That role remains with `granzon`.

## Current Scope

The active PromeFuzz extension is the `droidot` JNI baseline workflow:

- consume an existing `droidot` JNI harness directory
- optionally trigger the remote droidot compile helper
- stage the harness into a configured Android lane
- run bounded AFL fuzzing
- pull back results
- emit lightweight crash triage

Current directory contract:

- device-side PromeFuzz runs use `/data/local/tmp/promefuzz-bigemu/...`
- host-side source inputs remain under `/home/psy/droidot/...`
- local pulled results live under `PromeFuzz/android_runs/promefuzz-bigemu/...`
- local host-compile staging lives under `PromeFuzz/build/promefuzz-bigemu/...`
- profile authors may need to set `host_runtime_libcpp_path` when the app's
  bundled `libc++_shared.so` is ABI-incompatible with `droidot`-compiled
  `harness/libharness.so`
- bigemu profiles should prefer `compile_mode=auto` with a configured
  `host_compile_cxx` Windows Android NDK compiler so the baseline does not
  depend on a device-side Termux compiler
- Windows pullback is normalized rather than filename-preserving because AFL
  queue and crash filenames contain characters invalid on Windows

## Non-Goals

- do not treat PromeFuzz as the source of truth for maintained `granzon` runtime design
- do not silently import TikTok `classes.dex/libjenv.so` runtime assumptions into the droidot JNI baseline path
- do not expand PromeFuzz baseline scripts into a second maintained orchestra unless explicitly requested

## Operational Rules

- prefer adding PromeFuzz-specific runner code under `src/droidot/`
- keep the original PromeFuzz C/C++ library pipeline intact unless a change is clearly required
- record PromeFuzz-specific objectives under `PromeFuzz/goals/`
