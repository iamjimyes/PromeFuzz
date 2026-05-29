# PromeFuzz Bigemu Profile Contract

This file defines the PromeFuzz-owned directory and runtime contract for
`droidot` JNI baseline runs on bigemu-style lanes.

It is intentionally a baseline contract, not a `granzon` framework contract.

## Scope

This contract assumes the driver already exists in `droidot` form:

- compiled `harness`
- compiled `libharness.so`
- `afl.js`
- target app `base.apk`
- target app `lib/arm64-v8a/*`
- AFL runtime under `/home/psy/droidot/afl`

It does not assume:

- `classes.dex`
- `libjenv.so`
- TikTok standalone-JNI staging

## Device-side namespace

Use `/data/local/tmp/promefuzz-bigemu` as the root.

- `/data/local/tmp/promefuzz-bigemu/apps/<package>`
  - staged `base.apk`
  - staged `lib/arm64-v8a/*`
- `/data/local/tmp/promefuzz-bigemu/runtime/afl`
  - `afl-fuzz`
  - `afl-showmap`
  - `afl-frida-trace.so`
- `/data/local/tmp/promefuzz-bigemu/sessions/<profile>/<session>`
  - `harness`
  - `libharness.so`
  - `libc++_shared.so`
  - `afl.js`
  - `seeds/`
  - `output_fg/`
- `/data/local/tmp/promefuzz-bigemu/build`
  - optional remote compile scratch

Compatibility note:

- some `droidot` harnesses are linked with `RUNPATH=/data/data/com.termux/files/usr/lib`
- PromeFuzz baseline may therefore stage a matching `libc++_shared.so` into
  `/data/data/com.termux/files/usr/lib/libc++_shared.so` as a compatibility shim
- treat that shim as runtime scaffolding, not as proof that the lane is cleanly
  modeled yet

## Host-side source inputs

Treat these as source inputs rather than runtime truth:

- `/home/psy/droidot/target_APK/<package>/...`
- `/home/psy/droidot/harness/cpp/libharness.so`
- `/home/psy/droidot/afl/...`

## Local result root

Store pulled results under:

- `PromeFuzz/android_runs/promefuzz-bigemu/<profile>/<session>`

This keeps PromeFuzz baseline results separate from:

- `granzon` maintained outputs
- historical droidot staging under `/data/local/tmp/fuzzing`

## Profile Fields

These fields define the minimum reusable contract:

- `host_harness_dir`
  - compiled harness folder from `droidot`
- `host_libharness_path`
  - companion `libharness.so`
- `host_app_root`
  - unpacked target APK root containing `base.apk` and `lib/arm64-v8a`
- `host_afl_dir`
  - AFL runtime source directory
- `host_frida_script`
  - `afl.js` driver script
- `host_seed_dir`
  - optional seed folder; if empty PromeFuzz synthesizes one empty seed
- `host_runtime_libcpp_path`
  - optional override for the C++ runtime used by `harness/libharness.so`
  - if empty, PromeFuzz falls back to `<host_app_root>/lib/arm64-v8a/libc++_shared.so`
  - use this field when the app-bundled `libc++_shared.so` is ABI-incompatible
    with the `droidot`-compiled `harness/libharness.so`
- `device_runtime_root`
  - session namespace under `/data/local/tmp/promefuzz-bigemu/sessions/...`
- `device_app_root`
  - app staging namespace under `/data/local/tmp/promefuzz-bigemu/apps/...`
- `afl_preload_paths`
  - loader hints for AFL child startup
  - keep `/data/data/com.termux/files/usr/lib/libc++_shared.so` first when
    the harness expects Termux-style runtime layout

## Runtime Selection Rule

Use this order when choosing `libc++_shared.so`:

1. a profile-specific `host_runtime_libcpp_path` known to match the harness ABI
2. the target app's own `lib/arm64-v8a/libc++_shared.so`

If `harness` or `libharness.so` fail with missing C++ symbols:

- do not immediately patch the harness binary
- first supply a compatible runtime via `host_runtime_libcpp_path`
- record the chosen runtime path in the profile because this is part of the
  effective baseline contract

## Windows Pullback Rule

AFL result trees use filenames such as:

- `id:000000,time:0,execs:0,orig:seed0`

Those names are invalid on Windows. PromeFuzz therefore treats pullback as a
normalized copy, not a byte-for-byte filename-preserving extraction.

Current rule:

- keep raw tarball under `raw/output_fg.tar`
- extract into `raw/output_fg/...`
- sanitize Windows-invalid filename characters during extraction
- perform replay and triage against the sanitized local tree

Implication:

- local pulled filenames are analysis artifacts
- the tarball is the higher-fidelity preserved transport artifact
