import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.droidot.runner import (
    CompileRouteUnavailableError,
    DroidotBaselineRunner,
    DroidotProfile,
    StagedDeviceFile,
)


def run():
    profile = DroidotProfile(
        name="demo",
        ssh_target="psy@example",
        container_name="container",
        device_serial="emulator-0000",
        host_work_root="/home/psy/droidot",
        container_work_root="/mnt",
        host_harness_dir="/home/psy/droidot/target_APK/demo/harnesses/Java_demo_native@@0",
        host_libharness_path="/home/psy/droidot/harness/cpp/libharness.so",
        host_app_root="/home/psy/droidot/target_APK/demo",
        host_afl_dir="/home/psy/droidot/afl",
        device_runtime_root="/data/local/tmp/promefuzz-bigemu/sessions/demo",
        device_app_root="/data/local/tmp/promefuzz-bigemu/apps/demo",
        target_library_basename="libdemo.so",
        class0="demo/Class",
        afl_binary_path="/data/local/tmp/promefuzz-bigemu/runtime/afl/afl-fuzz",
        compile_mode="auto",
        host_compile_cxx=r"C:\Microsoft\AndroidNDK\android-ndk-r23c\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android31-clang++.cmd",
        host_compile_strip=r"C:\Microsoft\AndroidNDK\android-ndk-r23c\toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-strip.exe",
        local_build_root="build/promefuzz-bigemu",
        runtime_overrides_env_text=(
            "DROIDOT_CLASS_APK=/data/local/tmp/fuzzing/target_APK/demo/reif_min_class_shim.jar\n"
            "DROIDOT_ALLOW_NULL_CALLER=0\n"
        ),
        host_extra_stage_files=[
            StagedDeviceFile(
                host_path="/home/psy/droidot/target_APK/demo/reif_min_class_shim.jar",
                device_relative_path="aux/reif_min_class_shim.jar",
                chmod="644",
            )
        ],
    )
    runner = DroidotBaselineRunner(profile)
    env_map = runner._load_runtime_overrides(
        "/data/local/tmp/promefuzz-bigemu/sessions/demo/smoke"
    )
    assert (
        env_map["DROIDOT_CLASS_APK"]
        == "/data/local/tmp/promefuzz-bigemu/sessions/demo/smoke/aux/reif_min_class_shim.jar"
    ), env_map
    workspace = runner._local_compile_workspace("demo", debug_build=False)
    assert workspace.as_posix().endswith(
        "build/promefuzz-bigemu/host_compile/demo/release/demo"
    ), workspace
    command = runner._build_host_compile_command(
        Path(profile.host_compile_cxx),
        source_name="harness.cpp",
        harness_name="harness",
        debug_build=False,
    )
    assert command[:3] == ["cmd.exe", "/d", "/c"], command
    assert command[-3:] == ["-lharness", "-o", "harness"], command
    assert "-Wl,-rpath,$ORIGIN" in command, command

    class FakeRunner(DroidotBaselineRunner):
        def __init__(self, fake_profile: DroidotProfile):
            super().__init__(fake_profile)
            self.calls = []

        def _compile_remote_harness_device(self, *args, **kwargs):
            self.calls.append("device")
            raise CompileRouteUnavailableError("device compiler missing")

        def _compile_remote_harness_host(self, *args, **kwargs):
            import subprocess

            self.calls.append("host")
            return subprocess.CompletedProcess(
                args=["host"],
                returncode=0,
                stdout="host ok",
                stderr="",
            )

        def _remote_harness_artifact_status(self, *args, **kwargs):
            return {"up_to_date": True}

    fake_runner = FakeRunner(profile)
    compile_result = fake_runner._compile_remote_harness(
        profile.host_harness_dir,
        debug_build=False,
        compile_tag="demo",
    )
    assert fake_runner.calls == ["device", "host"], fake_runner.calls
    assert compile_result["compile_route"] == "host", compile_result
    assert compile_result["route_errors"][0]["route"] == "device", compile_result
    print("DROIDOT_PROFILE_CONTRACT_OK")


if __name__ == "__main__":
    run()
