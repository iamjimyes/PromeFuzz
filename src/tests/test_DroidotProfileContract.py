import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.droidot.runner import DroidotBaselineRunner, DroidotProfile, StagedDeviceFile


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
        host_extra_stage_files=[
            StagedDeviceFile(
                host_path="/home/psy/droidot/target_APK/demo/reif_min_class_shim.jar",
                device_relative_path="aux/reif_min_class_shim.jar",
                chmod="644",
            )
        ],
    )
    runner = DroidotBaselineRunner(profile)
    env_map = runner._parse_env_text(
        "DROIDOT_CLASS_APK=/data/local/tmp/fuzzing/target_APK/demo/reif_min_class_shim.jar\n"
        "DROIDOT_ALLOW_NULL_CALLER=0\n"
    )
    runner._rewrite_env_device_paths(
        env_map, "/data/local/tmp/promefuzz-bigemu/sessions/demo/smoke"
    )
    assert (
        env_map["DROIDOT_CLASS_APK"]
        == "/data/local/tmp/promefuzz-bigemu/sessions/demo/smoke/aux/reif_min_class_shim.jar"
    ), env_map
    print("DROIDOT_PROFILE_CONTRACT_OK")


if __name__ == "__main__":
    run()
