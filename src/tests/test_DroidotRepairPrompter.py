import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src import vars as global_vars
from src.llm.llm import CodexProcessClient, LLMChat
from src.llm.prompter import DroidotRepairPrompter


def run():
    repo_root = Path(__file__).resolve().parents[2]
    global_vars.promefuzz_path = repo_root
    global_vars.library_language = global_vars.SupportedLanguages.CPP

    with tempfile.TemporaryDirectory() as temp_dir:
        client = CodexProcessClient(
            executable=sys.executable,
            args=[
                str(repo_root / "src" / "tests" / "fake_codex_agent.py"),
                "--model",
                "{MODEL}",
                "--output-schema",
                "{SCHEMA_JSON}",
                "-o",
                "{RESULT_TXT}",
                "-",
            ],
            model="gpt-5.3-codex",
            work_root=temp_dir,
            timeout=60,
        )

        result = DroidotRepairPrompter(LLMChat(client)).prompt(
            replay_log="fake replay log",
            triage_summary={"kind": "setup-failure", "signature": "setup-failure@classloader"},
            harness_code="int main() { return 0; }\n",
            info_json='{"targetlibrary":"libdemo.so"}',
            runtime_overrides_text="DROIDOT_CLASS_APK=/old/path/shim.jar\n",
            allowed_target_files=["harness.cpp", "runtime_overrides.env"],
        )
        assert result["verdict"] == "harness_fp", result
        assert result["target_file"] == "harness.cpp", result
        assert "repaired_harness" in result["updated_file_content"], result
        print("DROIDOT_REPAIR_PROMPTER_OK")


if __name__ == "__main__":
    run()
