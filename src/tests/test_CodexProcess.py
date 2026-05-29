import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src import vars as global_vars
from src.llm.llm import CodexProcessReasoningClient, LLMChat
from src.llm.prompter import CrashAnalysisPrompter, LibPurposePrompter
from src.llm.prompter import RAGExcerpt


def run():
    repo_root = Path(__file__).resolve().parents[2]
    global_vars.promefuzz_path = repo_root
    global_vars.library_language = global_vars.SupportedLanguages.C
    global_vars.library_name = "demo"

    with tempfile.TemporaryDirectory() as temp_dir:
        client = CodexProcessReasoningClient(
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

        chat = LLMChat(client)
        lib_purpose = LibPurposePrompter(chat).prompt(
            "demo",
            [RAGExcerpt("A small demo library for testing.", "README.md")],
        )
        print("LIB_PURPOSE:", lib_purpose)

        analysis, reasoning = CrashAnalysisPrompter(LLMChat(client)).prompt(
            "Crash report body",
            "Demo library purpose",
            "demo",
        )
        print("ANALYSIS:", analysis)
        print("REASONING:", reasoning)


if __name__ == "__main__":
    run()
