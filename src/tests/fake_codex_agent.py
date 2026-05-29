import argparse
import json
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", nargs="?", default="exec")
    parser.add_argument("--model", default="")
    parser.add_argument("--task-file")
    parser.add_argument("--result-json")
    parser.add_argument("--output-schema")
    parser.add_argument("-o", "--output-last-message")
    args = parser.parse_args()

    if args.task_file:
        task_dir = Path(args.task_file).parent
    else:
        prompt = sys.stdin.read()
        if not prompt:
            raise SystemExit("no stdin prompt provided")
        cwd = Path.cwd()
        task_dir = cwd

    contract = json.loads(
        (task_dir / "outputs" / "expected_contract.json").read_text(encoding="utf-8")
    )
    kind = contract["kind"]

    if kind == "code_file":
        result = {
            "kind": "code_file",
            "language": contract.get("language", "c"),
            "code": "int LLVMFuzzerTestOneInput(const unsigned char *Data, unsigned long Size) { return 0; }",
            "usage": {"input_tokens": 11, "output_tokens": 7},
        }
    elif kind == "json_array_indexes":
        result = {
            "kind": "json_array_indexes",
            "indexes": [0],
            "usage": {"input_tokens": 5, "output_tokens": 2},
        }
    elif kind == "analysis_verdict":
        result = {
            "kind": "analysis_verdict",
            "verdict": "bug_in_library",
            "explanation": "The crash reaches library code with a plausible bug signature.",
            "reasoning": "Fake reasoning trace.",
            "usage": {"input_tokens": 9, "output_tokens": 6},
        }
    elif kind == "constraints_and_code":
        result = {
            "kind": "constraints_and_code",
            "constraints": {"foo": "Call foo only after initialization."},
            "code": "int LLVMFuzzerTestOneInput(const unsigned char *Data, unsigned long Size) { return 0; }",
            "usage": {"input_tokens": 13, "output_tokens": 9},
        }
    elif kind == "droidot_repair":
        result = {
            "kind": "droidot_repair",
            "verdict": "harness_fp",
            "target_file": "harness.cpp",
            "root_cause": "Caller setup is too brittle for this replay and should tolerate a missing class-backed caller.",
            "updated_file_content": "int repaired_harness = 1;\n",
            "verification_expectation": "The replay should no longer fail with the same harness-side setup condition.",
            "usage": {"input_tokens": 17, "output_tokens": 11},
        }
    else:
        result = {
            "kind": "plain_summary",
            "text": "Fake codex summary result.",
            "usage": {"input_tokens": 4, "output_tokens": 4},
        }

    if args.result_json:
        Path(args.result_json).write_text(json.dumps(result, indent=2), encoding="utf-8")
    elif args.output_last_message:
        Path(args.output_last_message).write_text(
            json.dumps(result, indent=2), encoding="utf-8"
        )
    else:
        print(json.dumps(result, indent=2))
    print("fake codex agent completed")


if __name__ == "__main__":
    main()
