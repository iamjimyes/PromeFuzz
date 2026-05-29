"""
Lightweight crash classification helpers that do not depend on the full ASan parser stack.
"""

from __future__ import annotations

import re
from pathlib import Path


class CrashLogClassifier:
    """
    Best-effort crash classifier for non-standard Android/JNI replay logs.
    """

    SIGNAL_RE = re.compile(r"\bSIG(SEGV|ABRT|BUS|ILL|FPE|TRAP)\b", re.IGNORECASE)
    TOMBSTONE_RE = re.compile(r"#\d+\s+pc\s+([0-9a-fA-F]+)\s+(.+)")
    SETUP_PATTERNS = (
        "afl_area_ptr is 0",
        "library base is 0",
        "env is 0",
        "callerobj0 is null",
        "failed to load",
        "missing jnionload",
        "registernatives",
        "getstaticmethodid",
        "findclass(",
        "classloader",
        "no such file or directory",
        "permission denied",
    )

    def classify(self, log_text: str) -> dict[str, str]:
        lower = log_text.lower()
        for pattern in self.SETUP_PATTERNS:
            if pattern in lower:
                sig = "setup-failure@" + re.sub(r"[^a-z0-9]+", "-", pattern).strip("-")
                return {
                    "kind": "setup-failure",
                    "signature": sig,
                    "summary": f"Runtime setup failed around: {pattern}",
                }

        if "program timed off" in lower or "timed out" in lower:
            return {
                "kind": "unknown",
                "signature": "timeout@unknown",
                "summary": "The deterministic replay timed out before it reached a parsed target crash signature.",
            }

        signal_match = self.SIGNAL_RE.search(log_text)
        tombstone_match = self.TOMBSTONE_RE.search(log_text)
        if signal_match or tombstone_match:
            signal = signal_match.group(0).upper() if signal_match else "SIGUNKNOWN"
            if tombstone_match:
                offset = tombstone_match.group(1).lower()
                module = Path(tombstone_match.group(2).strip().split()[0]).name or "unknown"
                signature = f"{signal}@{module}+0x{offset}"
                summary = (
                    f"Target crash reached signal {signal} in {module} at file offset 0x{offset}."
                )
            else:
                signature = f"{signal}@unknown"
                summary = f"Target crash reached signal {signal}, but no module offset was parsed."
            return {
                "kind": "target-crash",
                "signature": signature,
                "summary": summary,
            }

        if "addresssanitizer:" in lower or "==aborting" in lower:
            return {
                "kind": "target-crash",
                "signature": "asan-like@unknown",
                "summary": "The replay log looks like an ASan-style crash, but the full parser was not used.",
            }

        return {
            "kind": "unknown",
            "signature": "unknown@unknown",
            "summary": "The replay log did not match setup-failure, signal, or ASan patterns.",
        }
