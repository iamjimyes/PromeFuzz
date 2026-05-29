# Objective

Use `PromeFuzz` as a baseline lane for `droidot` JNI fuzz drivers.

# Success Criteria

- a `PromeFuzz droidot` command can validate or build a harness
- it can stage the harness to a configured Android lane
- it can launch a bounded AFL session
- it can pull back crashes and stats
- it can replay crash inputs and emit a lightweight triage summary

# Environment

- host: `psy@10.176.46.32`
- primary maintained lane target: configurable, default intended for bigemu-style use
- runtime details come from the selected profile JSON

# Source Truth

- `PromeFuzz` source under this directory
- remote harness and target app materials under `/home/psy/droidot/...`

# Non-Goals

- generating JNI harness source from PromeFuzz
- replacing `granzon`
- introducing `classes.dex` or `libjenv.so` assumptions into the droidot JNI baseline path

# Current Blockers

- exact maintained bigemu droidot harness profile still needs user-selected concrete values

# References

- `profiles/droidot_jni.template.json`
- `cli/droidot.py`
- `src/droidot/runner.py`
