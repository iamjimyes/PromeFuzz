# PromeFuzz Goals

This directory is the PromeFuzz-local counterpart of the repo-wide `goals/`.

Use it for PromeFuzz-specific baseline and experimental work only:

- `active/`
  - the current PromeFuzz objective
- `archive/`
  - completed or superseded PromeFuzz objectives

Each active goal should state:

- objective
- success criteria
- target environment identity
- input source of truth
- what is intentionally out of scope
- blockers

Boundary rule:

- `granzon` goals track maintained framework work
- `PromeFuzz/goals` tracks comparative or baseline work inside `PromeFuzz`
