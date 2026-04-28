# OpenCode Harness Style Guide

## Supported Languages

This harness supports `c_cpp`, `python`, `go`, `lua`, and `java`.

Every generated `project_model.json` file must mark each source file with one of those language values. Modules should use the same value when they are single-language, or `mixed` with a `languages` array when they contain multiple supported languages.

## Structured Context

`project_model.json` and `call_graph.json` are shared facts, not prose summaries.

- Use `schema_version: "1.0"` in both files.
- Prefer stable IDs (`mod-*`, `file-*`, `ep-*`, `fn-*`, `edge-*`, `flow-*`) over natural-language names.
- Attach `evidence` and `confidence` to high-risk modules, entry points, call edges, and data flows.
- Treat `call_graph.json` as a risk-focused sparse graph. It should contain `nodes`, `edges`, `data_flows`, and `unresolved`, not a full-project graph.
- Do not promote model-only inference to a high-confidence fact.
- Every scanner work item must produce a `COVERAGE_LEDGER` summary. Coordinators must persist it with `vuln-db coverage-add` before marking the work item complete.
- Use `scan-profiles.json` to control scan duration. `deep` is the default for vulnerability hunting.

## Evidence First

Scanner agents should write complete vulnerability details to `scan.db` through `vuln-db` before returning to the coordinator. Return text should contain only counts and compact cross-module hints.

For each candidate, prefer filling:

- `language`
- `framework`
- `source_kind`
- `sink_kind`
- `sanitizer_checked`
- `evidence_json`
- `rule_id`
- `analysis_backend`

## Language Packs

Language-specific knowledge lives in `.opencode/language/*.json` and `.opencode/skill/*-taint-tracking/SKILL.md`.

Do not add a new dedicated worker for every language unless the generic language worker cannot express the required behavior.
