# OpenCode Harness Style Guide

## Supported Languages

This harness supports `c_cpp`, `python`, `go`, `lua`, and `java`.

Every generated `project_model.json` file must mark each source file with one of those language values. Modules should use the same value when they are single-language, or `mixed` with a `languages` array when they contain multiple supported languages.

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

