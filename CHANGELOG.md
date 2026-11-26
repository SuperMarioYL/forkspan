# Changelog

Releases are tagged `vX.Y.Z`; `VERSION` is the canonical tag and this file's
newest section must match it (pinned by `TestChangelog_NewestVersionMatchesVERSION`).

## v0.11.0

Snapshot output and span-identity fixes.

- `inspect -o -` now writes the snapshot JSON to stdout. The resolver already
  used `-` internally to mean "stdout, no file", but the print branch keyed on
  `--json` alone, so `-o -` discarded the snapshot, created no file, printed
  `snapshot written → -`, and exited 0.
- An empty `reachable_tool_calls` set now serializes as `[]` instead of `null`,
  matching `reached_spans` in the same snapshot object.
- A span record without a `spanId` is rejected with a clear error instead of
  being indexed under the `""` no-parent sentinel, which made every root span's
  empty `parentSpanId` resolve to that unrelated span and fabricate ancestors.
- `--json`/`--out` without `--snapshot`/-s now fail with usage guidance instead
  of silently launching the interactive navigator and dropping both flags.
- Add this changelog; version surfaces (VERSION, the in-source version var,
  `web/site.json`) stay in lockstep.

## v0.10.0

Query and parse-conformance fixes.

- `inspect -s <span-id>` resolves hex span ids case-insensitively (and tolerates
  surrounding whitespace), per the OTLP/JSON spec, so an id copied from a
  spec-conforming export no longer fails with "not in tree".
- proto3-JSON non-finite double encodings (`"NaN"`, `"Infinity"`, `"-Infinity"`)
  are accepted instead of aborting the whole trace parse.
- `text_completion` and `embeddings` classify as LLM spans instead of rendering
  as unclassified.

## v0.9.0

Parse conformance and navigator fixes.

- OTLP/JSON exports using the spec-mandated integer enums (`kind`,
  `status.code`) and numeric int64 timestamps parse again instead of failing the
  whole run with exit 1.
- Hex trace/span IDs are case-insensitive, so mixed-case exports keep their
  parent → child structure.
- Spans trapped in a malformed parent cycle (self-loop or mutual) stay visible
  in the navigator and `inspect --list`.
- The committed demo recording was re-rendered so it no longer shows long-fixed
  "unknown flag" errors.

## v0.8.0

Version-surface fix: the in-source version var and the site `content_version`
stay in lockstep with `VERSION`, and `forkspan --version` self-reports the true
tag.

## v0.7.0

The `inspect --json` snapshot emits the recorded trigger payload as readable
text instead of base64.

## v0.6.0

Orphan spans — whose parent is missing from a partial export — no longer vanish
from the navigator and `inspect --list`; a span with an absent parent is a root.

## v0.5.0

Fix the stale in-source version, refresh the en/zh-CN README sample output, and
add `inspect --list` for non-interactive span-id discovery.

## v0.4.0

`inspect --snapshot` output fixes: `--json -o` writes the file, the default path
no longer double-outputs, and `reached_spans` use snake_case keys and string
enums.

## v0.3.0

Broken or self-referencing parent links no longer hang the snapshot walk.

## v0.2.0

Documented `fork`/`replay` invocations parse and print the roadmap pointer
instead of erroring on unknown flags, and tool spans are no longer misclassified.

## v0.1.0

Initial release: OTLP-GenAI span tree navigation, intrusion-span marking, and
StateSnapshot export.
