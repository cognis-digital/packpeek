# Roadmap

Direction for `packpeek`. Everything here is additive — the JSON contract and
CLI stay backward compatible; existing fields and flags keep their meaning.

## Near term

- **Signature coverage.** Grow the `SIGS` table with more documented, public
  packer/protector markers (e.g. additional installer stubs and .NET
  protectors), each mapped to a family and mirrored in `sarif.py`'s `_MARKERS`.
- **Per-region entropy hint.** Optionally report the highest-entropy fixed-size
  window alongside whole-file entropy, to distinguish a packed section from an
  otherwise-normal binary (complements [`entroc`](https://github.com/cognis-digital/entroc)).
- **`--json-lines` friendliness.** Document and test the NDJSON batch path
  end-to-end so directory scans are a first-class workflow.
- **SHA-256 field (opt-in).** Emit a content hash so batch reports are
  self-identifying for deduplication and tracking.

## Mid term

- **Confidence score.** Move beyond the three-state verdict to a 0–100 score
  combining entropy margin above threshold, marker count, and marker specificity.
- **Format awareness (optional, still dependency-free).** Light PE/ELF/Mach-O
  header sniffing to attribute markers to real section names and improve offset
  reporting, without a full parser.
- **Companion exporters.** CSV and JUnit outputs from `sarif.py` for spreadsheet
  triage and test-reporting pipelines.
- **Reusable GitHub Action.** A thin composite action wrapping build + scan +
  SARIF upload so downstream repos gate on packpeek in one step.

## Long term

- **Marker provenance.** Ship a machine-readable catalogue tying each signature
  to its public reference, surfaced in reports and YARA meta.
- **Streaming mode.** Constant-memory scanning for very large firmware images
  (chunked entropy + rolling marker search) so packpeek never loads the whole
  file.
- **Pluggable rule packs.** Load an external signature table at runtime so teams
  can extend detection without recompiling.

## Non-goals

- Unpacking, emulation, or executing samples — packpeek stays inert and offline.
- Full executable-format parsing or disassembly — it remains a fast, format-
  agnostic first-pass triage tool.
- Network lookups or telemetry of any kind.

Have a request or want to contribute a signature? Open an issue or a discussion.
