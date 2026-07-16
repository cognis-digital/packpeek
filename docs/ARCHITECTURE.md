# Architecture

packpeek is two small, single-purpose parts connected by one JSON contract.

```
  file bytes
      │
      ▼
┌──────────────────────────────────────────┐
│ packpeek.c  (C99, libc + libm only)       │
│                                            │
│  1. read whole file into memory            │
│  2. entropy(): Shannon over 256 byte bins  │
│  3. find(): portable memmem per signature  │
│  4. de-dup hits by family, keep 1st offset │
│  5. combine → verdict, print JSON, exit    │
└──────────────────────────────────────────┘
      │ stdout: one JSON object
      ▼
┌──────────────────────────────────────────┐
│ sarif.py  (Python ≥3.8, stdlib only)      │
│                                            │
│  load_reports() → [report, ...]            │
│  to_sarif() / to_yara() / to_markdown()    │
│  worst_verdict() + --fail-on gate          │
└──────────────────────────────────────────┘
      │ stdout: SARIF | YARA | Markdown
      ▼
  code scanning / detection rule / triage note
```

## The JSON contract

`packpeek` emits exactly one JSON object per file. This is the stable interface
between the C core and any consumer (the bundled companion or your own tooling):

| Field | Type | Meaning |
| --- | --- | --- |
| `tool` | string | Always `"packpeek"`. |
| `file` | string | Path as passed on the command line. |
| `size` | int | Bytes actually read. |
| `entropy` | float | Whole-file Shannon entropy, 0–8 bits/byte, 4 decimals. |
| `high_entropy` | bool | `entropy >= threshold`. |
| `threshold` | float | The threshold in effect (default 7.20). |
| `packers` | array | `{ "name": <family>, "offset": <int> }` per detected family. |
| `packer_count` | int | `len(packers)`. |
| `verdict` | string | `packed` \| `likely-packed` \| `clean`. |

## Verdict logic

Two independent signals are combined:

| Marker found? | High entropy? | Verdict | Exit |
| --- | --- | --- | --- |
| yes | yes | `packed` | 2 |
| yes | no | `likely-packed` | 2 |
| no | yes | `likely-packed` | 2 |
| no | no | `clean` | 0 |

The asymmetry is deliberate: a single signal is worth surfacing for a human, but
only the coincidence of both earns the confident `packed` label.

## Entropy

Shannon entropy over the byte-value distribution:

```
H = -Σ p(b) · log2 p(b)   for b in 0..255, p(b) = freq(b) / n
```

`H` ranges from `0` (a single repeated byte) to `8` (uniform random). Compressed
or encrypted payloads crowd the top of that range; the `7.2` default sits just
below where real-world packed sections land, trading a few false positives on
media-heavy binaries for high recall. Tune with `--threshold`.

## Signature table

Markers live in the `SIGS` array in `packpeek.c`. Each entry is a family name, a
byte string, and its length. Multiple markers can map to one family (e.g. `UPX0`,
`UPX1`, `UPX!` all → `UPX`); hits are de-duplicated by family name with the first
matching offset retained. Adding a packer is a one-line, additive change to that
table — see [ROADMAP.md](../ROADMAP.md).

The companion's `_MARKERS` map in `sarif.py` is the inverse: family → marker
strings, used to reconstruct a YARA rule from a detected family.

## Companion internals

`sarif.py` is pure functions plus a thin CLI:

- `load_reports(raw)` — normalises a single object, a JSON array, or NDJSON into
  a `list[dict]`. Raises `json.JSONDecodeError` on genuine garbage.
- `to_sarif(reports)` — SARIF 2.1.0; one result per non-clean report. A single
  `dict` is accepted for backward compatibility.
- `to_yara(reports)` — a rule whose strings are the union of all detected
  markers, named `packpeek_<families>`.
- `to_markdown(reports)` — a summary table plus a worst-verdict footer.
- `worst_verdict(reports)` — the highest-severity verdict across a batch.
- `main(argv)` — arg parsing, I/O, and the optional `--fail-on` exit gate.

## Design constraints

- **Offline & inert.** No network, no execution, read-only. Suitable for
  air-gapped triage.
- **Dependency-free.** C core is libc + libm; companion is Python stdlib.
- **Format-agnostic.** No PE/ELF/Mach-O parsing — whole-file statistics + byte
  markers work on any blob, including firmware.
- **Stable JSON contract.** The fields above are additive-only; existing keys
  keep their meaning across versions.
