# packpeek

**Static packer / loader fingerprinter (C)** — is this binary packed, and by what?

[![ci](https://github.com/cognis-digital/packpeek/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/packpeek/actions/workflows/ci.yml)
![lang](https://img.shields.io/badge/lang-C%20%2B%20Python-A8B9CC)
![license](https://img.shields.io/badge/license-COCL%201.0-2ea043)

Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)**. The classic first step in malware triage: `packpeek` searches a binary for the documented markers of common runtime packers/protectors — **UPX, ASPack, Themida, WinLicense, MPRESS, PECompact, Petite, FSG, MEW, NsPack, Enigma, VMProtect, Armadillo** — and measures **Shannon entropy**. A packer marker plus high entropy is a strong "this is packed, look closer" signal.

Format-agnostic (PE / ELF / Mach-O / firmware blob), dependency-free, JSON-out. Pairs with [`entroc`](https://github.com/cognis-digital/entroc) for windowed entropy and emits **SARIF + YARA + Markdown** via the bundled Python companion.

> Defensive triage only — reads a file, makes no network calls, executes nothing.

---

## Contents

- [Overview](#overview) · [Architecture](#architecture) · [Install & build](#install--build)
- [Usage](#usage) · [Output](#output) · [The companion (sarif.py)](#the-companion-sarifpy)
- [Configuration reference](#configuration-reference) · [Exit codes](#exit-codes) · [FAQ](#faq)
- Deep dives: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) · [docs/USAGE.md](docs/USAGE.md) · [ROADMAP.md](ROADMAP.md)

## Overview

Runtime packers and protectors compress or obfuscate an executable so that the
"real" code only materialises in memory at run time. That defeats naive static
analysis and is a near-universal trait of commodity malware. Before you spend
time in a disassembler, you want a fast, offline answer to two questions:

1. **Is it packed?** — a high whole-file Shannon entropy (near the 8.0 ceiling)
   is the tell-tale of compression/encryption.
2. **By what?** — most packers leave a documented fingerprint (a section name
   like `.aspack` / `.vmp0`, or a magic string like `UPX!`).

`packpeek` answers both in a single pass over the bytes and prints one JSON
object. It reads the whole file, computes entropy over all 256 byte values,
scans for a table of public packer markers, de-duplicates hits by family, and
combines the two signals into a `verdict`. Everything is stdlib-only C99; the
optional Python companion turns that JSON into SARIF (code scanning), a YARA
rule, or a Markdown summary.

<!-- cognis:example:start -->
## 🔎 Example output

**Sample result** _(illustrative values — run on your own data for real findings):_

```json
{
  "tool": "packpeek",
  "file": "suspicious.exe",
  "size": 204800,
  "entropy": 7.9128,
  "high_entropy": true,
  "threshold": 7.20,
  "packers": [
    { "name": "UPX", "offset": 336 }
  ],
  "packer_count": 1,
  "verdict": "packed"
}
```

`verdict` is `packed` when a marker **and** high entropy are present,
`likely-packed` when only one signal fires, and `clean` when neither does.
<!-- cognis:example:end -->

## Architecture

```
             +-------------------+        stdout JSON        +------------------+
  file  ---> |    packpeek (C)   | ------------------------> |  sarif.py (Py)   | ---> SARIF | YARA | Markdown
             |  entropy + markers|   {"verdict":"packed"...} |  companion       |
             +-------------------+                           +------------------+
                     |
                     +--> exit code (0 clean / 2 packed / 1 error) --> gate CI
```

- **`packpeek.c`** — the core. A single translation unit, no dependencies beyond
  libc + libm. Reads the file once into memory, computes entropy, runs a
  portable substring search (`find`, a dependency-free `memmem`) for each entry
  in the marker table `SIGS`, and prints the report.
- **`sarif.py`** — the reporting companion. Consumes packpeek JSON (a single
  object, a JSON array, or newline-delimited JSON for batches) and renders
  SARIF 2.1.0, a YARA rule, or a Markdown table. Stdlib-only.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full data model,
signature table, and verdict logic.

## Install & build

The core is a single C file:

```bash
gcc -O2 -std=c99 -Wall -Wextra -o packpeek packpeek.c -lm
```

The companion needs only Python ≥ 3.8 (no third-party runtime deps). For
development/tests:

```bash
python -m pip install -r requirements-dev.txt   # pytest
# or, editable install exposing the `packpeek-sarif` entry point:
python -m pip install -e .
```

## Usage

```
packpeek <file> [--threshold F]
  --threshold   entropy (bits, 0..8) above which a file is "high entropy" (default 7.2)
  -h, --help    print usage
```

```bash
packpeek suspicious.exe
packpeek suspicious.exe --threshold 7.5
packpeek suspicious.exe | python sarif.py            # -> SARIF for code scanning
packpeek suspicious.exe | python sarif.py --yara     # -> deployable YARA rule
packpeek suspicious.exe | python sarif.py --md       # -> Markdown triage summary
```

Batch a directory and aggregate the reports:

```bash
for f in samples/*; do packpeek "$f"; done | python sarif.py --md
for f in samples/*; do packpeek "$f"; done | python sarif.py --fail-on packed
```

## Output

```json
{"tool":"packpeek","file":"suspicious.exe","size":204800,"entropy":7.9128,
 "high_entropy":true,"threshold":7.20,
 "packers":[{"name":"UPX","offset":336}],"packer_count":1,"verdict":"packed"}
```

## The companion (sarif.py)

`sarif.py` converts packpeek JSON into three formats and can gate CI:

| Flag | Output |
| --- | --- |
| _(none)_ | SARIF 2.1.0 document (GitHub/GitLab code scanning) |
| `--yara` | A YARA rule matching the detected packers' markers |
| `--md`, `--markdown` | A Markdown summary table (great for PR comments) |
| `--fail-on LEVEL` | Also exit `2` when any report's verdict is ≥ `LEVEL` (`clean` \| `likely-packed` \| `packed`) |

It accepts **one report, a JSON array of reports, or newline-delimited JSON**,
so you can pipe a whole batch through it. Multiple reports are aggregated: SARIF
gains one result per non-clean file, YARA unions every marker, and Markdown
renders one row per file with a worst-verdict summary. See
[docs/USAGE.md](docs/USAGE.md) for worked examples.

## Configuration reference

| Setting | Where | Default | Meaning |
| --- | --- | --- | --- |
| `--threshold F` | `packpeek` | `7.2` | Entropy (bits, 0–8) at/above which `high_entropy` is true. Lower to catch lightly-compressed files; raise to reduce noise on media-heavy binaries. |
| `--yara` | `sarif.py` | off | Emit a YARA rule instead of SARIF. |
| `--md` / `--markdown` | `sarif.py` | off | Emit a Markdown summary instead of SARIF. |
| `--fail-on LEVEL` | `sarif.py` | off | Non-zero exit when the worst verdict is ≥ `LEVEL`. |

## Exit codes

| Code | `packpeek` | `sarif.py` |
| --- | --- | --- |
| `0` | verdict `clean` | success (unless `--fail-on` trips) |
| `2` | verdict `packed` or `likely-packed` | `--fail-on` threshold met |
| `1` | I/O / usage error | invalid JSON input or bad `--fail-on` value |

Gate CI directly on packpeek's exit, or on `sarif.py --fail-on` for batches.

## FAQ

**Does packpeek unpack anything or run the sample?** No. It only reads bytes and
computes statistics. It never executes the file and makes no network calls.

**Why whole-file entropy instead of per-section?** packpeek is deliberately
format-agnostic so it works on PE, ELF, Mach-O and raw firmware alike. Whole-file
entropy plus marker scanning is a robust, fast first pass. For windowed /
per-region entropy, pair it with [`entroc`](https://github.com/cognis-digital/entroc).

**A file is flagged `likely-packed` but I know it's fine — why?** `likely-packed`
means exactly one signal fired: either a marker with normal entropy (a false
positive on an incidental byte sequence) or high entropy with no marker (common
for legitimately compressed installers, media blobs, or encrypted resources).
Tune `--threshold` for your corpus.

**Can it miss a packer?** Yes — it matches _documented_ markers. A custom or
marker-stripped packer may only surface as high entropy. Treat a `clean` verdict
as "no known marker," not "definitely not packed."

**Is the marker `offset` meaningful?** It is the byte offset of the first
matching marker for that family, useful for jumping straight to the relevant
region in a hex editor.

## License

COCL 1.0 — see [LICENSE](LICENSE). Commercial use → licensing@cognis.digital
