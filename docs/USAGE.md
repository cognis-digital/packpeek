# Usage guide

Worked examples for `packpeek` and its companion `sarif.py`.

## Build

```bash
gcc -O2 -std=c99 -Wall -Wextra -o packpeek packpeek.c -lm
```

## Scan a single file

```bash
packpeek suspicious.exe
```

```json
{"tool":"packpeek","file":"suspicious.exe","size":204800,"entropy":7.9128,
 "high_entropy":true,"threshold":7.20,
 "packers":[{"name":"UPX","offset":336}],"packer_count":1,"verdict":"packed"}
```

Exit code is `2` (packed/likely-packed) or `0` (clean), so you can branch on it:

```bash
if packpeek "$f" >/dev/null; then echo "clean"; else echo "look closer"; fi
```

## Tune sensitivity

The only knob is the entropy threshold. Lower it to catch lightly-compressed
files; raise it to cut noise on media-heavy binaries.

```bash
packpeek installer.exe --threshold 7.5
packpeek firmware.bin  --threshold 6.8
```

## Convert to SARIF (code scanning)

```bash
packpeek suspicious.exe | python sarif.py > packpeek.sarif
```

Upload `packpeek.sarif` with the standard `github/codeql-action/upload-sarif`
step to surface findings in the Security tab. `clean` files produce a valid
SARIF run with zero results.

## Generate a YARA rule

```bash
packpeek suspicious.exe | python sarif.py --yara
```

```yara
rule packpeek_UPX {
    meta:
        author = "Cognis Digital / packpeek"
        verdict = "packed"
        entropy = "7.9128"
    strings:
        $s0 = "UPX0"
        $s1 = "UPX1"
        $s2 = "UPX!"
    condition:
        any of them
}
```

## Markdown summary (PR comments / triage notes)

```bash
packpeek suspicious.exe | python sarif.py --md
```

```markdown
## packpeek report

| File | Verdict | Entropy | High entropy | Packers |
| --- | --- | --- | --- | --- |
| `suspicious.exe` | packed | 7.9128 | yes | UPX |

**Files scanned:** 1 · **Worst verdict:** packed
```

## Batch a directory

`sarif.py` accepts a single report, a JSON array, or newline-delimited JSON, so
a loop of packpeek invocations pipes straight in and is aggregated:

```bash
# One SARIF document covering every sample:
for f in samples/*; do packpeek "$f"; done | python sarif.py > all.sarif

# One Markdown table, one row per file:
for f in samples/*; do packpeek "$f"; done | python sarif.py --md

# Two report files aggregated:
python sarif.py report-a.json report-b.json --md
```

## Gate CI on a batch

`--fail-on LEVEL` makes `sarif.py` exit `2` when the worst verdict across all
inputs is at or above `LEVEL` (`clean` < `likely-packed` < `packed`):

```bash
# Fail the job only if something is confidently packed:
for f in build/artifacts/*; do packpeek "$f"; done \
  | python sarif.py --fail-on packed

# Stricter: fail on any single signal:
for f in build/artifacts/*; do packpeek "$f"; done \
  | python sarif.py --fail-on likely-packed
```

The gate does not change the emitted document — you can `tee` the SARIF/Markdown
and still get the exit code:

```bash
for f in build/artifacts/*; do packpeek "$f"; done \
  | python sarif.py --md --fail-on packed | tee report.md
```

## Programmatic use

`sarif.py` is importable; its converters are pure functions:

```python
import json, subprocess, sarif

raw = subprocess.run(["./packpeek", "suspicious.exe"],
                     capture_output=True, text=True).stdout
reports = sarif.load_reports(raw)
doc = sarif.to_sarif(reports)          # dict, SARIF 2.1.0
rule = sarif.to_yara(reports)          # str, YARA
md = sarif.to_markdown(reports)        # str, Markdown
worst = sarif.worst_verdict(reports)   # "packed" | "likely-packed" | "clean"
```

## Running the tests

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -ra
```

The Python companion tests run everywhere; the C end-to-end tests build
`packpeek.c` automatically and are skipped when no C compiler is present.
