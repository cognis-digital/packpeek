#!/usr/bin/env python3
"""packpeek-sarif — convert packpeek JSON into SARIF, YARA, or Markdown.

Pipe packpeek's JSON in; get a SARIF report (for GitHub/GitLab code scanning),
a ready-to-deploy YARA rule that matches the same packer markers, or a compact
Markdown summary suitable for a PR comment or triage note.

The converter accepts a single packpeek report, a JSON array of reports, or
newline-delimited JSON (one report per line). When more than one report is
supplied the outputs are aggregated: SARIF gains one result per non-clean
report, YARA unions every detected marker, and Markdown renders one table row
per file.

Usage:
    packpeek file.bin | python sarif.py                 # -> SARIF on stdout
    packpeek file.bin | python sarif.py --yara          # -> YARA rule
    packpeek file.bin | python sarif.py --md            # -> Markdown summary
    python sarif.py report.json --yara
    python sarif.py a.json b.json --md                  # aggregate two reports
    packpeek f.bin | python sarif.py --fail-on packed   # exit 2 if >= packed

Options:
    --yara              emit a YARA rule instead of SARIF
    --md, --markdown    emit a Markdown summary instead of SARIF
    --sarif             emit SARIF explicitly (this is the default)
    --fail-on LEVEL     exit non-zero (2) when any report's verdict is at or
                        above LEVEL; LEVEL is one of clean, likely-packed,
                        packed. Useful for gating CI on a batch scan.

Part of the Cognis Neural Suite. Stdlib only.
"""
from __future__ import annotations

import json
import sys
from typing import Iterable, List, Union

TOOL = "packpeek"
VERSION = "1.0.0"
INFO_URI = "https://github.com/cognis-digital/packpeek"

Report = dict
Reports = Union[Report, List[Report]]

_LEVEL = {"packed": "error", "likely-packed": "warning", "clean": "note"}

# Ordered severity of the three verdicts, low to high. Used by --fail-on and to
# pick the worst verdict when aggregating a batch of reports.
_SEVERITY = {"clean": 0, "likely-packed": 1, "packed": 2}

# Map detected packer families back to their public marker strings. Shared by
# the YARA emitter so a family name round-trips to the bytes packpeek matched.
_MARKERS = {
    "UPX": ["UPX0", "UPX1", "UPX!"], "ASPack": [".aspack", ".adata"],
    "Themida": [".themida"], "WinLicense": [".winlice"],
    "MPRESS": [".MPRESS1", ".MPRESS2"], "PECompact": ["PEC2"],
    "Petite": [".petite"], "FSG": ["FSG!"], "MEW": ["MEW"],
    "NsPack": [".nsp0", ".nsp1"], "Enigma": [".enigma1"],
    "VMProtect": [".vmp0", ".vmp1"], "Armadillo": ["PDATA000"],
}


def _as_list(reports: Reports) -> List[Report]:
    """Normalise a single report or a list of reports to a list."""
    if isinstance(reports, dict):
        return [reports]
    return list(reports)


def load_reports(raw: str) -> List[Report]:
    """Parse packpeek output into a list of report dicts.

    Accepts a single JSON object, a JSON array of objects, or newline-delimited
    JSON (one object per line). Raises ``json.JSONDecodeError`` if the input is
    not valid JSON in any of those shapes.
    """
    text = raw.strip()
    if not text:
        raise json.JSONDecodeError("empty input", raw, 0)
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        # Fall back to newline-delimited JSON (a stream of report objects).
        reports: List[Report] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            reports.append(json.loads(line))  # re-raises on genuine garbage
        if not reports:
            raise
        return reports
    if isinstance(parsed, list):
        return [p for p in parsed]
    return [parsed]


def worst_verdict(reports: Reports) -> str:
    """Return the highest-severity verdict across one or more reports."""
    worst = "clean"
    for rep in _as_list(reports):
        v = rep.get("verdict", "clean")
        if _SEVERITY.get(v, 0) > _SEVERITY.get(worst, 0):
            worst = v
    return worst


def _result_for(rep: Report) -> dict:
    """Build a single SARIF result for a non-clean report."""
    verdict = rep.get("verdict", "clean")
    packers = ", ".join(p["name"] for p in rep.get("packers", [])) or "none"
    msg = f"{verdict}: entropy={rep.get('entropy')}, packers=[{packers}]"
    return {
        "ruleId": f"packpeek/{verdict}",
        "level": _LEVEL.get(verdict, "note"),
        "message": {"text": msg},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": rep.get("file", "")}
            }
        }],
    }


def to_sarif(reports: Reports) -> dict:
    """Render one or more packpeek reports as a SARIF 2.1.0 document.

    A single ``dict`` is accepted for backward compatibility and produces a run
    with at most one result. A list produces one result per non-clean report.
    """
    results = [_result_for(rep) for rep in _as_list(reports)
               if rep.get("verdict", "clean") != "clean"]
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": TOOL, "version": VERSION, "informationUri": INFO_URI,
                "rules": [
                    {"id": "packpeek/packed",
                     "shortDescription": {"text": "Packer marker + high entropy"}},
                    {"id": "packpeek/likely-packed",
                     "shortDescription": {"text": "Packer marker or high entropy"}},
                ],
            }},
            "results": results,
        }],
    }


def to_yara(reports: Reports) -> str:
    """Render a YARA rule matching every packer marker across the reports."""
    names: List[str] = []
    verdict = "unknown"
    entropy: object = 0
    for rep in _as_list(reports):
        for p in rep.get("packers", []):
            names.append(p["name"])
        # Surface the worst verdict / its entropy in the rule meta.
        v = rep.get("verdict", "unknown")
        if _SEVERITY.get(v, -1) >= _SEVERITY.get(verdict, -1):
            verdict, entropy = v, rep.get("entropy", entropy)

    strings, seen, emitted = [], 0, set()
    for name in names:
        for m in _MARKERS.get(name, []):
            if m in emitted:
                continue
            emitted.add(m)
            strings.append(f'        $s{seen} = "{m}"')
            seen += 1
    if not strings:
        strings = ['        $s0 = "UPX!"  // no packer detected; placeholder']
    body = "\n".join(strings)
    fam = "_".join(sorted(set(names))) or "generic"
    return (
        f"rule packpeek_{fam} {{\n"
        f"    meta:\n"
        f'        author = "Cognis Digital / packpeek"\n'
        f'        verdict = "{verdict}"\n'
        f'        entropy = "{entropy}"\n'
        f"    strings:\n{body}\n"
        f"    condition:\n        any of them\n"
        f"}}\n"
    )


def to_markdown(reports: Reports) -> str:
    """Render a compact Markdown summary table of one or more reports."""
    items = _as_list(reports)
    lines = [
        "## packpeek report",
        "",
        "| File | Verdict | Entropy | High entropy | Packers |",
        "| --- | --- | --- | --- | --- |",
    ]
    for rep in items:
        packers = ", ".join(p["name"] for p in rep.get("packers", [])) or "—"
        high = "yes" if rep.get("high_entropy") else "no"
        lines.append(
            f"| `{rep.get('file', '')}` | {rep.get('verdict', 'unknown')} "
            f"| {rep.get('entropy', 0)} | {high} | {packers} |"
        )
    worst = worst_verdict(items)
    lines += ["", f"**Files scanned:** {len(items)} · **Worst verdict:** {worst}"]
    return "\n".join(lines) + "\n"


def _parse_args(argv: List[str]):
    """Split argv into (mode, fail_on, positional_files)."""
    mode = "sarif"
    fail_on = None
    files: List[str] = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--yara":
            mode = "yara"
        elif a in ("--md", "--markdown"):
            mode = "md"
        elif a == "--sarif":
            mode = "sarif"
        elif a == "--fail-on":
            i += 1
            fail_on = argv[i] if i < len(argv) else None
        elif a.startswith("--fail-on="):
            fail_on = a.split("=", 1)[1]
        else:
            files.append(a)
        i += 1
    return mode, fail_on, files


def main(argv: Iterable[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    mode, fail_on, files = _parse_args(argv)

    if fail_on is not None and fail_on not in _SEVERITY:
        print(f"packpeek-sarif: --fail-on must be one of "
              f"{', '.join(_SEVERITY)}", file=sys.stderr)
        return 1

    if files:
        raw = "\n".join(
            open(f, encoding="utf-8").read() for f in files
        )
    else:
        raw = sys.stdin.read()

    try:
        reports = load_reports(raw)
    except json.JSONDecodeError as exc:
        print(f"packpeek-sarif: invalid JSON input: {exc}", file=sys.stderr)
        return 1

    if mode == "yara":
        print(to_yara(reports))
    elif mode == "md":
        print(to_markdown(reports))
    else:
        # Single report keeps the historical dict-in shape for byte-for-byte
        # backward compatibility; a batch is aggregated into one run.
        payload = reports[0] if len(reports) == 1 else reports
        print(json.dumps(to_sarif(payload), indent=2))

    if fail_on is not None:
        worst = worst_verdict(reports)
        if _SEVERITY.get(worst, 0) >= _SEVERITY[fail_on]:
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
