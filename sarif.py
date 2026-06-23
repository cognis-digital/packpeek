#!/usr/bin/env python3
"""packpeek-sarif — convert packpeek JSON into SARIF or a YARA rule.

Pipe packpeek's JSON in; get a SARIF report (for GitHub/GitLab code scanning)
or a ready-to-deploy YARA rule that matches the same packer markers.

Usage:
    packpeek file.bin | python sarif.py            # -> SARIF on stdout
    packpeek file.bin | python sarif.py --yara      # -> YARA rule on stdout
    python sarif.py report.json --yara

Part of the Cognis Neural Suite. Stdlib only.
"""
from __future__ import annotations

import json
import sys

TOOL = "packpeek"
VERSION = "1.0.0"
INFO_URI = "https://github.com/cognis-digital/packpeek"

_LEVEL = {"packed": "error", "likely-packed": "warning", "clean": "note"}


def to_sarif(rep: dict) -> dict:
    verdict = rep.get("verdict", "clean")
    level = _LEVEL.get(verdict, "note")
    results = []
    if verdict != "clean":
        packers = ", ".join(p["name"] for p in rep.get("packers", [])) or "none"
        msg = (f"{verdict}: entropy={rep.get('entropy')}, "
               f"packers=[{packers}]")
        results.append({
            "ruleId": f"packpeek/{verdict}",
            "level": level,
            "message": {"text": msg},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": rep.get("file", "")}
                }
            }],
        })
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


def to_yara(rep: dict) -> str:
    names = [p["name"] for p in rep.get("packers", [])]
    # Map detected packer families back to their public marker strings.
    markers = {
        "UPX": ["UPX0", "UPX1", "UPX!"], "ASPack": [".aspack", ".adata"],
        "Themida": [".themida"], "WinLicense": [".winlice"],
        "MPRESS": [".MPRESS1", ".MPRESS2"], "PECompact": ["PEC2"],
        "Petite": [".petite"], "FSG": ["FSG!"], "MEW": ["MEW"],
        "NsPack": [".nsp0", ".nsp1"], "Enigma": [".enigma1"],
        "VMProtect": [".vmp0", ".vmp1"], "Armadillo": ["PDATA000"],
    }
    strings, seen = [], 0
    for name in names:
        for m in markers.get(name, []):
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
        f'        verdict = "{rep.get("verdict", "unknown")}"\n'
        f'        entropy = "{rep.get("entropy", 0)}"\n'
        f"    strings:\n{body}\n"
        f"    condition:\n        any of them\n"
        f"}}\n"
    )


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    yara = "--yara" in argv
    argv = [a for a in argv if a != "--yara"]
    raw = open(argv[0], encoding="utf-8").read() if argv else sys.stdin.read()
    try:
        rep = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"packpeek-sarif: invalid JSON input: {exc}", file=sys.stderr)
        return 1
    print(to_yara(rep) if yara else json.dumps(to_sarif(rep), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
