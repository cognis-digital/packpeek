"""Unit tests for the packpeek SARIF/YARA/Markdown companion (sarif.py).

These exercise the pure-Python converter directly: report normalisation,
SARIF/YARA/Markdown rendering, batch aggregation, the CI gate, and the error
paths. No compiler required.
"""
from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import sarif  # noqa: E402


# --------------------------------------------------------------------------- #
# fixtures / helpers
# --------------------------------------------------------------------------- #
def packed_report(file="suspicious.exe"):
    return {
        "tool": "packpeek", "file": file, "size": 204800,
        "entropy": 7.91, "high_entropy": True, "threshold": 7.20,
        "packers": [{"name": "UPX", "offset": 336}],
        "packer_count": 1, "verdict": "packed",
    }


def clean_report(file="hello.bin"):
    return {
        "tool": "packpeek", "file": file, "size": 8192,
        "entropy": 3.10, "high_entropy": False, "threshold": 7.20,
        "packers": [], "packer_count": 0, "verdict": "clean",
    }


def likely_report(file="maybe.bin"):
    return {
        "tool": "packpeek", "file": file, "size": 65536,
        "entropy": 7.80, "high_entropy": True, "threshold": 7.20,
        "packers": [], "packer_count": 0, "verdict": "likely-packed",
    }


# --------------------------------------------------------------------------- #
# load_reports
# --------------------------------------------------------------------------- #
def test_load_reports_single_object():
    reports = sarif.load_reports(json.dumps(packed_report()))
    assert len(reports) == 1
    assert reports[0]["verdict"] == "packed"


def test_load_reports_json_array():
    raw = json.dumps([packed_report("a"), clean_report("b")])
    reports = sarif.load_reports(raw)
    assert [r["file"] for r in reports] == ["a", "b"]


def test_load_reports_ndjson():
    raw = "\n".join(json.dumps(r) for r in (packed_report("a"), clean_report("b")))
    reports = sarif.load_reports(raw)
    assert len(reports) == 2
    assert reports[1]["verdict"] == "clean"


def test_load_reports_ndjson_with_blank_lines():
    raw = f"\n{json.dumps(packed_report())}\n\n"
    reports = sarif.load_reports(raw)
    assert len(reports) == 1


def test_load_reports_empty_raises():
    with pytest.raises(json.JSONDecodeError):
        sarif.load_reports("   ")


def test_load_reports_garbage_raises():
    with pytest.raises(json.JSONDecodeError):
        sarif.load_reports("this is not json {")


# --------------------------------------------------------------------------- #
# to_sarif
# --------------------------------------------------------------------------- #
def test_sarif_packed_single_has_error_result():
    doc = sarif.to_sarif(packed_report())
    assert doc["version"] == "2.1.0"
    results = doc["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["level"] == "error"
    assert results[0]["ruleId"] == "packpeek/packed"
    assert "UPX" in results[0]["message"]["text"]
    assert results[0]["locations"][0]["physicalLocation"][
        "artifactLocation"]["uri"] == "suspicious.exe"


def test_sarif_clean_yields_no_results():
    doc = sarif.to_sarif(clean_report())
    assert doc["runs"][0]["results"] == []


def test_sarif_likely_is_warning():
    doc = sarif.to_sarif(likely_report())
    assert doc["runs"][0]["results"][0]["level"] == "warning"


def test_sarif_always_declares_rules():
    doc = sarif.to_sarif(clean_report())
    rule_ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert rule_ids == {"packpeek/packed", "packpeek/likely-packed"}


def test_sarif_batch_one_result_per_noncle_report():
    doc = sarif.to_sarif([packed_report("a"), clean_report("b"), likely_report("c")])
    results = doc["runs"][0]["results"]
    # clean report contributes no result
    assert len(results) == 2
    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for r in results}
    assert uris == {"a", "c"}


def test_sarif_dict_and_singleton_list_agree_on_results():
    from_dict = sarif.to_sarif(packed_report())["runs"][0]["results"]
    from_list = sarif.to_sarif([packed_report()])["runs"][0]["results"]
    assert from_dict == from_list


# --------------------------------------------------------------------------- #
# to_yara
# --------------------------------------------------------------------------- #
def test_yara_maps_family_to_markers():
    rule = sarif.to_yara(packed_report())
    assert "rule packpeek_UPX" in rule
    for marker in ("UPX0", "UPX1", "UPX!"):
        assert f'"{marker}"' in rule
    assert "any of them" in rule


def test_yara_no_packers_emits_placeholder():
    rule = sarif.to_yara(clean_report())
    assert "placeholder" in rule
    assert "rule packpeek_generic" in rule


def test_yara_family_name_sorted_and_deduped():
    rep = packed_report()
    rep["packers"] = [{"name": "VMProtect", "offset": 1},
                      {"name": "ASPack", "offset": 2},
                      {"name": "ASPack", "offset": 3}]
    rule = sarif.to_yara(rep)
    assert "rule packpeek_ASPack_VMProtect" in rule
    # each marker string appears exactly once
    assert rule.count('".aspack"') == 1
    assert rule.count('".vmp0"') == 1


def test_yara_batch_unions_markers():
    rule = sarif.to_yara([packed_report(), likely_report()])
    assert '"UPX0"' in rule


def test_yara_meta_reflects_worst_verdict():
    rule = sarif.to_yara([clean_report(), packed_report()])
    assert 'verdict = "packed"' in rule


# --------------------------------------------------------------------------- #
# to_markdown
# --------------------------------------------------------------------------- #
def test_markdown_has_table_and_row():
    md = sarif.to_markdown(packed_report())
    assert "| File | Verdict | Entropy | High entropy | Packers |" in md
    assert "`suspicious.exe`" in md
    assert "UPX" in md
    assert "packed" in md


def test_markdown_batch_rows_and_summary():
    md = sarif.to_markdown([packed_report("a"), clean_report("b")])
    assert "`a`" in md and "`b`" in md
    assert "Files scanned:** 2" in md
    assert "Worst verdict:** packed" in md


def test_markdown_clean_uses_dash_for_no_packers():
    md = sarif.to_markdown(clean_report())
    assert "| — |" in md


# --------------------------------------------------------------------------- #
# worst_verdict
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("reports,expected", [
    ([clean_report()], "clean"),
    ([clean_report(), likely_report()], "likely-packed"),
    ([likely_report(), packed_report()], "packed"),
    ([clean_report(), packed_report(), likely_report()], "packed"),
])
def test_worst_verdict(reports, expected):
    assert sarif.worst_verdict(reports) == expected


# --------------------------------------------------------------------------- #
# main() end-to-end via stdin/stdout
# --------------------------------------------------------------------------- #
def run_main(argv, stdin_text="", monkeypatch=None, capsys=None):
    if monkeypatch is not None:
        monkeypatch.setattr(sys, "stdin", io.StringIO(stdin_text))
    return sarif.main(argv)


def test_main_stdin_sarif(monkeypatch, capsys):
    code = run_main([], json.dumps(packed_report()), monkeypatch)
    out = capsys.readouterr().out
    assert code == 0
    doc = json.loads(out)
    assert doc["runs"][0]["results"][0]["ruleId"] == "packpeek/packed"


def test_main_stdin_yara(monkeypatch, capsys):
    code = run_main(["--yara"], json.dumps(packed_report()), monkeypatch)
    out = capsys.readouterr().out
    assert code == 0
    assert "rule packpeek_UPX" in out


def test_main_stdin_markdown(monkeypatch, capsys):
    code = run_main(["--md"], json.dumps(packed_report()), monkeypatch)
    out = capsys.readouterr().out
    assert code == 0
    assert "## packpeek report" in out


def test_main_file_argument(tmp_path, capsys):
    p = tmp_path / "r.json"
    p.write_text(json.dumps(packed_report()), encoding="utf-8")
    code = sarif.main([str(p)])
    out = capsys.readouterr().out
    assert code == 0
    assert json.loads(out)["runs"][0]["results"]


def test_main_multiple_files_aggregate(tmp_path, capsys):
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    a.write_text(json.dumps(packed_report("a")), encoding="utf-8")
    b.write_text(json.dumps(likely_report("b")), encoding="utf-8")
    code = sarif.main([str(a), str(b)])
    out = capsys.readouterr().out
    assert code == 0
    assert len(json.loads(out)["runs"][0]["results"]) == 2


def test_main_invalid_json_returns_1(monkeypatch, capsys):
    code = run_main([], "not json {", monkeypatch)
    err = capsys.readouterr().err
    assert code == 1
    assert "invalid JSON" in err


def test_main_fail_on_packed_trips(monkeypatch, capsys):
    code = run_main(["--fail-on", "packed"], json.dumps(packed_report()), monkeypatch)
    capsys.readouterr()
    assert code == 2


def test_main_fail_on_packed_passes_when_clean(monkeypatch, capsys):
    code = run_main(["--fail-on", "packed"], json.dumps(clean_report()), monkeypatch)
    capsys.readouterr()
    assert code == 0


def test_main_fail_on_likely_trips_on_likely(monkeypatch, capsys):
    code = run_main(["--fail-on", "likely-packed"], json.dumps(likely_report()), monkeypatch)
    capsys.readouterr()
    assert code == 2


def test_main_fail_on_equals_syntax(monkeypatch, capsys):
    code = run_main(["--fail-on=packed"], json.dumps(packed_report()), monkeypatch)
    capsys.readouterr()
    assert code == 2


def test_main_fail_on_invalid_level_returns_1(monkeypatch, capsys):
    code = run_main(["--fail-on", "bogus"], json.dumps(clean_report()), monkeypatch)
    err = capsys.readouterr().err
    assert code == 1
    assert "--fail-on" in err


def test_main_fail_on_does_not_change_output(monkeypatch, capsys):
    # SARIF output with the gate is identical to output without it.
    run_main([], json.dumps(packed_report()), monkeypatch)
    plain = capsys.readouterr().out
    run_main(["--fail-on", "packed"], json.dumps(packed_report()), monkeypatch)
    gated = capsys.readouterr().out
    assert plain == gated
