"""End-to-end tests for the compiled packpeek binary.

These build packpeek.c (via the ``packpeek_bin`` session fixture) and exercise
the real command: verdicts, exit codes, entropy, marker offsets, the
``--threshold`` flag, and error handling. They are skipped automatically when
no C compiler is available.
"""
from __future__ import annotations

import json
import os
import subprocess

import pytest


def run(binary, *args):
    proc = subprocess.run([binary, *args], capture_output=True, text=True)
    return proc


def make_packed(path):
    """A file with UPX markers followed by high-entropy random bytes."""
    with open(path, "wb") as fh:
        fh.write(b"UPX0UPX1UPX!")
        fh.write(os.urandom(8192))


def make_clean(path):
    """A low-entropy file with no packer markers."""
    with open(path, "wb") as fh:
        fh.write(b"A" * 8192)


def test_packed_sample_verdict_and_exit(packpeek_bin, tmp_path):
    sample = tmp_path / "sample.bin"
    make_packed(sample)
    proc = run(packpeek_bin, str(sample))
    assert proc.returncode == 2, proc.stderr
    rep = json.loads(proc.stdout)
    assert rep["verdict"] == "packed"
    assert rep["high_entropy"] is True
    assert rep["tool"] == "packpeek"
    names = {p["name"] for p in rep["packers"]}
    assert "UPX" in names


def test_packed_offset_points_at_marker(packpeek_bin, tmp_path):
    sample = tmp_path / "off.bin"
    with open(sample, "wb") as fh:
        fh.write(b"\x00" * 100)
        fh.write(b"UPX!")
        fh.write(os.urandom(8192))
    proc = run(packpeek_bin, str(sample))
    rep = json.loads(proc.stdout)
    upx = [p for p in rep["packers"] if p["name"] == "UPX"][0]
    assert upx["offset"] == 100


def test_clean_sample_verdict_and_exit(packpeek_bin, tmp_path):
    clean = tmp_path / "clean.bin"
    make_clean(clean)
    proc = run(packpeek_bin, str(clean))
    assert proc.returncode == 0, proc.stderr
    rep = json.loads(proc.stdout)
    assert rep["verdict"] == "clean"
    assert rep["high_entropy"] is False
    assert rep["packer_count"] == 0


def test_marker_without_high_entropy_is_likely_packed(packpeek_bin, tmp_path):
    # Low-entropy body but a real marker -> "likely-packed", exit 2.
    sample = tmp_path / "marker.bin"
    with open(sample, "wb") as fh:
        fh.write(b".themida")
        fh.write(b"A" * 8192)
    proc = run(packpeek_bin, str(sample))
    assert proc.returncode == 2, proc.stderr
    rep = json.loads(proc.stdout)
    assert rep["verdict"] == "likely-packed"
    assert rep["high_entropy"] is False
    assert {p["name"] for p in rep["packers"]} == {"Themida"}


def test_high_entropy_without_marker_is_likely_packed(packpeek_bin, tmp_path):
    sample = tmp_path / "rand.bin"
    with open(sample, "wb") as fh:
        fh.write(os.urandom(16384))
    proc = run(packpeek_bin, str(sample))
    assert proc.returncode == 2, proc.stderr
    rep = json.loads(proc.stdout)
    # High entropy alone is enough to be non-clean. (A random buffer can, very
    # rarely, contain a short marker byte-sequence; don't assert on its absence.)
    assert rep["high_entropy"] is True
    assert rep["verdict"] in ("likely-packed", "packed")


def test_threshold_flag_flips_high_entropy(packpeek_bin, tmp_path):
    clean = tmp_path / "clean.bin"
    make_clean(clean)
    # 'A'*8192 has entropy 0; a threshold of 0 forces high_entropy true.
    proc = run(packpeek_bin, str(clean), "--threshold", "0")
    rep = json.loads(proc.stdout)
    assert rep["threshold"] == 0.0
    assert rep["high_entropy"] is True
    assert rep["verdict"] == "likely-packed"
    assert proc.returncode == 2


def test_missing_file_errors(packpeek_bin, tmp_path):
    proc = run(packpeek_bin, str(tmp_path / "does-not-exist.bin"))
    assert proc.returncode == 1
    assert "cannot open" in proc.stderr


def test_no_input_file_errors(packpeek_bin):
    proc = run(packpeek_bin)
    assert proc.returncode == 1
    assert "no input file" in proc.stderr


def test_help_exits_zero(packpeek_bin):
    proc = run(packpeek_bin, "--help")
    assert proc.returncode == 0
    assert "usage" in proc.stderr


def test_packer_families_deduped(packpeek_bin, tmp_path):
    # Multiple UPX markers collapse to a single UPX entry.
    sample = tmp_path / "dup.bin"
    with open(sample, "wb") as fh:
        fh.write(b"UPX0 UPX1 UPX! .aspack")
        fh.write(os.urandom(8192))
    proc = run(packpeek_bin, str(sample))
    rep = json.loads(proc.stdout)
    names = [p["name"] for p in rep["packers"]]
    assert names.count("UPX") == 1
    assert "ASPack" in names


def test_output_is_valid_json_schema(packpeek_bin, tmp_path):
    sample = tmp_path / "s.bin"
    make_packed(sample)
    rep = json.loads(run(packpeek_bin, str(sample)).stdout)
    for key in ("tool", "file", "size", "entropy", "high_entropy",
                "threshold", "packers", "packer_count", "verdict"):
        assert key in rep


def test_end_to_end_pipe_into_sarif(packpeek_bin, tmp_path, sarif_module):
    sample = tmp_path / "s.bin"
    make_packed(sample)
    raw = run(packpeek_bin, str(sample)).stdout
    reports = sarif_module.load_reports(raw)
    doc = sarif_module.to_sarif(reports[0])
    assert doc["runs"][0]["results"][0]["ruleId"] == "packpeek/packed"
