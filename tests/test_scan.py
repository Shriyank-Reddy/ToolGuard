"""Scoring and end-to-end scans on a small subset of the sample data."""
import json
from pathlib import Path

import pytest

from toolguard.cli import main
from toolguard.loader import load_path, load_server
from toolguard.models import Finding
from toolguard.scoring import level_for, scan_server, server_score, tool_score

DATA = Path(__file__).resolve().parent.parent / "data"


def test_levels_and_scores():
    assert level_for(0) == "Low" and level_for(3) == "Medium" and level_for(6) == "High"
    assert tool_score([]) == 0
    assert tool_score([Finding("a", "high", "t", "r")]) == 6
    # two findings from the same check count once (the worst one)
    assert tool_score([Finding("a", "high", "t", "r"), Finding("a", "medium", "t", "r")]) == 6
    assert tool_score([Finding(c, "high", "t", "r") for c in "abc"]) == 10  # capped
    assert server_score([6, 3, 0]) == 6.5


def test_end_to_end_server_scan():
    server = load_server(DATA / "servers" / "weatherly.json")
    report = scan_server(server)
    assert report.level == "High" and any(t.level == "High" for t in report.tools)
    assert all(f.reason for t in report.tools for f in t.findings)


def test_benign_subset_is_low_risk():
    labels = json.loads((DATA / "labels.json").read_text())
    for server in load_path(DATA / "servers")[:8]:
        for tool in server.tools:
            if labels[f"{server.name}/{tool.name}"] == []:
                assert scan_server(type(server)(server.name, [tool])).level != "High", tool.name


def test_cli_scan_json_and_lock_diff(tmp_path, capsys):
    src = str(DATA / "servers" / "weatherly.json")
    assert main(["scan", src, "--json"]) == 1  # High risk -> exit code 1
    assert json.loads(capsys.readouterr().out)[0]["server"] == "weatherly"
    lock = str(tmp_path / "t.lock")
    assert main(["lock", src, "-o", lock]) == 0
    assert main(["diff", src, "--lock", lock]) == 0  # unchanged


def test_bad_input_gives_error_code(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert main(["scan", str(bad)]) == 2


def test_labels_are_not_read_by_detectors():
    """Detector modules must never reference the labels files."""
    for name in ["checks", "intent", "intent_data", "lockfile", "scoring", "loader", "config"]:
        source = (Path(__file__).resolve().parent.parent / "toolguard" / f"{name}.py").read_text()
        assert "labels.json" not in source and "_labels" not in source and "data/" not in source, name
