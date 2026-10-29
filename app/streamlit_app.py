"""ToolGuard web app.  Run:  streamlit run app/streamlit_app.py"""
import html
import json
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from toolguard.checks import reveal  # noqa: E402
from toolguard.loader import parse_server  # noqa: E402
from toolguard.lockfile import create_lock  # noqa: E402
from toolguard.scoring import scan_server  # noqa: E402

BADGE = {"Low": "🟢", "Medium": "🟡", "High": "🔴"}
SEV_ICON = {"low": "🟢", "medium": "🟡", "high": "🔴"}

st.set_page_config(page_title="ToolGuard", page_icon="🛡️", layout="wide")


def highlight(text: str, evidence: list[str]) -> str:
    """HTML-escape text (invisible characters made visible) and wrap evidence in <mark>."""
    shown = reveal(text)
    spans = []
    for ev in evidence:
        ev = reveal(ev)
        start = shown.find(ev) if ev else -1
        if start >= 0:
            spans.append((start, start + len(ev)))
    out, pos = [], 0
    for start, end in sorted(spans):
        if start < pos:
            continue
        out.append(html.escape(shown[pos:start]))
        out.append(f"<mark>{html.escape(shown[start:end])}</mark>")
        pos = end
    out.append(html.escape(shown[pos:]))
    return "<div style='white-space:pre-wrap'>" + "".join(out) + "</div>"


def show_findings(tool, report):
    for location, text in tool.texts():
        evidence = [f.evidence for f in report.findings if f.location == location and f.evidence]
        if evidence:
            st.markdown(f"**{location}**")
            st.markdown(highlight(text, evidence), unsafe_allow_html=True)
    for f in report.findings:
        st.markdown(f"{SEV_ICON[f.severity]} **{f.check.replace('_', ' ')}** ({f.severity}) - {f.reason}")
        if f.check == "rug_pull" and f.evidence:
            st.code(f.evidence, language="diff")


def show_server(server, lock=None):
    report = scan_server(server, lock)
    c1, c2, c3 = st.columns(3)
    c1.metric("Server risk", f"{BADGE[report.level]} {report.level}")
    c2.metric("Score", f"{report.score:.1f} / 10")
    c3.metric("Tools flagged", sum(1 for t in report.tools if t.level != "Low"))
    by_name = {t.name: t for t in server.tools}
    for tr in sorted(report.tools, key=lambda r: -r.score):
        with st.expander(f"{BADGE[tr.level]} {tr.name} - {tr.level} ({tr.score:.0f})", expanded=tr.level != "Low"):
            if not tr.findings:
                st.write("No findings.")
            show_findings(by_name[tr.name], tr)
    for f in report.notes:
        st.info(f"{f.tool}: {f.reason}")


def sample_files(folder):
    return sorted((ROOT / folder).glob("*.json"))


# ------------------------------------------------------------------ pages
def page_scanner():
    st.title("🛡️ Scanner")
    st.write("Upload a tool-definition JSON file or pick a sample (all samples are fictional).")
    upload = st.file_uploader("Tool-definition JSON", type="json")
    sample = st.selectbox("...or pick a sample server", sample_files("data/servers"), format_func=lambda p: p.stem)
    try:
        data = json.load(upload) if upload else json.loads(sample.read_text(encoding="utf-8"))
        server = parse_server(data, upload.name if upload else str(sample))
    except (ValueError, json.JSONDecodeError) as err:
        st.error(f"Could not read that file: {err}")
        return
    st.subheader(server.name)
    show_server(server)


def page_rugpull():
    st.title("🪤 Rug-pull demo")
    st.write("A server is approved, and ToolGuard locks a fingerprint of every tool. Later the server changes. "
             "Pick a scenario to compare the locked version with the modified one.")
    path = st.selectbox("Scenario", sample_files("data/rugpull"), format_func=lambda p: p.stem)
    pair = json.loads(path.read_text(encoding="utf-8"))
    locked, modified = parse_server(pair["locked"]), parse_server(pair["modified"])
    lock = create_lock([locked])
    left, right = st.columns(2)
    left.subheader("Locked version")
    left.json(pair["locked"]["tools"][0])
    right.subheader("Modified version")
    right.json(pair["modified"]["tools"][0])
    st.caption("Whitespace, key order and version-number changes are ignored. Typo-level edits show as low severity.")
    st.subheader("What ToolGuard reports")
    show_server(modified, lock)


def page_results():
    st.title("📊 Results")
    st.markdown(
        "**About.** ToolGuard statically scans tool definitions (name, description, input schema, permissions) for "
        "tool poisoning, hidden text, data exfiltration, over-permission, look-alike names and rug pulls. "
        "All data is synthetic. The **main** set was used while building the detectors, so its numbers are *tuned* "
        "(optimistic). The **held-out** set was written after the detectors were frozen and never used for tuning, "
        "so it is the honest estimate. Both are small, so treat the numbers as indicative.")
    files = {"Main set (tuned)": ROOT / "results/results.json", "Held-out set (frozen, not tuned)": ROOT / "results/heldout_results.json"}
    for title, path in files.items():
        if not path.exists():
            st.warning(f"{path.name} not found. Run `python -m toolguard.evaluate main`.")
            continue
        res = json.loads(path.read_text())
        st.subheader(f"{title}: {res['n_tools']} tools, {res['n_malicious']} malicious")
        rows = {**res["checks"], "overall (tool level)": res["overall"]}
        st.dataframe(pd.DataFrame(rows).T[["tp", "fp", "fn", "tn", "precision", "recall", "fpr"]])
        rd = res["rug_pull_detail"]
        st.write(f"Rug pull: benign changes wrongly flagged: **{rd['benign_wrongly_flagged']}**")
        st.dataframe(pd.DataFrame(rd["benign_by_change"]).T)
    chart = ROOT / "results/comparison.png"
    if chart.exists():
        st.image(str(chart), caption="Tuned main set vs. frozen held-out set")


PAGES = {"Scanner": page_scanner, "Rug-pull demo": page_rugpull, "Results": page_results}
choice = st.sidebar.radio("Page", list(PAGES))
st.sidebar.caption("Static analysis only. Synthetic data. For defensive use.")
PAGES[choice]()
