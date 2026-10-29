"""Measure the detectors against ground-truth labels.

This is the ONLY module that reads label files. Usage:
    python -m toolguard.evaluate main       # tuned set        -> results/results.json
    python -m toolguard.evaluate dev        # v1 held-out (development) -> results/heldout_v1_results.json
    python -m toolguard.evaluate freeze     # record a hash of the detector code
    python -m toolguard.evaluate heldout    # v2 fresh held-out -> results/heldout_v2_results.json
    python -m toolguard.evaluate chart      # results/comparison.png
"""
import hashlib
import json
import sys
from pathlib import Path

from .checks import CHECKS, run_static_checks
from .loader import load_path, parse_server
from .lockfile import create_lock
from .scoring import scan_server

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"
FREEZE_FILE = RESULTS / "detector_freeze.txt"
DETECTOR_FILES = ["config.py", "checks.py", "intent.py", "intent_data.py", "lockfile.py", "scoring.py"]

SETS = {
    "main": dict(servers="data/servers", labels="data/labels.json", pairs="data/rugpull",
                 pair_labels="data/rugpull_labels.json", out="results.json",
                 title="Main (tuned)"),
    # The v1 held-out set was used to find v1's weaknesses, so since v2 it is a DEVELOPMENT set.
    "heldout_v1": dict(servers="data/heldout_v1", labels="data/heldout_v1_labels.json", pairs="data/heldout_v1_rugpull",
                       pair_labels="data/heldout_v1_rugpull_labels.json", out="heldout_v1_results.json",
                       title="v1 held-out (now development)"),
    # Written after the v2 freeze and never tuned on.
    "heldout_v2": dict(servers="data/heldout_v2", labels="data/heldout_v2_labels.json", pairs="data/heldout_v2_rugpull",
                       pair_labels="data/heldout_v2_rugpull_labels.json", out="heldout_v2_results.json",
                       title="v2 fresh held-out (never tuned)"),
}
BENIGN_CHANGES = ("reformat", "whitespace", "version_bump", "typo_fix", "punctuation_fix")


def detector_hash() -> str:
    h = hashlib.sha256()
    for name in DETECTOR_FILES:
        h.update((ROOT / "toolguard" / name).read_bytes())
    return h.hexdigest()


def metrics(tp: int, fp: int, fn: int, tn: int) -> dict:
    """precision = TP/(TP+FP); recall = TP/(TP+FN); false positive rate = FP/(FP+TN)."""
    def ratio(a, b):
        return round(a / b, 3) if b else None
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": ratio(tp, tp + fp), "recall": ratio(tp, tp + fn), "fpr": ratio(fp, fp + tn)}


def evaluate_static(servers_dir, labels_path) -> dict:
    labels = json.loads(Path(labels_path).read_text())
    counts = {c: [0, 0, 0, 0] for c in CHECKS}  # tp, fp, fn, tn
    overall = [0, 0, 0, 0]
    false_positives, misses = [], []
    n_tools = 0
    for server in load_path(servers_dir):
        for tool in server.tools:
            key = f"{server.name}/{tool.name}"
            truth = set(labels[key])  # ground truth is only used here, after detection
            predicted = {f.check for f in run_static_checks(tool) if f.is_flag}
            n_tools += 1
            for check in CHECKS:
                hit, real = check in predicted, check in truth
                counts[check][0 if hit and real else 1 if hit else 2 if real else 3] += 1
                if hit and not real:
                    false_positives.append(f"{key} [{check}]")
                elif real and not hit:
                    misses.append(f"{key} [{check}]")
            idx = (0 if truth else 1) if predicted else (2 if truth else 3)
            overall[idx] += 1
    result = {c: metrics(*v) for c, v in counts.items()}
    return {"n_tools": n_tools, "n_malicious": sum(1 for v in labels.values() if v),
            "checks": result, "overall": metrics(*overall),
            "false_positives": false_positives, "misses": misses}


def evaluate_rug_pull(pairs_dir, labels_path) -> dict:
    """Each pair = a locked server and a modified copy. Malicious changes should be flagged."""
    labels = json.loads(Path(labels_path).read_text())
    tp = fp = fn = tn = 0
    benign = {c: {"n": 0, "ignored": 0, "shown_low": 0, "wrongly_flagged": 0} for c in BENIGN_CHANGES}
    missed, false_alarms = [], []
    for path in sorted(Path(pairs_dir).glob("*.json")):
        pair = json.loads(path.read_text())
        info = labels[pair["id"]]
        lock = create_lock([parse_server(pair["locked"])])
        report = scan_server(parse_server(pair["modified"]), lock)
        rug = [f for t in report.tools for f in t.findings if f.check == "rug_pull"] + report.notes
        flagged = any(f.is_flag for f in rug)
        if info["malicious"]:
            tp, fn = tp + flagged, fn + (not flagged)
            if not flagged:
                missed.append(f"{pair['id']} ({info['change']})")
        else:
            fp, tn = fp + flagged, tn + (not flagged)
            row = benign[info["change"]]
            row["n"] += 1
            row["wrongly_flagged" if flagged else ("shown_low" if rug else "ignored")] += 1
            if flagged:
                false_alarms.append(f"{pair['id']} ({info['change']})")
    return {"n_pairs": tp + fp + fn + tn, **metrics(tp, fp, fn, tn),
            "benign_wrongly_flagged": f"{fp} of {fp + tn}",
            "benign_by_change": benign, "missed": missed, "false_alarms": false_alarms}


def evaluate_set(name: str) -> dict:
    cfg = SETS[name]
    static = evaluate_static(ROOT / cfg["servers"], ROOT / cfg["labels"])
    rug = evaluate_rug_pull(ROOT / cfg["pairs"], ROOT / cfg["pair_labels"])
    static["checks"]["rug_pull"] = {k: rug[k] for k in ("tp", "fp", "fn", "tn", "precision", "recall", "fpr")}
    pooled = [sum(c[k] for c in static["checks"].values()) for k in ("tp", "fp", "fn", "tn")]
    result = {"set": name, "detector_hash": detector_hash(), **static,
              "pooled_all_checks": metrics(*pooled), "rug_pull_detail": rug}
    RESULTS.mkdir(exist_ok=True)
    (RESULTS / cfg["out"]).write_text(json.dumps(result, indent=2) + "\n")
    return result


def print_table(result: dict) -> None:
    print(f"\n== {result['set']}: {result['n_tools']} tools ({result['n_malicious']} malicious) ==")
    print(f"{'check':22}{'TP':>4}{'FP':>4}{'FN':>4}{'TN':>5}{'prec':>8}{'recall':>8}{'FPR':>8}")
    rows = dict(result["checks"], **{"OVERALL (tool level)": result["overall"]})
    for name, m in rows.items():
        f = lambda v: "n/a" if v is None else f"{v:.2f}"  # noqa: E731
        print(f"{name:22}{m['tp']:>4}{m['fp']:>4}{m['fn']:>4}{m['tn']:>5}{f(m['precision']):>8}{f(m['recall']):>8}{f(m['fpr']):>8}")
    rd = result["rug_pull_detail"]
    print(f"rug pull: benign changes wrongly flagged = {rd['benign_wrongly_flagged']}; by type = {rd['benign_by_change']}")
    print("false positives:", result["false_positives"][:12], "| false alarms (rug):", rd["false_alarms"])
    print("misses:", result["misses"][:12], "| missed rug pulls:", rd["missed"])


def make_chart() -> Path:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    runs = [("results.json", "#2a6fbb"), ("heldout_v1_results.json", "#8a8a8a"), ("heldout_v2_results.json", "#e0832b")]
    loaded = [(json.loads((RESULTS / f).read_text()), color) for f, color in runs]
    titles = [cfg["title"] for cfg in SETS.values()]
    names = list(loaded[0][0]["checks"]) + ["overall"]
    get = lambda r, n, k: (r["overall"] if n == "overall" else r["checks"][n])[k]  # noqa: E731
    fig, axes = plt.subplots(1, 3, figsize=(16, 4.8), sharey=True)
    width = 0.27
    for ax, (key, title) in zip(axes, [("precision", "Precision (higher is better)"),
                                       ("recall", "Recall (higher is better)"),
                                       ("fpr", "False positive rate (lower is better)")]):
        for j, ((res, color), label) in enumerate(zip(loaded, titles)):
            vals = [get(res, n, key) for n in names]
            xs = [i + (j - 1) * width for i in range(len(names))]
            ax.bar(xs, [v or 0 for v in vals], width, color=color, label=label)
            for x, v in zip(xs, vals):
                ax.text(x, (v or 0) + 0.02, "n/a" if v is None else f"{v:.2f}", ha="center", fontsize=6)
        ax.set_xticks(range(len(names)), [n.replace("_", "\n") for n in names], fontsize=7)
        ax.set_title(title, fontsize=10)
        ax.set_ylim(0, 1.12)
        ax.spines[["top", "right"]].set_visible(False)
    handles, labels_ = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels_, loc="upper right", ncol=3, fontsize=9, frameon=False)
    fig.suptitle("ToolGuard v2: tuned vs. development vs. fresh held-out", fontsize=12)
    fig.tight_layout()
    out = RESULTS / "comparison.png"
    fig.savefig(out, dpi=130)
    return out


def main(argv=None) -> int:
    cmd = (argv or sys.argv[1:] or ["main"])[0]
    if cmd == "main":
        print_table(evaluate_set("main"))
    elif cmd == "dev":
        print_table(evaluate_set("heldout_v1"))
    elif cmd == "freeze":
        RESULTS.mkdir(exist_ok=True)
        FREEZE_FILE.write_text(detector_hash() + "\n")
        print("froze detectors:", detector_hash()[:16])
    elif cmd == "heldout":
        frozen = FREEZE_FILE.read_text().strip() if FREEZE_FILE.exists() else None
        if frozen != detector_hash():
            print("Detectors changed after the freeze (or were never frozen). Run `freeze`, and if rules changed, "
                  "regenerate the held-out set first (see CLAUDE.md).")
            return 1
        print_table(evaluate_set("heldout_v2"))
    elif cmd == "chart":
        print("wrote", make_chart())
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
