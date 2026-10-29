# CLAUDE.md

## Goal
ToolGuard: a small, readable **static** security scanner for AI-agent tool definitions (MCP-style JSON). It is a student portfolio project, so clarity beats cleverness.

## Stack
Python 3.11+, scikit-learn (TF-IDF + logistic regression), rich (CLI), matplotlib, Streamlit, pytest. No network, no API keys, no databases.

## Commands
```bash
pip install -r requirements.txt && pip install -e .
pytest -q
toolguard scan data/servers/weatherly.json     # also: lock, diff, --json
streamlit run app/streamlit_app.py
python scripts/make_servers.py                 # regenerate main data
python scripts/make_heldout_v1.py              # v1 held-out (development set since v2)
python scripts/make_heldout_v2.py              # v2 fresh held-out
python -m toolguard.evaluate main | dev | freeze | heldout | chart
```

## File map
- `toolguard/models.py` dataclasses (Tool, Server, Finding)
- `toolguard/loader.py` JSON -> objects
- `toolguard/checks.py` checks 1-5; `intent.py` + `intent_data.py` classifier for check 1
- `toolguard/lockfile.py` check 6 (hash, lock, diff, severity policy)
- `toolguard/scoring.py` scores/levels and `scan_server`
- `toolguard/config.py` every threshold and keyword list
- `toolguard/evaluate.py` metrics, freeze guard, chart (the only code that reads labels)
- `toolguard/cli.py`, `app/streamlit_app.py` interfaces
- `scripts/` synthetic data generators; `data/` generated JSON; `results/` outputs; `docs/HOW_IT_WORKS.md`

## Rules
1. Keep it simple and readable. No new frameworks.
2. Static analysis only. Never run or connect to real MCP servers.
3. Synthetic data only, with `*.example` domains.
4. Detectors never read labels. Only `evaluate.py` does (a test enforces this).
5. A held-out set is never used for tuning. Any held-out set whose failures you looked at becomes a *development* set (the v1 held-out is one now, evaluated with `evaluate dev`).
6. If detector files change (`config.py`, `checks.py`, `intent.py`, `intent_data.py`, `lockfile.py`, `scoring.py`), the current held-out set is burned: write a NEW held-out set with fresh variations, then run `evaluate freeze` and `evaluate heldout` (which evaluates `data/heldout_v2`; for a v3, add a `heldout_v3` entry to `SETS` and a `make_heldout_v3.py` that asserts freshness against ALL earlier sets). The `heldout` command refuses to run if the detector hash differs from the freeze.
7. Report tuned (main), development (v1 held-out) and fresh held-out (v2) numbers separately and honestly; keep `results/baseline_v1_*.json` as the v1 reference.
