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
python scripts/make_heldout.py                 # regenerate held-out data
python -m toolguard.evaluate main | freeze | heldout | chart
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
5. The held-out set is never used for tuning.
6. If detector files change (`config.py`, `checks.py`, `intent.py`, `intent_data.py`, `lockfile.py`, `scoring.py`), the current held-out set is burned: write a NEW held-out set with fresh variations, then run `evaluate freeze` and `evaluate heldout`. The `heldout` command refuses to run if the detector hash differs from the freeze.
7. Report tuned (main) and held-out numbers separately and honestly.
