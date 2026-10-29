# ToolGuard — Build Plan

Static security scanner for AI-agent tool definitions (MCP-style JSON).
It never connects to a server; it only reads JSON files.

## 1. Architecture

```
 JSON server file(s) ──► loader ──► Server/Tool objects
                                         │
        ┌────────────────────────────────┼─────────────────────────────┐
        ▼                                ▼                             ▼
   checks.py (rule checks)         intent.py (TF-IDF +          lockfile.py
   1 hidden_instructions           logistic regression)         fingerprint, lock, diff
   2 obfuscation                   used by check 1              → check 6 rug_pull
   3 exfiltration
   4 over_permission
   5 lookalike
        └──────────────► Findings ◄───────────────────────────────────┘
                              │
                         scoring.py  → tool score + server score (Low/Medium/High)
                              │
              ┌───────────────┼────────────────┐
              ▼               ▼                ▼
           cli.py        evaluate.py     app/streamlit_app.py
         (rich output,   (metrics vs      (3 pages)
          JSON report)    labels file)
```

Key rule: **detectors never import or read labels**. Only `evaluate.py` reads them.

## 2. Input format (modeled on MCP)

```json
{
  "server": "weatherly",
  "version": "1.0.0",
  "tools": [
    {
      "name": "get_forecast",
      "description": "Returns a 5-day forecast for a city.",
      "inputSchema": {"type": "object",
        "properties": {"city": {"type": "string", "description": "City name"}},
        "required": ["city"]},
      "permissions": ["network:read"]
    }
  ]
}
```
`permissions` is our own simple extension (MCP has no standard field):
values like `network:read`, `network:write`, `file:read`, `file:write`, `shell:exec`, `env:read`, `email:send`, `browser:control`.

## 3. File structure

```
data/servers/*.json            ~30 synthetic servers (~120 tools)
data/heldout/*.json            ~25 tools, generated only at M6
data/labels.json               ground truth: {"server/tool": ["check_id", ...]}  ([] = benign)
data/heldout_labels.json
toolguard/                     package
  config.py     thresholds, weights, keyword lists, well-known tool names
  models.py     dataclasses: Tool, Server, Finding
  loader.py     read file/folder -> Server objects
  checks.py     checks 1-5 (+ run_all_checks)
  intent.py     train/load classifier, predict "hidden instruction" probability
  intent_data.py  ~150 own synthetic training sentences (never from eval tools)
  lockfile.py   normalize, hash, lock, diff (check 6)
  scoring.py    findings -> scores/levels
  evaluate.py   precision / recall / FPR per check and overall, chart
  cli.py        toolguard scan | lock | diff
scripts/make_servers.py        builds data/servers + labels.json (seeded, deterministic)
scripts/make_heldout.py        builds data/heldout + labels; asserts phrasing not in training set
app/streamlit_app.py
tests/
results/                       results.json, heldout_results.json, comparison.png
docs/HOW_IT_WORKS.md
README.md CLAUDE.md PLAN.md requirements.txt pyproject.toml
```

## 4. Checks and scoring

| id | check | method |
|----|-------|--------|
| `hidden_instructions` | commands aimed at the AI in tool/param descriptions | regex phrases ("before using any tool", "do not tell the user", "ignore previous") + classifier probability above threshold |
| `obfuscation` | hidden text | zero-width/bidi chars, HTML comments, long base64-like blobs, runs of whitespace/newlines |
| `exfiltration` | data leaving | suspicious param names (notes/context/metadata) whose descriptions mention secrets/files/history, plus URLs in descriptions (non-`*.example` allowed only if tool declares network) |
| `over_permission` | too many privileges | map tool purpose (keywords in name/description) → allowed permission set; extras are flagged |
| `lookalike` | impersonation | normalized Levenshtein/difflib ratio vs well-known names (exact match allowed only on a known-good list), homoglyph/leet normalization, descriptions that say "instead of"/"override the X tool" |
| `rug_pull` | change since lock | SHA-256 of canonical (sorted-key, whitespace-normalized) JSON per tool; diff vs `toolguard.lock.json` |

Scoring: each finding has severity weight (low 1, medium 3, high 5) × confidence. Tool score = sum (capped at 10) → Low <3, Medium 3–6, High ≥6. Server score = max tool score plus a small bonus for the number of risky tools. Every finding carries a plain-English `reason` and the `evidence` snippet (used for highlighting).

A tool counts as "flagged" for a check when that check produces a finding. For overall metrics: tool flagged if any finding (rug_pull excluded from the static eval, since it needs a lock; it's evaluated separately on a mutated-copy test).

## 5. Data plan (synthetic, fictional, `*.example` domains)

- `make_servers.py`: seeded RNG, templates of ~40 benign tool archetypes (weather, calc, notes, file reader, URL fetcher, git helper, etc.). ~60% benign, including tricky ones: long descriptions, legit file/network access, "always/must" used normally ("Dates must be ISO-8601").
- ~40% malicious across checks 1–5 (some tools carry two labels). Rug pull is tested using lock + mutated copies (generated in the evaluator/tests), not static files.
- Classifier training sentences live in `intent_data.py`, written independently from the generator's templates. The generator asserts no exact training sentence appears in data. Held-out generator additionally asserts word-trigram overlap (Jaccard) with training sentences is below a cutoff.

## 6. Evaluation

- Per-check and overall precision, recall, FPR on main set (tuned) → `results/results.json`.
- After M5, **freeze** `config.py` + `checks.py` + `intent_data.py` (record a hash of them in the heldout results to prove it). Generate held-out (~25 tools, new phrasing/obfuscation/look-alikes/permission combos), evaluate once → `results/heldout_results.json`. Chart main vs held-out → `results/comparison.png`.
- If any detector changes after that, the held-out set is regenerated (documented in CLAUDE.md).
- Expect held-out recall to be lower than tuned; I report that honestly.

## 7. Streamlit (3 pages)

1. Scanner — upload JSON or pick sample; server badge, per-tool findings, evidence highlighted via HTML `<mark>`.
2. Rug-pull demo — sample server, locked vs modified (modification done in memory), unified diff + findings.
3. Results — About blurb, metrics tables, comparison chart.

## 8. Milestones (one commit each)

- M1 setup, models, data format, generator, labels
- M2 loader, checks 1–3, classifier
- M3 checks 4–6, scoring
- M4 CLI (`rich` for color, `--json`)
- M5 evaluation + chart on main set
- M6 freeze, held-out generation, separate eval
- M7 Streamlit app
- M8 tests, README (real numbers), HOW_IT_WORKS.md, CLAUDE.md, PR into main

## 9. Dependencies (pinned in requirements.txt, installed once with `pip install -q`)

`scikit-learn`, `matplotlib`, `streamlit`, `rich`, `pytest`. (Edit distance uses stdlib `difflib` plus a small hand-written Levenshtein — no extra package.) No torch, no network calls.

## 10. Assumptions / simplest-option decisions

- `permissions` field is a ToolGuard extension; absent means "none declared".
- Rug-pull checking is per-tool by `server/tool` key; added/removed tools are reported too.
- Lockfile hashes the fields name, description, inputSchema, permissions only (not version).
- Classifier is trained at import/first use from `intent_data.py` (tiny, <1 s), so no model file to commit.
- Held-out set is small (~25 tools), so its metrics are noisy; README says so.
- Scores are heuristic, not calibrated probabilities.
- Target size ~1,800 lines of code (excluding generated data and docs).
- PR is opened with the GitHub MCP tools (no `gh`), after all work is pushed to `claude/adoring-bohr-r4ni7j`.

**Waiting for your approval before building.**
