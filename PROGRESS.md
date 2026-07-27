# Vigilance-Core — Progress & Handoff

Working notes for continuing this project. Last updated after the Tier 1–3 build-out.

Repo: `holialli/Vigilance-Core` (branch `main`). 87 tests passing (`python -m pytest tests/ -q`).

**Goal:** conversational forensics — an investigator asks questions in natural language
instead of manually hunting through artifacts. Not trying to match Autopsy's parser
coverage; competing on the AI/triage layer Autopsy doesn't have.

---

## Verification setup

Real evidence used throughout (both gitignored, sitting in the repo root):

- `Image.E01` — ~300 MB IACIS training image, Windows 7, host `IACIS-HDD-2014`.
  Carves to ~80k artifacts. **This is the good test image.**
- `C5W04_02.E01` — split image **missing its `.E02`+ segments**, so it cannot be
  opened. Errors out correctly via the existing "Split E01 Image Detected" guard.
  Not a bug; get the remaining segments if you want to use it.

Carve is slow (~5 min, longer with hashing). Run it in the background and cache the
result: carved artifacts land in `src/cache/<sha256>/artifacts.pkl`.

---

## Done

### Bug fixes (commits `b1a5566`, `5f23b99`)
- `requirements.txt` was UTF-16 → unusable by pip. The working UTF-8 copy was
  gitignored by a blanket `*.txt`. Rewrote as UTF-8, deleted the duplicate.
- Swapped unused `fpdf2` → `reportlab` (what `generate_pdf_report` actually imports).
  PDF reports were failing with "ReportLab not installed" on any fresh install.
- `.gitignore`: `!src/data/*.csv` never worked (gitignore has no trailing `#`
  comments; `data/` also matched recursively). Training CSVs are now committed, so
  `isolation_model.py` is reproducible from a clean clone.
- SAM logon counts silently dropped: regex looked for `Logons:` but the extractor
  emits `Login Count:`.
- ML train/serve skew: `EventsPerMinute` used a 50-row lookback at inference vs
  100 rows at training. Aligned to 100.
- Blank Event IDs defaulted to `0`, which collides with the real heuristic threat ID
  "Kernel Critical Event" → every such row falsely flagged. Now `-1`.
- PDF download button was wired with a pre-Gradio-6 API and silently did nothing.
- Cache-hit uploads never populated `artifact_counts`, so reopened cases lost the
  breakdown table in the PDF report.

### Session isolation (`8802cb8`)
Per-case state (`current_audit_df`, `faiss_index`, `session_log`, …) moved off module
globals onto a `CaseSession` stored per browser tab via `gr.State`. Two investigators
were previously overwriting each other's evidence. Verified with two independent
sessions against the real image.

### Package split + tests (`c1b8e4c`)
3200-line monolith → `src/forensics/` package. `chatbot_app.py` is now just the UI.
ML model and LLM clients no longer load at import time (`get_model()`,
`ensure_llm_available()`), so tests import cleanly without keys.

```
src/forensics/
  config.py       paths, HEURISTIC_THREAT_IDS, hashset paths
  session.py      CaseSession
  parsers.py      EVTX, registry hive, SHA-256, EWFImgInfo
  extractors.py   all extract_*, walk_filesystem, carve orchestrator  (1659 lines — still big)
  ml.py           engineer_features, lazy model load
  rag.py          hybrid retrieval + citations
  context.py      extract_system_context
  llm.py          Ollama → Groq → Gemini → offline chain
  reporting.py    PDF
  analysis.py     search, timeline, triage
  correlation.py  entity extraction + pivoting
  cases.py        save/load/list cases
  shimcache.py    AppCompatCache parser
  hashsets.py     hashing + known-good/bad matching
```

### Evidence citations + RAG overhaul (`42d95b6`)
- The prompt used to *forbid* citations. Now it requires inline `[E1]` tags; the UI
  appends a resolved evidence appendix (`format_citations`) showing only what was
  actually cited. This is the trust/traceability fix.
- **Retrieval was badly broken.** USB/BROWSER/PREFETCH/RECYCLE/ACTIVITY/RECENT/
  COMMUNICATION artifacts were *never indexed at all* — the chat could not cite them.
  Registry rows are 76% of the corpus and buried everything.
- Rewrote as hybrid retrieval: semantic (FAISS) + lexical + query→artifact-type
  routing, with off-target types demoted and near-duplicate rows collapsed.
  Rare types are matched lexically instead of embedded, so adding a type never
  invalidates a built index (a full re-embed is ~50 min on this CPU).

Before → after on real evidence:
| Query | Before | After |
|---|---|---|
| "USB device history" | registry noise | LEXAR JUMPDRIVE, Kingston DataTraveler (real serials) |
| "files deleted / recycle bin" | registry noise | actual RECYCLE artifacts |
| "user accounts" | ok | all 5 SAM accounts |

### Triage / Timeline / Search tabs (`8d09a1e`)
- **Triage** runs on upload, severity-ranked. Rules match Event IDs against the
  *column* and are channel-scoped — `1102` was matching `dot3svc.dll,-1102`, `4625`
  was matching a GUID, and all 26 "failed logons" were APPLICATION-channel events,
  not Security. All false positives eliminated.
- **Timeline** — daily/hourly/weekly buckets + busiest days, filterable by type.
  Fixed a mixed-timezone crash (`utc=True`).
- **Search** — substring/regex over all artifacts, type filter, invalid regex
  reported instead of crashing.
- Verified end-to-end through the running app via `gradio_client`.

### Extraction depth (`fb2cf06`)
- **ShimCache**: `extract_execution_history` was a permanent no-op stub. Now a real
  AppCompatCache parser. Found a genuine bug via real data — Win7 x64 entries pad 4
  bytes after the length WORDs; without it the parser returned 0. **Now recovers 492
  execution records** with correct paths/timestamps from `Image.E01`.
- **Deleted/orphaned files**: `_is_deleted()` checks TSK unalloc flags and the walk
  now includes `$OrphanFiles`. **Recovered 1,334 deleted entries** on the real image.
- **Hash sets** (`hashsets.py`): MD5+SHA-256 in one pass, NSRL-style loader, known-bad
  alerts / known-good suppression. Drop lists in `src/hashsets/`. Hashing is skipped
  when no sets are configured — it added ~22 min to the carve for zero benefit.
- **Correlation engine**: the `correlations` table existed but nothing ever wrote to
  it. Now extracts entities (users, USB serials, executables, domains), finds ones
  appearing across multiple artifact types, and supports pivoting. New **Leads** tab.
- **Case management** (`cases.py`): JSON manifest + artifacts per case; save/list/
  reopen without re-carving. New **Cases** tab.

### CI
`.github/workflows/tests.yml` exists **locally but is NOT pushed** — the PAT lacks
`workflow` scope, so GitHub rejects it. `.github/` is currently gitignored to stop it
being re-staged. To enable: use a token with `workflow` scope (then remove `.github/`
from `.gitignore`), or paste the file in via the GitHub web UI.

---

## Left to do

### 1. Confirm the thread-safety fix (highest priority — in flight)
**Found a real race**: a single `pytsk3` FS_Info handle was shared across 14 worker
threads. TSK handles are not thread-safe. Symptom: random `$IDX_ROOT not found`
errors and extractors *silently returning zero rows* — on one run BROWSER (49),
COMMUNICATION (19), PREFETCH (5) and RECYCLE (2) all vanished despite working
previously on the same image. Results were non-deterministic between runs.

Fix implemented: `open_fs()` + `isolated()` in `extractors.py` give every task its own
image + filesystem handle.

**A re-carve was running when this doc was written and had not finished.** Next
session: re-run and confirm BROWSER / COMMUNICATION / PREFETCH / RECYCLE all come
back, and that EXECUTION shows ~492 and DELETED ~1334.

```bash
cd src && ../.venv/Scripts/python.exe \
  <scratch>/recarve.py > /tmp/recarve.log 2>&1 &
```
(A copy of that script is in the session scratchpad; it just calls
`carve_evidence_from_image` + `engineer_features` and prints per-type counts.)

### 2. Verify Cases + Leads tabs in the live app
Both are wired and `build_gui()` succeeds, but they have **not** been driven
end-to-end yet the way Triage/Timeline/Search were. Use `gradio_client` against a
running app (see the pattern already used: `client.predict(..., api_name="/_find_leads")`).

### 3. LLM prompt change is unverified
The citation instructions in `llm.py` have never run against a live model —
**Groq key is expired, Gemini free-tier quota is exhausted, Ollama isn't installed**.
The app has been falling back to the deterministic offline summary for every query.
Fix a provider, then confirm the model actually emits `[E1]` tags and that
`format_citations` resolves them. Easiest: `ollama serve` + `llama3.2`.

### 4. The ML model is close to useless as-is
`AnomalyScore == -1` fires on **37.9% of artifacts** (27,285 / 71,900) on the real
image. It was trained on synthetic CSVs that look nothing like real registry data.
`anomaly_overview()` now reports the flag rate and warns when it's noisy, but the
real fix is retraining on features derived from actual carved images, or dropping the
statistical model and keeping only the heuristic Event-ID rules (which *do* work).

### 5. Smaller items
- `extractors.py` is still 1659 lines — split per artifact family.
- `context.py` has dead locals (`usb_str`, `run_str`) that are computed and never used.
- Carve is slow (~5 min). Now that each task has its own handle, extractors could use
  processes rather than threads.
- `prefetch` parsing only reads filenames/timestamps — no run counts from the `.pf`
  body.
- No hash sets shipped; consider documenting where to get NSRL.

---

## Gotchas

- **Don't trust a clean run.** Several bugs here only appeared against the real E01
  (ShimCache padding, mixed timezones, triage false positives, the thread race).
  Unit tests passed the whole time. Always re-carve the real image after touching
  extraction.
- Widening `EMBED_TYPES` in `rag.py` invalidates the cached FAISS index and forces a
  ~50-minute re-embed on this CPU. Use `LEXICAL_TYPES` for low-volume artifact types.
- Windows security Event IDs only mean what they're documented to mean **in the
  Security channel** — always constrain with `sources`.
- Test scripts must encode output as ASCII before printing; the Windows console
  (cp1252) crashes on emoji and some artifact text.
- The GitHub token lives in `src/.env` as `GITHUB_TOKEN` (gitignored). Push with a
  transient auth header; never write it to git config.
