# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Read `PROGRESS.md` too — it is the running engineering log, and it records which
past conclusions turned out to be wrong. Several of them were expensive.

## What this is

AI Forensic Engine — a digital forensics analysis tool that ingests raw disk images (`.dd`/`.raw`/`.E01`),
carves artifacts (EVTX logs, registry hives, filesystem metadata, browser/user activity, USB/prefetch/SRUM),
scores them with an Isolation Forest anomaly model, indexes them with FAISS for retrieval, and answers
natural-language investigator questions via an LLM (Gemini/Groq/Ollama) grounded in the retrieved evidence.

The UI is a single Gradio app (`src/chatbot_app.py`, ~840 lines). **Everything else lives in the
`src/forensics/` package** — the 3,200-line monolith was split in `c1b8e4c`, and any guidance describing
one big file is out of date.

## Running the app

```bash
python src/chatbot_app.py
```

Opens a Gradio app on `http://localhost:7860`. Upload a `.dd`/`.raw`/`.E01` image via the UI, wait for
carving + FAISS index build, then use the "AI Investigation" chat, "Dashboard & Summary", or "Raw Artifacts" tabs.

Requires `src/.env` with at least one LLM configured. `forensics.llm.ensure_llm_available()` raises
`RuntimeError` **at app startup, not at import** (deliberately — tests import the package with no keys
present) if none of `GEMINI_API_KEY`, `GROQ_API_KEY`, or a reachable local Ollama (`OLLAMA_BASE_URL`,
default `http://localhost:11434`) is available. Copy `.env.example` to `src/.env` to configure.

```bash
python -m pytest tests/ -q     # 146 tests
```

## Installing dependencies

```bash
pip install -r requirements.txt
```

Native forensic dependencies (`pytsk3` for SleuthKit filesystem parsing, `libewf-python` for `.E01` support)
are part of `requirements.txt` but may need OS-level libraries; see README.md Dependencies section for
platform notes (Windows recommended; Linux supported; macOS partial).

## Training the anomaly model

```bash
cd src && python isolation_model.py
```

Trains on **real carved artifacts** — every `src/cache/*/artifacts.pkl` on the machine — and writes
`src/models/forensic_alarm_v2.pkl`. The app only ever *loads* that pickle; it never trains. Run this first
on a fresh checkout if the pickle is missing.

Features come from `forensics.ml.compute_features`, which the training script **imports rather than
reimplements**. Do not add a second copy of that arithmetic: the last train/serve skew was a 50-row
lookback at inference against 100 in training, and neither file looked wrong on its own.

If no carve is cached it falls back to the synthetic CSVs in `src/data/` with a loud warning. That
fallback is a last resort, not a normal path — a model trained only on those CSVs flagged **37% of a real
image**, because a real registry hive looks nothing like a synthetic event log. Regenerate the CSVs with
`src/scripts/generate_demo_logs.py` and `src/scripts/generate_registry_data.py`.

There is deliberately **no synthetic threat injection**. It used to add 50 copies each of seven "threat"
patterns to the training set; an Isolation Forest calls *sparse* regions anomalous, so tight clusters of a
pattern teach it that the pattern is normal — the opposite of the intent. Known-bad Event IDs are handled
deterministically by `HEURISTIC_THREAT_IDS` in `config.py`, which is the right mechanism for them.

## Architecture

```
src/chatbot_app.py    Gradio UI only: handle_image_upload(), build_gui(), event wiring
src/forensics/
  config.py       paths, HEURISTIC_THREAT_IDS, hashset paths
  session.py      CaseSession — all per-case state
  parsers.py      EVTX, registry hive, SHA-256, EWFImgInfo
  extractors.py   all extract_*, walk_filesystem, carve orchestrator  (~2,070 lines)
  ml.py           compute_features / engineer_features, lazy model load
  rag.py          hybrid retrieval + citations, FAISS index build
  embedding.py    sentence embedding; bulk encode isolated in a subprocess
  context.py      extract_system_context
  llm.py          Ollama → Groq → Gemini → offline chain
  reporting.py    PDF
  analysis.py     search, timeline, triage, anomaly_overview
  correlation.py  entity extraction + pivoting
  cases.py        save/load/list cases
  shimcache.py    AppCompatCache parser
  hashsets.py     hashing + known-good/bad matching
  recyclebin.py   INFO2 (XP) and $I (Vista+) record parsers
```

**Session state.** Per-case state (`current_audit_df`, `faiss_index`, `image_hash_sha256`,
`artifact_counts`, `cached_system_facts`, `index_error`, `session_log`) lives on a `CaseSession`, one per
browser session via `gr.State(value=CaseSession)` — **not** module globals, so concurrent investigators
don't clobber each other's case. Functions that need it take a `session: CaseSession` parameter, and every
Gradio handler in `build_gui()` has `session_state` in its `inputs=[...]`.

**Carving.** `carve_evidence_from_image()` in `extractors.py` opens the image with `pytsk3` (raw) or
`pyewf` via the `EWFImgInfo` adapter (`.E01`, all segments), probes partition offsets, builds one shared
path index, then runs ~16 `extract_*`/`walk_filesystem` functions — **serially by default**
(`CARVE_MAX_WORKERS=1`). Threading was measured and it both loses on speed and silently drops evidence;
see PROGRESS.md item 1 before reaching for a thread pool again. Extractors carry `FIX-N` comments naming
specific past bugs — read the referenced fix before modifying one.

**Retrieval.** `build_rag_context()` embeds only `EVTX/REGISTRY/SAM/SOFTWARE` rows (`EMBED_TYPES`) via
`all-MiniLM-L6-v2`; low-volume high-value types (`LEXICAL_TYPES`: USB, BROWSER, PREFETCH, RECYCLE, …) are
scanned lexically on every query instead, so adding one never invalidates a built index. Retrieval is
hybrid: semantic + lexical + query→artifact-type routing. `query_llm()` builds a grounded system prompt
and requires inline `[E1]` citations, which the UI resolves into an evidence appendix.

### LLM fallback chain

`query_llm()` tries providers in fixed priority order and falls through on failure/absence:
**Ollama (local) → Groq (cloud) → Gemini (cloud) → deterministic offline summary**
(`build_offline_response()`, system facts + raw evidence, no LLM). Any subset may be configured.

### Caching

Per-image-hash, under `src/cache/<sha256>/`:

- `artifacts.pkl` — carved DataFrame; a repeat upload of the same image skips extraction entirely.
- `faiss.index` — vector index, rebuilt if its vector count doesn't match the current filtered set.
- `embed_chunks/` — partial encode output, so an index build that fails resumes instead of restarting.
  Carries a fingerprint of the text set and chunk size; stale chunks are discarded rather than reused.

`src/cache/embedding_cache.pkl` (14 MB) is **orphaned** — no code references it. It predates the package
split. Left in place rather than deleted, but do not treat it as a live cache.

### Memory: read this before debugging a crash in the index build

The encode step runs in a **child process** because a native crash there would otherwise take the Gradio
server down, and `except Exception` cannot catch one. On a Windows box with no page file the commit limit
is physical RAM, and an encode child at the old `batch_size=256` peaked at 2,871 MB — more than was free.

**A `0xC0000005` with no traceback from an encode child is an out-of-memory until proven otherwise.** Check
`GlobalMemoryStatusEx().ullAvailPageFile`, not free RAM; they differed by 3 GB on this machine. Three
sessions were spent attributing these to mixed OpenMP runtimes. Tuning knobs: `FORENSICS_EMBED_BATCH` (32,
this is the one that sets peak memory), `FORENSICS_EMBED_CHUNK` (500, resumption granularity only),
`FORENSICS_EMBED_IN_PROCESS=1` to disable subprocessing. Don't run anything heavy alongside a build.

Also: `.venv/Scripts/python.exe` is a redirector stub that spawns the real interpreter as a separate
process, so `Popen.pid` is **not** the process doing the work. Per-process probes aimed at it measure ~1 MB.
