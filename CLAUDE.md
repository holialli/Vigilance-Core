# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

AI Forensic Engine — a digital forensics analysis tool that ingests raw disk images (`.dd`/`.raw`/`.E01`),
carves artifacts (EVTX logs, registry hives, filesystem metadata, browser/user activity, USB/prefetch/SRUM),
scores them with an Isolation Forest anomaly model, indexes them with FAISS for retrieval, and answers
natural-language investigator questions via an LLM (Gemini/Groq/Ollama) grounded in the retrieved evidence.
The UI is a single Gradio app. Nearly all application logic lives in one file: `src/chatbot_app.py` (~3200 lines).

## Running the app

```bash
python src/chatbot_app.py
```

Opens a Gradio app on `http://localhost:7860`. Upload a `.dd`/`.raw`/`.E01` image via the UI, wait for
carving + FAISS index build, then use the "AI Investigation" chat, "Dashboard & Summary", or "Raw Artifacts" tabs.

Requires `src/.env` with at least one LLM configured — the app raises `RuntimeError` at import time
(`chatbot_app.py` line ~151) if none of `GEMINI_API_KEY`, `GROQ_API_KEY`, or a reachable local Ollama
(`OLLAMA_BASE_URL`, default `http://localhost:11434`) is available. Copy `.env.example` to `src/.env` to configure.

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

Reads all CSVs in `src/data/`, engineers 3 behavioral features (`EventID`, `HourOfDay`, `EventsPerMinute`
via a 60s rolling window), injects synthetic threat patterns for known malicious `EventID`s, trains an
`IsolationForest` (300 estimators, contamination=0.02), and writes `src/models/forensic_alarm_v2.pkl`.
`chatbot_app.py` fails fast at startup if this file is missing — run this script first on a fresh checkout
if `src/models/forensic_alarm_v2.pkl` isn't present.

Synthetic training data can be regenerated with `src/scripts/generate_demo_logs.py` and
`src/scripts/generate_registry_data.py`, which write into `src/data/`.

## Architecture

`src/chatbot_app.py` is organized into five numbered sections (searchable via `# SECTION N:` header comments):

1. **Global State** (~L47) — per-case state (`current_audit_df`, `faiss_index`, `image_hash_sha256`,
   `artifact_counts`, `cached_system_facts`, `session_log`) lives on a `CaseSession` instance, one per
   browser session via `gr.State(value=CaseSession)` — **not** module globals, so concurrent investigators
   don't clobber each other's case. Functions that need it take a `session: CaseSession` parameter; every
   Gradio event handler in `build_gui()` has `session_state` wired into its `inputs=[...]`. Truly shared,
   read-only-after-startup singletons stay as real module globals: `ai_model` (SentenceTransformer, guarded
   by `_ai_model_lock` on first load), `ml_alarm` (loaded Isolation Forest), an in-memory SQLite `db_conn`
   (created but currently unused — a stub for future cross-artifact correlation), and the Gemini/Groq/Ollama
   client init (each optional, checked independently; see "LLM fallback chain" below).
2. **Forensic Image Parsing** (~L161–1828) — the extraction layer. `carve_evidence_from_image()` (~L1694)
   is the orchestrator: opens the image with `pytsk3` (raw) or `pyewf` via the custom `EWFImgInfo` adapter
   class (`.E01`), probes partition offsets, then fans out ~16 independent `extract_*`/`walk_filesystem`
   functions across a `ThreadPoolExecutor(max_workers=14)` — one task per artifact type (EVTX, SAM,
   SOFTWARE, NTUSER, USB, prefetch, browser history, recycle bin, USN journal, SRUM, etc.). Each extractor
   returns its own DataFrame; results are concatenated into one `current_audit_df`. Extractors are annotated
   with `FIX-N` comments referencing specific past bugs (dir-type guards, dedup, isolated task execution) —
   read the referenced fix before modifying an extractor to avoid reintroducing it.
3. **Feature Engineering & ML** (~L1832) — `engineer_features()` derives the same 3-feature set used in
   training and scores rows against `ml_alarm` for anomaly triage.
4. **RAG / LLM** (~L1904) — `build_rag_context()` embeds only `EVTX/REGISTRY/SAM/SOFTWARE` artifact rows
   (filesystem/MFT rows are deliberately excluded from the vector index — file-count questions are answered
   separately via `extract_system_context()` metadata) via `all-MiniLM-L6-v2`, builds/caches a FAISS index
   per image hash under `src/cache/<sha256>/faiss.index`, and returns top-k evidence for a query.
   `query_llm()` builds a strict system prompt (grounded in `extract_system_context(session)`) and
   tries providers in order — see below. `generate_pdf_report()` renders a case report via `reportlab`.
5. **Upload Handler & GUI** (~L2641) — `handle_image_upload()` is the Gradio entry point: hashes the
   uploaded image (SHA-256), checks `src/cache/<sha256>/artifacts.pkl` for a prior carve of the same image
   before re-running extraction, then kicks off a background thread to warm the FAISS index. `build_gui()`
   assembles the Gradio Blocks layout (dark theme, custom CSS) and wires all event handlers.

### LLM fallback chain

`query_llm()` (~L2564) tries providers in fixed priority order and falls through on failure/absence:
**Ollama (local) → Groq (cloud) → Gemini (cloud) → deterministic offline summary**
(`build_offline_response()`, which returns system facts + raw evidence with no LLM). Any subset of
providers may be configured; the app only refuses to start if *none* are available.

### Caching

Per-image-hash caching lives under `src/cache/<sha256>/`: `artifacts.pkl` (carved DataFrame, skips
re-extraction on repeat upload) and `faiss.index` (vector index, invalidated/rebuilt if its vector count
doesn't match the current filtered artifact set). `src/cache/embedding_cache.pkl` is a separate
sentence-embedding cache keyed by normalized text (`_normalize_for_embedding()`) to raise cache-hit rate
across images with similar log text.

### Isolation Forest model

`src/isolation_model.py` is a standalone training script (not imported by the app) — run it manually to
regenerate `src/models/forensic_alarm_v2.pkl`. `chatbot_app.py` only ever *loads* this pickle at startup;
it never trains. If artifact feature engineering changes in `chatbot_app.py::engineer_features()`, keep the
feature set (`EventID`, `HourOfDay`, `EventsPerMinute`) in sync with `isolation_model.py`.
