# AI Forensic Engine

A digital forensics analysis tool that ingests raw disk images, carves artifacts from them, and
answers natural-language investigator questions grounded in the recovered evidence.

## Tool Overview

Upload a `.dd`, `.raw` or `.E01` image and the engine carves it into a single artifact table, screens
that table for anomalies, indexes it for retrieval, and lets you ask questions about it in plain
English — with every claim cited back to the artifact it came from.

Core capabilities:

- Automated extraction of EVTX logs, registry hives, filesystem metadata, browser and user activity,
  USB history, prefetch, SRUM, shimcache and recycle bin records
- SHA-256 hashing of the source image for integrity tracking, with per-image caching
- Isolation Forest anomaly screening, plus deterministic rules for known-bad Event IDs
- FAISS-backed hybrid retrieval (semantic + lexical + query routing) for grounded question answering
- Inline `[E1]`-style citations resolved into an evidence appendix, so answers can be checked
- PDF report generation with case metadata and evidence summaries

**Answers are grounded, not generated from memory.** The model is given retrieved artifacts and
required to cite them. If retrieval finds nothing relevant, it says so rather than filling the gap.

## How it works

```
 .dd/.raw/.E01 ──▶ carve ──▶ score ──▶ index ──▶ retrieve ──▶ answer with citations
                    │          │         │           │
              ~16 extractors  Isolation  FAISS   semantic + lexical
              over pytsk3/    Forest +   over    + query→type routing
              pyewf           rules      MiniLM
```

The design decisions that aren't obvious, and why they are the way they are:

**Carving runs serially, not in a thread pool.** The obvious optimisation is one thread per artifact
type. It was measured: threading was *slower*, and worse, it silently dropped evidence. A pytsk3
directory listing is invalidated by any other access through the same handle, so a concurrent
extractor could truncate another's listing with nothing raised — entries simply never appeared. That
cost the two largest event logs and every user profile after the first. `CARVE_MAX_WORKERS=1`.

**Retrieval is hybrid, and the split is deliberate.** Only high-volume types (`EVTX`, `REGISTRY`,
`SAM`, `SOFTWARE`) get embedded. Low-volume high-value types — USB, browser, prefetch, recycle bin —
are scanned lexically on every query instead. That isn't a shortcut: it means adding a new artifact
type never invalidates a built index, and a USB device with one occurrence can't be buried by
semantic similarity against 60,000 registry keys.

**The embedding step runs in a child process.** A native crash there would take the whole Gradio
server down, and `except Exception` cannot catch a segfault. Encoding writes fingerprinted chunks to
disk, so a build that dies resumes instead of restarting.

**Known-bad Event IDs are rules, not machine learning.** An Isolation Forest flags *sparse* regions,
so training it on clusters of known-bad patterns teaches it those patterns are normal — the exact
opposite of the intent. IDs like 1102 (audit log cleared) are handled deterministically in
`HEURISTIC_THREAT_IDS`; the model is left to do the thing it's actually suited for.

**Case state lives per browser session, not in module globals**, so two investigators working
concurrently can't overwrite each other's case.

Architecture and module layout: [CLAUDE.md](CLAUDE.md).

## Engineering log

[PROGRESS.md](PROGRESS.md) is the running log — what broke, how it was diagnosed, and which earlier
conclusions turned out to be wrong. A few that were expensive:

- **The anomaly model flagged 37% of a real image.** The cause wasn't the threshold. One feature was
  capped by its own loop bound — it counted events in a 60-second window by scanning back at most
  100 rows, so it could never return more than 101, and **58,058 rows (72%) sat at that ceiling**
  with true rates up to 14,474. Flagged and unflagged artifacts had identical distributions on it.
  Fixing the feature and retraining on real carved data took it to 2.1%.

- **The index would have cited the wrong evidence, silently.** Retrieval binds FAISS vector *i* to
  row *i* positionally, but the cache was validated by row *count*. Re-scoring re-sorted the frame
  with a non-stable sort, and **51,195 of 60,414 positions moved while the check still passed** —
  every citation resolving to a different artifact while still looking properly sourced. Fixed with
  a stable sort plus an order-sensitive fingerprint, and verified by making each row find its own
  vector.

- **Three sessions were lost to a misdiagnosis.** Repeated `0xC0000005` crashes were attributed to
  mixed OpenMP runtimes. They were out-of-memory: with no Windows page file the commit limit equals
  physical RAM, and the machine showed 3.7 GB of free RAM alongside 369 MB of free *commit*.

## Installation

1. Clone the repository.
2. Create and activate a Python virtual environment (**Python 3.11+**; developed on 3.12).
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Configure at least one LLM provider:
   ```bash
   cp .env.example src/.env      # then edit src/.env
   ```

### Choosing an LLM provider

The app tries providers in a fixed order and falls through on failure or absence:

**Ollama (local) → Groq (cloud) → Gemini (cloud) → deterministic offline summary**

Any subset may be configured; the app only refuses to start if *none* is available. If every
configured provider fails at query time, it still answers — from system facts and the retrieved
evidence directly, with no LLM involved.

**Prefer Ollama where the evidence is real.** It runs entirely on your machine, so artifact text is
never sent to a third-party API — which on an actual case may be a requirement rather than a
preference. It needs no key and no account:

```bash
ollama serve
ollama pull llama3.2
```

Groq and Gemini both have free tiers and need only an API key. See `.env.example`.

## Dependencies and Prerequisites

- **OS**: Windows 10/11 or Linux (WSL works). macOS is partial — see Platform Compatibility.
- **Python**: **3.11 or newer.** The pinned `pandas`, `numpy` and `scikit-learn` in
  `requirements.txt` all declare `requires-python >= 3.11`, so installing on 3.10 fails to resolve.
- **RAM**: 16 GB recommended.
- **Virtual memory**: on Windows, **a page file must be enabled** — see below. This matters more
  than the RAM figure.

> ### Windows: enable the page file
>
> With no page file, Windows' *commit limit* equals physical RAM exactly, and a program is refused
> memory once the limit is reached — **even when gigabytes of RAM are physically free**, because
> other processes have already reserved against it. On a 16 GB machine with the page file disabled
> this project measured 3.7 GB of free RAM alongside only 369 MB of free commit, and the embedding
> model needs ~1,040 MB to load. The index build fails, usually as an
> `OSError: The paging file is too small for this operation to complete. (os error 1455)`, or as a
> bare `0xC0000005` with no traceback.
>
> To enable: `sysdm.cpl` → Advanced → Performance Settings → Advanced → Virtual memory → Change →
> either tick "Automatically manage", or set a custom size on C: (4096 MB initial / 8192 MB maximum
> is ample). Adding a page file takes effect immediately; only removing one needs a reboot.

Primary Python dependencies:

- `gradio`, `pandas`, `numpy`, `scikit-learn`
- `sentence-transformers`, `faiss-cpu`, `torch`
- `python-evtx`, `python-registry`, `pytsk3` (SleuthKit), `libewf-python` (`.E01` support)
- `reportlab` for PDF report generation

`pytsk3` and `libewf-python` are native and may need OS-level libraries present first.

## Execution Steps

```bash
python src/chatbot_app.py
```

1. Open the local Gradio URL shown in the terminal (default `http://localhost:7860`).
2. Upload one or more forensic image files (`.dd`, `.raw`, `.E01` — all segments of an EWF set).
3. Wait for carving and index preparation to finish. The first run on a given image is the slow one;
   results are cached by image hash, so re-uploading the same image skips extraction entirely.
4. Use the tabs:
   - **AI Investigation** — natural-language questions with cited evidence
   - **Dashboard & Summary** — case-level overview and anomaly counts
   - **Raw Artifacts** — tabular inspection, search, timeline and triage

## Training the anomaly model

A trained model ships in `src/models/forensic_alarm_v2.pkl`, so this is optional. To retrain:

```bash
cd src && python isolation_model.py
```

It trains on **real carved artifacts** — every `src/cache/*/artifacts.pkl` on the machine — and falls
back to the synthetic CSVs in `src/data/` with a warning if none exists.

> **The shipped model was trained on a single disk image.** It will be miscalibrated on evidence that
> looks different, and re-running the script once you have carved your own images is worth doing —
> it concatenates every carve it finds. For reference: the same model trained only on the synthetic
> CSVs flagged **37% of a real image** as anomalous, because a real registry hive looks nothing like
> a synthetic event log. Trained on real carves it flags about 2%.
>
> The model stores decision thresholds over three numeric features (Event ID, hour of day, events per
> minute). It contains no artifact text, so publishing it discloses nothing about the source image.

## Known limitations

- The anomaly model has only been trained on one image (above).
- `RECYCLE` and `RECENT` artifacts currently come back fully flagged — 37 rows out of 80,191 on the
  reference image. Left as-is deliberately rather than tuned away against a single case.
- macOS support depends on native forensic parsing libraries that do not always install cleanly.

## Testing

```bash
python -m pytest tests/ -q      # 154 tests
```

## Platform Compatibility

- **Windows**: fully supported and recommended.
- **Linux**: supported where the native forensic libraries are installed.
- **macOS**: partial; depends on successful installation of the forensic parsing dependencies.

## Troubleshooting

**The index build fails, or crashes with `0xC0000005` and no traceback.**
This is an out-of-memory until proven otherwise — see the page file note above. Check *available
commit*, not free RAM; on Windows they can differ by gigabytes. If a page file is already enabled,
lower `FORENSICS_EMBED_BATCH` (default 32) and avoid running anything heavy alongside the build. A
failed build keeps its finished work in `src/cache/<hash>/embed_chunks/` and resumes from there, so
re-running is cheap.

**Startup fails with missing packages.**
`pip install -r requirements.txt --upgrade`

**`.E01` parsing fails.**
Verify `libewf-python` installed correctly. All segments of the set (`.E01`, `.E02`, …) must be
present and uploaded together.

**AI responses are unavailable.**
Confirm at least one provider is configured in `src/.env`. If Ollama is your provider, check that
`ollama serve` is running and the model has been pulled.

**Processing is slow on first run.**
Expected — carving and index construction both happen once per image. Subsequent runs on the same
image hash reuse the cache.

**No evidence appears after upload.**
Check the terminal for extractor warnings and confirm the image is a valid, readable filesystem
image.

## License

MIT — see [LICENSE](LICENSE).
