# Vigilance Core

A digital forensics analysis tool that ingests raw disk images, carves artifacts from them, and
answers natural-language investigator questions grounded in the recovered evidence.

Upload a `.dd`, `.raw` or `.E01` image and Vigilance Core carves it into a single artifact table,
screens that table for anomalies, indexes it for retrieval, and lets you query it in plain English —
with every claim cited back to the artifact it came from.

---

## Features

- **Artifact carving** — EVTX event logs, registry hives (SYSTEM, SOFTWARE, SAM, NTUSER), filesystem
  metadata, browser and user activity, USB device history, prefetch, SRUM, shimcache, recycle bin
  records and deleted-file entries
- **Integrity tracking** — SHA-256 hashing of the source image, with all results cached per image hash
- **Anomaly screening** — Isolation Forest behavioural scoring, combined with deterministic rules for
  known-bad Event IDs (audit log cleared, account creation, brute-force logons, registry persistence)
- **Grounded question answering** — FAISS-backed hybrid retrieval feeding an LLM that is required to
  cite its sources inline; citations resolve to a full evidence appendix
- **Investigation tools** — searchable artifact table, timeline view, triage findings, entity
  correlation and pivoting
- **Reporting** — PDF case reports with metadata and evidence summaries
- **Local-first LLM support** — runs fully offline against Ollama, so evidence never leaves the machine

Answers are grounded rather than generated from memory. The model is given retrieved artifacts and
required to cite them; if retrieval finds nothing relevant, it reports that instead of filling the gap.

---

## How it works

```
 .dd/.raw/.E01 ──▶ carve ──▶ score ──▶ index ──▶ retrieve ──▶ answer with citations
                     │         │         │           │
              ~16 extractors  Isolation FAISS    semantic + lexical
              via pytsk3 /    Forest +  over     + query→type routing
              pyewf           rules     MiniLM
```

1. **Carve** — the image is opened with `pytsk3` (raw) or `pyewf` (`.E01`, all segments). Partition
   offsets are probed, a shared path index is built, and roughly sixteen extractors run against it.
   Each returns a DataFrame; the results are concatenated into one artifact table.
2. **Score** — three behavioural features (Event ID, hour of day, events per minute) are computed and
   scored by a trained Isolation Forest. Known-bad Event IDs are flagged separately by rule, so they
   are always surfaced regardless of the model.
3. **Index** — high-volume artifact types (`EVTX`, `REGISTRY`, `SAM`, `SOFTWARE`) are embedded with
   `all-MiniLM-L6-v2` into a FAISS index. Low-volume, high-value types (USB, browser, prefetch,
   recycle bin) are scanned lexically at query time instead, so they cannot be buried by semantic
   similarity against tens of thousands of registry keys.
4. **Retrieve** — queries are answered by combining semantic search, lexical matching and
   query→artifact-type routing.
5. **Answer** — the retrieved evidence is passed to an LLM under a grounded system prompt requiring
   inline `[E1]`-style citations, which the interface resolves into an evidence appendix.

### Project layout

```
src/chatbot_app.py      Gradio interface and entry point
src/isolation_model.py  anomaly model training script
src/forensics/
  config.py       paths, threat-ID rules, hashset locations
  session.py      per-case session state
  parsers.py      EVTX, registry hive, hashing, E01 adapter
  extractors.py   artifact extractors and carve orchestration
  ml.py           feature engineering and anomaly scoring
  rag.py          retrieval, citations, FAISS index construction
  embedding.py    sentence embedding (isolated in a subprocess)
  context.py      system-context extraction
  llm.py          provider chain and prompting
  reporting.py    PDF report generation
  analysis.py     search, timeline, triage, anomaly overview
  correlation.py  entity extraction and pivoting
  cases.py        case save / load / list
  shimcache.py    AppCompatCache parsing
  hashsets.py     known-good / known-bad hash matching
  recyclebin.py   INFO2 and $I record parsing
```

---

## Requirements

| | |
|---|---|
| **OS** | Windows 10/11 (recommended), Linux, or WSL. macOS is partial. |
| **Python** | **3.11 or newer.** The pinned `pandas`, `numpy` and `scikit-learn` all declare `requires-python >= 3.11`, so installation on 3.10 fails to resolve. |
| **RAM** | 16 GB recommended. |
| **Disk** | ~2 GB for dependencies and models, plus space for cached carve results. |
| **Virtual memory** | On Windows, **a page file must be enabled.** See below. |
| **Network** | Required on first run to download the embedding model (~90 MB). |

### Windows: the page file must be enabled

With no page file, Windows' *commit limit* equals physical RAM exactly, and allocations are refused
once that limit is reached — **even while gigabytes of RAM appear free**, because other processes have
already reserved against it. The embedding model needs approximately 1,040 MB of commit to load, and
index construction will fail without it, typically as:

```
OSError: The paging file is too small for this operation to complete. (os error 1455)
```

or as a bare `0xC0000005` with no traceback.

To enable: `sysdm.cpl` → **Advanced** → **Performance → Settings** → **Advanced** → **Virtual memory
→ Change** → either tick *Automatically manage paging file size for all drives*, or set a custom size
on C: (4096 MB initial / 8192 MB maximum is ample). Adding a page file takes effect immediately; only
removing one requires a restart.

### Native dependencies

Two dependencies are native extensions and must be able to build:

| Package | Purpose | Install notes |
|---|---|---|
| `pytsk3` | SleuthKit filesystem parsing | Windows: requires Visual C++ Build Tools. Debian/Ubuntu: `sudo apt install libtsk-dev`. macOS: `brew install sleuthkit`. |
| `libewf-python` | `.E01` (EWF) image support | Requires `libewf` present on Linux and macOS. |

Vigilance Core starts and runs without them — every feature except image carving remains available —
but they are required to open disk images.

---

## Installation

```bash
git clone https://github.com/holialli/Vigilance-Core.git
cd Vigilance-Core

python -m venv .venv
.venv\Scripts\activate        # Windows
source .venv/bin/activate     # Linux / macOS

pip install -r requirements.txt
```

Then configure at least one LLM provider:

```bash
cp .env.example src/.env       # then edit src/.env
```

---

## Configuration

Vigilance Core tries LLM providers in a fixed order and falls through on failure or absence:

**Ollama (local) → Groq (cloud) → Gemini (cloud) → deterministic offline summary**

Any subset may be configured. The application refuses to start only if none is available. If every
configured provider fails at query time, it still answers — from system facts and retrieved evidence
directly, without an LLM.

| Variable | Purpose | Default |
|---|---|---|
| `OLLAMA_BASE_URL` | Local Ollama endpoint | `http://localhost:11434` |
| `OLLAMA_MODEL` | Local model name | `llama3.2` |
| `GROQ_API_KEY` | Groq API key | — |
| `GEMINI_API_KEY` | Google Gemini API key | — |
| `FORENSICS_EMBED_BATCH` | Encode batch size; sets peak memory | `32` |
| `FORENSICS_EMBED_CHUNK` | Encode chunk size; resume granularity | `500` |
| `CARVE_MAX_WORKERS` | Extractor concurrency | `1` |

### Using Ollama (recommended)

Ollama runs entirely on the local machine, so artifact text is never transmitted to a third-party
API — which may be a requirement rather than a preference when handling real evidence. It needs no
API key and no account:

```bash
ollama serve
ollama pull llama3.2
```

Groq and Gemini both offer free tiers and require only an API key. See `.env.example`.

---

## Usage

```bash
python src/chatbot_app.py
```

Open the local URL shown in the terminal — by default `http://localhost:7860`.

1. Upload one or more forensic image files (`.dd`, `.raw`, `.E01`). For a split EWF set, all segments
   must be present; the first segment is sufficient to select, and siblings are discovered
   automatically.
2. Wait for carving and index construction to complete. This is the slow step, and it happens once
   per image.
3. Work through the interface tabs:

| Tab | Purpose |
|---|---|
| **AI Investigation** | Natural-language questions answered with cited evidence |
| **Dashboard & Summary** | Case overview, artifact counts, anomaly totals, activity timeline |
| **Raw Artifacts** | Tabular inspection, search, timeline, triage findings and correlation |

### Caching

Results are cached per image hash under `src/cache/<sha256>/`:

| File | Contents |
|---|---|
| `artifacts.pkl` | Carved artifact table — re-uploading the same image skips extraction entirely |
| `faiss.index` | Vector index, with a fingerprint sidecar validating that it matches the current artifact set |
| `embed_chunks/` | Partial encode output, so an interrupted index build resumes rather than restarting |
| `case.json` | Case metadata: name, examiner, notes, artifact counts |

> **Note:** cached data contains the full carved contents of the analysed image. Treat
> `src/cache/` with the same handling requirements as the evidence itself.

---

## Training the anomaly model

A trained model ships in `src/models/forensic_alarm_v2.pkl`, so this step is optional.

```bash
cd src && python isolation_model.py
```

Training uses real carved artifacts — every `src/cache/*/artifacts.pkl` present on the machine — and
falls back to the synthetic CSVs in `src/data/` with a warning if no carve is available. The
application only ever loads the resulting model; it never trains at runtime.

The shipped model was trained on a single disk image and will be less well calibrated on evidence
that differs substantially. Re-running the script after carving your own images is recommended; it
concatenates every carve it finds. The model stores decision thresholds over three numeric features
only and contains no artifact text.

Synthetic training data can be regenerated with `src/scripts/generate_demo_logs.py` and
`src/scripts/generate_registry_data.py`.

---

## Testing

```bash
python -m pytest tests/ -q      # 156 tests
```

---

## Platform compatibility

| Platform | Status |
|---|---|
| **Windows 10/11** | Fully supported and recommended. Requires an enabled page file. |
| **Linux / WSL** | Supported where `libtsk-dev` and `libewf` are installed. |
| **macOS** | Partial — depends on successful installation of the native forensic parsers. |

---

## Limitations

- **Not a validated forensic tool.** Vigilance Core is an analysis and triage aid. It has not been
  validated against NIST CFTT or any equivalent programme and should not be relied upon as the sole
  basis for findings presented in legal proceedings.
- **Local use.** The interface has no authentication and binds to localhost. It is intended to run on
  an examiner's own machine, not to be exposed on a network or shared host.
- **Cloud LLM providers transmit evidence text.** Groq and Gemini receive the retrieved artifact
  excerpts included in a query. Use Ollama where this is not acceptable.
- **Anomaly model calibration** — see *Training the anomaly model* above. `RECYCLE` and `RECENT`
  artifacts are currently over-flagged.
- **Windows-oriented artifacts.** Extraction targets Windows filesystems and artifact types; Linux
  and macOS images are not meaningfully supported.

---

## Troubleshooting

**Index construction fails, or crashes with `0xC0000005` and no traceback.**
This is an out-of-memory condition. Confirm a page file is enabled (see *Requirements*), and check
*available commit* rather than free RAM — on Windows the two can differ by several gigabytes. If a
page file is already present, reduce `FORENSICS_EMBED_BATCH` and avoid running memory-intensive
processes alongside the build. Interrupted builds retain completed work in `embed_chunks/` and resume
on the next attempt.

**`ImportError` or build failure installing `pytsk3` / `libewf-python`.**
Install the native prerequisites listed under *Native dependencies*, then reinstall. The application
runs without them; only image carving is unavailable.

**Installation fails to resolve dependencies.**
Confirm Python 3.11 or newer: `python --version`.

**`.E01` parsing fails.**
Verify `libewf-python` installed correctly, and that every segment of the set (`.E01`, `.E02`, …) is
present in the same directory.

**No AI responses.**
Confirm at least one provider is configured in `src/.env`. If using Ollama, verify `ollama serve` is
running and the model has been pulled.

**First run is slow.**
Expected. Carving and index construction each occur once per image; subsequent runs against the same
image hash reuse the cache.

**No evidence after upload.**
Check the terminal for extractor warnings and confirm the image is a valid, readable filesystem image.

---

## License

MIT — see [LICENSE](LICENSE).
