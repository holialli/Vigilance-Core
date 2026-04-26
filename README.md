# AI Forensic Engine

## Tool Overview
AI Forensic Engine is a digital forensics analysis tool built for processing forensic disk images and converting raw artifacts into investigator-friendly evidence. The system combines artifact carving, behavioral anomaly screening, retrieval-augmented AI querying, and report generation in one workflow.

Core capabilities:
- Automated extraction of EVTX, registry, filesystem metadata, user activity artifacts, and account traces
- SHA-256 hashing for source-image integrity tracking
- Isolation Forest anomaly labeling for suspicious behavior triage
- FAISS-backed retrieval to support context-grounded forensic question answering
- PDF reporting with case metadata and evidence summaries

## Installation Instructions
1. Clone or download this repository.
2. Create and activate a Python virtual environment.
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Configure environment variables (if cloud LLM fallback is used):
   - `GEMINI_API_KEY`
   - `GROQ_API_KEY` (optional)

## Dependencies and Prerequisites
- OS: Windows 10/11 or Linux (WSL also works)
- Python: 3.10 or newer
- Memory: 8 GB minimum, 16 GB recommended for larger artifacts
- Optional forensic support:
  - The SleuthKit tools
  - `libewf` for improved `.E01` compatibility

Primary Python dependencies include:
- `gradio`, `pandas`, `numpy`, `scikit-learn`
- `sentence-transformers`, `faiss-cpu`
- `python-evtx`, `python-registry`, `pytsk3`
- `fpdf2` for report generation

## Execution Steps
1. Start the application:
   ```bash
   python src/chatbot_app.py
   ```
2. Open the local Gradio URL shown in terminal output.
3. Upload one or more forensic image files (`.dd`, `.raw`, `.E01` where supported).
4. Wait for carving and index preparation to finish.
5. Use:
   - `AI Investigation` for natural-language forensic queries
   - `Dashboard & Summary` for case-level overview
   - `Raw Artifacts` for tabular artifact inspection

## Platform Compatibility
- Windows: Fully supported and recommended for this project context
- Linux: Supported if required native forensic libraries are installed
- macOS: Partial support; depends on successful installation of forensic parsing dependencies

## Troubleshooting
- If startup fails with missing package errors, run:
  ```bash
  pip install -r requirements.txt --upgrade
  ```
- If `.E01` parsing fails, verify `libewf` and related bindings are correctly installed.
- If AI responses are unavailable, confirm API keys in environment settings.
- If processing appears slow on first run, allow index/cache creation to complete. Subsequent runs on the same evidence hash should be faster.
- If no evidence appears after upload, check terminal logs for extractor warnings and verify the uploaded image is valid.
