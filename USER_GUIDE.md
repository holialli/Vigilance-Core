# User Guide: AI Forensic Engine

## 1. Introduction to the Tool and Forensic Domain
AI Forensic Engine is designed to support digital forensic investigations where large forensic images must be parsed, triaged, and interpreted quickly without losing evidentiary context. In practical investigations, analysts often work with tens of thousands of records from Windows artifacts such as event logs, registry hives, user-profile traces, and filesystem metadata.  

This tool automates three major tasks:
- Artifact extraction and normalization from forensic image sources
- Behavior-aware scoring to separate normal and suspicious activity
- Evidence-grounded AI interpretation using retrieval over extracted artifacts

The goal is not to replace the investigator. The goal is to shorten the time between evidence ingestion and defensible conclusions.

## 2. Legal and Ethical Considerations (Mandatory)
Digital forensics work must remain legally defensible and ethically constrained. The following controls should be respected in every case:

- **Chain of custody**: Always record source details and verify hash values before analysis.
- **Data minimization**: Only inspect and report data relevant to case scope.
- **Authorization**: Process images only under proper legal authority (warrant, consent, policy mandate, or court order).
- **Integrity**: Do not alter source evidence. Work on forensic copies whenever possible.
- **Privacy**: Handle personal information under institutional policy and applicable privacy laws.
- **Transparency**: Clearly separate observed evidence from AI-assisted interpretation in final reports.

## 3. System Requirements
- Windows 10/11 (recommended) or Linux
- Python 3.10 or newer
- Minimum 8 GB RAM (16 GB recommended for larger images)
- Approx. 5 GB free storage for dependencies and case cache
- Optional but recommended:
  - SleuthKit tooling
  - `libewf` for `.E01` handling

## 4. Installation Steps
1. Clone or download the project.
2. Open a terminal in the project root.
3. Create and activate a virtual environment.
4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
5. Configure environment variables as needed:
   - `GEMINI_API_KEY`
   - `GROQ_API_KEY` (optional fallback)
6. Launch:
   ```bash
   python src/chatbot_app.py
   ```

## 5. Step-by-Step Usage Instructions
1. Start the application and open the local Gradio link in browser.
2. Click upload and provide forensic image file(s).
3. Wait until the status shows the case is ready.
4. Open the `Dashboard & Summary` tab and refresh summary.
5. Use `Raw Artifacts` to inspect extracted records directly.
6. Ask investigation questions in `AI Investigation`, for example:
   - "List all user accounts found in SAM"
   - "Show signs of suspicious logon activity"
   - "Summarize USB usage and related timestamps"
7. Export forensic report after reviewing generated findings.

## 6. Example Cases with Screenshots
The following screenshots should be captured during demonstration and inserted before submission:

- **Case A: Initial upload**
  - Screen showing image upload and SHA-256 displayed in status
- **Case B: Artifact extraction results**
  - Screen from `Raw Artifacts` tab with key fields (`Date and Time`, `Event ID`, `Task Category`)
- **Case C: AI forensic question answering**
  - Screen showing a query and evidence-grounded response
- **Case D: Dashboard summary**
  - Screen showing host, users, event counts, anomaly distribution
- **Case E: Report generation**
  - Screen showing successful PDF export

## 7. Interpretation of Results (Forensic Relevance)
Results should be interpreted with investigative caution:

- **Hash value** confirms the evidence source identity for chain-of-custody tracking.
- **Artifact counts** indicate data completeness and extraction coverage.
- **Top event IDs** guide pivot points for timeline reconstruction.
- **Anomaly labels** are triage indicators, not final proof of malicious activity.
- **AI responses** must be cross-checked against raw artifacts before legal reporting.

Recommended analyst flow:
1. Validate image hash and extraction completeness.
2. Review suspicious event groups and user-context artifacts.
3. Correlate AI findings with raw records and timestamps.
4. Document only evidence-backed conclusions in final report.

## 8. Work Division of Team Members (Technical Contributions)
Replace names below with actual team members before final submission.

- **Member 1 (Lead Forensic Pipeline Developer)**
  - Implemented artifact extraction modules (EVTX, registry, filesystem)
  - Added parser normalization and error handling

- **Member 2 (ML and Detection Engineer)**
  - Trained and integrated Isolation Forest anomaly model
  - Implemented feature engineering and anomaly labeling logic

- **Member 3 (RAG and Indexing Engineer)**
  - Implemented FAISS retrieval pipeline and embedding workflow
  - Added cache strategy to improve indexing performance

- **Member 4 (Interface and Reporting Engineer)**
  - Built Gradio workflow and investigation tabs
  - Implemented PDF report export and summary rendering

- **Member 5 (Validation and QA Engineer)**
  - Prepared test forensic cases
  - Verified extraction completeness, response quality, and report consistency

Notes:
- Each member contribution must map to implemented modules or technical validation work.
- Report writing alone is not counted as technical contribution.
