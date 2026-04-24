# 🛡️ Forensic Image Analysis Engine v4.0

A professional-grade digital forensics analysis platform that combines **The SleuthKit**, **Machine Learning**, and **Generative AI (RAG)** to automate evidence carving and interpretation from forensic disk images.

## 🚀 Key Features
- **Parallel Evidence Carving**: Rapidly extracts EVTX logs, Registry Hives, MFT/Filesystem metadata, SAM accounts, Prefetch, Browser History, and User Activity (LNK/JumpLists).
- **Behavioral Anomaly Detection**: Uses a trained **Isolation Forest** ML model to detect statistical outliers in system events.
- **AI-Powered Investigation (RAG)**: Integrated Gemini AI for semantic search and natural language interrogation of forensic artifacts.
- **Legal-Grade Reporting**: Generates cited forensic PDF reports with case metadata and executive summaries.
- **Forensic Soundness**: Automated SHA-256 hashing for chain of custody verification.

---

## 🛠️ Setup Instructions

### 1. Prerequisites
- **Python 3.10+**
- **The SleuthKit (Optional but recommended)**: For advanced `.E01` support, ensure `libewf` is installed on your system.

### 2. Environment Setup
Clone the repository and install dependencies:
```bash
# Install dependencies
pip install -r requirements.txt
```

### 3. Configuration
1. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```
2. Open `.env` and add your API keys:
   - `GEMINI_API_KEY`: [Get it here](https://aistudio.google.com/app/apikey)
   - `GROQ_API_KEY`: [Optional Fallback](https://console.groq.com/keys)

### 4. Running the Tool
```bash
python src/chatbot_app.py
```
Open the local URL (usually `http://127.0.0.1:7860`) in your browser.

---

## 📂 Project Structure
- `src/chatbot_app.py`: Main application engine and UI.
- `src/models/`: Contains the trained Isolation Forest ML model (`forensic_alarm_v2.pkl`).
- `requirements.txt`: Full list of forensic and AI dependencies.
- `cache/`: (Ignored) Storage for FAISS indices and processed dataframes.

---

## 📝 Usage Tips
- **Upload Image**: Support for `.dd`, `.raw`, and `.E01` (requires `libewf`).
- **Dashboard**: Generate a visual summary of the investigation.
- **Queries**: Ask questions like "How many PDF files exist?", "Was there a brute force attack?", or "Show all user accounts".
- **Report**: Fill in Case Metadata and click "Export PDF Report" to finalize your investigation.

---
*Developed for Digital Forensics Project - Spring 2026*
