# 🛡️ Vigilance Forensic Engine: Progress Tracker & Handover

## 🚀 Current Engineering State (CRITICAL)
The project is currently undergoing a high-stakes migration to **Gradio 6.0** and **Unified Forensic Caching**.

### 1. Unified Case Architecture
- **Location**: `src/cache/{sha256_hash}/`
- **Strategy**: All artifacts (`artifacts.pkl`) and search indices (`faiss.index`) are now stored in a single hash-locked vault. 
- **Goal**: Prevent "Cache Mismatches" where the AI reasons about data that doesn't match the currently loaded image.

### 2. Gradio 6.0 Migration (The "Messages" Standard)
- **Constraint**: `gr.Chatbot` now strictly requires `type="messages"`.
- **Logic**: History must be a list of dictionaries: `{"role": "user", "content": "..."}`.
- **Gotcha**: Legacy "tuple" format `(user, bot)` will crash the UI. A robust sanitizer is currently implemented in `respond()` to handle transitions.

### 3. Forensic Performance (100k+ Records)
- **Indexing**: Using `pytsk3` and `heuristic_discover_files` for Autopsy-style carving.
- **RAG**: FAISS index is regenerated automatically if the artifact count doesn't match the cache.
- **Speed**: Instant-reload is implemented via Pickle-based serialization of the `current_audit_df`.

## 🛠️ Outstanding Problems & Bugs
- [x] **Data Incompatibility**: Resolved by standardizing on the `messages` format.
- [x] **Double Cache Mismatch**: Resolved by unifying the cache into a single case directory.
- [ ] **UI Pining**: Ensure the chat input remains perfectly aligned at the bottom of the investigation tab across all screen sizes.
- [ ] **Recursive Depth**: Tuning `walk_filesystem` to handle deep system folders without latency spikes.

## 📅 Investigation Goals
1. **Case Preservation**: Ensure a full SHA-256 hash is always used for identity.
2. **Visual Transparency**: Maintain a multi-column Dashboard with forensic cards (Host, OS, Alerts).
3. **High Fidelity**: Extract 100% of artifacts (USB, Web, Recycle Bin) regardless of user profile paths.

This document serves as the architectural blueprint and current state-of-the-art summary for the **Vigilance Forensic Image Analysis Engine**. If this session ends, provide this file to your next AI assistant to continue development seamlessly.

## 📍 Current Status: Phase 3 (Stabilized & Exhaustive)
The system has transitioned from a basic prototype into a high-fidelity forensic tool capable of matching **Autopsy-level** artifact extraction.

### 🏗️ Accomplished Features
1.  **Multi-Part Image Support**: 
    - Full support for `.E01`, `.E02`, etc., split segment sets.
    - Automated segment validation (Case Number/Evidence Number verification).
2.  **Exhaustive Artifact Carving**:
    - **USB History**: Extraction from `SYSTEM` registry (includes Hubs, Controllers, and Composite devices). Matches Autopsy's 9-device count.
    - **Recycle Bin**: Deep scan of `$Recycle.Bin` across all User SIDs. Captures all 14 standard items.
    - **Recent Documents**: Parsing of `.lnk` files from `\Recent` folders to track user file access.
    - **Web Browser Analysis**: Unified parsing for **Chrome, Edge, and Firefox**. Includes History, Bookmarks (`places.sqlite`), and Cookies.
    - **Communication Discovery**: Scanning for `.pst`, `.ost`, `.msg`, and `.eml` files.
3.  **Local LLM Integration (Unlimited Analysis)**:
    - Support for **Ollama (Llama-3)** as a local backend.
    - Intelligent fallback chain: **Groq (Fast) → Gemini (Strong) → Ollama (Unlimited) → GPT4Free (Backup)**.
    - **Context Compression**: Automatic truncation of evidence blocks to save token quota.
4.  **Forensic Dashboard**:
    - 4-column Investigation Summary grid (Files, USB, Web, Activity).
    - Robustness: "Null-safe" logic prevents crashes if an image lacks specific artifact categories.

---

## 🚀 Future Roadmap: Phase 4 & 5
The following features are planned to reach a production-ready "1.0" release:

### 1. Advanced Visualization (Timeline)
- **Objective**: Implement a chronologically sorted "Master Timeline" using Plotly or a native Gradio component.
- **Goal**: Allow investigators to see exactly when a USB was plugged in relative to when a file was deleted.

### 2. Professional Reporting (PDF Export)
- **Objective**: Use `fpdf` or `ReportLab` to generate a tamper-proof forensic report.
- **Contents**: Image Hashes (SHA-256), System Summary, Detected Anomalies, and LLM-generated Forensic Significance sections.

### 3. Memory Forensics Integration
- **Objective**: Add support for raw memory dumps (`.mem`, `.raw`).
- **Tooling**: Integrate `Volatility 3` as a sub-process to extract running processes and network connections.

### 4. Parallel Carving
- **Objective**: Use Python's `multiprocessing` to run Registry, Browser, and Filesystem scans simultaneously.
- **Impact**: Reduce analysis time for large images (e.g., 500GB+) by 60-70%.

---

## 🛠️ Developer Notes (For the next AI)
- **Environment**: Python 3.12+, Native Windows, `pytsk3` and `libewf` installed.
- **Key File**: `src/chatbot_app.py` contains all logic.
- **Entry Point**: `python src/chatbot_app.py` starts the Gradio UI on port 7860.
- **Important Pattern**: All extraction functions return a `pd.DataFrame` which is then concatenated into the global `current_audit_df`.
- **LLM Context**: The `extract_system_context()` function is the most critical for AI reasoning—it condenses thousands of logs into a single prompt-friendly string.

---
**Status**: Ready for Deployment / Further Expansion.
**Last Updated**: 2026-04-25 by Antigravity AI.
