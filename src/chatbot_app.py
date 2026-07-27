"""
Forensic Image Analysis Engine — Gradio application entry point.

Carving, ML triage, retrieval, and reporting live in the `forensics` package;
this module wires them into the web UI.
"""

import os
import re
import threading
import traceback
from datetime import datetime

import gradio as gr
import pandas as pd

from forensics.config import CACHE_DIR, debug_extract
from forensics.context import extract_system_context
from forensics.extractors import carve_evidence_from_image
from forensics.llm import ensure_llm_available, query_llm
from forensics.ml import engineer_features
from forensics.parsers import compute_sha256
from forensics.rag import build_rag_context
from forensics.reporting import generate_pdf_report
from forensics.session import CaseSession



def handle_image_upload(files, session):
    if not files:
        return "No files uploaded."

    filepaths = [f.name if hasattr(f, 'name') else str(f) for f in files]
    primary_file = filepaths[0]
    image_hash_sha256 = compute_sha256(primary_file)

    case_dir = os.path.join(CACHE_DIR, image_hash_sha256)
    os.makedirs(case_dir, exist_ok=True)
    artifact_path = os.path.join(case_dir, "artifacts.pkl")

    if os.path.exists(artifact_path):
        df = pd.read_pickle(artifact_path)
        artifact_counts = df['ArtifactType'].str.lower().value_counts().to_dict()
        artifact_counts["total"] = len(df)
        status_msg = (
            f"Forensic Image Loaded: {len(df)} artifacts recovered. "
            f"SHA-256: {image_hash_sha256}"
        )
    else:
        print(f"  [IMAGE] Analyzing new forensic source...")
        df, artifact_counts = carve_evidence_from_image(filepaths)
        df = engineer_features(df)
        df.to_pickle(artifact_path)
        status_msg = (
            f"Forensic Image Carved: {len(df)} artifacts identified. "
            f"SHA-256: {image_hash_sha256}"
        )

    # ── REQ-6: Always reset state and trigger background index build ─────────
    # Applies to both fresh carves AND cache loads so repeated uploads work.
    session.current_audit_df = df
    session.image_hash_sha256 = image_hash_sha256
    session.artifact_counts = artifact_counts
    session.cached_system_facts = None
    session.faiss_index = None  # Force index rebuild for new image

    def _background_index_build():
        try:
            print("  [FAISS] Background index build started...")
            build_rag_context("Init", session)
            print("  [FAISS] Background index build complete.")
        except Exception as e:
            print(f"  [FAISS] Background index build failed: {e}")
            if debug_extract:
                traceback.print_exc()

    threading.Thread(target=_background_index_build, daemon=True).start()
    # ─────────────────────────────────────────────────────────────────────────

    return status_msg
def build_gui():
    CSS = """
    /* ── Layout ─────────────────────────────────────────────────────────── */
    .sidebar-box {
        background: #1e293b;
        padding: 18px;
        border-radius: 12px;
        border: 1px solid #334155;
        height: 100%;
        overflow-y: auto;
    }
    .main-col {
        background: #0f172a;
        border-radius: 12px;
        padding: 10px;
    }

    /* ── Stat cards on dashboard ─────────────────────────────────────────── */
    .stat-card {
        background: #1e293b;
        border: 1px solid #334155;
        padding: 15px;
        border-radius: 8px;
        margin: 5px;
        text-align: center;
    }

    /* ── Chat window ─────────────────────────────────────────────────────── */
    #chat-window {
        height: 520px;
        overflow-y: auto;
        background: #0f172a;
        border-radius: 10px;
        border: 1px solid #1e293b;
    }

    /* ── Chatbot bubble overrides ────────────────────────────────────────── */
    .message.svelte-1lcyrx4.svelte-1lcyrx4 {
        font-size: 0.93em !important;
        line-height: 1.6 !important;
    }
    .bot.svelte-1lcyrx4 {
        background: #1e293b !important;
        border: 1px solid #334155 !important;
        border-radius: 10px !important;
        padding: 12px 16px !important;
        color: #e2e8f0 !important;
    }
    .user.svelte-1lcyrx4 {
        background: #1d4ed8 !important;
        border-radius: 10px !important;
        padding: 10px 14px !important;
        color: #ffffff !important;
    }

    /* ── Raw artifacts table ─────────────────────────────────────────────── */
    #raw-artifacts {
        height: 520px;
        overflow: auto;
        font-size: 0.82em;
    }

    /* ── Status box colours ──────────────────────────────────────────────── */
    #status-ready textarea  { color: #4ade80 !important; }
    #status-working textarea { color: #facc15 !important; }

    /* ── Report form ─────────────────────────────────────────────────────── */
    .report-section {
        background: #162032;
        border: 1px solid #2d4a6b;
        border-radius: 8px;
        padding: 12px;
        margin-top: 8px;
    }

    /* ── Section dividers ────────────────────────────────────────────────── */
    .section-label {
        color: #94a3b8;
        font-size: 0.78em;
        font-weight: 600;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        margin: 14px 0 6px 0;
    }
    """

    # ── Build the interface ───────────────────────────────────────────────────
    with gr.Blocks(title="VIGILANCE Forensic Engine") as demo:
        session_state = gr.State(value=CaseSession)

        # ── Top banner ───────────────────────────────────────────────────────
        gr.HTML("""
        <div style='background:linear-gradient(135deg,#1e3a5f,#1d4ed8);
                    padding:18px 24px; border-radius:10px; margin-bottom:10px;
                    display:flex; align-items:center; gap:14px;'>
            <span style='font-size:2em;'>🛡️</span>
            <div>
                <div style='font-size:1.3em; font-weight:700;
                            color:#ffffff; letter-spacing:0.04em;'>
                    VIGILANCE FORENSIC ENGINE
                </div>
                <div style='font-size:0.78em; color:#93c5fd; margin-top:2px;'>
                    Digital Forensics Analysis Platform &nbsp;·&nbsp; v3.1
                </div>
            </div>
        </div>
        """)

        with gr.Row(equal_height=False):

            # ── LEFT SIDEBAR ─────────────────────────────────────────────────
            with gr.Column(scale=1, elem_classes="sidebar-box"):

                # Case Management
                gr.HTML("<div class='section-label'>📂 Case Management</div>")
                image_input = gr.File(
                    label="Upload Forensic Image (.dd / .E01)",
                    file_count="multiple"
                )
                upload_btn = gr.Button(
                    "🚀 CARVE ARTIFACTS", variant="primary", size="lg"
                )
                status_box = gr.Textbox(
                    label="FORENSIC STATUS",
                    value="⏸ Standby — awaiting image",
                    interactive=False,
                    elem_id="status-ready"
                )

                # Quick query hints
                gr.HTML("""
                <div class='section-label' style='margin-top:16px;'>
                    💡 Example Queries
                </div>
                <div style='background:#0f172a; border-radius:6px;
                            padding:10px 12px; font-size:0.82em;
                            color:#94a3b8; line-height:1.9;'>
                    • List all user accounts<br>
                    • Show USB device history<br>
                    • Were any audit logs cleared?<br>
                    • What programs were recently executed?<br>
                    • Find any suspicious registry entries
                </div>
                """)

                # Report generation form
                gr.HTML("""
                <div class='section-label' style='margin-top:16px;'>
                    📋 Report Generation
                </div>
                """)

                with gr.Group(elem_classes="report-section"):
                    report_inv_name = gr.Textbox(
                        label="Investigator Name",
                        placeholder="e.g. Det. Sarah Chen",
                        max_lines=1
                    )
                    report_case_num = gr.Textbox(
                        label="Case Number",
                        placeholder="e.g. CASE-2026-042",
                        max_lines=1
                    )
                    report_notes = gr.Textbox(
                        label="Case Notes",
                        placeholder="Observations, context, or notes "
                                    "to include in the report...",
                        lines=4
                    )
                    report_btn = gr.Button(
                        "📄 Generate PDF Report",
                        variant="secondary",
                        size="sm"
                    )
                    report_status = gr.Textbox(
                        label="Report Status",
                        interactive=False,
                        max_lines=2,
                        visible=True
                    )
                    report_file = gr.File(
                    label="⬇ Download Report",
                    visible=True,
                    interactive=False,
                    value=None
                )

            # ── MAIN PANEL ───────────────────────────────────────────────────
            with gr.Column(scale=3, elem_classes="main-col"):
                with gr.Tabs():

                    # Tab 1 — AI Chat
                    with gr.Tab("🔍 AI Investigation"):
                        chatbot = gr.Chatbot(
                            label="",
                            height=520,
                            elem_id="chat-window",
                            show_label=False,
                        )
                        with gr.Row():
                            msg = gr.Textbox(
                                placeholder="Ask a forensic question...",
                                scale=9,
                                container=False,
                                show_label=False,
                                lines=1,
                            )
                            submit_btn = gr.Button(
                                "Send ➤", scale=1, variant="primary"
                            )
                        gr.HTML("""
                        <div style='font-size:0.75em; color:#475569;
                                    text-align:center; margin-top:4px;'>
                            Responses are AI-generated and should be verified
                            against raw artifact data.
                        </div>
                        """)

                    # Tab 2 — Dashboard
                    with gr.Tab("📊 Dashboard"):
                        with gr.Row():
                            refresh_btn = gr.Button(
                                "🔄 Refresh Summary", variant="primary", size="sm"
                            )
                        summary_output = gr.HTML(
                            value="""
                            <div style='text-align:center; padding:60px 20px;
                                        color:#475569;'>
                                <div style='font-size:2.5em; margin-bottom:12px;'>
                                    🖴
                                </div>
                                <div style='font-size:1em; font-weight:600;'>
                                    No case loaded
                                </div>
                                <div style='font-size:0.85em; margin-top:6px;'>
                                    Upload a forensic image and click
                                    CARVE ARTIFACTS to begin.
                                </div>
                            </div>
                            """
                        )

                    # Tab 3 — Raw Artifacts
                    with gr.Tab("🗂 Raw Artifacts"):
                        with gr.Row():
                            artifacts_btn = gr.Button(
                                "Load Artifact Table",
                                variant="secondary",
                                size="sm"
                            )
                            gr.HTML("""
                            <div style='font-size:0.8em; color:#64748b;
                                        padding:6px 0;'>
                                Showing all extracted artifacts from
                                the loaded forensic image.
                            </div>
                            """)
                        raw_dataframe = gr.Dataframe(
                            interactive=False,
                            wrap=True,
                            elem_id="raw-artifacts"
                        )

        # ── INNER CALLBACKS ───────────────────────────────────────────────────

        def respond(message, history, session):
            """Handle a chat query through RAG → LLM pipeline."""
            # Guard: no image loaded
            if session.current_audit_df is None:
                reply = ("⚠️ No forensic image is loaded. "
                         "Please upload an image and carve artifacts first.")
                history = list(history or [])
                history.append({"role": "user",      "content": message})
                history.append({"role": "assistant", "content": reply})
                return "", history

            # Guard: FAISS index still building
            if session.faiss_index is None:
                reply = ("⏳ The forensic index is still building in the background. "
                         "Please wait 15–30 seconds and try again.")
                history = list(history or [])
                history.append({"role": "user",      "content": message})
                history.append({"role": "assistant", "content": reply})
                return "", history

            # Normalise history format
            clean_history = []
            for item in history:
                if isinstance(item, (list, tuple)):
                    clean_history.append(
                        {"role": "user",      "content": str(item[0])}
                    )
                    clean_history.append(
                        {"role": "assistant", "content": str(item[1])}
                    )
                else:
                    clean_history.append(item)

            # RAG retrieval + LLM
            _rows, context_text = build_rag_context(message, session)
            bot_message = query_llm(message, context_text, session)

            # Strip any raw evidence lines the LLM may still emit
            bot_message = re.sub(
                r'\n?EVIDENCE:\n(\-\s*\[Evidence\s*\d+\][^\n]*\n?)+',
                '', bot_message
            )
            bot_message = re.sub(
                r'\n?USED_EVIDENCE:\s*\[.*?\]', '', bot_message
            )
            bot_message = re.sub(
                r'\n?\[Evidence\s*\d+\]\s*Time:[^\n]+', '', bot_message
            )
            bot_message = bot_message.strip()

            # Persist to session log for PDF report
            session.session_log.append({
                "question": message,
                "answer":   bot_message,
                "time":     datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            })

            clean_history.append({"role": "user",      "content": message})
            clean_history.append({"role": "assistant", "content": bot_message})
            return "", clean_history

        def get_styled_summary(session):
            """Render the dashboard HTML summary panel."""
            if session.current_audit_df is None:
                return """
                <div style='text-align:center; padding:60px 20px; color:#475569;'>
                    <div style='font-size:2.5em; margin-bottom:12px;'>🖴</div>
                    <div style='font-weight:600;'>No case loaded</div>
                </div>
                """

            raw = extract_system_context(session)

            # Safe key extraction with fallbacks
            def _extract(key, fallback="N/A"):
                try:
                    return raw.split(f"{key}: ")[1].split("\n")[0].split(" | ")[0]
                except Exception:
                    return fallback

            host       = _extract("HOST")
            os_ver     = _extract("OS")
            total_logs = _extract("TOTAL LOGS")
            alerts     = _extract("ALERTS")
            users      = _extract("SAM USERS")
            anomalies  = _extract("ANOMALIES")
            time_range = _extract("RANGE")

            # Determine alert badge colour
            alert_color = (
                "#ef4444" if "DISABLED" in alerts.upper()
                          or "CLEARED"  in alerts.upper()
                else "#22c55e"
            )

            stat_cards = f"""
            <div style='display:grid; grid-template-columns:repeat(4,1fr);
                        gap:12px; margin-bottom:16px;'>
                <div class='stat-card'>
                    <div style='color:#60a5fa; font-size:0.75em;
                                font-weight:600; margin-bottom:4px;'>
                        HOST
                    </div>
                    <div style='font-weight:700; font-size:0.95em;'>
                        {host}
                    </div>
                </div>
                <div class='stat-card'>
                    <div style='color:#60a5fa; font-size:0.75em;
                                font-weight:600; margin-bottom:4px;'>
                        OS
                    </div>
                    <div style='font-weight:700; font-size:0.95em;'>
                        {os_ver}
                    </div>
                </div>
                <div class='stat-card'>
                    <div style='color:#60a5fa; font-size:0.75em;
                                font-weight:600; margin-bottom:4px;'>
                        TOTAL ARTIFACTS
                    </div>
                    <div style='font-weight:700; font-size:1.1em;
                                color:#4ade80;'>
                        {total_logs}
                    </div>
                </div>
                <div class='stat-card'>
                    <div style='color:#60a5fa; font-size:0.75em;
                                font-weight:600; margin-bottom:4px;'>
                        ALERTS
                    </div>
                    <div style='font-weight:700; font-size:0.85em;
                                color:{alert_color};'>
                        {alerts}
                    </div>
                </div>
            </div>

            <div style='display:grid; grid-template-columns:repeat(3,1fr);
                        gap:12px; margin-bottom:16px;'>
                <div class='stat-card'>
                    <div style='color:#a78bfa; font-size:0.75em;
                                font-weight:600; margin-bottom:4px;'>
                        USERS (SAM)
                    </div>
                    <div style='font-size:0.85em;'>{users}</div>
                </div>
                <div class='stat-card'>
                    <div style='color:#a78bfa; font-size:0.75em;
                                font-weight:600; margin-bottom:4px;'>
                        ANOMALY SCORE
                    </div>
                    <div style='font-size:0.85em;'>{anomalies}</div>
                </div>
                <div class='stat-card'>
                    <div style='color:#a78bfa; font-size:0.75em;
                                font-weight:600; margin-bottom:4px;'>
                        TIME RANGE
                    </div>
                    <div style='font-size:0.8em;'>{time_range}</div>
                </div>
            </div>
            """

            # Full monospace dump
            mono_dump = raw.replace("<", "&lt;").replace(">", "&gt;")
            mono_dump = mono_dump.replace("\n", "<br>")

            full_panel = f"""
            <div style='background:#0f172a; padding:16px 20px;
                        border-radius:8px; border:1px solid #1e293b;
                        color:#cbd5e1; font-family:monospace;
                        font-size:0.85em; line-height:1.7;
                        max-height:380px; overflow-y:auto;'>
                {mono_dump}
            </div>
            """

            return stat_cards + full_panel

        def _handle_report(inv_name, case_num, notes, session):
            """Wrapper — avoids variable name clash with msg textbox."""
            pdf_path, status_msg = generate_pdf_report(inv_name, case_num, notes, session)
            if pdf_path and os.path.exists(pdf_path):
                return status_msg, pdf_path   # Gradio 6: return path string directly
            return status_msg, None

        # ── WIRE EVENTS ───────────────────────────────────────────────────────
        upload_btn.click(
            handle_image_upload,
            inputs=[image_input, session_state],
            outputs=[status_box]
        )
        msg.submit(
            respond,
            inputs=[msg, chatbot, session_state],
            outputs=[msg, chatbot],
            show_progress="hidden"
        )
        submit_btn.click(
            respond,
            inputs=[msg, chatbot, session_state],
            outputs=[msg, chatbot],
            show_progress="hidden"
        )
        refresh_btn.click(
            get_styled_summary,
            inputs=[session_state],
            outputs=[summary_output]
        )
        artifacts_btn.click(
            fn=lambda session: (
                session.current_audit_df
                if session.current_audit_df is not None
                else pd.DataFrame()
            ),
            inputs=[session_state],
            outputs=[raw_dataframe]
        )
        report_btn.click(
            _handle_report,
            inputs=[report_inv_name, report_case_num, report_notes, session_state],
            outputs=[report_status, report_file]
        )

    return demo, CSS


if __name__ == "__main__":
    ensure_llm_available()
    app, css = build_gui()
    app.launch(server_port=7860, show_error=True, css=css)
