import re
import os

file_path = r"c:\Users\ali13\Desktop\Spring 26'\DF\Project\Chatbot\src\chatbot_app.py"

if not os.path.exists(file_path):
    print(f"File not found: {file_path}")
    exit(1)

with open(file_path, "r", encoding="utf-8") as f:
    lines = f.readlines()

# Clean up emojis in the first section (before UI starts)
# We find where CSS or with gr.Blocks starts
ui_start_idx = len(lines)
for i, line in enumerate(lines):
    if "with gr.Blocks" in line:
        ui_start_idx = i
        break

emojis_to_strip = ['✅', '⚠️', '❌', '🔒', '🔬', '📄', '🗝️', '👤', '💿', '🏃', '📂', '🧠', '⚡', '🛑', '🟢', '📊', '⚔️', '🗄️', '💬', '🔍', 'ℹ️', '⏳', '🔴', '🛡️', '📦', '▸', '⚡']

new_lines = []
for line in lines[:ui_start_idx]:
    for e in emojis_to_strip:
        line = line.replace(e, "")
    new_lines.append(line)

# Reconstruct the UI section from scratch to fix corruption
ui_code = """
with gr.Blocks(css=CSS) as demo:
    # -- HEADER --
    gr.HTML(\"\"\"
    <div style='background: linear-gradient(135deg, rgba(99,102,241,0.1), rgba(139,92,246,0.08), rgba(15,23,42,0.9));
                padding: 24px 32px; border-bottom: 1px solid rgba(99,102,241,0.15);
                margin: -16px -16px 20px -16px;'>
        <div style='display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:12px;'>
            <div>
                <div style='display:flex; align-items:center; gap:12px;'>
                    <div style='width:42px; height:42px; border-radius:12px;
                                background: linear-gradient(135deg, #6366f1, #8b5cf6);
                                display:flex; align-items:center; justify-content:center;
                                font-size:1.3em; box-shadow: 0 4px 15px rgba(99,102,241,0.3); color:white;'>DEF</div>
                    <div>
                        <h1 style='color:#e2e8f0; margin:0; font-size:1.35em; font-weight:700;
                                   font-family:Inter,sans-serif; letter-spacing:0.5px;'>
                            Forensic Analysis Engine
                        </h1>
                        <div style='color:#64748b; font-size:0.72em; letter-spacing:2px; margin-top:2px;
                                    font-family:JetBrains Mono,monospace;'>
                            v4.0 -- FULL IMAGE INTELLIGENCE
                        </div>
                    </div>
                </div>
            </div>
            <div style='display:flex; gap:8px; flex-wrap:wrap;'>
                <span style='background:rgba(99,102,241,0.12); color:#a5b4fc; padding:4px 12px;
                             border-radius:20px; font-size:0.65em; font-weight:500; letter-spacing:1px;
                             border:1px solid rgba(99,102,241,0.2);'>SLEUTHKIT</span>
                <span style='background:rgba(16,185,129,0.1); color:#6ee7b7; padding:4px 12px;
                             border-radius:20px; font-size:0.65em; font-weight:500; letter-spacing:1px;
                             border:1px solid rgba(16,185,129,0.2);'>FAISS + RAG</span>
                <span style='background:rgba(139,92,246,0.1); color:#c4b5fd; padding:4px 12px;
                             border-radius:20px; font-size:0.65em; font-weight:500; letter-spacing:1px;
                             border:1px solid rgba(139,92,246,0.2);'>GEMINI AI</span>
                <span style='background:rgba(245,158,11,0.1); color:#fcd34d; padding:4px 12px;
                             border-radius:20px; font-size:0.65em; font-weight:500; letter-spacing:1px;
                             border:1px solid rgba(245,158,11,0.2);'>MFT . SAM . PREFETCH</span>
            </div>
        </div>
    </div>
    \"\"\")

    with gr.Row():
        # -- LEFT SIDEBAR --
        with gr.Column(scale=1, min_width=280):
            gr.HTML(\"\"\"<div style='color:#94a3b8; font-size:0.7em; letter-spacing:2.5px;
                                  font-weight:600; margin-bottom:8px; font-family:Inter,sans-serif;'>
                        EVIDENCE INTAKE</div>\"\"\")
            file_input = gr.File(label="FORENSIC IMAGE (.dd / .E01)", file_types=[".dd", ".E01", ".e01", ".raw", ".img"])
            demo_btn = gr.Button("Load Demo Data", variant="secondary")
            status = gr.Textbox(label="SYSTEM STATUS", interactive=False, value="Awaiting evidence upload...", lines=4)

            gr.HTML(\"\"\"
            <div style='background: rgba(15, 23, 42, 0.6); backdrop-filter: blur(12px);
                        border: 1px solid rgba(99,102,241,0.12); border-radius: 14px;
                        padding: 16px; margin-top: 12px;'>
                <div style='color:#94a3b8; font-size:0.65em; letter-spacing:2.5px; font-weight:600;
                            margin-bottom:10px; font-family:Inter,sans-serif;'>QUERY GUIDE</div>
                <div style='color:#cbd5e1; font-size:0.78em; line-height:2.1; font-family:Inter,sans-serif;'>
                    <span style='color:#a5b4fc; font-weight:600;'>summary</span>
                    <span style='color:#64748b;'> -- forensic overview</span><br>
                    <span style='color:#a5b4fc; font-weight:600;'>anomalies</span>
                    <span style='color:#64748b;'> -- threats & outliers</span><br>
                    <span style='color:#a5b4fc; font-weight:600;'>how many users</span>
                    <span style='color:#64748b;'> -- SAM + profiles</span><br>
                    <span style='color:#a5b4fc; font-weight:600;'>files with .pdf</span>
                    <span style='color:#64748b;'> -- filesystem search</span><br>
                    <span style='color:#a5b4fc; font-weight:600;'>installed programs</span>
                    <span style='color:#64748b;'> -- SOFTWARE hive</span><br>
                    <span style='color:#a5b4fc; font-weight:600;'>logs 13:00 to 14:00</span>
                    <span style='color:#64748b;'> -- time range</span><br>
                    <span style='color:#a5b4fc; font-weight:600;'>any question</span>
                    <span style='color:#64748b;'> -- AI analysis</span>
                </div>
            </div>
            \"\"\")

            gr.HTML(\"\"\"
            <div style='background: linear-gradient(135deg, rgba(99,102,241,0.08), rgba(139,92,246,0.06));
                        border: 1px solid rgba(139,92,246,0.15); border-radius: 14px;
                        padding: 16px; margin-top: 12px;'>
                <div style='color:#c4b5fd; font-size:0.65em; letter-spacing:2.5px; font-weight:600;
                            margin-bottom:8px; font-family:Inter,sans-serif;'>AI EXAMPLES</div>
                <div style='color:#a78bfa; font-size:0.75em; line-height:2; font-family:Inter,sans-serif;'>
                    \"Was there a brute force attack?\"<br>
                    \"How many PDF files exist?\"<br>
                    \"List all user accounts\"<br>
                    \"What programs were executed?\"<br>
                    \"Show persistence mechanisms\"
                </div>
            </div>
            \"\"\")

        # -- MAIN CONTENT --
        with gr.Column(scale=3):
            with gr.Tabs(elem_classes="main-tabs"):
                # TAB 1: AI INVESTIGATION (CHAT)
                with gr.Tab("AI Investigation"):
                    gr.HTML(\"\"\"<div style='color:#94a3b8; font-size:0.7em; letter-spacing:2.5px;
                                          font-weight:600; margin-bottom:6px; font-family:Inter,sans-serif;'>
                                 AI INQUIRY TERMINAL</div>\"\"\")
                    query_input = gr.Textbox(
                        label="QUERY",
                        placeholder="Ask anything: how many users? . files with .pdf . installed programs . anomalies . ...",
                        lines=1
                    )
                    with gr.Row():
                        btn = gr.Button("EXECUTE QUERY", variant="primary")
                        stop_btn = gr.Button("STOP", variant="secondary")

                    gr.HTML(\"\"\"<div style='color:#94a3b8; font-size:0.68em; letter-spacing:2px; font-weight:600;
                                          margin:16px 0 8px 0; font-family:Inter,sans-serif;
                                          display:flex; align-items:center; gap:8px;'>
                                 OUTPUT STREAM</div>\"\"\")
                    chat_output = gr.HTML(
                        value=\"\"\"<div style='color:#64748b; font-family:Inter,sans-serif; padding:40px;
                                            text-align:center; font-size:0.95em;'>
                            <div style='font-size:2em; margin-bottom:12px; opacity:0.5;'>[INFO]</div>
                            <div style='font-weight:500;'>Ready for investigation</div>
                            <div style='font-size:0.8em; margin-top:6px; color:#475569;'>
                                Upload evidence and ask any question
                            </div>
                        </div>\"\"\",
                        elem_id="chat-output-box"
                    )

                # TAB 2: DASHBOARD
                with gr.Tab("Dashboard & Summary"):
                    refresh_btn = gr.Button("Generate Dashboard", variant="primary")
                    summary_output = gr.HTML(
                        value=\"\"\"<div style='color:#64748b; font-family:Inter,sans-serif; padding:40px; text-align:center;'>
                            Upload a forensic image and click Generate Dashboard.
                        </div>\"\"\",
                        elem_id="summary-output-box"
                    )

                # TAB 3: ATTACK TIMELINE
                with gr.Tab("Attack Timeline"):
                    timeline_btn = gr.Button("Generate Timeline", variant="primary")
                    timeline_output = gr.HTML(
                        value="<div style='color:#64748b; font-family:Inter,sans-serif; padding:40px; text-align:center;'>Click Generate to view chronological threats.</div>"
                    )

                # TAB 4: RAW ARTIFACTS
                with gr.Tab("Raw Artifacts"):
                    gr.HTML("<div style='color:#94a3b8; font-family:Inter,sans-serif; font-size:0.8em; margin-bottom:10px;'>Browse and filter all extracted evidence artifacts.</div>")
                    artifacts_btn = gr.Button("Load Artifacts", variant="primary")
                    raw_dataframe = gr.Dataframe(interactive=False, wrap=True)

    # -- EVENT BINDINGS --
    file_input.change(handle_image_upload, inputs=file_input, outputs=status, show_progress="full")
    demo_btn.click(handle_demo_load, outputs=status, show_progress="full")
    
    query_click = btn.click(ask_chatbot, inputs=query_input, outputs=chat_output, show_progress="full")
    query_submit = query_input.submit(ask_chatbot, inputs=query_input, outputs=chat_output, show_progress="full")
    stop_btn.click(fn=None, inputs=None, outputs=None, cancels=[query_click, query_submit])
    
    refresh_btn.click(get_investigation_summary, outputs=summary_output, show_progress="hidden")
    timeline_btn.click(get_attack_timeline, outputs=timeline_output, show_progress="hidden")
    artifacts_btn.click(get_raw_artifacts, outputs=raw_dataframe, show_progress="hidden")

demo.launch()
"""

with open(file_path, "w", encoding="utf-8") as f:
    f.writelines(new_lines)
    f.write(ui_code)
print("SUCCESS: File reconstructed and emojis stripped.")
