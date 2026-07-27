"""Forensic PDF report generation."""

import os
import re
import traceback
from datetime import datetime

from .config import CACHE_DIR
from .context import extract_system_context

def generate_pdf_report(inv_name, case_num, notes_text, session):
    """Generate a professional forensic PDF report from the current session."""
    if session.current_audit_df is None:
        return None, "No forensic image loaded. Upload an image first."

    if not inv_name.strip():
        inv_name = "Unknown Examiner"
    if not case_num.strip():
        case_num = "CASE-UNASSIGNED"

    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer,
            Table, TableStyle, HRFlowable
        )

# Write to temp dir — guaranteed writable, Gradio can serve from here
        report_filename = (
            f"ForensicReport_{case_num.replace(' ', '_')}_"
            f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        )
        report_dir = os.path.join(CACHE_DIR, "reports")
        os.makedirs(report_dir, exist_ok=True)
        report_path = os.path.join(report_dir, report_filename)

        doc = SimpleDocTemplate(
            report_path, pagesize=A4,
            leftMargin=2*cm, rightMargin=2*cm,
            topMargin=2*cm, bottomMargin=2*cm
        )

        styles = getSampleStyleSheet()

        # Custom styles
        title_style = ParagraphStyle(
            'ForensicTitle',
            parent=styles['Title'],
            fontSize=20, textColor=colors.HexColor('#1e3a5f'),
            spaceAfter=6, fontName='Helvetica-Bold'
        )
        heading_style = ParagraphStyle(
            'ForensicHeading',
            parent=styles['Heading2'],
            fontSize=13, textColor=colors.HexColor('#1e3a5f'),
            spaceBefore=14, spaceAfter=4, fontName='Helvetica-Bold'
        )
        subheading_style = ParagraphStyle(
            'ForensicSub',
            parent=styles['Heading3'],
            fontSize=10, textColor=colors.HexColor('#2d6a9f'),
            spaceBefore=10, spaceAfter=2, fontName='Helvetica-Bold'
        )
        body_style = ParagraphStyle(
            'ForensicBody',
            parent=styles['Normal'],
            fontSize=9, leading=14,
            textColor=colors.HexColor('#1a1a1a'), fontName='Helvetica'
        )
        mono_style = ParagraphStyle(
            'ForensicMono',
            parent=styles['Code'],
            fontSize=8, leading=12,
            textColor=colors.HexColor('#2d2d2d'),
            backColor=colors.HexColor('#f4f4f4'),
            fontName='Courier', leftIndent=10
        )
        note_style = ParagraphStyle(
            'ForensicNote',
            parent=styles['Normal'],
            fontSize=9, leading=13, fontName='Helvetica-Oblique',
            textColor=colors.HexColor('#555555')
        )

        story = []
        system_facts = extract_system_context(session)

        # ── HEADER ────────────────────────────────────────────────────────────
        story.append(Paragraph("DIGITAL FORENSIC EXAMINATION REPORT", title_style))
        story.append(HRFlowable(width="100%", thickness=2,
                                color=colors.HexColor('#1e3a5f')))
        story.append(Spacer(1, 0.3*cm))

        # Case metadata table
        meta_data = [
            ["Case Number",      case_num,
             "Report Generated", datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
            ["Examiner",         inv_name,
             "Image SHA-256",    (session.image_hash_sha256 or "N/A")[:32] + "..."],
            ["Classification",   "CONFIDENTIAL",
             "Total Artifacts",  str(len(session.current_audit_df))],
        ]
        meta_table = Table(meta_data, colWidths=[3.5*cm, 6*cm, 3.5*cm, 6*cm])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,-1), colors.HexColor('#1e3a5f')),
            ('BACKGROUND', (2,0), (2,-1), colors.HexColor('#1e3a5f')),
            ('TEXTCOLOR',  (0,0), (0,-1), colors.white),
            ('TEXTCOLOR',  (2,0), (2,-1), colors.white),
            ('FONTNAME',   (0,0), (-1,-1), 'Helvetica'),
            ('FONTNAME',   (0,0), (0,-1),  'Helvetica-Bold'),
            ('FONTNAME',   (2,0), (2,-1),  'Helvetica-Bold'),
            ('FONTSIZE',   (0,0), (-1,-1), 8),
            ('GRID',       (0,0), (-1,-1), 0.5, colors.HexColor('#cccccc')),
            ('ROWBACKGROUNDS', (1,0), (-1,-1),
             [colors.HexColor('#f0f4f8'), colors.HexColor('#ffffff')]),
            ('PADDING',    (0,0), (-1,-1), 6),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 0.4*cm))

        # ── EXAMINER NOTES ────────────────────────────────────────────────────
        if notes_text and notes_text.strip():
            story.append(Paragraph("Examiner Notes", heading_style))
            story.append(HRFlowable(width="100%", thickness=0.5,
                                    color=colors.HexColor('#cccccc')))
            story.append(Spacer(1, 0.2*cm))
            story.append(Paragraph(notes_text.strip(), note_style))
            story.append(Spacer(1, 0.3*cm))

        # ── SYSTEM SUMMARY ────────────────────────────────────────────────────
        story.append(Paragraph("System & Evidence Summary", heading_style))
        story.append(HRFlowable(width="100%", thickness=0.5,
                                color=colors.HexColor('#cccccc')))
        story.append(Spacer(1, 0.2*cm))

        for line in system_facts.split('\n'):
            line = line.strip()
            if not line:
                continue
            if ':' in line:
                key, _, val = line.partition(':')
                styled_line = f"<b>{key.strip()}:</b> {val.strip()}"
            else:
                styled_line = line
            story.append(Paragraph(styled_line, body_style))
        story.append(Spacer(1, 0.4*cm))

        # ── INVESTIGATION Q&A LOG ─────────────────────────────────────────────
        if session.session_log:
            story.append(Paragraph("Investigation Query Log", heading_style))
            story.append(HRFlowable(width="100%", thickness=0.5,
                                    color=colors.HexColor('#cccccc')))
            story.append(Spacer(1, 0.2*cm))

            for i, entry in enumerate(session.session_log, 1):
                story.append(Paragraph(
                    f"Query {i} — {entry.get('time', 'N/A')}",
                    subheading_style
                ))
                story.append(Paragraph(
                    f"<b>Q:</b> {entry['question']}", body_style
                ))
                story.append(Spacer(1, 0.1*cm))

                # Clean answer text for PDF
                answer = entry['answer']
                answer = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', answer)
                answer = re.sub(r'\*(.*?)\*',   r'<i>\1</i>', answer)

                for line in answer.split('\n'):
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith('- ') or line.startswith('• '):
                        story.append(Paragraph(
                            f"&nbsp;&nbsp;&nbsp;• {line[2:]}", body_style
                        ))
                    else:
                        story.append(Paragraph(line, body_style))

                story.append(Spacer(1, 0.3*cm))
        else:
            story.append(Paragraph("Investigation Query Log", heading_style))
            story.append(Paragraph(
                "No queries were made during this session.", note_style
            ))

        # ── ARTIFACT COUNTS ───────────────────────────────────────────────────
        story.append(Paragraph("Artifact Extraction Summary", heading_style))
        story.append(HRFlowable(width="100%", thickness=0.5,
                                color=colors.HexColor('#cccccc')))
        story.append(Spacer(1, 0.2*cm))

        if session.artifact_counts:
            counts_data = [["Artifact Type", "Count"]]
            for k, v in session.artifact_counts.items():
                if k != "total":
                    counts_data.append([k.upper(), str(v)])
            counts_data.append(["TOTAL", str(session.artifact_counts.get("total", len(session.current_audit_df)))])

            counts_table = Table(counts_data, colWidths=[8*cm, 4*cm])
            counts_table.setStyle(TableStyle([
                ('BACKGROUND',     (0,0), (-1,0),  colors.HexColor('#1e3a5f')),
                ('TEXTCOLOR',      (0,0), (-1,0),  colors.white),
                ('FONTNAME',       (0,0), (-1,0),  'Helvetica-Bold'),
                ('FONTNAME',       (0,1), (-1,-1), 'Helvetica'),
                ('FONTSIZE',       (0,0), (-1,-1), 9),
                ('ROWBACKGROUNDS', (0,1), (-1,-2),
                 [colors.HexColor('#f0f4f8'), colors.HexColor('#ffffff')]),
                ('BACKGROUND',     (0,-1), (-1,-1), colors.HexColor('#e8f0e8')),
                ('FONTNAME',       (0,-1), (-1,-1), 'Helvetica-Bold'),
                ('GRID',           (0,0), (-1,-1), 0.5, colors.HexColor('#cccccc')),
                ('ALIGN',          (1,0), (1,-1),  'CENTER'),
                ('PADDING',        (0,0), (-1,-1), 6),
            ]))
            story.append(counts_table)

        # ── FOOTER ────────────────────────────────────────────────────────────
        story.append(Spacer(1, 0.5*cm))
        story.append(HRFlowable(width="100%", thickness=1,
                                color=colors.HexColor('#1e3a5f')))
        story.append(Paragraph(
            f"Report generated by VIGILANCE FORENSIC ENGINE v3.1 | "
            f"Examiner: {inv_name} | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            ParagraphStyle('footer', parent=styles['Normal'],
                           fontSize=7, textColor=colors.HexColor('#888888'),
                           alignment=1)
        ))

        doc.build(story)

        if not os.path.exists(report_path):
            return None, "❌ PDF file was not created — unknown write error."
        size_kb = os.path.getsize(report_path) / 1024
        if size_kb < 1:
            return None, "❌ PDF file is empty — ReportLab build failed silently."

        print(f"  [REPORT] Generated: {report_path} ({size_kb:.1f} KB)")
        return report_path, f"✅ Report ready — {os.path.basename(report_path)} ({size_kb:.1f} KB)"

    except ImportError:
        return None, "❌ ReportLab not installed. Run: pip install reportlab"
    except Exception as e:
        traceback.print_exc()
        return None, f"❌ Report generation failed: {type(e).__name__}: {e}"
