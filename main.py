# main.py
from fastapi import FastAPI
from fastapi.responses import StreamingResponse, JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from scan import scan_tech, get_headers, map_vulnerabilities, check_security_headers, build_summary
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, PageBreak
from reportlab.lib.units import cm
from reportlab.lib.enums import TA_LEFT, TA_CENTER
import io
import datetime
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = FastAPI(title="ThreatLens API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Serve the frontend ────────────────────────────────────────
@app.get("/", include_in_schema=False)
def serve_frontend():
    """Serve index.html so the page and API share the same origin."""
    return FileResponse(os.path.join(BASE_DIR, "index.html"))

@app.get("/scan")
def scan(url: str):
    tech_result = scan_tech(url)
    vulnerabilities = {}

    if "tech_stack" in tech_result and tech_result["tech_stack"]:
        vulnerabilities = map_vulnerabilities(tech_result["tech_stack"])

    headers = {}
    try:
        headers = get_headers(url)
    except Exception as e:
        headers = {"error": str(e)}

    # ── New: security headers check + summary ────────────────
    security_header_findings = []
    if not headers.get("error"):
        security_header_findings = check_security_headers(headers)

    summary = build_summary(
        tech_result.get("tech_stack", {}),
        vulnerabilities,
        security_header_findings
    )

    return {
        "tech_detected": tech_result,
        "headers": headers,
        "vulnerabilities": vulnerabilities,
        "security_headers": security_header_findings,
        "summary": summary,
    }


@app.post("/report")
def generate_report(payload: dict):
    """Generate a PDF report from the scan results."""
    url = payload.get("url", "Unknown")
    tech_detected = payload.get("tech_detected", {})
    headers = payload.get("headers", {})
    vulnerabilities = payload.get("vulnerabilities", {})
    summary = payload.get("summary", {})
    security_headers_findings = payload.get("security_headers", [])
    scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm
    )

    styles = getSampleStyleSheet()

    # ── Style definitions ─────────────────────────────────────
    title_style = ParagraphStyle(
        "TitleStyle", parent=styles["Title"],
        fontSize=26, textColor=colors.HexColor("#0f172a"),
        spaceAfter=4, fontName="Helvetica-Bold"
    )
    subtitle_style = ParagraphStyle(
        "SubtitleStyle", parent=styles["Normal"],
        fontSize=11, textColor=colors.HexColor("#64748b"),
        spaceAfter=2, fontName="Helvetica"
    )
    section_style = ParagraphStyle(
        "SectionStyle", parent=styles["Heading2"],
        fontSize=13, textColor=colors.HexColor("#0ea5e9"),
        spaceBefore=16, spaceAfter=6, fontName="Helvetica-Bold"
    )
    exec_section_style = ParagraphStyle(
        "ExecSectionStyle", parent=styles["Heading2"],
        fontSize=13, textColor=colors.HexColor("#0f172a"),
        spaceBefore=14, spaceAfter=6, fontName="Helvetica-Bold"
    )
    body_style = ParagraphStyle(
        "BodyStyle", parent=styles["Normal"],
        fontSize=9, textColor=colors.HexColor("#334155"),
        spaceAfter=3, fontName="Helvetica", leading=14
    )
    body_plain_style = ParagraphStyle(
        "BodyPlainStyle", parent=styles["Normal"],
        fontSize=10, textColor=colors.HexColor("#1e293b"),
        spaceAfter=4, fontName="Helvetica", leading=16
    )
    mono_style = ParagraphStyle(
        "MonoStyle", parent=styles["Normal"],
        fontSize=8, textColor=colors.HexColor("#475569"),
        fontName="Courier", leading=12, spaceAfter=2
    )
    label_style = ParagraphStyle(
        "LabelStyle", parent=styles["Normal"],
        fontSize=8, textColor=colors.HexColor("#64748b"),
        fontName="Helvetica-Bold", spaceAfter=1
    )

    _SEV_COLORS = {
        "CRITICAL": colors.HexColor("#c026d3"),
        "HIGH": colors.HexColor("#dc2626"),
        "MEDIUM": colors.HexColor("#d97706"),
        "LOW": colors.HexColor("#16a34a"),
    }
    _RISK_COLORS = {
        "Critical": colors.HexColor("#c026d3"),
        "High": colors.HexColor("#dc2626"),
        "Medium": colors.HexColor("#d97706"),
        "Low": colors.HexColor("#16a34a"),
    }

    elements = []

    # ════════════════════════════════════════════════════════
    # PAGE 1 — EXECUTIVE SUMMARY
    # ════════════════════════════════════════════════════════
    elements.append(Paragraph("ThreatLens", title_style))
    elements.append(Paragraph("Executive Security Summary", subtitle_style))
    elements.append(HRFlowable(width="100%", thickness=1.5,
                               color=colors.HexColor("#0ea5e9"), spaceAfter=10))

    # Scan meta
    meta_data = [
        ["Target URL", url],
        ["Scan Date", scan_time],
        ["HTTP Status", str(tech_detected.get("status", "N/A"))],
    ]
    meta_table = Table(meta_data, colWidths=[4 * cm, 13 * cm])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1),
         [colors.HexColor("#f8fafc"), colors.white]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 12))

    # Overall risk badge
    overall_risk = summary.get("overall_risk", "Unknown")
    risk_color = _RISK_COLORS.get(overall_risk, colors.HexColor("#64748b"))
    risk_table = Table(
        [[Paragraph(f"Overall Risk: <b>{overall_risk}</b>",
                    ParagraphStyle("Risk", parent=body_plain_style,
                                   fontSize=14,
                                   textColor=risk_color,
                                   fontName="Helvetica-Bold"))]],
        colWidths=[17 * cm]
    )
    risk_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 1.5, risk_color),
        ("PADDING", (0, 0), (-1, -1), 12),
        ("RADIUS", (0, 0), (-1, -1), 4),
    ]))
    elements.append(risk_table)
    elements.append(Spacer(1, 6))

    # What we checked
    what_checked = summary.get("what_we_checked", "")
    if what_checked:
        elements.append(Paragraph(what_checked, ParagraphStyle(
            "Checked", parent=body_plain_style,
            fontSize=9, textColor=colors.HexColor("#64748b")
        )))

    elements.append(Spacer(1, 4))
    elements.append(Paragraph(
        "<i>Note: CVE matching is keyword-based and may produce false positives. "
        "Results should be reviewed by a qualified security professional.</i>",
        ParagraphStyle("Disclaimer", parent=body_style, fontSize=8,
                       textColor=colors.HexColor("#94a3b8"))
    ))

    # Top findings (executive, plain English)
    findings = summary.get("findings", [])
    if findings:
        elements.append(Paragraph("Key Findings", exec_section_style))
        for i, finding in enumerate(findings[:5], 1):
            sev = finding.get("severity", "UNKNOWN").upper()
            sev_color = _SEV_COLORS.get(sev, colors.HexColor("#64748b"))

            finding_data = [
                [
                    Paragraph(f"<b>{i}. {finding.get('title', 'Finding')}</b>",
                              ParagraphStyle("FTitle", parent=body_plain_style,
                                             fontSize=10, fontName="Helvetica-Bold")),
                    Paragraph(f"<b>{sev}</b>",
                              ParagraphStyle("FSev", parent=body_style,
                                             textColor=sev_color,
                                             fontName="Helvetica-Bold",
                                             alignment=TA_CENTER)),
                ],
                [
                    Paragraph(finding.get("plain_explanation", ""),
                              ParagraphStyle("FExp", parent=body_plain_style,
                                             fontSize=9, textColor=colors.HexColor("#334155"))),
                    "",
                ],
                [
                    Paragraph(
                        f"<b>What to do:</b> {finding.get('recommended_fix', '')}",
                        ParagraphStyle("FFix", parent=body_style,
                                       fontSize=9, textColor=colors.HexColor("#0369a1"))
                    ),
                    "",
                ],
            ]
            ft = Table(finding_data, colWidths=[14 * cm, 3 * cm])
            ft.setStyle(TableStyle([
                ("SPAN", (0, 1), (-1, 1)),
                ("SPAN", (0, 2), (-1, 2)),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("BACKGROUND", (0, 2), (-1, 2), colors.HexColor("#f0f9ff")),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
                ("PADDING", (0, 0), (-1, -1), 6),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ALIGN", (1, 0), (1, 0), "CENTER"),
                ("LEFTPADDING", (1, 0), (1, 0), 4),
            ]))
            elements.append(ft)
            elements.append(Spacer(1, 6))

    # Executive footer note
    elements.append(Spacer(1, 16))
    elements.append(HRFlowable(width="100%", thickness=0.5,
                               color=colors.HexColor("#e2e8f0")))
    elements.append(Paragraph(
        "For authorized security assessment only. "
        "This report is generated automatically by ThreatLens and should "
        "be reviewed by a qualified security professional before action is taken.",
        ParagraphStyle("ExecFooter", parent=body_style, fontSize=7,
                       textColor=colors.HexColor("#94a3b8"), alignment=TA_CENTER)
    ))

    # ════════════════════════════════════════════════════════
    # PAGE 2+ — TECHNICAL APPENDIX
    # ════════════════════════════════════════════════════════
    elements.append(PageBreak())
    elements.append(Paragraph("Technical Appendix", title_style))
    elements.append(Paragraph("Detailed Findings", subtitle_style))
    elements.append(HRFlowable(width="100%", thickness=1.5,
                               color=colors.HexColor("#0ea5e9"), spaceAfter=10))

    # Tech Stack
    elements.append(Paragraph("Detected Technology Stack", section_style))
    tech_stack = tech_detected.get("tech_stack", {})
    if tech_stack:
        tech_rows = [["Technology", "Version / Details"]]
        for tech, values in tech_stack.items():
            vals = values if isinstance(values, list) else [str(values)]
            tech_rows.append([tech, ", ".join(str(v) for v in vals)])
        t = Table(tech_rows, colWidths=[6 * cm, 11 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0ea5e9")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.HexColor("#f8fafc"), colors.white]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.append(t)
    else:
        elements.append(Paragraph("No technology stack detected.", body_style))

    # Security Headers
    elements.append(Paragraph("Security Header Analysis", section_style))
    if security_headers_findings:
        sh_rows = [["Missing Header", "Risk", "Recommendation"]]
        for f in security_headers_findings:
            title_parts = f.get("title", "").replace("Missing security header: ", "")
            sh_rows.append([title_parts, f.get("severity", "MEDIUM"), f.get("recommended_fix", "")])
        sht = Table(sh_rows, colWidths=[5 * cm, 2.5 * cm, 9.5 * cm])
        sht.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f59e0b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.HexColor("#fffbeb"), colors.white]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]))
        elements.append(sht)
    else:
        elements.append(Paragraph(
            "All checked security headers are present.", body_style))

    # HTTP Response Headers
    elements.append(Paragraph("HTTP Response Headers", section_style))
    if headers and "error" not in headers:
        header_rows = [["Header", "Value"]]
        for k, v in list(headers.items())[:20]:
            header_rows.append([k, str(v)[:80]])
        ht = Table(header_rows, colWidths=[7 * cm, 10 * cm])
        ht.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#334155")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.HexColor("#f8fafc"), colors.white]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("PADDING", (0, 0), (-1, -1), 5),
            ("FONTNAME", (0, 1), (-1, -1), "Courier"),
        ]))
        elements.append(ht)
    else:
        elements.append(Paragraph(
            str(headers.get("error", "No headers available.")), body_style))

    # CVE Vulnerabilities
    elements.append(Paragraph("CVE Vulnerability Findings", section_style))
    if vulnerabilities:
        for tech_key, cves in vulnerabilities.items():
            elements.append(Paragraph(
                f">> {tech_key}",
                ParagraphStyle("TechKey", parent=body_style,
                               fontName="Helvetica-Bold", fontSize=10)
            ))
            if not cves:
                elements.append(Paragraph("No CVEs found.", body_style))
                continue
            for cve in cves:
                if "error" in cve:
                    elements.append(
                        Paragraph(f"Error: {cve['error']}", body_style))
                    continue
                sev = cve.get("severity", "UNKNOWN").upper()
                score = cve.get("score", "N/A")
                cve_id = cve.get("id", "N/A")
                desc = cve.get("description", "No description.")[:300]
                sev_color = (
                    "#ef4444" if sev in ("CRITICAL", "HIGH")
                    else "#f59e0b" if sev == "MEDIUM"
                    else "#22c55e"
                )

                cve_table = Table([
                    [
                        Paragraph(f"<b>{cve_id}</b>", body_style),
                        Paragraph(
                            f"<font color='{sev_color}'><b>{sev}</b></font>",
                            body_style),
                        Paragraph(f"Score: {score}", body_style),
                    ],
                    [Paragraph(desc, mono_style), "", ""],
                ], colWidths=[5 * cm, 3 * cm, 9 * cm])
                cve_table.setStyle(TableStyle([
                    ("SPAN", (0, 1), (-1, 1)),
                    ("BACKGROUND", (0, 0), (-1, 0),
                     colors.HexColor("#f1f5f9")),
                    ("GRID", (0, 0), (-1, -1), 0.3,
                     colors.HexColor("#e2e8f0")),
                    ("PADDING", (0, 0), (-1, -1), 5),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]))
                elements.append(cve_table)
                elements.append(Spacer(1, 4))
            elements.append(Spacer(1, 8))
    else:
        elements.append(Paragraph("No vulnerabilities found.", body_style))

    # Appendix footer
    elements.append(Spacer(1, 20))
    elements.append(HRFlowable(width="100%", thickness=0.5,
                               color=colors.HexColor("#e2e8f0")))
    elements.append(Paragraph(
        f"Report generated by ThreatLens | {scan_time} | "
        "For authorized security assessment only.",
        ParagraphStyle("Footer", parent=body_style, fontSize=7,
                       textColor=colors.HexColor("#94a3b8"),
                       alignment=TA_CENTER)
    ))

    doc.build(elements)
    buffer.seek(0)

    filename = (
        f"threatlens_report_"
        f"{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    )
    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )