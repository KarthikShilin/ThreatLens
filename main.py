# main.py
from fastapi import FastAPI
from fastapi.responses import StreamingResponse, JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from scan import scan_tech, get_headers, map_vulnerabilities
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
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

    return {
        "tech_detected": tech_result,
        "headers": headers,
        "vulnerabilities": vulnerabilities
    }


@app.post("/report")
def generate_report(payload: dict):
    """Generate a PDF report from the scan results."""
    url = payload.get("url", "Unknown")
    tech_detected = payload.get("tech_detected", {})
    headers = payload.get("headers", {})
    vulnerabilities = payload.get("vulnerabilities", {})
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
    body_style = ParagraphStyle(
        "BodyStyle", parent=styles["Normal"],
        fontSize=9, textColor=colors.HexColor("#334155"),
        spaceAfter=3, fontName="Helvetica", leading=14
    )
    mono_style = ParagraphStyle(
        "MonoStyle", parent=styles["Normal"],
        fontSize=8, textColor=colors.HexColor("#475569"),
        fontName="Courier", leading=12, spaceAfter=2
    )

    elements = []

    # Header
    elements.append(Paragraph("ThreatLens", title_style))
    elements.append(Paragraph("Web Vulnerability Intelligence Report", subtitle_style))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0ea5e9"), spaceAfter=10))

    # Meta info
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
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(meta_table)

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
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.append(t)
    else:
        elements.append(Paragraph("No technology stack detected.", body_style))

    # Headers
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
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("PADDING", (0, 0), (-1, -1), 5),
            ("FONTNAME", (0, 1), (-1, -1), "Courier"),
        ]))
        elements.append(ht)
    else:
        elements.append(Paragraph(str(headers.get("error", "No headers available.")), body_style))

    # Vulnerabilities
    elements.append(Paragraph("CVE Vulnerability Findings", section_style))
    if vulnerabilities:
        for tech_key, cves in vulnerabilities.items():
            elements.append(Paragraph(
                f">> {tech_key}",
                ParagraphStyle("TechKey", parent=body_style, fontName="Helvetica-Bold", fontSize=10)
            ))
            if not cves:
                elements.append(Paragraph("No CVEs found.", body_style))
                continue
            for cve in cves:
                if "error" in cve:
                    elements.append(Paragraph(f"Error: {cve['error']}", body_style))
                    continue
                sev = cve.get("severity", "UNKNOWN").upper()
                score = cve.get("score", "N/A")
                cve_id = cve.get("id", "N/A")
                desc = cve.get("description", "No description.")[:300]
                sev_color = "#ef4444" if sev in ("CRITICAL", "HIGH") else "#f59e0b" if sev == "MEDIUM" else "#22c55e"

                cve_table = Table([
                    [
                        Paragraph(f"<b>{cve_id}</b>", body_style),
                        Paragraph(f"<font color='{sev_color}'><b>{sev}</b></font>", body_style),
                        Paragraph(f"Score: {score}", body_style),
                    ],
                    [Paragraph(desc, mono_style), "", ""],
                ], colWidths=[5 * cm, 3 * cm, 9 * cm])
                cve_table.setStyle(TableStyle([
                    ("SPAN", (0, 1), (-1, 1)),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                    ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
                    ("PADDING", (0, 0), (-1, -1), 5),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]))
                elements.append(cve_table)
                elements.append(Spacer(1, 4))
            elements.append(Spacer(1, 8))
    else:
        elements.append(Paragraph("No vulnerabilities found.", body_style))

    # Footer
    elements.append(Spacer(1, 20))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e2e8f0")))
    elements.append(Paragraph(
        f"Report generated by ThreatLens | {scan_time} | For authorized security assessment only.",
        ParagraphStyle("Footer", parent=body_style, fontSize=7,
                       textColor=colors.HexColor("#94a3b8"), alignment=TA_CENTER)
    ))

    doc.build(elements)
    buffer.seek(0)

    filename = f"threatlens_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )