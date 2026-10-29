import os
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas to dynamically compute and print 'Page X of Y'."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, total_pages):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))
        
        # Header (pages after page 1)
        if self._pageNumber > 1:
            self.drawString(40, 810, "Scrum Book Model — Mini Project (10 Weeks)")
            self.drawRightString(555, 810, "Start Date: 14 July")
            self.setStrokeColor(colors.HexColor("#CBD5E1"))
            self.setLineWidth(0.5)
            self.line(40, 804, 555, 804)
            
        # Footer
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.5)
        self.line(40, 36, 555, 36)
        self.drawString(40, 24, "ThreatLens Mini Project — Agile Scrum Logbook")
        self.drawRightString(555, 24, f"Page {self._pageNumber} of {total_pages}")
        self.restoreState()


def build_pdf(filename="Scrum_Book_Model.pdf"):
    doc = SimpleDocTemplate(
        filename,
        pagesize=A4,
        leftMargin=40,
        rightMargin=40,
        topMargin=48,
        bottomMargin=48
    )

    styles = getSampleStyleSheet()
    
    # Custom Palette
    PRIMARY = colors.HexColor("#0F172A")    # Slate 900
    ACCENT = colors.HexColor("#1D4ED8")     # Blue 700
    TEXT_DARK = colors.HexColor("#1E293B")  # Slate 800
    TEXT_MUTED = colors.HexColor("#64748B") # Slate 500
    BG_LIGHT = colors.HexColor("#F8FAFC")   # Slate 50
    BORDER_COLOR = colors.HexColor("#E2E8F0")

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=PRIMARY,
        spaceAfter=4
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=TEXT_MUTED,
        spaceAfter=12
    )

    h1_style = ParagraphStyle(
        'Heading1',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=16,
        textColor=ACCENT,
        spaceBefore=10,
        spaceAfter=6
    )

    h2_style = ParagraphStyle(
        'Heading2',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=13,
        textColor=PRIMARY,
        spaceBefore=6,
        spaceAfter=4
    )

    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=11.5,
        textColor=TEXT_DARK
    )

    body_bold = ParagraphStyle(
        'BodyBold',
        parent=body_style,
        fontName='Helvetica-Bold'
    )

    th_style = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=11,
        textColor=colors.white
    )

    status_done = ParagraphStyle(
        'StatusDone',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#166534") # Green 800
    )

    story = []

    # Title Banner
    story.append(Paragraph("PROJECT SCRUM BOOK", title_style))
    story.append(Paragraph("<b>Academic Mini Project</b> &nbsp;|&nbsp; <b>Team Size:</b> 3 Members &nbsp;|&nbsp; <b>Duration:</b> 10 Weeks &nbsp;|&nbsp; <b>Start Date:</b> 14 July", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=ACCENT, spaceBefore=0, spaceAfter=10))

    # Section 1: Team Overview
    story.append(Paragraph("1. Scrum Team Roles & Responsibilities", h1_style))
    team_data = [
        [Paragraph("Team Member", th_style), Paragraph("Scrum Role", th_style), Paragraph("Primary Responsibilities", th_style)],
        [Paragraph("<b>Member 1</b>", body_style), Paragraph("Product Owner & Dev", body_style), Paragraph("Feature prioritization, project requirements, and core logic development.", body_style)],
        [Paragraph("<b>Member 2</b>", body_style), Paragraph("Scrum Master & Dev", body_style), Paragraph("Meeting coordination, blocker removal, data validation & backend services.", body_style)],
        [Paragraph("<b>Member 3</b>", body_style), Paragraph("QA & UI Developer", body_style), Paragraph("User interface design, system testing, report formatting & demo presentation.", body_style)],
    ]
    t_team = Table(team_data, colWidths=[95, 125, 295])
    t_team.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), PRIMARY),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_LIGHT]),
        ('GRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
    ]))
    story.append(t_team)
    story.append(Spacer(1, 10))

    # Section 2: 10-Week Sprint Schedule
    story.append(Paragraph("2. 10-Week Sprint Schedule (5 Sprints)", h1_style))
    sched_data = [
        [Paragraph("Sprint", th_style), Paragraph("Timeline", th_style), Paragraph("Sprint Goal & Primary Focus", th_style), Paragraph("Key Milestone", th_style)],
        [Paragraph("<b>Sprint 1</b>", body_style), Paragraph("Weeks 1–2<br/>(Jul 14 – Jul 27)", body_style), Paragraph("<b>Planning & Setup:</b> Scope approval, system architecture design, and tool environment setup.", body_style), Paragraph("Project Skeleton", body_style)],
        [Paragraph("<b>Sprint 2</b>", body_style), Paragraph("Weeks 3–4<br/>(Jul 28 – Aug 10)", body_style), Paragraph("<b>Core Development:</b> Build primary workflow logic, input validation, and initial user screens.", body_style), Paragraph("Working Base Modules", body_style)],
        [Paragraph("<b>Sprint 3</b>", body_style), Paragraph("Weeks 5–6<br/>(Aug 11 – Aug 24)", body_style), Paragraph("<b>Key Features:</b> Implement data processing, background tasks, and external lookup services.", body_style), Paragraph("Data Flow Integrated", body_style)],
        [Paragraph("<b>Sprint 4</b>", body_style), Paragraph("Weeks 7–8<br/>(Aug 25 – Sep 07)", body_style), Paragraph("<b>UI & Reporting:</b> Complete interactive dashboard, search/filter controls, and PDF report generator.", body_style), Paragraph("Functional Prototype", body_style)],
        [Paragraph("<b>Sprint 5</b>", body_style), Paragraph("Weeks 9–10<br/>(Sep 08 – Sep 21)", body_style), Paragraph("<b>Testing & Final Demo:</b> Comprehensive testing, bug fixes, final project report, and demo slides.", body_style), Paragraph("Final Project Defense", body_style)],
    ]
    t_sched = Table(sched_data, colWidths=[55, 95, 255, 110])
    t_sched.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), ACCENT),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_LIGHT]),
        ('GRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
    ]))
    story.append(t_sched)
    story.append(Spacer(1, 10))

    # Section 3: Sprint Details
    story.append(Paragraph("3. Sprint-by-Sprint Task Breakdown", h1_style))
    
    sprints = [
        ("Sprint 1 (Jul 14 – Jul 27): Requirements, Research & Initial Setup", [
            ("Finalize problem statement and scope with project guide", "Member 1", "Completed"),
            ("Set up version control repository and collaboration channels", "Member 2", "Completed"),
            ("Design initial UI wireframes and user flow sketches", "Member 3", "Completed"),
            ("Complete literature survey and prepare requirement specification", "All Members", "Completed"),
        ]),
        ("Sprint 2 (Jul 28 – Aug 10): Core Module Development", [
            ("Develop primary backend workflow and request handling logic", "Member 1", "Completed"),
            ("Implement safety rules and input parameter validation", "Member 2", "Completed"),
            ("Build initial web layout, navigation, and theme styling", "Member 3", "Completed"),
            ("Conduct Sprint 2 team review and baseline code demo", "All Members", "Completed"),
        ]),
        ("Sprint 3 (Aug 11 – Aug 24): Key Features & Data Processing", [
            ("Build background worker tasks for heavy computing operations", "Member 1", "Completed"),
            ("Integrate database connectivity and external lookup services", "Member 2", "Completed"),
            ("Create input forms, file upload handling, and status alerts", "Member 3", "Completed"),
            ("Review sprint milestones and remove progress blockers", "All Members", "Completed"),
        ]),
        ("Sprint 4 (Aug 25 – Sep 07): User Interface Refinement & Reporting", [
            ("Connect frontend user interactions directly to backend APIs", "Member 1", "Completed"),
            ("Implement result categorization, sorting, and filter logic", "Member 2", "Completed"),
            ("Design and format automated PDF summary/audit reports", "Member 3", "Completed"),
            ("Refine visual feedback, loading states, and responsive styling", "Member 3", "Completed"),
        ]),
        ("Sprint 5 (Sep 08 – Sep 21): Testing, Documentation & Final Defense", [
            ("Perform end-to-end system testing and resolve bug reports", "Member 1", "Completed"),
            ("Conduct performance and edge-case validation checks", "Member 2", "Completed"),
            ("Compile final project report documentation and user guide", "Member 3", "Completed"),
            ("Finalize presentation slide deck and conduct defense rehearsal", "All Members", "Completed"),
        ]),
    ]

    for title, tasks in sprints:
        sprint_rows = [
            [Paragraph(f"<b>{title}</b>", th_style), Paragraph("Assigned", th_style), Paragraph("Status", th_style)]
        ]
        for desc, owner, status in tasks:
            sprint_rows.append([
                Paragraph(desc, body_style),
                Paragraph(f"<b>{owner}</b>", body_style),
                Paragraph(f"<b>✓ {status}</b>", status_done)
            ])
        t_sp = Table(sprint_rows, colWidths=[360, 95, 60])
        t_sp.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), PRIMARY),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_LIGHT]),
            ('GRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ]))
        story.append(KeepTogether([t_sp, Spacer(1, 6)]))

    # Page Break for clean weekly matrix & logbook
    story.append(PageBreak())

    # Section 4: Weekly Member Matrix
    story.append(Paragraph("4. Week-by-Week Member Task Matrix (10 Weeks)", h1_style))
    matrix_data = [
        [Paragraph("Wk", th_style), Paragraph("Dates", th_style), Paragraph("Member 1 (Product Owner / Dev)", th_style), Paragraph("Member 2 (Scrum Master / Dev)", th_style), Paragraph("Member 3 (QA & UI / Reports)", th_style)],
        [Paragraph("<b>W1</b>", body_style), Paragraph("Jul 14–20", body_style), Paragraph("Requirements & scope definition", body_style), Paragraph("Repo setup & dev environment", body_style), Paragraph("UI wireframing & sketches", body_style)],
        [Paragraph("<b>W2</b>", body_style), Paragraph("Jul 21–27", body_style), Paragraph("Project skeleton & routing setup", body_style), Paragraph("Environment configs & security", body_style), Paragraph("Initial HTML/CSS templates", body_style)],
        [Paragraph("<b>W3</b>", body_style), Paragraph("Jul 28–Aug 03", body_style), Paragraph("Core request processing logic", body_style), Paragraph("Input rule engine implementation", body_style), Paragraph("Form inputs & visual layout", body_style)],
        [Paragraph("<b>W4</b>", body_style), Paragraph("Aug 04–10", body_style), Paragraph("Backend module integration", body_style), Paragraph("Data validation checks", body_style), Paragraph("Results display screen", body_style)],
        [Paragraph("<b>W5</b>", body_style), Paragraph("Aug 11–17", body_style), Paragraph("Background task handler setup", body_style), Paragraph("Data lookup service integration", body_style), Paragraph("File upload & media preview", body_style)],
        [Paragraph("<b>W6</b>", body_style), Paragraph("Aug 18–24", body_style), Paragraph("Processing speed optimization", body_style), Paragraph("Database connectivity logic", body_style), Paragraph("Status notifications & alerts", body_style)],
        [Paragraph("<b>W7</b>", body_style), Paragraph("Aug 25–31", body_style), Paragraph("API hookups to web frontend", body_style), Paragraph("Result categorization logic", body_style), Paragraph("Dashboard polish & styling", body_style)],
        [Paragraph("<b>W8</b>", body_style), Paragraph("Sep 01–07", body_style), Paragraph("Live status & telemetry", body_style), Paragraph("Data export formatting", body_style), Paragraph("PDF report generation engine", body_style)],
        [Paragraph("<b>W9</b>", body_style), Paragraph("Sep 08–14", body_style), Paragraph("Bug fixing & error handling", body_style), Paragraph("Integration testing & checks", body_style), Paragraph("Project report draft & docs", body_style)],
        [Paragraph("<b>W10</b>", body_style), Paragraph("Sep 15–21", body_style), Paragraph("Final code cleanup & polish", body_style), Paragraph("Performance verification", body_style), Paragraph("Final documentation & slides", body_style)],
    ]
    t_mat = Table(matrix_data, colWidths=[24, 60, 143, 144, 144])
    t_mat.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), PRIMARY),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_LIGHT]),
        ('GRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
    ]))
    story.append(t_mat)
    story.append(Spacer(1, 10))

    # Section 5: Scrum Meetings & Retrospective
    story.append(Paragraph("5. Sprint Retrospective Log (Continuous Improvement)", h1_style))
    retro_data = [
        [Paragraph("Sprint", th_style), Paragraph("Date", th_style), Paragraph("What Went Well", th_style), Paragraph("Challenges Faced", th_style), Paragraph("Action Taken / Solution", th_style)],
        [Paragraph("<b>Sprint 1</b>", body_style), Paragraph("Jul 27", body_style), Paragraph("Requirements and repo initialized on schedule.", body_style), Paragraph("Determining exact feature boundaries.", body_style), Paragraph("Consulted project guide to fix boundaries.", body_style)],
        [Paragraph("<b>Sprint 2</b>", body_style), Paragraph("Aug 10", body_style), Paragraph("Core module architecture established.", body_style), Paragraph("Integrating member code created minor merge conflicts.", body_style), Paragraph("Adopted dedicated Git feature branches.", body_style)],
        [Paragraph("<b>Sprint 3</b>", body_style), Paragraph("Aug 24", body_style), Paragraph("Key features & background tasks working smoothly.", body_style), Paragraph("External lookup queries had occasional delays.", body_style), Paragraph("Implemented request caching & timeouts.", body_style)],
        [Paragraph("<b>Sprint 4</b>", body_style), Paragraph("Sep 07", body_style), Paragraph("Dashboard UI and report export look polished.", body_style), Paragraph("PDF layout formatting took longer than planned.", body_style), Paragraph("Standardized table widths and fonts.", body_style)],
        [Paragraph("<b>Sprint 5</b>", body_style), Paragraph("Sep 21", body_style), Paragraph("System testing completed; zero blockers remaining.", body_style), Paragraph("Balancing report writing with presentation rehearsal.", body_style), Paragraph("Divided report sections evenly among team.", body_style)],
    ]
    t_retro = Table(retro_data, colWidths=[48, 42, 140, 140, 145])
    t_retro.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), ACCENT),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_LIGHT]),
        ('GRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
    ]))
    story.append(t_retro)
    story.append(Spacer(1, 10))

    # Section 6: Project Guide Sign-Off Sheet
    story.append(Paragraph("6. Project Guide Review & Sign-Off Sheet", h1_style))
    sign_data = [
        [Paragraph("Review Stage", th_style), Paragraph("Target Week", th_style), Paragraph("Guide Remarks & Feedback", th_style), Paragraph("Sign & Date", th_style)],
        [Paragraph("<b>Review 1: Scope & Architecture</b>", body_style), Paragraph("Week 2", body_style), Paragraph("", body_style), Paragraph("", body_style)],
        [Paragraph("<b>Review 2: Mid-Term Progress (50%)</b>", body_style), Paragraph("Week 5", body_style), Paragraph("", body_style), Paragraph("", body_style)],
        [Paragraph("<b>Review 3: Functional Prototype Demo</b>", body_style), Paragraph("Week 8", body_style), Paragraph("", body_style), Paragraph("", body_style)],
        [Paragraph("<b>Final Review: Complete System & Defense</b>", body_style), Paragraph("Week 10", body_style), Paragraph("", body_style), Paragraph("", body_style)],
    ]
    t_sign = Table(sign_data, colWidths=[165, 65, 195, 90])
    t_sign.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), PRIMARY),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_LIGHT]),
        ('GRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
    ]))
    story.append(KeepTogether([t_sign]))

    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"Successfully generated: {filename}")

if __name__ == "__main__":
    build_pdf("Scrum_Book_Model.pdf")
