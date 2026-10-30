"""PDF version of a launchcheck report: the score, what to fix first, and every finding with its fix.
Built from the same data as the HTML report (report.build), with reportlab (pure Python)."""
from __future__ import annotations

import io
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle

INK, MUT, LINE = colors.HexColor("#111311"), colors.HexColor("#5d625e"), colors.HexColor("#e4e5e0")
SEV = {"high": ("Fix now", colors.HexColor("#c2321f")), "medium": ("Fix soon", colors.HexColor("#b26b00")),
       "low": ("Good to fix", colors.HexColor("#2b5fa8")), "info": ("Note", MUT)}


def _styles():
    ss = getSampleStyleSheet()
    base = ParagraphStyle("b", parent=ss["Normal"], fontName="Helvetica", fontSize=9.5, leading=13.5, textColor=INK)
    return {
        "title": ParagraphStyle("t", parent=base, fontName="Helvetica-Bold", fontSize=22, leading=26),
        "sub": ParagraphStyle("s", parent=base, fontSize=9, textColor=MUT),
        "h": ParagraphStyle("h", parent=base, fontName="Helvetica-Bold", fontSize=13, leading=17, spaceBefore=12, spaceAfter=6),
        "ft": ParagraphStyle("ft", parent=base, fontName="Helvetica-Bold", fontSize=10.5, leading=14),
        "b": base, "small": ParagraphStyle("sm", parent=base, fontSize=8, leading=10.5, textColor=MUT),
        "code": ParagraphStyle("c", parent=base, fontName="Helvetica", fontSize=8.5, leading=11.5, textColor=INK, backColor=colors.HexColor("#f2f3ef"), borderPadding=5),
    }


def build_pdf(data: dict) -> bytes:
    S = _styles()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
                            title=f"launchcheck report - {data['target']}", author="launchcheck")
    W = A4[0] - 36 * mm
    c = data["counts"]
    score = Table([[Paragraph(f"<font size=40><b>{data['score']}</b></font>", S["b"]),
                    Paragraph(f"<b>Grade {data['grade']}</b><br/>{c['high']} fix now &nbsp; {c['medium']} fix soon &nbsp; "
                              f"{c['low']} good to fix &nbsp; {c['info']} notes", S["b"])]], colWidths=[34 * mm, W - 34 * mm])
    score.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f2f3ef")),
                               ("LEFTPADDING", (0, 0), (-1, -1), 10), ("TOPPADDING", (0, 0), (-1, -1), 10), ("BOTTOMPADDING", (0, 0), (-1, -1), 12)]))
    el = [Paragraph("launchcheck report", S["title"]), Paragraph(f"{escape(data['target'])} &nbsp;·&nbsp; {escape(data['checked_at'])}", S["sub"]),
          Spacer(1, 10), score]

    fs = data["findings"]
    top = [f for f in fs if f["severity"] in ("high", "medium")][:5]
    if top:
        el.append(Paragraph("Fix these first", S["h"]))
        el += [Paragraph(f"{i}. {escape(f['title'])}", S["b"]) for i, f in enumerate(top, 1)]
    el.append(Paragraph("Every finding", S["h"]))
    if not fs:
        el.append(Paragraph("No problems found by these checks.", S["b"]))
    for f in fs:
        word, col = SEV[f["severity"]]
        block = [Paragraph(f'<font color="{col.hexval()}"><b>{word}</b></font> &nbsp; {escape(f["title"])}', S["ft"]),
                 Paragraph(escape(f["why"]), S["b"]), Spacer(1, 3), Preformatted(f["fix"], S["code"], maxLineLength=110)]
        meta = " · ".join(x for x in (f.get("where") or "", f"seen: {f['evidence']}" if f.get("evidence") else "") if x)
        if meta:
            block.append(Paragraph(escape(meta), S["small"]))
        t = Table([[block]], colWidths=[W])
        t.setStyle(TableStyle([("LINEBEFORE", (0, 0), (0, -1), 3, col), ("LEFTPADDING", (0, 0), (-1, -1), 9),
                               ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                               ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE)]))
        el.append(KeepTogether([t]))
    el += [Spacer(1, 12), Paragraph("Passive checks only: the requests a normal visitor's browser makes, plus one plain-HTTP and one "
                                    "cross-origin request. A good score means these common mistakes are absent, not that the app is "
                                    "secure: it does not test logins, authorisation rules or database access rules.", S["small"])]

    def footer(canvas, d):
        canvas.saveState(); canvas.setFont("Helvetica", 7.5); canvas.setFillColor(MUT)
        canvas.drawString(18 * mm, 9 * mm, "launchcheck · github.com/NiharPatel2545/launchcheck")
        canvas.drawRightString(A4[0] - 18 * mm, 9 * mm, f"Page {d.page}"); canvas.restoreState()

    doc.build(el, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()
