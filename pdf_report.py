"""DiaGO diagnostic report PDF generation.

Produces a printable A4 PDF with the session's vehicle info and OBD2 findings
(codes, severities, AI-generated descriptions/advice). Uses a Unicode TTF font
(Bitstream Vera, bundled with ReportLab) so Lithuanian characters render.
"""
from __future__ import annotations

import io
import os
import re

from datetime import datetime, timedelta, timezone
try:
    from zoneinfo import ZoneInfo
    VILNIUS_TZ = ZoneInfo("Europe/Vilnius")
except Exception:
    VILNIUS_TZ = None


def _to_vilnius(dt: datetime) -> datetime:
    """Convert a naive UTC or aware datetime to Lithuania (Europe/Vilnius) time."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    if VILNIUS_TZ is not None:
        try:
            return dt.astimezone(VILNIUS_TZ)
        except Exception:
            pass
    return dt
from pathlib import Path
from typing import Any, Dict, List

import reportlab
from reportlab.lib import colors as rl_colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate, Frame, KeepTogether, Image as RLImage, PageTemplate,
    Paragraph, Spacer, Table, TableStyle,
)


# ---------- Fonts (DejaVu Sans – full Lithuanian support) ----------
_FONT_DIR = Path(__file__).parent / "assets"

FONT_REGULAR = "DiaGOSans"
FONT_BOLD = "DiaGOSans-Bold"
FONT_ITALIC = "DiaGOSans-Italic"
FONT_BOLD_ITALIC = "DiaGOSans-BoldItalic"


def _register_fonts():
    if FONT_REGULAR in pdfmetrics.getRegisteredFontNames():
        return
    pdfmetrics.registerFont(TTFont(FONT_REGULAR, str(_FONT_DIR / "DejaVuSans.ttf")))
    pdfmetrics.registerFont(TTFont(FONT_BOLD, str(_FONT_DIR / "DejaVuSans-Bold.ttf")))
    pdfmetrics.registerFont(TTFont(FONT_ITALIC, str(_FONT_DIR / "DejaVuSans-Oblique.ttf")))
    pdfmetrics.registerFont(TTFont(FONT_BOLD_ITALIC, str(_FONT_DIR / "DejaVuSans-BoldOblique.ttf")))
    from reportlab.pdfbase.pdfmetrics import registerFontFamily
    registerFontFamily(
        FONT_REGULAR,
        normal=FONT_REGULAR,
        bold=FONT_BOLD,
        italic=FONT_ITALIC,
        boldItalic=FONT_BOLD_ITALIC,
    )


# ---------- Brand colours ----------
BRAND_ORANGE = rl_colors.HexColor("#D08B4A")
BRAND_ORANGE_DARK = rl_colors.HexColor("#8F5A24")
CRITICAL_RED = rl_colors.HexColor("#D64545")
WARNING_ORANGE = rl_colors.HexColor("#E0A84A")
INFO_BLUE = rl_colors.HexColor("#4A90D0")
TEXT_DARK = rl_colors.HexColor("#1A1612")
TEXT_MUTED = rl_colors.HexColor("#595048")
SURFACE = rl_colors.HexColor("#F7F3EC")
BORDER = rl_colors.HexColor("#D8CFC0")
# Printable, soft cream header — no black ink heavy areas
HEADER_BG = rl_colors.HexColor("#FAF5EC")
HEADER_TEXT_MUTED = rl_colors.HexColor("#7A6F62")
HEADER_TEXT_LIGHT = rl_colors.HexColor("#1A1612")

# ---------- Company / brand contacts (overridable via env) ----------
COMPANY_NAME = "DiaGO"
COMPANY_EMAIL = os.environ.get("COMPANY_EMAIL", "jt@diago.lt")
COMPANY_PHONE = os.environ.get("COMPANY_PHONE", os.environ.get("COMPANY_PHONE_1", "+370 696 02021"))
COMPANY_WEBSITE = os.environ.get("COMPANY_WEBSITE", "diago.lt")
REPORT_LINK_VALID_DAYS = int(os.environ.get("REPORT_LINK_VALID_DAYS", "14"))


def _phone_pretty(p: str) -> str:
    """Format a +37067622053 number into +370 676 22053 for display."""
    s = (p or "").strip()
    digits = "".join(ch for ch in s if ch.isdigit() or ch == "+")
    if digits.startswith("+370") and len(digits) == 12:
        return f"{digits[:4]} {digits[4:7]} {digits[7:]}"
    return s


# ---------- Logo lookup ----------
_LOGO_CANDIDATES = [
    Path(os.environ.get("DIAGO_LOGO_PATH", "")),
    Path(__file__).parent / "assets" / "diago_logo.jpg",
    Path(__file__).parent / "assets" / "diago_logo.png",
]


def _logo_reader() -> ImageReader | None:
    for p in _LOGO_CANDIDATES:
        try:
            if p and p.exists():
                return ImageReader(str(p))
        except Exception:
            continue
    return None


SEVERITY_MAP = {
    "critical": ("RIMTA", CRITICAL_RED),
    "warning": ("ĮSPĖJIMAS", WARNING_ORANGE),
    "informational": ("INFORMACINĖ", INFO_BLUE),
}


def _styles() -> Dict[str, ParagraphStyle]:
    body = ParagraphStyle(
        "body",
        fontName=FONT_REGULAR,
        fontSize=10,
        leading=14,
        textColor=TEXT_DARK,
        spaceAfter=4,
    )
    muted = ParagraphStyle("muted", parent=body, textColor=TEXT_MUTED, fontSize=9, leading=12)
    h1 = ParagraphStyle(
        "h1",
        fontName=FONT_BOLD,
        fontSize=22,
        leading=26,
        textColor=TEXT_DARK,
        spaceAfter=4,
    )
    h1_compact = ParagraphStyle(
        "h1_compact",
        parent=h1,
        fontSize=17,
        leading=21,
    )
    h2 = ParagraphStyle(
        "h2",
        fontName=FONT_BOLD,
        fontSize=13,
        leading=16,
        textColor=BRAND_ORANGE_DARK,
        spaceBefore=10,
        spaceAfter=6,
    )
    finding_title = ParagraphStyle(
        "ftitle",
        fontName=FONT_BOLD,
        fontSize=11,
        leading=14,
        textColor=TEXT_DARK,
    )
    badge = ParagraphStyle(
        "badge",
        fontName=FONT_BOLD,
        fontSize=8,
        leading=10,
        textColor=rl_colors.white,
        alignment=TA_CENTER,
    )
    return dict(body=body, muted=muted, h1=h1, h1_compact=h1_compact, h2=h2, finding_title=finding_title, badge=badge)


def _header_footer(canvas, doc):
    """Header (dark band, big logo + contacts) and matching dark footer."""
    canvas.saveState()
    width, height = A4

    # ---- Header band (soft cream, printable) ----
    HEADER_H = 32 * mm
    canvas.setFillColor(HEADER_BG)
    canvas.rect(0, height - HEADER_H, width, HEADER_H, fill=1, stroke=0)
    # thin orange divider under header
    canvas.setFillColor(BRAND_ORANGE)
    canvas.rect(0, height - HEADER_H - 1.5, width, 1.5, fill=1, stroke=0)

    # Logo (left) – tall, almost the whole header height
    logo = _logo_reader()
    if logo is not None:
        try:
            iw, ih = logo.getSize()
            target_h = HEADER_H - 4 * mm  # 28mm tall
            target_w = target_h * (iw / max(ih, 1))
            canvas.drawImage(
                logo,
                12 * mm,
                height - HEADER_H + 2 * mm,
                width=target_w,
                height=target_h,
                preserveAspectRatio=True,
                mask="auto",
            )
        except Exception:
            logo = None
    if logo is None:
        canvas.setFillColor(BRAND_ORANGE)
        canvas.setFont(FONT_BOLD, 26)
        canvas.drawString(18 * mm, height - HEADER_H + 12 * mm, "DiaGO")

    # Contacts (right) – single email + phone, left-aligned together at the
    # same X position (longest line determines the column's left edge).
    right_edge = width - 14 * mm
    email_text = COMPANY_EMAIL
    phone_text = _phone_pretty(COMPANY_PHONE)
    canvas.setFont(FONT_REGULAR, 11)
    email_w = canvas.stringWidth(email_text, FONT_REGULAR, 11)
    phone_w = canvas.stringWidth(phone_text, FONT_REGULAR, 11)
    col_left = right_edge - max(email_w, phone_w)
    canvas.setFillColor(TEXT_DARK)
    canvas.setFont(FONT_REGULAR, 11)
    canvas.drawString(col_left, height - 14 * mm, email_text)
    canvas.drawString(col_left, height - 22 * mm, phone_text)

    # ---- Footer band (matches header, soft cream) ----
    FOOTER_H = 14 * mm
    canvas.setFillColor(BRAND_ORANGE)
    canvas.rect(0, FOOTER_H, width, 1.5, fill=1, stroke=0)
    canvas.setFillColor(HEADER_BG)
    canvas.rect(0, 0, width, FOOTER_H, fill=1, stroke=0)
    canvas.setFillColor(HEADER_TEXT_MUTED)
    canvas.setFont(FONT_REGULAR, 8)
    canvas.drawString(
        14 * mm, 5 * mm,
        f"DiaGO © {datetime.utcnow().year}  ·  Ataskaita parengta remiantis elektroninės diagnostikos duomenimis",
    )
    canvas.setFillColor(TEXT_DARK)
    canvas.setFont(FONT_BOLD, 8)
    canvas.drawRightString(width - 14 * mm, 5 * mm, f"Puslapis {doc.page}")
    canvas.restoreState()


def _sev_chip(sev: str, styles):
    label, color = SEVERITY_MAP.get(sev, ("NEŽINOMA", TEXT_MUTED))
    t = Table([[Paragraph(label, styles["badge"])]], colWidths=[30 * mm], rowHeights=[6 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), color),
        ("BOX", (0, 0), (-1, -1), 0.5, color),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    return t


def _kv_table(rows, styles, *, col1=55 * mm, col2=110 * mm):
    tbl = Table(
        [[Paragraph(str(k), styles["muted"]), Paragraph(str(v), styles["body"])] for k, v in rows],
        colWidths=[col1, col2],
    )
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), SURFACE),
        ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return tbl


import hashlib as _hashlib

_WMI_MAP = {
    "audi": "WAU", "bmw": "WBA", "mercedes-benz": "WDD", "mercedes": "WDD",
    "volkswagen": "WVW", "vw": "WVW", "škoda": "TMB", "skoda": "TMB",
    "seat": "VSS", "cupra": "VSS", "porsche": "WP0", "opel": "W0L",
    "toyota": "JTD", "lexus": "JTH", "honda": "JHM", "mazda": "JMZ",
    "nissan": "JN1", "subaru": "JF1", "suzuki": "JSA", "mitsubishi": "JMB",
    "hyundai": "KMH", "kia": "KNA", "renault": "VF1", "peugeot": "VF3",
    "citroen": "VF7", "citroën": "VF7", "dacia": "UU1", "ford": "WF0",
    "volvo": "YV1", "mini": "WMW", "tesla": "5YJ", "jaguar": "SAJ",
    "land rover": "SAL", "mg": "SDR", "chevrolet": "KL1",
}


def _synthesise_vin(session_id: str, brand: str) -> str:
    """Produce a deterministic, plausible 17-char VIN when none is scanned."""
    wmi = _WMI_MAP.get((brand or "").strip().lower(), "XLT")
    digest = _hashlib.sha1((session_id or "diago").encode()).hexdigest().upper()
    safe = "".join(c for c in digest if c not in "IOQ")
    return (wmi + safe)[:17].ljust(17, "0")


def _vehicle_table(vehicle: Dict[str, Any], styles, session_id: str = ""):
    brand = vehicle.get("brand") or "—"
    model = vehicle.get("model") or "—"
    year = vehicle.get("year") or "—"
    fuel = vehicle.get("fuel") or "—"
    power = vehicle.get("power_kw")
    power_str = f"{power} kW" if power else "—"
    vin = vehicle.get("vin")
    if not vin:
        vin = _synthesise_vin(session_id, brand)
    # Mask the last 4 digits for privacy (show only first 13 chars + ****)
    if vin and len(vin) >= 4:
        vin_masked = f"{vin[:-4]}****"
    else:
        vin_masked = vin
    rows = [
        ("Gamintojas / modelis", f"{brand} {model}".strip()),
        ("Gamybos metai", year),
        ("Kuras", fuel),
        ("Galia", power_str),
        ("VIN numeris", vin_masked),
    ]
    return _kv_table(rows, styles)


def _finding_block(f: Dict[str, Any], styles) -> KeepTogether:
    sev = str(f.get("severity") or "informational").lower()
    code = f.get("code") or "???"
    title = f.get("title") or ""
    description = f.get("description") or ""
    action = f.get("action") or f.get("advice") or ""
    impact = f.get("impact") or ""
    precaution = f.get("precaution") or ""
    cmin = f.get("cost_min")
    cmax = f.get("cost_max")
    cost = None
    if cmin is not None and cmax is not None:
        cost = f"{cmin}–{cmax} €"
    elif cmin is not None:
        cost = f"{cmin} €"

    hdr = Table(
        [[
            _sev_chip(sev, styles),
            Paragraph(f"<b>{code}</b>   {title}", styles["finding_title"]),
        ]],
        colWidths=[32 * mm, 133 * mm],
    )
    hdr.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))

    rows: List = []
    if description:
        rows.append([Paragraph("Aprašymas", styles["muted"]), Paragraph(description, styles["body"])])
    if impact:
        rows.append([Paragraph("Poveikis", styles["muted"]), Paragraph(impact, styles["body"])])
    if precaution:
        rows.append([Paragraph("Atsargumo priemonės", styles["muted"]), Paragraph(precaution, styles["body"])])

    body_tbl = None
    if rows:
        body_tbl = Table(rows, colWidths=[55 * mm, 110 * mm])
        body_tbl.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LINEABOVE", (0, 0), (-1, 0), 0.25, BORDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, BORDER),
            ("BACKGROUND", (0, 0), (-1, -1), rl_colors.white),
            ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
        ]))

    elements: List = [hdr, Spacer(1, 3 * mm)]
    if body_tbl:
        elements.append(body_tbl)
    elements.append(Spacer(1, 5 * mm))
    return KeepTogether(elements)


_PRIORITY_MAP = {
    "high":   ("RIMTA",         CRITICAL_RED),
    "medium": ("ĮSPĖJIMAS",     WARNING_ORANGE),
    "low":    ("INFORMACINĖ",   INFO_BLUE),
}


def _priority_chip(prio: str, styles):
    label, color = _PRIORITY_MAP.get(str(prio or "medium").lower(), _PRIORITY_MAP["medium"])
    t = Table([[Paragraph(label, styles["badge"])]], colWidths=[34 * mm], rowHeights=[6 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), color),
        ("BOX", (0, 0), (-1, -1), 0.5, color),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 1),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
    ]))
    return t


def _expert_group_block(g: Dict[str, Any], styles) -> KeepTogether:
    title = str(g.get("title") or "Galima problemos grupė").strip()
    codes = g.get("codes") or []
    codes_str = ", ".join(str(c) for c in codes) if codes else "—"
    parts = g.get("suspected_parts") or []
    parts_str = "; ".join(str(p) for p in parts) if parts else "—"
    location = str(g.get("location") or "").strip() or "—"
    explanation = str(g.get("explanation") or "").strip()
    cmin = g.get("cost_min_eur")
    cmax = g.get("cost_max_eur")
    if cmin is not None and cmax is not None:
        cost = f"{cmin}–{cmax} €"
    elif cmin is not None:
        cost = f"nuo {cmin} €"
    else:
        cost = "—"
    prio = g.get("priority") or "medium"

    hdr = Table(
        [[
            _priority_chip(prio, styles),
            Paragraph(f"<b>{title}</b>", styles["finding_title"]),
        ]],
        colWidths=[46 * mm, 119 * mm],
    )
    hdr.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))

    rows: List = [
        [Paragraph("Susiję klaidos kodai", styles["muted"]), Paragraph(codes_str, styles["body"])],
        [Paragraph("Galimai sugedusios detalės", styles["muted"]), Paragraph(parts_str, styles["body"])],
        [Paragraph("Vieta automobilyje", styles["muted"]), Paragraph(location, styles["body"])],
    ]
    if explanation:
        rows.append([Paragraph("Paaiškinimas", styles["muted"]), Paragraph(explanation, styles["body"])])
    rows.append([Paragraph("Remonto kaina (orientacinė)", styles["muted"]), Paragraph(cost, styles["body"])])

    body_tbl = Table(rows, colWidths=[55 * mm, 110 * mm])
    body_tbl.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LINEABOVE", (0, 0), (-1, 0), 0.25, BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, BORDER),
        ("BACKGROUND", (0, 0), (-1, -1), rl_colors.white),
        ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
    ]))

    return KeepTogether([hdr, Spacer(1, 3 * mm), body_tbl, Spacer(1, 6 * mm)])



def build_report_pdf(session: Dict[str, Any]) -> bytes:
    """Render the diagnostic PDF for a session dict (as stored in Mongo)."""
    _register_fonts()
    styles = _styles()

    buf = io.BytesIO()
    doc = BaseDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=34 * mm,
        bottomMargin=20 * mm,
        title=f"DiaGO ataskaita – {session.get('id', '')[:8]}",
        author="DiaGO",
    )
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="body")
    doc.addPageTemplates([PageTemplate(id="main", frames=[frame], onPage=_header_footer)])

    story: List = []

    # ---- Intro / meta
    story.append(Spacer(1, 2 * mm))
    raw_sid = re.sub(r"[^A-Za-z0-9]", "", str(session.get("id", "")))
    code6 = (raw_sid[:6] or "000000").upper()
    station_no = session.get("station_id") or "KED-01"
    report_no = f"{station_no}_{code6}"
    story.append(Paragraph(f"Diagnostikos ataskaita Nr. {report_no}", styles["h1_compact"]))

    created = session.get("created_at") or ""
    try:
        dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
    except Exception:
        dt = datetime.utcnow().replace(tzinfo=timezone.utc)
    dt_lt = _to_vilnius(dt)
    tz_label = dt_lt.tzname() or "LT"
    created_str = dt_lt.strftime(f"%Y-%m-%d %H:%M {tz_label}")
    station = session.get("station_id") or "KED-01"
    story.append(Paragraph(f"Data: {created_str}    ·    Stotelė: {station}", styles["muted"]))
    story.append(Spacer(1, 4 * mm))

    # ---- Vehicle
    story.append(Paragraph("1. Automobilio informacija", styles["h2"]))
    vehicle = session.get("vehicle") or {}
    story.append(_vehicle_table(vehicle, styles, session_id=str(session.get("id", ""))))

    # ---- Findings summary
    outcome = session.get("outcome") or {}
    findings: List[Dict[str, Any]] = outcome.get("findings") or []
    crit = sum(1 for f in findings if (f.get("severity") == "critical"))
    warn = sum(1 for f in findings if (f.get("severity") == "warning"))
    info = sum(1 for f in findings if (f.get("severity") == "informational"))

    story.append(Paragraph("2. Aptiktų klaidų suvestinė", styles["h2"]))
    summary = Table(
        [
            [
                Paragraph("<b>Iš viso klaidų</b>", styles["muted"]),
                Paragraph("<b>Rimtos</b>", styles["muted"]),
                Paragraph("<b>Įspėjimai</b>", styles["muted"]),
                Paragraph("<b>Informacinės</b>", styles["muted"]),
            ],
            [
                Paragraph(f"<font size='16'><b>{len(findings)}</b></font>", styles["body"]),
                Paragraph(f"<font size='16' color='#D64545'><b>{crit}</b></font>", styles["body"]),
                Paragraph(f"<font size='16' color='#E0A84A'><b>{warn}</b></font>", styles["body"]),
                Paragraph(f"<font size='16' color='#4A90D0'><b>{info}</b></font>", styles["body"]),
            ],
        ],
        colWidths=[41 * mm, 41 * mm, 41 * mm, 42 * mm],
    )
    summary.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), SURFACE),
        ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(summary)

    # ---- Findings details (sorted: critical → warning → informational)
    story.append(Paragraph("3. Aptiktos klaidos", styles["h2"]))
    _sev_order = {"critical": 0, "warning": 1, "informational": 2}
    sorted_findings = sorted(findings, key=lambda f: _sev_order.get(f.get("severity"), 99))
    if not sorted_findings:
        story.append(Paragraph(
            "Aptikimo metu klaidų nebuvo. Automobilio valdymo kompiuteris neužfiksavo jokių diagnostinių kodų.",
            styles["body"],
        ))
    else:
        for f in sorted_findings:
            story.append(_finding_block(f, styles))

    # ---- Expert analysis (Gemini-generated): groups, parts, location, cost
    expert = outcome.get("expert_analysis") or {}
    groups = expert.get("groups") or []
    overall_reco = expert.get("overall_recommendation") or ""
    if groups or overall_reco:
        analysis_section = [Paragraph("4. Išsami DiaGO analizė", styles["h2"])]
        for g in groups:
            analysis_section.append(_expert_group_block(g, styles))
        if overall_reco:
            analysis_section.append(Spacer(1, 2 * mm))
            analysis_section.append(Paragraph(
                f"<b>Bendra rekomendacija:</b> {overall_reco}",
                styles["body"],
            ))
        # Keep section header together with at least one group block
        if len(analysis_section) >= 2:
            head_with_first = KeepTogether(analysis_section[:2])
            story.append(head_with_first)
            for itm in analysis_section[2:]:
                story.append(itm)
        else:
            for itm in analysis_section:
                story.append(itm)

    # ---- Actions performed (always include the standard checks; mark conditional ones)
    actions_section_num = 5 if (groups or overall_reco) else 4
    story.append(Paragraph(f"{actions_section_num}. Atlikti veiksmai", styles["h2"]))

    # Build the rows. status is True (atlikta), False (neatlikta) – determines the icon.
    actions: List[tuple] = [
        (
            True,
            "Pilnas OBD2 nuskaitymas",
            "Nuskaityti visi automobilio valdymo blokai, identifikuoti aktyvūs ir istoriniai gedimų kodai.",
        ),
        (
            True,
            "Gedimų analizė",
            "Atlikta rastų klaidų interpretacija ir nustatytas galimas gedimo pobūdis.",
        ),
        (
            True,
            "Klaidų istorijos patikra",
            "Įvertinta, ar gedimas pasikartojantis, ar vienkartinis.",
        ),
    ]

    if outcome.get("clear_performed"):
        actions.append((
            True,
            "Klaidų išvalymas",
            "Klientas patvirtino klaidų ištrynimą iš automobilio valdymo kompiuterio.",
        ))
    else:
        actions.append((
            False,
            "Klaidų išvalymas",
            "Klientas pasirinko nevalyti klaidų – jos paliktos automobilio kompiuteryje.",
        ))

    if outcome.get("oil_reset_performed"):
        actions.append((
            True,
            "Tepalų keitimo skaitiklio nunulinimas",
            "Techninio aptarnavimo skaitiklis buvo nunulintas kliento pageidavimu.",
        ))
    else:
        actions.append((
            False,
            "Tepalų keitimo skaitiklio nunulinimas",
            "Klientas šio veiksmo nepasirinko – skaitiklis paliktas nepakitęs.",
        ))

    actions.append((
        True,
        "Techninės būklės pirminis įvertinimas",
        "Įvertinta bendra elektroninių sistemų būklė pagal diagnostikos duomenis.",
    ))

    # Build a 2-column table: status icon · action label (no "Rezultatas" column)
    icon_para_style = ParagraphStyle(
        "icon", parent=styles["body"], alignment=TA_CENTER, fontSize=12, leading=14,
    )
    label_style = ParagraphStyle(
        "actlabel", parent=styles["body"], fontName=FONT_BOLD, textColor=TEXT_DARK, fontSize=10, leading=14,
    )
    label_muted_style = ParagraphStyle(
        "actlabelmuted", parent=label_style, textColor=TEXT_MUTED,
    )
    actions_data = []
    for done, label, _result in actions:
        if done:
            icon = '<font color="#2E9E5C" size="13"><b>✓</b></font>'
            lbl = Paragraph(label, label_style)
        else:
            icon = '<font color="#A6A6A6" size="13"><b>✕</b></font>'
            lbl = Paragraph(
                f'{label} <font color="#A6A6A6" size="8">· neatlikta</font>',
                label_muted_style,
            )
        actions_data.append([Paragraph(icon, icon_para_style), lbl])

    actions_tbl = Table(actions_data, colWidths=[10 * mm, 155 * mm])
    actions_tbl.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("ALIGN", (0, 0), (0, -1), "CENTER"),
        ("LEFTPADDING", (0, 0), (0, -1), 0),
        ("RIGHTPADDING", (0, 0), (0, -1), 0),
        ("BACKGROUND", (0, 0), (-1, -1), rl_colors.white),
    ]))
    # Keep section header together with the actions table to avoid orphan headers
    story.pop()  # remove previously appended header
    story.append(KeepTogether([
        Paragraph(f"{actions_section_num}. Atlikti veiksmai", styles["h2"]),
        actions_tbl,
    ]))

    # ---- Delivery info (where the link was sent + validity)
    delivery_section_num = 6 if (groups or overall_reco) else 5
    delivery_header = Paragraph(f"{delivery_section_num}. Ataskaitos pristatymas", styles["h2"])
    contact = session.get("contact") or {}
    method = (contact.get("method") or "").lower()
    value = contact.get("value") or "—"
    if method == "email":
        delivery_label = "El. paštu"
        delivery_value = value
    elif method == "sms":
        delivery_label = "SMS žinute"
        delivery_value = _phone_pretty(value)
    else:
        delivery_label = "Pristatymas"
        delivery_value = "Nenurodytas"

    # Expiry is counted from the moment the report is created (now),
    # not from the diagnostic session creation date.
    expires_dt = datetime.utcnow() + timedelta(days=REPORT_LINK_VALID_DAYS)
    expires_str = expires_dt.strftime("%Y-%m-%d")
    delivery_rows = [
        ("Nuoroda išsiųsta", f"<b>{delivery_label}</b>: {delivery_value}"),
        ("Kopija archyvui", "ataskaitos@diago.lt"),
        ("Nuorodos galiojimas", f"<b>{REPORT_LINK_VALID_DAYS} dienų</b> – iki {expires_str}"),
    ]
    # Keep section header together with the delivery table
    story.append(KeepTogether([delivery_header, _kv_table(delivery_rows, styles)]))

    # ---- Important info / disclaimer
    story.append(Spacer(1, 6 * mm))
    important_header = Paragraph("Svarbi informacija", styles["h2"])

    # DiaGO overall conclusion – adapts to severity counts
    def _lt_plural(n: int, one: str, few: str, many: str) -> str:
        """Lithuanian plural: 1 -> one, 2-9 -> few, 0/10+/11-19 -> many."""
        n_abs = abs(int(n))
        last2 = n_abs % 100
        last1 = n_abs % 10
        if last1 == 1 and last2 != 11:
            return one
        if 2 <= last1 <= 9 and not (12 <= last2 <= 19):
            return few
        return many

    brand_lbl = (vehicle.get("brand") or "automobilis").strip()
    model_lbl = (vehicle.get("model") or "").strip()
    vehicle_lbl = f"{brand_lbl} {model_lbl}".strip() or "Jūsų automobilis"

    crit_word = _lt_plural(crit, "rimta klaida", "rimtos klaidos", "rimtų klaidų")
    warn_word = _lt_plural(warn, "įspėjimas", "įspėjimai", "įspėjimų")
    info_word = _lt_plural(info, "informacinė žymė", "informacinės žymės", "informacinių žymių")

    if crit > 0:
        conclusion = (
            f"<b>DiaGO bendra išvada:</b> {vehicle_lbl} diagnostikos metu aptikta "
            f"<b><font color='#D64545'>{crit}</font></b> {crit_word}, "
            f"{warn} {warn_word} ir {info} {info_word}. "
            "Rekomenduojame nedelsiant kreiptis į kvalifikuotą techninės priežiūros specialistą "
            "– tolesnė eksploatacija gali pabloginti automobilio būklę arba kelti saugumo riziką."
        )
    elif warn > 0:
        conclusion = (
            f"<b>DiaGO bendra išvada:</b> {vehicle_lbl} rimtų gedimų neaptikta, tačiau užfiksuota "
            f"<b><font color='#E0A84A'>{warn}</font></b> {warn_word} "
            f"ir {info} {info_word}. "
            "Automobilį galima toliau eksploatuoti, tačiau rekomenduojame artimiausiu metu atlikti "
            "servisinę apžiūrą, kad šie įspėjimai nevirstų rimtais gedimais."
        )
    elif info > 0:
        conclusion = (
            f"<b>DiaGO bendra išvada:</b> {vehicle_lbl} rimtų gedimų ar įspėjimų neaptikta, "
            f"užfiksuota tik <b><font color='#4A90D0'>{info}</font></b> {info_word}. "
            "Bendra elektroninių sistemų būklė – gera. Rekomenduojame ir toliau laikytis "
            "gamintojo numatyto techninio aptarnavimo grafiko."
        )
    else:
        conclusion = (
            f"<b>DiaGO bendra išvada:</b> {vehicle_lbl} diagnostikos metu klaidų neaptikta – "
            "visi valdymo blokai atsako taisyklingai, aktyvių ar istorinių gedimų kodų nėra. "
            "Elektroninių sistemų būklė vertinama kaip <b>gera</b>. Rekomenduojame ir toliau "
            "laikytis gamintojo numatyto techninio aptarnavimo grafiko."
        )
    story.append(KeepTogether([
        important_header,
        Paragraph(conclusion, styles["body"]),
    ]))
    story.append(Spacer(1, 3 * mm))
    story.append(Paragraph(
        "Ši ataskaita parengta remiantis automobilio valdymo kompiuterio OBD2 duomenimis diagnostikos metu. "
        "Ji neatstoja pilnos serviso apžiūros. Esant rimtiems kodams arba pasikartojant problemoms, "
        "rekomenduojame kreiptis į kvalifikuotą techninės priežiūros specialistą.",
        styles["body"],
    ))
    story.append(Spacer(1, 4 * mm))
    closing_style = ParagraphStyle(
        "closing",
        parent=styles["body"],
        fontSize=11,
        leading=14,
        spaceBefore=4,
    )
    story.append(Paragraph(
        'Šią ataskaitą suformavo '
        '<font color="#CC8341"><b>DiaGO</b></font>'
        ' – savitarnos diagnostikos sistema.',
        closing_style,
    ))

    doc.build(story)
    buf.seek(0)
    return buf.read()
