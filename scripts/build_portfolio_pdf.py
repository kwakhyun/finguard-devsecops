#!/usr/bin/env python3
# ruff: noqa: E501
"""Build the submission-ready FinGuard DevSecOps portfolio PDF."""

from __future__ import annotations

import argparse
import hashlib
import math
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path

from pypdf import PdfReader, PdfWriter
from pypdf.generic import (
    ArrayObject,
    BooleanObject,
    DecodedStreamObject,
    DictionaryObject,
    NameObject,
    NumberObject,
    TextStringObject,
)
from reportlab.lib import colors
from reportlab.lib.colors import Color, HexColor
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.pdfdoc import PDFString
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import Paragraph, Table, TableStyle

PAGE_W, PAGE_H = A4
MARGIN = 17 * mm

NAVY = HexColor("#0B1324")
NAVY_2 = HexColor("#121E33")
INK = HexColor("#172033")
SLATE = HexColor("#516079")
MUTED = HexColor("#59677E")
LINE = HexColor("#DCE3EC")
PAPER = HexColor("#F5F7FA")
WHITE = colors.white
TEAL = HexColor("#15B8A6")
TEAL_DARK = HexColor("#067067")
TEAL_SOFT = HexColor("#E7F8F5")
BLUE = HexColor("#245FC7")
BLUE_SOFT = HexColor("#EAF1FF")
AMBER = HexColor("#F0A62E")
AMBER_SOFT = HexColor("#FFF4DE")
RED = HexColor("#B9363E")
RED_SOFT = HexColor("#FDECEC")
GREEN = HexColor("#238B68")
GREEN_SOFT = HexColor("#E8F6F0")

REPO_URL = "https://github.com/kwakhyun/finguard-devsecops"
ACTIONS_URL = "https://github.com/kwakhyun/finguard-devsecops/actions/workflows/portfolio-ci.yml"
PROFILE_URL = "https://github.com/kwakhyun"
POLICY_SHA256 = "20f198a2be733c2d2bccb963952eade70d225391a6dbe79375a5fe3c81a1e7ab"
TEST_COUNT = 195
COVERAGE_PERCENT = "85.35%"
PDF_RELEASE_DATE = "D:20260902000000+09'00'"
MAX_VALIDATION_REPORT_BYTES = 50 * 1024 * 1024


def register_fonts() -> None:
    root = Path(__file__).resolve().parents[1]
    bundled_regular = root / "assets/fonts/NanumGothic-Regular.ttf"
    bundled_bold = root / "assets/fonts/NanumGothic-Bold.ttf"
    fallback_candidates = [
        Path("/System/Library/Fonts/Supplemental/AppleGothic.ttf"),
        Path("/System/Library/Fonts/Supplemental/Arial Unicode.ttf"),
    ]
    regular = (
        bundled_regular
        if bundled_regular.is_file()
        else next((path for path in fallback_candidates if path.is_file()), None)
    )
    if regular is None:
        raise SystemExit("A Korean TrueType font is required to build the portfolio PDF")
    bold = bundled_bold if bundled_bold.is_file() else regular
    pdfmetrics.registerFont(TTFont("Portfolio", str(regular)))
    pdfmetrics.registerFont(TTFont("PortfolioBold", str(bold)))
    pdfmetrics.registerFontFamily(
        "Portfolio",
        normal="Portfolio",
        bold="PortfolioBold",
        italic="Portfolio",
        boldItalic="PortfolioBold",
    )


def style(
    name: str,
    size: float,
    leading: float,
    color: Color = INK,
    *,
    alignment: int = TA_LEFT,
    space_after: float = 0,
    font_name: str = "Portfolio",
) -> ParagraphStyle:
    return ParagraphStyle(
        name,
        fontName=font_name,
        fontSize=size,
        leading=leading,
        textColor=color,
        alignment=alignment,
        wordWrap="CJK",
        splitLongWords=True,
        allowWidows=False,
        allowOrphans=False,
        spaceAfter=space_after,
    )


STYLES: dict[str, ParagraphStyle] = {}


def initialize_styles() -> None:
    STYLES.update(
        {
            "cover_label": style("cover_label", 8.7, 11.2, TEAL, font_name="PortfolioBold"),
            "cover_title": style("cover_title", 29, 35, WHITE, font_name="PortfolioBold"),
            "cover_subtitle": style(
                "cover_subtitle", 13, 20, HexColor("#D7E0EF"), font_name="PortfolioBold"
            ),
            "cover_note": style("cover_note", 8.1, 12.5, HexColor("#AEBBD0")),
            "section_no": style("section_no", 8.2, 10.5, TEAL_DARK, font_name="PortfolioBold"),
            "page_title": style("page_title", 21, 27, INK, font_name="PortfolioBold"),
            "page_kicker": style("page_kicker", 9.2, 14, SLATE),
            "card_title": style("card_title", 11.3, 15, INK, font_name="PortfolioBold"),
            "fit_title": style("fit_title", 9.8, 13, INK, font_name="PortfolioBold"),
            "body": style("body", 8.7, 13.2, SLATE),
            "body_dark": style("body_dark", 8.7, 13.2, INK),
            "body_small": style("body_small", 8.35, 12.2, SLATE),
            "body_tiny": style("body_tiny", 8.0, 11.4, MUTED),
            "label": style("label", 8.0, 10.5, MUTED),
            "metric": style("metric", 18, 21, INK, font_name="PortfolioBold"),
            "metric_light": style("metric_light", 18, 21, WHITE, font_name="PortfolioBold"),
            "metric_label": style("metric_label", 8.0, 10.5, SLATE),
            "metric_label_light": style("metric_label_light", 8.0, 10.5, HexColor("#BFCBDD")),
            "diagram": style("diagram", 8.0, 10.3, INK, alignment=TA_CENTER),
            "diagram_light": style("diagram_light", 8.0, 10.3, WHITE, alignment=TA_CENTER),
            "mono": style("mono", 8.0, 12.2, HexColor("#DCE8F7")),
            "footer": style("footer", 8.0, 10.2, MUTED),
            "link": style("link", 8.5, 12.5, BLUE),
            "quote": style("quote", 12.2, 18, INK, font_name="PortfolioBold"),
            "table_head": style(
                "table_head", 8.0, 10.7, WHITE, alignment=TA_CENTER, font_name="PortfolioBold"
            ),
            "table_cell": style("table_cell", 8.15, 11.2, INK, font_name="PortfolioBold"),
            "table_cell_small": style("table_cell_small", 8.0, 11.2, SLATE),
        }
    )


def verify_source_facts(root: Path) -> dict[str, str]:
    readme = (root / "README.md").read_text(encoding="utf-8")
    if f"현재 회귀 테스트는 {TEST_COUNT}개" not in readme:
        raise SystemExit("README test count changed; review portfolio metrics before rebuilding")
    policy_path = root / "policies/financial-baseline.toml"
    policy = tomllib.loads(policy_path.read_text(encoding="utf-8"))
    digest = hashlib.sha256(policy_path.read_bytes()).hexdigest()
    if digest != POLICY_SHA256:
        raise SystemExit("Baseline policy digest changed; review the deployment example first")
    if policy["metadata"]["version"] != "5.1.1":
        raise SystemExit("Baseline policy version changed; review portfolio metrics first")
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    return {
        "project_version": str(project["project"]["version"]),
        "policy_version": str(policy["metadata"]["version"]),
        "policy_id": str(policy["metadata"]["id"]),
        "test_count": str(TEST_COUNT),
        "coverage_percent": COVERAGE_PERCENT,
    }


def _validation_xml_root(path: Path) -> ET.Element:
    """Parse bounded CI-generated XML without allowing DTD or entity declarations."""

    try:
        if path.stat().st_size > MAX_VALIDATION_REPORT_BYTES:
            raise SystemExit(f"Validation report exceeds 50 MiB limit: {path}")
        payload = path.read_bytes()
    except OSError as exc:
        raise SystemExit(f"Cannot read validation report {path}: {exc}") from exc
    upper_payload = payload.upper()
    if b"<!DOCTYPE" in upper_payload or b"<!ENTITY" in upper_payload:
        raise SystemExit(f"XML DTD and entity declarations are not allowed: {path}")
    try:
        return ET.fromstring(payload)  # noqa: S314 - declarations are rejected above
    except ET.ParseError as exc:
        raise SystemExit(f"Cannot parse validation report {path}: {exc}") from exc


def verify_validation_reports(junit_xml: Path | None, coverage_xml: Path | None) -> None:
    """Verify that the portfolio metrics match fresh CI reports when supplied."""

    if (junit_xml is None) != (coverage_xml is None):
        raise SystemExit("Both --junit-xml and --coverage-xml are required together")
    if junit_xml is None or coverage_xml is None:
        return

    junit_root = _validation_xml_root(junit_xml)
    if junit_root.tag == "testsuites":
        test_count = sum(
            int(suite.attrib.get("tests", "0")) for suite in junit_root.findall("testsuite")
        )
    elif junit_root.tag == "testsuite":
        test_count = int(junit_root.attrib.get("tests", "0"))
    else:
        raise SystemExit(f"Unsupported JUnit root element: {junit_root.tag}")
    if test_count != TEST_COUNT:
        raise SystemExit(
            f"JUnit test count is {test_count}; expected portfolio metric {TEST_COUNT}"
        )

    coverage_root = _validation_xml_root(coverage_xml)
    try:
        line_rate = float(coverage_root.attrib["line-rate"])
        lines_valid = int(coverage_root.attrib["lines-valid"])
        lines_covered = int(coverage_root.attrib["lines-covered"])
    except (KeyError, ValueError) as exc:
        raise SystemExit("Coverage XML does not contain valid line metrics") from exc
    if (
        not math.isfinite(line_rate)
        or not 0 <= line_rate <= 1
        or lines_valid <= 0
        or not 0 <= lines_covered <= lines_valid
    ):
        raise SystemExit("Coverage XML line metrics are outside the allowed range")
    raw_rate = lines_covered / lines_valid
    if abs(raw_rate - line_rate) > 0.00005:
        raise SystemExit("Coverage XML line-rate is inconsistent with its raw counts")
    coverage_value = raw_rate * 100
    actual_coverage = f"{coverage_value:.2f}%"
    if actual_coverage != COVERAGE_PERCENT:
        raise SystemExit(
            f"Coverage is {actual_coverage}; expected portfolio metric {COVERAGE_PERCENT}"
        )


def para(
    canvas: Canvas,
    text: str,
    x: float,
    top: float,
    width: float,
    style_name: str,
    *,
    max_height: float = 600,
) -> float:
    paragraph = Paragraph(text, STYLES[style_name])
    _, height = paragraph.wrap(width, max_height)
    paragraph.drawOn(canvas, x, top - height)
    return height


def rounded_card(
    canvas: Canvas,
    x: float,
    top: float,
    width: float,
    height: float,
    *,
    fill: Color = WHITE,
    stroke: Color = LINE,
    radius: float = 4 * mm,
    line_width: float = 0.7,
) -> None:
    canvas.saveState()
    canvas.setFillColor(fill)
    canvas.setStrokeColor(stroke)
    canvas.setLineWidth(line_width)
    canvas.roundRect(x, top - height, width, height, radius, fill=1, stroke=1)
    canvas.restoreState()


def pill(
    canvas: Canvas,
    text: str,
    x: float,
    y: float,
    width: float,
    *,
    fill: Color,
    text_color: Color,
) -> None:
    canvas.saveState()
    canvas.setFillColor(fill)
    canvas.roundRect(x, y, width, 6.8 * mm, 3.4 * mm, fill=1, stroke=0)
    canvas.restoreState()
    custom = style(f"pill-{text}", 8.0, 10.0, text_color, alignment=TA_CENTER)
    paragraph = Paragraph(text, custom)
    _, height = paragraph.wrap(width - 3 * mm, 6 * mm)
    paragraph.drawOn(canvas, x + 1.5 * mm, y + (6.8 * mm - height) / 2)


def dot(canvas: Canvas, x: float, y: float, color: Color = TEAL, radius: float = 1.35) -> None:
    canvas.saveState()
    canvas.setFillColor(color)
    canvas.circle(x, y, radius, fill=1, stroke=0)
    canvas.restoreState()


def bullet_list(
    canvas: Canvas,
    items: list[str],
    x: float,
    top: float,
    width: float,
    *,
    style_name: str = "body",
    gap: float = 4.5,
    bullet_color: Color = TEAL,
) -> float:
    cursor = top
    for item in items:
        dot(canvas, x + 2.2, cursor - 5.4, bullet_color)
        height = para(canvas, item, x + 10, cursor, width - 10, style_name)
        cursor -= height + gap
    return top - cursor


def arrow(
    canvas: Canvas,
    x1: float,
    y1: float,
    x2: float,
    y2: float,
    *,
    color: Color = MUTED,
    width: float = 1.1,
) -> None:
    canvas.saveState()
    canvas.setStrokeColor(color)
    canvas.setFillColor(color)
    canvas.setLineWidth(width)
    canvas.line(x1, y1, x2, y2)
    import math

    angle = math.atan2(y2 - y1, x2 - x1)
    length = 5
    spread = 0.52
    points = [
        (x2, y2),
        (
            x2 - length * math.cos(angle - spread),
            y2 - length * math.sin(angle - spread),
        ),
        (
            x2 - length * math.cos(angle + spread),
            y2 - length * math.sin(angle + spread),
        ),
    ]
    path = canvas.beginPath()
    path.moveTo(*points[0])
    path.lineTo(*points[1])
    path.lineTo(*points[2])
    path.close()
    canvas.drawPath(path, fill=1, stroke=0)
    canvas.restoreState()


def flow_box(
    canvas: Canvas,
    text: str,
    x: float,
    y: float,
    width: float,
    height: float,
    *,
    fill: Color = WHITE,
    stroke: Color = LINE,
    text_style: str = "diagram",
) -> None:
    canvas.saveState()
    canvas.setFillColor(fill)
    canvas.setStrokeColor(stroke)
    canvas.setLineWidth(0.8)
    canvas.roundRect(x, y, width, height, 3 * mm, fill=1, stroke=1)
    canvas.restoreState()
    paragraph = Paragraph(text, STYLES[text_style])
    _, para_height = paragraph.wrap(width - 5 * mm, height - 3 * mm)
    paragraph.drawOn(canvas, x + 2.5 * mm, y + (height - para_height) / 2)


def section_header(
    canvas: Canvas,
    number: str,
    title: str,
    kicker: str,
) -> float:
    para(canvas, f"{number} / 06", MARGIN, PAGE_H - 16 * mm, 80 * mm, "section_no")
    para(canvas, title, MARGIN, PAGE_H - 24 * mm, PAGE_W - 2 * MARGIN, "page_title")
    para(canvas, kicker, MARGIN, PAGE_H - 36 * mm, PAGE_W - 2 * MARGIN, "page_kicker")
    canvas.saveState()
    canvas.setStrokeColor(LINE)
    canvas.setLineWidth(0.7)
    canvas.line(MARGIN, PAGE_H - 47 * mm, PAGE_W - MARGIN, PAGE_H - 47 * mm)
    canvas.restoreState()
    return PAGE_H - 53 * mm


def footer(canvas: Canvas, page_number: int) -> None:
    y = 10 * mm
    canvas.saveState()
    canvas.setStrokeColor(LINE)
    canvas.setLineWidth(0.55)
    canvas.line(MARGIN, y + 5 * mm, PAGE_W - MARGIN, y + 5 * mm)
    canvas.restoreState()
    para(canvas, "FinGuard DevSecOps 포트폴리오", MARGIN, y + 2.2 * mm, 70 * mm, "footer")
    page_style = style("footer_page", 8.0, 10.2, MUTED, alignment=TA_RIGHT)
    paragraph = Paragraph(f"{page_number} / 7", page_style)
    _, height = paragraph.wrap(25 * mm, 10 * mm)
    paragraph.drawOn(canvas, PAGE_W - MARGIN - 25 * mm, y + 2.2 * mm - height)


def metric_card(
    canvas: Canvas,
    x: float,
    top: float,
    width: float,
    value: str,
    label: str,
    *,
    dark: bool = False,
) -> None:
    height = 26 * mm
    fill = NAVY_2 if dark else WHITE
    stroke = HexColor("#263650") if dark else LINE
    rounded_card(canvas, x, top, width, height, fill=fill, stroke=stroke)
    para(
        canvas,
        value,
        x + 4 * mm,
        top - 4.5 * mm,
        width - 8 * mm,
        "metric_light" if dark else "metric",
    )
    para(
        canvas,
        label,
        x + 4 * mm,
        top - 14.8 * mm,
        width - 8 * mm,
        "metric_label_light" if dark else "metric_label",
    )


def page_cover(canvas: Canvas, facts: dict[str, str]) -> None:
    canvas.setFillColor(NAVY)
    canvas.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)

    canvas.saveState()
    canvas.setFillColor(TEAL)
    canvas.circle(PAGE_W - 25 * mm, PAGE_H - 24 * mm, 27 * mm, fill=1, stroke=0)
    canvas.setFillColor(NAVY_2)
    canvas.circle(PAGE_W - 22 * mm, PAGE_H - 20 * mm, 22 * mm, fill=1, stroke=0)
    canvas.restoreState()

    para(canvas, "PYTHON DEVSECOPS PORTFOLIO", MARGIN, PAGE_H - 24 * mm, 100 * mm, "cover_label")
    para(canvas, "FinGuard", MARGIN, PAGE_H - 46 * mm, 150 * mm, "cover_title")
    para(
        canvas,
        "온프레미스 DevSecOps<br/>릴리스 게이트",
        MARGIN,
        PAGE_H - 67 * mm,
        150 * mm,
        "cover_title",
    )
    para(
        canvas,
        "검사한 커밋, 승인한 이미지, 실제 배포 대상을 다시 대조하고<br/>잘못된 릴리스를 차단하는 Python 기반 정책 게이트",
        MARGIN,
        PAGE_H - 111 * mm,
        158 * mm,
        "cover_subtitle",
    )

    metric_width = (PAGE_W - 2 * MARGIN - 3 * 5 * mm) / 4
    metric_top = PAGE_H - 150 * mm
    metrics = [
        (facts["test_count"], "회귀 테스트"),
        (facts["coverage_percent"], "테스트 커버리지"),
        (facts["policy_version"], "기준 정책 버전"),
        ("100%", "개인 기여도"),
    ]
    for index, (value, label) in enumerate(metrics):
        metric_card(
            canvas,
            MARGIN + index * (metric_width + 5 * mm),
            metric_top,
            metric_width,
            value,
            label,
            dark=True,
        )

    y = PAGE_H - 193 * mm
    tags = [
        ("Python", 22 * mm),
        ("Bash", 19 * mm),
        ("GitLab CI", 27 * mm),
        ("Jenkins", 23 * mm),
        ("Semgrep", 24 * mm),
        ("Trivy", 19 * mm),
        ("OWASP ZAP", 30 * mm),
    ]
    x = MARGIN
    for text, width in tags:
        pill(canvas, text, x, y, width, fill=HexColor("#1C2B43"), text_color=HexColor("#DCE7F7"))
        x += width + 3 * mm
        if x > PAGE_W - MARGIN - 25 * mm:
            x = MARGIN
            y -= 10 * mm
    for text, width in [
        ("Kubernetes", 29 * mm),
        ("Cosign", 22 * mm),
        ("SARIF", 20 * mm),
        ("CycloneDX", 28 * mm),
    ]:
        pill(canvas, text, x, y, width, fill=HexColor("#1C2B43"), text_color=HexColor("#DCE7F7"))
        x += width + 3 * mm

    rounded_card(
        canvas,
        MARGIN,
        PAGE_H - 222 * mm,
        PAGE_W - 2 * MARGIN,
        42 * mm,
        fill=NAVY_2,
        stroke=HexColor("#263650"),
    )
    para(canvas, "작성자", MARGIN + 5 * mm, PAGE_H - 228 * mm, 25 * mm, "metric_label_light")
    para(canvas, "@kwakhyun", MARGIN + 5 * mm, PAGE_H - 237 * mm, 45 * mm, "cover_subtitle")
    para(
        canvas,
        f"개인 프로젝트 v{facts['project_version']}  |  기획, 아키텍처, 구현, 정책, CI/CD, 테스트, 문서화",
        MARGIN + 53 * mm,
        PAGE_H - 229 * mm,
        PAGE_W - 2 * MARGIN - 58 * mm,
        "cover_note",
    )
    para(
        canvas,
        "예제 스캔 보고서와 샘플 서비스로 구성한 독립 포트폴리오입니다. 실제 운영 적용이나 규제 준수 인증을 주장하지 않습니다.",
        MARGIN + 53 * mm,
        PAGE_H - 243 * mm,
        PAGE_W - 2 * MARGIN - 58 * mm,
        "cover_note",
    )
    para(
        canvas,
        f'<link href="{REPO_URL}" color="#56D9CA"><u>github.com/kwakhyun/finguard-devsecops</u></link>',
        MARGIN + 53 * mm,
        PAGE_H - 256 * mm,
        PAGE_W - 2 * MARGIN - 58 * mm,
        "cover_note",
    )


def page_problem(canvas: Canvas) -> None:
    top = section_header(
        canvas,
        "01",
        "문제 정의와 핵심 설계",
        "보안 도구를 연결하는 것보다 중요한 것은 검사, 승인, 배포가 같은 대상을 가리키도록 만드는 일입니다.",
    )

    card_gap = 5 * mm
    card_width = (PAGE_W - 2 * MARGIN - 2 * card_gap) / 3
    problems = [
        (
            "01  제각각인 보고서",
            "도구마다 결과 형식과 심각도가 달라<br/>같은 배포 기준을 적용하기 어렵습니다.",
        ),
        (
            "02  검사 대상 불일치",
            "검사한 커밋, 승인한 이미지, 배포한<br/>이미지가 다르면 개별 검사가 통과해도<br/>안전한 릴리스가 아닙니다.",
        ),
        (
            "03  승인 자료 불일치",
            "변경 승인, 직무 분리, 배포 허용 시간,<br/>롤백 계획이 대상과 연결되지 않으면<br/>감사 기록을 신뢰하기 어렵습니다.",
        ),
    ]
    for index, (title, body) in enumerate(problems):
        x = MARGIN + index * (card_width + card_gap)
        rounded_card(canvas, x, top, card_width, 36 * mm, fill=PAPER)
        para(canvas, title, x + 4 * mm, top - 5 * mm, card_width - 8 * mm, "card_title")
        para(canvas, body, x + 3.2 * mm, top - 15 * mm, card_width - 6.4 * mm, "body_small")

    quote_top = top - 44 * mm
    rounded_card(
        canvas,
        MARGIN,
        quote_top,
        PAGE_W - 2 * MARGIN,
        28 * mm,
        fill=TEAL_SOFT,
        stroke=HexColor("#BEEBE5"),
    )
    para(
        canvas,
        "“검증한 모든 입력이 같은 릴리스 대상을 가리킬 때만 PASS를 생성한다.”",
        MARGIN + 8 * mm,
        quote_top - 7 * mm,
        PAGE_W - 2 * MARGIN - 16 * mm,
        "quote",
    )

    subject_top = quote_top - 36 * mm
    para(
        canvas,
        "ReleaseSubject: 배포 대상을 하나로 묶는 불변 식별자",
        MARGIN,
        subject_top,
        PAGE_W - 2 * MARGIN,
        "card_title",
    )
    center_x = PAGE_W / 2
    center_y = subject_top - 48 * mm
    flow_box(
        canvas,
        "<b>ReleaseSubject</b><br/>정규형 SHA-256",
        center_x - 25 * mm,
        center_y - 11 * mm,
        50 * mm,
        22 * mm,
        fill=NAVY,
        stroke=NAVY,
        text_style="diagram_light",
    )
    nodes = [
        ("Git 커밋", MARGIN, center_y + 25 * mm),
        ("이미지<br/>다이제스트", MARGIN, center_y - 6 * mm),
        ("SBOM SHA-256", MARGIN, center_y - 37 * mm),
        ("클러스터<br/>네임스페이스", PAGE_W - MARGIN - 38 * mm, center_y + 25 * mm),
        ("워크로드<br/>컨테이너", PAGE_W - MARGIN - 38 * mm, center_y - 6 * mm),
        ("상태 확인 URL", PAGE_W - MARGIN - 38 * mm, center_y - 37 * mm),
    ]
    for label, x, y in nodes:
        flow_box(canvas, label, x, y, 38 * mm, 17 * mm, fill=WHITE)
        if x < center_x:
            arrow(canvas, x + 38 * mm, y + 8.5 * mm, center_x - 27 * mm, center_y)
        else:
            arrow(canvas, x, y + 8.5 * mm, center_x + 27 * mm, center_y)

    principle_top = subject_top - 101 * mm
    rounded_card(canvas, MARGIN, principle_top, PAGE_W - 2 * MARGIN, 32 * mm, fill=PAPER)
    para(
        canvas, "세 가지 설계 원칙", MARGIN + 5 * mm, principle_top - 5 * mm, 35 * mm, "card_title"
    )
    principles = [
        "<b>정규화:</b> 보고서 형식을 공통 모델로 변환",
        "<b>대상 대조:</b> 검사, 승인, 배포의 대상이 같은지 해시로 확인",
        "<b>오류 시 차단:</b> 누락, 파싱 오류, 서명 실패를 취약점 0건과 구분",
    ]
    bullet_list(
        canvas,
        principles,
        MARGIN + 47 * mm,
        principle_top - 5 * mm,
        PAGE_W - 2 * MARGIN - 52 * mm,
        style_name="body_small",
    )


def page_flow(canvas: Canvas) -> None:
    top = section_header(
        canvas,
        "02",
        "신뢰 경계를 분리한 릴리스 흐름",
        "변경 검증과 보호 릴리스를 나누고, 각 구간에는 필요한 권한만 부여했습니다.",
    )
    zone_height = 39 * mm
    zone_gap = 5 * mm
    zones = [
        ("구간 1  변경 검증", "운영 비밀정보 미사용", BLUE_SOFT, BLUE),
        ("구간 2  보호 릴리스", "서명 키와 승인 정보에 접근", TEAL_SOFT, TEAL_DARK),
        ("구간 3  배포 및 복구", "공개키로 판정 증적 검증", AMBER_SOFT, HexColor("#9A6514")),
    ]
    zone_width = (PAGE_W - 2 * MARGIN - 2 * zone_gap) / 3
    for index, (title, subtitle, fill, accent) in enumerate(zones):
        x = MARGIN + index * (zone_width + zone_gap)
        rounded_card(canvas, x, top, zone_width, zone_height, fill=fill, stroke=fill)
        canvas.saveState()
        canvas.setFillColor(accent)
        canvas.roundRect(x, top - 7 * mm, zone_width, 7 * mm, 3 * mm, fill=1, stroke=0)
        canvas.rect(x, top - 7 * mm, zone_width, 3 * mm, fill=1, stroke=0)
        canvas.restoreState()
        head_style = style(
            f"zone{index}", 8.1, 10.2, WHITE, alignment=TA_CENTER, font_name="PortfolioBold"
        )
        p = Paragraph(title, head_style)
        _, h = p.wrap(zone_width - 4 * mm, 8 * mm)
        p.drawOn(canvas, x + 2 * mm, top - 5.3 * mm - h / 2)
        para(canvas, subtitle, x + 4 * mm, top - 12 * mm, zone_width - 8 * mm, "label")

    y1 = top - 32 * mm
    box_w = 20 * mm
    box_h = 16 * mm
    # Zone 1
    x1 = MARGIN + 4.5 * mm
    flow_box(canvas, "PR / MR", x1, y1, box_w, box_h, fill=WHITE)
    flow_box(canvas, "Lint, Test<br/>SAST", x1 + 23 * mm, y1, box_w, box_h, fill=WHITE)
    arrow(canvas, x1 + box_w, y1 + box_h / 2, x1 + 22 * mm, y1 + box_h / 2, color=BLUE)
    # Zone 2
    x2 = MARGIN + zone_width + zone_gap + 4.5 * mm
    flow_box(canvas, "보호된<br/>main", x2, y1, box_w, box_h, fill=WHITE)
    flow_box(canvas, "불변 이미지<br/>다이제스트", x2 + 23 * mm, y1, box_w, box_h, fill=WHITE)
    arrow(canvas, x2 + box_w, y1 + box_h / 2, x2 + 22 * mm, y1 + box_h / 2, color=TEAL_DARK)
    # Zone 3
    x3 = MARGIN + 2 * (zone_width + zone_gap) + 4.5 * mm
    flow_box(canvas, "서명된<br/>PASS 증적", x3, y1, box_w, box_h, fill=WHITE)
    flow_box(canvas, "Kubernetes<br/>롤아웃", x3 + 23 * mm, y1, box_w, box_h, fill=WHITE)
    arrow(canvas, x3 + box_w, y1 + box_h / 2, x3 + 22 * mm, y1 + box_h / 2, color=AMBER)

    between_y = top - 50 * mm
    para(canvas, "보호 릴리스 실행 순서", MARGIN, between_y, PAGE_W - 2 * MARGIN, "card_title")
    steps = [
        ("1", "이미지<br/>한 번만 빌드", BLUE_SOFT, BLUE),
        ("2", "동일 이미지로<br/>SCA, SBOM, DAST", BLUE_SOFT, BLUE),
        ("3", "스캔 실행 기록에<br/>서명", TEAL_SOFT, TEAL_DARK),
        ("4", "ITSM 보안 검토<br/>및 릴리스 승인", TEAL_SOFT, TEAL_DARK),
        ("5", "정책 게이트<br/>PASS / FAIL", AMBER_SOFT, HexColor("#9A6514")),
        ("6", "배포, 상태 확인<br/>실패 시 롤백", AMBER_SOFT, HexColor("#9A6514")),
    ]
    step_gap = 5 * mm
    step_w = (PAGE_W - 2 * MARGIN - 2 * step_gap) / 3
    step_h = 20 * mm
    row_y = [between_y - 29 * mm, between_y - 54 * mm]
    for index, (number, label, fill, accent) in enumerate(steps):
        row, column = divmod(index, 3)
        x = MARGIN + column * (step_w + step_gap)
        step_y = row_y[row]
        flow_box(canvas, label, x, step_y, step_w, step_h, fill=fill, stroke=fill)
        canvas.saveState()
        canvas.setFillColor(accent)
        canvas.circle(x + 5 * mm, step_y + 15 * mm, 3.2 * mm, fill=1, stroke=0)
        canvas.restoreState()
        number_style = style(
            f"step-number-{index}",
            8.0,
            9.5,
            WHITE,
            alignment=TA_CENTER,
            font_name="PortfolioBold",
        )
        p = Paragraph(number, number_style)
        _, h = p.wrap(6.4 * mm, 6 * mm)
        p.drawOn(canvas, x + 1.8 * mm, step_y + 15 * mm - h / 2)
        if column < 2:
            arrow(
                canvas,
                x + step_w,
                step_y + step_h / 2,
                x + step_w + step_gap - 1,
                step_y + step_h / 2,
                color=MUTED,
                width=0.8,
            )

    decisions_top = row_y[1] - 10 * mm
    decision_gap = 5 * mm
    decision_w = (PAGE_W - 2 * MARGIN - 2 * decision_gap) / 3
    decisions = [
        (
            "변경 검증 권한 분리",
            "변경 코드가 승인 정보, 서명 키,<br/>Kubernetes 자격 증명에 접근하지<br/>못하게 합니다.",
        ),
        (
            "CI와 정책 로직 분리",
            "GitLab CI와 Jenkins가 같은 Python<br/>CLI를 사용하므로 게이트 규칙이 특정<br/>CI 제품에 종속되지 않습니다.",
        ),
        (
            "단일 빌드 이미지 재사용",
            "레지스트리에서 받은 불변 이미지를<br/>검사, 승인, 배포에 그대로 사용합니다.",
        ),
    ]
    for index, (title, body) in enumerate(decisions):
        x = MARGIN + index * (decision_w + decision_gap)
        rounded_card(canvas, x, decisions_top, decision_w, 40 * mm, fill=WHITE)
        para(canvas, title, x + 4 * mm, decisions_top - 5 * mm, decision_w - 8 * mm, "card_title")
        para(canvas, body, x + 4 * mm, decisions_top - 19 * mm, decision_w - 8 * mm, "body_small")

    evidence_top = decisions_top - 48 * mm
    rounded_card(canvas, MARGIN, evidence_top, PAGE_W - 2 * MARGIN, 25 * mm, fill=NAVY, stroke=NAVY)
    para(canvas, "구현 근거", MARGIN + 5 * mm, evidence_top - 5 * mm, 25 * mm, "cover_subtitle")
    para(
        canvas,
        ".gitlab-ci.yml  |  Jenkinsfile  |  finguard/cli.py  |  tests/test_pipeline_contracts.py",
        MARGIN + 35 * mm,
        evidence_top - 7 * mm,
        PAGE_W - 2 * MARGIN - 40 * mm,
        "mono",
    )
    para(
        canvas,
        "ITSM, KMS, 보호 러너 연계는 코드와 파이프라인 계약으로 검증한 설계이며, 실제 운영 실적은 아닙니다.",
        MARGIN + 35 * mm,
        evidence_top - 15 * mm,
        PAGE_W - 2 * MARGIN - 40 * mm,
        "cover_note",
    )


def page_policy(canvas: Canvas) -> None:
    top = section_header(
        canvas,
        "03",
        "정책 기반 품질과 보안 관리",
        "스캐너별 다른 결과를 공통 모델로 정규화하고, 정책이 정한 필수 입력과 차단 조건을 하나의 게이트에서 평가합니다.",
    )

    data = [
        [
            Paragraph("영역", STYLES["table_head"]),
            Paragraph("구현 메커니즘", STYLES["table_head"]),
            Paragraph("차단 조건 예시", STYLES["table_head"]),
        ],
        [
            "코드 품질",
            "JUnit의 테스트 및 실패 건수와<br/>커버리지 원시 집계를 교차 검증",
            "실패 발생, 85% 미만,<br/>선언값과 실제 건수 불일치",
        ],
        [
            "SAST",
            "Semgrep JSON과 범용 SARIF를<br/>공통 탐지 결과로 변환",
            "차단 심각도 탐지, 보고서 누락, 스캐너 오류",
        ],
        [
            "SCA / OSS",
            "Trivy, CycloneDX, SPDX 표현식,<br/>VEX와 수정 버전 정보",
            "CRITICAL 취약점, 수정 버전 없음, 금지 라이선스",
        ],
        [
            "DAST",
            "OWASP ZAP 결과와 검사 대상 URL을<br/>이미지 다이제스트에 연결",
            "HIGH 탐지, 승인되지 않은 대상, 보고서 누락",
        ],
        [
            "변경 통제",
            "CB/SR, 승인 역할, 직무 분리,<br/>롤백 계획과 배포 허용 시간",
            "필수 승인 부족, 요청자와 배포자가 동일,<br/>만료된 변경",
        ],
        [
            "검증 입력",
            "보고서 SHA-256, 명령어와 규칙 세트 해시,<br/>러너와 키 허용 목록",
            "서명 실패, 유효 시간 초과, 커밋과 이미지 불일치",
        ],
        [
            "예외 정책",
            "단일 탐지 지문, 독립 승인, 최대 30일,<br/>보완 통제",
            "CRITICAL 등급 예외, 범위 불일치,<br/>만료 또는 연장된 예외",
        ],
    ]
    converted = []
    for row_index, row in enumerate(data):
        if row_index == 0:
            converted.append(row)
        else:
            converted.append(
                [
                    Paragraph(f"<b>{row[0]}</b>", STYLES["table_cell"]),
                    Paragraph(row[1], STYLES["table_cell_small"]),
                    Paragraph(row[2], STYLES["table_cell_small"]),
                ]
            )
    table = Table(
        converted,
        colWidths=[29 * mm, 69 * mm, PAGE_W - 2 * MARGIN - 98 * mm],
        rowHeights=[9 * mm] + [18.8 * mm] * 7,
    )
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("GRID", (0, 0), (-1, -1), 0.45, LINE),
                ("BACKGROUND", (0, 1), (-1, -1), WHITE),
                ("BACKGROUND", (0, 2), (-1, 2), PAPER),
                ("BACKGROUND", (0, 4), (-1, 4), PAPER),
                ("BACKGROUND", (0, 6), (-1, 6), PAPER),
            ]
        )
    )
    _, table_h = table.wrap(PAGE_W - 2 * MARGIN, 160 * mm)
    table.drawOn(canvas, MARGIN, top - table_h)

    lower_top = top - table_h - 7 * mm
    layer_gap = 4 * mm
    layer_w = (PAGE_W - 2 * MARGIN - 2 * layer_gap) / 3
    layers = [
        ("merge-request.toml", "변경 중 빠른 피드백", BLUE_SOFT, BLUE),
        ("financial-baseline.toml", "로컬에서 전체 통제 재현", TEAL_SOFT, TEAL_DARK),
        (
            "financial-release.toml",
            "보호 릴리스용 엄격한 정책",
            AMBER_SOFT,
            HexColor("#9A6514"),
        ),
    ]
    for index, (name, description, fill, accent) in enumerate(layers):
        x = MARGIN + index * (layer_w + layer_gap)
        rounded_card(canvas, x, lower_top, layer_w, 27 * mm, fill=fill, stroke=fill)
        canvas.saveState()
        canvas.setFillColor(accent)
        canvas.rect(x, lower_top - 2.2 * mm, layer_w, 2.2 * mm, fill=1, stroke=0)
        canvas.restoreState()
        para(canvas, name, x + 4 * mm, lower_top - 6 * mm, layer_w - 8 * mm, "card_title")
        para(canvas, description, x + 4 * mm, lower_top - 17 * mm, layer_w - 8 * mm, "body_tiny")

    fail_top = lower_top - 35 * mm
    rounded_card(
        canvas,
        MARGIN,
        fail_top,
        PAGE_W - 2 * MARGIN,
        29 * mm,
        fill=RED_SOFT,
        stroke=HexColor("#F4CACA"),
    )
    para(canvas, "차단 동작 검증", MARGIN + 5 * mm, fail_top - 5 * mm, 43 * mm, "card_title")
    para(
        canvas,
        "SCA의 CRITICAL 취약점, SAST의 HIGH 탐지, AGPL, 테스트 실패, 직무 분리 위반",
        MARGIN + 51 * mm,
        fail_top - 7 * mm,
        PAGE_W - 2 * MARGIN - 57 * mm,
        "body_dark",
    )
    para(
        canvas,
        "위반을 재현해 종료 코드 2를 반환합니다. 누락이나 파싱 실패도 배포를 차단합니다.",
        MARGIN + 51 * mm,
        fail_top - 17 * mm,
        PAGE_W - 2 * MARGIN - 57 * mm,
        "body_tiny",
    )


def page_evidence(canvas: Canvas) -> None:
    top = section_header(
        canvas,
        "04",
        "스캔 실행 기록과 감사 증적",
        "결과 파일만 믿지 않고 실행 주체, 도구, 검사 대상을 확인한 뒤 입력과 판정을 함께 보존합니다.",
    )

    left_w = 69 * mm
    right_x = MARGIN + left_w + 7 * mm
    right_w = PAGE_W - MARGIN - right_x
    rounded_card(canvas, MARGIN, top, left_w, 90 * mm, fill=NAVY, stroke=NAVY)
    para(
        canvas, "PASS 증적 번들", MARGIN + 6 * mm, top - 7 * mm, left_w - 12 * mm, "cover_subtitle"
    )

    tree_lines = [
        (".finguard-evidence", "FinGuard가 생성한 경로"),
        ("manifest.json", "허용 파일 목록과 SHA-256"),
        ("decision.json", "PASS / FAIL과 위반 사유"),
        ("audit.jsonl", "해시 체인 감사 로그"),
        ("summary.md", "검토용 요약"),
        ("inputs/", "정책, 보고서, 변경, 승인"),
        ("signature.*", "HMAC 또는 Cosign 서명"),
    ]
    cursor = top - 21 * mm
    for name, description in tree_lines:
        canvas.saveState()
        canvas.setStrokeColor(HexColor("#37506E"))
        canvas.line(MARGIN + 7 * mm, cursor - 1.5, MARGIN + 12 * mm, cursor - 1.5)
        canvas.restoreState()
        para(canvas, name, MARGIN + 14 * mm, cursor + 3, left_w - 20 * mm, "mono")
        para(canvas, description, MARGIN + 14 * mm, cursor - 8, left_w - 20 * mm, "cover_note")
        cursor -= 9.5 * mm

    rounded_card(canvas, right_x, top, right_w, 90 * mm, fill=WHITE)
    para(
        canvas,
        "스캔 실행 증명서가 확인하는 것",
        right_x + 5 * mm,
        top - 6 * mm,
        right_w - 10 * mm,
        "card_title",
    )
    attestation_items = [
        "보고서 원문의 SHA-256과 스캐너 이름, 버전",
        "실행한 명령어와 규칙 세트의 해시, 종료 코드",
        "전체 소스 커밋, SCA와 DAST의 이미지 다이제스트",
        "허용된 러너 ID, 서명 키 ID, CI 실행 정보",
        "취약점 DB 해시와 갱신 시각, 보고서 최신성",
        "DAST 대상 URL과 승인된 상태 확인 URL의 일치",
    ]
    bullet_list(
        canvas,
        attestation_items,
        right_x + 5 * mm,
        top - 20 * mm,
        right_w - 10 * mm,
        style_name="body_small",
    )
    rounded_card(
        canvas,
        right_x + 5 * mm,
        top - 70 * mm,
        right_w - 10 * mm,
        14 * mm,
        fill=TEAL_SOFT,
        stroke=TEAL_SOFT,
    )
    para(
        canvas,
        "보고서를 바꾸면 서명이 무효화됩니다. 보고서가 없으면 검사 실패로 처리합니다.",
        right_x + 8 * mm,
        top - 73 * mm,
        right_w - 16 * mm,
        "body_tiny",
    )

    flow_top = top - 100 * mm
    para(
        canvas,
        "입력을 고정하고 완성된 증적만 게시",
        MARGIN,
        flow_top,
        PAGE_W - 2 * MARGIN,
        "card_title",
    )
    stages = [
        ("검증 입력", "입력 원문<br/>스냅샷", BLUE_SOFT),
        ("정책 평가", "정책, 보고서<br/>변경, 승인", BLUE_SOFT),
        ("준비 디렉터리", "매니페스트<br/>해시 체인", TEAL_SOFT),
        ("서명", "로컬은 HMAC<br/>보호 환경은 Cosign", TEAL_SOFT),
        ("완성본 교체", "생성 경로 확인<br/>불완전 결과 차단", AMBER_SOFT),
    ]
    gap = 5 * mm
    row_counts = [3, 2]
    row_y = [flow_top - 27 * mm, flow_top - 52 * mm]
    for index, (title, body, fill) in enumerate(stages):
        row = 0 if index < 3 else 1
        column = index if row == 0 else index - 3
        stage_w = (PAGE_W - 2 * MARGIN - (row_counts[row] - 1) * gap) / row_counts[row]
        x = MARGIN + column * (stage_w + gap)
        y = row_y[row]
        flow_box(
            canvas, f"<b>{title}</b><br/>{body}", x, y, stage_w, 20 * mm, fill=fill, stroke=fill
        )
        if column < row_counts[row] - 1:
            arrow(canvas, x + stage_w, y + 10 * mm, x + stage_w + gap - 1, y + 10 * mm, color=MUTED)

    trust_top = row_y[1] - 8 * mm
    trust_gap = 5 * mm
    trust_w = (PAGE_W - 2 * MARGIN - 2 * trust_gap) / 3
    trusts = [
        ("로컬 재현", "공개된 데모 키로 HMAC 서명.<br/>운영 환경에서는 사용 금지.", BLUE_SOFT),
        (
            "보호 릴리스 설계",
            "KMS 또는 Vault URI로 Cosign 서명.<br/>게이트에만 서명 권한 부여.",
            TEAL_SOFT,
        ),
        ("배포 러너", "증적 검증용 공개키만 보유.<br/>PASS 증적 생성 권한 없음.", AMBER_SOFT),
    ]
    for index, (title, body, fill) in enumerate(trusts):
        x = MARGIN + index * (trust_w + trust_gap)
        rounded_card(canvas, x, trust_top, trust_w, 31 * mm, fill=fill, stroke=fill)
        para(canvas, title, x + 4 * mm, trust_top - 5 * mm, trust_w - 8 * mm, "card_title")
        para(canvas, body, x + 4 * mm, trust_top - 16 * mm, trust_w - 8 * mm, "body_tiny")


def page_deploy(canvas: Canvas) -> None:
    top = section_header(
        canvas,
        "05",
        "증적 검증부터 자동 롤백까지",
        "PASS 판정만 믿지 않고 서명, 정책 원문, 변경, 이미지, 배포 위치를 실행 직전에 다시 대조합니다.",
    )

    phases = [
        (
            "01  사전 검증",
            [
                "증적 서명과 매니페스트",
                "정책 ID, 버전, 원문 SHA-256",
                "증적 생성 시각과 배포 허용 시간",
                "배포 위치와 이미지 다이제스트 일치",
            ],
            BLUE_SOFT,
            BLUE,
        ),
        (
            "02  배포 실행",
            [
                "kubectl auth can-i로<br/>RBAC 권한 확인",
                "다이제스트 참조 이미지만 허용",
                "변경 ID와 증적 해시를<br/>애너테이션에 기록",
                "기존 이미지와 감사 정보 저장",
            ],
            TEAL_SOFT,
            TEAL_DARK,
        ),
        (
            "03  검증과 기록",
            [
                "롤아웃 상태와 HTTP 상태 확인",
                "배포 결과를 Cosign으로 서명",
                "결과 파일과 서명 번들<br/>덮어쓰기 금지",
                "실패 결과도 감사 기록으로 보존",
            ],
            AMBER_SOFT,
            HexColor("#9A6514"),
        ),
    ]
    gap = 5 * mm
    phase_w = (PAGE_W - 2 * MARGIN - 2 * gap) / 3
    for index, (title, items, fill, accent) in enumerate(phases):
        x = MARGIN + index * (phase_w + gap)
        rounded_card(canvas, x, top, phase_w, 64 * mm, fill=fill, stroke=fill)
        canvas.saveState()
        canvas.setFillColor(accent)
        canvas.rect(x, top - 2.3 * mm, phase_w, 2.3 * mm, fill=1, stroke=0)
        canvas.restoreState()
        para(canvas, title, x + 5 * mm, top - 7 * mm, phase_w - 10 * mm, "card_title")
        bullet_list(
            canvas,
            items,
            x + 5 * mm,
            top - 23 * mm,
            phase_w - 10 * mm,
            style_name="body_small",
            bullet_color=accent,
        )

    rollback_top = top - 74 * mm
    rounded_card(
        canvas,
        MARGIN,
        rollback_top,
        PAGE_W - 2 * MARGIN,
        45 * mm,
        fill=RED_SOFT,
        stroke=HexColor("#F4CACA"),
    )
    para(canvas, "자동 롤백 경로", MARGIN + 6 * mm, rollback_top - 6 * mm, 42 * mm, "card_title")
    triggers = ["롤아웃 실패", "스모크 테스트 실패", "배포 결과 저장 실패", "결과 Cosign 서명 실패"]
    x = MARGIN + 49 * mm
    y = rollback_top - 10 * mm
    chip_width = 42 * mm
    for index, item in enumerate(triggers):
        if index == 2:
            x = MARGIN + 49 * mm
            y -= 10 * mm
        pill(canvas, item, x, y, chip_width, fill=WHITE, text_color=RED)
        x += chip_width + 4 * mm
    para(
        canvas,
        "Kubernetes 배포 이후 실패가 발생하면 직전에 확인한 이전 불변 이미지 다이제스트와 기존 FinGuard 감사 애너테이션을 복원합니다.",
        MARGIN + 49 * mm,
        rollback_top - 31 * mm,
        PAGE_W - 2 * MARGIN - 55 * mm,
        "body_small",
    )

    lower_top = rollback_top - 53 * mm
    left_w = (PAGE_W - 2 * MARGIN - 6 * mm) / 2
    right_x = MARGIN + left_w + 6 * mm
    rounded_card(canvas, MARGIN, lower_top, left_w, 52 * mm, fill=PAPER)
    para(
        canvas,
        "온프레미스 적용 설계",
        MARGIN + 5 * mm,
        lower_top - 6 * mm,
        left_w - 10 * mm,
        "card_title",
    )
    bullet_list(
        canvas,
        [
            "BuildKit 또는 Podman으로 루트 권한 없이 한 번만 빌드",
            "도구와 인프라 이미지를 다이제스트로 고정",
            "SonarQube와 PostgreSQL 이미지를<br/>내부 레지스트리에 반입해 서명 검증",
            "배포 러너에는 공개키만 두고 서명 권한은 분리",
        ],
        MARGIN + 5 * mm,
        lower_top - 20 * mm,
        left_w - 10 * mm,
        style_name="body_tiny",
    )
    rounded_card(canvas, right_x, lower_top, left_w, 52 * mm, fill=PAPER)
    para(
        canvas,
        "개발자와 운영자에게 제공하는 결과",
        right_x + 5 * mm,
        lower_top - 6 * mm,
        left_w - 10 * mm,
        "card_title",
    )
    bullet_list(
        canvas,
        [
            "GitLab Code Quality JSON과 SARIF 내보내기",
            "적용 전에 후보 정책과 기준 정책을 비교한 결과",
            "판정, 탐지, 예외, VEX, OSS 인벤토리와<br/>승인 증적 검증 지표를 Prometheus 형식으로 출력",
            "로컬 내장 스캐너로 외부 보안 서버 없이 빠른 피드백",
        ],
        right_x + 5 * mm,
        lower_top - 20 * mm,
        left_w - 10 * mm,
        style_name="body_tiny",
    )


def page_validation(canvas: Canvas, facts: dict[str, str]) -> None:
    top = section_header(
        canvas,
        "06",
        "검증 결과와 제출 범위",
        "재현 명령, 테스트 결과, 공개 CI와 검증하지 않은 범위를 함께 제시합니다.",
    )

    metric_gap = 5 * mm
    metric_w = (PAGE_W - 2 * MARGIN - 3 * metric_gap) / 4
    for index, (value, label) in enumerate(
        [
            (facts["test_count"], "회귀 테스트"),
            (facts["coverage_percent"], "핵심 패키지 커버리지"),
            ("0", "Ruff 위반"),
            ("0", "Mypy 오류"),
        ]
    ):
        metric_card(canvas, MARGIN + index * (metric_w + metric_gap), top, metric_w, value, label)

    columns_top = top - 35 * mm
    col_gap = 6 * mm
    col_w = (PAGE_W - 2 * MARGIN - col_gap) / 2
    rounded_card(canvas, MARGIN, columns_top, col_w, 74 * mm, fill=GREEN_SOFT, stroke=GREEN_SOFT)
    para(
        canvas, "검증한 범위", MARGIN + 5 * mm, columns_top - 6 * mm, col_w - 10 * mm, "card_title"
    )
    verified = [
        "GitHub Actions에서 품질 검사와 E2E 데모 실행",
        "Semgrep, Trivy, OWASP ZAP을 공개 CI에서 실제 실행",
        "Cosign 및 kubectl 어댑터의 하위 프로세스 계약 검증",
        "변조, 누락, 서명 오류, 유효 시간 초과 상황의 회귀 테스트",
        "롤아웃, 스모크 테스트 또는 결과 서명 실패 시 롤백",
        "main 브랜치 보호, 필수 CI 검사,<br/>강제 푸시 및 브랜치 삭제 차단",
    ]
    bullet_list(
        canvas,
        verified,
        MARGIN + 5 * mm,
        columns_top - 20 * mm,
        col_w - 10 * mm,
        style_name="body_small",
        bullet_color=GREEN,
    )

    right_x = MARGIN + col_w + col_gap
    rounded_card(canvas, right_x, columns_top, col_w, 74 * mm, fill=AMBER_SOFT, stroke=AMBER_SOFT)
    para(
        canvas,
        "검증하지 않은 범위",
        right_x + 5 * mm,
        columns_top - 6 * mm,
        col_w - 10 * mm,
        "card_title",
    )
    limitations = [
        "예제 스캔 보고서와 샘플 서비스로 구성한 포트폴리오",
        "실제 온프레미스 서버 및 Kubernetes<br/>운영 실적은 포함하지 않음",
        "Coverity와 SonarQube는 SARIF 파일만 검증.<br/>상용 서버 API는 연동하지 않음",
        "FOSSA는 실행하지 않음. Trivy, CycloneDX, SPDX로 OSS 관리",
        "실제 도입에는 ITSM과 IdP API, 워크로드 아이덴티티, WORM 저장소, SIEM 전송 필요",
    ]
    bullet_list(
        canvas,
        limitations,
        right_x + 5 * mm,
        columns_top - 20 * mm,
        col_w - 10 * mm,
        style_name="body_small",
        bullet_color=AMBER,
    )

    reproduce_top = columns_top - 83 * mm
    rounded_card(
        canvas, MARGIN, reproduce_top, PAGE_W - 2 * MARGIN, 42 * mm, fill=NAVY, stroke=NAVY
    )
    para(canvas, "로컬 재현", MARGIN + 6 * mm, reproduce_top - 6 * mm, 30 * mm, "cover_subtitle")
    commands = (
        "python3 -m venv .venv<br/>"
        ".venv/bin/pip install -r requirements-dev.lock<br/>"
        ".venv/bin/pip install --no-deps -e .<br/>"
        "make quality<br/>"
        "./scripts/demo.sh"
    )
    para(canvas, commands, MARGIN + 42 * mm, reproduce_top - 6 * mm, 68 * mm, "mono")
    para(
        canvas,
        "PASS 증적 서명과 재검증, 위험 변경 차단을 한 번에 확인합니다. FAIL 시나리오는 의도한 종료 코드 2를 반환합니다.",
        MARGIN + 116 * mm,
        reproduce_top - 8 * mm,
        PAGE_W - MARGIN - (MARGIN + 116 * mm) - 6 * mm,
        "cover_note",
    )

    fit_top = reproduce_top - 45 * mm
    para(
        canvas,
        "직무 역량과 연결되는 구체적 근거",
        MARGIN,
        fit_top,
        PAGE_W - 2 * MARGIN,
        "card_title",
    )
    fit_items = [
        ("CI/CD 표준화", "GitLab과 Jenkins에서 같은 CLI와 정책을 사용"),
        ("DevSecOps 자동화", "SAST, SCA, DAST와 OSS 통제를 게이트에 통합"),
        ("정책 기반 품질 관리", "품질 기준과 승인 규칙을 TOML로 관리"),
        ("배포 안전성", "불변 이미지, RBAC, 서명, 자동 롤백"),
    ]
    fit_gap = 5 * mm
    fit_w = (PAGE_W - 2 * MARGIN - fit_gap) / 2
    fit_card_h = 21.5 * mm
    for index, (title, body) in enumerate(fit_items):
        row, column = divmod(index, 2)
        card_top = fit_top - 7 * mm - row * (fit_card_h + 4 * mm)
        x = MARGIN + column * (fit_w + fit_gap)
        rounded_card(canvas, x, card_top, fit_w, fit_card_h, fill=PAPER)
        para(canvas, title, x + 4 * mm, card_top - 4 * mm, fit_w - 8 * mm, "fit_title")
        para(canvas, body, x + 4 * mm, card_top - 11.5 * mm, fit_w - 8 * mm, "body_tiny")

    links_top = fit_top - 59 * mm
    para(
        canvas,
        f'<link href="{REPO_URL}"><u>저장소 및 코드</u></link>  |  '
        f'<link href="{ACTIONS_URL}"><u>GitHub Actions 실행 이력</u></link>  |  '
        f'<link href="{PROFILE_URL}"><u>@kwakhyun</u></link>',
        MARGIN,
        links_top,
        PAGE_W - 2 * MARGIN,
        "link",
    )


def add_accessibility_structure(output: Path, page_titles: list[str]) -> None:
    """Add a page-level logical structure without changing the visual design.

    ReportLab does not expose high-level tagged-PDF authoring. The post-process
    wraps each page in a marked-content section and builds a Document > Sect
    structure tree. This provides deterministic page reading order and tagged
    navigation while intentionally stopping short of a PDF/UA conformance claim.
    """

    reader = PdfReader(output)
    if len(reader.pages) != len(page_titles):
        raise SystemExit("PDF page count changed before accessibility tagging")

    writer = PdfWriter()
    writer.clone_document_from_reader(reader)

    struct_root = DictionaryObject({NameObject("/Type"): NameObject("/StructTreeRoot")})
    struct_root_ref = writer._add_object(struct_root)
    document_element = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/StructElem"),
            NameObject("/S"): NameObject("/Document"),
            NameObject("/P"): struct_root_ref,
            NameObject("/T"): TextStringObject("FinGuard DevSecOps 포트폴리오"),
        }
    )
    document_ref = writer._add_object(document_element)
    section_refs = ArrayObject()
    parent_tree_numbers = ArrayObject()

    for index, (page, title) in enumerate(zip(writer.pages, page_titles, strict=True)):
        contents = page.get_contents()
        payload = contents.get_data() if contents is not None else b""
        marked_stream = DecodedStreamObject()
        marked_stream.set_data(b"/Sect <</MCID 0>> BDC\n" + payload + b"\nEMC\n")
        page[NameObject("/Contents")] = writer._add_object(marked_stream)
        page[NameObject("/StructParents")] = NumberObject(index)
        page[NameObject("/Tabs")] = NameObject("/S")

        page_ref = page.indirect_reference
        if page_ref is None:
            raise SystemExit("Unable to resolve an indirect page reference for tagging")
        marked_content = DictionaryObject(
            {
                NameObject("/Type"): NameObject("/MCR"),
                NameObject("/Pg"): page_ref,
                NameObject("/MCID"): NumberObject(0),
            }
        )
        section = DictionaryObject(
            {
                NameObject("/Type"): NameObject("/StructElem"),
                NameObject("/S"): NameObject("/Sect"),
                NameObject("/P"): document_ref,
                NameObject("/Pg"): page_ref,
                NameObject("/K"): ArrayObject([marked_content]),
                NameObject("/T"): TextStringObject(title),
            }
        )
        section_ref = writer._add_object(section)
        section_refs.append(section_ref)
        parent_tree_numbers.extend([NumberObject(index), ArrayObject([section_ref])])

    document_element[NameObject("/K")] = section_refs
    parent_tree = DictionaryObject({NameObject("/Nums"): parent_tree_numbers})
    parent_tree_ref = writer._add_object(parent_tree)
    struct_root.update(
        {
            NameObject("/K"): document_ref,
            NameObject("/ParentTree"): parent_tree_ref,
            NameObject("/ParentTreeNextKey"): NumberObject(len(page_titles)),
        }
    )
    writer.root_object[NameObject("/StructTreeRoot")] = struct_root_ref
    writer.root_object[NameObject("/MarkInfo")] = DictionaryObject(
        {NameObject("/Marked"): BooleanObject(True)}
    )
    writer.add_metadata(
        {
            "/CreationDate": PDF_RELEASE_DATE,
            "/ModDate": PDF_RELEASE_DATE,
        }
    )

    temporary = output.with_suffix(".tagged.tmp.pdf")
    with temporary.open("wb") as file_obj:
        writer.write(file_obj)
    temporary.replace(output)


def build_pdf(
    output: Path,
    root: Path,
    *,
    junit_xml: Path | None = None,
    coverage_xml: Path | None = None,
) -> None:
    register_fonts()
    initialize_styles()
    verify_validation_reports(junit_xml, coverage_xml)
    facts = verify_source_facts(root)
    output.parent.mkdir(parents=True, exist_ok=True)
    canvas = Canvas(str(output), pagesize=A4, pageCompression=1, invariant=1)
    canvas.setTitle("FinGuard DevSecOps 포트폴리오")
    canvas.setAuthor("@kwakhyun")
    canvas.setCreator("FinGuard portfolio PDF generator")
    canvas.setSubject("온프레미스 환경을 고려한 Python 기반 DevSecOps 릴리스 게이트 포트폴리오")
    canvas.setKeywords("DevSecOps, Python, CI/CD, SAST, SCA, DAST, Kubernetes, 포트폴리오")
    canvas._doc.Catalog.Lang = PDFString("ko-KR")
    canvas.showOutline()

    pages = [
        ("FinGuard", lambda c: page_cover(c, facts)),
        ("문제 정의와 핵심 설계", page_problem),
        ("신뢰 경계를 분리한 릴리스 흐름", page_flow),
        ("정책 기반 품질과 보안 관리", page_policy),
        ("스캔 실행 기록과 감사 증적", page_evidence),
        ("증적 검증부터 자동 롤백까지", page_deploy),
        ("검증 결과와 제출 범위", lambda c: page_validation(c, facts)),
    ]
    for index, (title, draw_page) in enumerate(pages):
        if index:
            canvas.showPage()
        page_key = f"page-{index + 1}"
        canvas.bookmarkPage(page_key)
        canvas.addOutlineEntry(title, page_key, level=0, closed=False)
        draw_page(canvas)
        if index:
            footer(canvas, index + 1)
    canvas.save()
    add_accessibility_structure(output, [title for title, _ in pages])


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("output/pdf/FinGuard_DevSecOps_Portfolio.pdf"),
    )
    parser.add_argument(
        "--junit-xml",
        type=Path,
        help="Optional fresh JUnit report used to verify the displayed test count",
    )
    parser.add_argument(
        "--coverage-xml",
        type=Path,
        help="Optional fresh Coverage XML used to verify the displayed coverage",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    root = Path(__file__).resolve().parents[1]
    output = args.output if args.output.is_absolute() else root / args.output
    build_pdf(
        output,
        root,
        junit_xml=args.junit_xml,
        coverage_xml=args.coverage_xml,
    )
    print(output)


if __name__ == "__main__":
    main()
