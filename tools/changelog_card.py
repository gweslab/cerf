from __future__ import annotations

import io
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from PIL import Image, ImageDraw, ImageFont

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import changelog
from ci_release import Artifact, latest_release
from source_diffstat import diffstat

ROOT = Path(__file__).resolve().parent.parent
FONT_DIR = ROOT / "assets" / "fonts"
LOGO_PATH = ROOT / "assets" / "cerf_1024.png"

SCALE = 2
WIDTH = 1200
PAD = 44
GUTTER = 52
LOGO = 88

BACKGROUND = (49, 51, 56)
TEXT = (219, 222, 225)
MUTED = (148, 155, 164)
HEADING = (255, 255, 255)
RULE = (70, 74, 82)
GREEN = (63, 185, 80)
RED = (248, 81, 73)
BLUE = (88, 166, 255)
NEUTRAL = (72, 79, 88)
WHITE = (255, 255, 255)

KINDS = {
    "release": ("RELEASE", (35, 134, 54)),
    "candidate": ("RELEASE CANDIDATE", (187, 128, 9)),
    "unstable": ("UNSTABLE", (196, 90, 30)),
}
MARKER_COLORS = {"new": GREEN, "fixed": BLUE, "deleted": RED}

TITLE_SIZE = 34
SUB_SIZE = 22
BADGE_SIZE = 13
STAT_SIZE = 24
SINCE_SIZE = 16
HEAD_SIZE = 22
HEAD_LINE = 30
HEAD_ABOVE = 22
HEAD_BELOW = 8
ITEM_SIZE = 17
ITEM_LINE = 25
ITEM_GAP = 7
MARKER = 16
INDENT = 28
BLOCK = 14
BLOCK_GAP = 3
BLOCKS = 5

BOLD_MARKUP = re.compile(r"\*\*(.+?)\*\*")
Token = Tuple[str, bool, bool]
Row = List[Tuple[str, bool, float]]


@dataclass(frozen=True)
class CardInfo:
    series: str
    build: int
    kind: str
    added: int
    deleted: int
    since: str


@dataclass(frozen=True)
class _Element:
    group: str
    marker: Optional[str] = None
    line: Optional[str] = None

    @property
    def is_heading(self) -> bool:
        return self.line is None


def _tokens(line: str) -> List[Token]:
    tokens: List[Token] = []
    gap = False
    for index, chunk in enumerate(BOLD_MARKUP.split(line)):
        for piece in re.split(r"(\s+)", chunk):
            if not piece:
                continue
            if piece.isspace():
                gap = True
                continue
            tokens.append((piece, index % 2 == 1, gap and bool(tokens)))
            gap = False
    return tokens


def _elements(groups: List[dict]) -> List[_Element]:
    elements = []
    for group in groups:
        elements.append(_Element(group["heading"]))
        for sub in group["subcats"]:
            for line in sub["lines"]:
                elements.append(_Element(group["heading"], sub.get("key"), line))
    return elements


def diff_blocks(added: int, deleted: int) -> Tuple[int, int, int]:
    total = added + deleted
    if total == 0:
        return 0, 0, BLOCKS
    green = added * BLOCKS // total
    red = deleted * BLOCKS // total
    return green, red, BLOCKS - green - red


class _Painter:
    def __init__(self) -> None:
        self.fonts: Dict[Tuple[int, bool], ImageFont.FreeTypeFont] = {}
        self.draw: Optional[ImageDraw.ImageDraw] = None
        self.image: Optional[Image.Image] = None

    def font(self, size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
        key = (size, bold)
        if key not in self.fonts:
            name = "IBMPlexSans-Bold.ttf" if bold else "IBMPlexSans-Regular.ttf"
            self.fonts[key] = ImageFont.truetype(str(FONT_DIR / name), size * SCALE)
        return self.fonts[key]

    def width(self, text: str, size: int, bold: bool = False) -> float:
        return self.font(size, bold).getlength(text) / SCALE

    def wrap(self, line: str, width: float) -> List[Row]:
        rows: List[Row] = [[]]
        x = 0.0
        for word, bold, space in _tokens(line):
            w = self.width(word, ITEM_SIZE, bold)
            gap = self.width(" ", ITEM_SIZE) if space else 0.0
            if rows[-1] and space and x + gap + w > width:
                rows.append([])
                x, gap = 0.0, 0.0
            rows[-1].append((word, bold, gap))
            x += gap + w
        return rows

    def begin(self, height: int) -> None:
        self.image = Image.new("RGB", (WIDTH * SCALE, height * SCALE), BACKGROUND)
        self.draw = ImageDraw.Draw(self.image)

    def text(self, x: float, baseline: float, text: str, size: int,
             color: tuple, bold: bool = False) -> float:
        self.draw.text((x * SCALE, baseline * SCALE), text,
                       font=self.font(size, bold), fill=color, anchor="ls")
        return self.width(text, size, bold)

    def box(self, x0: float, y0: float, x1: float, y1: float, color: tuple,
            radius: float = 0) -> None:
        self.draw.rounded_rectangle(
            (x0 * SCALE, y0 * SCALE, x1 * SCALE, y1 * SCALE),
            radius=radius * SCALE, fill=color)

    def line(self, points: List[Tuple[float, float]], color: tuple,
             width: float) -> None:
        self.draw.line([(x * SCALE, y * SCALE) for x, y in points],
                       fill=color, width=round(width * SCALE), joint="curve")

    def logo(self, x: float, y: float, size: int) -> None:
        with Image.open(LOGO_PATH) as source:
            logo = source.convert("RGBA").resize((size * SCALE, size * SCALE),
                                                 Image.LANCZOS)
        self.image.paste(logo, (round(x * SCALE), round(y * SCALE)), logo)

    def png(self) -> bytes:
        out = io.BytesIO()
        self.image.save(out, format="PNG", optimize=True)
        return out.getvalue()


class _Card:
    def __init__(self, groups: List[dict], info: CardInfo) -> None:
        self.info = info
        self.paint = _Painter()
        self.column = (WIDTH - 2 * PAD - GUTTER) / 2
        self.elements = _elements(groups)
        self.rows = {i: self.paint.wrap(e.line, self.column - INDENT)
                     for i, e in enumerate(self.elements) if not e.is_heading}

    def element_height(self, index: int, first: bool) -> float:
        if self.elements[index].is_heading:
            return (0 if first else HEAD_ABOVE) + HEAD_LINE + HEAD_BELOW
        return len(self.rows[index]) * ITEM_LINE + ITEM_GAP

    def column_height(self, indices: List[int]) -> float:
        return sum(self.element_height(i, n == 0) for n, i in enumerate(indices))

    def columns(self) -> Tuple[List[int], List[int]]:
        count = len(self.elements)
        best: Optional[Tuple[float, List[int], List[int]]] = None
        for split in range(1, count + 1):
            if split < count and not self.elements[split].is_heading:
                continue
            left = list(range(split))
            right = list(range(split, count))
            height = max(self.column_height(left), self.column_height(right))
            if best is None or height < best[0]:
                best = (height, left, right)
        return (best[1], best[2]) if best else ([], [])

    def header_height(self) -> float:
        return PAD + LOGO + 22

    def render(self) -> bytes:
        left, right = self.columns()
        body_top = self.header_height() + 20
        body = max(self.column_height(left), self.column_height(right))
        if not self.elements:
            body = ITEM_LINE
        height = round(body_top + body + PAD)
        self.paint.begin(height)
        self.draw_header()
        self.paint.box(PAD, self.header_height(), WIDTH - PAD,
                       self.header_height() + 1, RULE)
        if not self.elements:
            self.paint.text(PAD, body_top + 18,
                            f"Nothing recorded in the {self.info.series} "
                            "changelog yet.", ITEM_SIZE, MUTED)
            return self.paint.png()
        self.draw_column(left, PAD, body_top)
        self.draw_column(right, PAD + self.column + GUTTER, body_top)
        if right:
            x = PAD + self.column + GUTTER / 2
            self.paint.box(x, body_top, x + 1, body_top + body - ITEM_GAP, RULE)
        return self.paint.png()

    def draw_header(self) -> None:
        paint = self.paint
        info = self.info
        paint.logo(PAD, PAD, LOGO)
        x = PAD + LOGO + 22
        title_base = PAD + 38
        sub_base = PAD + 72
        paint.text(x, title_base, "CE Runtime Foundation", TITLE_SIZE, HEADING,
                   bold=True)
        x += paint.text(x, sub_base, f"v{info.series} build {info.build}",
                        SUB_SIZE, TEXT) + 14
        label, color = KINDS[info.kind]
        label_w = paint.width(label, BADGE_SIZE, bold=True)
        paint.box(x, sub_base - 19, x + label_w + 18, sub_base + 3, color, 11)
        paint.text(x + 9, sub_base - 3, label, BADGE_SIZE, WHITE, bold=True)
        self.draw_diffstat(title_base, sub_base)

    def draw_diffstat(self, stat_base: float, since_base: float) -> None:
        paint = self.paint
        info = self.info
        added = f"+{info.added:,}"
        deleted = f"-{info.deleted:,}"
        blocks_w = BLOCKS * BLOCK + (BLOCKS - 1) * BLOCK_GAP
        added_w = paint.width(added, STAT_SIZE, bold=True)
        deleted_w = paint.width(deleted, STAT_SIZE, bold=True)
        x = WIDTH - PAD - (added_w + 10 + deleted_w + 14 + blocks_w)
        x += paint.text(x, stat_base, added, STAT_SIZE, GREEN, bold=True) + 10
        x += paint.text(x, stat_base, deleted, STAT_SIZE, RED, bold=True) + 14
        green, red, _ = diff_blocks(info.added, info.deleted)
        top = stat_base - 8 - BLOCK / 2
        for n in range(BLOCKS):
            color = GREEN if n < green else RED if n < green + red else NEUTRAL
            paint.box(x, top, x + BLOCK, top + BLOCK, color, 2)
            x += BLOCK + BLOCK_GAP
        since = f"since {info.since}"
        paint.text(WIDTH - PAD - paint.width(since, SINCE_SIZE), since_base,
                   since, SINCE_SIZE, MUTED)

    def draw_column(self, indices: List[int], x: float, y: float) -> None:
        for n, index in enumerate(indices):
            element = self.elements[index]
            if element.is_heading:
                if n:
                    y += HEAD_ABOVE
                self.paint.text(x, y + 22, element.group, HEAD_SIZE, HEADING,
                                bold=True)
                y += HEAD_LINE + HEAD_BELOW
                continue
            self.draw_marker(element.marker, x + MARKER / 2, y + 12)
            for row in self.rows[index]:
                cursor = x + INDENT
                for word, bold, gap in row:
                    cursor += gap
                    cursor += self.paint.text(cursor, y + 18, word, ITEM_SIZE,
                                              TEXT, bold)
                y += ITEM_LINE
            y += ITEM_GAP

    def draw_marker(self, marker: Optional[str], cx: float, cy: float) -> None:
        paint = self.paint
        half = MARKER / 2
        color = MARKER_COLORS.get(marker)
        if color is None:
            paint.box(cx - 3, cy - 3, cx + 3, cy + 3, MUTED, 3)
            return
        paint.box(cx - half, cy - half, cx + half, cy + half, color, 4)
        arm = MARKER * 0.28
        if marker == "fixed":
            paint.line([(cx - arm, cy), (cx - arm * 0.25, cy + arm * 0.8),
                        (cx + arm, cy - arm * 0.7)], WHITE, 2)
            return
        paint.box(cx - arm, cy - 1, cx + arm, cy + 1, WHITE)
        if marker == "new":
            paint.box(cx - 1, cy - arm, cx + 1, cy + arm, WHITE)


def render_card(groups: List[dict], info: CardInfo) -> bytes:
    if info.kind not in KINDS:
        raise ValueError(f"unknown card kind {info.kind!r}")
    return _Card(groups, info).render()


def artifact_card(token: str, artifact: Artifact, kind: str) -> bytes:
    since, base = latest_release(token)
    added, deleted = diffstat(base, artifact.sha)
    entry = changelog.entry_for(artifact.series)
    groups = entry["groups"] if entry else []
    return render_card(groups, CardInfo(
        series=artifact.series, build=artifact.run_number, kind=kind,
        added=added, deleted=deleted, since=since))
