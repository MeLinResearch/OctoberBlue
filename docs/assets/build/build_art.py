"""Generate OctoberBlue's README artwork.

Every glyph is converted to a path, so the SVGs render the same on GitHub, in any
browser and in light or dark mode, with no font loading.

Usage:
    pip install fonttools uharfbuzz
    OCTOBERBLUE_FONTS=/path/to/fonts PYTHONPATH=src python docs/assets/build/build_art.py

Fonts expected in OCTOBERBLUE_FONTS (all SIL OFL; variable fonts instanced with
``fontTools.varLib.instancer``):
    BigShouldersStencil-Black.ttf   Big Shoulders Stencil, opsz 72, wght 900
    BigShoulders-Black.ttf          Big Shoulders, opsz 72, wght 900
    IBMPlexSans-Regular.ttf         IBM Plex Sans, wdth 100, wght 400
    IBMPlexSans-SemiBold.ttf        IBM Plex Sans, wdth 100, wght 600
    IBMPlexSans-Bold.ttf            IBM Plex Sans, wdth 100, wght 700
    IBMPlexSansCond-Bold.ttf        IBM Plex Sans, wdth 85, wght 700
    IBMPlexMono-Regular.ttf, IBMPlexMono-Medium.ttf, IBMPlexMono-Bold.ttf

The harness-check card runs the real offline demo (four synthetic runs, $0.00);
the nutrition label reads its counts from docs/REQUIREMENTS.md. Nothing on any
card is typed in by hand as a result.
"""

from __future__ import annotations

import math
import os
import re
from pathlib import Path
from xml.sax.saxutils import escape

import uharfbuzz as hb
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.ttLib import TTFont

FONT_DIR = Path(os.environ.get("OCTOBERBLUE_FONTS", Path.home() / ".fonts"))
OUT_DIR = Path(__file__).resolve().parents[1]
DOCS = OUT_DIR.parent

# -- palette -----------------------------------------------------------------
BG = "#090c15"
PANEL = "#111727"
PANEL2 = "#182035"
LINE = "#252f48"
INK = "#eaf0fb"
INK2 = "#a7b2cb"
MUTED = "#69758f"
RED = "#ff4d5e"  # red side: research and attack
BLUE = "#4f8dff"  # blue side: research and guard
TEAL = "#2fd3b0"  # trusted code: harness, gateway, verifier
AMBER = "#ffb020"  # budget and spend
VIOLET = "#a68bff"  # memory and Dreaming
RED_BG = "#2a1320"
BLUE_BG = "#122245"
TEAL_BG = "#0f2a2b"


# --------------------------------------------------------------------------
# text -> path
# --------------------------------------------------------------------------
class Face:
    def __init__(self, filename: str) -> None:
        path = FONT_DIR / filename
        self.tt = TTFont(path)
        self.glyphs = self.tt.getGlyphSet()
        self.order = self.tt.getGlyphOrder()
        self.upm = self.tt["head"].unitsPerEm
        self.hb = hb.Font(hb.Face(hb.Blob.from_file_path(str(path))))

    def _shape(self, s: str):
        buf = hb.Buffer()
        buf.add_str(s)
        buf.guess_segment_properties()
        hb.shape(self.hb, buf, {"kern": True, "liga": False})
        return buf.glyph_infos, buf.glyph_positions

    def width(self, s: str, size: float, track: float = 0) -> float:
        _, pos = self._shape(s)
        return sum(p.x_advance for p in pos) * size / self.upm + track * max(len(pos) - 1, 0)

    def d(self, s: str, x: float, y: float, size: float, track: float = 0) -> str:
        infos, pos = self._shape(s)
        k = size / self.upm
        pen = SVGPathPen(self.glyphs)
        cx = x
        for info, p in zip(infos, pos, strict=True):
            name = self.order[info.codepoint]
            tp = TransformPen(pen, (k, 0, 0, -k, cx + p.x_offset * k, y - p.y_offset * k))
            self.glyphs[name].draw(tp)
            cx += p.x_advance * k + track
        return re.sub(
            r"-?\d+\.\d+", lambda m: f"{float(m.group()):.1f}".rstrip("0").rstrip("."),
            pen.getCommands(),
        )


F = {
    "stencil": Face("BigShouldersStencil-Black.ttf"),
    "display": Face("BigShoulders-Black.ttf"),
    "reg": Face("IBMPlexSans-Regular.ttf"),
    "semi": Face("IBMPlexSans-SemiBold.ttf"),
    "bold": Face("IBMPlexSans-Bold.ttf"),
    "cond": Face("IBMPlexSansCond-Bold.ttf"),
    "mono": Face("IBMPlexMono-Regular.ttf"),
    "monom": Face("IBMPlexMono-Medium.ttf"),
    "monob": Face("IBMPlexMono-Bold.ttf"),
}


class Svg:
    def __init__(self, w: int, h: int, label: str, bg: str | None = BG, rx: int = 16) -> None:
        self.w, self.h = w, h
        self.parts: list[str] = []
        self.defs: list[str] = []
        self.label = label
        self.bg = bg
        self.rx = rx

    def add(self, s: str) -> None:
        self.parts.append(s)

    def text(self, s, x, y, font, size, fill, anchor="start", track=0.0, op=None):
        w = F[font].width(s, size, track)
        if anchor == "middle":
            x -= w / 2
        elif anchor == "end":
            x -= w
        o = f' opacity="{op}"' if op is not None else ""
        self.add(f'<path d="{F[font].d(s, x, y, size, track)}" fill="{fill}"{o}/>')
        return w

    def lines(self, rows, x, y, font, size, fill, lead, anchor="start", track=0.0):
        for i, row in enumerate(rows):
            self.text(row, x, y + i * lead, font, size, fill, anchor, track)

    def rect(self, x, y, w, h, fill="none", rx=0, stroke=None, sw=1, dash=None, op=None):
        s = f' stroke="{stroke}" stroke-width="{sw}"' if stroke else ""
        d = f' stroke-dasharray="{dash}"' if dash else ""
        o = f' opacity="{op}"' if op is not None else ""
        self.add(f'<rect x="{x:g}" y="{y:g}" width="{w:g}" height="{h:g}" rx="{rx}" '
                 f'fill="{fill}"{s}{d}{o}/>')

    def line(self, x1, y1, x2, y2, stroke, sw=1.5, dash=None, op=None, cap="round"):
        d = f' stroke-dasharray="{dash}"' if dash else ""
        o = f' opacity="{op}"' if op is not None else ""
        self.add(f'<line x1="{x1:g}" y1="{y1:g}" x2="{x2:g}" y2="{y2:g}" stroke="{stroke}" '
                 f'stroke-width="{sw}" stroke-linecap="{cap}"{d}{o}/>')

    def path(self, d, stroke="none", sw=1.5, fill="none", dash=None, op=None, join="round"):
        dd = f' stroke-dasharray="{dash}"' if dash else ""
        o = f' opacity="{op}"' if op is not None else ""
        self.add(f'<path d="{d}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}" '
                 f'stroke-linecap="round" stroke-linejoin="{join}"{dd}{o}/>')

    def circle(self, cx, cy, r, fill="none", stroke=None, sw=1.5, dash=None, op=None):
        s = f' stroke="{stroke}" stroke-width="{sw}"' if stroke else ""
        d = f' stroke-dasharray="{dash}"' if dash else ""
        o = f' opacity="{op}"' if op is not None else ""
        self.add(f'<circle cx="{cx:g}" cy="{cy:g}" r="{r:g}" fill="{fill}"{s}{d}{o}/>')

    def card(self, x, y, w, h, bar, fill=PANEL, rx=14, bar_w=5):
        """A rounded panel whose left accent bar is clipped to the panel's corners."""
        cid = f"c{len(self.defs)}"
        self.defs.append(f'<clipPath id="{cid}"><rect x="{x:g}" y="{y:g}" width="{w:g}" '
                         f'height="{h:g}" rx="{rx}"/></clipPath>')
        self.rect(x, y, w, h, fill=fill, rx=rx)
        self.add(f'<rect x="{x:g}" y="{y:g}" width="{bar_w}" height="{h:g}" fill="{bar}" '
                 f'clip-path="url(#{cid})"/>')

    def done(self) -> str:
        label = escape(self.label, {'"': "&quot;"})
        defs = f"<defs>{''.join(self.defs)}</defs>" if self.defs else ""
        bg = (f'<rect width="{self.w}" height="{self.h}" rx="{self.rx}" fill="{self.bg}"/>'
              if self.bg else "")
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {self.w} {self.h}" '
            f'width="{self.w}" height="{self.h}" role="img" aria-label="{label}">'
            f"<title>{escape(self.label)}</title>{defs}{bg}{''.join(self.parts)}</svg>\n"
        )


def arrowhead(s: Svg, x, y, angle, color, size=8):
    """A filled triangle pointing along ``angle`` (radians), tip at (x, y)."""
    a1, a2 = angle + math.radians(150), angle - math.radians(150)
    p1 = (x + size * math.cos(a1), y + size * math.sin(a1))
    p2 = (x + size * math.cos(a2), y + size * math.sin(a2))
    s.add(f'<path d="M{x:.1f} {y:.1f} L{p1[0]:.1f} {p1[1]:.1f} L{p2[0]:.1f} {p2[1]:.1f} Z" '
          f'fill="{color}"/>')


def arrow(s: Svg, x1, y1, x2, y2, color, sw=2, dash=None, op=None, size=9):
    ang = math.atan2(y2 - y1, x2 - x1)
    s.line(x1, y1, x2 - (size - 2) * math.cos(ang), y2 - (size - 2) * math.sin(ang), color,
           sw=sw, dash=dash, op=op)
    arrowhead(s, x2, y2, ang, color, size=size)


def wrap(text: str, font: str, size: float, width: float) -> list[str]:
    words, rows, row = text.split(), [], ""
    for word in words:
        trial = f"{row} {word}".strip()
        if F[font].width(trial, size) <= width or not row:
            row = trial
        else:
            rows.append(row)
            row = word
    if row:
        rows.append(row)
    return rows


def pill(s: Svg, text, cx, cy, color, fill=BG, font="monob", size=11, pad=10, track=0.6):
    w = F[font].width(text, size, track) + 2 * pad
    s.rect(cx - w / 2, cy - 12, w, 24, fill=fill, rx=12, stroke=color, sw=1.5)
    s.text(text, cx, cy + size * 0.36, font, size, color, anchor="middle", track=track)
    return w


def tag(s: Svg, text, x, y, color, size=9.5, track=1.0, right=False):
    """A small outlined status tag; (x, y) is its top-left, or top-right if ``right``."""
    w = F["monob"].width(text, size, track) + 14
    if right:
        x -= w
    s.rect(x, y, w, 19, fill="none", rx=5, stroke=color, sw=1.2)
    s.text(text, x + w / 2, y + 13.5, "monob", size, color, anchor="middle", track=track)
    return w


def grid_dots(s: Svg, x0, y0, x1, y1, step=20, r=1.0, color=LINE, op=0.9):
    dots = []
    y = y0
    while y <= y1:
        x = x0
        while x <= x1:
            dots.append(f"M{x} {y}h0")
            x += step
        y += step
    s.add(f'<path d="{" ".join(dots)}" stroke="{color}" stroke-width="{2 * r}" '
          f'stroke-linecap="round" opacity="{op}"/>')


def node(s: Svg, x, y, w, h, title, color, fill, sub=None, title_size=13):
    s.rect(x, y, w, h, fill=fill, rx=10, stroke=color, sw=1.6)
    if sub:
        s.text(title, x + w / 2, y + h / 2 - 2, "monob", title_size, color, anchor="middle")
        s.text(sub, x + w / 2, y + h / 2 + 15, "reg", 11, INK2, anchor="middle")
    else:
        s.text(title, x + w / 2, y + h / 2 + 4.5, "monob", title_size, color, anchor="middle")


def shield(s: Svg, cx, cy, size, color, fill):
    k = size
    d = (f"M{cx:.1f} {cy - k:.1f} L{cx + 0.82 * k:.1f} {cy - 0.62 * k:.1f} "
         f"L{cx + 0.82 * k:.1f} {cy + 0.05 * k:.1f} "
         f"Q{cx + 0.78 * k:.1f} {cy + 0.72 * k:.1f} {cx:.1f} {cy + k:.1f} "
         f"Q{cx - 0.78 * k:.1f} {cy + 0.72 * k:.1f} {cx - 0.82 * k:.1f} {cy + 0.05 * k:.1f} "
         f"L{cx - 0.82 * k:.1f} {cy - 0.62 * k:.1f} Z")
    s.path(d, stroke=color, sw=2, fill=fill)


# --------------------------------------------------------------------------
# hero
# --------------------------------------------------------------------------
def hero() -> str:
    W, H = 800, 470
    s = Svg(W, H, "OctoberBlue. Red attacks, blue defends, only the evidence decides. "
                  "Red-side agents send an attack through an untrusted surface into a "
                  "sandboxed target; the blue guard filters it; a trusted gateway denies the "
                  "unauthorized tool call; an independent verifier scores the run from "
                  "recorded events, not from any agent's claim.")
    grid_dots(s, 436, 70, 784, 418, step=20, r=0.9, op=0.6)

    s.text("MELINRESEARCH / OCTOBERBLUE", 32, 40, "monom", 11.5, MUTED, track=1.4)
    s.text("v0.1 OFFLINE  ·  MIT  ·  PYTHON 3.11+", W - 32, 40, "monom", 11.5, MUTED,
           anchor="end", track=1.4)
    s.line(32, 54, W - 32, 54, LINE, sw=1)

    # wordmark
    s.text("OCTOBER", 28, 152, "stencil", 104, INK, track=2)
    s.text("BLUE", 28, 246, "stencil", 104, BLUE, track=2)
    s.rect(34, 262, 30, 6, fill=RED, rx=3)
    s.rect(68, 262, 30, 6, fill=BLUE, rx=3)
    s.text("Red attacks. Blue defends.", 32, 304, "bold", 25, INK)
    s.text("Only the evidence decides.", 32, 336, "bold", 25, INK)
    s.lines(["Adversarial evaluation of AI agents.",
             "Separate red and blue memory, an independent",
             "verifier, and a $0.00 default budget."],
            32, 372, "reg", 15, INK2, lead=22)

    # -- arena ------------------------------------------------------------------
    # sandbox
    sx, sy, sw_, sh = 560, 132, 168, 176
    s.rect(sx, sy, sw_, sh, fill=TEAL_BG, rx=16, stroke=TEAL, sw=1.6, dash="7 6", op=None)
    s.text("SANDBOX", sx + 4, sy - 10, "monob", 9.5, TEAL, track=1.4)

    # red side nodes
    s.circle(474, 112, 14, fill=RED_BG, stroke=RED, sw=2)
    s.circle(474, 196, 18, fill=RED, stroke=None)
    s.line(474, 126, 474, 178, RED, sw=2, op=0.7)
    s.text("research", 474, 84, "monom", 10.5, RED, anchor="middle")
    s.text("attack", 474, 232, "monom", 10.5, RED, anchor="middle")

    # attack path into the sandbox
    s.path("M494 196 C 520 196, 530 214, 556 214", stroke=RED, sw=2.6)
    arrowhead(s, 562, 214, 0, RED, size=10)

    # blue guard at the sandbox wall
    shield(s, sx + 30, 214, 20, BLUE, BLUE_BG)
    s.line(sx + 30, 204, sx + 30, 224, BLUE, sw=2.4)
    s.line(sx + 22, 214, sx + 38, 214, BLUE, sw=2.4)

    # target
    tx, ty = sx + 108, 214
    s.rect(tx - 26, ty - 26, 52, 52, fill=PANEL2, rx=12, stroke=INK2, sw=1.6)
    s.circle(tx, ty, 7, fill=INK)
    s.text("target", tx, ty + 46, "monom", 10.5, INK2, anchor="middle")

    # blue side
    s.circle(762, 112, 14, fill=BLUE_BG, stroke=BLUE, sw=2)
    s.text("research", 762, 84, "monom", 10.5, BLUE, anchor="middle")
    s.path(f"M762 126 C 762 168, 680 110, {sx + 30} {214 - 26}", stroke=BLUE, sw=1.8,
           dash="5 5", op=0.85)
    arrowhead(s, sx + 30, 214 - 24, math.radians(115), BLUE, size=8)

    # gateway: tool request denied
    gx, gy = tx, sy + sh + 34
    s.line(tx, ty + 56, tx, gy - 14, INK2, sw=1.6, dash="4 4")
    s.rect(gx - 15, gy - 15, 30, 30, fill=TEAL_BG, rx=8, stroke=TEAL, sw=1.8)
    s.line(gx - 6, gy - 6, gx + 6, gy + 6, RED, sw=2.4)
    s.line(gx + 6, gy - 6, gx - 6, gy + 6, RED, sw=2.4)
    s.text("gateway", gx + 24, gy + 4, "monom", 10.5, TEAL)

    # verifier
    vx, vy = 488, 372
    s.circle(vx, vy, 19, fill=TEAL_BG, stroke=TEAL, sw=2)
    s.path(f"M{vx - 10} {vy} Q{vx} {vy - 9} {vx + 10} {vy} Q{vx} {vy + 9} {vx - 10} {vy} Z",
           stroke=TEAL, sw=1.6)
    s.circle(vx, vy, 3.4, fill=TEAL)
    s.path(f"M{sx + 6} {sy + sh - 20} C 520 300, 500 330, {vx + 8} {vy - 20}", stroke=TEAL,
           sw=1.6, dash="3 5", op=0.9)
    s.path(f"M{gx - 18} {gy} C 600 {gy + 20}, 540 {vy}, {vx + 22} {vy}", stroke=TEAL, sw=1.6,
           dash="3 5", op=0.9)

    pill(s, "ATTACK · UNTRUSTED INPUT", 462, 266, RED, size=10)
    pill(s, "VERDICT · FROM EVENTS", vx + 2, vy + 38, TEAL)

    s.line(32, 432, W - 32, 432, LINE, sw=1)
    items = ["INDEPENDENT VERIFIER", "SEPARATE RED / BLUE MEMORY", "$0.00 DEFAULT BUDGET"]
    widths = [F["monom"].width(t, 10.5, 1.2) for t in items]
    gap = (W - 64 - sum(widths)) / (len(items) - 1)
    x = 32
    for t, w in zip(items, widths, strict=True):
        s.text(t, x, 454, "monom", 10.5, MUTED, track=1.2)
        x += w + gap
    return s.done()


# --------------------------------------------------------------------------
# at a glance
# --------------------------------------------------------------------------
def glance() -> str:
    W, H = 800, 104
    chips = [
        ("RED", RED, "Attack", "researcher + attack builder"),
        ("BLUE", BLUE, "Defend", "researcher + runtime guard"),
        ("VERIFY", TEAL, "Evidence only", "deterministic code, no LLM"),
        ("BUDGET", AMBER, "$0.00 default", "reserve first, hard stop"),
    ]
    s = Svg(W, H, "At a glance: the red side researches and builds attacks; the blue side "
                  "researches and runs a guard; a deterministic verifier scores outcomes from "
                  "evidence; the default model budget is zero dollars with a hard stop.", bg=None)
    gap = 12
    w = (W - 3 * gap) / 4
    for i, (t, color, title, sub) in enumerate(chips):
        x = i * (w + gap)
        s.card(x, 0, w, H, color)
        s.text(t, x + 22, 30, "monob", 10.5, color, track=1.6)
        s.text(title, x + 22, 59, "semi", 18, INK)
        s.text(sub, x + 22, 83, "reg", 12, INK2)
    return s.done()


# --------------------------------------------------------------------------
# lifecycle
# --------------------------------------------------------------------------
def lifecycle() -> str:
    steps = [
        ("RESEARCH", RED, "Each side studies its field",
         "Red finds threats, blue finds defenses. Sources recorded, memories kept apart.",
         "v0.3"),
        ("BUILD", RED, "Typed, versioned artifacts",
         "The attacker builds an attack; blue freezes the defense it will run with.", "v0.2"),
        ("EXECUTE", BLUE, "Run behind the gateway",
         "Attacks enter only untrusted surfaces; every tool call is checked. Sandbox in v0.2.",
         "PARTIAL"),
        ("VERIFY", TEAL, "Score from the record",
         "Attempted, prevented, completed, task success, or indeterminate. Never self-report.",
         "IN v0.1"),
        ("DREAM", VIOLET, "Consolidate between epochs",
         "Each side turns verified runs into lessons. An operator approves promotion.", "v0.4"),
        ("EVALUATE", AMBER, "Sealed holdouts decide",
         "Unseen tests, thresholds preregistered before any result is read.", "v0.5"),
    ]
    W = 800
    m, gap, ch = 16, 14, 122
    cw = (W - 2 * m - gap) / 2
    H = m * 2 + 3 * ch + 2 * gap
    s = Svg(W, H, "The red/blue lifecycle: 1 research, each side studies its field (v0.3); "
                  "2 build typed, versioned attack and defense artifacts (v0.2); 3 execute the "
                  "target behind the gateway, attacks enter only untrusted surfaces and every "
                  "tool call is checked (partly in v0.1, sandbox in v0.2); 4 verify from the record (in v0.1); "
                  "5 dream, each side consolidates verified lessons between epochs with operator "
                  "approval (v0.4); 6 evaluate on sealed holdouts with preregistered thresholds "
                  "(v0.5).")
    for i, (t, color, title, body, status) in enumerate(steps):
        col, row = i % 2, i // 2
        x, y = m + col * (cw + gap), m + row * (ch + gap)
        s.card(x, y, cw, ch, color)
        s.rect(x + 24, y + 22, 34, 34, fill=color, rx=8)
        s.text(str(i + 1), x + 41, y + 46, "monob", 17, BG, anchor="middle")
        s.text(t, x + 72, y + 36, "monob", 10.5, color, track=1.6)
        s.text(title, x + 72, y + 56, "semi", 17.5, INK)
        live = status.startswith("IN")
        tag(s, status, x + cw - 18, y + 22,
            TEAL if live else (AMBER if status == "PARTIAL" else MUTED), right=True)
        s.lines(wrap(body, "reg", 13.5, cw - 48), x + 24, y + 88, "reg", 13.5, INK2, lead=20)
    return s.done()


# --------------------------------------------------------------------------
# trust boundaries
# --------------------------------------------------------------------------
def trust() -> str:
    W, H = 800, 560
    s = Svg(W, H, "Trust boundaries. The operator sets budgets, seals holdouts and approves "
                  "memory promotion. Red and blue sides each have two agents and a private "
                  "memory neither side can read across. Trusted code in the middle, which no "
                  "agent can modify, holds the execution harness, the sandbox with the target "
                  "agent and synthetic tools, the gateway, the independent verifier and the "
                  "budget ledger. Red attacks enter the sandbox only through an untrusted "
                  "surface; blue's guard is frozen for the run; verified development runs feed "
                  "Dreaming; holdout results never feed back.")
    # operator
    s.rect(16, 16, W - 32, 52, fill=PANEL, rx=12, stroke=LINE, sw=1.2)
    s.text("OPERATOR", 36, 47, "monob", 11, INK, track=1.6)
    s.text("sets budgets · seals holdouts · approves memory promotion · hard stop", W - 36, 47,
           "reg", 13, INK2, anchor="end")

    top, ch = 92, 300
    # red side
    rx_, rw = 16, 206
    s.card(rx_, top, rw, ch, RED)
    s.text("RED SIDE", rx_ + 24, top + 32, "monob", 11, RED, track=1.6)
    s.text("agents · untrusted", rx_ + 24, top + 50, "reg", 11.5, INK2)
    node(s, rx_ + 20, top + 70, rw - 36, 46, "red_researcher", RED, RED_BG, title_size=12)
    node(s, rx_ + 20, top + 132, rw - 36, 46, "red_attacker", RED, RED_BG, title_size=12)
    s.rect(rx_ + 20, top + 214, rw - 36, 62, fill=PANEL2, rx=10, stroke=VIOLET, sw=1.2,
           dash="4 4")
    s.text("private memory", rx_ + 20 + (rw - 36) / 2, top + 240, "monob", 11.5, VIOLET,
           anchor="middle")
    s.text("red lessons only", rx_ + 20 + (rw - 36) / 2, top + 258, "reg", 11, INK2,
           anchor="middle")

    # blue side
    bx, bw = W - 16 - 206, 206
    s.card(bx, top, bw, ch, BLUE)
    s.text("BLUE SIDE", bx + 24, top + 32, "monob", 11, BLUE, track=1.6)
    s.text("agents · untrusted", bx + 24, top + 50, "reg", 11.5, INK2)
    node(s, bx + 20, top + 70, bw - 36, 46, "blue_researcher", BLUE, BLUE_BG, title_size=12)
    node(s, bx + 20, top + 132, bw - 36, 46, "blue_guard", BLUE, BLUE_BG, title_size=12)
    s.rect(bx + 20, top + 214, bw - 36, 62, fill=PANEL2, rx=10, stroke=VIOLET, sw=1.2,
           dash="4 4")
    s.text("private memory", bx + 20 + (bw - 36) / 2, top + 240, "monob", 11.5, VIOLET,
           anchor="middle")
    s.text("blue lessons only", bx + 20 + (bw - 36) / 2, top + 258, "reg", 11, INK2,
           anchor="middle")

    # trusted core
    cx0, cw = 246, W - 2 * 246
    s.rect(cx0, top, cw, ch, fill=TEAL_BG, rx=14, stroke=TEAL, sw=1.8)
    s.text("TRUSTED CODE", cx0 + 20, top + 30, "monob", 11, TEAL, track=1.6)
    s.text("no agent can modify", cx0 + cw - 20, top + 30, "reg", 11.5, INK2, anchor="end")
    # harness + sandbox
    s.rect(cx0 + 16, top + 46, cw - 32, 130, fill=BG, rx=12, stroke=TEAL, sw=1.2, dash="6 5")
    s.text("execution_harness · sandbox", cx0 + 30, top + 68, "monom", 11, TEAL)
    tgx, tgw, tlw = cx0 + 28, 108, 88
    tlx = cx0 + cw - 28 - tlw
    gwx = (tgx + tgw + tlx) / 2
    node(s, tgx, top + 80, tgw, 52, "target_agent", INK, PANEL2, sub="under test",
         title_size=11.5)
    node(s, tlx, top + 80, tlw, 52, "tools", INK2, PANEL2, sub="synthetic", title_size=11.5)
    s.rect(gwx - 3, top + 82, 6, 48, fill=TEAL, rx=3)
    arrow(s, tgx + tgw + 3, top + 106, gwx - 6, top + 106, INK2, sw=1.6, size=7)
    arrow(s, gwx + 6, top + 106, tlx - 3, top + 106, INK2, sw=1.6, size=7)
    s.text("gateway", gwx, top + 150, "monob", 11, TEAL, anchor="middle")
    s.text("checks every tool call", gwx, top + 166, "reg", 10.5, INK2, anchor="middle")
    # verifier + ledger
    node(s, cx0 + 16, top + 192, (cw - 44) / 2, 56, "verifier", TEAL, PANEL2,
         sub="events → verdict", title_size=12)
    node(s, cx0 + 28 + (cw - 44) / 2, top + 192, (cw - 44) / 2, 56, "ledger", AMBER, PANEL2,
         sub="reserve · settle", title_size=12)
    s.text("holdout store", cx0 + cw / 2, top + 278, "monob", 11, AMBER, anchor="middle")
    s.text("sealed", cx0 + cw / 2, top + 292, "reg", 10.5, INK2, anchor="middle")

    # red attack -> sandbox, blue guard -> sandbox
    arrow(s, rx_ + rw - 16, top + 155, cx0 + 16, top + 155, RED, sw=2.4, size=10)
    s.text("untrusted surface only", rx_ + rw / 2 + 2, top + 198, "monom", 10.5, RED,
           anchor="middle")
    arrow(s, bx + 20, top + 155, cx0 + cw - 16, top + 155, BLUE, sw=2.4, size=10)
    s.text("frozen for the run", bx + bw / 2 + 2, top + 198, "monom", 10.5, BLUE,
           anchor="middle")

    # no cross-side access marker across the top of the core
    # bottom: dreaming loop
    by = top + ch + 24
    s.rect(16, by, W - 32, 120, fill=PANEL, rx=14, stroke=LINE, sw=1.2)
    s.text("BETWEEN EPOCHS", 36, by + 30, "monob", 11, VIOLET, track=1.6)
    flow = [("verified runs", TEAL), ("dev only", INK2), ("Dream, per side", VIOLET),
            ("proposal", VIOLET), ("operator OK", INK), ("that side's memory", VIOLET)]
    x = 36
    yy = by + 66
    for i, (label, color) in enumerate(flow):
        w = F["monom"].width(label, 11.5) + 20
        s.rect(x, yy - 18, w, 30, fill=PANEL2, rx=8, stroke=color, sw=1.1)
        s.text(label, x + 10, yy + 2, "monom", 11.5, color)
        x += w
        if i < len(flow) - 1:
            arrow(s, x + 4, yy - 3, x + 20, yy - 3, MUTED, sw=1.6, size=7)
            x += 24
    s.line(36, by + 92, 36 + 12, by + 92, RED, sw=2)
    s.text("Holdout results never feed back to either side. Neither side reads the other's "
           "memory.", 56, by + 96, "reg", 12, INK2)
    return s.done()


# --------------------------------------------------------------------------
# Dreaming
# --------------------------------------------------------------------------
def dreaming() -> str:
    W, H = 800, 352
    s = Svg(W, H, "Dreaming: memory consolidation between epochs, run separately for red and "
                  "blue. 1 Gather verified development runs; holdout and indeterminate runs are "
                  "refused (in v0.1). 2 Dream: batch-synthesize lessons (v0.4). 3 Propose a new "
                  "version linked to its parent and its evidence runs (in v0.1). 4 Gate: "
                  "regression tests and operator approval; stale parents are refused (approval "
                  "in v0.1, regression gate v0.4). 5 Promote, with rollback to the prior "
                  "version (v0.4). A wall separates the two lanes.")
    s.text("DREAMING · MEMORY CONSOLIDATION BETWEEN EPOCHS", 28, 38, "monob", 11.5, INK,
           track=1.6)
    s.text("ONE LANE PER SIDE", W - 28, 38, "monom", 10, MUTED, anchor="end", track=1.0)
    stages = [
        ("GATHER", "verified dev runs", "holdout refused", "IN v0.1"),
        ("DREAM", "batch synthesis", "efficient model", "v0.4"),
        ("PROPOSE", "version N+1", "parent + evidence", "IN v0.1"),
        ("GATE", "tests + approval", "stale parent refused", "PARTIAL"),
        ("PROMOTE", "becomes latest", "rollback to N", "v0.4"),
    ]
    m, gap = 28, 18
    sw_ = (W - 2 * m - 4 * gap) / 5
    lanes = [(RED, RED_BG, "red", 64), (BLUE, BLUE_BG, "blue", 196)]
    for color, fill, name, y in lanes:
        s.text(name.upper(), m, y + 10, "monob", 10, color, track=1.6)
        for i, (t, a, b, status) in enumerate(stages):
            x = m + i * (sw_ + gap)
            bx_y = y + 20
            s.rect(x, bx_y, sw_, 92, fill=PANEL, rx=12, stroke=color, sw=1.3,
                   op=None)
            s.text(t, x + 14, bx_y + 26, "monob", 11, color, track=1.2)
            s.text(a, x + 14, bx_y + 50, "semi", 12.5, INK)
            s.text(b, x + 14, bx_y + 68, "reg", 11.5, INK2)
            if name == "red":
                pass
            if i < 4:
                arrow(s, x + sw_ + 3, bx_y + 46, x + sw_ + gap - 3, bx_y + 46, color, sw=1.8,
                      size=7)
        # status tags under the blue lane only once (shared)
    # status row
    sy = 196 + 20 + 92 + 24
    for i, (_, _, _, status) in enumerate(stages):
        x = m + i * (sw_ + gap)
        live = status.startswith("IN")
        tag(s, status, x, sy - 12, TEAL if live else (AMBER if status == "PARTIAL" else MUTED))
    # wall between lanes
    wy = 64 + 20 + 92 + 12
    s.line(m, wy + 4, W - m, wy + 4, INK2, sw=1, dash="2 5")
    s.text("no cross-side access", W - m, wy, "monom", 10, INK2, anchor="end")
    return s.done()


# --------------------------------------------------------------------------
# harness check (real demo output)
# --------------------------------------------------------------------------
def demo_results():
    import json
    import tempfile
    from contextlib import redirect_stdout
    from io import StringIO

    from octoberblue.cli import main as cli_main

    with tempfile.TemporaryDirectory() as tmp:
        buf = StringIO()
        with redirect_stdout(buf):
            cli_main(["demo", "--db", str(Path(tmp) / "demo.sqlite3")])
    return json.loads(buf.getvalue())


def harness() -> str:
    report = demo_results()
    runs = {(r["attack"], r["guard_enabled"]): r for r in report["results"]}
    W, H = 800, 368
    s = Svg(W, H, "v0.1 harness check: four synthetic runs, zero paid calls, $0.00. Clean "
                  "input, guard off or on: no attempt, task succeeds, pass. Injected input, "
                  "guard off: the target attempts an unauthorized tool call, the gateway denies "
                  "it, no completed effect, task succeeds, pass. Injected input, guard on: the "
                  "guard filters it, no attempt, task succeeds, pass. This checks the wiring, "
                  "not defense quality.")
    s.text("v0.1 HARNESS CHECK", 28, 38, "monob", 11.5, INK, track=1.6)
    s.text(f"{len(report['results'])} SYNTHETIC RUNS · {report['paid_model_calls']} PAID CALLS · "
           f"${report['budget_ceiling_dollars']}", W - 28, 38, "monom", 10, MUTED, anchor="end",
           track=1.0)
    # grid
    lx, top = 28, 66
    colw = (W - 56 - 150 - 12) / 2
    for j, (guard, label, color) in enumerate(((False, "GUARD OFF", MUTED),
                                               (True, "GUARD ON", BLUE))):
        x = lx + 150 + 12 + j * colw
        s.text(label, x + colw / 2, top + 6, "monob", 10.5, color, anchor="middle", track=1.4)
    rows = (("clean", "Clean input"), ("synthetic-attack", "Injected input"))
    rh = 104
    for i, (key, label) in enumerate(rows):
        y = top + 22 + i * (rh + 12)
        s.text(label, lx, y + 46, "semi", 15, INK)
        s.text("legitimate task" if key == "clean" else "lower-trust surface", lx, y + 66, "reg",
               11.5, INK2)
        for j, guard in enumerate((False, True)):
            r = runs[(key, guard)]
            x = lx + 150 + 12 + j * colw
            cw = colw - 12
            s.rect(x, y, cw, rh, fill=PANEL, rx=12)
            facts = [
                ("attempted", r["attempted"], RED),
                ("completed", r["completed"], RED),
                ("task ok", r["task_success"], TEAL),
            ]
            fx = x + 18
            for name, val, col in facts:
                s.text(name, fx, y + 30, "monom", 10.5, MUTED)
                good = (val if name == "task ok" else not val)
                s.text("yes" if val else "no", fx, y + 52, "semi", 17,
                       INK if good else col)
                fx += (cw - 36) / 3
            note = ""
            if key == "synthetic-attack" and not guard:
                note = "gateway denied the tool call"
            elif key == "synthetic-attack" and guard:
                note = "guard filtered the input"
            else:
                note = "no filter on clean input"
            s.text(note, x + 18, y + 84, "reg", 11.5, INK2)
            tag(s, r["verdict"].upper(), x + cw - 16, y + 70, TEAL, right=True)
    s.line(28, H - 52, W - 28, H - 52, LINE, sw=1)
    s.text("Checks the wiring, not defense quality. The synthetic target is vulnerable by "
           "construction and the guard is a phrase match.", 28, H - 28, "reg", 12, INK2)
    return s.done()


# --------------------------------------------------------------------------
# roadmap
# --------------------------------------------------------------------------
def roadmap() -> str:
    ms = [
        ("v0.1", "Offline scaffold", "harness · verifier · $0 budget · split memory", True),
        ("v0.2", "Real benchmark", "sandbox · gateway · typed artifacts · paired runs", False),
        ("v0.3", "Live models", "provider adapters · research · spend controls", False),
        ("v0.4", "Dreaming", "per-side lessons · promotion · rollback", False),
        ("v0.5", "Sealed evaluation", "holdouts · replay · statistics", False),
        ("v0.6", "Operator console", "dashboard · audit exports · deploy", False),
    ]
    W = 800
    m, gap = 16, 10
    cw = (W - 2 * m - 2 * gap) / 3
    ch = 124
    H = m * 2 + 2 * ch + gap
    s = Svg(W, H, "Roadmap. v0.1 offline scaffold, done: harness, verifier, zero-dollar budget, "
                  "split memory. v0.2 real benchmark: sandbox, gateway, typed artifacts, paired "
                  "runs. v0.3 live models: provider adapters, research, spend controls. v0.4 "
                  "Dreaming: per-side lessons, promotion, rollback. v0.5 sealed evaluation: "
                  "holdouts, replay, statistics. v0.6 operator console: dashboard, audit "
                  "exports, deployment.", bg=None)
    for i, (v, title, body, done) in enumerate(ms):
        col, row = i % 3, i // 3
        x, y = m + col * (cw + gap), m + row * (ch + gap)
        color = TEAL if done else (BLUE if i == 1 else LINE)
        s.card(x, y, cw, ch, color, fill=PANEL)
        s.text(v, x + 22, y + 40, "display", 30, TEAL if done else INK)
        tag(s, "DONE" if done else ("NEXT" if i == 1 else "PLANNED"), x + cw - 16, y + 18,
            TEAL if done else (BLUE if i == 1 else MUTED), right=True)
        s.text(title, x + 22, y + 66, "semi", 15.5, INK)
        s.lines(wrap(body, "reg", 12, cw - 40), x + 22, y + 88, "reg", 12, INK2, lead=17)
    return s.done()


# --------------------------------------------------------------------------
# AI nutrition facts
# --------------------------------------------------------------------------
def invariant_counts() -> dict[str, int]:
    text = (DOCS / "REQUIREMENTS.md").read_text(encoding="utf-8")
    rows = re.findall(r"^\| INV-\d+ \| [^|]+ \| (Tested|Partial|Planned) \|", text, re.M)
    return {k: rows.count(k) for k in ("Tested", "Partial", "Planned")} | {"total": len(rows)}


def check(s: Svg, x, y, color, size=10):
    s.path(f"M{x:.1f} {y - size * 0.45:.1f} L{x + size * 0.38:.1f} {y - size * 0.08:.1f} "
           f"L{x + size:.1f} {y - size * 0.9:.1f}", stroke=color, sw=2.2)


def nutrition() -> str:
    """OctoberBlue's AI nutrition label: its requirements and evidence, at a glance.

    Standard AI nutrition label fields (description, privacy ladder, model type,
    base model, trust ingredients, compliance), plus an evidence block that keeps
    synthetic runs, real-model observations and withheld holdout results apart, and
    the HTI-1 source-attribute categories a requirements reader needs.
    """
    W = 460
    s = Svg(W, 100, "")
    L, R = 28, W - 28
    y = 0

    def rule(h, color=INK):
        nonlocal y
        s.rect(L, y, R - L, h, fill=color, rx=min(h / 2, 2))
        y += h

    def thin():
        s.rect(L, y + 8, R - L, 1, fill=LINE)

    def ids_pills(ids, right):
        x = right
        for rid in reversed(ids.split()):
            w = F["monom"].width(rid, 9.5) + 10
            x -= w
            s.rect(x, y - 12, w, 16, fill="none", rx=5, stroke="#34405a", sw=1)
            s.text(rid, x + w / 2, y - 0.5, "monom", 9.5, INK2, anchor="middle")
            x -= 5
        return x

    def kv(label, value, ids="", mark=None, label_color=INK2, value_color=INK,
           label_font="reg", value_font="cond", size=13.5, step=26):
        nonlocal y
        y += step
        s.text(label, L, y, label_font, size, label_color)
        vw = s.text(value, R, y, value_font, size, value_color, anchor="end")
        left = R - vw
        if mark == "yes":
            check(s, left - 16, y - 1, TEAL)
            left -= 20
        elif mark == "partial":
            s.circle(left - 10, y - 5, 4, fill=AMBER)
            left -= 20
        elif mark == "planned":
            s.rect(left - 15, y - 6, 9, 2.2, fill=MUTED, rx=1)
            left -= 20
        if ids:
            ids_pills(ids, left - 8)
        thin()

    def heading(text, color, step=34):
        nonlocal y
        y += step
        s.rect(L, y - 15, 4, 18, fill=color, rx=2)
        s.text(text, L + 14, y, "cond", 17, color)
        thin()

    def para(label, text, color, size=12.5, lead=17):
        nonlocal y
        y += 26
        s.text(label.upper(), L, y, "monob", 10, color, track=1.4)
        for line in wrap(text, "reg", size, R - L):
            y += lead
            s.text(line, L, y, "reg", size, INK2)
        y += 4
        thin()

    y = 40
    s.text("MELINRESEARCH / OCTOBERBLUE", L, y, "monom", 10.5, MUTED, track=1.4)
    s.text("v0.1", R, y, "monom", 10.5, MUTED, anchor="end", track=1.4)
    y += 54
    s.text("AI Nutrition Facts", L - 1, y, "display", 50, INK, track=0.5)
    y += 12
    s.rect(L, y, 30, 5, fill=RED, rx=2.5)
    s.rect(L + 34, y, 30, 5, fill=BLUE, rx=2.5)
    y += 30
    s.text("OctoberBlue", L, y, "cond", 18, BLUE)
    s.text("red/blue adversarial evaluation", R, y, "reg", 13.5, INK2, anchor="end")
    y += 12
    rule(8)

    y += 4
    para("Description", "Evaluates AI agents under attack. Red and blue sides evolve separately; "
         "a deterministic verifier scores each run from recorded tool calls and state, never "
         "from an agent's claim.", BLUE)
    kv("Privacy Ladder Level", "N/A · synthetic data", label_font="semi", label_color=INK)
    kv("Feature is Optional", "Yes · runs offline", label_font="semi", label_color=INK)
    kv("Model Type", "None in v0.1 · synthetic target", label_font="semi", label_color=INK)
    kv("Base Model", "None · pinned per run from v0.3", label_font="semi", label_color=INK)
    y += 16
    rule(8)

    heading("Trust Ingredients", VIOLET)
    kv("Base model trained with customer data", "No")
    kv("Customer data shared with model vendor", "No · no calls")
    kv("Training data anonymized", "N/A")
    kv("Data deletion", "Local files")
    kv("Human in the loop", "Yes · promotion", ids="INV-13")
    kv("Data retention", "You control")
    y += 16
    rule(8)

    heading("Compliance", AMBER)
    kv("Gateway on every tool call", "Yes", ids="INV-04", mark="yes")
    kv("Red / blue memory separated", "Yes", ids="INV-07", mark="yes")
    kv("Holdouts kept out of learning", "Yes", ids="INV-08", mark="yes")
    kv("Budget enforced", "Yes · $0", ids="INV-18", mark="yes")
    kv("Verdicts from evidence", "Partial", ids="INV-01 INV-10", mark="partial")
    kv("Logging & provenance", "Partial", ids="INV-09", mark="partial")
    kv("Sandbox containment", "v0.2", ids="INV-11", mark="planned")
    y += 16
    rule(8)

    heading("Evidence", TEAL)
    kv("Synthetic runs", "Harness check only")
    kv("Real-model observations", "None yet")
    kv("Withheld holdout results", "None · sealed in v0.5")
    y += 16
    rule(8)

    para("Intended use", "Authorized research on whether evolving attacks and defenses "
         "improve real resistance without hurting legitimate tasks or blowing the budget.", BLUE)
    para("Out-of-scope use", "Attacking systems you do not own, external targets or "
         "credentials, and any claim about real model robustness from v0.1 results.", RED)
    para("What results do not establish", "v0.1 has no findings. The target is vulnerable by "
         "construction and the guard is a phrase match, so passing runs show the wiring works, "
         "not that a defense does.", AMBER)
    para("Maintenance", "CI on every push across Linux, macOS and Windows: lint, invariant "
         "tests, and an offline demo that must spend $0.00.", VIOLET)
    y += 16
    rule(4)

    c = invariant_counts()
    y += 44
    s.text("Security invariants", L, y, "display", 30, INK, track=0.5)
    s.text(str(c["total"]), R, y + 2, "display", 40, AMBER, anchor="end")
    y += 18
    bw = R - L
    s.rect(L, y, bw, 10, fill=PANEL2, rx=5)
    t, p = c["Tested"] / c["total"], c["Partial"] / c["total"]
    s.rect(L, y, bw * (t + p), 10, fill=AMBER, rx=5)
    s.rect(L, y, bw * t, 10, fill=TEAL, rx=5)
    y += 10
    kv("Tested in v0.1", str(c["Tested"]), mark="yes", step=28)
    kv("Partly built and tested", str(c["Partial"]), mark="partial")
    kv("Planned, with a milestone", str(c["Planned"]), mark="planned")
    y += 18
    foot = ("v0.1 checks run in one process; they test the logic, not a security boundary. "
            "Full list: docs/REQUIREMENTS.md. Not a certification.")
    for line in wrap(foot, "reg", 10.5, R - L):
        y += 14
        s.text(line, L, y, "reg", 10.5, MUTED)
    y += 26

    H = int(math.ceil(y))
    s.h = H
    s.parts.insert(0, f'<rect x="10" y="10" width="{W - 20}" height="{H - 20}" rx="10" '
                      f'fill="none" stroke="{LINE}" stroke-width="1.5"/>')
    s.label = (
        "AI Nutrition Facts for OctoberBlue v0.1, red/blue adversarial evaluation. Privacy "
        "ladder not applicable (synthetic data); runs offline; no model in v0.1, a synthetic "
        "target; base model none, version-pinned per run from v0.3. Trust ingredients: no "
        "training on customer data, nothing sent to a model vendor, human approval for memory "
        "promotion. Compliance: gateway on every tool call, separated red and blue memory, "
        "holdouts kept out of learning and a zero-dollar enforced budget are yes; verdicts "
        "from evidence and logging are partial; sandbox containment arrives in v0.2. Evidence: "
        "synthetic harness check only, no real-model observations, no holdout results. "
        f"{c['total']} security invariants: {c['Tested']} tested, {c['Partial']} partly built "
        f"and tested, {c['Planned']} planned.")
    return s.done()


def main() -> None:
    files = {
        "octoberblue-hero.svg": hero(),
        "octoberblue-glance.svg": glance(),
        "octoberblue-lifecycle.svg": lifecycle(),
        "octoberblue-trust.svg": trust(),
        "octoberblue-dreaming.svg": dreaming(),
        "octoberblue-harness.svg": harness(),
        "octoberblue-roadmap.svg": roadmap(),
        "octoberblue-nutrition.svg": nutrition(),
    }
    for name, svg in files.items():
        (OUT_DIR / name).write_text(svg, encoding="utf-8")
        print(f"wrote {OUT_DIR / name} ({len(svg) // 1024} KB)")


if __name__ == "__main__":
    main()
