"""Turn demo_capture.json into docs/demo.svg: two terminals side by side,
each line appearing in the order it was printed, slowed to reading speed.

Standard library only. The SVG has no script and no external file, so it
plays in a GitHub README (as an <img>) and on the site under its CSP. The
text is exactly what the agent printed; only the timing is changed.
"""

import json
import os
import sys
from html import escape

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "demo.svg")

W = 1200
PAD = 24
GAP = 16
PANEL_W = (W - 2 * PAD - GAP) // 2
HEAD_H = 44
FONT = 13
LINE_H = 21
WRAP = 64          # characters per line, with room to spare for wider fonts
INDENT = 10        # the agent's output puts every label in a 10-character column
CYCLE = 15.0       # seconds before the clip starts again
START = 0.9        # pause before the first line

BG = "#0e1216"
TERM = "#151b22"
FG = "#d8dee5"
DIM = "#8995a2"
RED = "#ff8a80"
GREEN = "#7fdcaa"
AMBER = "#ffd27a"
NOTE_BG = "rgba(242,176,30,0.16)"


def wrap(text):
    """Split one printed line into rows of at most WRAP characters, breaking
    at spaces and indenting the continuation rows under the label column."""
    # The label ("AGENT     ") is padded with spaces, so split after it.
    label, rest = text[:INDENT], text[INDENT:]
    words = rest.split(" ")
    rows, current = [], label + words[0]
    for word in words[1:]:
        if len(current) + 1 + len(word) <= WRAP:
            current += " " + word
        else:
            rows.append(current)
            current = " " * INDENT + word
    rows.append(current)
    return rows


def kind(text):
    body = text[INDENT:] if len(text) > INDENT else ""
    if body.startswith("[razorwire]"):
        return "note"
    if text.startswith("DATABASE") and "DELETED" in text:
        return "bad"
    if text.startswith("RESULT"):
        return "good" if "still there" in text else "bad"
    return "plain"


def timeline(lines):
    """Display times: the real order and grouping, slowed to reading speed.
    Lines printed together appear 0.35 s apart; new turns at least 0.9 s."""
    start = lines[0]["t"]
    shown, prev_real, prev_shown = [], None, START
    for i, line in enumerate(lines):
        real = line["t"] - start
        if i == 0:
            at = START
        elif abs(real - prev_real) < 0.05:
            at = prev_shown + 0.35
        else:
            at = max(prev_shown + 0.9, START + real * 1.6)
        shown.append(at)
        prev_real, prev_shown = real, at
    return shown


def panel(x, title, verdict, verdict_ok, lines, ids):
    parts = []
    y0 = PAD
    rows = []
    for line, at in zip(lines, timeline(lines)):
        text = line["text"]
        if not text.strip():
            rows.append(("blank", [""], at))
            continue
        rows.append((kind(text), wrap(text), at))
    height = HEAD_H + 16 + sum(len(r[1]) for r in rows) * LINE_H + 18
    parts.append(f'<rect x="{x}" y="{y0}" width="{PANEL_W}" height="{height}" rx="10" fill="{TERM}"/>')
    parts.append(f'<line x1="{x}" y1="{y0 + HEAD_H}" x2="{x + PANEL_W}" y2="{y0 + HEAD_H}" '
                 f'stroke="#ffffff" stroke-opacity="0.08"/>')
    parts.append(f'<text x="{x + 16}" y="{y0 + 27}" class="label">{escape(title)}</text>')
    last = max(r[2] for r in rows) + 0.6
    badge_w = 8 + len(verdict) * 8
    color = GREEN if verdict_ok else RED
    fill = "rgba(85,197,143,0.16)" if verdict_ok else "rgba(255,116,104,0.16)"
    vid = next(ids)
    parts.append(f'<g class="l" style="animation-name:{vid}">'
                 f'<rect x="{x + PANEL_W - 16 - badge_w}" y="{y0 + 12}" width="{badge_w}" height="22" '
                 f'rx="4" fill="{fill}"/>'
                 f'<text x="{x + PANEL_W - 16 - badge_w / 2}" y="{y0 + 27}" class="badge" '
                 f'fill="{color}" text-anchor="middle">{escape(verdict)}</text></g>')
    keyframes = [(vid, last)]
    y = y0 + HEAD_H + 16 + 14
    for k, wrapped, at in rows:
        lid = next(ids)
        keyframes.append((lid, at))
        group = [f'<g class="l" style="animation-name:{lid}">']
        if k == "note":
            group.append(f'<rect x="{x + 10}" y="{y - 15}" width="{PANEL_W - 20}" '
                         f'height="{len(wrapped) * LINE_H + 4}" rx="4" fill="{NOTE_BG}"/>')
        for i, row in enumerate(wrapped):
            label, rest = (row[:INDENT], row[INDENT:]) if i == 0 else ("", row)
            color = {"note": AMBER, "bad": RED, "good": GREEN}.get(k, FG)
            spans = ""
            if label.strip():
                spans += f'<tspan fill="{DIM}">{escape(label)}</tspan>'
            else:
                rest = label + rest
            spans += f'<tspan fill="{color}">{escape(rest)}</tspan>'
            group.append(f'<text x="{x + 16}" y="{y + i * LINE_H}" class="t" '
                         f'xml:space="preserve">{spans}</text>')
        group.append("</g>")
        parts.append("".join(group))
        y += len(wrapped) * LINE_H
    return parts, height, keyframes


def main():
    with open(os.path.join(HERE, "demo_capture.json"), encoding="utf-8") as f:
        capture = json.load(f)
    counter = iter(f"k{i}" for i in range(1000))
    left, h1, k1 = panel(PAD, "WITHOUT RAZORWIRE", "PRODUCTION LOST", False,
                         capture["off"]["lines"], counter)
    right, h2, k2 = panel(PAD + PANEL_W + GAP, "WITH RAZORWIRE", "PRODUCTION SAFE", True,
                          capture["on"]["lines"], counter)
    body_h = max(h1, h2)
    # Both terminals the height of the taller one.
    for parts, x in ((left, PAD), (right, PAD + PANEL_W + GAP)):
        parts[0] = (f'<rect x="{x}" y="{PAD}" width="{PANEL_W}" height="{body_h}" rx="10" '
                    f'fill="{TERM}"/>')
    H = PAD + body_h + 46
    caption = ("Real output: the same agent and prompt, gpt-oss-120b on Groq. "
               "The only difference is one rule. Slowed down to reading speed.")
    css = [
        f".t{{font:{FONT}px ui-monospace,SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace}}",
        ".label{font:600 11px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;"
        f"letter-spacing:.12em;fill:{DIM}}}",
        ".badge{font:700 11px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;letter-spacing:.1em}",
        f".cap{{font:13px -apple-system,'Segoe UI',system-ui,sans-serif;fill:{DIM}}}",
        f".l{{opacity:0;animation-duration:{CYCLE}s;animation-iteration-count:infinite;"
        "animation-timing-function:linear}",
        "@media (prefers-reduced-motion:reduce){.l{animation:none;opacity:1}}",
    ]
    for name, at in k1 + k2:
        p = at / CYCLE * 100
        q = min(p + 1.2, 95)
        css.append(f"@keyframes {name}{{0%,{p:.2f}%{{opacity:0}}{q:.2f}%,96%{{opacity:1}}100%{{opacity:0}}}}")
    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" '
        'role="img" aria-label="Two terminals. Without Razorwire, an AI agent told to free disk space drops '
        'the staging and the production database. With Razorwire, staging is dropped but the call to drop '
        'production is blocked by a policy rule, and production is still there.">',
        "<title>Razorwire: an agent told to drop two databases, without and with the firewall</title>",
        f"<style>{''.join(css)}</style>",
        f'<rect width="{W}" height="{H}" rx="14" fill="{BG}"/>',
        *left,
        *right,
        f'<text x="{PAD}" y="{H - 18}" class="cap">{escape(caption)}</text>',
        "</svg>",
    ]
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(svg) + "\n")
    print(f"wrote {OUT}: {W}x{H}, {os.path.getsize(OUT)} bytes, cycle {CYCLE}s,"
          f" last line at {max(t for _, t in k1 + k2):.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
