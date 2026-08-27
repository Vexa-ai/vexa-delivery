#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate the station-anatomy diagram (light + dark SVG).

Channel -> station machinery -> Vexa, inside the customer's boundary.
Edit here, run, commit the SVGs:
    python3 docs/images/generate-station-anatomy.py
"""
import pathlib

OUT = pathlib.Path(__file__).resolve().parent

L = dict(zone="#f6f8fb", zlab="#64748b", violet="#7c3aed", violetT="#6d28d9",
         cardF="#ffffff", cardB="#cbd5e1", cardBl="#ddd6fe",
         chipF="#f8fafc", chipB="#e2e8f0", text="#0f172a", muted="#64748b",
         faint="#94a3b8", arrow="#7c3aed", arrow2="#334155",
         bandL="#f5f3ff", bandLb="#ddd6fe", shadow="rgba(15,23,42,0.06)")

D = dict(zone="#131720", zlab="#7a8698", violet="#a78bfa", violetT="#c4b5fd",
         cardF="#161a24", cardB="#334155", cardBl="#3f3663",
         chipF="#1a1f2b", chipB="#2b3446", text="#e5e7eb", muted="#94a3b8",
         faint="#64748b", arrow="#a78bfa", arrow2="#94a3b8",
         bandL="#221b3a", bandLb="#3f3663", shadow="rgba(0,0,0,0.35)")

FONT = "Inter, -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif"
W, H = 860, 380


def chips(x, y, items, P, gap=8):
    out, cx = [], x
    for t in items:
        w = len(t) * 10.5 * 0.54 + 20
        out.append(f'<rect x="{cx:.0f}" y="{y}" width="{w:.0f}" height="22" rx="11" '
                   f'fill="{P["chipF"]}" stroke="{P["chipB"]}"/>'
                   f'<text x="{cx + w/2:.0f}" y="{y+15}" font-size="10.5" text-anchor="middle" '
                   f'fill="{P["muted"]}">{t}</text>')
        cx += w + gap
    return "".join(out)


def render(P):
    s = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" '
         f'font-family="{FONT}">']
    # ---- left: the channel (outside their boundary)
    s.append(f'<rect x="24" y="60" width="200" height="220" rx="14" fill="{P["bandL"]}" '
             f'stroke="{P["bandLb"]}"/>')
    s.append(f'<text x="124" y="92" text-anchor="middle" font-size="15" font-weight="700" '
             f'fill="{P["violetT"]}">Vexa channel</text>')
    s.append(f'<text x="124" y="112" text-anchor="middle" font-size="11" fill="{P["muted"]}">private, signed</text>')
    for i, row in enumerate(["releases — frozen digests", "evidence + attestations", "station bundle (machinery)"]):
        y = 146 + i * 36
        s.append(f'<rect x="40" y="{y}" width="168" height="26" rx="8" fill="{P["cardF"]}" stroke="{P["cardBl"]}"/>')
        s.append(f'<text x="124" y="{y+17}" text-anchor="middle" font-size="10.5" fill="{P["text"]}">{row}</text>')

    # ---- right: their boundary
    s.append(f'<rect x="292" y="28" width="544" height="326" rx="16" fill="{P["zone"]}" '
             f'stroke="{P["faint"]}" stroke-dasharray="7 5"/>')
    s.append(f'<text x="564" y="54" text-anchor="middle" font-size="12" font-weight="600" '
             f'letter-spacing="1.5" fill="{P["zlab"]}">YOUR CLUSTER · YOUR NAMESPACE</text>')

    # station machinery card
    s.append(f'<rect x="320" y="76" width="488" height="112" rx="12" fill="{P["cardF"]}" '
             f'stroke="{P["cardBl"]}" stroke-width="1.5"/>')
    s.append(f'<text x="336" y="102" font-size="14" font-weight="700" fill="{P["text"]}">Station machinery</text>')
    s.append(f'<text x="336" y="120" font-size="11" fill="{P["muted"]}">receives Vexa — installed once by your bootstrap commit</text>')
    s.append(chips(336, 136, ["subscription", "your contract", "admission", "floor check"], P))

    # vexa card
    s.append(f'<rect x="320" y="238" width="488" height="92" rx="12" fill="{P["cardF"]}" '
             f'stroke="{P["cardB"]}" stroke-width="1.5"/>')
    s.append(f'<text x="336" y="264" font-size="14" font-weight="700" fill="{P["text"]}">Vexa</text>')
    s.append(f'<text x="336" y="282" font-size="11" fill="{P["muted"]}">running release — byte-identical to what the evidence describes</text>')
    s.append(chips(336, 296, ["gateway", "APIs", "dashboard", "meeting bots"], P))

    # ---- arrow 1: channel -> machinery (pull)
    s.append(f'<path d="M224,132 C262,132 268,132 306,132" fill="none" stroke="{P["arrow"]}" '
             f'stroke-width="2.2" marker-end="url(#a1)"/>')
    s.append(f'<text x="265" y="118" text-anchor="middle" font-size="10.5" font-weight="600" '
             f'fill="{P["violetT"]}">pulls</text>')
    s.append(f'<text x="428" y="212" font-size="11" fill="{P["muted"]}">'
             f'only what passes <tspan font-weight="600" fill="{P["violetT"]}">your contract</tspan>'
             f' — verified here, rolled out automatically</text>')

    # ---- arrow 2: machinery -> vexa
    s.append(f'<path d="M396,188 L396,224" fill="none" stroke="{P["arrow2"]}" stroke-width="2.2" '
             f'marker-end="url(#a2)"/>')

    # markers
    s.append(f'<defs>'
             f'<marker id="a1" markerWidth="9" markerHeight="9" refX="7" refY="4.5" orient="auto">'
             f'<path d="M0,0 L8,4.5 L0,9 z" fill="{P["arrow"]}"/></marker>'
             f'<marker id="a2" markerWidth="9" markerHeight="9" refX="7" refY="4.5" orient="auto">'
             f'<path d="M0,0 L8,4.5 L0,9 z" fill="{P["arrow2"]}"/></marker>'
             f'</defs>')
    s.append('</svg>')
    return "".join(s)


for name, P in (("station-anatomy-light.svg", L), ("station-anatomy-dark.svg", D)):
    (OUT / name).write_text(render(P))
    print("wrote", name)
