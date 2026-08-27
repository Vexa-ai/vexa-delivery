#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate the "How a release reaches you" diagram (light + dark SVG).

The single source of the docs diagram - edit here, run, commit the SVGs:
    python3 docs/customer/images/generate-release-flow.py
"""
import pathlib

OUT = pathlib.Path(__file__).resolve().parent

L = dict(zoneL="#faf8ff", zoneR="#f6f8fb", zlabL="#a5a0c8", zlabR="#64748b",
         bandL="#f5f3ff", bandLb="#ddd6fe", bandR="#f8fafc", bandRb="#cbd5e1",
         violet="#7c3aed", violetT="#6d28d9", note="#8b87a8", rnote="#64748b",
         spine="#a78bfa", vertL="#c4b5fd", vertR="#94a3b8",
         chipF="#ffffff", chipB="#e2e8f0", chipBr="#cbd5e1", text="#0f172a", muted="#94a3b8",
         okF="#ecfdf5", okB="#a7f3d0", okT="#047857",
         pinF="#f5f3ff", pinB="#ddd6fe",
         pill="#334155", dash="#94a3b8",
         cardF="#ffffff", cardBl="#ddd6fe", cardBr="#cbd5e1", subL="#8b5cf6", subR="#64748b",
         shadow="rgba(15,23,42,0.06)", white="#ffffff")

D = dict(zoneL="#17151f", zoneR="#131720", zlabL="#6f6a92", zlabR="#7a8698",
         bandL="#221b3a", bandLb="#3f3663", bandR="#151a22", bandRb="#334155",
         violet="#a78bfa", violetT="#c4b5fd", note="#7d7897", rnote="#94a3b8",
         spine="#8b7cf0", vertL="#7d6fd0", vertR="#64748b",
         chipF="#1a1f2b", chipB="#2b3446", chipBr="#3a4456", text="#e5e7eb", muted="#8b93a3",
         okF="#06281e", okB="#0d4a36", okT="#34d399",
         pinF="#241d3d", pinB="#3f3663",
         pill="#cbd5e1", dash="#64748b",
         cardF="#161a24", cardBl="#3f3663", cardBr="#334155", subL="#a78bfa", subR="#94a3b8",
         shadow="rgba(0,0,0,0.35)", white="#1a1f2b")

FONT = "Inter, -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif"


def tw(s, fs):
    return len(s) * fs * 0.54


def badge(cx_cursor, y, text, kind, P):
    w = 9 + 4 + tw(text, 10.5) + 16
    fill, border, color = (P["okF"], P["okB"], P["okT"]) if kind == "ok" else (P["pinF"], P["pinB"], P["violetT"])
    weight = "400" if kind == "ok" else "600"
    x = cx_cursor
    icon_x = x + 8
    if kind == "ok":
        icon = f'<path d="M{icon_x+1:.0f},{y+9:.0f} l3,3 l5.5,-6.5" fill="none" stroke="{P["okT"]}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>'
    else:
        icon = (f'<g transform="translate({icon_x},{y+3.5})" fill="none" stroke="{P["violetT"]}" stroke-width="1.3">'
                f'<path d="M5 10.5 s3.4-3.7 3.4-6.1 a3.4 3.4 0 1 0 -6.8 0 c0 2.4 3.4 6.1 3.4 6.1z"/><circle cx="5" cy="4.2" r="1.1"/></g>')
    s = (f'<rect x="{x:.0f}" y="{y:.0f}" width="{w:.0f}" height="18" rx="9" fill="{fill}" stroke="{border}"/>'
         f'{icon}<text x="{x+9+7:.0f}" y="{y+13:.0f}" font-size="10.5" font-weight="{weight}" fill="{color}">{text}</text>')
    return s, w


def chip(cx, tag, badges, P, border=None):
    parts = []
    if badges:
        bw = sum(9 + 4 + tw(t, 10.5) + 16 for t, _ in badges) + 5 * (len(badges) - 1)
    else:
        bw = tw("no signatures yet", 10.5)
    w = max(bw, tw(tag, 11)) + 26
    x = cx - w / 2
    parts.append(f'<rect x="{x:.0f}" y="142" width="{w:.0f}" height="52" rx="10" fill="{P["chipF"]}" stroke="{border or P["chipB"]}"/>')
    parts.append(f'<text x="{cx:.0f}" y="160" text-anchor="middle" font-size="11" font-weight="600" fill="{P["text"]}">{tag}</text>')
    if badges:
        cur = cx - bw / 2
        for t, kind in badges:
            s, w2 = badge(cur, 168, t, kind, P)
            parts.append(s)
            cur += w2 + 5
    else:
        parts.append(f'<text x="{cx:.0f}" y="181" text-anchor="middle" font-size="10.5" fill="{P["muted"]}">no signatures yet</text>')
    return "".join(parts)


def pillbox(cx, y, text, P, fs=12, border=None, color=None, weight="400", h=26, icon=False):
    w = tw(text, fs) + 28 + (15 if icon else 0)
    x = cx - w / 2
    s = f'<rect x="{x:.0f}" y="{y}" width="{w:.0f}" height="{h}" rx="{h/2:.0f}" fill="{P["chipF"]}" stroke="{border or P["chipB"]}" stroke-width="{1.5 if border else 1}"/>'
    tx = cx + (7 if icon else 0)
    if icon:
        ix = x + 12
        s += (f'<g transform="translate({ix:.0f},{y+6.5:.0f})" fill="none" stroke="{color}" stroke-width="1.4">'
              f'<path d="M5.5 12 s3.8-4.1 3.8-6.8 a3.8 3.8 0 1 0 -7.6 0 c0 2.7 3.8 6.8 3.8 6.8z"/><circle cx="5.5" cy="4.6" r="1.2"/></g>')
    s += f'<text x="{tx:.0f}" y="{y+h/2+4.2:.0f}" text-anchor="middle" font-size="{fs}" font-weight="{weight}" fill="{color or P["pill"]}">{text}</text>'
    return s


def card(x, name, sub, P, right):
    b = P["cardBr"] if right else P["cardBl"]
    sc = P["subR"] if right else P["subL"]
    return (f'<rect x="{x}" y="380" width="250" height="96" rx="10" fill="{P["cardF"]}" stroke="{b}" stroke-width="1.5"/>'
            f'<text x="{x+125}" y="424" text-anchor="middle" font-size="15.5" font-weight="600" fill="{P["text"]}">{name}</text>'
            f'<text x="{x+125}" y="447" text-anchor="middle" font-size="11" fill="{sc}">{sub}</text>')


def render(P):
    e = []
    e.append(f'<rect x="0" y="0" width="700" height="540" fill="{P["zoneL"]}"/>')
    e.append(f'<rect x="700" y="0" width="700" height="540" fill="{P["zoneR"]}"/>')
    e.append(f'<text x="48" y="40" font-size="11" letter-spacing="2.5" font-weight="600" fill="{P["zlabL"]}">VEXA\'S PERIMETER</text>')
    e.append(f'<text x="1352" y="40" text-anchor="end" font-size="11" letter-spacing="2.5" font-weight="600" fill="{P["zlabR"]}">YOUR PERIMETER</text>')
    e.append(f'<path d="M74,74 H700 V224 H74 Q60,224 60,210 V88 Q60,74 74,74 Z" fill="{P["bandL"]}" stroke="{P["bandLb"]}" stroke-width="1.5"/>')
    e.append(f'<path d="M700,74 H1326 Q1340,74 1340,88 V210 Q1340,224 1326,224 H700 Z" fill="{P["bandR"]}" stroke="{P["bandRb"]}" stroke-width="1.5"/>')
    e.append(f'<g transform="translate(84,88)" fill="none" stroke="{P["violet"]}" stroke-width="1.6">'
             f'<ellipse cx="6.5" cy="2.7" rx="6" ry="2.2"/><path d="M0.5 2.7v7.8c0 1.2 2.7 2.2 6 2.2s6-1 6-2.2V2.7"/><path d="M0.5 6.6c0 1.2 2.7 2.2 6 2.2s6-1 6-2.2"/></g>')
    e.append(f'<text x="104" y="99" font-size="11" letter-spacing="1.8" font-weight="600" fill="{P["violet"]}">RELEASE STORE</text>')
    e.append(f'<text x="222" y="99" font-size="11.5" fill="{P["note"]}">— the same frozen release, gaining evidence</text>')
    e.append(f'<text x="722" y="99" font-size="10.5" letter-spacing="1.6" font-weight="600" fill="{P["rnote"]}">PULLED INTO YOUR PERIMETER</text>')
    e.append(f'<line x1="110" y1="168" x2="1296" y2="168" stroke="{P["spine"]}" stroke-width="2"/>')
    e.append(f'<path d="M1296,162 L1308,168 L1296,174 Z" fill="{P["spine"]}"/>')
    e.append(f'<path d="M700,162 L712,168 L700,174 Z" fill="{P["spine"]}"/>')
    for cx, right in ((245, False), (548, False), (852, True), (1155, True)):
        v = P["vertR"] if right else P["vertL"]
        e.append(f'<line x1="{cx}" y1="224" x2="{cx}" y2="370" stroke="{v}" stroke-width="1.5"/>')
        e.append(f'<path d="M{cx-5},370 L{cx+5},370 L{cx},380 Z" fill="{v}"/>')
    e.append(chip(245, "v0.12.31", [], P))
    e.append(chip(548, "v0.12.31", [("staging", "ok")], P))
    e.append(chip(852, "v0.12.31", [("staging", "ok"), ("prod soak", "ok")], P))
    e.append(chip(1155, "v0.12.31", [("staging", "ok"), ("prod soak", "ok"), ("pinned by you", "pin")], P, border=P["chipBr"]))
    e.append(pillbox(245, 258, "consumes candidates", P))
    e.append(pillbox(548, 258, "staging-validated only", P))
    e.append(pillbox(852, 258, "completed Vexa chain only", P, border=P["chipBr"]))
    e.append(pillbox(1155, 258, "only the release your pin names", P, fs=12, border=P["violet"], color=P["violetT"], weight="600", h=27, icon=True))
    e.append(card(120, "Vexa staging", "a Vexa Enterprise unit", P, False))
    e.append(card(423, "Vexa production", "a Vexa Enterprise unit", P, False))
    e.append(card(727, "Your staging", "a Vexa Enterprise unit — yours", P, True))
    e.append(card(1030, "Your production", "a Vexa Enterprise unit — yours", P, True))
    e.append(f'<line x1="700" y1="0" x2="700" y2="540" stroke="{P["dash"]}" stroke-width="2" stroke-dasharray="7 7"/>')
    e.append(pillbox(700, 312, "your boundary — nothing pushes across", P, fs=12, border=P["dash"], weight="600", h=27))
    body = "".join(e)
    return (f'<svg width="1400" height="540" viewBox="0 0 1400 540" xmlns="http://www.w3.org/2000/svg" '
            f'font-family="{FONT}">{body}</svg>\n')


OUT.mkdir(parents=True, exist_ok=True)
(OUT / "release-flow-light.svg").write_text(render(L))
(OUT / "release-flow-dark.svg").write_text(render(D))
print("wrote", OUT / "release-flow-light.svg", "and dark")
