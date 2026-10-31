#!/usr/bin/env python3
"""
Generate docs/assets/og-image.png — the 1200x630 link-preview card that
LinkedIn, X, Slack and Medium show when someone shares the website.

Dev-only dependency: Pillow (``pip install pillow``). Uses Segoe UI on Windows
and falls back to DejaVu fonts elsewhere.

    python scripts/make_og_image.py
"""
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageFont

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "assets" / "og-image.png"
W, H = 1200, 630

BG, PANEL, NODE, LINE = (11, 11, 13), (20, 20, 23), (28, 28, 33), (46, 46, 54)
FG, MUTED, DIM = (242, 242, 245), (165, 165, 175), (110, 110, 120)
GOLD, RED, RED2, GREEN = (192, 154, 60), (228, 0, 43), (255, 45, 82), (63, 174, 106)

_DIRS = [Path("C:/Windows/Fonts"), Path("/usr/share/fonts/truetype/dejavu"),
         Path("/usr/share/fonts/dejavu"), Path("/Library/Fonts")]


def font(names, size):
    for name in names:
        for d in _DIRS:
            if (d / name).exists():
                return ImageFont.truetype(str(d / name), size)
    return ImageFont.load_default()


BOLD = ["segoeuib.ttf", "DejaVuSans-Bold.ttf"]
SEMI = ["seguisb.ttf", "DejaVuSans-Bold.ttf"]
REG = ["segoeui.ttf", "DejaVuSans.ttf"]
MONO = ["consola.ttf", "DejaVuSansMono.ttf"]


def quad(p0, p1, p2, n=48):
    pts = []
    for i in range(n + 1):
        t = i / n
        pts.append(((1 - t) ** 2 * p0[0] + 2 * (1 - t) * t * p1[0] + t * t * p2[0],
                    (1 - t) ** 2 * p0[1] + 2 * (1 - t) * t * p1[1] + t * t * p2[1]))
    return pts


def eye(draw, ox, oy, s, col, w):
    """The same stylized Eye of Horus as the website/explorer SVG logo."""
    P = lambda x, y: (ox + x * s, oy + y * s)  # noqa: E731
    segs = [
        quad(P(2, 9), P(32, -7), P(62, 9)),
        quad(P(5, 20), P(32, 1), P(59, 20)) + quad(P(59, 20), P(32, 36), P(5, 20))[1:],
        [P(29, 29), P(26.5, 40)],
        quad(P(39, 28), P(45, 39), P(53, 34)) + quad(P(53, 34), P(57, 31), P(53, 28))[1:],
    ]
    for pts in segs:
        draw.line(pts, fill=col, width=w, joint="curve")
        for x, y in (pts[0], pts[-1]):
            draw.ellipse([x - w / 2, y - w / 2, x + w / 2, y + w / 2], fill=col)
    cx, cy = P(32, 19)
    r = 7 * s
    draw.ellipse([cx - r, cy - r, cx + r, cy + r], fill=col)


def glow(img, box, color, alpha, blur):
    layer = Image.new("RGBA", img.size, (0, 0, 0, 0))
    ImageDraw.Draw(layer).ellipse(box, fill=color + (alpha,))
    layer = layer.filter(ImageFilter.GaussianBlur(blur))
    img.alpha_composite(layer)


def pill(draw, x, y, text, fnt, fg, border, fill):
    tw = draw.textlength(text, font=fnt)
    w, h = tw + 28, 34
    draw.rounded_rectangle([x, y, x + w, y + h], radius=17, fill=fill, outline=border, width=2)
    draw.text((x + 14, y + 5), text, font=fnt, fill=fg)
    return w


def node(draw, x, y, w, h, name, sub, fill, border, f_name, f_sub):
    draw.rounded_rectangle([x, y, x + w, y + h], radius=14, fill=fill, outline=border, width=3)
    draw.text((x + 22, y + 7), name, font=f_name, fill=FG)
    draw.text((x + 22, y + 37), sub, font=f_sub, fill=MUTED)


def main():
    img = Image.new("RGBA", (W, H), BG + (255,))
    glow(img, [-120, -200, 620, 420], RED, 70, 110)
    glow(img, [820, 360, 1400, 860], GOLD, 38, 120)
    d = ImageDraw.Draw(img)

    # ── Left: brand ──
    glow(img, [70, 70, 230, 200], RED, 90, 40)
    d = ImageDraw.Draw(img)
    eye(d, 82, 92, 2.15, GOLD, 8)
    f_title = font(BOLD, 112)
    d.text((74, 180), "Horus", font=f_title, fill=FG)
    d.text((74 + d.textlength("Horus", font=f_title), 180), "Eye", font=f_title, fill=RED2)
    d.text((80, 322), "See the path. Know the fix.", font=font(SEMI, 46), fill=GOLD)
    f_desc = font(REG, 29)
    d.text((80, 400), "Active Directory attack-path analysis:", font=f_desc, fill=MUTED)
    d.text((80, 440), "evidence, fixes, and a portable offline report.", font=f_desc, fill=MUTED)
    url_w = pill(d, 80, 532, "omar-tamerr.github.io/HorusEye", font(MONO, 22), FG, LINE, (22, 22, 26))
    pill(d, 80 + url_w + 14, 532, "Open source · MIT", font(SEMI, 20), GOLD, (90, 72, 32), (30, 25, 15))

    # ── Right: mini attack-path card ──
    x0, y0, x1, y1 = 712, 58, 1142, 572
    d.rounded_rectangle([x0, y0, x1, y1], radius=22, fill=PANEL, outline=LINE, width=2)
    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([x0 + 22 + i * 22, y0 + 20, x0 + 34 + i * 22, y0 + 32], fill=c)
    d.text((x0 + 100, y0 + 15), "attack path to Domain Admin", font=font(MONO, 18), fill=DIM)

    nx, nw, nh = 770, 300, 66
    ys = [112, 228, 344, 460]
    f_name, f_sub = font(SEMI, 26), font(REG, 18)
    nodes = [("JDOE", "foothold", (16, 37, 26), GREEN),
             ("HELPDESK", "group", NODE, (58, 58, 66)),
             ("WEB01", "computer", NODE, (58, 58, 66)),
             ("ADMINISTRATOR", "Tier-0 target", (42, 15, 20), RED)]
    labels = [("✂ Member of", RED2, RED, (34, 10, 14)),
              ("Admin to", GOLD, (110, 88, 40), (28, 24, 15)),
              ("Has session", GOLD, (110, 88, 40), (28, 24, 15))]
    glow(img, [nx - 20, ys[3] - 20, nx + nw + 20, ys[3] + nh + 20], RED, 80, 22)
    d = ImageDraw.Draw(img)
    f_lab = font(SEMI, 18)
    sym = font(["seguisym.ttf", "DejaVuSans.ttf"], 18)
    ax = nx + 46
    for i in range(3):
        top, bot = ys[i] + nh + 4, ys[i + 1] - 6
        col = RED if i == 0 else GOLD
        d.line([(ax, top), (ax, bot - 12)], fill=col, width=4)
        d.polygon([(ax - 9, bot - 14), (ax + 9, bot - 14), (ax, bot)], fill=col)
        text, fg, border, fill = labels[i]
        lx, ly = ax + 24, (top + bot) / 2 - 17
        if text.startswith("✂"):
            tw = d.textlength("✂", font=sym) + d.textlength(" Member of", font=f_lab)
            d.rounded_rectangle([lx, ly, lx + tw + 28, ly + 34], radius=17, fill=fill, outline=border, width=2)
            d.text((lx + 14, ly + 6), "✂", font=sym, fill=fg)
            d.text((lx + 14 + d.textlength("✂", font=sym), ly + 5), " Member of", font=f_lab, fill=fg)
        else:
            pill(d, lx, ly, text, f_lab, fg, border, fill)
    for (name, sub, fill, border), y in zip(nodes, ys):
        node(d, nx, y, nw, nh, name, sub, fill, border, f_name, f_sub)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    img.convert("RGB").save(OUT, "PNG", optimize=True)
    print(f"wrote {OUT.relative_to(ROOT)} ({OUT.stat().st_size // 1024} KB, {W}x{H})")


if __name__ == "__main__":
    main()
