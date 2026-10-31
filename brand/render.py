#!/usr/bin/env python3
"""Renders the Android brand assets from the SVG sources in brand/svg.

    python3 brand/render.py

writes brand/android/res, the files ci/patch.py copies over the upstream
resources of the same name (sizes and formats as upstream has them), and
brand/android/qr_login_logo.json and calls_log_logo.json, the shapes
ci/patch.py puts into the logo layers of the upstream raw/qr_login.json and
raw/calls_log.json animations. Two resources upstream does not have are
added: the laptop animation of Settings > Devices, copied from
brand/lottie/pluma-devices.json to res/raw/pluma_devices.json, and the mark
writing itself on page 1 of the intro, res/raw/pluma_mark_write.json, which
brand/mark_write.py writes from pluma-mark.svg.

Bitmaps go through rsvg-convert (PNG) and cwebp (lossless WebP); vector
drawables, Lottie animations and the SVG for the QR code centre are written
from the path data directly. Needs rsvg-convert and cwebp in PATH; the
output is the same on every run with the same versions of the two.
"""

import json
import math
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

BRAND = pathlib.Path(__file__).resolve().parent
SVG = BRAND / "svg"
OUT = BRAND / "android"
RES = OUT / "res"

# The icon canvas of the brand kit: pluma-icon.svg is 512x512 and the mark
# sits on it as designed. Every composition maps this canvas.
CANVAS = 512
CENTRE = (256.0, 256.0)

WHITE = "#FFFFFF"
SAGE = "#5B7A5E"  # the light accent of the palette

DENSITIES = {"mdpi": 1, "hdpi": 1.5, "xhdpi": 2, "xxhdpi": 3, "xxxhdpi": 4}

# --- SVG sources -------------------------------------------------------------

NS = {"svg": "http://www.w3.org/2000/svg"}


def mark_strokes(name):
    """The strokes of a mark SVG: [(d, colour, width, round_join)]."""
    out = []
    for p in ET.parse(SVG / name).getroot().iter("{http://www.w3.org/2000/svg}path"):
        if p.get("fill") != "none" or p.get("stroke-linecap") != "round":
            sys.exit(f"render: {name}: expected round-capped strokes only")
        out.append((p.get("d"), p.get("stroke").upper(), float(p.get("stroke-width")),
                    p.get("stroke-linejoin") == "round"))
    if len(out) != 4:
        sys.exit(f"render: {name}: expected the ring and three feathers")
    return out


def icon_corner_radius():
    rect = ET.parse(SVG / "pluma-icon.svg").getroot().find("svg:rect", NS)
    if rect is None or rect.get("width") != str(CANVAS):
        sys.exit("render: pluma-icon.svg: expected a 512x512 rect")
    return float(rect.get("rx")), rect.get("fill").upper()


def wordmark_path():
    paths = ET.parse(SVG / "pluma-wordmark.svg").getroot().findall("svg:path", NS)
    if len(paths) != 1:
        sys.exit("render: pluma-wordmark.svg: expected one path")
    return paths[0].get("d")


# --- path data ---------------------------------------------------------------

ARGS = {"M": 2, "L": 2, "H": 1, "V": 1, "C": 6, "Q": 4, "Z": 0}


def parse_path(d):
    """Absolute M/L/H/V/C/Q/Z only (what the brand kit uses)."""
    tokens = re.findall(r"[A-Za-z]|-?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?", d)
    out, i, cmd = [], 0, None
    while i < len(tokens):
        if tokens[i].isalpha():
            cmd = tokens[i]
            i += 1
            if cmd not in ARGS:
                sys.exit(f"render: path command {cmd!r} is not supported")
            if cmd == "Z":
                out.append(("Z", []))
                continue
        n = ARGS[cmd]
        out.append((cmd, [float(t) for t in tokens[i:i + n]]))
        i += n
        if cmd == "M":
            cmd = "L"
    return out


def transform(segs, s, dx, dy):
    out = []
    for cmd, a in segs:
        if cmd == "H":
            a = [a[0] * s + dx]
        elif cmd == "V":
            a = [a[0] * s + dy]
        else:
            a = [v * s + (dx if k % 2 == 0 else dy) for k, v in enumerate(a)]
        out.append((cmd, a))
    return out


def num(v):
    s = f"{v:.3f}".rstrip("0").rstrip(".")
    return "0" if s in ("-0", "") else s


def path_data(segs):
    parts = []
    for cmd, a in segs:
        parts.append(cmd + " ".join(num(v) for v in a))
    return " ".join(parts)


def bbox(segs, pad=0.0):
    """Exact bounds of the path (extrema of the curves), grown by pad."""
    xs, ys = [], []
    x = y = 0.0

    def add(px, py):
        xs.append(px)
        ys.append(py)

    for cmd, a in segs:
        if cmd in ("M", "L"):
            x, y = a
            add(x, y)
        elif cmd == "H":
            x = a[0]
            add(x, y)
        elif cmd == "V":
            y = a[0]
            add(x, y)
        elif cmd == "Q":
            for t in [k / 64 for k in range(65)]:
                add((1 - t) ** 2 * x + 2 * (1 - t) * t * a[0] + t * t * a[2],
                    (1 - t) ** 2 * y + 2 * (1 - t) * t * a[1] + t * t * a[3])
            x, y = a[2], a[3]
        elif cmd == "C":
            for t in [k / 64 for k in range(65)]:
                u = 1 - t
                add(u ** 3 * x + 3 * u * u * t * a[0] + 3 * u * t * t * a[2] + t ** 3 * a[4],
                    u ** 3 * y + 3 * u * u * t * a[1] + 3 * u * t * t * a[3] + t ** 3 * a[5])
            x, y = a[4], a[5]
    return min(xs) - pad, min(ys) - pad, max(xs) + pad, max(ys) + pad


def mark_bounds(strokes):
    boxes = [bbox(parse_path(d), w / 2) for d, _, w, _ in strokes]
    return (min(b[0] for b in boxes), min(b[1] for b in boxes),
            max(b[2] for b in boxes), max(b[3] for b in boxes))


def mark_radius(strokes):
    """How far the mark reaches from the canvas centre, strokes included."""
    r = 0.0
    for d, _, w, _ in strokes:
        segs = parse_path(d)
        pts = []
        x = y = 0.0
        for cmd, a in segs:
            if cmd in ("M", "L"):
                pts.append(tuple(a))
                if cmd == "L":
                    pts += [(x + (a[0] - x) * k / 32, y + (a[1] - y) * k / 32) for k in range(33)]
                x, y = a[-2], a[-1]
            elif cmd == "C":
                for t in [k / 64 for k in range(65)]:
                    u = 1 - t
                    pts.append((u ** 3 * x + 3 * u * u * t * a[0] + 3 * u * t * t * a[2] + t ** 3 * a[4],
                                u ** 3 * y + 3 * u * u * t * a[1] + 3 * u * t * t * a[3] + t ** 3 * a[5]))
                x, y = a[4], a[5]
        for px, py in pts:
            r = max(r, math.hypot(px - CENTRE[0], py - CENTRE[1]) + w / 2)
    return r


# --- compositions ------------------------------------------------------------
# A composition is a list of SVG elements in pixel space of a WxH image.


def mark_elements(strokes, s, cx, cy, colour=None):
    """The mark with the canvas centre at (cx, cy), canvas units scaled by s."""
    dx, dy = cx - CENTRE[0] * s, cy - CENTRE[1] * s
    out = []
    for d, c, w, join in strokes:
        out.append(f'<path fill="none" stroke="{colour or c}" stroke-width="{num(w * s)}" stroke-linecap="round"'
                   + (' stroke-linejoin="round"' if join else "")
                   + f' d="{path_data(transform(parse_path(d), s, dx, dy))}"/>')
    return out


def svg_doc(w, h, elements):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{num(w)}" height="{num(h)}" '
            f'viewBox="0 0 {num(w)} {num(h)}">' + "".join(elements) + "</svg>\n")


def circle(cx, cy, r, fill):
    return f'<circle cx="{num(cx)}" cy="{num(cy)}" r="{num(r)}" fill="{fill}"/>'


class Renderer:
    def __init__(self, tmp):
        self.tmp = pathlib.Path(tmp)
        self.count = 0

    def bitmap(self, rel, w, h, elements):
        dst = RES / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        self.count += 1
        src = self.tmp / f"{self.count}.svg"
        src.write_text(svg_doc(w, h, elements))
        png = dst if dst.suffix == ".png" else self.tmp / f"{self.count}.png"
        subprocess.run(["rsvg-convert", "-w", str(w), "-h", str(h), "-o", str(png), str(src)], check=True)
        if dst.suffix == ".webp":
            subprocess.run(["cwebp", "-quiet", "-lossless", "-z", "9", "-metadata", "none", str(png), "-o", str(dst)],
                           check=True)
        elif dst.suffix != ".png":
            sys.exit(f"render: {rel}: unknown format")


def text(rel, content):
    dst = OUT / rel
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(content)


# --- vector drawables ----------------------------------------------------------


def vector(width_dp, height_dp, vw, vh, paths):
    lines = ['<?xml version="1.0" encoding="utf-8"?>',
             '<!-- Generated by brand/render.py of pluma-android from brand/svg. -->',
             '<vector xmlns:android="http://schemas.android.com/apk/res/android"',
             f'    android:width="{width_dp}dp"',
             f'    android:height="{height_dp}dp"',
             f'    android:viewportWidth="{num(vw)}"',
             f'    android:viewportHeight="{num(vh)}">']
    for p in paths:
        lines.append("    <path")
        lines += [f'        android:{k}="{v}"' for k, v in p[:-1]]
        k, v = p[-1]
        lines.append(f'        android:{k}="{v}" />')
    lines.append("</vector>")
    return "\n".join(lines) + "\n"


def vector_mark(strokes, s, cx, cy, colour=None):
    dx, dy = cx - CENTRE[0] * s, cy - CENTRE[1] * s
    out = []
    for d, c, w, join in strokes:
        p = [("pathData", path_data(transform(parse_path(d), s, dx, dy))),
             ("strokeColor", "#FF" + (colour or c)[1:]),
             ("strokeWidth", num(w * s)),
             ("strokeLineCap", "round")]
        if join:
            p.append(("strokeLineJoin", "round"))
        out.append(p)
    return out


def vector_circle(cx, cy, r, colour):
    d = (f"M{num(cx - r)} {num(cy)}A{num(r)} {num(r)} 0 1 0 {num(cx + r)} {num(cy)}"
         f"A{num(r)} {num(r)} 0 1 0 {num(cx - r)} {num(cy)}Z")
    return [("pathData", d), ("fillColor", "#FF" + colour[1:])]


# --- Lottie ------------------------------------------------------------------


def lottie_shape(segs):
    """An absolute M/L/C path as a Lottie bezier shape."""
    v, i, o = [], [], []
    x = y = 0.0
    for cmd, a in segs:
        if cmd == "M":
            if v:
                sys.exit("render: one subpath per stroke")
            x, y = a
            v.append([x, y])
            i.append([0, 0])
            o.append([0, 0])
        elif cmd == "L":
            x, y = a
            v.append([x, y])
            i.append([0, 0])
            o.append([0, 0])
        elif cmd == "C":
            o[-1] = [a[0] - x, a[1] - y]
            x, y = a[4], a[5]
            v.append([x, y])
            i.append([a[2] - x, a[3] - y])
            o.append([0, 0])
        else:
            sys.exit(f"render: {cmd} in a Lottie shape")
    closed = len(v) > 2 and math.hypot(v[0][0] - v[-1][0], v[0][1] - v[-1][1]) < 1e-6
    if closed:
        i[0] = i.pop()
        o.pop()
        v.pop()

    def r(points):
        return [[round(p[0], 3), round(p[1], 3)] for p in points]

    return {"i": r(i), "o": r(o), "v": r(v), "c": closed}


def lottie_groups(strokes, s, dx, dy, colour):
    rgb = [round(int(colour[k:k + 2], 16) / 255, 4) for k in (1, 3, 5)] + [1]
    groups = []
    for n, (d, _, w, join) in enumerate(strokes):
        groups.append({
            "ty": "gr", "nm": "Ring" if n == 0 else f"Feather {n}",
            "it": [
                {"ty": "sh", "nm": "Path", "ks": {"a": 0, "k": lottie_shape(transform(parse_path(d), s, dx, dy))}},
                {"ty": "st", "nm": "Stroke", "c": {"a": 0, "k": rgb}, "o": {"a": 0, "k": 100},
                 "w": {"a": 0, "k": round(w * s, 3)}, "lc": 2, "lj": 2 if join else 1, "ml": 4},
                {"ty": "tr", "p": {"a": 0, "k": [0, 0]}, "a": {"a": 0, "k": [0, 0]}, "s": {"a": 0, "k": [100, 100]},
                 "r": {"a": 0, "k": 0}, "o": {"a": 0, "k": 100}, "sk": {"a": 0, "k": 0}, "sa": {"a": 0, "k": 0}},
            ],
        })
    return groups


def lottie_static(strokes, size, s, ip, op, colour):
    """A still Lottie of the mark, the frame range of the animation it replaces."""
    dx, dy = size / 2 - CENTRE[0] * s, size / 2 - CENTRE[1] * s
    return {
        "v": "5.5.2", "fr": 60, "ip": ip, "op": op, "w": size, "h": size, "nm": "Pluma", "ddd": 0, "assets": [],
        "layers": [{
            "ddd": 0, "ind": 1, "ty": 4, "nm": "Mark", "sr": 1,
            "ks": {"o": {"a": 0, "k": 100}, "r": {"a": 0, "k": 0}, "p": {"a": 0, "k": [0, 0, 0]},
                   "a": {"a": 0, "k": [0, 0, 0]}, "s": {"a": 0, "k": [100, 100, 100]}},
            "ao": 0, "shapes": lottie_groups(strokes, s, dx, dy, colour),
            "ip": 0, "op": 180, "st": 0, "bm": 0,
        }],
    }


# --- the assets ----------------------------------------------------------------


def main():
    for tool in ("rsvg-convert", "cwebp"):
        if not shutil.which(tool):
            sys.exit(f"render: {tool} is not installed")
    mark = mark_strokes("pluma-mark.svg")
    mono = mark_strokes("pluma-mark-mono.svg")
    if [m[::2] for m in mark] != [m[::2] for m in mono]:
        sys.exit("render: pluma-mark.svg and pluma-mark-mono.svg differ in shape")
    rx, icon_fill = icon_corner_radius()
    x0, y0, x1, y1 = mark_bounds(mark)
    reach = mark_radius(mark)
    # In a circle the mark reaches 86% of the radius (in the rounded square of
    # pluma-icon.svg, 84% of half the side).
    round_scale = 0.86 * CANVAS / 2 / reach

    if OUT.exists():
        shutil.rmtree(OUT)
    with tempfile.TemporaryDirectory() as tmp:
        r = Renderer(tmp)

        def round_icon(n):
            """The mark on a white disc filling an n x n image."""
            return [circle(n / 2, n / 2, n / 2, WHITE), *mark_elements(mark, n / CANVAS * round_scale, n / 2, n / 2)]

        for dens, k in DENSITIES.items():
            # Launcher icons before API 26: the rounded square and the circle,
            # 44 of 48 dp.
            n = round(48 * k)
            side = n * 44 / 48
            s = side / CANVAS
            off = (n - side) / 2
            r.bitmap(f"mipmap-{dens}/ic_launcher.png", n, n, [
                f'<rect x="{num(off)}" y="{num(off)}" width="{num(side)}" height="{num(side)}" '
                f'rx="{num(rx * s)}" fill="{icon_fill}"/>',
                *mark_elements(mark, s, n / 2, n / 2)])
            r.bitmap(f"mipmap-{dens}/ic_launcher_round.png", n, n,
                     [circle(n / 2, n / 2, side / 2, icon_fill), *mark_elements(mark, s * round_scale, n / 2, n / 2)])

            # Adaptive icon foreground: 108 dp, the 512 canvas on the 72 dp
            # the masks show (the mark stays inside the 66 dp safe zone).
            n = round(108 * k)
            s = 72 * k / CANVAS
            for name in ("icon_foreground", "icon_foreground_round", "icon_foreground_sa"):
                r.bitmap(f"mipmap-{dens}/{name}.png", n, n, mark_elements(mark, s, n / 2, n / 2))

            # The round app icon: conversation person, call account, contacts.
            n = round(48 * k)
            r.bitmap(f"drawable-{dens}/ic_launcher_dr.webp", n, n, round_icon(n))

            # Chat shortcut badge on the home screen.
            n = {"mdpi": 15, "hdpi": 22, "xhdpi": 30, "xxhdpi": 45, "xxxhdpi": 60}[dens]
            r.bitmap(f"drawable-{dens}/book_logo.webp", n, n, round_icon(n))

            if dens == "xxxhdpi":
                continue
            # Status bar icon: a white silhouette in the 20 dp live area of 24 dp.
            n = round(24 * k)
            s = 20 * k / max(x1 - x0, y1 - y0)
            r.bitmap(f"drawable-{dens}/notification.webp", n, n,
                     mark_elements(mono, s, n / 2 - ((x0 + x1) / 2 - CENTRE[0]) * s,
                                   n / 2 - ((y0 + y1) / 2 - CENTRE[1]) * s, WHITE))

            # Terms of service logo, 68 dp.
            n = round(68 * k)
            ext = "webp" if dens in ("mdpi", "hdpi") else "png"
            r.bitmap(f"drawable-{dens}/logo_middle.{ext}", n, n, round_icon(n))

            # Intro plane texture (82x74 units): none. Page 1 shows the mark
            # writing itself (pluma_mark_write.json, below) and the patched
            # renderer draws no plane; upstream still loads the texture, and
            # the empty one keeps Telegram's plane out of the APK.
            r.bitmap(f"drawable-{dens}/intro_tg_plane.webp", round(82 * k), round(74 * k), [])

        # Round video watermark text ("TELEGRAM" along the edge): none.
        r.bitmap("raw/round_blur_overlay_text.png", 248, 248, [])

    # Monochrome layer of the adaptive icon (themed icons): the foreground's
    # geometry in one colour.
    text("res/drawable/icon_plane.xml", vector(108, 108, 108, 108, vector_mark(mono, 72 / CANVAS, 54, 54, WHITE)))

    # Splash screen (API 31+): the round icon in the middle of the 320 dp
    # drawable; on the light background its white disc does not show.
    disc = 144
    text("res/drawable/tg_splash_320.xml", vector(320, 320, 320, 320, [
        vector_circle(160, 160, disc / 2, WHITE),
        *vector_mark(mark, disc / CANVAS * round_scale, 160, 160)]))

    # The word "pluma" for the intro title (83x19 dp, centred) and the chat
    # list title (90x20.4 dp, left aligned). The app tints them, so white.
    word = parse_path(wordmark_path())
    wx0, wy0, wx1, wy1 = bbox(word)
    for name, wdp, hdp, vw, vh, centred in (("telegram_logo", "83", "19", 249, 57, True),
                                            ("telegram_logo_2", "90", "20.408922", 269, 61, False)):
        k = vh / (wy1 - wy0)
        if (wx1 - wx0) * k > vw:
            sys.exit(f"render: the wordmark does not fit {name}")
        dx = ((vw - (wx1 - wx0) * k) / 2 if centred else 0) - wx0 * k
        text(f"res/drawable/{name}.xml", vector(wdp, hdp, vw, vh, [[
            ("pathData", path_data(transform(word, k, dx, -wy0 * k))),
            ("fillColor", "#FFFFFFFF")]]))

    # QR code centre (QRCodeWriter draws it from this SVG): the white mark on
    # a sage disc.
    s = 150 / CANVAS * round_scale
    text("res/raw/qr_logo.svg", svg_doc(150, 150, [circle(75, 75, 75, SAGE), *mark_elements(mono, s, 75, 75, WHITE)]))

    # The white plane over QR codes and the round video watermark: the white
    # mark, still, over the same frames.
    s = 230 / (x1 - x0)
    for name in ("qr_code_logo", "qr_code_logo_2", "plane_logo_plain"):
        text(f"res/raw/{name}.json", json.dumps(lottie_static(mono, 512, s, 20, 74, WHITE), separators=(",", ":")))

    # "Link desktop device" animation: the logo layer, centred on its oval
    # (71.36 units at 539.18,282.5; the layer sits at 537.4,284).
    s = 71.36 / CANVAS * round_scale
    text("qr_login_logo.json", json.dumps(
        lottie_groups(mono, s, 539.18 - 537.4 - CENTRE[0] * s, 282.5 - 284 - CENTRE[1] * s, WHITE),
        separators=(",", ":")) + "\n")

    # The call-log permission explanation of the login: the caller, a white
    # disc 48 units across (Telegram's logo, centred on its layer), becomes the
    # white mark reaching as far.
    s = 24 / reach
    text("calls_log_logo.json", json.dumps(
        lottie_groups(mono, s, -CENTRE[0] * s, -CENTRE[1] * s, WHITE), separators=(",", ":")) + "\n")

    # The laptop animation of Settings > Devices, as it is (README, Branding).
    shutil.copyfile(BRAND / "lottie" / "pluma-devices.json", RES / "raw" / "pluma_devices.json")

    # Page 1 of the intro: the mark writing itself, the site's writeMark() as a
    # Lottie animation on the kit's 512 grid (README, Branding).
    subprocess.run([sys.executable, "-I", str(BRAND / "mark_write.py"), str(SVG / "pluma-mark.svg"),
                    str(RES / "raw" / "pluma_mark_write.json")], check=True)

    files = sorted(p.relative_to(OUT) for p in OUT.rglob("*") if p.is_file())
    print(f"render: {len(files)} files in {OUT.relative_to(BRAND.parent)}")


if __name__ == "__main__":
    main()
