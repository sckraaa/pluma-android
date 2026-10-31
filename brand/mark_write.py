#!/usr/bin/env python3
"""Writes the Pluma mark writing itself as a Lottie animation, for page 1 of
the intro in the iOS and Android clients (both play it with rlottie).

    python3 mark_write.py pluma-mark.svg mark_write.json [--site pluma-site/src]

The motion is the site's writeMark() (pluma-site src/components/mark.ts) with
the curves of src/motion/ease.ts, sampled at 60 frames a second:

- the ring is drawn by a trim path in 1.05 s, on twos: onTwos() cuts the
  'pen' curve into round(1.05 * 12) = 13 drawings, each held 1.05/13 s, so a
  drawing appears on the first frame at or after its time, as a 60 Hz display
  shows the site;
- the quill (the three feathers) rides the nib: the ring's point at the drawn
  length plus the mark's own offset of the nib from the ring's start, held with
  the drawing;
- 0.1 s after the ring is drawn the feathers breathe once: opacity 1 -> 0.25
  over 0.24 s on the 'breath' curve, nib first, 0.12 s apart, and back. The
  tween gives yoyo and repeat at its top level, so GSAP plays the whole
  staggered wave backwards: the outer feather turns back first, the nib
  feather last, each on its own curve in reverse time. The mark is at rest
  from 2.11 s, the length of writeMark's timeline (measured with the site's
  GSAP 3.15.0);
- the last frames are the finished mark at rest.

The geometry, stroke widths and ink come from the brand kit's pluma-mark.svg,
on the kit's full 512 grid (the mark's viewBox 64 80 392 336 lies inside it),
so the riding quill never leaves the canvas. With --site the constants are
checked against mark.ts and ease.ts, and the script stops if they moved.

Layers, top to bottom: Feather1 (the nib feather, darkest, on top as in
createMark), Feather2, Feather3, Ring, and the null layer Quill that carries
the feathers. A client recolours them by layer name (keypath "Ring.**") or by
colour replacement: the four inks are distinct and written so that rlottie,
which truncates c * 255, draws exactly the kit's bytes.

Only what rlottie parses and draws is used: shape and null layers, parenting,
groups, bezier paths, round-capped strokes, a trim path, hold and bezier
keyframes on position, trim end and opacity. Standard library only; the output
is the same bytes on every run.
"""

import argparse
import hashlib
import json
import math
import re
import struct
import sys
import xml.etree.ElementTree as ET
from fractions import Fraction

FPS = 60
CANVAS = 512                     # the brand kit's grid
END = Fraction(22, 10)           # the composition lasts 2.2 s, 132 frames

# writeMark() and its curves (mark.ts, ease.ts); --site checks them.
WRITE = Fraction(105, 100)       # writeMark duration
DRAWINGS_PER_SECOND = 12         # onTwos() fps
PEN = (0.5, 0.12, 0.22, 1.0)     # CustomEase 'pen'
BREATH = (0.445, 0.05, 0.55, 0.95)  # CustomEase 'breath'
BREATH_DELAY = Fraction(1, 10)   # after the ring is drawn
BREATH_HALF = Fraction(24, 100)  # each way
BREATH_STAGGER = Fraction(12, 100)
BREATH_LOW = 25                  # opacity, %
# True: yoyo and repeat sit at the tween's top level, as in mark.ts, and the
# whole staggered wave goes back. False would be yoyo inside the stagger
# object: each feather turns back on its own and the mark rests at 1.87 s.
YOYO_WHOLE_WAVE = True

RING_WIDTH = 46
FEATHER_WIDTH = 30
# The kit's light ink, ring first, then the feathers from the nib outwards.
# The clients' dark theme replaces exactly these colours.
LIGHT_INK = ("#111111", "#4A4A4A", "#8A8A8A", "#BDBDBD")

# Lines of the site the constants above were read from. Each must occur once.
SITE_ANCHORS = {
    "components/mark.ts": (
        "export const MARK_VIEWBOX = '64 80 392 336';",
        "CustomEase.create('pen', '0.5,0.12,0.22,1');",
        "ring.setAttribute('stroke-width', '46');",
        "p.setAttribute('stroke-width', '30');",
        "quill.append(...[...feathers].reverse());",
        "const duration = opts.duration ?? 1.05;",
        "const dx = NIB.x - start.x;",
        "const dy = NIB.y - start.y;",
        "const pt = m.ring.getPointAtLength(length * state.p);",
        "const ease = onTwos('pen', duration);",
        ".to(m.ring, { drawSVG: '0% 100%', duration, ease }, 0)",
        ".to(state, { p: 1, duration, ease, onUpdate: placeQuill }, 0);",
        "tl.to(m.feathers, { opacity: 0.25, duration: 0.24, ease: 'breath', "
        "stagger: { each: 0.12, from: 'start' }, yoyo: true, repeat: 1 }, duration + 0.1);",
    ),
    "motion/ease.ts": (
        "CustomEase.create('breath', '0.445,0.05,0.55,0.95');",
        "seconds: number, fps = 12): (p: number) => number {",
        "const frames = Math.max(1, Math.round(seconds * fps));",
        "return (p: number) => (p >= 1 ? 1 : base(Math.floor(p * frames) / frames));",
    ),
}


def fail(msg):
    sys.exit(f"mark_write: {msg}")


# --- the brand kit ---------------------------------------------------------------


def parse_path(d):
    """Absolute M, L and C commands, the ones the kit's mark uses."""
    tokens = re.findall(r"[A-Za-z]|-?(?:\d+\.?\d*|\.\d+)", d)
    args = {"M": 2, "L": 2, "C": 6}
    out, i = [], 0
    while i < len(tokens):
        cmd = tokens[i]
        if cmd not in args:
            fail(f"path command {cmd!r} is not supported")
        nums = tokens[i + 1:i + 1 + args[cmd]]
        if len(nums) != args[cmd] or any(t.isalpha() for t in nums):
            fail(f"malformed path {d!r}")
        out.append((cmd, [float(t) for t in nums]))
        i += 1 + args[cmd]
    if not out or out[0][0] != "M" or any(c == "M" for c, _ in out[1:]):
        fail(f"one subpath per stroke expected in {d!r}")
    return out


def read_kit(svg_path):
    root = ET.parse(svg_path).getroot()
    vb = [float(v) for v in root.get("viewBox", "").split()]
    if len(vb) != 4 or vb[0] < 0 or vb[1] < 0 or vb[0] + vb[2] > CANVAS or vb[1] + vb[3] > CANVAS:
        fail(f"viewBox {root.get('viewBox')!r} is not inside the {CANVAS} grid")
    paths = [e for e in root.iter() if e.tag.rsplit("}", 1)[-1] == "path"]
    if len(paths) != 4:
        fail(f"{svg_path}: a ring and three feathers expected, found {len(paths)} paths")
    strokes = []
    for e in paths:
        if e.get("fill") != "none" or e.get("stroke-linecap") != "round":
            fail(f"{svg_path}: unfilled round-capped strokes expected")
        strokes.append({"d": parse_path(e.get("d")), "raw": e.get("d"), "ink": e.get("stroke").upper(),
                        "width": float(e.get("stroke-width"))})
    ring, feathers = strokes[0], strokes[1:]
    if [c for c, _ in ring["d"]] != ["M", "C", "C", "C", "C"] or ring["width"] != RING_WIDTH \
            or paths[0].get("stroke-linejoin") != "round":
        fail(f"{svg_path}: the ring is not four cubics of width {RING_WIDTH} with round joins")
    nib = tuple(feathers[0]["d"][0][1])
    for f in feathers:
        if [c for c, _ in f["d"]] != ["M", "L"] or tuple(f["d"][0][1]) != nib or f["width"] != FEATHER_WIDTH:
            fail(f"{svg_path}: the feathers are not lines of width {FEATHER_WIDTH} from one nib")
    ink = tuple(s["ink"] for s in strokes)
    if ink != LIGHT_INK:
        fail(f"{svg_path}: ink {ink} is not the light ink {LIGHT_INK} the clients recolour")
    return {
        "viewbox": root.get("viewBox"),
        "ring": ring["d"],
        "ring_raw": ring["raw"],
        "nib": nib,
        "feathers": [(f["ink"], tuple(f["d"][1][1])) for f in feathers],
    }


def check_site(site, kit):
    """Stops when mark.ts or ease.ts no longer say what this script assumes."""
    texts = {}
    for name, anchors in SITE_ANCHORS.items():
        path = f"{site}/{name}"
        try:
            with open(path, encoding="utf-8") as fh:
                texts[name] = fh.read()
        except OSError as err:
            fail(f"--site: {err}")
        for a in anchors:
            n = texts[name].count(a)
            if n != 1:
                fail(f"{path}: expected once, found {n} times: {a}")
    mark = texts["components/mark.ts"]
    ring = re.search(r"export const RING_PATH = '([^']*)';", mark)
    nib = re.search(r"const NIB = \{ x: ([\d.]+), y: ([\d.]+) \};", mark)
    feathers = re.findall(r"\{ color: '(#[0-9A-Fa-f]{6})', x: ([\d.]+), y: ([\d.]+) \}", mark)
    if not ring or ring.group(1) != kit["ring_raw"]:
        fail("RING_PATH in mark.ts differs from the kit's ring")
    if not nib or (float(nib.group(1)), float(nib.group(2))) != kit["nib"]:
        fail("NIB in mark.ts differs from the kit's nib")
    if [(c.upper(), (float(x), float(y))) for c, x, y in feathers] != kit["feathers"]:
        fail("FEATHERS in mark.ts differ from the kit's feathers")
    if "'" + kit["viewbox"] + "'" not in mark:
        fail("MARK_VIEWBOX in mark.ts differs from the kit's viewBox")


# --- geometry and curves -----------------------------------------------------------


def cubic_ease(x1, y1, x2, y2):
    """A CSS cubic-bezier timing function."""
    def coord(a, b, t):
        u = 1 - t
        return 3 * u * u * t * a + 3 * u * t * t * b + t * t * t

    def ease(x):
        if x <= 0:
            return 0.0
        if x >= 1:
            return 1.0
        lo, hi = 0.0, 1.0
        for _ in range(64):
            mid = (lo + hi) / 2
            if coord(x1, x2, mid) < x:
                lo = mid
            else:
                hi = mid
        return coord(y1, y2, (lo + hi) / 2)
    return ease


def cubics(path):
    out, cur = [], None
    for cmd, a in path:
        if cmd == "M":
            cur = (a[0], a[1])
        else:
            out.append((cur, (a[0], a[1]), (a[2], a[3]), (a[4], a[5])))
            cur = (a[4], a[5])
    return out


def bez(seg, t):
    (x0, y0), (x1, y1), (x2, y2), (x3, y3) = seg
    u = 1 - t
    a, b, c, d = u * u * u, 3 * u * u * t, 3 * u * t * t, t * t * t
    return (a * x0 + b * x1 + c * x2 + d * x3, a * y0 + b * y1 + c * y2 + d * y3)


class Measure:
    """Arc length along a chain of cubics, like SVG's getPointAtLength()."""

    STEPS = 4096  # per cubic; the polyline is within 1e-4 of the curve's length

    def __init__(self, segs):
        self.pts = [segs[0][0]]
        for seg in segs:
            for k in range(1, self.STEPS + 1):
                self.pts.append(bez(seg, k / self.STEPS))
        self.acc = [0.0]
        for (ax, ay), (bx, by) in zip(self.pts, self.pts[1:]):
            self.acc.append(self.acc[-1] + math.sqrt((bx - ax) * (bx - ax) + (by - ay) * (by - ay)))
        self.length = self.acc[-1]

    def point(self, s):
        if s <= 0:
            return self.pts[0]
        if s >= self.length:
            return self.pts[-1]
        lo, hi = 0, len(self.acc) - 1
        while hi - lo > 1:
            mid = (lo + hi) // 2
            if self.acc[mid] <= s:
                lo = mid
            else:
                hi = mid
        f = (s - self.acc[lo]) / (self.acc[hi] - self.acc[lo])
        (ax, ay), (bx, by) = self.pts[lo], self.pts[hi]
        return (ax + (bx - ax) * f, ay + (by - ay) * f)


def cubic_bounds(seg):
    """The exact bounding box of a cubic, from the roots of its derivative."""
    xs, ys = [seg[0][0], seg[3][0]], [seg[0][1], seg[3][1]]
    for axis, out in ((0, xs), (1, ys)):
        p0, p1, p2, p3 = (p[axis] for p in seg)
        a = -p0 + 3 * p1 - 3 * p2 + p3
        b = 2 * (p0 - 2 * p1 + p2)
        c = p1 - p0
        roots = []
        if abs(a) < 1e-12:
            if abs(b) > 1e-12:
                roots.append(-c / b)
        else:
            disc = b * b - 4 * a * c
            if disc >= 0:
                r = math.sqrt(disc)
                roots += [(-b + r) / (2 * a), (-b - r) / (2 * a)]
        for t in roots:
            if 0 < t < 1:
                out.append(bez(seg, t)[axis])
    return min(xs), min(ys), max(xs), max(ys)


def js_round(x):
    """Math.round() on a Fraction."""
    return math.floor(x + Fraction(1, 2))


def num(x, places):
    """A JSON number: rounded, an integer when whole, never -0."""
    r = round(float(x), places)
    if r == 0:
        return 0
    return int(r) if r == int(r) else r


def f32(x):
    return struct.unpack("<f", struct.pack("<f", x))[0]


def lottie_colour(hex6):
    """The ink as Lottie's 0..1 floats, each just above byte/255: rlottie and
    lottie-web truncate c * 255 (VColor(int), Math.floor), and rlottie's colour
    replacement keys on round(c * 255), so both give back the kit's byte."""
    out = []
    for i in (1, 3, 5):
        byte = int(hex6[i:i + 2], 16)
        c = -(-byte * 10 ** 6 // 255) / 10 ** 6
        if int(f32(f32(c) * 255)) != byte or math.floor(c * 255) != byte or round(c * 255) != byte:
            fail(f"{hex6}: {c} does not give back {byte}")
        out.append(num(c, 6))
    return out + [1]


# --- the animation -----------------------------------------------------------------


def static(k):
    return {"a": 0, "k": k}


def animated(keys):
    return {"a": 1, "k": keys}


def layer_transform(p=None, o=None):
    return {"o": o or static(100), "r": static(0), "p": p or static([0, 0, 0]),
            "a": static([0, 0, 0]), "s": static([100, 100, 100])}


def group(name, path, ink, width, trim=None):
    v, i, o = [], [], []
    x = y = 0.0
    for cmd, a in path:
        if cmd == "C":
            o[-1] = [num(a[0] - x, 4), num(a[1] - y, 4)]
            i.append([num(a[2] - a[4], 4), num(a[3] - a[5], 4)])
        else:
            i.append([0, 0])
        x, y = a[-2], a[-1]
        v.append([num(x, 4), num(y, 4)])
        o.append([0, 0])
    items = [{"ty": "sh", "nm": "Path", "ks": static({"i": i, "o": o, "v": v, "c": False})}]
    if trim is not None:
        items.append({"ty": "tm", "nm": "Trim", "s": static(0), "e": trim, "o": static(0), "m": 1})
    items.append({"ty": "st", "nm": "Stroke", "c": static(lottie_colour(ink)), "o": static(100),
                  "w": static(width), "lc": 2, "lj": 2, "ml": 4})
    items.append({"ty": "tr", "nm": "Transform", "p": static([0, 0]), "a": static([0, 0]),
                  "s": static([100, 100]), "r": static(0), "o": static(100), "sk": static(0), "sa": static(0)})
    return {"ty": "gr", "nm": name, "it": items}


def held(values):
    """Hold keyframes for one value per frame, a key only where it changes."""
    keys = []
    for frame, v in enumerate(values):
        if not keys or keys[-1]["s"] != v:
            keys.append({"t": frame, "s": v, "h": 1})
    return keys


def ease_keys(curve):
    return {"x": [curve[0]], "y": [curve[1]]}, {"x": [curve[2]], "y": [curve[3]]}


def build(kit):
    write_frames = WRITE * FPS
    op = END * FPS
    if write_frames.denominator != 1 or op.denominator != 1:
        fail("the write and the composition must last whole frames")
    write_frames, op = int(write_frames), int(op)
    drawings = max(1, js_round(WRITE * DRAWINGS_PER_SECOND))

    # onTwos('pen', WRITE) at each frame: the drawn share of the ring's length.
    pen = cubic_ease(*PEN)
    drawn = []
    for frame in range(write_frames + 1):
        p = Fraction(frame, write_frames)
        drawn.append(1.0 if p >= 1 else pen(math.floor(p * drawings) / drawings))

    ring = Measure(cubics(kit["ring"]))
    start = ring.point(0)
    off = (kit["nib"][0] - start[0], kit["nib"][1] - start[1])
    nibs = []
    for share in drawn:
        x, y = ring.point(ring.length * share)
        nibs.append((x + off[0], y + off[1]))
    trim = held([[num(100 * share, 4)] for share in drawn])
    quill = held([[num(x, 3), num(y, 3), 0] for x, y in nibs])
    if quill[-1]["s"][:2] != [num(c, 3) for c in kit["nib"]]:
        fail("the quill does not come to rest at the nib")

    # The riding quill must stay on the canvas, round caps included.
    reach = FEATHER_WIDTH / 2
    x0 = y0 = math.inf
    x1 = y1 = -math.inf
    for nx, ny in nibs:
        for _, (tx, ty) in kit["feathers"]:
            for px, py in ((nx, ny), (nx + tx - kit["nib"][0], ny + ty - kit["nib"][1])):
                x0, y0, x1, y1 = min(x0, px - reach), min(y0, py - reach), max(x1, px + reach), max(y1, py + reach)
    if x0 < 0 or y0 < 0 or x1 > CANVAS or y1 > CANVAS:
        fail(f"the quill leaves the canvas: {x0:.1f},{y0:.1f} .. {x1:.1f},{y1:.1f}")

    down = ease_keys(BREATH)
    # GSAP's yoyo runs the same tween backwards: the reverse of (x1,y1,x2,y2)
    # is (1-x2, 1-y2, 1-x1, 1-y1).
    back = ease_keys(tuple(num(v, 6) for v in (1 - BREATH[2], 1 - BREATH[3], 1 - BREATH[0], 1 - BREATH[1])))
    wave = BREATH_HALF + (len(kit["feathers"]) - 1) * BREATH_STAGGER  # the wave, one way
    last_rest = 0
    layers = [{"ddd": 0, "ind": 1, "ty": 3, "nm": "Quill", "sr": 1,
               "ks": layer_transform(p=animated(quill)), "ao": 0, "ip": 0, "op": op, "st": 0, "bm": 0}]
    for n, (ink, (tx, ty)) in enumerate(kit["feathers"]):
        out = WRITE + BREATH_DELAY + n * BREATH_STAGGER
        low = out + BREATH_HALF
        if YOYO_WHOLE_WAVE:
            back_at = WRITE + BREATH_DELAY + 2 * wave - (n * BREATH_STAGGER + BREATH_HALF)
        else:
            back_at = low
        rest = back_at + BREATH_HALF
        keys = [{"t": num(out * FPS, 4), "s": [100], "o": down[0], "i": down[1]}]
        if back_at > low:
            keys.append({"t": num(low * FPS, 4), "s": [BREATH_LOW], "h": 1})
        keys.append({"t": num(back_at * FPS, 4), "s": [BREATH_LOW], "o": back[0], "i": back[1]})
        keys.append({"t": num(rest * FPS, 4), "s": [100]})
        last_rest = max(last_rest, math.ceil(rest * FPS))
        opacity = animated(keys)
        line = [("M", [0, 0]), ("L", [tx - kit["nib"][0], ty - kit["nib"][1]])]
        name = f"Feather{n + 1}"
        layers.append({"ddd": 0, "ind": n + 2, "ty": 4, "nm": name, "parent": 1, "sr": 1,
                       "ks": layer_transform(o=opacity), "ao": 0,
                       "shapes": [group(name, line, ink, FEATHER_WIDTH)],
                       "ip": 0, "op": op, "st": 0, "bm": 0})
    layers.append({"ddd": 0, "ind": len(layers) + 1, "ty": 4, "nm": "Ring", "sr": 1, "ks": layer_transform(),
                   "ao": 0, "shapes": [group("Ring", kit["ring"], LIGHT_INK[0], RING_WIDTH, animated(trim))],
                   "ip": 0, "op": op, "st": 0, "bm": 0})
    # A player that steps two frames at a time (rlottie's limitFps) still ends at rest.
    if last_rest > op - 2:
        fail(f"the breath ends at frame {last_rest}, too close to the last frame {op - 1}")

    # The resting mark's ink box, strokes included, for the clients' layout.
    box = [math.inf, math.inf, -math.inf, -math.inf]
    for seg in cubics(kit["ring"]):
        bx0, by0, bx1, by1 = cubic_bounds(seg)
        box = [min(box[0], bx0 - RING_WIDTH / 2), min(box[1], by0 - RING_WIDTH / 2),
               max(box[2], bx1 + RING_WIDTH / 2), max(box[3], by1 + RING_WIDTH / 2)]
    for px, py in [kit["nib"]] + [tip for _, tip in kit["feathers"]]:
        box = [min(box[0], px - reach), min(box[1], py - reach), max(box[2], px + reach), max(box[3], py + reach)]

    doc = {"v": "5.7.4", "fr": FPS, "ip": 0, "op": op, "w": CANVAS, "h": CANVAS, "nm": "Pluma mark",
           "ddd": 0, "assets": [], "layers": layers}
    facts = {
        "frames": op, "write_end": write_frames, "drawing_frames": [k["t"] for k in trim],
        "rest_from": last_rest, "ink_box": box, "quill_box": (x0, y0, x1, y1), "ring_length": ring.length,
    }
    return doc, facts


def main():
    ap = argparse.ArgumentParser(description="Writes the Pluma mark writing itself as a Lottie animation.")
    ap.add_argument("svg", help="the brand kit's pluma-mark.svg")
    ap.add_argument("out", help="the Lottie JSON to write")
    ap.add_argument("--site", help="pluma-site/src, to check the constants against mark.ts and ease.ts")
    args = ap.parse_args()
    kit = read_kit(args.svg)
    if args.site:
        check_site(args.site, kit)
    doc, facts = build(kit)
    data = (json.dumps(doc, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
    with open(args.out, "wb") as fh:
        fh.write(data)
    box = facts["ink_box"]
    print(f"{args.out}: {len(data)} bytes, sha256 {hashlib.sha256(data).hexdigest()}")
    print(f"  {FPS} fps, frames 0..{facts['frames'] - 1} ({facts['frames'] / FPS:.2f} s); "
          f"layers {', '.join(layer['nm'] for layer in doc['layers'])}")
    print(f"  drawings at frames {facts['drawing_frames']}, ring drawn at {facts['write_end']}, "
          f"at rest from {facts['rest_from']}")
    print(f"  ink {', '.join(LIGHT_INK)}; resting ink box x {box[0]:.2f}..{box[2]:.2f} "
          f"y {box[1]:.2f}..{box[3]:.2f} ({box[2] - box[0]:.2f} x {box[3] - box[1]:.2f})")
    qb = facts["quill_box"]
    print(f"  riding quill within x {qb[0]:.1f}..{qb[2]:.1f} y {qb[1]:.1f}..{qb[3]:.1f} of {CANVAS}; "
          f"ring length {facts['ring_length']:.3f}")


if __name__ == "__main__":
    main()
