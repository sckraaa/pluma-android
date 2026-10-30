#!/usr/bin/env python3
import hashlib
import json
import pathlib
import re
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import patch  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Telegram's production and test server keys, as tgnet carries them, with
# the fingerprints tgnet pairs them with.
TELEGRAM_PROD = """-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA6LszBcC1LGzyr992NzE0ieY+BSaOW622Aa9Bd4ZHLl+TuFQ4lo4g
5nKaMBwK/BIb9xUfg0Q29/2mgIR6Zr9krM7HjuIcCzFvDtr+L0GQjae9H0pRB2OO
62cECs5HKhT5DZ98K33vmWiLowc621dQuwKWSQKjWf50XYFw42h21P2KXUGyp2y/
+aEyZ+uVgLLQbRA1dEjSDZ2iGRy12Mk5gpYc397aYp438fsJoHIgJ2lgMv5h7WY9
t6N/byY9Nw9p21Og3AoXSL2q/2IJ1WRUhebgAdGVMlV1fkuOQoEzR7EdpqtQD9Cs
5+bfo3Nhmcyvk5ftB0WkJ9z6bNZ7yxrP8wIDAQAB
-----END RSA PUBLIC KEY-----"""

TELEGRAM_TEST = """-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAyMEdY1aR+sCR3ZSJrtztKTKqigvO/vBfqACJLZtS7QMgCGXJ6XIR
yy7mx66W0/sOFa7/1mAZtEoIokDP3ShoqF4fVNb6XeqgQfaUHd8wJpDWHcR2OFwv
plUUI1PLTktZ9uW2WE23b+ixNwJjJGwBDJPQEQFBE+vfmH0JP503wr5INS1poWg/
j25sIWeYPHYeOrFp/eXaqhISP6G+q2IeTaWTXpwZj4LzXq5YOpk4bYEQ6mvRq7D1
aHWfYmlEGepfaYR8Q0YqvvhYtMte3ITnuSJs171+GDqpdKcSwHnd6FudwGO4pcCO
j4WcDuXc2CTHgH8gFTNhp/Y8/SpDOhvn9QIDAQAB
-----END RSA PUBLIC KEY-----"""

# A 1024-bit key.
SHORT_KEY = """-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMBvrxwgy0g1WuxFbnjB79af4juEIO3ZXfx30SS/tndZtRAb4XJuUkTj
uONmIsoK45uRKr4M3ALh8hMjCUXWfEOJAcd/CQjW5Iki3JK6DDkh9vZnPdM0vYv9
mYMNNrfzbwRjZeV714GXl0lT5km9M59gELCLwoFVOeKaLC400rX9AgMBAAE=
-----END RSA PUBLIC KEY-----"""


def fingerprint(pem):
    return patch.key_fingerprint(*patch.parse_pkcs1_public_key(pem))


class KeyTest(unittest.TestCase):
    def test_telegram_fingerprints(self):
        self.assertEqual(fingerprint(TELEGRAM_PROD), 0xD09D1D85DE64FD85)
        self.assertEqual(fingerprint(TELEGRAM_TEST), 0xB25898DF208D2603)

    def test_dev_key_fingerprint(self):
        # The fingerprint the server prints for the development key
        # (tools/genserverkey in the server repository).
        pem = (ROOT / "config/dev/server_public.pem").read_text()
        self.assertEqual(fingerprint(pem), 14037083214707814241)

    def test_canonical_pem_round_trip(self):
        n, e = patch.parse_pkcs1_public_key(TELEGRAM_PROD)
        self.assertEqual("\n".join(patch.canonical_pem(n, e)), TELEGRAM_PROD)

    def test_rejects_other_formats(self):
        spki = TELEGRAM_PROD.replace("RSA PUBLIC KEY", "PUBLIC KEY")
        with self.assertRaises(patch.PatchError):
            patch.parse_pkcs1_public_key(spki)


def config(**over):
    upstream = {"UPSTREAM_LAYER": "228", "UPSTREAM_VERSION": "12.9.1", "NDK_VERSION": "27.2.12479018", "CMAKE_VERSION": "3.10.2"}
    app = patch.load_env(ROOT / "config/app.env")
    args = dict(server_ipv4="203.0.113.7", server_port="443", server_ipv6="", rsa_pem=TELEGRAM_TEST,
                abis="arm64-v8a", ccache=False, google_services="")
    args.update(over)
    return patch.Config(upstream, app, **args)


class ConfigTest(unittest.TestCase):
    def test_valid(self):
        c = config(server_ipv6="2001:db8::1", abis="arm64-v8a, x86_64")
        self.assertEqual(c.ipv6, "2001:0db8:0000:0000:0000:0000:0000:0001")
        self.assertEqual(c.abis, ["arm64-v8a", "x86_64"])
        self.assertEqual(c.package, "chat.pluma.app")

    def test_rejects(self):
        for over in (
            {"server_ipv4": "pluma.chat"},
            {"server_ipv4": "2001:db8::1"},
            {"server_port": "0"},
            {"server_port": "https"},
            {"server_ipv6": "203.0.113.7"},
            {"rsa_pem": SHORT_KEY},
            {"abis": "mips"},
            {"abis": "arm64-v8a arm64-v8a"},
            {"abis": ""},
        ):
            with self.subTest(over=over), self.assertRaises(patch.PatchError):
                config(**over)


class TreeTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.dir.name)
        (root / "TMessagesProj").mkdir()
        (root / "a.txt").write_text("one two two\nvoid f() {\n    body;\n}\n")
        self.tree = patch.Tree(root)

    def tearDown(self):
        self.dir.cleanup()

    def test_replace_counts(self):
        with self.assertRaises(patch.PatchError):
            self.tree.replace("a.txt", "two", "2")
        with self.assertRaises(patch.PatchError):
            self.tree.replace("a.txt", "three", "3")
        self.tree.replace("a.txt", "two", "2", count=2)
        self.assertTrue(self.tree.read("a.txt").startswith("one 2 2\n"))

    def test_replace_body(self):
        with self.assertRaises(patch.PatchError):
            self.tree.replace_body("a.txt", "void f() {\n", "\n}\n", "    other;", must_contain=("missing",))
        self.tree.replace_body("a.txt", "void f() {\n", "\n}\n", "    other;", must_contain=("body;",))
        self.assertTrue(self.tree.read("a.txt").endswith("void f() {\n    other;\n}\n"))

    def test_not_a_checkout(self):
        with tempfile.TemporaryDirectory() as d, self.assertRaises(patch.PatchError):
            patch.Tree(d)


class BrandTest(unittest.TestCase):
    def test_rename_strings(self):
        xml = ('<string name="TelegramFAQ">Telegram FAQ</string>\n'
               '<string name="Tips">https://t.me/TelegramTips</string>\n'
               '<string name="Faq">https://telegram.org/faq and Telegram.org</string>\n'
               '<string name="A">__Telegram Premium.__ Use Telegram. INVITE TO TELEGRAM</string>\n'
               '<string name="B">Telegramm, @Telegram, Telegram\'s</string>\n'
               '<string name="C">텔레그램이 텔레그램</string>\n')
        out, counts = patch.rename_strings(xml, (("텔레그램이", "Pluma가", 1), ("텔레그램", "Pluma", 1)))
        self.assertEqual(out, '<string name="TelegramFAQ">Pluma FAQ</string>\n'
                              '<string name="Tips">https://t.me/TelegramTips</string>\n'
                              '<string name="Faq">https://telegram.org/faq and Telegram.org</string>\n'
                              '<string name="A">__Pluma Premium.__ Use Pluma. INVITE TO PLUMA</string>\n'
                              '<string name="B">Telegramm, @Telegram, Pluma\'s</string>\n'
                              '<string name="C">Pluma가 Pluma</string>\n')
        self.assertEqual((counts["Telegram"], counts["TELEGRAM"], counts["텔레그램이"], counts["텔레그램"]), (4, 1, 1, 1))

    def test_assets_are_rendered(self):
        res = patch.BRAND / "res"
        files = {p.relative_to(res).as_posix() for p in res.rglob("*") if p.is_file()}
        self.assertEqual(files, set(patch.BRAND_ASSETS) | set(patch.BRAND_ADDED),
                         "run brand/render.py and update BRAND_ASSETS or BRAND_ADDED")
        self.assertFalse(set(patch.BRAND_ASSETS) & set(patch.BRAND_ADDED))
        for rel, sha in patch.BRAND_ADDED.items():
            self.assertEqual(hashlib.sha256((res / rel).read_bytes()).hexdigest(), sha, rel)
        for rel in files:
            if rel.endswith((".png", ".webp")):
                data = (res / rel).read_bytes()
                self.assertEqual(data[:4] == b"RIFF", rel.endswith(".webp"), rel)
                self.assertGreater(min(patch.image_size(data)), 0, rel)
        for _, _, _, _, src in patch.BRAND_LAYERS:
            groups = json.loads((patch.BRAND / src).read_text())
            self.assertEqual([g["ty"] for g in groups], ["gr"] * 4, src)

    def test_devices_animation(self):
        # The copy brand/render.py makes of the source: a Lottie animation of
        # the size of a sticker.
        data = (patch.BRAND / "res/raw/pluma_devices.json").read_bytes()
        self.assertEqual(data, (patch.BRAND.parent / "lottie/pluma-devices.json").read_bytes(), "run brand/render.py")
        anim = json.loads(data)
        self.assertEqual((anim["w"], anim["h"]), (512, 512))
        self.assertGreater(anim["op"], anim["ip"])
        self.assertTrue(anim["layers"])

    def test_add_asset(self):
        rel = "raw/pluma_devices.json"
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            raw = root / patch.RES / "raw"
            raw.mkdir(parents=True)
            tree = patch.Tree(root)
            with self.assertRaisesRegex(patch.PatchError, "SHA-256"):
                patch.add_asset(tree, rel, "0" * 64)
            # A resource of the same name, whatever its extension.
            (raw / "pluma_devices.tgs").write_bytes(b"")
            with self.assertRaisesRegex(patch.PatchError, "pluma_devices.tgs"):
                patch.add_asset(tree, rel, patch.BRAND_ADDED[rel])
            (raw / "pluma_devices.tgs").unlink()
            patch.add_asset(tree, rel, patch.BRAND_ADDED[rel])
            self.assertEqual((raw / "pluma_devices.json").read_bytes(), (patch.BRAND / "res" / rel).read_bytes())

    def test_edit_string(self):
        xml = ('<string name="Url">https://desktop.telegram.org/</string>\n'
               '<string name="Info">Get it from *desktop.telegram.org*.</string>\n')
        out = patch.edit_string(xml, "x", "Url", "https://desktop.telegram.org/", "https://pluma.chat/")
        out = patch.edit_string(out, "x", "Info", "*desktop.telegram.org*", "*pluma.chat*")
        self.assertEqual(out, '<string name="Url">https://pluma.chat/</string>\n'
                              '<string name="Info">Get it from *pluma.chat*.</string>\n')
        for key, old in (("Url", "https://desktop.telegram.org"),     # a URL is the whole text
                         ("Info", "*getdesktop.telegram.org*"),       # the link the text marks
                         ("Other", "https://desktop.telegram.org/")):  # no such string
            with self.subTest(key=key), self.assertRaises(patch.PatchError):
                patch.edit_string(xml, "x", key, old, "https://pluma.chat/")
        with self.assertRaises(patch.PatchError):
            patch.edit_string(xml + xml, "x", "Url", "https://desktop.telegram.org/", "https://pluma.chat/")

    def test_client_links(self):
        for key, old, new, langs in patch.CLIENT_LINKS:
            with self.subTest(key=key, old=old):
                self.assertLessEqual(set(langs), set(patch.STRING_RENAMES))
                self.assertRegex(old, patch.CLIENT_SITES)
                self.assertNotIn("telegram.org", new)
                if key.endswith("Url"):
                    self.assertRegex(new, r"\Ahttps://(web\.)?pluma\.chat/\Z")

    def test_image_size(self):
        png = b"\x89PNG\r\n\x1a\n" + b"\0\0\0\rIHDR" + (82).to_bytes(4, "big") + (74).to_bytes(4, "big")
        self.assertEqual(patch.image_size(png), (82, 74))
        vp8l = b"RIFF\0\0\0\0WEBPVP8L\0\0\0\0\x2f" + ((81 | (73 << 14)).to_bytes(4, "little"))
        self.assertEqual(patch.image_size(vp8l), (82, 74))

    def test_edit_accents(self):
        rows = "".join(f"                new int[]    {{ {r}0,  0x{r}1 }},\n" for r in range(10))
        text = ('        themeInfo.name = "Blue";\n'
                "        themeInfo.setAccentColorOptions(\n" + rows +
                '                new String[] {         "",  "slug" }\n'
                "                );\n")
        out = patch.edit_accents(text, "Blue", ((1, 1, "0x11", "0xFF5B7A5E"),))
        self.assertIn("new int[]    { 10,  0xFF5B7A5E },\n", out)
        self.assertEqual(out.replace("0xFF5B7A5E", "0x11"), text)
        with self.assertRaises(patch.PatchError):
            patch.edit_accents(text, "Blue", ((1, 1, "0x12", "0x0"),))
        with self.assertRaises(patch.PatchError):
            patch.edit_accents(text, "Dark Blue", ())

    def test_edit_attheme(self):
        text = "a=-1\nb=5\n"
        self.assertEqual(patch.edit_attheme(text, "t", (("a", -1, "#5B7A5E"), ("c", None, "#80000000")), {"a", "c"}),
                         "a=-10782114\nb=5\nc=-2147483648\n")
        for table in ((("a", -2, "#000000"),), (("a", None, "#000000"),), (("x", None, "#000000"),)):
            with self.subTest(table=table), self.assertRaises(patch.PatchError):
                patch.edit_attheme(text, "t", table, {"a", "c"})

    def test_tables(self):
        for table in (patch.PALETTE_LIGHT, patch.PALETTE_DARK):
            keys = [k for k, _, _ in table]
            self.assertEqual(len(keys), len(set(keys)))
            for _, _, colour in table:
                self.assertRegex(colour, r"\A#(?:[0-9A-F]{6}|[0-9A-F]{8})\Z")
        self.assertFalse(set(patch.SCHEME_JAVA) & set(patch.SCHEME_KEEP))
        self.assertEqual(set(patch.STRING_LOCAL_NAMES) - set(patch.STRING_RENAMES), set())


def theme_java(light_accent="0xFF5B7A5E", extra=""):
    """A Theme.java with the two default themes, as the patch leaves them."""
    def theme(name, accents, ids, base_line=""):
        n = len(ids)
        zeros = ", ".join(["0x00000000"] * n)
        slugs = ", ".join(['""'] * n)
        rows = ([f"new int[]    {{ {', '.join(accents)} }},"] + [f"new int[]    {{ {zeros} }},"] * 6
                + [f"new int[]    {{ {', '.join(ids)} }},", f"new String[] {{ {slugs} }},"]
                + [f"new int[]    {{ {', '.join(['0'] * n)} }},"] * 2)
        rows[-1] = rows[-1].rstrip(",")
        return (f'        themeInfo.name = "{name}";\n'
                "        themeInfo.setAccentColorOptions(\n"
                + "".join(f"                {r}\n" for r in rows) +
                "                );\n" + base_line +
                "        sortAccents(themeInfo);\n"
                "        themes.add(themeInfo);\n")
    return ("        fallbackKeys.put(key_e, Theme.key_f);\n"
            "        themeAccentExclusionKeys.add(key_d);\n"
            "        for (int i = 0; i < keys_avatar.length; i++) {\n"
            "            themeAccentExclusionKeys.add(keys_avatar[i]);\n"
            "        }\n"
            "    public static int[] keys_avatar = {key_h};\n"
            + theme("Blue", [light_accent, "0xFF328ACF"], ["99", "0"])
            + theme("Dark Blue", ["0xff9DBB9F"], ["0"], "        themeInfo.accentBaseColor = 0xff3685fa;\n")
            + extra)


COLORS_JAVA = """
    public static final int TELEGRAM_COLOR = 0xFF229AF0;        // -14509328
        defaultColors[key_a] = TELEGRAM_COLOR;
        defaultColors[key_b] = 0xffff0000;
        defaultColors[key_c] = 0xFF3030D0;
        defaultColors[key_d] = TELEGRAM_COLOR;
        defaultColors[key_e] = TELEGRAM_COLOR;
        defaultColors[key_f] = TELEGRAM_COLOR;
        defaultColors[key_g] = ColorUtils.setAlphaComponent(Color.WHITE, 90);
        defaultColors[key_h] = 0xFF5CAFFA;
        defaultColors[key_i] = 0xFF30C8D0;
""" + "".join(f'        colorKeysMap.put(key_{k}, "{k}");\n' for k in "abcdefghi")


class ThemeTest(unittest.TestCase):
    FILES = {"bluebubbles.attheme": f"f={patch.argb('#5B7A5E')}\n", "darkblue.attheme": f"f={patch.argb('#9DBB9F')}\n"}

    def test_accent_shift(self):
        # The base becomes the accent; what lies 30 degrees away stays.
        self.assertEqual(patch.accent_shift(0xFF328ACF, 0xFF5B7A5E, 0xFF328ACF, False), 0xFF5B7A5E)
        self.assertEqual(patch.accent_shift(0xFF328ACF, 0xFF5B7A5E, 0xFFFF0000, False), 0xFFFF0000)
        self.assertEqual(patch.accent_shift(0xFF328ACF, 0xFF5B7A5E, 0xFF3030D0, False), 0xFF3030D0)
        for dark in (False, True):
            shifted = patch.accent_shift(0xff3685fa, 0xff9DBB9F, 0x80229AF0, dark)
            self.assertEqual(shifted >> 24, 0x80)
            self.assertFalse(patch.telegram_blue(shifted))
        self.assertTrue(patch.telegram_blue(0xFF229AF0))
        self.assertFalse(patch.telegram_blue(0xFF5B7A5E))

    def test_theme_defaults(self):
        names, defaults = patch.theme_defaults(COLORS_JAVA)
        self.assertEqual(names["key_a"], "a")
        self.assertEqual(defaults["key_a"], 0xFF229AF0)
        self.assertEqual(defaults["key_g"], 0x5AFFFFFF)
        with self.assertRaises(patch.PatchError):
            patch.theme_defaults(COLORS_JAVA + "        defaultColors[key_x] = OTHER_COLOR;\n")

    def test_blue_left(self):
        # A Telegram blue the engine moves (a), one that falls back to a key of
        # the file (e), excluded keys (d, h), and blues the engine does not
        # reach, beyond 30 degrees from the base (c in the day theme, i in the
        # night one), which the check names.
        self.assertEqual(patch.default_theme_blues(theme_java(), COLORS_JAVA, self.FILES),
                         {"bluebubbles.attheme": ["c"], "darkblue.attheme": ["i"]})
        files = {k: v + f"c=#5B7A5E\ni={patch.argb('#5B7A5E')}\n" for k, v in self.FILES.items()}
        self.assertEqual(patch.default_theme_blues(theme_java(), COLORS_JAVA, files),
                         {"bluebubbles.attheme": [], "darkblue.attheme": []})
        # A blue the theme file sets.
        blue = dict(files, **{"bluebubbles.attheme": files["bluebubbles.attheme"] + "b=#3030D0\n"})
        self.assertEqual(patch.default_theme_blues(theme_java(), COLORS_JAVA, blue)["bluebubbles.attheme"], ["b"])
        # A home accent that does not tint leaves Telegram's blue.
        self.assertEqual(patch.default_theme_blues(theme_java("0xFF328ACF"), COLORS_JAVA, files)["bluebubbles.attheme"],
                         ["a"])

    def test_default_accent_shortcuts(self):
        # Upstream's Theme.getColor answers Telegram's colours for the home
        # accent of the day theme, whatever the theme file says.
        upstream = ("            } else {\n"
                    "                useDefault = currentTheme.isDefaultMainAccent();\n"
                    "            }\n")
        for extra in (upstream, *patch.DEFAULT_ACCENT_SHORTCUTS):
            with self.subTest(extra=extra), self.assertRaises(patch.PatchError):
                patch.default_theme_blues(theme_java(extra=extra), COLORS_JAVA, self.FILES)

    def test_colour_literals_left(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "TMessagesProj").mkdir()
            for rel, old, new, _ in patch.BRAND_COLOURS:
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).write_text(new)
            rel, old, _, _ = patch.BRAND_COLOURS[-1]
            (root / rel).write_text(old)
            with self.assertRaisesRegex(patch.PatchError, "is still there"):
                patch.verify_theme(patch.Tree(root))


class GoogleServicesTest(unittest.TestCase):
    def test_placeholder_is_well_formed(self):
        cfg = patch.placeholder_google_services(["chat.pluma.app", "chat.pluma.app.beta"])
        for client in cfg["client"]:
            # The formats the Firebase SDK checks before it starts.
            self.assertRegex(client["api_key"][0]["current_key"], r"\AA[\w-]{38}\Z")
            self.assertRegex(client["client_info"]["mobilesdk_app_id"], r"\A1:\d+:android:[0-9a-f]+\Z")
        self.assertEqual([c["client_info"]["android_client_info"]["package_name"] for c in cfg["client"]],
                         ["chat.pluma.app", "chat.pluma.app.beta"])


if __name__ == "__main__":
    unittest.main()
