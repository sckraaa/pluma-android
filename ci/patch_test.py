#!/usr/bin/env python3
import hashlib
import json
import pathlib
import re
import sys
import tempfile
import unittest
import unittest.mock

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


class BirthdaysTest(unittest.TestCase):
    # DialogsActivity as upstream writes it, from the texts the edits expect:
    # the imports (StarGiftSheet is another class and stays), then the
    # birthday notice between the branches before and after it.
    UPSTREAM = (patch.BIRTHDAY_EDITS[0][0] + "import org.telegram.ui.Stars.StarGiftSheet;\n" + "            });\n"
                + "".join(old for old, _ in patch.BIRTHDAY_EDITS[1:]) + "        } else if (\n")
    STRINGS = "".join(f"    {s}\n" for s in patch.BIRTHDAY_STRINGS)

    def tree(self, root, dialogs, strings=None):
        for rel, text in ((patch.DIALOGS, dialogs), ("TMessagesProj/src/main/res/values/strings.xml", strings or self.STRINGS)):
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text, encoding="utf-8")
        return patch.Tree(root)

    def test_notice_leads_to_the_chat(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d), self.UPSTREAM)
            # Upstream's notice: only while Premium can be bought, to the gift sheet.
            with self.assertRaisesRegex(patch.PatchError, "still has premiumPurchaseBlocked"):
                patch.verify_birthdays(tree)
            patch.birthdays(tree)
            patch.verify_birthdays(tree)
            notice = patch.birthday_notice(tree.read(patch.DIALOGS))
            self.assertIn("ItemOptions.makeOptions(this, dialogsHintCell)", notice)
            self.assertIn("options.setDrawScrim(false).show();", notice)
            self.assertIn("LocaleController.getString(R.string.SendMessage)", notice)
            # The gift sheet's import goes with its only use.
            text = tree.read(patch.DIALOGS)
            self.assertNotRegex(text, r"\bGiftSheet\b")
            self.assertIn("import org.telegram.ui.Stars.StarGiftSheet;\n", text)
            # A second run finds none of the upstream texts.
            with self.assertRaises(patch.PatchError):
                patch.birthdays(tree)
        for s in patch.BIRTHDAY_STRINGS:
            self.assertNotRegex(s, r"(?i)gift")

    def test_upstream_changed(self):
        for i, (old, _) in enumerate(patch.BIRTHDAY_EDITS):
            with self.subTest(edit=i), tempfile.TemporaryDirectory() as d:
                tree = self.tree(pathlib.Path(d), self.UPSTREAM.replace(old, old.replace(".", ". ", 1)))
                with self.assertRaises(patch.PatchError):
                    patch.birthdays(tree)
        # The gift sheet, used elsewhere in the file too: its import must stay.
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d), self.UPSTREAM + "        new GiftSheet(getContext(), currentAccount, 0, null, null);\n")
            with self.assertRaisesRegex(patch.PatchError, "GiftSheet is still used"):
                patch.birthdays(tree)
        # The text of the notice, changed to offer a gift.
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d), self.UPSTREAM, self.STRINGS.replace(">Send Message<", ">Send a Gift<"))
            with self.assertRaisesRegex(patch.PatchError, "SendMessage"):
                patch.birthdays(tree)

    def test_check(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d), self.UPSTREAM)
            patch.birthdays(tree)
            patched = tree.read(patch.DIALOGS)
            for text, error in (
                (patched.replace("options.setDrawScrim(false).show();\n",
                                 "options.setDrawScrim(false).show();\n                UserSelectorBottomSheet.open(0, state);\n"),
                 "still has UserSelectorBottomSheet"),
                (patched.replace("options.setDrawScrim(false).show();\n",
                                 "options.setDrawScrim(false).show();\n"
                                 "                presentFragment(new PremiumPreviewFragment(\"birthday\"));\n"),
                 "leads to Premium"),
                (patched.replace("presentFragment(ChatActivity.of(state.today.get(0).id));", "return;"), "does not lead"),
                (patched.replace("presentFragment(ChatActivity.of(user.id))", "options.dismiss()"), "does not lead"),
                (patched + patched, "2 birthday notices"),
            ):
                with self.subTest(error=error):
                    self.assertNotEqual(text, patched)
                    tree.write(patch.DIALOGS, text)
                    with self.assertRaisesRegex(patch.PatchError, error):
                        patch.verify_birthdays(tree)


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
        # "Day" passes null for two of its arrays.
        nulls = text.replace("new int[]    { 50,  0x51 },", "null,")
        self.assertEqual(patch.accent_table(nulls, "Blue")[5], [])
        self.assertIn("0xFF5B7A5E", patch.edit_accents(nulls, "Blue", ((1, 1, "0x11", "0xFF5B7A5E"),)))
        with self.assertRaises(patch.PatchError):
            patch.edit_accents(nulls, "Blue", ((5, 0, "50", "0"),))

    def test_edit_attheme(self):
        text = "a=-1\nb=5\n"
        self.assertEqual(patch.edit_attheme(text, "t", (("a", -1, "#5B7A5E"), ("c", None, "#80000000")), {"a", "c"}),
                         "a=-10782114\nb=5\nc=-2147483648\n")
        for table in ((("a", -2, "#000000"),), (("a", None, "#000000"),), (("x", None, "#000000"),)):
            with self.subTest(table=table), self.assertRaises(patch.PatchError):
                patch.edit_attheme(text, "t", table, {"a", "c"})
        # An unterminated last line, which the app never reads, stays last and
        # does not set its key.
        self.assertEqual(patch.edit_attheme("a=-1\nb=5", "t", (("a", -1, "#5B7A5E"), ("b", None, "#80000000")),
                                            {"a", "b"}),
                         "a=-10782114\nb=-2147483648\nb=5")
        with self.assertRaises(patch.PatchError):
            patch.edit_attheme("a=-1\nb=5", "t", (("b", 5, "#000000"),), {"a", "b"})

    def test_tables(self):
        for name, table in patch.THEME_FILES.items():
            keys = [k for k, _, _ in table]
            self.assertEqual(len(keys), len(set(keys)), name)
            for _, _, colour in table:
                self.assertRegex(colour, r"\A#(?:[0-9A-F]{6}|[0-9A-F]{8})\Z")
        # Every bundled theme has its table and is checked.
        self.assertEqual(set(patch.THEME_FILES), {asset for asset, _, _ in patch.DEFAULT_THEMES.values()})
        self.assertLessEqual(set(patch.ACCENTS), set(patch.DEFAULT_THEMES))
        for theme, base in patch.ACCENT_BASES.items():
            # The base is the colour the accent of id 0 had.
            self.assertTrue(any(row == 0 and old == base for row, _, old, _ in patch.ACCENTS[theme]), theme)
        self.assertFalse(set(patch.SCHEME_JAVA) & set(patch.SCHEME_KEEP))
        self.assertEqual(set(patch.STRING_LOCAL_NAMES) - set(patch.STRING_RENAMES), set())

    def test_outgoing_contrast(self):
        # What a table writes on the outgoing bubble reads at least as well on
        # Pluma's bubble as Telegram's colour on Telegram's, at each end of the
        # bubble's gradient (WCAG 2 contrast ratio).
        def colour(value):
            return (value if isinstance(value, int) else patch.argb(value)) & 0xFFFFFFFF

        def luminance(c):
            def channel(x):
                x /= 255
                return x / 12.92 if x <= 0.04045 else ((x + 0.055) / 1.055) ** 2.4
            r, g, b = (channel((c >> s) & 0xFF) for s in (16, 8, 0))
            return 0.2126 * r + 0.7152 * g + 0.0722 * b

        def contrast(fg, bg):
            a = (fg >> 24) / 255
            fg = sum(round(a * ((fg >> s) & 0xFF) + (1 - a) * ((bg >> s) & 0xFF)) << s for s in (16, 8, 0))
            hi, lo = sorted((luminance(fg), luminance(bg)), reverse=True)
            return (hi + 0.05) / (lo + 0.05)

        on_bubble = ("chat_messageTextOut", "chat_messageLinkOut")
        for name, table in patch.THEME_FILES.items():
            rows = {key: (old, new) for key, old, new in table}
            old_bubble, new_bubble = rows["chat_outBubble"]
            old_end, new_end = rows.get("chat_outBubbleGradient", (None, None))
            ends = [(colour(old_bubble), colour(new_bubble)),
                    (colour(old_end if old_end is not None else old_bubble),
                     colour(new_end if new_end is not None else new_bubble))]
            for key, (old, new) in rows.items():
                if old is None or key.startswith("chat_outBubble"):
                    continue
                if not (key.startswith("chat_out") or key in on_bubble):
                    continue
                for telegram, pluma in ends:
                    self.assertGreaterEqual(contrast(colour(new), pluma), contrast(colour(old), telegram),
                                            f"{name} {key}")


# The accents of the default themes as the patch leaves them: (id, accent, my
# messages) by theme. The day themes shift from 0xFF328ACF, the night ones from
# 0xff3685fa.
FIXTURE_ACCENTS = {
    "Blue": (("99", "0xFF5B7A5E", "0x00000000"), ("0", "0xFF328ACF", "0x00000000")),
    "Day": (("9", "0xFF5B7A5E", "0x00000000"), ("0", "0xFF5B7A5E", "0x00000000")),
    "Arctic Blue": (("0", "0xFF5B7A5E", "0x00000000"),),
    "Night": (("0", "0xff9DBB9F", "0x00000000"),),
    "Dark Blue": (("0", "0xff9DBB9F", "0x00000000"),),
}
FIXTURE_BASES = {"Day": "0xFF328ACF", "Arctic Blue": "0xFF328ACF", "Night": "0xff3685fa", "Dark Blue": "0xff3685fa"}


def theme_java(changes=None, extra=""):
    """A Theme.java with the five default themes, as the patch leaves them.
    changes: {(theme, id): (accent, my messages)}. "Day" passes null for two
    of its arrays, as upstream does."""
    changes = changes or {}

    def theme(name):
        ids = [i for i, _, _ in FIXTURE_ACCENTS[name]]
        accents = [changes.get((name, i), (a, m)) for i, a, m in FIXTURE_ACCENTS[name]]
        n = len(ids)
        zeros = ", ".join(["0x00000000"] * n)
        slugs = ", ".join(['""'] * n)
        wallpaper = [f"new int[]    {{ {zeros} }},"] * 4
        if name == "Day":
            wallpaper[2:] = ["null,"] * 2
        rows = ([f"new int[]    {{ {', '.join(a for a, _ in accents)} }},",
                 f"new int[]    {{ {', '.join(m for _, m in accents)} }},", f"new int[]    {{ {zeros} }},"]
                + wallpaper
                + [f"new int[]    {{ {', '.join(ids)} }},", f"new String[] {{ {slugs} }},"]
                + [f"new int[]    {{ {', '.join(['0'] * n)} }},"] * 2)
        rows[-1] = rows[-1].rstrip(",")
        base = FIXTURE_BASES.get(name)
        return (f'        themeInfo.name = "{name}";\n'
                "        themeInfo.setAccentColorOptions(\n"
                + "".join(f"                {r}\n" for r in rows) +
                "                );\n" + (f"        themeInfo.accentBaseColor = {base};\n" if base else "") +
                "        sortAccents(themeInfo);\n"
                "        themes.add(themeInfo);\n")
    return ("        fallbackKeys.put(key_e, Theme.key_f);\n"
            "        themeAccentExclusionKeys.add(key_d);\n"
            "        for (int i = 0; i < keys_avatar.length; i++) {\n"
            "            themeAccentExclusionKeys.add(keys_avatar[i]);\n"
            "        }\n"
            "    public static int[] keys_avatar = {key_h};\n"
            + "".join(theme(name) for name in FIXTURE_ACCENTS)
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
    FILES = {asset: f"f={patch.argb('#9DBB9F' if dark else '#5B7A5E')}\n"
             for asset, _, dark in patch.DEFAULT_THEMES.values()}

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

    def test_theme_file_values(self):
        # As Theme.getThemeFileValues reads a theme file: not the wallpaper
        # link, nothing from the embedded wallpaper on, and not a last line a
        # newline does not end.
        text = "a=-1\nb=#80FF0000\nWLS=link\nc=5\nWPS\nd=1\nWPE\n"
        self.assertEqual(patch.theme_file_values(text), {"a": 0xFFFFFFFF, "b": 0x80FF0000, "c": 5})
        self.assertEqual(patch.theme_file_values("a=1\nb=2"), {"a": 1})

    def test_blue_left(self):
        # A Telegram blue the engine moves (a), one that falls back to a key of
        # the file (e), excluded keys (d, h), and blues the engine does not
        # reach, beyond 30 degrees from the base (c in the day themes, i in the
        # night ones), which the check names.
        self.assertEqual(patch.default_theme_blues(theme_java(), COLORS_JAVA, self.FILES),
                         {asset: ["i"] if dark else ["c"] for asset, _, dark in patch.DEFAULT_THEMES.values()})
        files = {k: v + f"c=#5B7A5E\ni={patch.argb('#5B7A5E')}\n" for k, v in self.FILES.items()}
        self.assertEqual(patch.default_theme_blues(theme_java(), COLORS_JAVA, files), dict.fromkeys(files, []))
        # A blue the theme file sets beyond the reach of the engine, in any of
        # the themes.
        for asset, _, dark in patch.DEFAULT_THEMES.values():
            with self.subTest(asset=asset):
                blue = dict(files, **{asset: files[asset] + ("b=#30C8D0\n" if dark else "b=#3030D0\n")})
                self.assertEqual(patch.default_theme_blues(theme_java(), COLORS_JAVA, blue)[asset], ["b"])
        # Not on a last line without a newline, which the app never reads.
        tail = dict(files, **{"day.attheme": files["day.attheme"] + "b=#3030D0"})
        self.assertEqual(patch.default_theme_blues(theme_java(), COLORS_JAVA, tail)["day.attheme"], [])
        # An accent shown before the user picks a colour that does not tint
        # leaves Telegram's blue: both of "Day" count.
        for theme, accents in FIXTURE_ACCENTS.items():
            for accent_id in [i for i, _, _ in accents if (theme, i) != ("Blue", "0")]:
                with self.subTest(theme=theme, accent=accent_id):
                    base = FIXTURE_BASES.get(theme, "0xFF328ACF")
                    out = patch.default_theme_blues(theme_java({(theme, accent_id): (base, "0x00000000")}),
                                                    COLORS_JAVA, files)
                    self.assertEqual(out[patch.DEFAULT_THEMES[theme][0]], ["a"])
        # Colours for my messages, which the check does not model, stop it.
        with self.assertRaisesRegex(patch.PatchError, "my messages"):
            patch.default_theme_blues(theme_java({("Day", "9"): ("0xFF5B7A5E", "0xFF6580DC")}), COLORS_JAVA, files)
        # A key the engine skips (h) is checked when the tables recolour it.
        with unittest.mock.patch.object(patch, "ALSO_CHECKED", ("h",)):
            self.assertEqual(patch.default_theme_blues(theme_java(), COLORS_JAVA, files), dict.fromkeys(files, ["h"]))
            sage = {k: v + f"h={patch.argb('#7FA082')}\n" for k, v in files.items()}
            self.assertEqual(patch.default_theme_blues(theme_java(), COLORS_JAVA, sage), dict.fromkeys(files, []))

    def test_default_accent_shortcuts(self):
        # Upstream's Theme.getColor answers Telegram's colours for the home
        # accent of the day theme, whatever the theme file says.
        upstream = ("            } else {\n"
                    "                useDefault = currentTheme.isDefaultMainAccent();\n"
                    "            }\n")
        for extra in (upstream, *patch.DEFAULT_ACCENT_SHORTCUTS):
            with self.subTest(extra=extra), self.assertRaises(patch.PatchError):
                patch.default_theme_blues(theme_java(extra=extra), COLORS_JAVA, self.FILES)

    def test_forced_bubbles(self):
        # Upstream forces blue to purple bubbles on every accent of "Night";
        # the patch leaves them to the accents other than its home one.
        def forced(condition):
            return ("                //override default themes\n"
                    f"                if ({condition}) {{\n"
                    "                    themeAccent.myMessagesAccentColor = 0xff258DE5;\n"
                    '                    if (name.equals("Night")) {\n'
                    "                        themeAccent.patternIntensity = -0.57f;\n"
                    "                    }\n"
                    "                }\n")
        patched = theme_java(extra=forced('name.equals("Night") && !isHome(themeAccent)'))
        self.assertEqual(patch.default_theme_blues(patched, COLORS_JAVA, self.FILES)["night.attheme"], ["i"])
        for condition in ('isHome(themeAccent) && name.equals("Dark Blue") || name.equals("Night")',
                          'name.equals("Night")'):
            with self.subTest(condition=condition), self.assertRaises(patch.PatchError):
                patch.default_theme_blues(theme_java(extra=forced(condition)), COLORS_JAVA, self.FILES)

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
