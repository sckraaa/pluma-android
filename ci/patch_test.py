#!/usr/bin/env python3
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
        self.assertEqual(files, set(patch.BRAND_ASSETS), "run brand/render.py and update BRAND_ASSETS")
        for rel in files:
            if rel.endswith((".png", ".webp")):
                data = (res / rel).read_bytes()
                self.assertEqual(data[:4] == b"RIFF", rel.endswith(".webp"), rel)
                self.assertGreater(min(patch.image_size(data)), 0, rel)
        groups = json.loads((patch.BRAND / "qr_login_logo.json").read_text())
        self.assertEqual([g["ty"] for g in groups], ["gr"] * 4)

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
