#!/usr/bin/env python3
import hashlib
import json
import pathlib
import re
import subprocess
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


# The mark writing itself on page 1 of the intro, as brand/mark_write.py writes it.
MARK_WRITE_SHA256 = "f5d89139ddab9cc3d1ffb2ec42c574307c37e92eb92f5d2413e8fc0855221c41"


def intro_text():
    """What the intro edits write into IntroActivity."""
    return "".join(new for rel, _, new in patch.INTRO_EDITS if rel == patch.INTRO)


def intro_method(name):
    """The method of IntroActivity of this name, as the edits write it."""
    found = re.findall(rf"\n    private \w+ {name}\([^)]*\) {{\n.*?\n    }}\n", intro_text(), re.S)
    if len(found) != 1:
        raise AssertionError(f"{name}: {len(found)} methods in the intro edits")
    return found[0]


def intro_constants(*names):
    """The values of IntroActivity's constants of these names, as the edits write them."""
    text = intro_text()
    out = []
    for name in names:
        found = re.findall(rf"\b{name} = ([\d.]+)f?[,;]", text)
        if len(found) != 1:
            raise AssertionError(f"{name}: {len(found)} definitions in the intro edits")
        out.append(float(found[0]))
    return out


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
    upstream = {"UPSTREAM_LAYER": "233", "UPSTREAM_VERSION": "13.2.1", "NDK_VERSION": "27.2.12479018", "CMAKE_VERSION": "3.22.1"}
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
        self.assertEqual(c.version_name, "13.2.1.00000")
        self.assertEqual(config(build=57).version_name, "13.2.1.00057")

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
            {"build": -1},
            {"build": 100000},
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


class VideoQualityTest(unittest.TestCase):
    # The upstream files, made of the texts the edits expect.
    def tree(self, root, edits=patch.VIDEO_QUALITY_EDITS):
        files = {}
        for rel, old, _ in edits:
            files[rel] = files.get(rel, "class X {\n") + old + "        x();\n"
        for rel, text in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text + "}\n", encoding="utf-8")
        return patch.Tree(root)

    def test_bitrates(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            with self.assertRaisesRegex(patch.PatchError, "is not there"):
                patch.verify_video_quality(tree)
            patch.video_quality(tree)
            patch.verify_video_quality(tree)
            caps = re.findall(r"maxBitrate = (\d+)_000;", tree.read(patch.MEDIA_CONTROLLER))
            self.assertEqual([int(c) * 1000 for c in caps], [12_000_000, 5_000_000, 2_500_000, 1_500_000])
            self.assertNotRegex(tree.read(patch.MEDIA_CONTROLLER), r"ompressFactor = 0\.\d+f;")
            viewer = tree.read(patch.PHOTO_VIEWER)
            self.assertIn("int maxCompression = Math.max(0, Math.min(this.compressionsCount - 1, Math.round(", viewer)
            self.assertIn("(100f / this.compressionsCount)) - 1));", viewer)
            self.assertIn("return maxCompression;", viewer)
            self.assertNotIn("(100f / compressionsCount)", viewer)
            self.assertNotIn("int maxCompression = 2;", viewer)
            downloads = tree.read(patch.DOWNLOAD_CONTROLLER)
            self.assertIn('"13_13_13_13_1048576_10485760_1048576_524288_1_1_1_0_85_1"', downloads)
            self.assertIn("preset.equals(oldMedium) || preset.equals(upstreamMedium)", downloads)
            self.assertNotIn("preset.equals(mediumPreset)", downloads)
            # The old presets are kept before the server's answer changes them.
            self.assertLess(downloads.index("final Preset oldMedium"), downloads.index("lowPreset.set(res.low);"))
            helper = tree.read(patch.SEND_MESSAGES_HELPER)
            self.assertEqual(re.findall(r"maxSize = (\d+)\.0f;", helper), ["480", "854", "1280", "1920"])
            self.assertIn("videoEditedInfo.originalHeight) > 1920) {", helper)
            self.assertNotIn("> 1280", helper)
            for rel in (patch.PHOTO_VIEWER, patch.VIDEO_CONVERTOR):
                self.assertNotIn("921600", tree.read(rel))
                self.assertIn("bitrate = 1843200;", tree.read(rel))
            # A second run finds none of the upstream texts.
            with self.assertRaises(patch.PatchError):
                patch.video_quality(tree)

    def test_upstream_changed(self):
        for i, (rel, old, _) in enumerate(patch.VIDEO_QUALITY_EDITS):
            changed = old.replace(" = ", " =  ", 1) if " = " in old else old.replace("(", "( ", 1)
            self.assertNotEqual(changed, old)
            edits = [(r, changed if j == i else o, n) for j, (r, o, n) in enumerate(patch.VIDEO_QUALITY_EDITS)]
            with self.subTest(edit=i), tempfile.TemporaryDirectory() as d:
                tree = self.tree(pathlib.Path(d), edits)
                with self.assertRaisesRegex(patch.PatchError, "0 occurrences"):
                    patch.video_quality(tree)
        # An anchor upstream uses twice.
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d), patch.VIDEO_QUALITY_EDITS + patch.VIDEO_QUALITY_EDITS[1:2])
            with self.assertRaisesRegex(patch.PatchError, "2 occurrences"):
                patch.video_quality(tree)

    def test_check(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            patch.video_quality(tree)
            for rel, old, new in patch.VIDEO_QUALITY_EDITS:
                patched = tree.read(rel)
                for text in (patched.replace(new, old), patched.replace(new, ""), patched + new):
                    with self.subTest(file=rel, edit=new.splitlines()[0]):
                        self.assertNotEqual(text, patched)
                        tree.write(rel, text)
                        with self.assertRaisesRegex(patch.PatchError, "is not there"):
                            patch.verify_video_quality(tree)
                tree.write(rel, patched)
            patch.verify_video_quality(tree)

class SavedTagsTest(unittest.TestCase):
    # Premium checks of upstream that are not about tags; they must stay.
    OTHER_PREMIUM = {
        patch.MESSAGES_CONTROLLER: "    public int getMaxUserReactionsCount() {\n"
                                   "        return getUserConfig().isPremium() ? reactionsUserMaxPremium : reactionsUserMaxDefault;\n"
                                   "    }\n",
        patch.CHAT_ACTIVITY: "        if (SharedConfig.multipleReactionsPromoShowed || cell == null || visibleReaction == null || "
                             "getUserConfig().isPremium()) {\n",
        patch.REACTIONS_CONTAINER: "        if (type == TYPE_TAGS && !UserConfig.getInstance(currentAccount).isPremium()) {\n"
                                   "            showExpandableReactions = false;\n",
    }

    # The upstream files, made of the texts the edits expect.
    def tree(self, root, edits=patch.SAVED_TAGS_EDITS):
        files = {}
        for rel, old, _ in edits:
            files[rel] = files.get(rel, "class X {\n" + self.OTHER_PREMIUM.get(rel, "")) + old + "        x();\n"
        for rel, text in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text + "}\n", encoding="utf-8")
        return patch.Tree(root)

    def test_tags_without_premium(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            with self.assertRaisesRegex(patch.PatchError, "is not there"):
                patch.verify_saved_tags(tree)
            patch.saved_tags(tree)
            patch.verify_saved_tags(tree)
            self.assertIn("    public boolean savedTagsAvailable() {\n        return true;\n    }\n",
                          tree.read(patch.MESSAGES_CONTROLLER))
            # Every tag place asks savedTagsAvailable() instead of Premium.
            for rel, _, new in patch.SAVED_TAGS_EDITS:
                self.assertNotIn("isPremium()", new)
                self.assertNotIn("userIsPremium", new)
                self.assertNotIn("premiumFeaturesBlocked", new)
            self.assertIn("if (isReactionsAvailable && (!tags || getMessagesController().savedTagsAvailable())) {",
                          tree.read(patch.CHAT_ACTIVITY))
            # A message takes as many tags as with Premium; reactions keep the
            # server's limit for a user without Premium.
            self.assertIn("int maxReactionsCount = areTags() ? MessagesController.getInstance(currentAccount)"
                          ".reactionsUserMaxPremium : MessagesController.getInstance(currentAccount)"
                          ".getMaxUserReactionsCount();", tree.read(patch.MESSAGE_OBJECT))
            # The other Premium checks stay as upstream has them.
            for rel, text in self.OTHER_PREMIUM.items():
                self.assertEqual(tree.read(rel).count(text), 1)
            # A second run finds none of the upstream texts.
            with self.assertRaises(patch.PatchError):
                patch.saved_tags(tree)

    def test_upstream_changed(self):
        for i, (rel, old, _) in enumerate(patch.SAVED_TAGS_EDITS):
            changed = old.replace("(", "( ", 1) if "(" in old else old.replace(" == ", " ==  ", 1)
            self.assertNotEqual(changed, old)
            edits = [(r, changed if j == i else o, n) for j, (r, o, n) in enumerate(patch.SAVED_TAGS_EDITS)]
            with self.subTest(edit=i), tempfile.TemporaryDirectory() as d:
                tree = self.tree(pathlib.Path(d), edits)
                with self.assertRaisesRegex(patch.PatchError, "0 occurrences"):
                    patch.saved_tags(tree)
        # An anchor upstream uses twice.
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d), patch.SAVED_TAGS_EDITS + patch.SAVED_TAGS_EDITS[2:3])
            with self.assertRaisesRegex(patch.PatchError, "2 occurrences"):
                patch.saved_tags(tree)

    def test_check(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            patch.saved_tags(tree)
            for rel, old, new in patch.SAVED_TAGS_EDITS:
                patched = tree.read(rel)
                for text in (patched.replace(new, old), patched.replace(new, ""), patched + new):
                    with self.subTest(file=rel, edit=new.splitlines()[1]):
                        self.assertNotEqual(text, patched)
                        tree.write(rel, text)
                        with self.assertRaisesRegex(patch.PatchError, "is not there"):
                            patch.verify_saved_tags(tree)
                tree.write(rel, patched)
            patch.verify_saved_tags(tree)
            # One more place that asks it: some other feature would open.
            for rel in patch.SAVED_TAGS_USES:
                patched = tree.read(rel)
                with self.subTest(file=rel):
                    tree.write(rel, patched + "        if (getMessagesController().savedTagsAvailable()) {\n")
                    with self.assertRaisesRegex(patch.PatchError, "uses of savedTagsAvailable"):
                        patch.verify_saved_tags(tree)
                tree.write(rel, patched)
            # The tags available only with Premium again.
            patched = tree.read(patch.MESSAGES_CONTROLLER)
            tree.write(patch.MESSAGES_CONTROLLER,
                       patched.replace("        return true;\n", "        return getUserConfig().isPremium();\n", 1))
            with self.assertRaises(patch.PatchError):
                patch.verify_saved_tags(tree)


class PremiumStickersTest(unittest.TestCase):
    # Premium checks of upstream that are not about premium stickers; they stay.
    OTHER_PREMIUM = {
        patch.EMOJI_VIEW: "            if (UserConfig.getInstance(currentAccount).isPremium()) {\n"
                          "                premiumStickers = MediaDataController.getInstance(currentAccount).getRecentStickers(MediaDataController.TYPE_PREMIUM_STICKERS);\n",
    }

    # The upstream files, made of the texts the edits expect.
    def tree(self, root, edits=patch.PREMIUM_STICKERS_EDITS):
        files = {}
        for rel, old, _ in edits:
            files[rel] = files.get(rel, "class X {\n" + self.OTHER_PREMIUM.get(rel, "")) + old + "        x();\n"
        for rel, text in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text + "}\n", encoding="utf-8")
        return patch.Tree(root)

    def test_stickers_without_premium(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            with self.assertRaisesRegex(patch.PatchError, "is not there"):
                patch.verify_premium_stickers(tree)
            patch.premium_stickers(tree)
            patch.verify_premium_stickers(tree)
            self.assertIn("    public boolean premiumStickersAvailable() {\n        return true;\n    }\n",
                          tree.read(patch.MESSAGES_CONTROLLER))
            self.assertIn("if (premiumStickersAvailable() || !premiumFeaturesBlocked() || stickerSet == null) {",
                          tree.read(patch.MESSAGES_CONTROLLER))
            # The sender's effect stays for what else Premium plays there.
            for rel, _, new in patch.PREMIUM_STICKERS_EDITS:
                if rel != patch.CHAT_ACTIVITY:
                    self.assertNotIn("isPremium()", new)
            self.assertIn("getUserConfig().isPremium() || (getMessagesController().premiumStickersAvailable() && messageObject.isPremiumSticker())",
                          tree.read(patch.CHAT_ACTIVITY))
            for rel, text in self.OTHER_PREMIUM.items():
                self.assertEqual(tree.read(rel).count(text), 1)
            # Both cells import the class they now ask.
            for rel in (patch.STICKER_CELL, patch.STICKER_EMOJI_CELL):
                self.assertEqual(tree.read(rel).count("import org.telegram.messenger.MessagesController;\n"), 1)
            with self.assertRaises(patch.PatchError):
                patch.premium_stickers(tree)

    def test_upstream_changed(self):
        for i, (rel, old, _) in enumerate(patch.PREMIUM_STICKERS_EDITS):
            changed = old.replace("(", "( ", 1) if "(" in old else old.replace("import", "import  ", 1)
            self.assertNotEqual(changed, old)
            edits = [(r, changed if j == i else o, n) for j, (r, o, n) in enumerate(patch.PREMIUM_STICKERS_EDITS)]
            with self.subTest(edit=i), tempfile.TemporaryDirectory() as d:
                tree = self.tree(pathlib.Path(d), edits)
                with self.assertRaisesRegex(patch.PatchError, "0 occurrences"):
                    patch.premium_stickers(tree)

    def test_check(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            patch.premium_stickers(tree)
            for rel, old, new in patch.PREMIUM_STICKERS_EDITS:
                patched = tree.read(rel)
                for text in (patched.replace(new, old), patched.replace(new, "")):
                    with self.subTest(file=rel, edit=new.splitlines()[0]):
                        self.assertNotEqual(text, patched)
                        tree.write(rel, text)
                        with self.assertRaisesRegex(patch.PatchError, "is not there"):
                            patch.verify_premium_stickers(tree)
                tree.write(rel, patched)
            patch.verify_premium_stickers(tree)
            for rel in patch.PREMIUM_STICKERS_USES:
                patched = tree.read(rel)
                with self.subTest(file=rel):
                    tree.write(rel, patched + "        if (getMessagesController().premiumStickersAvailable()) {\n")
                    with self.assertRaisesRegex(patch.PatchError, "uses of premiumStickersAvailable"):
                        patch.verify_premium_stickers(tree)
                tree.write(rel, patched)
            patched = tree.read(patch.MESSAGES_CONTROLLER)
            tree.write(patch.MESSAGES_CONTROLLER,
                       patched.replace("        return true;\n", "        return getUserConfig().isPremium();\n", 1))
            with self.assertRaises(patch.PatchError):
                patch.verify_premium_stickers(tree)


class SelfUpdateTest(unittest.TestCase):
    COMPONENTS = {"UpdateAppAlertDialog.java": b"class UpdateAppAlertDialog {}\n", "UpdateLayout.java": b"class UpdateLayout {}\n"}

    # The upstream files, made of the texts the edits expect, and the
    # standalone module's sheet and panel.
    def tree(self, root):
        files = {}
        for rel, old, _ in patch.SELF_UPDATE_EDITS:
            files[rel] = files.get(rel, "class X {\n") + old + "        x();\n"
        for rel, text in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text + "}\n", encoding="utf-8")
        (root / patch.APP_LOADER_IMPL).parent.mkdir(parents=True, exist_ok=True)
        (root / patch.APP_LOADER_IMPL).write_text(patch.APP_LOADER_IMPL_UPSTREAM, encoding="utf-8")
        (root / "gradle.properties").write_text("APP_VERSION_CODE=7291\nAPP_VERSION_NAME=13.2.1\n", encoding="utf-8")
        (root / patch.APP_BUILD_GRADLE).write_text("android {\n" + patch.VERSION_CODE + "    defaultConfig {\n" + patch.VERSION_NAME
                                                   + "    }\n}\ndependencies {\n" + patch.APP_DEPENDENCY + "}\n",
                                                   encoding="utf-8")
        (root / "TMessagesProj/build.gradle").write_text("dependencies {\n" + patch.ANDROIDX_CORE + "}\n", encoding="utf-8")
        (root / patch.STANDALONE_COMPONENTS).mkdir(parents=True)
        for name, data in self.COMPONENTS.items():
            (root / patch.STANDALONE_COMPONENTS / name).write_bytes(data)
        return patch.Tree(root)

    def setUp(self):
        shas = {name: hashlib.sha256(data).hexdigest() for name, data in self.COMPONENTS.items()}
        p = unittest.mock.patch.object(patch, "SELF_UPDATE_FILES", shas)
        p.start()
        self.addCleanup(p.stop)

    def test_self_update(self):
        c = config(build=57)
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            with self.assertRaisesRegex(patch.PatchError, "is not there"):
                patch.verify_self_update(tree, c)
            patch.self_update(tree, c)
            patch.verify_self_update(tree, c)
            # Only the update places ask the new method; isStandaloneBuild()
            # keeps every other place of the standalone build off.
            for rel, _, new in patch.SELF_UPDATE_EDITS[1:]:
                self.assertNotIn("isStandaloneBuild()", new)
            self.assertIn("public static boolean isSelfUpdatingBuild() {\n        return true;\n    }\n",
                          tree.read(patch.APPLICATION_LOADER))
            self.assertNotIn("isStandalone()", tree.read(patch.APP_LOADER_IMPL))
            for name, data in self.COMPONENTS.items():
                self.assertEqual((tree.root / patch.APP_COMPONENTS / name).read_bytes(), data)
            # The library keeps upstream's version; the app module gets the build.
            self.assertIn("APP_VERSION_NAME=13.2.1\n", tree.read("gradle.properties"))
            self.assertIn('        versionName APP_VERSION_NAME + ".00057" // pluma: 13.2.1.00057, the build number\n',
                          tree.read(patch.APP_BUILD_GRADLE))
            self.assertIn("Integer.parseInt(APP_VERSION_CODE) * 1000 + 57 ", tree.read(patch.APP_BUILD_GRADLE))
            # A second run finds none of the upstream texts.
            with self.assertRaises(patch.PatchError):
                patch.self_update(tree, c)

    def test_upstream_changed(self):
        c = config()
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            (tree.root / patch.STANDALONE_COMPONENTS / "UpdateLayout.java").write_bytes(b"class UpdateLayout { int x; }\n")
            with self.assertRaisesRegex(patch.PatchError, "changed upstream"):
                patch.self_update(tree, c)
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            tree.write(patch.APP_LOADER_IMPL, patch.APP_LOADER_IMPL_UPSTREAM.replace("}\n}\n", "}\n    void y() {}\n}\n"))
            with self.assertRaisesRegex(patch.PatchError, "0 occurrences"):
                patch.self_update(tree, c)

    def test_check(self):
        c = config(build=3)
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            patch.self_update(tree, c)
            for rel, old, new in patch.SELF_UPDATE_EDITS:
                patched = tree.read(rel)
                with self.subTest(file=rel, edit=new.strip().splitlines()[-1]):
                    tree.write(rel, patched.replace(new, old))
                    with self.assertRaisesRegex(patch.PatchError, "is not there"):
                        patch.verify_self_update(tree, c)
                tree.write(rel, patched)
            # One more place that asks it.
            for rel in patch.SELF_UPDATE_USES:
                patched = tree.read(rel)
                with self.subTest(file=rel):
                    tree.write(rel, patched + "        if (ApplicationLoader.isSelfUpdatingBuild()) {\n")
                    with self.assertRaisesRegex(patch.PatchError, "uses of"):
                        patch.verify_self_update(tree, c)
                tree.write(rel, patched)
            # Another build number than the configuration's.
            with self.assertRaisesRegex(patch.PatchError, "versionName"):
                patch.verify_self_update(tree, config(build=4))
            patch.verify_self_update(tree, c)


class LinksTest(unittest.TestCase):
    STRINGS = {
        "values": '<string name="GroupDescription3">Public links such as t.me/title</string>\n'
                  '<string name="TelegramFeaturesUrl">https://t.me/TelegramTips</string>\n',
        "values-de": '<string name="TelegramFeaturesUrl">https://t.me/TelegramTipsDE</string>\n',
    }

    # The upstream files, made of the texts the edits expect, with the t.me
    # literals and host checks upstream keeps.
    def tree(self, root, edits=patch.LINKS_EDITS, strings=STRINGS):
        files, kept = {}, {}
        for rel, old, new, count in edits:
            files[rel] = files.get(rel, "") + (old + "\n") * count
            kept[rel] = kept.get(rel, "") + (new + "\n") * count
        for rel, (full, bare) in patch.LINKS_OUT.items():
            rel = f"{patch.JAVA}/{rel}"
            files[rel] = files.get(rel, "") + 'share("https://t.me/" + name);\n' * full + 'show("t.me/" + name);\n' * bare
        for rel, n in patch.LINKS_KEEP.items():
            rel = f"{patch.JAVA}/{rel}"
            n -= len(patch.LINK_LITERAL.findall(kept.get(rel, "")))
            # The kept literals are not of the forms the table replaces.
            files[rel] = files.get(rel, "") + 'open("http://t.me/BotFather");\n' * n
        for rel, n in patch.HOSTS_KEEP.items():
            rel = f"{patch.JAVA}/{rel}"
            files[rel] = files.get(rel, "") + 'if ("t.me".equals(uri.getHost())) {}\n' * n
        for lang, text in strings.items():
            files[f"{patch.RES}/{lang}/strings.xml"] = text
        for rel, text in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text, encoding="utf-8")
        return patch.Tree(root)

    def test_links(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            with self.assertRaisesRegex(patch.PatchError, "is not there"):
                patch.verify_links(tree)
            patch.links(tree)
            patch.verify_links(tree)
            for rel in patch.LINKS_OUT:
                self.assertNotRegex(tree.read(f"{patch.JAVA}/{rel}"), r'"(?:https://)?t\.me/" \+ name')
            self.assertIn('"https://pluma.chat/" + name', tree.read(f"{patch.JAVA}/ui/ChatActivity.java"))
            self.assertIn('show("pluma.chat/" + name)', tree.read(f"{patch.JAVA}/ui/Cells/StickerSetCell.java"))
            manifest = tree.read(f"{patch.MAIN}/AndroidManifest.xml")
            self.assertEqual(manifest.count('<data android:host="pluma.chat" android:scheme="https" />'), 1)
            self.assertEqual(manifest.count('<intent-filter android:autoVerify="true">'), 1)
            # pluma.chat is only in the filter with the paths of links.
            for block in re.findall(r"<intent-filter.*?</intent-filter>", manifest, re.S):
                if "pluma.chat" in block:
                    self.assertIn('android:autoVerify="true"', block)
                    self.assertIn('<data android:pathPrefix="/joinchat/" />', block)
                    self.assertIn('<data android:pathPrefix="/webproxy" />', block)
                    self.assertIn('<data android:pathAdvancedPattern="/[A-Za-z][A-Za-z0-9_]{4,31}" />', block)
                    self.assertNotIn("android:pathPattern", block)
            self.assertIn('<data android:scheme="https"/>', manifest)
            browser = tree.read(f"{patch.JAVA}/messenger/browser/Browser.java")
            for name in patch.LINK_SITE_PATHS:
                self.assertIn(f'"{name}"', browser)
            self.assertIn("return plumaUsername(link.substring(19));", browser)
            self.assertIn("pluma.chat/title", tree.read(f"{patch.RES}/values/strings.xml"))
            self.assertIn("https://t.me/TelegramTipsDE", tree.read(f"{patch.RES}/values-de/strings.xml"))
            # A second run finds none of the upstream texts.
            with self.assertRaises(patch.PatchError):
                patch.links(tree)

    def test_upstream_changed(self):
        for i, (_, old, _, _) in enumerate(patch.LINKS_EDITS):
            changed = old[0] + "x" + old[1:]
            edits = [(r, changed if j == i else o, n, c) for j, (r, o, n, c) in enumerate(patch.LINKS_EDITS)]
            with self.subTest(edit=old.strip()[:60]), tempfile.TemporaryDirectory() as d:
                tree = self.tree(pathlib.Path(d), edits)
                with self.assertRaisesRegex(patch.PatchError, "0 occurrences"):
                    patch.links(tree)
        # One more outgoing t.me link in a file of the table.
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            rel = f"{patch.JAVA}/ui/PhotoViewer.java"
            tree.write(rel, tree.read(rel) + 'share("https://t.me/" + name);\n')
            with self.assertRaisesRegex(patch.PatchError, "3 occurrences"):
                patch.links(tree)
        # The text about public links in a bundled translation too.
        strings = dict(self.STRINGS, **{"values-de": self.STRINGS["values"]})
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d), strings=strings)
            with self.assertRaisesRegex(patch.PatchError, "GroupDescription3 in values, values-de"):
                patch.links(tree)

    def test_check(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            patch.links(tree)
            for rel, old, new, _ in patch.LINKS_EDITS:
                patched = tree.read(rel)
                with self.subTest(edit=old.strip()[:60]):
                    tree.write(rel, patched.replace(new, old))
                    with self.assertRaisesRegex(patch.PatchError, "is not there"):
                        patch.verify_links(tree)
                tree.write(rel, patched)
            patch.verify_links(tree)
            # A new t.me link anywhere, a new t.me host check without
            # pluma.chat, a new built-in text with t.me.
            for rel, extra, error in (
                    (f"{patch.JAVA}/ui/ProfileActivity.java", 'share("https://t.me/" + name);\n', "t.me links left"),
                    (f"{patch.JAVA}/ui/PhotoViewer.java", 'show("t.me/" + name);\n', "t.me links left"),
                    (f"{patch.JAVA}/ui/LaunchActivity.java", 'if (host.equals("telegram.me")) {}\n', "host checks"),
                    (f"{patch.JAVA}/ui/LinkManager.java", 'if ("t.me".equalsIgnoreCase(host)) {}\n', "host checks"),
                    (f"{patch.RES}/values-de/strings.xml", '<string name="X">Links wie t.me/name</string>\n',
                     "X still shows t.me")):
                path = tree.root / rel
                patched = path.read_text(encoding="utf-8") if path.exists() else None
                with self.subTest(file=rel, extra=extra):
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text((patched or "") + extra, encoding="utf-8")
                    with self.assertRaisesRegex(patch.PatchError, error):
                        patch.verify_links(tree)
                if patched is None:
                    path.unlink()
                else:
                    path.write_text(patched, encoding="utf-8")
            patch.verify_links(tree)

    def test_tables(self):
        for rel, old, new, count in patch.LINKS_EDITS:
            self.assertTrue(patch.LINK_HOST in new or r"pluma\\.chat" in new, new)
            self.assertNotIn(patch.LINK_HOST, old)
            self.assertGreater(count, 0)
        for rel, counts in patch.LINKS_OUT.items():
            self.assertGreater(sum(counts), 0, rel)
        for table in (patch.LINKS_KEEP, patch.HOSTS_KEEP):
            self.assertTrue(all(n > 0 for n in table.values()))
        self.assertFalse({key for key, _, _, _ in patch.LINK_STRINGS} & patch.LINK_STRINGS_KEEP)

    def test_site_paths(self):
        # The site's paths, the same list in every client.
        self.assertEqual(patch.LINK_SITE_PATHS, (
            "iphone", "ipad", "android", "mac", "windows", "linux", "web", "pero", "app", "en", "dl", "ios",
            "collect", "assets", "_l", ".well-known",
            "favicon.svg", "og.png", "apple-touch-icon.png", "404.html", "progress.json"))
        self.assertEqual(len(set(patch.LINK_SITE_PATHS)), len(patch.LINK_SITE_PATHS))
        self.assertTrue(all(p == p.lower() for p in patch.LINK_SITE_PATHS))
        # No link prefix the manifest takes is a page of the site.
        for prefix in patch.LINK_PATH_PREFIXES:
            self.assertTrue(prefix.startswith("/"), prefix)
            self.assertNotIn(prefix.strip("/").lower(), patch.LINK_SITE_PATHS)

    def test_username_patterns(self):
        # The manifest's patterns read as Android's advanced glob does: the
        # whole path, a set or a dot with an optional count, no alternatives.
        def matches(path):
            return any(re.fullmatch(p, path) for p in patch.LINK_USERNAME_PATTERNS)
        for path in ("/durov", "/Durov_1", "/durov/123", "/durov/s/5", "/durov/", "/a" + "b" * 31):
            self.assertTrue(matches(path), path)
        for path in ("/", "/abcd", "/1abcd", "/_abcd", "/a" + "b" * 32, "/en/iphone", "/ipad", "/dl/x",
                     "/.well-known/assetlinks.json", "/favicon.svg", "/_l/x", "/pero", "/web"):
            self.assertFalse(matches(path), path)
        # The site's words of 5 letters and more still match: the app opens
        # those in the browser (Browser.isPlumaSite in LaunchActivity).
        self.assertEqual(sorted(p for p in patch.LINK_SITE_PATHS if matches("/" + p)),
                         ["android", "assets", "collect", "iphone", "linux", "windows"])


class SchemeTest(unittest.TestCase):
    # The files the scheme edits read, with the literals they expect.
    def tree(self, root):
        files = {f"{patch.JAVA}/{rel}": '"tg://x";\n' * colon + '"tg";\n' * bare
                 for rel, (colon, bare) in patch.SCHEME_JAVA.items()}
        link_manager = f"{patch.JAVA}/{patch.SCHEME_REGEX[0]}"
        files[link_manager] = files.get(link_manager, "") + patch.SCHEME_REGEX[1] + "\n"
        files[f"{patch.JAVA}/messenger/AndroidUtilities.java"] += "|ton|tg|tonsite):\n"
        files[f"{patch.JAVA}/messenger/LinkifyPort.java"] = "|ton|tg|tonsite)://\n"
        files[f"{patch.MAIN}/AndroidManifest.xml"] = '<data android:scheme="tg" />\n'
        files[f"{patch.RES}/xml/shortcuts.xml"] = 'android:value="tg://x"\n' * 6
        for rel, text in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text, encoding="utf-8")
        return patch.Tree(root)

    def test_scheme_of_the_new_places(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            patch.brand_scheme(tree)
            for rel in ("utils/proxy/ProxySettings.java", "ui/Cells/ChatMessageBotButtons.java",
                        "ui/QrShare/QrScanOverlay.java", "messenger/NotificationsController.java"):
                text = tree.read(f"{patch.JAVA}/{rel}")
                self.assertIn('"plm:', text, rel)
                self.assertNotRegex(text, patch.SCHEME_LITERAL)
            link_manager = tree.read(f"{patch.JAVA}/{patch.SCHEME_REGEX[0]}")
            self.assertNotIn(patch.SCHEME_REGEX[1], link_manager)
            self.assertIn(patch.SCHEME_REGEX[2], link_manager)


class StickerSetsTest(unittest.TestCase):
    def tree(self, root, text):
        (root / patch.MESSAGES_CONTROLLER).parent.mkdir(parents=True, exist_ok=True)
        (root / patch.MESSAGES_CONTROLLER).write_text(text, encoding="utf-8")
        return patch.Tree(root)

    def test_kind_of_sets(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d), "x\n" + patch.STICKER_SETS_OLD + "y\n")
            with self.assertRaises(patch.PatchError):
                patch.verify_sticker_sets(tree)
            patch.sticker_sets(tree)
            patch.verify_sticker_sets(tree)
            text = tree.read(patch.MESSAGES_CONTROLLER)
            self.assertIn("type = MediaDataController.TYPE_EMOJIPACKS;", text)
            self.assertNotIn("loadStickers(MediaDataController.TYPE_IMAGE, false, true)", text)

    def test_upstream_changed(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d), patch.STICKER_SETS_OLD.replace("TYPE_IMAGE", "TYPE_IMAGE "))
            with self.assertRaises(patch.PatchError):
                patch.sticker_sets(tree)


class BrandTest(unittest.TestCase):
    def test_rename_strings(self):
        xml = ('<string name="TelegramFAQ">Telegram FAQ</string>\n'
               '<string name="Tips">https://t.me/TelegramTips</string>\n'
               '<string name="Faq">https://telegram.org/faq and Telegram.org</string>\n'
               '<string name="A">__Telegram Premium.__ Use Telegram. INVITE TO TELEGRAM</string>\n'
               '<string name="B">Telegramm, @Telegram, Telegram\'s</string>\n'
               '<string name="C">텔레그램이 텔레그램</string>\n'
               '<string name="D">no linked\\nTelegram account, Telegram</string>\n')
        out, counts = patch.rename_strings(xml, (("텔레그램이", "Pluma가", 1), ("텔레그램", "Pluma", 1)))
        self.assertEqual(out, '<string name="TelegramFAQ">Pluma FAQ</string>\n'
                              '<string name="Tips">https://t.me/TelegramTips</string>\n'
                              '<string name="Faq">https://telegram.org/faq and Telegram.org</string>\n'
                              '<string name="A">__Pluma Premium.__ Use Pluma. INVITE TO PLUMA</string>\n'
                              '<string name="B">Telegramm, @Telegram, Pluma\'s</string>\n'
                              '<string name="C">Pluma가 Pluma</string>\n'
                              '<string name="D">no linked\\nPluma account, Pluma</string>\n')
        self.assertEqual((counts["Telegram"], counts["TELEGRAM"], counts["텔레그램이"], counts["텔레그램"]), (6, 1, 1, 1))
        self.assertTrue(patch.JAVA_NAME_LITERAL.search(r'text = "no linked\nTelegram account";'))
        self.assertFalse(patch.JAVA_NAME_LITERAL.search(r'text = "no linked\nTelegramm";'))

    def test_invite_link(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            for rel in patch.INVITE_LINK_FILES:
                (root / patch.JAVA / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / patch.JAVA / rel).write_text('link = "https://telegram.org/dl";\n', encoding="utf-8")
            tree = patch.Tree(root)
            patch.brand_invite_link(tree)
            for rel in patch.INVITE_LINK_FILES:
                self.assertEqual(tree.read(f"{patch.JAVA}/{rel}"), 'link = "https://pluma.chat/";\n')
            with self.assertRaises(patch.PatchError):
                patch.brand_invite_link(tree)
        self.assertFalse(set(patch.INVITE_LINK_FILES) & set(patch.TELEGRAM_SITE_KEEP))

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

    def test_mark_write_animation(self):
        # brand/mark_write.py writes the same bytes from the kit's mark again,
        # the file BRAND_ADDED names, and prints the resting ink box the intro
        # lays the mark out by.
        rel = "raw/pluma_mark_write.json"
        data = (patch.BRAND / "res" / rel).read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), MARK_WRITE_SHA256)
        self.assertEqual(patch.BRAND_ADDED[rel], MARK_WRITE_SHA256)
        with tempfile.TemporaryDirectory() as d:
            out = pathlib.Path(d) / "mark_write.json"
            run = subprocess.run([sys.executable, "-I", str(patch.BRAND.parent / "mark_write.py"),
                                  str(patch.BRAND.parent / "svg/pluma-mark.svg"), str(out)],
                                 check=True, capture_output=True, text=True)
            self.assertEqual(out.read_bytes(), data, "run brand/render.py")
        box = re.search(r"resting ink box x ([\d.]+)\.\.([\d.]+) y ([\d.]+)\.\.([\d.]+)", run.stdout)
        self.assertIsNotNone(box, run.stdout)
        self.assertEqual(intro_constants("MARK_INK_LEFT", "MARK_INK_RIGHT", "MARK_INK_TOP", "MARK_INK_BOTTOM"),
                         [float(v) for v in box.groups()])
        # What IntroActivity relies on: the kit's grid and frame rate, the
        # layer names it recolours, the kit's light ink drawn first.
        anim = json.loads(data)
        self.assertEqual((anim["w"], anim["h"], anim["fr"], anim["ip"], anim["op"]), (512, 512, 60, 0, 132))
        self.assertEqual(intro_constants("MARK_GRID"), [512])
        self.assertEqual([layer["nm"] for layer in anim["layers"]], ["Quill", "Feather1", "Feather2", "Feather3", "Ring"])
        self.assertEqual(re.findall(r'"(\w+)\.\*\*"', intro_text()), ["Ring", "Feather1", "Feather2", "Feather3"])
        inks = []
        for name in ("Ring", "Feather1", "Feather2", "Feather3"):
            layer = patch.brand_layer(anim, rel, name, None)
            stroke = [it for it in layer["shapes"][0]["it"] if it["ty"] == "st"]
            inks.append("#%02X%02X%02X" % tuple(int(c * 255) for c in stroke[0]["c"]["k"][:3]))
        self.assertEqual(inks, ["#111111", "#4A4A4A", "#8A8A8A", "#BDBDBD"])

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


class IntroTest(unittest.TestCase):
    # IntroActivity and IntroRenderer.c as upstream writes them, from the texts
    # the edits expect.
    UPSTREAM = {rel: "".join(old + "\n" for r, old, _ in patch.INTRO_EDITS if r == rel)
                for rel in (patch.INTRO, patch.INTRO_RENDERER)}
    UPSTREAM[patch.INTRO_RENDERER] += patch.INTRO_PACE[1]

    def tree(self, root, texts=None):
        for rel, text in (texts or self.UPSTREAM).items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text, encoding="utf-8")
        return patch.Tree(root)

    def test_page_one_shows_the_mark(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            # Upstream's page 1: the disc and the plane, the old layout.
            with self.assertRaisesRegex(patch.PatchError, "is still there"):
                patch.verify_intro(tree)
            patch.brand_intro(tree)
            patch.verify_intro(tree)
            renderer = tree.read(patch.INTRO_RENDERER)
            self.assertNotIn("telegram_sphere", renderer)
            self.assertNotIn("telegram_plane", renderer)
            # The speedometer of page 2 fades out on page 1 and in on page 2,
            # with no disc over it, at the pace the mark crosses with.
            self.assertIn("fast_body.params.alpha = t(1, 0, 0, duration_const, Linear);", renderer)
            self.assertIn("fast_body.params.alpha = t(0, 1, 0, duration_const, Linear);", renderer)
            self.assertNotIn("fast_body.params.alpha = 1;", renderer)
            self.assertEqual(patch.INTRO_PACE, (patch.INTRO_RENDERER, "static float duration_const = 0.3f;\n"))
            self.assertEqual(intro_constants("MARK_FADE_MS"), [300])
            # A second run finds none of the upstream texts.
            with self.assertRaises(patch.PatchError):
                patch.brand_intro(tree)

    def test_layout(self):
        # Layout B, its three numbers on one line: the mark's ink 128 dp high,
        # 32 dp over the wordmark, the group from the mark to the dots at 44 %
        # of the free space; the start button 24 dp over the navigation bar.
        self.assertEqual(intro_constants("MARK_DP", "MARK_GAP_DP", "MARK_BIAS", "BUTTON_BOTTOM_DP"), [128, 32, 0.44, 24])
        self.assertEqual(len(re.findall(r"\bfloat MARK_DP = [\d.]+, MARK_GAP_DP = [\d.]+, MARK_BIAS = [\d.]+f;\n",
                                        intro_text())), 1)
        # The kit's ink, light and dark.
        text = intro_text()
        self.assertIn("MARK_INK_LIGHT = {0xFF111111, 0xFF4A4A4A, 0xFF8A8A8A, 0xFFBDBDBD};", text)
        self.assertIn("MARK_INK_DARK = {0xFFE8ECE8, 0xFFBDBDBD, 0xFF8A8A8A, 0xFF6B6F6B};", text)

    def test_upstream_changed(self):
        for i, (rel, old, _) in enumerate(patch.INTRO_EDITS):
            with self.subTest(edit=i), tempfile.TemporaryDirectory() as d:
                texts = dict(self.UPSTREAM)
                texts[rel] = texts[rel].replace(old, re.sub(r"(\S)", r"\1 ", old, count=1))
                with self.assertRaises(patch.PatchError):
                    patch.brand_intro(self.tree(pathlib.Path(d), texts))
        # The pace of IntroRenderer's pictures, which the mark crosses with.
        with tempfile.TemporaryDirectory() as d:
            texts = dict(self.UPSTREAM)
            texts[patch.INTRO_RENDERER] = texts[patch.INTRO_RENDERER].replace("0.3f", "0.25f")
            with self.assertRaisesRegex(patch.PatchError, "duration_const"):
                patch.brand_intro(self.tree(pathlib.Path(d), texts))
        # The old layout or a sprite of page 1 somewhere the edits do not reach.
        for rel, s in patch.INTRO_GONE:
            with self.subTest(gone=s), tempfile.TemporaryDirectory() as d:
                texts = dict(self.UPSTREAM)
                texts[rel] += s + "\n"
                with self.assertRaisesRegex(patch.PatchError, "is still there"):
                    patch.brand_intro(self.tree(pathlib.Path(d), texts))

    def test_check(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            patch.brand_intro(tree)
            patched = {rel: tree.read(rel) for rel in self.UPSTREAM}
            for rel, old, new, error in (
                (patch.INTRO_RENDERER, "        rglNormalDraw();\n    } else if (current_page == 2) {\n",
                 "        rglNormalDraw();\n        draw_textured_shape(&telegram_sphere, main_matrix, NORMAL);\n"
                 "    } else if (current_page == 2) {\n", "telegram_"),
                (patch.INTRO, "showMark(i == 0, true);", "", "incomplete"),
                (patch.INTRO, "showMark(viewPager.getCurrentItem() == 0, false);", "", "incomplete"),
                (patch.INTRO, "R.raw.pluma_mark_write, markSize", "R.raw.sun, markSize", "incomplete"),
            ):
                with self.subTest(error=error, new=new):
                    self.assertIn(old, patched[rel])
                    tree.write(rel, patched[rel].replace(old, new))
                    with self.assertRaisesRegex(patch.PatchError, error):
                        patch.verify_intro(tree)
                    tree.write(rel, patched[rel])

    def test_every_edit_is_checked(self):
        # verify_intro, which verify_brand runs on the patched tree, fails when
        # any one of the edits is missing.
        for i in range(len(patch.INTRO_EDITS)):
            with self.subTest(edit=i), tempfile.TemporaryDirectory() as d:
                tree = self.tree(pathlib.Path(d))
                for rel, old, new in patch.INTRO_EDITS[:i] + patch.INTRO_EDITS[i + 1:]:
                    tree.replace(rel, old, new)
                with self.assertRaises(patch.PatchError):
                    patch.verify_intro(tree)

    def test_mark_frames(self):
        # With the system's animations off the written mark is chosen before
        # the view starts decoding (setAnimation). RLottieDrawable's worker
        # reads the frame again after a decode: a frame set meanwhile would be
        # taken for the end, and the intro would keep the decoded first frame.
        # showMark then leaves that frame as it is.
        text = intro_text()
        still = "markDrawable.setCurrentFrame(markDrawable.getFramesCount() - 1, true);\n"
        self.assertEqual(text.count(still), 1)
        self.assertLess(text.index('new RLottieDrawable(R.raw.pluma_mark_write, markSize'), text.index(still))
        self.assertLess(text.index(still), text.index("markView.setAnimation(markDrawable);\n"))
        show = intro_method("showMark")
        self.assertIn("            } else if (!markDrawable.isLastFrame()) {\n", show)
        # A replay draws nothing until its first frame is decoded rather than
        # the written mark of the time before; only that reset blanks it.
        self.assertIn("                markDrawable.setInvalidateOnProgressSet(true);\n"
                      "                markDrawable.setCurrentFrame(0, true, true);\n"
                      "                markDrawable.setInvalidateOnProgressSet(false);\n"
                      "                markView.playAnimation();\n", show)
        self.assertEqual(text.count("setInvalidateOnProgressSet("), 2)
        # The ink: the four layers in one decode, and only when the theme's
        # ink changes, not at every step of an animated theme change.
        self.assertRegex(intro_method("updateMarkInk"),
                         r"\n        if \(ink == markInk\) \{\n            return;\n        \}\n"
                         r"        markInk = ink;\n"
                         r"        markDrawable\.beginApplyLayerColors\(\);\n"
                         r"        for \([^\n]*\n            markView\.setLayerColor\([^\n]*\n        \}\n"
                         r"        markDrawable\.commitApplyLayerColors\(\);\n    \}\n$")
        self.assertIn("        markInk = null;\n", intro_method("releaseMark"))


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

    def test_verified_badge(self):
        # The fixture's badge: the rosette a, the accent f; the check g, the
        # text on the accent i. The accent engine moves the blue rosette near
        # the accent but not onto it, and the check stays as it is.
        badge = (("a", "f"), ("g", "i"))
        with unittest.mock.patch.object(patch, "VERIFIED_BADGE", badge):
            self.assertEqual(patch.default_theme_badges(theme_java(), COLORS_JAVA, self.FILES),
                             dict.fromkeys(self.FILES, ["a", "g"]))
            # The theme files give both parts the accent and the text on it.
            files = {asset: text + f"a={patch.argb('#9DBB9F' if dark else '#5B7A5E')}\n"
                     f"g={patch.argb('#131513' if dark else '#FFFFFF')}\n"
                     f"i={patch.argb('#131513' if dark else '#FFFFFF')}\n"
                     for (asset, _, dark), text in zip(patch.DEFAULT_THEMES.values(), self.FILES.values())}
            self.assertEqual(patch.default_theme_badges(theme_java(), COLORS_JAVA, files), dict.fromkeys(files, []))
            # A check left white on the light sage of a dark theme.
            night = dict(files, **{"night.attheme": files["night.attheme"] + "g=-1\n"})
            self.assertEqual(patch.default_theme_badges(theme_java(), COLORS_JAVA, night)["night.attheme"], ["g"])
        # A key upstream renamed stops the check instead of passing it.
        with unittest.mock.patch.object(patch, "VERIFIED_BADGE", (("x", "f"),)):
            with self.assertRaisesRegex(patch.PatchError, "no colour key x"):
                patch.default_theme_badges(theme_java(), COLORS_JAVA, self.FILES)

    def test_verified_badge_tables(self):
        # Each theme table gives the badge the accent and the text on it of
        # the same table, and every part of the badge is in every table.
        for name, table in patch.THEME_FILES.items():
            colours = {k: c for k, _, c in table}
            for key, like in patch.VERIFIED_BADGE:
                with self.subTest(theme=name, key=key):
                    self.assertEqual(colours[key], colours[like])

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


class PremiumForEveryoneTest(unittest.TestCase):
    # The upstream files, made of the texts the edits expect.
    def tree(self, root, edits=patch.PREMIUM_FOR_EVERYONE_EDITS):
        (root / "TMessagesProj").mkdir(exist_ok=True)
        files = {}
        for edit in edits:
            rel, old = edit[0], edit[1]
            count = edit[3] if len(edit) > 3 else 1
            files[rel] = files.get(rel, "") + (old + "x\n") * count
        for rel, text in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text, encoding="utf-8")
        return patch.Tree(root)

    def test_applies(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            with self.assertRaisesRegex(patch.PatchError, "the edit of task 071 is not there"):
                patch.verify_premium_for_everyone(tree)
            patch.premium_for_everyone(tree)
            patch.verify_premium_for_everyone(tree)
            # A second run is refused: nothing is left to edit.
            with self.assertRaises(patch.PatchError):
                patch.premium_for_everyone(tree)

    def test_upstream_changed(self):
        for i, edit in enumerate(patch.PREMIUM_FOR_EVERYONE_EDITS):
            changed = edit[1][:-2] + "~" + edit[1][-1]
            edits = [e if j != i else (edit[0], changed) + tuple(edit[2:]) for j, e in enumerate(patch.PREMIUM_FOR_EVERYONE_EDITS)]
            with self.subTest(edit=i), tempfile.TemporaryDirectory() as d:
                tree = self.tree(pathlib.Path(d), edits)
                with self.assertRaisesRegex(patch.PatchError, "occurrences"):
                    patch.premium_for_everyone(tree)

    def test_check(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            patch.premium_for_everyone(tree)
            for edit in patch.PREMIUM_FOR_EVERYONE_EDITS:
                rel, old, new = edit[0], edit[1], edit[2]
                patched = tree.read(rel)
                tree.write(rel, patched.replace(new, old))
                with self.subTest(file=rel), self.assertRaisesRegex(patch.PatchError, "the edit of task 071 is not there"):
                    patch.verify_premium_for_everyone(tree)
                tree.write(rel, patched)
            patch.verify_premium_for_everyone(tree)


class NotServedTest(unittest.TestCase):
    # The upstream files, made of the texts the edits expect.
    def tree(self, root, edits=patch.NOT_SERVED_EDITS):
        files = {}
        for rel, old, _ in edits:
            files[rel] = files.get(rel, "") + old + "x\n"
        files[patch.SETTINGS_ACTIVITY] += "R.string.SettingsExperimental\n"
        for rel, text in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text, encoding="utf-8")
        return patch.Tree(root)

    def test_applies(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            with self.assertRaisesRegex(patch.PatchError, "is open again"):
                patch.verify_not_served(tree)
            patch.not_served(tree)
            patch.verify_not_served(tree)
            with self.assertRaises(patch.PatchError):
                patch.not_served(tree)

    def test_upstream_changed(self):
        # A row added inside a block stops the patch: the block is exact.
        for i, (rel, old, new) in enumerate(patch.NOT_SERVED_EDITS):
            changed = old[:len(old) // 2] + "        added();\n" + old[len(old) // 2:]
            edits = [e if j != i else (rel, changed, new) for j, e in enumerate(patch.NOT_SERVED_EDITS)]
            with self.subTest(edit=i), tempfile.TemporaryDirectory() as d:
                tree = self.tree(pathlib.Path(d), edits)
                with self.assertRaisesRegex(patch.PatchError, "occurrences"):
                    patch.not_served(tree)

    def test_check(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            patch.not_served(tree)
            for rel, old, new in patch.NOT_SERVED_EDITS:
                patched = tree.read(rel)
                tree.write(rel, patched.replace(new, old))
                with self.subTest(file=rel), self.assertRaisesRegex(patch.PatchError, "is open again"):
                    patch.verify_not_served(tree)
                tree.write(rel, patched)
            patch.verify_not_served(tree)

    def test_experimental_section_stays(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            patch.not_served(tree)
            text = tree.read(patch.SETTINGS_ACTIVITY)
            tree.write(patch.SETTINGS_ACTIVITY, text.replace("R.string.SettingsExperimental", ""))
            with self.assertRaisesRegex(patch.PatchError, "experimental section is gone"):
                patch.verify_not_served(tree)


class LoginScreensTest(unittest.TestCase):
    # LoginActivity made of the texts the edits expect, the end of the view
    # class, the manifest and every strings.xml.
    def tree(self, root, missing=patch.LOGIN_MISSING_HEAD + "        mail(\"sms@telegram.org\");\n"):
        java = "".join(old for old, _ in patch.LOGIN_EDITS)
        java += patch.LOGIN_VIEW + "{\n" + "".join(old for old, _ in patch.LOGIN_VIEW_EDITS)
        java += missing + patch.LOGIN_MISSING_TAIL + "\n    public class LoginActivityRecoverView {\n"
        files = {patch.LOGIN: java, f"{patch.MAIN}/AndroidManifest.xml": "    <queries>\n    </queries>\n"}
        for folder in patch.STRING_RENAMES:
            files[f"{patch.RES}/{folder}/strings.xml"] = "<resources>\n</resources>\n"
        for rel, text in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text, encoding="utf-8")
        return patch.Tree(root)

    def test_applies(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            with self.assertRaises(patch.PatchError):
                patch.verify_login_screens(tree)
            patch.login_screens(tree)
            patch.verify_login_screens(tree)
            text = tree.read(patch.LOGIN)
            self.assertNotIn("sms@telegram.org", text)
            self.assertIn('"tg://settings/phone_privacy"', text)
            ru = tree.read(f"{patch.RES}/values-ru/strings.xml")
            self.assertIn("Кто может найти меня по номеру? → Все", ru)
            with self.assertRaises(patch.PatchError):
                patch.login_screens(tree)

    def test_every_language_has_every_text(self):
        for key, texts in patch.LOGIN_STRINGS.items():
            with self.subTest(key=key):
                self.assertEqual(set(texts), set(patch.STRING_RENAMES))
        for folder in patch.STRING_RENAMES:
            with self.subTest(folder=folder):
                self.assertIn("%1$s", patch.LOGIN_STRINGS["PlumaLoginFallbackText"][folder])
                self.assertIn("%1$d:%2$02d", patch.LOGIN_STRINGS["PlumaLoginSendAgainIn"][folder])

    def test_check(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            patch.login_screens(tree)
            text = tree.read(patch.LOGIN)
            for old, new in patch.LOGIN_EDITS + patch.LOGIN_VIEW_EDITS:
                tree.write(patch.LOGIN, text.replace(new, old))
                with self.subTest(edit=new[:60]), self.assertRaises(patch.PatchError):
                    patch.verify_login_screens(tree)
            tree.write(patch.LOGIN, text.replace(patch.LOGIN_MISSING_BODY, "mail(\"sms@telegram.org\");\n"))
            with self.assertRaisesRegex(patch.PatchError, "Telegram's support"):
                patch.verify_login_screens(tree)
            tree.write(patch.LOGIN, text)
            ru = f"{patch.RES}/values-ru/strings.xml"
            xml = tree.read(ru)
            tree.write(ru, xml.replace("→ Все", "→ Мои контакты"))
            with self.assertRaisesRegex(patch.PatchError, "not the text of task 076"):
                patch.verify_login_screens(tree)
            tree.write(ru, xml)
            patch.verify_login_screens(tree)

    def test_upstream_string_stops(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d))
            rel = f"{patch.RES}/values/strings.xml"
            tree.write(rel, '<resources>\n    <string name="PlumaLoginSendAgain">x</string>\n</resources>\n')
            with self.assertRaisesRegex(patch.PatchError, "upstream has a string"):
                patch.login_screens(tree)

    def test_support_branch_changed(self):
        with tempfile.TemporaryDirectory() as d:
            tree = self.tree(pathlib.Path(d), missing=patch.LOGIN_MISSING_HEAD + "        report();\n")
            with self.assertRaisesRegex(patch.PatchError, "no longer writes"):
                patch.login_screens(tree)


if __name__ == "__main__":
    unittest.main()
