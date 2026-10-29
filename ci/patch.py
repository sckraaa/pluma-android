#!/usr/bin/env python3
"""Turns a checkout of DrKLO/Telegram into the Pluma client.

Every change is an exact edit: the text it replaces must occur the expected
number of times, or the whole run fails. An upstream update that moves any
of these places stops the build here instead of producing a client that
talks to Telegram or does not sign in. After the edits the result is checked
again (no Telegram datacenter address or server key is left).

Standard library only, so the CI and a developer machine run it as is.
"""

import argparse
import base64
import collections
import hashlib
import ipaddress
import json
import pathlib
import re
import sys

ABIS = ("armeabi-v7a", "arm64-v8a", "x86", "x86_64")

# Telegram's own server keys; none of them may survive the patch.
TELEGRAM_FINGERPRINTS = ("0xd09d1d85de64fd85", "0xb25898df208d2603")


class PatchError(Exception):
    pass


# --- RSA key -----------------------------------------------------------------


def _der_read(data, pos, tag):
    if data[pos] != tag:
        raise PatchError(f"RSA key: DER tag {data[pos]:#x} at {pos}, expected {tag:#x}")
    pos += 1
    length = data[pos]
    pos += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    return data[pos:pos + length], pos + length


def parse_pkcs1_public_key(pem):
    """Returns (n, e) as big-endian bytes without leading zeros."""
    lines = [l.strip() for l in pem.strip().splitlines()]
    if not lines or lines[0] != "-----BEGIN RSA PUBLIC KEY-----" or lines[-1] != "-----END RSA PUBLIC KEY-----":
        raise PatchError("RSA key: expected a PKCS#1 PEM (BEGIN RSA PUBLIC KEY)")
    der = base64.b64decode("".join(lines[1:-1]), validate=True)
    seq, end = _der_read(der, 0, 0x30)
    if end != len(der):
        raise PatchError("RSA key: trailing data after the key")
    n, pos = _der_read(seq, 0, 0x02)
    e, pos = _der_read(seq, pos, 0x02)
    if pos != len(seq):
        raise PatchError("RSA key: unexpected fields in the key")
    return n.lstrip(b"\0"), e.lstrip(b"\0")


def _tl_bytes(b):
    if len(b) < 254:
        out = bytes([len(b)]) + b
    else:
        out = b"\xfe" + len(b).to_bytes(3, "little") + b
    return out + b"\0" * (-len(out) % 4)


def key_fingerprint(n, e):
    """MTProto fingerprint: the low 64 bits of SHA1 over the TL-serialized
    modulus and exponent."""
    digest = hashlib.sha1(_tl_bytes(n) + _tl_bytes(e)).digest()
    return int.from_bytes(digest[-8:], "little")


def canonical_pem(n, e):
    def der_int(b):
        if b[0] & 0x80:
            b = b"\0" + b
        return b"\x02" + _der_len(len(b)) + b

    body = der_int(n) + der_int(e)
    der = b"\x30" + _der_len(len(body)) + body
    b64 = base64.b64encode(der).decode()
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return ["-----BEGIN RSA PUBLIC KEY-----", *lines, "-----END RSA PUBLIC KEY-----"]


def _der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


# --- edits -------------------------------------------------------------------


class Tree:
    def __init__(self, root):
        self.root = pathlib.Path(root)
        if not (self.root / "TMessagesProj").is_dir():
            raise PatchError(f"{root}: not a DrKLO/Telegram checkout")

    def read(self, rel):
        return (self.root / rel).read_text(encoding="utf-8")

    def write(self, rel, text):
        (self.root / rel).write_text(text, encoding="utf-8")

    def expect(self, rel, s, count=1):
        found = self.read(rel).count(s)
        if found != count:
            raise PatchError(f"{rel}: {found} occurrences of {s!r}, expected {count}; upstream changed it")

    def replace(self, rel, old, new, count=1):
        text = self.read(rel)
        found = text.count(old)
        if found != count:
            raise PatchError(f"{rel}: {found} occurrences of {old!r}, expected {count}")
        self.write(rel, text.replace(old, new))

    def sub(self, rel, pattern, repl, count=1, flags=0):
        text = self.read(rel)
        out, found = re.subn(pattern, repl, text, flags=flags)
        if found != count:
            raise PatchError(f"{rel}: {found} matches of /{pattern}/, expected {count}")
        self.write(rel, out)

    def replace_body(self, rel, head, tail, body, must_contain=()):
        """Replaces what lies between head and the first tail after it."""
        text = self.read(rel)
        if text.count(head) != 1:
            raise PatchError(f"{rel}: {text.count(head)} occurrences of {head!r}, expected 1")
        start = text.index(head) + len(head)
        end = text.find(tail, start)
        if end < 0:
            raise PatchError(f"{rel}: no {tail!r} after {head!r}")
        for s in must_contain:
            if s not in text[start:end]:
                raise PatchError(f"{rel}: the replaced block has no {s!r}; upstream changed it")
        self.write(rel, text[:start] + body + text[end:])

    def replace_in_tree(self, subdir, suffixes, old, new, count):
        found = 0
        for p in sorted((self.root / subdir).rglob("*")):
            if p.suffix not in suffixes or not p.is_file():
                continue
            text = p.read_text(encoding="utf-8")
            if old in text:
                found += text.count(old)
                p.write_text(text.replace(old, new), encoding="utf-8")
        if found != count:
            raise PatchError(f"{subdir}: {found} occurrences of {old!r}, expected {count}")


# --- configuration -----------------------------------------------------------


def load_env(path):
    out = {}
    for n, line in enumerate(pathlib.Path(path).read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep:
            raise PatchError(f"{path}:{n}: expected KEY=VALUE")
        out[key.strip()] = value.strip()
    return out


class Config:
    def __init__(self, upstream, app, server_ipv4, server_port, server_ipv6, rsa_pem, abis, ccache, google_services):
        def need(env, key):
            if not env.get(key):
                raise PatchError(f"{key} is not set")
            return env[key]

        self.layer = int(need(upstream, "UPSTREAM_LAYER"))
        self.version = need(upstream, "UPSTREAM_VERSION")
        self.ndk = need(upstream, "NDK_VERSION")
        self.cmake = need(upstream, "CMAKE_VERSION")

        self.package = need(app, "PLUMA_PACKAGE")
        if not re.fullmatch(r"[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+", self.package):
            raise PatchError(f"PLUMA_PACKAGE {self.package!r} is not a Java package name")
        self.app_name = need(app, "PLUMA_APP_NAME")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 .-]*", self.app_name):
            raise PatchError(f"PLUMA_APP_NAME {self.app_name!r}: letters, digits, spaces, dots and dashes only")
        self.api_id = int(need(app, "PLUMA_API_ID"))
        if self.api_id <= 0:
            raise PatchError("PLUMA_API_ID must be positive")
        self.api_hash = need(app, "PLUMA_API_HASH")
        if not re.fullmatch(r"[0-9a-f]{32}", self.api_hash):
            raise PatchError("PLUMA_API_HASH must be 32 lowercase hex digits")

        try:
            self.ipv4 = str(ipaddress.IPv4Address(server_ipv4))
        except ValueError:
            raise PatchError(f"server IPv4 {server_ipv4!r} is not an IPv4 address (tgnet needs an address, not a name)")
        self.ipv6 = None
        if server_ipv6:
            try:
                self.ipv6 = ipaddress.IPv6Address(server_ipv6).exploded
            except ValueError:
                raise PatchError(f"server IPv6 {server_ipv6!r} is not an IPv6 address")
        try:
            self.port = int(server_port)
        except ValueError:
            self.port = 0
        if not 0 < self.port < 65536:
            raise PatchError(f"server port {server_port!r} is not a port")

        n, e = parse_pkcs1_public_key(rsa_pem)
        if len(n) * 8 != 2048:
            raise PatchError(f"RSA key: {len(n) * 8} bits, the clients expect 2048")
        self.rsa_pem = canonical_pem(n, e)
        self.fingerprint = key_fingerprint(n, e)

        self.abis = [a for a in re.split(r"[\s,]+", abis.strip()) if a]
        if not self.abis or any(a not in ABIS for a in self.abis) or len(set(self.abis)) != len(self.abis):
            raise PatchError(f"ABIs {abis!r}: a list of {', '.join(ABIS)}")
        self.ccache = ccache
        self.google_services = google_services


# --- the patch ---------------------------------------------------------------


def placeholder_google_services(packages):
    """A well-formed Firebase config of no real project: the build needs one,
    the Firebase SDK accepts it, push stays off until the real one is given."""
    def client(pkg):
        h = hashlib.sha256(pkg.encode()).hexdigest()
        return {
            "client_info": {
                "mobilesdk_app_id": f"1:100000000000:android:{h[:16]}",
                "android_client_info": {"package_name": pkg},
            },
            "oauth_client": [],
            "api_key": [{"current_key": "AIza" + h[:35]}],
            "services": {"appinvite_service": {"other_platform_oauth_client": []}},
        }

    return {
        "project_info": {
            "project_number": "100000000000",
            "project_id": "pluma-placeholder",
            "storage_bucket": "pluma-placeholder.appspot.com",
        },
        "client": [client(p) for p in packages],
        "configuration_version": "1",
    }


def patch(tree, c):
    # The upstream is the one upstream.env describes: the schema layer the server
    # speaks (ADR 0008), the version and the toolchain the CI installs.
    tree.expect("TMessagesProj/src/main/java/org/telegram/tgnet/TLRPC.java", f"public static final int LAYER = {c.layer};")
    tree.expect("gradle.properties", f"APP_VERSION_NAME={c.version}\n")
    for rel in ("TMessagesProj/build.gradle", "TMessagesProj_App/build.gradle"):
        tree.expect(rel, f'ndkVersion "{c.ndk}"')
    tree.expect("TMessagesProj/build.gradle", f"version '{c.cmake}'")

    # tgnet: one datacenter, the Pluma server, for the production and the
    # test backend alike; a fresh install starts on it.
    lines = [
        "    // pluma: a single datacenter, the Pluma server, on both backends.",
        "    if (datacenters.find(1) == datacenters.end()) {",
        "        Datacenter *datacenter = new Datacenter(instanceNum, 1);",
        f'        datacenter->addAddressAndPort("{c.ipv4}", {c.port}, 0, "");',
    ]
    if c.ipv6:
        lines.append(f'        datacenter->addAddressAndPort("{c.ipv6}", {c.port}, 1, "");')
    lines += ["        datacenters[1] = datacenter;", "    }"]
    tree.replace_body("TMessagesProj/jni/tgnet/ConnectionsManager.cpp",
                      "void ConnectionsManager::initDatacenters() {\n", "\n}\n", "\n".join(lines),
                      must_contain=('addAddressAndPort("149.154.175.50", 443, 0, "")', "testBackend"))
    tree.replace("TMessagesProj/jni/tgnet/ConnectionsManager.cpp",
                 "            currentDatacenterId = 2;\n", "            currentDatacenterId = 1;\n")

    # tgnet: the server key replaces Telegram's production and test keys.
    indent = " " * 16
    pem = [f'"{l}\\n"' for l in c.rsa_pem[:-1]] + [f'"{c.rsa_pem[-1]}"']
    key = (f"{indent}// pluma: the key of the Pluma server, for both backends.\n"
           f"{indent}serverPublicKeys.emplace_back({pem[0]}\n"
           + "".join(f"{indent}                              {l}\n" for l in pem[1:-1])
           + f"{indent}                              {pem[-1]});\n"
           f"{indent}serverPublicKeysFingerprints.push_back({c.fingerprint:#018x});")
    tree.replace_body("TMessagesProj/jni/tgnet/Handshake.cpp",
                      "            if (serverPublicKeys.empty()) {\n", "\n            }\n\n            size_t count2", key,
                      must_contain=TELEGRAM_FINGERPRINTS)

    # No backup addresses from Telegram's DNS and Firebase records: they
    # would point the client at Telegram.
    tree.replace_body("TMessagesProj/src/main/java/org/telegram/tgnet/ConnectionsManager.java",
                      "    public static void onRequestNewServerIpAndPort(final int second, final int currentAccount) {\n",
                      "\n    }\n",
                      "        // pluma: the client knows its server; Telegram's backup addresses do not apply.",
                      must_contain=("GoogleDnsLoadTask", "FirebaseTask"))

    # Application identity.
    bv = "TMessagesProj/src/main/java/org/telegram/messenger/BuildVars.java"
    tree.sub(bv, r"public static int APP_ID = \d+;", f"public static int APP_ID = {c.api_id};")
    tree.sub(bv, r'public static String APP_HASH = "[0-9a-f]{32}";', f'public static String APP_HASH = "{c.api_hash}";')
    tree.replace(bv, '"org.telegram.messenger.beta"', f'"{c.package}.beta"')
    tree.sub("gradle.properties", r"(?m)^APP_PACKAGE=.*$", f"APP_PACKAGE={c.package}")

    # Names that must not clash with Telegram installed on the same phone:
    # the contacts account type and the MIME types of contact actions.
    tree.replace("TMessagesProj/src/main/java/org/telegram/messenger/ContactsController.java",
                 '"org.telegram.messenger")', f'"{c.package}")', count=5)
    for rel in ("TMessagesProj/src/main/res/xml/auth.xml", "TMessagesProj/src/main/res/xml/sync_contacts.xml"):
        tree.replace(rel, 'android:accountType="org.telegram.messenger"', f'android:accountType="{c.package}"')
    tree.replace("TMessagesProj/src/main/res/xml/auth_menu.xml",
                 'android:targetPackage="org.telegram.messenger"', f'android:targetPackage="{c.package}"')
    tree.replace_in_tree("TMessagesProj/src/main", {".java", ".xml"},
                         "vnd.org.telegram.messenger.android.", f"vnd.{c.package}.android.", count=11)

    # The app name in every language the APK carries.
    res = tree.root / "TMessagesProj/src/main/res"
    files = sorted(res.glob("values*/strings.xml"))
    named = 0
    for p in files:
        rel = str(p.relative_to(tree.root))
        if '<string name="AppName">' not in tree.read(rel):
            continue
        tree.sub(rel, r'<string name="AppName">[^<]*</string>', f'<string name="AppName">{c.app_name}</string>')
        tree.sub(rel, r'<string name="AppNameBeta">[^<]*</string>', f'<string name="AppNameBeta">{c.app_name} Beta</string>')
        named += 1
    if named < 10:
        raise PatchError(f"AppName found in {named} strings.xml files, expected at least 10")

    # Only the modules Pluma builds; no Huawei repository or plugin.
    for module in ("TMessagesProj_AppHuawei", "TMessagesProj_AppHockeyApp", "TMessagesProj_AppStandalone", "TMessagesProj_AppTests"):
        tree.replace("settings.gradle", f"include ':{module}'\n", "")
    tree.replace("build.gradle", "        maven { url 'https://developer.huawei.com/repo/' }\n", "")
    tree.sub("build.gradle", r"        classpath 'com\.huawei\.agconnect:agcp:[^']+'\n", "")

    # The ABIs of the APK.
    abis = ", ".join(f'"{a}"' for a in c.abis)
    tree.sub("TMessagesProj_App/build.gradle", r'(        afat \{\n            ndk \{\n                abiFilters )[^\n]+',
             lambda m: m.group(1) + abis)

    # ccache for the native code (CMake 3.10 has no launcher variables in the
    # environment, so they go to the CMake arguments).
    if c.ccache:
        tree.replace("TMessagesProj/build.gradle",
                     "arguments '-DANDROID_STL=c++_static', '-DANDROID_PLATFORM=android-21'",
                     "arguments '-DANDROID_STL=c++_static', '-DANDROID_PLATFORM=android-21', "
                     "'-DCMAKE_C_COMPILER_LAUNCHER=ccache', '-DCMAKE_CXX_COMPILER_LAUNCHER=ccache'")

    # Firebase: the real config when given (push, task 009), a placeholder
    # otherwise. The library module keeps its own namespace.
    if c.google_services:
        app_config = json.loads(pathlib.Path(c.google_services).read_text())
        names = {cl["client_info"]["android_client_info"]["package_name"] for cl in app_config.get("client", [])}
        if c.package not in names:
            raise PatchError(f"google-services.json has no client for {c.package}")
    else:
        app_config = placeholder_google_services([c.package, c.package + ".beta"])
    tree.write("TMessagesProj_App/google-services.json", json.dumps(app_config, indent=2) + "\n")
    tree.write("TMessagesProj/google-services.json",
               json.dumps(placeholder_google_services(["org.telegram.messenger"]), indent=2) + "\n")

    brand(tree)


# --- branding ----------------------------------------------------------------
# Task 017 of the server repository: the user sees Pluma, not Telegram (names,
# logo, the plm:// link scheme, the "graphite and sage" palette). Identifiers,
# packages, file names, copyright notices and URLs stay as they are.

MAIN = "TMessagesProj/src/main"
JAVA = f"{MAIN}/java/org/telegram"
RES = f"{MAIN}/res"

# Built-in strings. Whole-word "Telegram" and "TELEGRAM" in the text of the
# strings (never in keys or tags) become "Pluma" and "PLUMA"; URLs
# (t.me/TelegramTips, telegram.org) and other words ("Telegramm") stay. The
# counts are per file, after the AppName edit; a new language file or a
# changed count stops the build.
TELEGRAM_WORD = re.compile(r"(?<![A-Za-z0-9@/.])(Telegram|TELEGRAM)(?![A-Za-z0-9]|\.\w)")
ELEMENT_TEXT = re.compile(r">[^<]*<")
STRING_RENAMES = {
    "values": (508, 1),
    "values-ar": (0, 0),
    "values-de": (80, 0),
    "values-es": (95, 0),
    "values-it": (96, 0),
    "values-ko": (1, 0),
    "values-nl": (79, 0),
    "values-pt-rBR": (97, 1),
    "values-ru": (18, 0),
    "values-uk": (21, 0),
}
# The name in other scripts and in compounds, in this order, with counts.
# Korean particles follow the last sound of the word: "Pluma" ends in a vowel.
STRING_LOCAL_NAMES = {
    "values-ar": (("لتيليجرام", "لـPluma", 8), ("تيليجرام", "Pluma", 80), ("تليجرام", "Pluma", 1)),
    "values-ko": (("텔레그램이라는", "Pluma라는", 1), ("텔레그램이", "Pluma가", 12), ("텔레그램으로", "Pluma로", 2),
                  ("텔레그램은", "Pluma는", 4), ("텔레그램을", "Pluma를", 5), ("텔레그램", "Pluma", 71)),
    "values-nl": (("Telegramberichten", "Pluma-berichten", 1),),
}
LOCAL_NAMES = ("텔레그램", "تيليجرام", "تليجرام", "Telegramberichten")
# A sentence that would turn false with the name changed.
STRING_REWRITES = (
    ("values/strings.xml",
     r"Some videos can\'t be streamed – e.g., all videos that were sent from Android using Telegram 4.7 and earlier versions.",
     r"Some videos can\'t be streamed – e.g., videos that were sent from very old versions of the app."),
)
# The name in Java string literals the user sees.
JAVA_NAMES = (
    ("messenger/ContactsController.java", '"Telegram Profile"', '"Pluma Profile"', 1),
    ("messenger/ContactsController.java", '"Telegram Voice Call"', '"Pluma Voice Call"', 1),
    ("messenger/ContactsController.java", '"Telegram Video Call"', '"Pluma Video Call"', 1),
    ("messenger/MessagesController.java", 'user.first_name = "Telegram";', 'user.first_name = "Pluma";', 2),
    ("ui/Components/ChatAttachAlertDocumentLayout.java", 'fs.title = "Telegram";', 'fs.title = "Pluma";', 1),
    ("ui/Components/MessagePreviewView.java", '"Subscribe to **Telegram Premium** to', '"Subscribe to **Pluma Premium** to', 1),
    ("ui/Components/PasscodeView.java", '"Unlock to use Telegram"', '"Unlock to use Pluma"', 1),
    ("ui/LoginActivity.java", "But Telegram says it's", "But Pluma says it's", 2),
    ("ui/NewContactBottomSheet.java", '"This phone number is not on Telegram.', '"This phone number is not on Pluma.', 1),
    ("ui/NewContactBottomSheet.java", '"This phone number is on Telegram."', '"This phone number is on Pluma."', 1),
    ("ui/ThemePreviewActivity.java", '"Telegram Beta Chat"', '"Pluma Beta Chat"', 1),
)

# Deep links: plm:// instead of tg://. Every "tg: and "tg" literal of these
# files is the link scheme; the counts are those of the upstream (after the
# Help rows of the settings search are gone). Telegram keeps tg:// when it is
# installed next to Pluma, and the QR login (plm://login?token=...) works
# between Pluma clients only.
SCHEME_JAVA = {
    "messenger/AndroidUtilities.java": (13, 1),
    "messenger/MusicPlayerService.java": (2, 0),
    "messenger/browser/Browser.java": (3, 1),
    "ui/Business/BusinessLinksController.java": (1, 0),
    "ui/CameraScanActivity.java": (1, 0),
    "ui/Cells/ChatMessageCell.java": (2, 1),
    "ui/ChatActivity.java": (13, 0),
    "ui/Components/Premium/boosts/GiftInfoBottomSheet.java": (2, 1),
    "ui/Components/Premium/boosts/UserSelectorBottomSheet.java": (2, 1),
    "ui/Components/UndoView.java": (3, 0),
    "ui/LaunchActivity.java": (156, 2),
    "ui/LinkManager.java": (2, 2),
    "ui/LoginActivity.java": (1, 0),
    "ui/PaymentFormActivity.java": (0, 1),
    "ui/ProfileActivity.java": (76, 0),
    "ui/ProxySettingsActivity.java": (2, 0),
    "ui/SessionsActivity.java": (1, 0),
    "ui/WebviewActivity.java": (2, 1),
}
# What stays: the tg:// URIs ExoPlayer streams files through (internal, never
# a link) and the language code of Tajik.
SCHEME_KEEP = {
    "messenger/FileStreamLoadOperation.java": 1,
    "messenger/MediaController.java": 2,
    "messenger/TranslateController.java": 1,
    "messenger/secretmedia/ExtendedDefaultDataSource.java": 1,
    "ui/Components/Premium/VideoScreenPreview.java": 1,
    "ui/Components/VideoPlayer.java": 1,
    "ui/Components/VideoSeekPreviewImage.java": 1,
    "ui/Stories/PeerStoriesView.java": 2,
}
SCHEME_LITERAL = re.compile(r'"tg(?::|")')


def rename_strings(xml, local_names=()):
    """Renames Telegram in the text of the elements only; returns the new XML
    and the counts of each replacement."""
    counts = collections.Counter()

    def element(m):
        s = m.group(0)

        def word(w):
            counts[w.group(1)] += 1
            return "Pluma" if w.group(1) == "Telegram" else "PLUMA"

        s = TELEGRAM_WORD.sub(word, s)
        for old, new, _ in local_names:
            counts[old] += s.count(old)
            s = s.replace(old, new)
        return s

    return ELEMENT_TEXT.sub(element, xml), counts


def brand(tree):
    brand_entry_points(tree)
    brand_strings(tree)
    brand_scheme(tree)


def brand_entry_points(tree):
    # Settings: no Help section. Its rows lead only to Telegram's services:
    # the volunteer support chat, the FAQ, the feature tips channel and the
    # privacy policy.
    settings = f"{JAVA}/ui/SettingsActivity.java"
    tree.replace_body(settings,
                      "getString(R.string.SendAGift)));\n        }\n",
                      "            items.add(UItem.asHeader(getString(R.string.SettingsDebug)));\n",
                      "\n        // pluma: no Help section; it leads to Telegram's support, FAQ, feature tips and\n"
                      "        // privacy policy only.\n"
                      "        if (BuildVars.LOGS_ENABLED || BuildVars.DEBUG_PRIVATE_VERSION) {\n"
                      "            if (items.get(items.size() - 1).viewType != UniversalAdapter.VIEW_TYPE_SHADOW)\n"
                      "                items.add(UItem.asShadow(null));\n",
                      must_contain=("R.string.AskAQuestion", "R.string.TelegramFAQ", "R.string.TelegramFeatures",
                                    "R.string.PrivacyPolicy", "items.add(UItem.asShadow(null));"))
    tree.replace(settings, "        items.add(UItem.asCustomShadow(versionView));\n",
                 "        if (items.get(items.size() - 1).viewType == UniversalAdapter.VIEW_TYPE_SHADOW) {\n"
                 "            items.remove(items.size() - 1);\n"
                 "        }\n"
                 "        items.add(UItem.asCustomShadow(versionView));\n")
    # The same rows in the settings search, and the app icon (below).
    tree.sub(f"{JAVA}/ui/ProfileActivity.java",
             r"\n {20}new SearchResult\((?:324, getString\(R\.string\.AppIcon\)|402, getString\(R\.string\.AskAQuestion\)"
             r"|403, getString\(R\.string\.TelegramFAQ\)|404, getString\(R\.string\.PrivacyPolicy\))[^\n]*", "", count=4)
    # Chat settings: no app icon picker; the alternative icons are Telegram's.
    tree.replace(f"{JAVA}/ui/ThemeActivity.java",
                 "            appIconHeaderRow = rowCount++;\n"
                 "            appIconSelectorRow = rowCount++;\n"
                 "            appIconShadowRow = rowCount++;\n",
                 "            // pluma: no app icon picker; the alternative icons are Telegram's.\n")


def brand_strings(tree):
    files = {p.parent.name: str(p.relative_to(tree.root)) for p in sorted((tree.root / RES).glob("values*/strings.xml"))}
    if set(files) != set(STRING_RENAMES):
        raise PatchError(f"{RES}: strings.xml in {', '.join(sorted(files))}, expected {', '.join(sorted(STRING_RENAMES))}")
    for rel, old, new in STRING_REWRITES:
        tree.replace(f"{RES}/{rel}", old, new)
    for lang, rel in files.items():
        local = STRING_LOCAL_NAMES.get(lang, ())
        text, counts = rename_strings(tree.read(rel), local)
        expected = {"Telegram": STRING_RENAMES[lang][0], "TELEGRAM": STRING_RENAMES[lang][1]}
        expected.update((old, n) for old, _, n in local)
        for key, n in expected.items():
            if counts[key] != n:
                raise PatchError(f"{rel}: {counts[key]} names {key!r} to rename, expected {n}; upstream changed it")
        tree.write(rel, text)
    for rel, old, new, count in JAVA_NAMES:
        tree.replace(f"{JAVA}/{rel}", old, new, count)


def brand_scheme(tree):
    for rel, (colon, bare) in SCHEME_JAVA.items():
        tree.replace(f"{JAVA}/{rel}", '"tg:', '"plm:', colon)
        tree.replace(f"{JAVA}/{rel}", '"tg"', '"plm"', bare)
    # Links in message text.
    tree.replace(f"{JAVA}/messenger/AndroidUtilities.java", "|ton|tg|tonsite):", "|ton|plm|tonsite):")
    tree.replace(f"{JAVA}/messenger/LinkifyPort.java", "|ton|tg|tonsite)://", "|ton|plm|tonsite)://")
    # The system hands plm:// links to the app, and no longer tg:// ones.
    tree.replace(f"{MAIN}/AndroidManifest.xml", '<data android:scheme="tg" />', '<data android:scheme="plm" />')
    tree.replace(f"{RES}/xml/shortcuts.xml", 'android:value="tg://', 'android:value="plm://', count=6)


def verify_brand(tree):
    for p in sorted((tree.root / RES).glob("values*/strings.xml")):
        for m in ELEMENT_TEXT.finditer(p.read_text(encoding="utf-8")):
            left = TELEGRAM_WORD.search(m.group(0)) or re.search("|".join(LOCAL_NAMES), m.group(0))
            if left:
                raise PatchError(f"{p.relative_to(tree.root)}: {left.group(0)!r} is still in {m.group(0)[:80]!r}")
    found = {}
    for p in sorted((tree.root / JAVA).rglob("*.java")):
        n = len(SCHEME_LITERAL.findall(p.read_text(encoding="utf-8")))
        if n:
            found[p.relative_to(tree.root / JAVA).as_posix()] = n
    if found != SCHEME_KEEP:
        raise PatchError(f"tg: literals left in {found}, expected only the internal ones {SCHEME_KEEP}")
    if 'android:scheme="tg"' in tree.read(f"{MAIN}/AndroidManifest.xml"):
        raise PatchError("AndroidManifest.xml: the app still takes tg:// links")


def verify(tree, c):
    """Checks the result independently of how the edits were made."""
    tgnet = tree.root / "TMessagesProj/jni/tgnet"
    for p in sorted(tgnet.glob("*.cpp")):
        text = p.read_text(encoding="utf-8", errors="replace")
        for s in ("149.154.", "95.161.76.100", "2001:b28:", "2001:67c:", *TELEGRAM_FINGERPRINTS):
            if s in text:
                raise PatchError(f"{p.relative_to(tree.root)}: Telegram's {s!r} is still there")
    cm = tree.read("TMessagesProj/jni/tgnet/ConnectionsManager.cpp")
    if cm.count('datacenter->addAddressAndPort("') != 1 + (1 if c.ipv6 else 0):
        raise PatchError("ConnectionsManager.cpp: unexpected datacenter addresses")
    hs = tree.read("TMessagesProj/jni/tgnet/Handshake.cpp")
    if hs.count("serverPublicKeysFingerprints.push_back(") != 1 or f"{c.fingerprint:#018x}" not in hs:
        raise PatchError("Handshake.cpp: the server key is not the only one")
    props = tree.read("gradle.properties")
    if f"APP_PACKAGE={c.package}\n" not in props:
        raise PatchError("gradle.properties: APP_PACKAGE")
    for rel in ("TMessagesProj/src/main/res/xml/auth.xml", "TMessagesProj/src/main/res/xml/sync_contacts.xml"):
        if "org.telegram.messenger" in tree.read(rel):
            raise PatchError(f"{rel}: Telegram's account type is still there")
    verify_brand(tree)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--source", required=True, help="the DrKLO/Telegram checkout")
    ap.add_argument("--upstream", required=True, help="upstream.env")
    ap.add_argument("--app", required=True, help="config/app.env")
    ap.add_argument("--server-ipv4", required=True)
    ap.add_argument("--server-port", required=True)
    ap.add_argument("--server-ipv6", default="")
    ap.add_argument("--rsa-public-key", required=True, help="PKCS#1 PEM of the server key")
    ap.add_argument("--abis", default="", help="ABIs of the APK (default: PLUMA_ABIS of the app config)")
    ap.add_argument("--google-services", default="", help="the Firebase config of the app")
    ap.add_argument("--ccache", action="store_true")
    a = ap.parse_args(argv)
    try:
        app = load_env(a.app)
        c = Config(load_env(a.upstream), app, a.server_ipv4, a.server_port, a.server_ipv6,
                   pathlib.Path(a.rsa_public_key).read_text(), a.abis or app.get("PLUMA_ABIS", ""),
                   a.ccache, a.google_services)
        tree = Tree(a.source)
        patch(tree, c)
        verify(tree, c)
    except PatchError as e:
        print(f"patch: {e}", file=sys.stderr)
        return 1
    print(f"patch: {c.package} \"{c.app_name}\", layer {c.layer}, server key {c.fingerprint:#018x}, "
          f"ABIs {' '.join(c.abis)}, Firebase {'given' if c.google_services else 'placeholder'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
