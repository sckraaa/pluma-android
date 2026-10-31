#!/usr/bin/env python3
"""Turns a checkout of DrKLO/Telegram into the Pluma client.

Every change is an exact edit: the text it replaces must occur the expected
number of times, or the whole run fails. An upstream update that moves any
of these places stops the build here instead of producing a client that
talks to Telegram or does not sign in. The brand assets of brand/android
replace upstream files only when those are byte for byte the ones expected,
and add files only under names upstream does not use.
After the edits the result is checked again (no Telegram datacenter address
or server key is left, no Telegram name and no link to Telegram's desktop
and web clients in the built-in strings, no tg:// link scheme, no Telegram
blue in the colours of the default themes, a birthday notice that leads to
the chat rather than to gifts).

Standard library only, so the CI and a developer machine run it as is.
"""

import argparse
import base64
import collections
import colorsys
import hashlib
import ipaddress
import json
import pathlib
import re
import sys

ABIS = ("armeabi-v7a", "arm64-v8a", "x86", "x86_64")

# The rendered brand assets (brand/render.py).
BRAND = pathlib.Path(__file__).resolve().parent.parent / "brand" / "android"

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

    birthdays(tree)
    brand(tree)


# --- birthdays ---------------------------------------------------------------
# Task 020 of the server repository: the notice over the chat list of the
# contacts whose birthday is today (DialogsActivity.updateDialogsHint, the
# list from contacts.getBirthdays). Upstream shows it only while Premium can
# be bought and leads to the Premium gift sheet; Pluma sells no Premium and has
# no gifts (help.getAppConfig sets premium_purchase_blocked), so it never
# showed. It shows now, with Telegram's title, avatars and close button, and
# leads to the chat (the owner's decision): with one contact a tap opens the
# chat with them, with several it lists them in the app's peer picker
# (ItemOptions.addChat, without the scrim, as upstream's own pickers of a peer
# in ChannelAffiliateProgramsFragment and StarsReactionsSheet), and a tap on one
# opens the chat. Its second line is
# "Send Message", the label upstream gives the action that opens the chat with
# a user, instead of "Send them a Gift." Closing it hides it as upstream does,
# without the toast that Premium can be gifted later in Settings (Settings has
# no such row while Premium cannot be bought), and the notice no longer
# preloads the star gifts. The import only the gift sheet used goes.
DIALOGS = "TMessagesProj/src/main/java/org/telegram/ui/DialogsActivity.java"
BIRTHDAY_EDITS = (
    ("import org.telegram.ui.Gifts.GiftSheet;\n", ""),
    ("        } else if (folderId == 0 && communityId == 0 && !getMessagesController().premiumPurchaseBlocked() && "
     "BirthdayController.getInstance(currentAccount).contains() && "
     '!getMessagesController().dismissedSuggestions.contains("BIRTHDAY_CONTACTS_TODAY")) {\n',
     "        } else if (folderId == 0 && communityId == 0 && "
     "BirthdayController.getInstance(currentAccount).contains() && "
     '!getMessagesController().dismissedSuggestions.contains("BIRTHDAY_CONTACTS_TODAY")) {\n'
     "            // pluma: no Premium to gift; the notice leads to the chat.\n"),
    ("                    showDialog(new GiftSheet(getContext(), currentAccount, state.today.get(0).id, null, null).setBirthday());\n",
     "                    presentFragment(ChatActivity.of(state.today.get(0).id));\n"),
    ("                UserSelectorBottomSheet.open(0, state);\n",
     "                final ItemOptions options = ItemOptions.makeOptions(this, dialogsHintCell);\n"
     "                for (TLRPC.User user : state.today) {\n"
     "                    options.addChat(user, false, () -> presentFragment(ChatActivity.of(user.id)));\n"
     "                }\n"
     "                options.setDrawScrim(false).show();\n"),
    ("                LocaleController.formatString(users.size() == 1 ? R.string.BirthdayTodaySingleMessage2 : "
     "R.string.BirthdayTodayMultipleMessage2)\n",
     "                LocaleController.getString(R.string.SendMessage)\n"),
    ('                MessagesController.getInstance(currentAccount).removeSuggestion(0, "BIRTHDAY_CONTACTS_TODAY");\n'
     "                updateDialogsHint();\n"
     "                BulletinFactory.of(this)\n"
     "                        .createSimpleBulletin(R.raw.gift, LocaleController.getString(R.string.BoostingPremiumChristmasToast), 4)\n"
     "                        .setDuration(Bulletin.DURATION_PROLONG)\n"
     "                        .show();\n"
     "            });\n"
     "            StarsController.getInstance(currentAccount).loadStarGifts();\n",
     '                MessagesController.getInstance(currentAccount).removeSuggestion(0, "BIRTHDAY_CONTACTS_TODAY");\n'
     "                updateDialogsHint();\n"
     "            });\n"),
)
# The English texts the notice shows, none of which offers a gift; other
# languages come with the language pack. A changed text stops the build here.
BIRTHDAY_STRINGS = (
    '<string name="BirthdayTodaySingleTitle">It’s %s’s **birthday** today! 🎂</string>',
    '<string name="BirthdayTodayMultipleTitle_other">%d contacts have **birthdays** today! 🎂</string>',
    '<string name="SendMessage">Send Message</string>',
)
# What leads to Premium or gifts: none of it may be left in the notice.
BIRTHDAY_GONE = ("premiumPurchaseBlocked", "GiftSheet", "UserSelectorBottomSheet", "BirthdayTodaySingleMessage2",
                 "BirthdayTodayMultipleMessage2", "BoostingPremiumChristmasToast", "loadStarGifts")


def birthdays(tree):
    for old, new in BIRTHDAY_EDITS:
        tree.replace(DIALOGS, old, new)
    if re.search(r"\bGiftSheet\b", tree.read(DIALOGS)):
        raise PatchError(f"{DIALOGS}: GiftSheet is still used; upstream changed it")
    for s in BIRTHDAY_STRINGS:
        tree.expect("TMessagesProj/src/main/res/values/strings.xml", s)


def birthday_notice(text):
    """The branch of DialogsActivity.updateDialogsHint that shows the birthday
    notice, from its condition to the next branch."""
    head = 'dismissedSuggestions.contains("BIRTHDAY_CONTACTS_TODAY")) {\n'
    if text.count(head) != 1:
        raise PatchError(f"{DIALOGS}: {text.count(head)} birthday notices, expected 1")
    start = text.rindex("\n", 0, text.index(head)) + 1
    end = text.find("\n        } else if (", start)
    if end < 0:
        raise PatchError(f"{DIALOGS}: the birthday notice has no next branch")
    return text[start:end]


def verify_birthdays(tree):
    notice = birthday_notice(tree.read(DIALOGS))
    for name in BIRTHDAY_GONE:
        if name in notice:
            raise PatchError(f"{DIALOGS}: the birthday notice still has {name}")
    # Any other way to Premium, gifts or Stars an upstream update may add to
    # the notice, such as PremiumPreviewFragment or StarsIntroActivity.
    code = re.sub(r"//[^\n]*", "", notice)
    found = re.search(r"Gift|Premium|Stars", code)
    if found:
        raise PatchError(f"{DIALOGS}: the birthday notice leads to {found.group()}")
    if notice.count("presentFragment(ChatActivity.of(") != 2:
        raise PatchError(f"{DIALOGS}: the birthday notice does not lead to the chat")


# --- branding ----------------------------------------------------------------
# Task 017 of the server repository: the user sees Pluma, not Telegram (names,
# logo, the plm:// link scheme, the "graphite and sage" palette). Identifiers,
# packages, file names, copyright notices and URLs stay as they are.

MAIN = "TMessagesProj/src/main"
JAVA = f"{MAIN}/java/org/telegram"
RES = f"{MAIN}/res"

# Upstream files the rendered assets of brand/android/res replace, by their
# SHA-256: an upstream update that changes one stops the build here.
BRAND_ASSETS = {
    "drawable-hdpi/book_logo.webp": "8d328b0dc5dac3a154cf241f7c06a897cdeb7275193d2dbf979c311a00c1f364",
    "drawable-hdpi/ic_launcher_dr.webp": "4c6f7ea82ec6c913ac78913c5e93cbcc3cedef2ec7db188a04476edbaf353f3f",
    "drawable-hdpi/intro_tg_plane.webp": "f3708145353cfd4ded45bd430bca03e40a4a47a34800939def46ddd91d65538d",
    "drawable-hdpi/logo_middle.webp": "5c978ff1649e913da5dc0c7273c43a059162582ff99f91dcee8dded18125ae29",
    "drawable-hdpi/notification.webp": "873db3d9f0c4e81bda605b2601b4f0bd4bc376fe8b8648ab84d1bed55fd2d65a",
    "drawable-mdpi/book_logo.webp": "b8a0c34f77256b5a7d7ca8b3aeff690e04f9239b19c124662366cb0ef8282433",
    "drawable-mdpi/ic_launcher_dr.webp": "2db2c54fb7a44941d90f75f9224ab8205a41333d2cc6d29b3c089c1294601238",
    "drawable-mdpi/intro_tg_plane.webp": "44ca1d3e2e1cd1ee4f8278bd809908415bf1130435824f3a1bb73ff45fa3c0f8",
    "drawable-mdpi/logo_middle.webp": "6ff591b644d032f5f9c8e750766ca3a3a77cb06267e1ff876cbd0c02ddbe808f",
    "drawable-mdpi/notification.webp": "127b37ede36a3cf43884044440bb07d55afdb92b03c7b4c1d3e5a094c4676f21",
    "drawable-xhdpi/book_logo.webp": "1aae222c620b760301ec50c96e134cc1f29e9033bedfa315da438d5b101ffa9a",
    "drawable-xhdpi/ic_launcher_dr.webp": "b33718f18bfa8c8cfd3a318d247e578279ba351b08466af92b0e4533e748d246",
    "drawable-xhdpi/intro_tg_plane.webp": "637cf777fc9eea8cf41efdf73cc1d35f0617cc5129a452a3e4b5d0c420de078a",
    "drawable-xhdpi/logo_middle.png": "7ef367a9e12679e91ed3da8046c09bc3e101d086d9ec4f38f8254cbc3b696b4f",
    "drawable-xhdpi/notification.webp": "c29bd2eb35a23a93a4352f0f432535c73934755e785cd4bbe0118a2cfe2f2fa0",
    "drawable-xxhdpi/book_logo.webp": "5feb9c04521c9cbdb4515c3ffbcfd3d448006f01543b6e237b0cf67657e35ef2",
    "drawable-xxhdpi/ic_launcher_dr.webp": "74f2f223fd5a9d679d145bd3b46d6a5d8f63155d144b9ed1b5b027c1d91daa35",
    "drawable-xxhdpi/intro_tg_plane.webp": "5ec557af601fdd61bef74cd7c04fb3d749082dcb58f586541fe8a85763ec6d63",
    "drawable-xxhdpi/logo_middle.png": "96a4313f9ee79430aae7f48f6551a2a83996092da9b6efa056726c364f1cd9a2",
    "drawable-xxhdpi/notification.webp": "6df1bef4b36b42656179dc5772845df208204439c57f06792eb480313bb11e4d",
    "drawable-xxxhdpi/book_logo.webp": "04a96305f5e0165a4ea0143363351793fc9c6c6e7de6af7903376e2c70e0ec04",
    "drawable-xxxhdpi/ic_launcher_dr.webp": "86044e329a82c927b9e5b518c0ded5fd99723c2b93bea92180dbd374e6dd7df8",
    "drawable/icon_plane.xml": "5e22f04d4b4f509b48c92b852f3e1375870bd33aeb920af5805538e8a68d4705",
    "drawable/telegram_logo.xml": "7813838eeb6332fd3f412bcce0ff941edb5e2483320efe73c668c4fe054e8c72",
    "drawable/telegram_logo_2.xml": "6d5fc4c19e03cd7c64668733d55cf7d09a4baf26f7dc34dbdca7eb4685d49bbc",
    "drawable/tg_splash_320.xml": "bbbd6a828e11fff0b90d2a08a8321d1e17b9a8474430e0773bb4c1244d86963a",
    "mipmap-hdpi/ic_launcher.png": "a85e4853116e84a7ab0036cb9d660ed333f0774e6f7f06332a592ff21a90fa45",
    "mipmap-hdpi/ic_launcher_round.png": "a85e4853116e84a7ab0036cb9d660ed333f0774e6f7f06332a592ff21a90fa45",
    "mipmap-hdpi/icon_foreground.png": "fc3404ec8b5199a5471bd970df2493d0a477f5131d5927a50b1fd49bc5352a38",
    "mipmap-hdpi/icon_foreground_round.png": "c9b304fada82e85859623537c54a9c8a8b3618b380331b9bb2d5f591bad7f16c",
    "mipmap-hdpi/icon_foreground_sa.png": "ab59b11c9cd7487fe33191e1bc7a694de1ae4fe2833d10544d79a22f6efc12f0",
    "mipmap-mdpi/ic_launcher.png": "ff75b6cdd50dd079e07632426d1d9bd8c1e2b8fcb00bdb7478908056a8242efb",
    "mipmap-mdpi/ic_launcher_round.png": "ff75b6cdd50dd079e07632426d1d9bd8c1e2b8fcb00bdb7478908056a8242efb",
    "mipmap-mdpi/icon_foreground.png": "154c04ed048fdd9c1de5c7a3535a1de210a9a2f663a470c248dd103187a992f5",
    "mipmap-mdpi/icon_foreground_round.png": "b8e7b20804a80e540bf7a3cc75fa3a6d7d5b44e8d64f7b757de0141e56eb461c",
    "mipmap-mdpi/icon_foreground_sa.png": "e60c634b0e62c4fe085d2c32491e13e4367eb226c49a16763f924ae75c7c9b1c",
    "mipmap-xhdpi/ic_launcher.png": "71835417e22e53e21b34b14bb10ed8051066b03ebfccc8801c81957391cf4347",
    "mipmap-xhdpi/ic_launcher_round.png": "71835417e22e53e21b34b14bb10ed8051066b03ebfccc8801c81957391cf4347",
    "mipmap-xhdpi/icon_foreground.png": "e522a488c25bdd5a0c6e98c2f43e408dabe6f0e231e48ec2fd8e9f8102b79fc8",
    "mipmap-xhdpi/icon_foreground_round.png": "e7548727c7672809a766efbd21319aada6a183267db8130bcd61825ff87b0fc7",
    "mipmap-xhdpi/icon_foreground_sa.png": "6aced0a436baabf1e70e5bc9b3be55c92db542f5a9d91724e8ebe13d70735f14",
    "mipmap-xxhdpi/ic_launcher.png": "42ef1e7e29b81d38e02e6952e3db97fc95e0ccf3f9df130c4ca66a4a57be72b9",
    "mipmap-xxhdpi/ic_launcher_round.png": "42ef1e7e29b81d38e02e6952e3db97fc95e0ccf3f9df130c4ca66a4a57be72b9",
    "mipmap-xxhdpi/icon_foreground.png": "818deb7f7de9ab363f347c4c5b691cc5ce4b3bfc2f1648c4befd00b3f415fd6b",
    "mipmap-xxhdpi/icon_foreground_round.png": "c9876818ba9c910e07608aba794711654e07278f8e228926d0b199b5134badae",
    "mipmap-xxhdpi/icon_foreground_sa.png": "1b9dc5cd69b203a6ddfdbded85db98d5f339e58d16cce8d567b4a3fff6a61c7c",
    "mipmap-xxxhdpi/ic_launcher.png": "838696ab91ba1708781c20833a3c04884411ba021c3ec49f287088a51dfeddf4",
    "mipmap-xxxhdpi/ic_launcher_round.png": "838696ab91ba1708781c20833a3c04884411ba021c3ec49f287088a51dfeddf4",
    "mipmap-xxxhdpi/icon_foreground.png": "89f1990484339efa2bcba4cc803622da6a6e9f37c0b14d0ce50b06d836a9599d",
    "mipmap-xxxhdpi/icon_foreground_round.png": "cfb6bb1dbce81462bcfb2ec9d15de480ae234dfb63b1d5b7447be880e17e8717",
    "mipmap-xxxhdpi/icon_foreground_sa.png": "bf938f915c029b85d75ad9ad2b22868fea31df3348b0529099bedc07a2f0a1c3",
    "raw/plane_logo_plain.json": "35cfefbe333b74e11462fbced88f69c9be6f7727819f1d90bdcbf71e291be73d",
    "raw/qr_code_logo.json": "2a072f8111209cd543929806110c7523082331b6f01ae5ec31c99db41df57b79",
    "raw/qr_code_logo_2.json": "289a89cd75fe9056fe2f9953291e14252b1d9b5645c316f28eeb0c480dcab64b",
    "raw/qr_logo.svg": "b40b79aba680695563c4e788cf51dc087cdd496faa667a2679b1b4fde49de470",
    "raw/round_blur_overlay_text.png": "8484201589fbb2eaa7efb62f438992814f4e2804f3a5a1660744d9fbbc7365da",
}
# Files of brand/android/res the patch adds, by their own SHA-256: no upstream
# resource may have the name. The laptop animation of Settings > Devices
# (brand/lottie, brand_devices) and the mark writing itself on page 1 of the
# intro (brand/mark_write.py, brand_intro).
BRAND_ADDED = {
    "raw/pluma_devices.json": "287368fa82b029ea22b0b7ee0a28654d48557c9eb8f672afd08bddfe759020a7",
    "raw/pluma_mark_write.json": "f5d89139ddab9cc3d1ffb2ec42c574307c37e92eb92f5d2413e8fc0855221c41",
}
# Logo layers of upstream animations the shapes of a brand/android file
# replace: (animation, its SHA-256, the layer's name and index, the file).
# "Link desktop device": the logo over the oval. The call-log permission
# explanation of the login: the caller, Telegram's logo (a white disc with the
# plane cut out), becomes the white mark.
BRAND_LAYERS = (
    ("raw/qr_login.json", "40cccd31a7f01608dd1e8a3bd4597b05832585f10cdc7a5914204b22c507ab79", "Logo full", None,
     "qr_login_logo.json"),
    ("raw/calls_log.json", "2cbcb5bf3fa757f613e35420704bb4a4fe518e2fff4e23d15a99d6dec87fd6cd", "Shape", 2,
     "calls_log_logo.json"),
)

# Settings > Devices: the laptop animation over "Link Desktop Device". Upstream
# shows the seventh sticker of the set tg_placeholders_android, which it asks
# the server for; the Pluma server has no such set, so the place stays empty.
# ScanQRCodeView plays the bundled animation of BRAND_ADDED instead, the way
# the sticker played: rendered at 130 dp (the sticker's "130_130") into the
# 120 dp view, once (auto-repeat 2), again on a tap. The sticker loading, its
# notification and the imports only it used go.
SESSIONS = f"{JAVA}/ui/SessionsActivity.java"
SESSIONS_EDITS = (
    ("import android.widget.FrameLayout;\n",
     "import android.widget.FrameLayout;\nimport android.widget.ImageView;\n", 1),
    ("import org.telegram.messenger.DocumentObject;\n", "", 1),
    ("import org.telegram.messenger.ImageLocation;\n", "", 1),
    ("import org.telegram.messenger.MediaDataController;\n", "", 1),
    ("import org.telegram.messenger.SvgHelper;\n", "", 1),
    ("import org.telegram.ui.Components.BackupImageView;\n", "", 1),
    ("import org.telegram.ui.Components.RecyclerListView;\n",
     "import org.telegram.ui.Components.RLottieImageView;\nimport org.telegram.ui.Components.RecyclerListView;\n", 1),
    ("    private class ScanQRCodeView extends FrameLayout implements NotificationCenter.NotificationCenterDelegate {\n"
     "\n"
     "        BackupImageView imageView;\n",
     "    private class ScanQRCodeView extends FrameLayout {\n"
     "\n"
     "        RLottieImageView imageView;\n", 1),
    ("            imageView = new BackupImageView(context);\n"
     "            addView(imageView, LayoutHelper.createFrame(120, 120, Gravity.CENTER_HORIZONTAL, 0, 16, 0, 0));\n",
     "            // pluma: the bundled animation, not a sticker of Telegram's server.\n"
     "            imageView = new RLottieImageView(context);\n"
     "            imageView.setScaleType(ImageView.ScaleType.FIT_CENTER);\n"
     "            imageView.setAnimation(R.raw.pluma_devices, 130, 130);\n"
     "            imageView.getAnimatedDrawable().setAutoRepeat(2);\n"
     "            imageView.playAnimation();\n"
     "            addView(imageView, LayoutHelper.createFrame(120, 120, Gravity.CENTER_HORIZONTAL, 0, 16, 0, 0));\n", 1),
    ("imageView.getImageReceiver().getLottieAnimation()", "imageView.getAnimatedDrawable()", 4),
    ("            addView(buttonTextView, LayoutHelper.createFrame(LayoutHelper.MATCH_PARENT, 48, Gravity.BOTTOM, 16, 15, 16, 16));\n"
     "\n"
     "            setSticker();\n"
     "        }\n",
     "            addView(buttonTextView, LayoutHelper.createFrame(LayoutHelper.MATCH_PARENT, 48, Gravity.BOTTOM, 16, 15, 16, 16));\n"
     "        }\n", 1),
    ("\n"
     "        @Override\n"
     "        protected void onAttachedToWindow() {\n"
     "            super.onAttachedToWindow();\n"
     "            setSticker();\n"
     "            NotificationCenter.getInstance(currentAccount).addObserver(this, NotificationCenter.diceStickersDidLoad);\n"
     "        }\n"
     "\n"
     "        @Override\n"
     "        protected void onDetachedFromWindow() {\n"
     "            super.onDetachedFromWindow();\n"
     "            NotificationCenter.getInstance(currentAccount).removeObserver(this, NotificationCenter.diceStickersDidLoad);\n"
     "        }\n"
     "\n"
     "        @Override\n"
     "        public void didReceivedNotification(int id, int account, Object... args) {\n"
     "            if (id == NotificationCenter.diceStickersDidLoad) {\n"
     "                String name = (String) args[0];\n"
     "                if (AndroidUtilities.STICKERS_PLACEHOLDER_PACK_NAME.equals(name)) {\n"
     "                    setSticker();\n"
     "                }\n"
     "            }\n"
     "        }\n"
     "\n"
     "        private void setSticker() {\n"
     "            String imageFilter = null;\n"
     "            TLRPC.Document document = null;\n"
     "            TLRPC.TL_messages_stickerSet set = null;\n"
     "\n"
     "            set = MediaDataController.getInstance(currentAccount).getStickerSetByName(AndroidUtilities.STICKERS_PLACEHOLDER_PACK_NAME);\n"
     "            if (set == null) {\n"
     "                set = MediaDataController.getInstance(currentAccount).getStickerSetByEmojiOrName(AndroidUtilities.STICKERS_PLACEHOLDER_PACK_NAME);\n"
     "            }\n"
     "            if (set != null && set.documents.size() > 6) {\n"
     "                document = set.documents.get(6);\n"
     "            }\n"
     '            imageFilter = "130_130";\n'
     "\n"
     "            SvgHelper.SvgDrawable svgThumb = null;\n"
     "            if (document != null) {\n"
     "                svgThumb = DocumentObject.getSvgThumb(document.thumbs, Theme.key_emptyListPlaceholder, 0.2f);\n"
     "            }\n"
     "            if (svgThumb != null) {\n"
     "                svgThumb.overrideWidthAndHeight(512, 512);\n"
     "            }\n"
     "\n"
     "            if (document != null) {\n"
     "                ImageLocation imageLocation = ImageLocation.getForDocument(document);\n"
     '                imageView.setImage(imageLocation, imageFilter, "tgs", svgThumb, set);\n'
     "                imageView.getImageReceiver().setAutoRepeat(2);\n"
     "            } else {\n"
     "                MediaDataController.getInstance(currentAccount).loadStickersByEmojiOrName(AndroidUtilities.STICKERS_PLACEHOLDER_PACK_NAME, false, set == null);\n"
     "            }\n"
     "        }\n"
     "    }\n"
     "\n"
     "    private void openCameraScanActivity() {\n",
     "    }\n"
     "\n"
     "    private void openCameraScanActivity() {\n", 1),
)
# What only the sticker used: none of it may be left in the file.
SESSIONS_GONE = ("BackupImageView", "DocumentObject", "ImageLocation", "MediaDataController", "SvgHelper",
                 "STICKERS_PLACEHOLDER_PACK_NAME", "diceStickersDidLoad", "setSticker")

# The intro (task 020 of the server repository). Page 1 shows Pluma's mark
# writing itself, the site's writeMark() as the animation of BRAND_ADDED
# (brand/mark_write.py), in the brand kit's ink for the theme, with no disc.
# IntroActivity plays it with the app's rlottie over the GL box of the
# pictures: when page 1 appears and again each time the user comes back to it,
# or the written mark at once when the system's animations are off. It fades
# with the page scroll and crosses with the pictures of the other pages in one
# fade at their pace (duration_const, 0.3 s): the speedometer of page 2 fades
# out as the mark fades in, and the other way round. IntroRenderer draws
# neither the disc, the plane nor the mask of page 1 any more, and fades that
# speedometer where the disc used to hide it. The layout
# is layout B: the mark MARK_DP high, MARK_GAP_DP over the wordmark, the group
# from the mark down to the dots at MARK_BIAS of the free space between the
# status bar and the start button, which sits 24 dp over the navigation bar;
# pages 2-6 share it, the GL box placed so that its 148-unit pictures end where
# the mark's ink ends.
INTRO = f"{JAVA}/ui/IntroActivity.java"
INTRO_RENDERER = "TMessagesProj/jni/intro/IntroRenderer.c"
INTRO_EDITS = (
    # Page 1, back from page 2: the speedometer fades out, as the disc no
    # longer covers it.
    (INTRO_RENDERER,
     "            fast_body.params.alpha = 1;\n"
     "            fast_body.params.scale = xyzMake(scale, scale, 1);\n",
     "            // pluma: no disc covers it; it fades out as the mark comes back.\n"
     "            fast_body.params.alpha = t(1, 0, 0, duration_const, Linear);\n"
     "            fast_body.params.scale = xyzMake(scale, scale, 1);\n"),
    # Page 2, from page 1: it fades in rather than showing at once under the disc.
    (INTRO_RENDERER,
     "            fast_body.params.scale = xyzMake(1, 1, 1);\n"
     "            fast_body.params.alpha = 1;\n",
     "            fast_body.params.scale = xyzMake(1, 1, 1);\n"
     "            // pluma: no disc over it; it fades in as the mark fades out.\n"
     "            fast_body.params.alpha = t(0, 1, 0, duration_const, Linear);\n"),
    # Neither the disc, the plane nor the mask that clips the plane.
    (INTRO_RENDERER,
     "    if (current_page == 0) {\n"
     "        rglNormalDraw();\n"
     "        if (direct == 0) {\n"
     "            telegram_sphere.params.alpha = t(0, 1, 0, duration_const * 0.8f, Linear);\n"
     "            scale = 1;\n"
     "\n"
     "            telegram_sphere.params.scale = xyzMake(scale, scale, 1);\n"
     "            draw_textured_shape(&telegram_sphere, main_matrix, NORMAL);\n"
     "\n"
     "            float tt = MINf(0, (float) (-M_PI * 125.0f / 180.0f + time * M_PI * 2 * 1.5f));\n"
     "            float dx = t(-75, 0, 0, 0.15f, EaseIn);\n"
     "            float dy = t(75, 0, 0, 0.15f, EaseIn);\n"
     "            telegram_plane.params.position = xyzMake(dx, dy, 0);\n"
     "            float scale = t(0.1f, 1, 0.03f, 0.15f, EaseOut);\n"
     "            telegram_plane.params.scale = xyzMake(scale, scale, 1);\n"
     "\n"
     "            if (tt < D2R(125)) {\n"
     "                glBlendFunc(GL_ONE, GL_ONE_MINUS_SRC_ALPHA);\n"
     "                draw_textured_shape(&telegram_plane, main_matrix, NORMAL_ONE);\n"
     "                draw_textured_shape(&telegram_mask, main_matrix, NORMAL);\n"
     "            }\n"
     "        }\n"
     "    } else if (current_page == 1) {\n"
     "        rglNormalDraw();\n"
     "        if (direct == 1) {\n"
     "            telegram_sphere.params.alpha = t(1, 0, 0, duration_const, Linear);\n"
     "            draw_textured_shape(&telegram_sphere, main_matrix, NORMAL);\n"
     "\n"
     "            double tt = time * M_PI * 2 * 1.5f;\n"
     "\n"
     "            float dx = t(0, 75, 0, 0.15f, EaseOut);\n"
     "            float dy = t(0, -75, 0, 0.15f, EaseOut);\n"
     "\n"
     "            telegram_plane.params.position = xyzMake(dx, dy, 0);\n"
     "\n"
     "            float scale = t(1, 0.1f, 0.03f, 0.15f, EaseOut);\n"
     "            telegram_plane.params.scale = xyzMake(scale, scale, 1);\n"
     "\n"
     "            if (tt < D2R(125)) {\n"
     "                glBlendFunc(GL_ONE, GL_ONE_MINUS_SRC_ALPHA);\n"
     "                draw_textured_shape(&telegram_plane, main_matrix, NORMAL_ONE);\n"
     "                draw_textured_shape(&telegram_mask, main_matrix, NORMAL);\n"
     "            }\n"
     "        }\n"
     "    } else if (current_page == 2) {\n",
     "    if (current_page == 0 || current_page == 1) {\n"
     "        // pluma: no disc and no plane; page 1 shows the mark writing itself (IntroActivity).\n"
     "        rglNormalDraw();\n"
     "    } else if (current_page == 2) {\n"),
    (INTRO, "import android.view.WindowManager;\n",
     "import android.view.WindowManager;\nimport android.view.animation.LinearInterpolator;\n"),
    (INTRO,
     "    private final static int ICON_WIDTH_DP = 200, ICON_HEIGHT_DP = 150;\n",
     "    private final static int ICON_WIDTH_DP = 200, ICON_HEIGHT_DP = 150;\n"
     "    // pluma: page 1 shows Pluma's mark writing itself (layout B of the intro). MARK_DP is the height\n"
     "    // of the mark's ink, MARK_GAP_DP the gap from it to the wordmark, MARK_BIAS where the group from\n"
     "    // the mark down to the page dots sits in the free space between the status bar and the start\n"
     "    // button (0 at the top, 1 at the bottom).\n"
     "    private final static float MARK_DP = 128, MARK_GAP_DP = 32, MARK_BIAS = 0.44f;\n"
     "    // The resting ink of pluma_mark_write.json in its 512-unit grid, round caps included\n"
     "    // (brand/mark_write.py prints it).\n"
     "    private final static float MARK_GRID = 512, MARK_INK_LEFT = 79.6f, MARK_INK_TOP = 99.95f,\n"
     "            MARK_INK_RIGHT = 433.1f, MARK_INK_BOTTOM = 405.15f;\n"
     "    // The 148-unit pictures centred in the GL box (the speedometer of page 2) end where the mark's\n"
     "    // ink ends; the page dots keep upstream's distance under the titles; the start button sits over\n"
     "    // the navigation bar.\n"
     "    private final static int PICTURE_BOTTOM_DP = (ICON_HEIGHT_DP + 148) / 2,\n"
     "            TITLE_TO_DOTS_DP = 122 + 17 - (16 + 9), BUTTON_BOTTOM_DP = 24;\n"
     "    // The mark crosses with the pictures at their pace (duration_const of IntroRenderer.c).\n"
     "    private final static int MARK_FADE_MS = 300;\n"
     "    // The layers of the animation and the kit's ink for them, the ring and then the feathers from\n"
     "    // the nib outwards, on light and on dark paper.\n"
     '    private final static String[] MARK_LAYERS = {"Ring.**", "Feather1.**", "Feather2.**", "Feather3.**"};\n'
     "    private final static int[] MARK_INK_LIGHT = {0xFF111111, 0xFF4A4A4A, 0xFF8A8A8A, 0xFFBDBDBD};\n"
     "    private final static int[] MARK_INK_DARK = {0xFFE8ECE8, 0xFFBDBDBD, 0xFF8A8A8A, 0xFF6B6F6B};\n"),
    (INTRO,
     "    private FrameLayout frameContainerView;\n",
     "    private FrameLayout frameContainerView;\n"
     "    // pluma: the mark of page 1, seen while page 1 is selected (markShown) and fading as the page\n"
     "    // scrolls away (markScroll), in the ink it was last given (markInk).\n"
     "    private RLottieImageView markView;\n"
     "    private RLottieDrawable markDrawable;\n"
     "    private ValueAnimator markAnimator;\n"
     "    private int[] markInk;\n"
     "    private float markShown, markScroll = 1;\n"),
    (INTRO,
     "        logoDrawable.setBounds(0, dp(8.666f), dp(115), dp(35));\n",
     "        // pluma: the word starts at the top of the title, MARK_GAP_DP under the mark.\n"
     "        logoDrawable.setBounds(0, 0, dp(115), dp(26.333f));\n"),
    (INTRO,
     "                int oneFourth = (bottom - top) / 4;\n"
     "\n"
     "                int y = (oneFourth * 3 - dp(275)) / 2;\n"
     "                frameLayout2.layout(0, y, frameLayout2.getMeasuredWidth(), y + frameLayout2.getMeasuredHeight());\n"
     "                y += dp(ICON_HEIGHT_DP);\n"
     "                y += dp(122 + 17);\n"
     "                int x = (getMeasuredWidth() - bottomPages.getMeasuredWidth()) / 2;\n"
     "                bottomPages.layout(x, y, x + bottomPages.getMeasuredWidth(), y + bottomPages.getMeasuredHeight());\n"
     "                viewPager.layout(0, 0, viewPager.getMeasuredWidth(), viewPager.getMeasuredHeight());\n"
     "\n"
     "                y = oneFourth * 3 + (oneFourth - startMessagingButton.getMeasuredHeight()) / 2;\n",
     "                // pluma: layout B. The mark's ink ends MARK_GAP_DP over the titles, and so do the\n"
     "                // pictures of the GL box.\n"
     "                int title = titleTop(bottom - top);\n"
     "                float k = markView.getMeasuredWidth() / MARK_GRID;\n"
     "                int x = Math.round(getMeasuredWidth() / 2f - (MARK_INK_LEFT + MARK_INK_RIGHT) / 2 * k);\n"
     "                int y = Math.round(title - dpf2(MARK_GAP_DP) - MARK_INK_BOTTOM * k);\n"
     "                markView.layout(x, y, x + markView.getMeasuredWidth(), y + markView.getMeasuredHeight());\n"
     "                y = title - dp(MARK_GAP_DP + PICTURE_BOTTOM_DP);\n"
     "                frameLayout2.layout(0, y, frameLayout2.getMeasuredWidth(), y + frameLayout2.getMeasuredHeight());\n"
     "                y = title + dp(TITLE_TO_DOTS_DP);\n"
     "                x = (getMeasuredWidth() - bottomPages.getMeasuredWidth()) / 2;\n"
     "                bottomPages.layout(x, y, x + bottomPages.getMeasuredWidth(), y + bottomPages.getMeasuredHeight());\n"
     "                viewPager.layout(0, 0, viewPager.getMeasuredWidth(), viewPager.getMeasuredHeight());\n"
     "\n"
     "                y = buttonTop(bottom - top);\n"),
    (INTRO,
     "        frameLayout2.addView(textureView, LayoutHelper.createFrame(ICON_WIDTH_DP, ICON_HEIGHT_DP, Gravity.CENTER));\n",
     "        frameLayout2.addView(textureView, LayoutHelper.createFrame(ICON_WIDTH_DP, ICON_HEIGHT_DP, Gravity.CENTER));\n"
     "\n"
     "        // pluma: the mark of page 1, over the GL box, which draws no disc there. The animation's\n"
     "        // 512-unit grid is drawn at the size that makes the mark's ink MARK_DP high. A view made\n"
     "        // again (rebuildAllFragmentViews) starts with a mark of its own.\n"
     "        releaseMark();\n"
     "        int markSize = dp(MARK_DP * MARK_GRID / (MARK_INK_BOTTOM - MARK_INK_TOP));\n"
     '        markDrawable = new RLottieDrawable(R.raw.pluma_mark_write, "" + R.raw.pluma_mark_write, markSize, markSize, false, null);\n'
     "        // With the system's animations off, the written mark. Its frame is set while nothing decodes yet\n"
     "        // (setAnimation starts the first decode): a frame set during a decode can be lost, as that decode\n"
     "        // then takes the new frame for the end and keeps its own.\n"
     "        if (AndroidUtilities.getAnimatorDurationScale() == 0) {\n"
     "            markDrawable.setCurrentFrame(markDrawable.getFramesCount() - 1, true);\n"
     "        }\n"
     "        markView = new RLottieImageView(context);\n"
     "        markView.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);\n"
     "        updateMarkInk();\n"
     "        markView.setAnimation(markDrawable);\n"
     "        markView.setAlpha(0f);\n"
     "        frameContainerView.addView(markView, new FrameLayout.LayoutParams(markSize, markSize));\n"),
    (INTRO,
     "                bottomPages.setPageOffset(position, positionOffset);\n",
     "                bottomPages.setPageOffset(position, positionOffset);\n"
     "                // pluma: the mark fades as page 1 scrolls away, gone at half a page.\n"
     "                markScroll = position == 0 ? Math.max(0, 1 - 2 * positionOffset) : 0;\n"
     "                updateMarkAlpha();\n"),
    (INTRO,
     "            public void onPageSelected(int i) {\n"
     "                currentViewPagerPage = i;\n"
     "            }\n",
     "            public void onPageSelected(int i) {\n"
     "                currentViewPagerPage = i;\n"
     "                showMark(i == 0, true); // pluma: the mark of page 1\n"
     "            }\n"),
    (INTRO,
     "                    int oneFourth = (bottom - top) / 4;\n"
     "                    int y = (oneFourth * 3 - dp(275)) / 2;\n"
     "                    y += dp(ICON_HEIGHT_DP);\n"
     "                    y += dp(16 + 9);\n",
     "                    int y = titleTop(bottom - top); // pluma: layout B\n"),
    (INTRO,
     "                viewPager.setCurrentItem(0);\n"
     "                lastPage = 0;\n"
     "            }\n"
     "            justCreated = false;\n",
     "                viewPager.setCurrentItem(0);\n"
     "                lastPage = 0;\n"
     "            }\n"
     "            showMark(viewPager.getCurrentItem() == 0, false); // pluma: page 1 opens with the mark writing itself\n"
     "            justCreated = false;\n"),
    (INTRO,
     "        super.onFragmentDestroy();\n"
     "        destroyed = true;\n",
     "        super.onFragmentDestroy();\n"
     "        destroyed = true;\n"
     "        releaseMark(); // pluma: the mark of page 1\n"),
    (INTRO,
     "    @Override\n"
     "    public ArrayList<ThemeDescription> getThemeDescriptions() {\n",
     "    // pluma: layout B of the intro and the mark of page 1.\n"
     "    private int buttonTop(int height) {\n"
     "        return height - dp(BUTTON_BOTTOM_DP) - startMessagingButton.getMeasuredHeight();\n"
     "    }\n"
     "\n"
     "    // The top of the titles: the group from the mark's ink down to the page dots sits at MARK_BIAS of\n"
     "    // the free space between the status bar and the start button, 16 dp clear of the language link\n"
     "    // (30 dp high, 30 dp over the button).\n"
     "    private int titleTop(int height) {\n"
     "        float top = AndroidUtilities.isTablet() ? 0 : AndroidUtilities.statusBarHeight;\n"
     "        float button = buttonTop(height);\n"
     "        float group = dpf2(MARK_DP + MARK_GAP_DP + TITLE_TO_DOTS_DP) + bottomPages.getMeasuredHeight();\n"
     "        float y = top + MARK_BIAS * Math.max(0, button - top - group);\n"
     "        y = Math.max(top, Math.min(y, button - dpf2(30 + 30 + 16) - group));\n"
     "        return Math.round(y + dpf2(MARK_DP + MARK_GAP_DP));\n"
     "    }\n"
     "\n"
     "    // The mark shows while page 1 is selected and crosses with the pictures of IntroRenderer, which\n"
     "    // change on selection too. Each time it comes back from hidden it writes itself again, and until\n"
     "    // its first frame is decoded nothing is drawn rather than the written mark of the time before\n"
     "    // (the flag is set for that reset only: start(), which the view calls again each time it is\n"
     "    // attached, would blank the written mark too). With the system's animations off it keeps the\n"
     "    // written mark createView chose.\n"
     "    private void showMark(boolean show, boolean animated) {\n"
     "        if (markAnimator != null) {\n"
     "            markAnimator.cancel();\n"
     "            markAnimator = null;\n"
     "        }\n"
     "        if (show && markShown == 0) {\n"
     "            if (AndroidUtilities.getAnimatorDurationScale() != 0) {\n"
     "                markDrawable.setInvalidateOnProgressSet(true);\n"
     "                markDrawable.setCurrentFrame(0, true, true);\n"
     "                markDrawable.setInvalidateOnProgressSet(false);\n"
     "                markView.playAnimation();\n"
     "            } else if (!markDrawable.isLastFrame()) {\n"
     "                markDrawable.setCurrentFrame(markDrawable.getFramesCount() - 1, true, true);\n"
     "            }\n"
     "        }\n"
     "        float shown = show ? 1 : 0;\n"
     "        if (!animated) {\n"
     "            markShown = shown;\n"
     "            updateMarkAlpha();\n"
     "            return;\n"
     "        }\n"
     "        markAnimator = ValueAnimator.ofFloat(markShown, shown);\n"
     "        markAnimator.addUpdateListener(a -> {\n"
     "            markShown = (float) a.getAnimatedValue();\n"
     "            updateMarkAlpha();\n"
     "        });\n"
     "        markAnimator.setInterpolator(new LinearInterpolator());\n"
     "        markAnimator.setDuration(MARK_FADE_MS);\n"
     "        markAnimator.start();\n"
     "    }\n"
     "\n"
     "    private void releaseMark() {\n"
     "        if (markAnimator != null) {\n"
     "            markAnimator.cancel();\n"
     "            markAnimator = null;\n"
     "        }\n"
     "        if (markDrawable != null) {\n"
     "            markDrawable.recycle(false);\n"
     "        }\n"
     "        markInk = null;\n"
     "        markShown = 0;\n"
     "        markScroll = 1;\n"
     "    }\n"
     "\n"
     "    private void updateMarkAlpha() {\n"
     "        markView.setAlpha(markShown * markScroll);\n"
     "    }\n"
     "\n"
     "    // The four layers change together, in one decode, and only when the ink does: updateColors also\n"
     "    // runs at every step of an animated theme change.\n"
     "    private void updateMarkInk() {\n"
     "        int[] ink = Theme.isCurrentThemeDark() ? MARK_INK_DARK : MARK_INK_LIGHT;\n"
     "        if (ink == markInk) {\n"
     "            return;\n"
     "        }\n"
     "        markInk = ink;\n"
     "        markDrawable.beginApplyLayerColors();\n"
     "        for (int i = 0; i < MARK_LAYERS.length; i++) {\n"
     "            markView.setLayerColor(MARK_LAYERS[i], ink[i]);\n"
     "        }\n"
     "        markDrawable.commitApplyLayerColors();\n"
     "    }\n"
     "\n"
     "    @Override\n"
     "    public ArrayList<ThemeDescription> getThemeDescriptions() {\n"),
    (INTRO,
     "        darkThemeDrawable.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_featuredStickers_addButton), "
     "PorterDuff.Mode.SRC_IN));\n",
     "        darkThemeDrawable.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_featuredStickers_addButton), "
     "PorterDuff.Mode.SRC_IN));\n"
     "        updateMarkInk(); // pluma: the mark in the kit's ink for the theme\n"),
)
# The pace of the pictures, which the mark's fade (MARK_FADE_MS) follows.
INTRO_PACE = (INTRO_RENDERER, "static float duration_const = 0.3f;\n")
# What only the old layout, the wordmark's old place, the disc and plane of
# page 1 and the speedometer shown at once under the disc had: none of it may
# be left.
INTRO_GONE = ((INTRO, "oneFourth"), (INTRO, "dp(275)"), (INTRO, "dp(8.666f)"),
              (INTRO_RENDERER, "draw_textured_shape(&telegram_"), (INTRO_RENDERER, "fast_body.params.alpha = 1;"))
# IntroActivity after the edits, each text once: the fade's interpolator, the
# layout's numbers and the mark's fields; the wordmark at the top of the title;
# the mark created from the bundled animation, fading with the scroll, played
# when the page is selected and when the intro opens, released with the
# screen; the layout and the mark's methods; the ink following the theme.
# Together with INTRO_GONE every edit of INTRO_EDITS leaves a trace here.
INTRO_MARK = (
    "import android.view.animation.LinearInterpolator;\n",
    "private final static float MARK_DP = ",
    "private RLottieImageView markView;\n",
    "logoDrawable.setBounds(0, 0, dp(115), dp(26.333f));\n",
    'new RLottieDrawable(R.raw.pluma_mark_write, "" + R.raw.pluma_mark_write,',
    "markScroll = position == 0 ? Math.max(0, 1 - 2 * positionOffset) : 0;\n",
    "showMark(i == 0, true);",
    "showMark(viewPager.getCurrentItem() == 0, false);",
    "releaseMark(); // pluma: the mark of page 1\n",
    "private int titleTop(int height) {\n",
    "private void showMark(boolean show, boolean animated) {\n",
    "updateMarkInk(); // pluma: the mark in the kit's ink for the theme\n",
)

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
# The QR login's links to the desktop and web clients, the one exception to
# keeping telegram.org: Pluma's site and its web client (the owner's
# decision). The steps of "Link Desktop Device" (ActionIntroActivity), the
# text under the laptop of Settings > Devices (SessionsActivity) and the
# scanner's hint (CameraScanActivity) show them. Each entry: the key, the
# upstream text, the new one, and the language folders whose strings.xml have
# it; no other folder may have the key. A URL is the whole text; in a
# sentence, the link is what the code turns into one, between asterisks.
LINK_LANGUAGES = ("values", "values-ar", "values-de", "values-es", "values-it", "values-ko", "values-nl", "values-pt-rBR")
CLIENT_LINKS = (
    ("AuthAnotherClientDownloadClientUrl", "https://getdesktop.telegram.org/", "https://pluma.chat/", ("values",)),
    ("AuthAnotherClientDownloadClientUrl", "https://desktop.telegram.org", "https://pluma.chat/", ("values-ar",)),
    ("AuthAnotherClientDownloadClientUrl", "https://desktop.telegram.org/", "https://pluma.chat/", LINK_LANGUAGES[2:]),
    ("AuthAnotherWebClientUrl", "https://web.telegram.org/", "https://web.pluma.chat/", LINK_LANGUAGES),
    ("AuthAnotherClientInfo1", "*getdesktop.telegram.org*", "*pluma.chat*", ("values",)),
    ("AuthAnotherClientInfo1", "*desktop.telegram.org*", "*pluma.chat*", LINK_LANGUAGES[1:]),
    ("AuthAnotherClientInfo5", "*getdesktop.telegram.org*", "*pluma.chat*", ("values",)),
    ("AuthAnotherClientInfo5", "*web.telegram.org*", "*web.pluma.chat*", ("values",)),
)
# Telegram's client sites, which no built-in string may name after the edits.
CLIENT_SITES = re.compile(r"(?:get)?desktop\.telegram\.org|web\.telegram\.org")

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

# Palette "graphite and sage" (docs/tasks/017-rebranding.md of the server
# repository) in the five themes the app bundles: the default day theme "Blue"
# with its home accent, the default night theme "Dark Blue", and "Day",
# "Arctic Blue" and "Night". The accent engine shifts every remaining colour
# near the theme's blue base to the sage accent; these keys get the palette's
# exact values, which lie outside the shifted hues. Each entry is (key, the
# upstream value or None when the key is not set, the new colour).
# Upstream answers Telegram's built-in colours (ThemeColors) for the home
# accent of "Blue" and skips both the theme file and the accent engine;
# brand_theme makes that accent go through them like any other.
# bluebubbles.attheme ("Blue").
PALETTE_LIGHT = (
    # text
    ("windowBackgroundWhiteBlackText", None, "#111111"),
    ("chats_name", None, "#111111"),
    ("chat_messageTextIn", None, "#111111"),
    ("actionBarDefaultTitle", None, "#111111"),
    ("dialogTextBlack", None, "#111111"),
    ("telegram_color_dialogsLogo", None, "#111111"),
    # secondary text
    ("windowBackgroundWhiteGrayText", -7565423, "#6B6F6B"),
    ("windowBackgroundWhiteGrayText2", -7565423, "#6B6F6B"),
    ("windowBackgroundWhiteGrayText3", -7565423, "#6B6F6B"),
    ("chats_message", None, "#6B6F6B"),
    ("chats_date", None, "#6B6F6B"),
    ("actionBarDefaultSubtitle", -8156010, "#6B6F6B"),
    # accent: buttons, switches, counters, checks
    ("telegram_color", -14509328, "#5B7A5E"),
    ("chats_unreadCounter", -14509328, "#5B7A5E"),
    ("switchTrackChecked", -14509328, "#5B7A5E"),
    ("chats_actionBackground", -10376481, "#5B7A5E"),
    ("chat_messagePanelSend", None, "#5B7A5E"),
    ("windowBackgroundWhiteBlueHeader", -14380330, "#5B7A5E"),
    ("windowBackgroundWhiteBlueText", -16285752, "#5B7A5E"),
    ("windowBackgroundWhiteBlueText4", None, "#5B7A5E"),
    ("windowBackgroundWhiteValueText", -13003565, "#5B7A5E"),
    ("featuredStickers_addButton", None, "#5B7A5E"),
    ("dialogTextBlue", -14510887, "#5B7A5E"),
    ("dialogTextBlue2", -14510887, "#5B7A5E"),
    ("dialogButton", -13200935, "#5B7A5E"),
    ("checkboxSquareBackground", None, "#5B7A5E"),
    ("checkbox", None, "#5B7A5E"),
    ("radioBackgroundChecked", None, "#5B7A5E"),
    ("progressCircle", -14375188, "#5B7A5E"),
    ("chats_sentCheck", -15753754, "#5B7A5E"),
    ("chats_sentReadCheck", -15754010, "#5B7A5E"),
    ("actionBarTabLine", None, "#5B7A5E"),
    ("actionBarTabActiveText", None, "#5B7A5E"),
    ("windowBackgroundWhiteInputFieldActivated", None, "#5B7A5E"),
    ("dialogTopBackground", -13473128, "#5B7A5E"),
    ("chats_actionPressedBackground", -11166764, "#4F6E52"),
    ("featuredStickers_addButtonPressed", -12412453, "#4F6E52"),
    # text on the accent
    ("chats_unreadCounterText", None, "#FFFFFF"),
    ("chats_actionIcon", None, "#FFFFFF"),
    ("featuredStickers_buttonText", None, "#FFFFFF"),
    # the blue identity colour of people (Theme.keys_avatar_*[5]): sage
    ("avatar_backgroundBlue", None, "#7FA082"),
    ("avatar_background2Blue", None, "#5B7A5E"),
    ("avatar_nameInMessageBlue", -14643754, "#4F6E52"),
    # the cyan identity colour (Theme.keys_avatar_*[4]): teal, without the blue of Telegram's
    ("avatar_backgroundCyan", None, "#5BCBC4"),
    ("avatar_background2Cyan", None, "#2C9C98"),
    ("avatar_nameInMessageCyan", -13655095, "#1F8A80"),
    # Telegram's blue and light blue as plain colours (the playback speed slider, a bot's
    # emoji status permission, the fallback of statistics chart lines) and the internal
    # storage of the file picker: sage
    ("color_blue", -13467675, "#5B7A5E"),
    ("color_lightblue", -10966803, "#8FAE92"),
    ("chat_attachGalleryBackground", None, "#5B7A5E"),
    # soft accent: avatars, selection
    ("avatar_backgroundSaved", -9847303, "#6F8F72"),
    ("avatar_backgroundArchivedHidden", -10832396, "#6F8F72"),
    ("chat_selectedBackground", 839350980, "#325B7A5E"),
    ("windowBackgroundWhiteLinkSelection", None, "#335B7A5E"),
    # links
    ("windowBackgroundWhiteLinkText", -14054705, "#4F6E52"),
    ("chat_messageLinkIn", -16090691, "#4F6E52"),
    ("chat_messageLinkOut", -16155709, "#4F6E52"),
    ("dialogTextLink", -14057020, "#4F6E52"),
    ("telegram_color_text", None, "#4F6E52"),
    # bubbles
    ("chat_inBubble", None, "#F1F2F0"),
    ("chat_inBubbleSelected", -1509892, "#E3EAE2"),
    ("chat_outBubble", -1641732, "#E3EAE2"),
    ("chat_outBubbleGradient", None, "#D5E1D4"),
    ("chat_outBubbleSelected", -2690305, "#D5E1D4"),
    ("chat_messageTextOut", None, "#1F2E20"),
    # time and checks in outgoing
    ("chat_outTimeText", -141776195, "#5B7A5E"),
    ("chat_outTimeSelectedText", -8674358, "#5B7A5E"),
    ("chat_outSentCheck", -14967834, "#5B7A5E"),
    ("chat_outSentCheckSelected", -14968350, "#5B7A5E"),
    ("chat_outSentCheckRead", -14967834, "#5B7A5E"),
    ("chat_outSentCheckReadSelected", None, "#5B7A5E"),
    ("chat_outSentClock", -594761027, "#5B7A5E"),
    ("chat_outSentClockSelected", -260332598, "#5B7A5E"),
    ("chat_outViews", -259216707, "#5B7A5E"),
    ("chat_outViewsSelected", -260332598, "#5B7A5E"),
)
# darkblue.attheme ("Dark Blue").
PALETTE_DARK = (
    # backgrounds
    ("windowBackgroundWhite", -14866637, "#131513"),
    ("chats_menuBackground", -14998481, "#131513"),
    ("chat_wallpaper", -15393241, "#131513"),
    ("windowBackgroundUnchecked", -14866637, "#131513"),
    ("switchTrackBlueThumb", -14866637, "#131513"),
    ("windowBackgroundGray", -15393241, "#0D0F0D"),
    ("graySection", -15459033, "#0D0F0D"),
    ("actionBarDefault", -14406343, "#1B1F1B"),
    ("actionBarActionModeDefault", -14273984, "#1B1F1B"),
    ("actionBarActionModeDefaultTop", -14536643, "#1B1F1B"),
    ("chats_menuTopBackgroundCats", -14471105, "#1B1F1B"),
    ("dialogBackground", -14602949, "#1B1F1B"),
    ("dialogBackgroundGray", -14932431, "#161916"),
    ("actionBarDefaultSubmenuBackground", -14141368, "#1E221E"),
    ("actionBarDefaultArchived", -13748149, "#232623"),
    # text
    ("windowBackgroundWhiteBlackText", -1, "#E8ECE8"),
    ("chats_name", -1446156, "#E8ECE8"),
    ("chats_nameMessage", -1446156, "#E8ECE8"),
    ("chats_nameMessage_threeLines", -1446156, "#E8ECE8"),
    ("chat_messageTextIn", -328966, "#E8ECE8"),
    ("chat_messageTextOut", -328966, "#E8ECE8"),
    ("actionBarDefaultTitle", -1, "#E8ECE8"),
    ("actionBarDefaultIcon", -1, "#E8ECE8"),
    ("dialogTextBlack", -592138, "#E8ECE8"),
    # secondary text
    ("windowBackgroundWhiteGrayText", -8549479, "#9AA29A"),
    ("windowBackgroundWhiteGrayText3", -8549479, "#9AA29A"),
    ("windowBackgroundWhiteGrayText5", -8549479, "#9AA29A"),
    ("windowBackgroundWhiteGrayText6", -8549479, "#9AA29A"),
    ("windowBackgroundWhiteGrayText8", -8549479, "#9AA29A"),
    ("windowBackgroundWhiteHintText", -8549479, "#9AA29A"),
    ("windowBackgroundWhiteGrayIcon", -8549479, "#9AA29A"),
    ("chats_message", -8549479, "#9AA29A"),
    ("chats_message_threeLines", -8549479, "#9AA29A"),
    ("chats_date", -9207925, "#9AA29A"),
    ("chats_nameMessageArchived", -8549479, "#9AA29A"),
    ("actionBarDefaultSubtitle", 2111566591, "#9AA29A"),
    ("chat_inTimeText", -645885536, "#9AA29A"),
    ("chats_menuItemIcon", -8483430, "#9AA29A"),
    ("actionBarTabUnactiveText", -7628894, "#9AA29A"),
    # accent: buttons, switches, counters, checks
    ("telegram_color", None, "#9DBB9F"),
    ("chats_unreadCounter", -10177041, "#9DBB9F"),
    ("switchTrackChecked", -10378281, "#9DBB9F"),
    ("chats_actionBackground", -10509346, "#9DBB9F"),
    ("chat_messagePanelSend", -14509328, "#9DBB9F"),
    ("windowBackgroundWhiteBlueHeader", -8796932, "#9DBB9F"),
    ("windowBackgroundWhiteBlueText", -10177041, "#9DBB9F"),
    ("windowBackgroundWhiteBlueText3", -10177041, "#9DBB9F"),
    ("windowBackgroundWhiteBlueText4", -10177041, "#9DBB9F"),
    ("windowBackgroundWhiteBlueText5", -10177041, "#9DBB9F"),
    ("windowBackgroundWhiteValueText", -528890628, "#9DBB9F"),
    ("featuredStickers_addButton", None, "#9DBB9F"),
    ("dialogTextBlue", -10177041, "#9DBB9F"),
    ("dialogTextBlue2", -10177041, "#9DBB9F"),
    ("dialogTextBlue4", -10177041, "#9DBB9F"),
    ("dialogButton", -10177041, "#9DBB9F"),
    ("checkboxSquareBackground", -10177051, "#9DBB9F"),
    ("checkbox", None, "#9DBB9F"),
    ("radioBackgroundChecked", -10177041, "#9DBB9F"),
    ("progressCircle", -10177027, "#9DBB9F"),
    ("actionBarTabLine", -10179073, "#9DBB9F"),
    ("actionBarTabActiveText", -9781249, "#9DBB9F"),
    ("chats_sentCheck", -10177041, "#9DBB9F"),
    ("chats_sentReadCheck", None, "#9DBB9F"),
    ("windowBackgroundWhiteInputFieldActivated", -9522449, "#9DBB9F"),
    ("chats_actionMessage", -10178583, "#9DBB9F"),
    ("chats_actionPressedBackground", None, "#B2CEB4"),
    ("featuredStickers_addButtonPressed", None, "#B2CEB4"),
    # text on the accent
    ("chats_unreadCounterText", None, "#131513"),
    ("chats_actionIcon", None, "#131513"),
    ("featuredStickers_buttonText", None, "#131513"),
    # the blue identity colour of people (Theme.keys_avatar_*[5]): sage
    ("avatar_backgroundBlue", None, "#7FA082"),
    ("avatar_background2Blue", None, "#5B7A5E"),
    ("avatar_nameInMessageBlue", -10703382, "#9DBB9F"),
    # the cyan identity colour (Theme.keys_avatar_*[4]): teal, without the blue of Telegram's
    ("avatar_backgroundCyan", None, "#5BCBC4"),
    ("avatar_background2Cyan", None, "#2C9C98"),
    # Telegram's blue and light blue as plain colours (the playback speed slider, a bot's
    # emoji status permission, the fallback of statistics chart lines) and the internal
    # storage of the file picker: sage
    ("color_blue", -11362305, "#9DBB9F"),
    ("color_lightblue", -12814100, "#7FA082"),
    ("chat_attachGalleryBackground", -11692299, "#7FA082"),
    # soft accent: avatars, selection
    ("avatar_backgroundSaved", None, "#7FA082"),
    ("windowBackgroundChecked", -11632213, "#2C3A2D"),
    ("chat_selectedBackground", 710909411, "#2A9DBB9F"),
    ("windowBackgroundWhiteLinkSelection", 862238205, "#339DBB9F"),
    # links
    ("windowBackgroundWhiteLinkText", -10572831, "#B2CEB4"),
    ("chat_messageLinkIn", -8796932, "#B2CEB4"),
    ("chat_messageLinkOut", -6631937, "#B2CEB4"),
    ("dialogTextLink", -10177041, "#B2CEB4"),
    ("telegram_color_text", None, "#B2CEB4"),
    # bubbles
    ("chat_inBubble", -14471621, "#232623"),
    ("chat_inBubbleSelected", -13546911, "#2C3A2D"),
    ("chat_outBubble", -12689014, "#2C3A2D"),
    ("chat_outBubbleGradient", None, "#36473A"),
    ("chat_outBubbleSelected", -11829841, "#36473A"),
    # time and checks in outgoing
    ("chat_outTimeText", -7357217, "#B2CEB4"),
    ("chat_outTimeSelectedText", -4268038, "#B2CEB4"),
    ("chat_outSentCheck", -7878657, "#B2CEB4"),
    ("chat_outSentCheckSelected", -4268038, "#B2CEB4"),
    ("chat_outSentCheckRead", None, "#B2CEB4"),
    ("chat_outSentCheckReadSelected", None, "#B2CEB4"),
    ("chat_outSentClock", -8213557, "#B2CEB4"),
    ("chat_outSentClockSelected", -4268038, "#B2CEB4"),
    ("chat_outViews", -7357217, "#B2CEB4"),
    ("chat_outViewsSelected", -4268038, "#B2CEB4"),
)
# day.attheme ("Day"): the keys of PALETTE_LIGHT, except in the outgoing
# bubble. Day and Arctic Blue colour that bubble and write on it in white, as
# Telegram does, so it takes the accent rather than the palette's light bubble.
# White reads 4.8:1 on it and 3.6:1 at the light end of Day's gradient
# (Telegram's Day: 4.2:1 and 2.3:1). Day's time, views and file details on it
# are the palette's pale sage, 3.9:1 and 2.9:1 (Telegram's: 3.2:1 and 1.8:1);
# shifted by the accent engine, they would read 2.6:1 and 2.0:1.
PALETTE_DAY = (
    # text
    ("windowBackgroundWhiteBlackText", -13421773, "#111111"),
    ("chats_name", None, "#111111"),
    ("chat_messageTextIn", None, "#111111"),
    ("actionBarDefaultTitle", -13421773, "#111111"),
    ("dialogTextBlack", None, "#111111"),
    ("telegram_color_dialogsLogo", None, "#111111"),
    # secondary text
    ("windowBackgroundWhiteGrayText", -8354940, "#6B6F6B"),
    ("windowBackgroundWhiteGrayText2", None, "#6B6F6B"),
    ("windowBackgroundWhiteGrayText3", None, "#6B6F6B"),
    ("chats_message", None, "#6B6F6B"),
    ("chats_date", None, "#6B6F6B"),
    ("actionBarDefaultSubtitle", -8814210, "#6B6F6B"),
    # accent: buttons, switches, counters, checks
    ("telegram_color", None, "#5B7A5E"),
    ("chats_unreadCounter", -14373129, "#5B7A5E"),
    ("switchTrackChecked", -14509328, "#5B7A5E"),
    ("chats_actionBackground", -11427096, "#5B7A5E"),
    ("chat_messagePanelSend", -14509328, "#5B7A5E"),
    ("windowBackgroundWhiteBlueHeader", -14054705, "#5B7A5E"),
    ("windowBackgroundWhiteBlueText", -14447901, "#5B7A5E"),
    ("windowBackgroundWhiteBlueText4", -12675352, "#5B7A5E"),
    ("windowBackgroundWhiteValueText", -14054705, "#5B7A5E"),
    ("featuredStickers_addButton", -11689749, "#5B7A5E"),
    ("dialogTextBlue", -14709290, "#5B7A5E"),
    ("dialogTextBlue2", -14772773, "#5B7A5E"),
    ("dialogButton", -13987604, "#5B7A5E"),
    ("checkboxSquareBackground", None, "#5B7A5E"),
    ("checkbox", None, "#5B7A5E"),
    ("radioBackgroundChecked", -14509328, "#5B7A5E"),
    ("progressCircle", -12605954, "#5B7A5E"),
    ("chats_sentCheck", -15032337, "#5B7A5E"),
    ("chats_sentReadCheck", -15033105, "#5B7A5E"),
    ("actionBarTabLine", -14054705, "#5B7A5E"),
    ("actionBarTabActiveText", -14054705, "#5B7A5E"),
    ("windowBackgroundWhiteInputFieldActivated", None, "#5B7A5E"),
    ("dialogTopBackground", None, "#5B7A5E"),
    ("chats_actionPressedBackground", -13201944, "#4F6E52"),
    ("featuredStickers_addButtonPressed", None, "#4F6E52"),
    # text on the accent
    ("chats_unreadCounterText", None, "#FFFFFF"),
    ("chats_actionIcon", None, "#FFFFFF"),
    ("featuredStickers_buttonText", None, "#FFFFFF"),
    # the blue identity colour of people (Theme.keys_avatar_*[5]): sage
    ("avatar_backgroundBlue", -11491866, "#7FA082"),
    ("avatar_background2Blue", None, "#5B7A5E"),
    ("avatar_nameInMessageBlue", -14317866, "#4F6E52"),
    # the cyan identity colour (Theme.keys_avatar_*[4]): teal, without the blue of Telegram's
    ("avatar_backgroundCyan", None, "#5BCBC4"),
    ("avatar_background2Cyan", None, "#2C9C98"),
    ("avatar_nameInMessageCyan", None, "#1F8A80"),
    # Telegram's blue and light blue as plain colours (the playback speed slider, a bot's
    # emoji status permission, the fallback of statistics chart lines) and the internal
    # storage of the file picker: sage
    ("color_blue", -13467675, "#5B7A5E"),
    ("color_lightblue", -10966803, "#8FAE92"),
    ("chat_attachGalleryBackground", None, "#5B7A5E"),
    # soft accent: avatars, selection
    ("avatar_backgroundSaved", -12208385, "#6F8F72"),
    ("avatar_backgroundArchivedHidden", -14509328, "#6F8F72"),
    ("chat_selectedBackground", 134217728, "#325B7A5E"),
    ("windowBackgroundWhiteLinkSelection", 560114147, "#335B7A5E"),
    # links
    ("windowBackgroundWhiteLinkText", -14054705, "#4F6E52"),
    ("chat_messageLinkIn", -15566134, "#4F6E52"),
    ("dialogTextLink", -14317077, "#4F6E52"),
    ("telegram_color_text", None, "#4F6E52"),
    # bubbles: the outgoing one from the accent to the soft accent
    ("chat_inBubble", -986896, "#F1F2F0"),
    ("chat_inBubbleSelected", -1381654, "#E3EAE2"),
    ("chat_outBubble", -13795627, "#5B7A5E"),
    ("chat_outBubbleGradient", -10701088, "#6F8F72"),
    ("chat_outBubbleSelected", -12418863, "#4F6E52"),
    # time, views and file details in outgoing
    ("chat_outTimeText", -3676417, "#E3EAE2"),
    ("chat_outTimeSelectedText", -3348225, "#E3EAE2"),
    ("chat_outViews", -3676417, "#E3EAE2"),
    ("chat_outViewsSelected", -3676417, "#E3EAE2"),
    ("chat_outFileInfoText", -3676417, "#E3EAE2"),
    ("chat_outFileInfoSelectedText", -3676417, "#E3EAE2"),
    ("chat_outAudioDurationText", -3676417, "#E3EAE2"),
    ("chat_outAudioDurationSelectedText", -3676417, "#E3EAE2"),
    ("chat_outVenueInfoText", -3676417, "#E3EAE2"),
    ("chat_outVenueInfoSelectedText", -3676417, "#E3EAE2"),
    ("chat_outContactPhoneText", -3676417, "#E3EAE2"),
)
# arctic.attheme ("Arctic Blue"): as PALETTE_DAY; its outgoing bubble has no
# gradient.
PALETTE_ARCTIC = (
    # text
    ("windowBackgroundWhiteBlackText", -13421773, "#111111"),
    ("chats_name", None, "#111111"),
    ("chat_messageTextIn", None, "#111111"),
    ("actionBarDefaultTitle", -13421773, "#111111"),
    ("dialogTextBlack", None, "#111111"),
    ("telegram_color_dialogsLogo", None, "#111111"),
    # secondary text
    ("windowBackgroundWhiteGrayText", -7629665, "#6B6F6B"),
    ("windowBackgroundWhiteGrayText2", None, "#6B6F6B"),
    ("windowBackgroundWhiteGrayText3", None, "#6B6F6B"),
    ("chats_message", None, "#6B6F6B"),
    ("chats_date", None, "#6B6F6B"),
    ("actionBarDefaultSubtitle", -7630182, "#6B6F6B"),
    # accent: buttons, switches, counters, checks
    ("telegram_color", None, "#5B7A5E"),
    ("chats_unreadCounter", -16012289, "#5B7A5E"),
    ("switchTrackChecked", -14509328, "#5B7A5E"),
    ("chats_actionBackground", -11492107, "#5B7A5E"),
    ("chat_messagePanelSend", -14509328, "#5B7A5E"),
    ("windowBackgroundWhiteBlueHeader", -13789715, "#5B7A5E"),
    ("windowBackgroundWhiteBlueText", -14579729, "#5B7A5E"),
    ("windowBackgroundWhiteBlueText4", -12675352, "#5B7A5E"),
    ("windowBackgroundWhiteValueText", -13134357, "#5B7A5E"),
    ("featuredStickers_addButton", None, "#5B7A5E"),
    ("dialogTextBlue", -14709290, "#5B7A5E"),
    ("dialogTextBlue2", -14772773, "#5B7A5E"),
    ("dialogButton", -13987604, "#5B7A5E"),
    ("checkboxSquareBackground", None, "#5B7A5E"),
    ("checkbox", None, "#5B7A5E"),
    ("radioBackgroundChecked", -14638337, "#5B7A5E"),
    ("progressCircle", -12605954, "#5B7A5E"),
    ("chats_sentCheck", -13982474, "#5B7A5E"),
    ("chats_sentReadCheck", None, "#5B7A5E"),
    ("actionBarTabLine", -13655305, "#5B7A5E"),
    ("actionBarTabActiveText", -13590803, "#5B7A5E"),
    ("windowBackgroundWhiteInputFieldActivated", None, "#5B7A5E"),
    ("dialogTopBackground", None, "#5B7A5E"),
    ("chats_actionPressedBackground", -13466664, "#4F6E52"),
    ("featuredStickers_addButtonPressed", -12478762, "#4F6E52"),
    # text on the accent
    ("chats_unreadCounterText", None, "#FFFFFF"),
    ("chats_actionIcon", None, "#FFFFFF"),
    ("featuredStickers_buttonText", None, "#FFFFFF"),
    # the blue identity colour of people (Theme.keys_avatar_*[5]): sage
    ("avatar_backgroundBlue", -11491866, "#7FA082"),
    ("avatar_background2Blue", None, "#5B7A5E"),
    ("avatar_nameInMessageBlue", -13464859, "#4F6E52"),
    # the cyan identity colour (Theme.keys_avatar_*[4]): teal, without the blue of Telegram's
    ("avatar_backgroundCyan", None, "#5BCBC4"),
    ("avatar_background2Cyan", None, "#2C9C98"),
    ("avatar_nameInMessageCyan", None, "#1F8A80"),
    # Telegram's blue and light blue as plain colours (the playback speed slider, a bot's
    # emoji status permission, the fallback of statistics chart lines) and the internal
    # storage of the file picker: sage
    ("color_blue", -13467675, "#5B7A5E"),
    ("color_lightblue", -10966803, "#8FAE92"),
    ("chat_attachGalleryBackground", None, "#5B7A5E"),
    # soft accent: avatars, selection
    ("avatar_backgroundSaved", -12208385, "#6F8F72"),
    ("avatar_backgroundArchivedHidden", None, "#6F8F72"),
    ("chat_selectedBackground", 756261375, "#325B7A5E"),
    ("windowBackgroundWhiteLinkSelection", 560114147, "#335B7A5E"),
    # links
    ("windowBackgroundWhiteLinkText", -14054705, "#4F6E52"),
    ("chat_messageLinkIn", -16677912, "#4F6E52"),
    ("dialogTextLink", -14317077, "#4F6E52"),
    ("telegram_color_text", None, "#4F6E52"),
    # bubbles
    ("chat_inBubble", -1, "#F1F2F0"),
    ("chat_inBubbleSelected", -1706753, "#E3EAE2"),
    ("chat_outBubble", -13332245, "#5B7A5E"),
    ("chat_outBubbleSelected", -13332255, "#4F6E52"),
)
# night.attheme ("Night"): the keys of PALETTE_DARK, except the neutral greys
# of its bars, menus, sections and dialogs, which are Night's own and not
# blue.
PALETTE_NIGHT = (
    # background
    ("windowBackgroundWhite", -15198183, "#131513"),
    # text
    ("windowBackgroundWhiteBlackText", -1, "#E8ECE8"),
    ("chats_name", -921103, "#E8ECE8"),
    ("chats_nameMessage", -1315861, "#E8ECE8"),
    ("chats_nameMessage_threeLines", -1315861, "#E8ECE8"),
    ("chat_messageTextIn", -328966, "#E8ECE8"),
    ("chat_messageTextOut", -328966, "#E8ECE8"),
    ("actionBarDefaultTitle", -1, "#E8ECE8"),
    ("actionBarDefaultIcon", -1, "#E8ECE8"),
    ("dialogTextBlack", -592138, "#E8ECE8"),
    # secondary text
    ("windowBackgroundWhiteGrayText", 1862270975, "#9AA29A"),
    ("windowBackgroundWhiteGrayText3", -7960954, "#9AA29A"),
    ("windowBackgroundWhiteGrayText5", -8549479, "#9AA29A"),
    ("windowBackgroundWhiteGrayText6", -8553091, "#9AA29A"),
    ("windowBackgroundWhiteGrayText8", -8553091, "#9AA29A"),
    ("windowBackgroundWhiteHintText", -8553091, "#9AA29A"),
    ("windowBackgroundWhiteGrayIcon", -8553091, "#9AA29A"),
    ("chats_message", -8224126, "#9AA29A"),
    ("chats_message_threeLines", -8224126, "#9AA29A"),
    ("chats_date", -8882056, "#9AA29A"),
    ("chats_nameMessageArchived", -8553091, "#9AA29A"),
    ("actionBarDefaultSubtitle", 1945301746, "#9AA29A"),
    ("chat_inTimeText", -8552575, "#9AA29A"),
    ("chats_menuItemIcon", -8224126, "#9AA29A"),
    ("actionBarTabUnactiveText", -7434609, "#9AA29A"),
    # accent: buttons, switches, counters, checks
    ("telegram_color", None, "#9DBB9F"),
    ("chats_unreadCounter", -13000973, "#9DBB9F"),
    ("switchTrackChecked", -12215069, "#9DBB9F"),
    ("chats_actionBackground", -10575653, "#9DBB9F"),
    ("chat_messagePanelSend", -14509328, "#9DBB9F"),
    ("windowBackgroundWhiteBlueHeader", -9652488, "#9DBB9F"),
    ("windowBackgroundWhiteBlueText", -10177041, "#9DBB9F"),
    ("windowBackgroundWhiteBlueText3", -11689489, "#9DBB9F"),
    ("windowBackgroundWhiteBlueText4", -10177041, "#9DBB9F"),
    ("windowBackgroundWhiteBlueText5", -10177041, "#9DBB9F"),
    ("windowBackgroundWhiteValueText", -529942787, "#9DBB9F"),
    ("featuredStickers_addButton", None, "#9DBB9F"),
    ("dialogTextBlue", -10177041, "#9DBB9F"),
    ("dialogTextBlue2", -10177041, "#9DBB9F"),
    ("dialogTextBlue4", -10177041, "#9DBB9F"),
    ("dialogButton", -10177041, "#9DBB9F"),
    ("checkboxSquareBackground", -10177051, "#9DBB9F"),
    ("checkbox", None, "#9DBB9F"),
    ("radioBackgroundChecked", -12015889, "#9DBB9F"),
    ("progressCircle", -10177027, "#9DBB9F"),
    ("actionBarTabLine", -12339201, "#9DBB9F"),
    ("actionBarTabActiveText", -10698241, "#9DBB9F"),
    ("chats_sentCheck", -12145165, "#9DBB9F"),
    ("chats_sentReadCheck", -12145165, "#9DBB9F"),
    ("windowBackgroundWhiteInputFieldActivated", -9522449, "#9DBB9F"),
    ("chats_actionMessage", -10178583, "#9DBB9F"),
    ("chats_actionPressedBackground", -9388826, "#B2CEB4"),
    ("featuredStickers_addButtonPressed", None, "#B2CEB4"),
    # text on the accent
    ("chats_unreadCounterText", None, "#131513"),
    ("chats_actionIcon", None, "#131513"),
    ("featuredStickers_buttonText", None, "#131513"),
    # the blue identity colour of people (Theme.keys_avatar_*[5]): sage
    ("avatar_backgroundBlue", None, "#7FA082"),
    ("avatar_background2Blue", None, "#5B7A5E"),
    ("avatar_nameInMessageBlue", -10703382, "#9DBB9F"),
    # the cyan identity colour (Theme.keys_avatar_*[4]): teal, without the blue of Telegram's
    ("avatar_backgroundCyan", None, "#5BCBC4"),
    ("avatar_background2Cyan", None, "#2C9C98"),
    # Telegram's blue and light blue as plain colours (the playback speed slider, a bot's
    # emoji status permission, the fallback of statistics chart lines) and the internal
    # storage of the file picker: sage
    ("color_blue", -11362305, "#9DBB9F"),
    ("color_lightblue", -12814100, "#7FA082"),
    ("chat_attachGalleryBackground", -11692299, "#7FA082"),
    # soft accent: avatars, selection
    ("avatar_backgroundSaved", -11558424, "#7FA082"),
    ("avatar_background2Saved", -15038233, "#7FA082"),
    ("avatar_backgroundArchivedHidden", -12279320, "#7FA082"),
    ("windowBackgroundChecked", -13666645, "#2C3A2D"),
    ("chat_selectedBackground", 710909411, "#2A9DBB9F"),
    ("windowBackgroundWhiteLinkSelection", 1030010365, "#339DBB9F"),
    # links
    ("windowBackgroundWhiteLinkText", -11032608, "#B2CEB4"),
    ("chat_messageLinkIn", -8796932, "#B2CEB4"),
    ("chat_messageLinkOut", -5316609, "#B2CEB4"),
    ("dialogTextLink", -10177041, "#B2CEB4"),
    ("telegram_color_text", None, "#B2CEB4"),
    # bubbles
    ("chat_inBubble", -14737117, "#232623"),
    ("chat_inBubbleSelected", -13546911, "#2C3A2D"),
    ("chat_outBubble", -13210449, "#2C3A2D"),
    ("chat_outBubbleGradient", -12874567, "#36473A"),
    ("chat_outBubbleSelected", -11829841, "#36473A"),
    # time and checks in outgoing
    ("chat_outTimeText", -7023626, "#B2CEB4"),
    ("chat_outTimeSelectedText", -7023626, "#B2CEB4"),
    ("chat_outSentCheck", -506859265, "#B2CEB4"),
    ("chat_outSentCheckSelected", -5841921, "#B2CEB4"),
    ("chat_outSentCheckRead", -506859265, "#B2CEB4"),
    ("chat_outSentCheckReadSelected", None, "#B2CEB4"),
    ("chat_outSentClock", -6698513, "#B2CEB4"),
    ("chat_outSentClockSelected", -4268038, "#B2CEB4"),
    ("chat_outViews", -7357217, "#B2CEB4"),
    ("chat_outViewsSelected", -4268038, "#B2CEB4"),
)
# The theme files and their tables.
THEME_FILES = {
    "bluebubbles.attheme": PALETTE_LIGHT,
    "day.attheme": PALETTE_DAY,
    "arctic.attheme": PALETTE_ARCTIC,
    "night.attheme": PALETTE_NIGHT,
    "darkblue.attheme": PALETTE_DARK,
}
# The accent arrays of Theme.java: (row, column, upstream, new). Rows: 0
# accent, 1 my messages, 2 their gradient, 3-6 wallpaper colours, 7 ids. The
# accents a theme shows before the user picks a colour (DEFAULT_THEMES) turn
# sage; the others stay as Telegram has them.
ACCENTS = {
    # The home accent (id 99, first column): sage; the bubbles come from the
    # theme file instead of the green of my-messages.
    "Blue": ((7, 0, "99", "99"), (0, 0, "0xFF5890C5", "0xFF5B7A5E"), (1, 0, "0xFFB8E18D", "0x00000000")),
    # The home accent (id 9, first column) and the accent the theme starts with
    # (id 0, sixth column): sage, the bubbles of both from the theme file
    # instead of the blue to cyan of my-messages.
    "Day": ((7, 0, "9", "9"), (0, 0, "0xFF56A2C9", "0xFF4F6E52"), (1, 0, "0xFF6580DC", "0x00000000"),
            (2, 0, "0xFF3EC1D6", "0x00000000"), (7, 5, "0", "0"), (0, 5, "0xFF4C91DF", "0xFF5B7A5E")),
    # The accent the theme starts with (id 0, seventh column): sage, on the
    # light blue wallpaper colours shifted to sage as the accent engine shifts
    # the theme.
    "Arctic Blue": ((7, 6, "0", "0"), (0, 6, "0xFF3490EB", "0xFF5B7A5E"), (3, 6, "0xffe0e7ed", "0xffDDE1DD"),
                    (4, 6, "0xffbed7f3", "0xffB4C2B6"), (5, 6, "0xffe0e8f3", "0xffDCE1DD"),
                    (6, 6, "0xffc8dbf3", "0xffBFCBC1")),
    # The home accent (id 0, sixth column): sage, on its near black wallpaper
    # colours shifted to sage the same way.
    "Night": ((7, 5, "0", "0"), (0, 5, "0xff3e88f7", "0xff9DBB9F"), (3, 5, "0xff0d0e17", "0xff101211"),
              (4, 5, "0xff090a0c", "0xff0A0B0A"), (5, 5, "0xff181c28", "0xff1D201E"),
              (6, 5, "0xff0e0f12", "0xff0F100F")),
    # The home accent (id 0, ninth column): sage, on a dark green wallpaper.
    "Dark Blue": ((7, 8, "0", "0"), (0, 8, "0xff3685fa", "0xff9DBB9F"), (3, 8, "0xff0e141a", "0xff0F120F"),
                  (4, 8, "0xff172431", "0xff1A211B"), (5, 8, "0xff0f171e", "0xff121612"),
                  (6, 8, "0xff141c2b", "0xff171D18")),
}
# The base colour of the accent engine. Upstream takes it from the accent of id
# 0; where that accent turns sage, the Telegram blue it had stays the base the
# sage accents shift from.
ACCENT_BASES = {"Day": "0xFF4C91DF", "Arctic Blue": "0xFF3490EB", "Night": "0xff3e88f7", "Dark Blue": "0xff3685fa"}
# Colour literals outside the themes: (file, upstream, new, count).
BRAND_COLOURS = (
    (f"{JAVA}/messenger/NotificationsController.java", "0xff11acfa", "0xff5b7a5e", 2),
    (f"{JAVA}/messenger/voip/VoIPService.java", "0xff2ca5e0", "0xff5b7a5e", 3),
    (f"{JAVA}/messenger/voip/VoIPGroupNotification.java", "0xff2ca5e0", "0xff5b7a5e", 1),
    (f"{JAVA}/messenger/voip/VoIPPreNotificationService.java", "0xff2ca5e0", "0xff5b7a5e", 1),
    (f"{RES}/drawable/call_custom_notification_icon.xml", "#2ca5e0", "#5b7a5e", 1),
    (f"{RES}/values/styles.xml", "#ff527da3", "#ff5b7a5e", 1),
    (f"{RES}/values-v21/styles.xml", "#527da3", "#5b7a5e", 6),
    (f"{RES}/values-v21/styles.xml", "#ff527da3", "#ff5b7a5e", 1),
    (f"{RES}/values-v21/styles.xml", "#426482", "#4f6e52", 1),
    (f"{RES}/values-v21/styles.xml", "#4991cc", "#5b7a5e", 5),
    (f"{RES}/values-v21/styles.xml", "#408bc8", "#5b7a5e", 4),
    (f"{RES}/values-v31/styles.xml", "#527da3", "#5b7a5e", 3),
    (f"{RES}/values-v31/styles.xml", "#426482", "#4f6e52", 1),
    (f"{RES}/values-night/styles.xml", "#1f2732", "#131513", 3),
    (f"{RES}/values-night/styles.xml", "#1c242e", "#0d0f0d", 1),
    (f"{RES}/values-night/styles.xml", "#232d3a", "#1b1f1b", 1),
    (f"{RES}/values-night/styles.xml", "#ff232d3a", "#ff1b1f1b", 1),
    (f"{RES}/values-night/colors.xml", "#75ADE5", "#9DBB9F", 1),
    # The intro: page indicator, the illustrations of the later pages.
    (f"{JAVA}/ui/Components/BottomPagesView.java", "paint.setColor(ThemeColors.TELEGRAM_COLOR);",
     "paint.setColor(0xFF5B7A5E); // pluma: the sage accent", 1),
    ("TMessagesProj/jni/intro/IntroRenderer.c", "gl_FragColor = vec4(0,0.6,0.898,p);",
     "gl_FragColor = vec4(91./255.,122./255.,94./255.,p);", 1),
    ("TMessagesProj/jni/intro/IntroRenderer.c", "gl_FragColor = vec4(42./255.,180./255.,247./255.,p);",
     "gl_FragColor = vec4(111./255.,143./255.,114./255.,p);", 1),
    ("TMessagesProj/jni/intro/IntroRenderer.c", "{42 / 255.0f, 180 / 255.0f, 247 / 255.0f, 1}",
     "{111 / 255.0f, 143 / 255.0f, 114 / 255.0f, 1}", 1),
    ("TMessagesProj/jni/intro/IntroRenderer.c", "{47 / 255.f, 90 / 255.f, 131 / 255.f, 1}",
     "{79 / 255.f, 110 / 255.f, 82 / 255.f, 1}", 1),
)


def image_size(data):
    """(width, height) of a PNG or WebP image."""
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return int.from_bytes(data[16:20], "big"), int.from_bytes(data[20:24], "big")
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        chunk = data[12:16]
        if chunk == b"VP8 ":
            return int.from_bytes(data[26:28], "little") & 0x3FFF, int.from_bytes(data[28:30], "little") & 0x3FFF
        if chunk == b"VP8L":
            bits = int.from_bytes(data[21:25], "little")
            return (bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1
        if chunk == b"VP8X":
            return int.from_bytes(data[24:27], "little") + 1, int.from_bytes(data[27:30], "little") + 1
    raise PatchError("not a PNG or WebP image")


def brand_layer(anim, rel, name, index):
    """The one layer of a Lottie animation with this name (and index)."""
    found = [l for l in anim["layers"] if l.get("nm") == name and (index is None or l.get("ind") == index)]
    if len(found) != 1:
        raise PatchError(f"{rel}: {len(found)} layers {name!r} (index {index}), expected 1")
    return found[0]


def argb(colour):
    """#RRGGBB or #AARRGGBB as the signed int of a .attheme file."""
    v = int(colour[1:], 16) | (0xFF000000 if len(colour) == 7 else 0)
    return v - (1 << 32) if v & 0x80000000 else v


# --- the colours of the default themes ----------------------------------------
# A model of what Theme.getColor answers for the accents a default theme shows
# before the user picks a colour, read from the patched sources: the theme
# file, the accent engine over it and over the defaults of ThemeColors
# (ThemeAccent.fillAccentColors, Theme.changeColorAccent), fallbackKeys.
# verify_theme fails when a colour outside themeAccentExclusionKeys (user
# colours, calls, statistics, Premium, stories) is still Telegram's blue.

# The places where upstream gives such an accent Telegram's own colours instead
# of the theme file and the accent engine: Theme.getColor, changeColorAccent,
# saveCurrentTheme, and the blue to purple bubbles that
# ThemeInfo.setAccentColorOptions forces on the home accent of "Dark Blue" and
# on every accent of "Night", its home accent included (a condition that ends
# in name.equals("Night") right before the forced colours).
DEFAULT_ACCENT_SHORTCUTS = (
    "currentTheme.isDefaultMainAccent()",
    "currentTheme.isDefaultMyMessages()",
    "currentTheme.isDefaultMyMessagesBubbles()",
    "themeInfo.firstAccentIsDefault && themeInfo.currentAccentId == DEFALT_THEME_ACCENT_ID",
    "currentTheme.firstAccentIsDefault && accent.id == DEFALT_THEME_ACCENT_ID",
    'isHome(themeAccent) && name.equals("Dark Blue")',
    'name.equals("Night")) {\n                    themeAccent.myMessagesAccentColor',
)
# The default themes, all five the app bundles: theme file, the accents shown
# before the user picks a colour, dark. Those are the home accent (Theme.isHome:
# 99 of "Blue", 9 of "Day", 0 of "Night" and "Dark Blue"; "Arctic Blue" has
# none), which Settings > Chat Settings applies from its row of default themes
# (EmojiThemes.createHomePreviewTheme), and the accent a theme starts with,
# 99 of "Blue" and 0 of the others (the static initializer of Theme:
# currentAccentId, firstAccentIsDefault ? DEFALT_THEME_ACCENT_ID : 0). The
# intro's moon switch, for one, turns on "Night" with its accent 0
# (IntroActivity).
DEFAULT_THEMES = {
    "Blue": ("bluebubbles.attheme", (99,), False),
    "Day": ("day.attheme", (9, 0), False),
    "Arctic Blue": ("arctic.attheme", (0,), False),
    "Night": ("night.attheme", (0,), True),
    "Dark Blue": ("darkblue.attheme", (0,), True),
}


def theme_defaults(source):
    """ThemeColors.java: (the string name of each key, the default colour of
    each key), both by the key's Java name."""
    names = dict(re.findall(r'colorKeysMap\.put\((key_\w+), "(\w+)"\);', source))
    consts = {n: int(v, 16) for n, v in re.findall(r"public static final int (\w+) = 0x([0-9A-Fa-f]{8});", source)}
    consts.update({"Color.WHITE": 0xFFFFFFFF, "Color.BLACK": 0xFF000000, "Color.TRANSPARENT": 0})

    def value(v):
        if v in consts:
            return consts[v]
        if re.fullmatch(r"0x[0-9A-Fa-f]{1,8}", v):
            return int(v, 16)
        if re.fullmatch(r"-?\d+", v):
            return int(v) & 0xFFFFFFFF
        m = re.fullmatch(r"ColorUtils\.setAlphaComponent\(([\w.]+), (\d+)\)", v)
        if m and m.group(1) in consts:
            return consts[m.group(1)] & 0xFFFFFF | int(m.group(2)) << 24
        raise PatchError(f"ThemeColors.java: cannot read the default colour {v!r}")

    defaults = {k: value(v.strip()) for k, v in re.findall(r"defaultColors\[(key_\w+)\] = ([^;]+);", source)}
    return names, defaults


def theme_engine(source):
    """Theme.java: (fallbackKeys, themeAccentExclusionKeys)."""
    fallback = dict(re.findall(r"fallbackKeys\.put\((?:Theme\.)?(key_\w+), (?:Theme\.)?(key_\w+)\);", source))
    arrays = {n: re.findall(r"key_\w+", body) for n, body in re.findall(r"int\[\] (keys_\w+) = \{([^}]*)\};", source)}
    keys = re.findall(r"themeAccentExclusionKeys\.add\((key_\w+)\);", source)
    loops = re.findall(r"themeAccentExclusionKeys\.add\((keys_\w+)\[i\]\);", source)
    if len(keys) + len(loops) != source.count("themeAccentExclusionKeys.add("):
        raise PatchError("Theme.java: an exclusion from the accent engine the check cannot read")
    excluded = set(keys)
    for n in loops:
        if n not in arrays:
            raise PatchError(f"Theme.java: no array {n}")
        excluded.update(arrays[n])
    return fallback, excluded


def theme_accent(source, theme, accent_id):
    """(the base colour of the accent engine, the accent of this id) of a
    theme. The base is the accent of id 0, unless the theme sets
    accentBaseColor."""
    table = accent_table(source, theme)
    ids, accents = table[7], table[0]
    if str(accent_id) not in ids or "0" not in ids:
        raise PatchError(f"Theme.java: {theme}: no accent {accent_id} or 0")
    column = ids.index(str(accent_id))
    if int(table[1][column], 16) or int(table[2][column], 16):
        raise PatchError(f"Theme.java: {theme}: the accent {accent_id} has colours for my messages; "
                         "the check does not model them")
    head = source.index(f'        themeInfo.name = "{theme}";\n')
    block = source[head:source.index("        themes.add(", head)]
    base = re.findall(r"themeInfo\.accentBaseColor = (0x[0-9A-Fa-f]{8});", block)
    return int(base[-1] if base else accents[ids.index("0")], 16), int(accents[column], 16)


def _hsv(c):
    h, s, v = colorsys.rgb_to_hsv((c >> 16 & 255) / 255, (c >> 8 & 255) / 255, (c & 255) / 255)
    return h * 360, s, v


def _brightness(c):
    return ((c >> 16 & 255) * 0.2126 + (c >> 8 & 255) * 0.7152 + (c & 255) * 0.0722) / 255


def accent_shift(base, accent, colour, dark):
    """Theme.changeColorAccent: a colour within 30 degrees of the base's hue
    moves to the accent; a light theme never gets it lighter, a dark one never
    darker."""
    bh, bs, bv = _hsv(base)
    ah, as_, av = _hsv(accent)
    h, s, v = _hsv(colour)
    if min(abs(h - bh), abs(h - bh - 360)) > 30:
        return colour
    dist = min(1.5 * s / bs, 1)
    h = min(max(h + ah - bh, 0), 360) % 360
    s = min(max(s * as_ / bs, 0), 1)
    v = min(max(v * (1 - dist + dist * av / bv), 0), 1)
    r, g, b = colorsys.hsv_to_rgb(h / 360, s, v)
    new = colour & 0xFF000000 | round(r * 255) << 16 | round(g * 255) << 8 | round(b * 255)
    was, now = _brightness(colour), _brightness(new)
    if now and (was > now if dark else was < now):
        k = 0.4 * was / now + 0.6
        new = colour & 0xFF000000 | sum(min(int((new >> n & 255) * k), 255) << n for n in (16, 8, 0))
    return new


def theme_file_values(text):
    """{key name: colour} of a .attheme file as Theme.getThemeFileValues reads
    it: only the lines a newline ends, up to the WPS line of an embedded
    wallpaper, without the WLS line of a wallpaper link. An unterminated last
    line (day.attheme and arctic.attheme have one) is never read."""
    out = {}
    for line in text.split("\n")[:-1]:
        if line.startswith("WPS"):
            break
        name, sep, v = line.partition("=")
        if sep and name != "WLS":
            out[name] = (argb(v) if v.startswith("#") else int(v)) & 0xFFFFFFFF
    return out


def theme_colours(theme_file, names, defaults, fallback, excluded, base, accent, dark):
    """What Theme.getColor answers for each key: the theme file, the accent
    engine over the file and the defaults, the fallback keys, the defaults."""
    by_name = {n: k for k, n in names.items()}
    file = {by_name[n]: v for n, v in theme_file_values(theme_file).items() if n in by_name}
    current = dict(file)
    for key in set(defaults) | set(file):
        if key in excluded:
            continue
        if key in file:
            c = file[key]
        elif fallback.get(key) in file:
            continue
        else:
            c = defaults[key]
        new = accent_shift(base, accent, c, dark)
        if new != c:
            current[key] = new
    out = {}
    for key in set(defaults) | set(file):
        if key in current:
            out[key] = current[key]
        elif fallback.get(key) in current:
            out[key] = current[fallback[key]]
        else:
            out[key] = defaults[key]
    return out


def telegram_blue(c):
    h, s, v = _hsv(c)
    return c >> 24 >= 0x20 and s >= 0.3 and v >= 0.3 and 180 <= h <= 240


# Keys the accent engine skips that the check names all the same, since the
# tables recolour them:
# - the blue and the cyan of the seven identity colours of people
#   (Theme.keys_avatar_background, keys_avatar_background2 and
#   keys_avatar_nameInMessage, indices 5 and 4): names, replies, link
#   previews and avatars of the users whose id % 7 is 5 or 4
#   (UserObject.getColorId), now sage and teal; the other five keep
#   Telegram's colours;
# - Telegram's blue and light blue as plain colours and the internal storage
#   of the file picker.
ALSO_CHECKED = ("avatar_backgroundBlue", "avatar_background2Blue", "avatar_nameInMessageBlue",
                "avatar_backgroundCyan", "avatar_background2Cyan", "avatar_nameInMessageCyan",
                "color_blue", "color_lightblue", "chat_attachGalleryBackground")


def default_theme_blues(theme_java, colors_java, theme_files):
    """{theme file: the keys still Telegram's blue} for the default themes,
    from the sources of Theme.java and ThemeColors.java and the theme files
    by name."""
    for s in DEFAULT_ACCENT_SHORTCUTS:
        if s in theme_java:
            raise PatchError(f"Theme.java: {s!r}: an accent of a default theme still gets Telegram's colours")
    names, defaults = theme_defaults(colors_java)
    fallback, excluded = theme_engine(theme_java)
    out = {}
    for theme, (asset, accent_ids, dark) in DEFAULT_THEMES.items():
        blue = set()
        for accent_id in accent_ids:
            base, accent = theme_accent(theme_java, theme, accent_id)
            colours = theme_colours(theme_files[asset], names, defaults, fallback, excluded, base, accent, dark)
            blue.update(names.get(k, k) for k, c in colours.items()
                        if (k not in excluded or names.get(k, k) in ALSO_CHECKED) and telegram_blue(c))
        out[asset] = sorted(blue)
    return out


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


def edit_string(xml, rel, key, old, new):
    """Replaces old in the text of the string key, which the file must have
    once: old is the whole text (a URL), or a link the text marks with
    asterisks, there once."""
    found = re.findall(rf'<string name="{re.escape(key)}">([^<]*)</string>', xml)
    if len(found) != 1:
        raise PatchError(f"{rel}: {len(found)} strings {key}, expected 1")
    text = found[0]
    marked = old.startswith("*") and old.endswith("*")
    if (text.count(old) != 1) if marked else (text != old):
        raise PatchError(f"{rel}: {key} is {text!r}, expected {old!r} in it; upstream changed it")
    element = f'<string name="{key}">{text}</string>'
    return xml.replace(element, f'<string name="{key}">{text.replace(old, new)}</string>')


def _accent_arrays(text, theme):
    """The accent arrays of a theme in Theme.java: (start, end, the lines from
    start to end, the indices of the 11 array lines among them)."""
    head = f'        themeInfo.name = "{theme}";\n'
    if text.count(head) != 1:
        raise PatchError(f"Theme.java: {text.count(head)} themes {theme!r}, expected 1")
    start = text.index("        themeInfo.setAccentColorOptions(\n", text.index(head))
    end = text.index("\n                );\n", start)
    lines = text[start:end].split("\n")
    # "Day" passes null for the last two wallpaper colours.
    rows = [i for i, l in enumerate(lines) if re.match(r"\s*(?:new (?:int|String)\[\]|null\b)", l)]
    if len(rows) != 11:
        raise PatchError(f"Theme.java: {theme}: {len(rows)} accent arrays, expected 11")
    return start, end, lines, rows


def _accent_cells(line):
    if "{" not in line:  # a null array
        return 0, []
    first = line.index("{") + 1
    return first, list(re.finditer(r"[^\s,{}]+", line[first:line.index("}")]))


def accent_table(text, theme):
    """The cells of the 11 accent arrays of a theme, as written."""
    _, _, lines, rows = _accent_arrays(text, theme)
    return [[m.group(0) for m in _accent_cells(lines[r])[1]] for r in rows]


def edit_accents(text, theme, edits):
    """Edits cells of the accent arrays of a theme in Theme.java."""
    start, end, lines, rows = _accent_arrays(text, theme)
    for row, column, old, new in edits:
        line = lines[rows[row]]
        first, cells = _accent_cells(line)
        if column >= len(cells) or cells[column].group(0) != old:
            found = cells[column].group(0) if column < len(cells) else None
            raise PatchError(f"Theme.java: {theme}: accent array {row}, column {column} is {found}, expected {old}")
        a, b = first + cells[column].start(), first + cells[column].end()
        lines[rows[row]] = line[:a] + new + line[b:]
    return text[:start] + "\n".join(lines) + text[end:]


def edit_attheme(text, name, table, known_keys):
    """Sets keys of a .attheme file; each must have its upstream value, or be
    absent when that is None. The app never reads an unterminated last line
    (theme_file_values): it stays last and as it is, and does not count as
    setting its key."""
    lines = text.split("\n")
    tail = lines.pop()
    where = collections.defaultdict(list)
    for i, line in enumerate(lines):
        key, sep, _ = line.partition("=")
        if sep:
            where[key].append(i)
    added = []
    for key, old, new in table:
        if key not in known_keys:
            raise PatchError(f"{name}: {key} is not a theme colour key")
        if old is None:
            if where[key]:
                raise PatchError(f"{name}: {key} is set already; upstream changed it")
            added.append(f"{key}={argb(new)}")
        else:
            if len(where[key]) != 1 or lines[where[key][0]] != f"{key}={old}":
                raise PatchError(f"{name}: {key} is not {old}; upstream changed it")
            lines[where[key][0]] = f"{key}={argb(new)}"
    return "\n".join(lines + added) + "\n" + tail


def brand(tree):
    brand_entry_points(tree)
    brand_strings(tree)
    brand_client_links(tree)
    brand_scheme(tree)
    brand_assets(tree)
    brand_devices(tree)
    brand_intro(tree)
    brand_theme(tree)


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


def brand_client_links(tree):
    files = {p.parent.name: str(p.relative_to(tree.root)) for p in sorted((tree.root / RES).glob("values*/strings.xml"))}
    for key in sorted({key for key, _, _, _ in CLIENT_LINKS}):
        want = {lang for k, _, _, langs in CLIENT_LINKS if k == key for lang in langs}
        have = {lang for lang, rel in files.items() if f'<string name="{key}">' in tree.read(rel)}
        if have != want:
            raise PatchError(f"{RES}: {key} in {', '.join(sorted(have))}, expected {', '.join(sorted(want))}; "
                             "upstream changed it")
    for key, old, new, langs in CLIENT_LINKS:
        for lang in langs:
            tree.write(files[lang], edit_string(tree.read(files[lang]), files[lang], key, old, new))


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


def add_asset(tree, rel, sha):
    """Adds brand/android/res/<rel>, the file BRAND_ADDED names, as a resource
    upstream does not have. R.raw.qr_login is raw/qr_login.json: no upstream
    file of the folder may have the name, whatever its extension."""
    data = (BRAND / "res" / rel).read_bytes()
    if hashlib.sha256(data).hexdigest() != sha:
        raise PatchError(f"brand/android/res/{rel}: not the file BRAND_ADDED names (SHA-256)")
    dst = tree.root / RES / rel
    if not dst.parent.is_dir():
        raise PatchError(f"{RES}/{pathlib.PurePosixPath(rel).parent}: missing; upstream changed it")
    name = dst.name.split(".")[0]
    taken = sorted(p.name for p in dst.parent.iterdir() if p.name.split(".")[0] == name)
    if taken:
        raise PatchError(f"{RES}/{rel}: upstream has {', '.join(taken)} now; the name of the brand file must change")
    dst.write_bytes(data)


def brand_assets(tree):
    have = {p.relative_to(BRAND / "res").as_posix() for p in (BRAND / "res").rglob("*") if p.is_file()}
    want = set(BRAND_ASSETS) | set(BRAND_ADDED)
    if have != want:
        raise PatchError(f"brand/android/res and BRAND_ASSETS, BRAND_ADDED differ: {sorted(have ^ want)}")
    for rel, sha in sorted(BRAND_ADDED.items()):
        add_asset(tree, rel, sha)
    for rel, sha in sorted(BRAND_ASSETS.items()):
        dst = tree.root / RES / rel
        if not dst.is_file() or hashlib.sha256(dst.read_bytes()).hexdigest() != sha:
            raise PatchError(f"{RES}/{rel}: not the upstream file the brand asset replaces; upstream changed it")
        new = (BRAND / "res" / rel).read_bytes()
        if dst.suffix in (".png", ".webp") and image_size(new) != image_size(dst.read_bytes()):
            raise PatchError(f"brand/android/res/{rel}: {image_size(new)} pixels, upstream has {image_size(dst.read_bytes())}")
        dst.write_bytes(new)
    for name, sha, layer, index, src in BRAND_LAYERS:
        rel = f"{RES}/{name}"
        data = (tree.root / rel).read_bytes()
        if hashlib.sha256(data).hexdigest() != sha:
            raise PatchError(f"{rel}: not the animation the patch expects; upstream changed it")
        anim = json.loads(data)
        brand_layer(anim, rel, layer, index)["shapes"] = json.loads((BRAND / src).read_text())
        tree.write(rel, json.dumps(anim, separators=(",", ":")))
    # The background of the adaptive icon: white, as in the brand kit.
    tree.replace(f"{RES}/drawable/icon_background_sa.xml", 'android:startColor="#289AD1"', 'android:startColor="#FFFFFF"')
    tree.replace(f"{RES}/drawable/icon_background_sa.xml", 'android:endColor="#38AEEB"', 'android:endColor="#FFFFFF"')


def brand_devices(tree):
    for old, new, count in SESSIONS_EDITS:
        tree.replace(SESSIONS, old, new, count)
    text = tree.read(SESSIONS)
    for name in SESSIONS_GONE:
        if re.search(rf"\b{name}\b", text):
            raise PatchError(f"{SESSIONS}: {name} is still used; upstream changed it")


def brand_intro(tree):
    tree.expect(*INTRO_PACE)
    for rel, old, new in INTRO_EDITS:
        tree.replace(rel, old, new)
    for rel, s in INTRO_GONE:
        if s in tree.read(rel):
            raise PatchError(f"{rel}: {s!r} is still there; upstream changed it")


def brand_theme(tree):
    rel = f"{JAVA}/ui/ActionBar/Theme.java"
    text = tree.read(rel)
    for theme, base in ACCENT_BASES.items():
        table = accent_table(text, theme)
        ids, accents = table[7], table[0]
        if "0" not in ids or accents[ids.index("0")] != base:
            raise PatchError(f"Theme.java: {theme}: the accent of id 0 is not {base}; upstream changed it")
    for theme, edits in ACCENTS.items():
        text = edit_accents(text, theme, edits)
    # These themes keep Telegram's blue as the base of the hue shift, so that
    # their sage accents recolour the theme (the base is the accent of id 0,
    # which setAccentColorOptions sets).
    for theme, base in ACCENT_BASES.items():
        _, end, _, _ = _accent_arrays(text, theme)
        end += len("\n                );\n")
        text = (text[:end] + "        // pluma: Telegram's blue stays the base the sage accents shift from.\n"
                f"        themeInfo.accentBaseColor = {base};\n" + text[end:])
    tree.write(rel, text)
    # The home accents of the two dark themes take their bubbles from the theme
    # files, not Telegram's blue to purple gradient that upstream forces on the
    # home accent of "Dark Blue" and on every accent of "Night", and the home
    # accent of "Night" its wallpaper from the accent arrays, not the one
    # upstream forces with the gradient on "Night" alone. The other accents of
    # "Night", colours the user picks, keep both.
    tree.replace(rel, '                if (isHome(themeAccent) && name.equals("Dark Blue") || name.equals("Night")) {\n',
                 "                // pluma: the home accents of the dark themes take their bubbles from the theme files.\n"
                 '                if (name.equals("Night") && !isHome(themeAccent)) {\n')
    # The home accent of the day theme goes through bluebubbles.attheme and the
    # accent engine like any other accent. Upstream answers Telegram's built-in
    # colours (ThemeColors) for it in getColor, which leaves the palette of the
    # theme file unused, keeps it out of changeColorAccent, and saves those
    # built-in colours into a theme made from it.
    tree.replace(rel, "        if (currentTheme == defaultTheme) {\n"
                      "            boolean useDefault;\n"
                      "            if (isMyMessagesBubbles(key)) {\n"
                      "                useDefault = currentTheme.isDefaultMyMessagesBubbles();\n"
                      "            } else if (isMyMessages(key)) {\n"
                      "                useDefault = currentTheme.isDefaultMyMessages();\n"
                      "            } else if (key_chat_wallpaper == key || key_chat_wallpaper_gradient_to1 == key"
                      " || key_chat_wallpaper_gradient_to2 == key || key_chat_wallpaper_gradient_to3 == key) {\n"
                      "                useDefault = false;\n"
                      "            } else {\n"
                      "                useDefault = currentTheme.isDefaultMainAccent();\n"
                      "            }\n"
                      "            if (useDefault) {\n"
                      "                if (key == key_chat_serviceBackground) {\n"
                      "                    return serviceMessageColor;\n"
                      "                } else if (key == key_chat_serviceBackgroundSelected) {\n"
                      "                    return serviceSelectedMessageColor;\n"
                      "                }\n"
                      "                return getDefaultColor(key);\n"
                      "            }\n"
                      "        }\n",
                 "        // pluma: the home accent of the default theme takes its colours from the theme file and\n"
                 "        // the accent engine, as every other accent does, not Telegram's built-in ones.\n")
    tree.replace(rel, "        if (accent == 0 || themeInfo.accentBaseColor == 0 || accent == themeInfo.accentBaseColor"
                      " || themeInfo.firstAccentIsDefault && themeInfo.currentAccentId == DEFALT_THEME_ACCENT_ID) {\n",
                 "        // pluma: the home accent of the default theme tints too.\n"
                 "        if (accent == 0 || themeInfo.accentBaseColor == 0 || accent == themeInfo.accentBaseColor) {\n")
    tree.replace(rel, "        boolean useDefaultColors = currentTheme.firstAccentIsDefault && accent.id == DEFALT_THEME_ACCENT_ID;\n",
                 "        // pluma: a theme made from the home accent keeps the colours it shows.\n"
                 "        boolean useDefaultColors = false;\n")
    # Previews of the default themes in the theme list.
    tree.replace(rel, "        themeInfo.previewBackgroundColor = 0xff5f6e82;\n"
                      "        themeInfo.previewInColor = 0xff76869c;\n"
                      "        themeInfo.previewOutColor = 0xff82a8e3;\n",
                 "        themeInfo.previewBackgroundColor = 0xff2a302a;\n"
                 "        themeInfo.previewInColor = 0xff3b423b;\n"
                 "        themeInfo.previewOutColor = 0xff4f6552;\n")
    tree.replace(rel, "                return 0xffffffff;\n            }\n            return previewInColor;",
                 "                return 0xfff1f2f0;\n            }\n            return previewInColor;")
    tree.replace(rel, "                return 0xfff0fee0;\n", "                return 0xffe3eae2;\n")
    tree.replace(rel, "                return 0xffcfd9e3;\n", "                return 0xffdde3dc;\n")

    known = set(re.findall(r'colorKeysMap\.put\(key_\w+, "(\w+)"\);', tree.read(f"{JAVA}/ui/ActionBar/ThemeColors.java")))
    for name, table in THEME_FILES.items():
        rel = f"{MAIN}/assets/{name}"
        tree.write(rel, edit_attheme(tree.read(rel), name, table, known))

    for rel, old, new, count in BRAND_COLOURS:
        tree.replace(rel, old, new, count)


def verify_brand(tree):
    for rel in sorted(set(BRAND_ASSETS) | set(BRAND_ADDED)):
        if (tree.root / RES / rel).read_bytes() != (BRAND / "res" / rel).read_bytes():
            raise PatchError(f"{RES}/{rel}: not the brand asset")
    for p in sorted((tree.root / RES).glob("values*/strings.xml")):
        for m in ELEMENT_TEXT.finditer(p.read_text(encoding="utf-8")):
            left = (TELEGRAM_WORD.search(m.group(0)) or re.search("|".join(LOCAL_NAMES), m.group(0))
                    or CLIENT_SITES.search(m.group(0)))
            if left:
                raise PatchError(f"{p.relative_to(tree.root)}: {left.group(0)!r} is still in {m.group(0)[:80]!r}")
    sessions = tree.read(SESSIONS)
    if sessions.count("R.raw.pluma_devices") != 1 or "STICKERS_PLACEHOLDER_PACK_NAME" in sessions:
        raise PatchError(f"{SESSIONS}: Settings > Devices does not play the bundled animation")
    verify_intro(tree)
    found = {}
    for p in sorted((tree.root / JAVA).rglob("*.java")):
        n = len(SCHEME_LITERAL.findall(p.read_text(encoding="utf-8")))
        if n:
            found[p.relative_to(tree.root / JAVA).as_posix()] = n
    if found != SCHEME_KEEP:
        raise PatchError(f"tg: literals left in {found}, expected only the internal ones {SCHEME_KEEP}")
    if 'android:scheme="tg"' in tree.read(f"{MAIN}/AndroidManifest.xml"):
        raise PatchError("AndroidManifest.xml: the app still takes tg:// links")
    for name, _, layer, index, src in BRAND_LAYERS:
        rel = f"{RES}/{name}"
        if brand_layer(json.loads(tree.read(rel)), rel, layer, index)["shapes"] != json.loads((BRAND / src).read_text()):
            raise PatchError(f"{rel}: the layer {layer!r} is not the brand's")
    verify_theme(tree)


def verify_intro(tree):
    for rel, s in INTRO_GONE:
        if s in tree.read(rel):
            raise PatchError(f"{rel}: {s!r} is still there")
    intro = tree.read(INTRO)
    for s in INTRO_MARK:
        if intro.count(s) != 1:
            raise PatchError(f"{INTRO}: the intro of the mark is incomplete, "
                             f"{intro.count(s)} occurrences of {s!r}, expected 1")


def verify_theme(tree):
    """No Telegram blue in the default themes, the colour literals of
    BRAND_COLOURS included."""
    for rel, old, _, _ in BRAND_COLOURS:
        if old in tree.read(rel):
            raise PatchError(f"{rel}: Telegram's colour {old!r} is still there")
    themes = {asset: tree.read(f"{MAIN}/assets/{asset}") for asset, _, _ in DEFAULT_THEMES.values()}
    theme_java = tree.read(f"{JAVA}/ui/ActionBar/Theme.java")
    colors_java = tree.read(f"{JAVA}/ui/ActionBar/ThemeColors.java")
    # A model that reads nothing would pass anything: the defaults it reads
    # must be Telegram's blue in many places.
    names, defaults = theme_defaults(colors_java)
    if sum(map(telegram_blue, defaults.values())) < 100 or len(names) < 500:
        raise PatchError("ThemeColors.java: the check reads too few colours; upstream changed it")
    for asset, left in default_theme_blues(theme_java, colors_java, themes).items():
        if left:
            raise PatchError(f"{asset}: Telegram's blue is left in {', '.join(left)}")


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
    verify_birthdays(tree)
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
