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
and web clients in the built-in strings, no tg:// link scheme, no t.me link
the app makes itself and pluma.chat taken wherever t.me is, no Telegram
blue in the colours of the default themes, a birthday notice that leads to
the chat rather than to gifts, the video bitrates of Pluma, tags in Saved
Messages that ask for no Premium, premium stickers sent without Premium).

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
    def __init__(self, upstream, app, server_ipv4, server_port, server_ipv6, rsa_pem, abis, ccache, google_services, build=0):
        def need(env, key):
            if not env.get(key):
                raise PatchError(f"{key} is not set")
            return env[key]

        self.layer = int(need(upstream, "UPSTREAM_LAYER"))
        self.version = need(upstream, "UPSTREAM_VERSION")
        self.ndk = need(upstream, "NDK_VERSION")
        self.cmake = need(upstream, "CMAKE_VERSION")
        # Pluma's build number, the fourth part of versionName (self-update).
        if not isinstance(build, int) or not 0 <= build < 100000:
            raise PatchError(f"build number {build!r}: 0 to 99999")
        self.build = build
        self.version_name = f"{self.version}.{build:05d}"
        if not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", self.version_name):
            raise PatchError(f"version {self.version_name!r}: four numbers, as Android compares them")

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
                      must_contain=("GoogleDnsLoadTask", "MozillaDnsLoadTask"))

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

    # ccache for the native code: the launcher variables go to the CMake
    # arguments of the module that builds it.
    if c.ccache:
        tree.replace("TMessagesProj/build.gradle",
                     "arguments '-DANDROID_STL=c++_static', '-DANDROID_PLATFORM=android-23'",
                     "arguments '-DANDROID_STL=c++_static', '-DANDROID_PLATFORM=android-23', "
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

    video_quality(tree)
    birthdays(tree)
    sticker_sets(tree)
    saved_tags(tree)
    premium_stickers(tree)
    premium_for_everyone(tree)
    not_served(tree)
    self_update(tree, c)
    links(tree)
    brand(tree)
    login_screens(tree)


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


# updateStickerSets says which kind of sets changed (masks, emojis), as
# updateStickerSetsOrder does; upstream reloads the stickers whatever it says,
# so an emoji set installed or removed on another device reached this one
# only after a restart. The kind is taken as for updateStickerSetsOrder.
MESSAGES_CONTROLLER = "TMessagesProj/src/main/java/org/telegram/messenger/MessagesController.java"
STICKER_SETS_OLD = (
    "                        TL_update.TL_updateStickerSets update = (TL_update.TL_updateStickerSets) baseUpdate;\n"
    "                        getMediaDataController().loadStickers(MediaDataController.TYPE_IMAGE, false, true);\n")
STICKER_SETS_NEW = (
    "                        TL_update.TL_updateStickerSets update = (TL_update.TL_updateStickerSets) baseUpdate;\n"
    "                        // pluma: the kind of sets the update is about.\n"
    "                        int type;\n"
    "                        if (update.masks) {\n"
    "                            type = MediaDataController.TYPE_MASK;\n"
    "                        } else if (update.emojis) {\n"
    "                            type = MediaDataController.TYPE_EMOJIPACKS;\n"
    "                        } else {\n"
    "                            type = MediaDataController.TYPE_IMAGE;\n"
    "                        }\n"
    "                        getMediaDataController().loadStickers(type, false, true);\n")


def sticker_sets(tree):
    tree.replace(MESSAGES_CONTROLLER, STICKER_SETS_OLD, STICKER_SETS_NEW)


def verify_sticker_sets(tree):
    if STICKER_SETS_NEW not in tree.read(MESSAGES_CONTROLLER):
        raise PatchError(f"{MESSAGES_CONTROLLER}: updateStickerSets still reloads only the stickers")


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


# --- video quality -----------------------------------------------------------
# Task 052 of the server repository: a video is re-encoded before sending, as
# in Telegram, with the same choice of quality, but at a higher bitrate for
# every resolution (the owner's decision). By default a video goes in 720p on
# mobile data and in 1080p on Wi-Fi: the server's video_upload_maxbitrate is 85
# in the medium preset and 100 in the high one. Lines are those of upstream
# 12.9.1.
# - MediaController.makeVideoBitrate (6766-6797) caps the bitrate by the
#   shorter output side: 6.8 Mbit/s from 1080, 2.6 from 720, 1.0 from 480 and
#   0.75 below, and below 720 it also cuts the source bitrate (to 0.75 and 0.6
#   of it, with floors of 0.9 and 0.7 of the reference). The caps become 12, 5,
#   2.5 and 1.5 Mbit/s and no tier cuts the source bitrate. A small source is
#   never inflated: the convertor takes Math.min(originalBitrate, bitrate)
#   (MediaCodecVideoConvertor.java:427-429).
# - PhotoViewer.selectCompression (21689-21705) caps both the saved choice
#   (compress_video_%d, didChangedCompressionLevel 21233-21243, written on any
#   move of the slider and on Cancel of the picker, 6140-6143) and the default
#   at step 2, 720p. The cap becomes the step of the network: round(
#   video_upload_maxbitrate / (100 / steps)) - 1 over the steps of the source,
#   as SendMessagesHelper does (11727), not over the local compressionsCount
#   the loop has left at 5 (21697-21704). For a 1080p source (4 steps) 85, the
#   mobile preset, gives step 2, 720p, and 100, the Wi-Fi one, step 3, 1080p.
#   A choice saved on Wi-Fi comes back no higher than 720p on mobile data, as
#   the brief of task 052 asks; a lower one is kept, as upstream keeps it.
# - DownloadController (261-275): the mobile preset of a new install is the
#   built-in medium one; the built-in medium preset takes the server's 85
#   (app/bff/autodownload, videoUploadMaxBitrateMedium). loadAutoDownloadConfig
#   (360-383) sets the low, medium and high presets from the server first and
#   then moves the mobile, Wi-Fi and roaming presets that equal them, so a
#   preset that followed the medium one stops following it once the server's
#   value changes (installs from before 85 kept 100, 1080p on mobile data). It
#   compares with the presets as they were before the answer, and a preset left
#   at upstream's built-in medium one (bitrate 100) follows the medium one too.
# - SendMessagesHelper.createCompressionSettings (11679-11777), sending without
#   the editor (straight from the attachment menu, a share from another app),
#   picks step round(v / (100 / steps)) (1-based, 11727-11731) with long sides
#   432, 640, 848 and 1280 (11736-11749), one step below the editor's 480, 854,
#   1280 and 1920 (PhotoViewer.calculateResultVideoSize 21403-21438), and
#   scaled every source above 1280 px down to 1280 (11733-11734). It takes the
#   editor's sizes and scales only a source above 1920 px, so 85 gives 720p and
#   100 keeps 1080p, as in the editor.
# - A muted video, sent as a GIF, has no bitrate of its own (-1, PhotoViewer
#   9818-9820): the convertor gives it 921,600 bit/s
#   (MediaCodecVideoConvertor.java:424-426) and the size estimate the same
#   (PhotoViewer 21296-21298). Both become 1,843,200.
MEDIA_CONTROLLER = "TMessagesProj/src/main/java/org/telegram/messenger/MediaController.java"
PHOTO_VIEWER = "TMessagesProj/src/main/java/org/telegram/ui/PhotoViewer.java"
DOWNLOAD_CONTROLLER = "TMessagesProj/src/main/java/org/telegram/messenger/DownloadController.java"
SEND_MESSAGES_HELPER = "TMessagesProj/src/main/java/org/telegram/messenger/SendMessagesHelper.java"
VIDEO_CONVERTOR = "TMessagesProj/src/main/java/org/telegram/messenger/video/MediaCodecVideoConvertor.java"
VIDEO_BITRATE_OLD = (
    "        if (Math.min(height, width) >= 1080) {\n"
    "            maxBitrate = 6800_000;\n"
    "            compressFactor = 1f;\n"
    "            minCompressFactor = 1f;\n"
    "        } else if (Math.min(height, width) >= 720) {\n"
    "            maxBitrate = 2600_000;\n"
    "            compressFactor = 1f;\n"
    "            minCompressFactor = 1f;\n"
    "        } else if (Math.min(height, width) >= 480) {\n"
    "            maxBitrate = 1000_000;\n"
    "            compressFactor = 0.75f;\n"
    "            minCompressFactor = 0.9f;\n"
    "        } else {\n"
    "            maxBitrate = 750_000;\n"
    "            compressFactor = 0.6f;\n"
    "            minCompressFactor = 0.7f;\n"
    "        }\n")
VIDEO_BITRATE_NEW = (
    "        // pluma: higher caps than Telegram's, and no tier cuts the source\n"
    "        // bitrate; the convertor never goes above the source bitrate.\n"
    "        if (Math.min(height, width) >= 1080) {\n"
    "            maxBitrate = 12000_000;\n"
    "            compressFactor = 1f;\n"
    "            minCompressFactor = 1f;\n"
    "        } else if (Math.min(height, width) >= 720) {\n"
    "            maxBitrate = 5000_000;\n"
    "            compressFactor = 1f;\n"
    "            minCompressFactor = 1f;\n"
    "        } else if (Math.min(height, width) >= 480) {\n"
    "            maxBitrate = 2500_000;\n"
    "            compressFactor = 1f;\n"
    "            minCompressFactor = 1f;\n"
    "        } else {\n"
    "            maxBitrate = 1500_000;\n"
    "            compressFactor = 1f;\n"
    "            minCompressFactor = 1f;\n"
    "        }\n")
VIDEO_STEPS_OLD = (
    "                switch (selectedCompression) {\n"
    "                    case 1:\n"
    "                        maxSize = 432.0f;\n"
    "                        break;\n"
    "                    case 2:\n"
    "                        maxSize = 640.0f;\n"
    "                        break;\n"
    "                    case 3:\n"
    "                        maxSize = 848.0f;\n"
    "                        break;\n"
    "                    default:\n"
    "                        maxSize = 1280.0f;\n"
    "                        break;\n"
    "                }\n")
VIDEO_STEPS_NEW = (
    "                // pluma: the sizes of the editor's steps (PhotoViewer.calculateResultVideoSize).\n"
    "                switch (selectedCompression) {\n"
    "                    case 1:\n"
    "                        maxSize = 480.0f;\n"
    "                        break;\n"
    "                    case 2:\n"
    "                        maxSize = 854.0f;\n"
    "                        break;\n"
    "                    case 3:\n"
    "                        maxSize = 1280.0f;\n"
    "                        break;\n"
    "                    default:\n"
    "                        maxSize = 1920.0f;\n"
    "                        break;\n"
    "                }\n")
VIDEO_QUALITY_EDITS = (
    (MEDIA_CONTROLLER, VIDEO_BITRATE_OLD, VIDEO_BITRATE_NEW),
    (PHOTO_VIEWER,
     "        int maxCompression = 2;\n",
     "        // pluma: the network's step is the top: 720p on mobile data, 1080p on Wi-Fi; a lower saved choice is kept.\n"
     "        int maxCompression = Math.max(0, Math.min(this.compressionsCount - 1, Math.round(DownloadController"
     ".getInstance(currentAccount).getMaxVideoBitrate() / (100f / this.compressionsCount)) - 1));\n"),
    (PHOTO_VIEWER,
     "        return Math.min(maxCompression, Math.round(DownloadController.getInstance(currentAccount)"
     ".getMaxVideoBitrate() / (100f / compressionsCount)) - 1);\n",
     "        return maxCompression; // pluma: the network's step, above\n"),
    (DOWNLOAD_CONTROLLER,
     "                TL_account.autoDownloadSettings res = (TL_account.autoDownloadSettings) response;\n"
     "                lowPreset.set(res.low);\n",
     "                TL_account.autoDownloadSettings res = (TL_account.autoDownloadSettings) response;\n"
     "                // pluma: a preset follows the server's one it equalled before this answer, and one left at\n"
     "                // upstream's built-in medium (bitrate 100) follows the medium one.\n"
     "                final Preset oldLow = new Preset(lowPreset.toString(), lowPreset.toString());\n"
     "                final Preset oldMedium = new Preset(mediumPreset.toString(), mediumPreset.toString());\n"
     "                final Preset oldHigh = new Preset(highPreset.toString(), highPreset.toString());\n"
     "                final Preset upstreamMedium = new Preset(\"13_13_13_13_1048576_10485760_1048576_524288_1_1_1_0_100_1\", "
     "\"13_13_13_13_1048576_10485760_1048576_524288_1_1_1_0_100_1\");\n"
     "                lowPreset.set(res.low);\n"),
    (DOWNLOAD_CONTROLLER,
     "                    if (preset.equals(lowPreset)) {\n"
     "                        preset.set(res.low);\n"
     "                        preset.preloadStories = false;\n"
     "                    } else if (preset.equals(mediumPreset)) {\n"
     "                        preset.set(res.medium);\n"
     "                    } else if (preset.equals(highPreset)) {\n",
     "                    if (preset.equals(oldLow)) {\n"
     "                        preset.set(res.low);\n"
     "                        preset.preloadStories = false;\n"
     "                    } else if (preset.equals(oldMedium) || preset.equals(upstreamMedium)) {\n"
     "                        preset.set(res.medium);\n"
     "                    } else if (preset.equals(oldHigh)) {\n"),
    (PHOTO_VIEWER,
     "                bitrate = 921600;\n"
     "            }\n"
     "            estimatedSize = (long) (bitrate / 8 * (estimatedDuration / 1000.0f));\n",
     "                bitrate = 1843200; // pluma: as the convertor gives a muted video\n"
     "            }\n"
     "            estimatedSize = (long) (bitrate / 8 * (estimatedDuration / 1000.0f));\n"),
    (DOWNLOAD_CONTROLLER,
     '        String defaultMedium = "13_13_13_13_1048576_10485760_1048576_524288_1_1_1_0_100_1";\n',
     "        // pluma: video_upload_maxbitrate 85, the server's medium preset (720p on mobile data).\n"
     '        String defaultMedium = "13_13_13_13_1048576_10485760_1048576_524288_1_1_1_0_85_1";\n'),
    (SEND_MESSAGES_HELPER,
     "            if (selectedCompression != compressionsCount || "
     "Math.max(videoEditedInfo.originalWidth, videoEditedInfo.originalHeight) > 1280) {\n",
     "            // pluma: the top step keeps up to 1920 px, as in the editor.\n"
     "            if (selectedCompression != compressionsCount || "
     "Math.max(videoEditedInfo.originalWidth, videoEditedInfo.originalHeight) > 1920) {\n"),
    (SEND_MESSAGES_HELPER, VIDEO_STEPS_OLD, VIDEO_STEPS_NEW),
    (VIDEO_CONVERTOR,
     "                            } else if (bitrate <= 0) {\n"
     "                                bitrate = 921600;\n"
     "                            }\n"
     "                            if (originalBitrate > 0) {\n",
     "                            } else if (bitrate <= 0) {\n"
     "                                bitrate = 1843200; // pluma: twice Telegram's, for a muted video (GIF)\n"
     "                            }\n"
     "                            if (originalBitrate > 0) {\n"),
)


def video_quality(tree):
    for rel, old, new in VIDEO_QUALITY_EDITS:
        tree.replace(rel, old, new)


def verify_video_quality(tree):
    for rel, old, new in VIDEO_QUALITY_EDITS:
        text = tree.read(rel)
        if text.count(new) != 1 or old in text:
            changed = next(line for line in new.splitlines()
                           if line not in old.splitlines() and "// pluma:" not in line.split(";")[0])
            raise PatchError(f"{rel}: the video quality edit {changed.strip()!r} is not there")


# --- saved message tags ------------------------------------------------------
# Task 053 of the server repository: reaction tags in Saved Messages work for
# every user, as for a Premium user of Telegram (the owner's decision); Pluma
# sells no Premium. The client reads no server setting for tags: each place
# asks whether the user has Premium (UserConfig.isPremium), and
# premium_purchase_blocked, which the server sets, even hides the tag selector
# of the message menu (ChatActivity 31909, premiumFeaturesBlocked). Premium
# itself would open every Premium feature, so MessagesController gets
# savedTagsAvailable(), true, and only the tag places ask it instead. Lines are
# those of upstream 12.9.1.
# - ChatActivity: the long-press hint over a tag (8851), the Tag action of the
#   selection (10252, 19217) and its selector (10271, 10324), the hint and the
#   selector of the message menu (31899, 31909), adding or removing a tag
#   (32654), the search by tags (38579, isSupportedTags), a tap on a tag under a
#   message (44862) and its Rename item (44934).
# - SearchTagsList, the tags over the search results: filtering (272), renaming
#   on a long press (303-306), the Premium banner (655).
# - ReactionsContainerLayout, the tag selector: the full list of reactions with
#   the expand button (1073), the recent and the default reactions in it
#   (1390), the lock on each tag (1964). The expand button of tags stays off as
#   for Premium (1119-1122); custom emoji in the expanded list still ask for
#   Premium (CustomEmojiReactionsWindow 209), as reactions do elsewhere.
# - SharedMediaLayout, the search icon of Saved Messages in the profile (3787).
# - BulletinFactory, the tag selector in the notice of messages forwarded to
#   Saved Messages (1321, 1361).
# - MessageObject.selectReaction (12341): a message takes as many tags as a
#   Premium user may put, reactions_user_max_premium (3 from the server);
#   reactions elsewhere keep getMaxUserReactionsCount, which for a user without
#   Premium is the server's reactions_user_max_default.
# The Premium sheets these places showed are no longer reached; no new text.
CHAT_ACTIVITY = "TMessagesProj/src/main/java/org/telegram/ui/ChatActivity.java"
SEARCH_TAGS_LIST = "TMessagesProj/src/main/java/org/telegram/ui/Components/SearchTagsList.java"
REACTIONS_CONTAINER = "TMessagesProj/src/main/java/org/telegram/ui/Components/ReactionsContainerLayout.java"
SHARED_MEDIA_LAYOUT = "TMessagesProj/src/main/java/org/telegram/ui/Components/SharedMediaLayout.java"
BULLETIN_FACTORY = "TMessagesProj/src/main/java/org/telegram/ui/Components/BulletinFactory.java"
MESSAGE_OBJECT = "TMessagesProj/src/main/java/org/telegram/messenger/MessageObject.java"
SAVED_TAGS_CALL = "savedTagsAvailable()"
SAVED_TAGS_COMMENT = "// pluma: saved message tags without Premium."
SAVED_TAGS_EDITS = (
    (MESSAGES_CONTROLLER,
     "    public boolean premiumPurchaseBlocked() {\n"
     "        return premiumLocked;\n"
     "    }\n",
     "    public boolean premiumPurchaseBlocked() {\n"
     "        return premiumLocked;\n"
     "    }\n"
     "    // pluma: tags in Saved Messages are open to every user; Pluma sells no Premium.\n"
     "    public boolean savedTagsAvailable() {\n"
     "        return true;\n"
     "    }\n"),
    (CHAT_ACTIVITY,
     "            if (getUserConfig().isPremium()) {\n"
     "                savedMessagesTagHint = new HintView2(",
     f"            {SAVED_TAGS_COMMENT}\n"
     "            if (getMessagesController().savedTagsAvailable()) {\n"
     "                savedMessagesTagHint = new HintView2("),
    (CHAT_ACTIVITY,
     "        actionMode.setItemVisibility(tag_message, getUserConfig().isPremium() ? View.VISIBLE : View.GONE);\n",
     f"        {SAVED_TAGS_COMMENT}\n"
     "        actionMode.setItemVisibility(tag_message, getMessagesController().savedTagsAvailable() ? View.VISIBLE : View.GONE);\n"),
    (CHAT_ACTIVITY,
     "        if (getDialogId() != getUserConfig().getClientUserId() || !getUserConfig().isPremium()) return;\n"
     "        if (tagSelector != null) return;\n",
     f"        {SAVED_TAGS_COMMENT}\n"
     "        if (getDialogId() != getUserConfig().getClientUserId() || !getMessagesController().savedTagsAvailable()) return;\n"
     "        if (tagSelector != null) return;\n"),
    (CHAT_ACTIVITY,
     "                if (getDialogId() == getUserConfig().getClientUserId() && !getUserConfig().isPremium()) {\n"
     "                    new PremiumFeatureBottomSheet(ChatActivity.this, PremiumPreviewFragment.PREMIUM_FEATURE_SAVED_TAGS, true).show();\n"
     "                    clearSelectionMode(false);\n",
     f"                {SAVED_TAGS_COMMENT}\n"
     "                if (getDialogId() == getUserConfig().getClientUserId() && !getMessagesController().savedTagsAvailable()) {\n"
     "                    new PremiumFeatureBottomSheet(ChatActivity.this, PremiumPreviewFragment.PREMIUM_FEATURE_SAVED_TAGS, true).show();\n"
     "                    clearSelectionMode(false);\n"),
    (CHAT_ACTIVITY,
     "                    tagItem.setVisibility(getUserConfig().isPremium() && (\n",
     f"                    {SAVED_TAGS_COMMENT}\n"
     "                    tagItem.setVisibility(getMessagesController().savedTagsAvailable() && (\n"),
    (CHAT_ACTIVITY,
     "                    reactionsLayout.setHint(getUserConfig().isPremium() ? LocaleController.getString(R.string.SavedTagReactionsHint2) : ",
     f"                    {SAVED_TAGS_COMMENT}\n"
     "                    reactionsLayout.setHint(getMessagesController().savedTagsAvailable() ? LocaleController.getString(R.string.SavedTagReactionsHint2) : "),
    (CHAT_ACTIVITY,
     "                if (isReactionsAvailable && (!tags || !getMessagesController().premiumFeaturesBlocked())) {\n",
     f"                {SAVED_TAGS_COMMENT}\n"
     "                if (isReactionsAvailable && (!tags || getMessagesController().savedTagsAvailable())) {\n"),
    (CHAT_ACTIVITY,
     "        if (getDialogId() == getUserConfig().getClientUserId() && !getUserConfig().isPremium() && primaryMessage.messageOwner != null && ",
     f"        {SAVED_TAGS_COMMENT}\n"
     "        if (getDialogId() == getUserConfig().getClientUserId() && !getMessagesController().savedTagsAvailable() && primaryMessage.messageOwner != null && "),
    (CHAT_ACTIVITY,
     "\t\treturn getUserConfig().getClientUserId() == getDialogId() && !getMessagesController().getSavedMessagesController().unsupported && getUserConfig().isPremium();\n",
     f"\t\t{SAVED_TAGS_COMMENT}\n"
     "\t\treturn getUserConfig().getClientUserId() == getDialogId() && !getMessagesController().getSavedMessagesController().unsupported && getMessagesController().savedTagsAvailable();\n"),
    (CHAT_ACTIVITY,
     "        if (getUserConfig().getClientUserId() == getDialogId() && messageObject.areTags() && !getUserConfig().isPremium()) {\n",
     f"        {SAVED_TAGS_COMMENT}\n"
     "        if (getUserConfig().getClientUserId() == getDialogId() && messageObject.areTags() && !getMessagesController().savedTagsAvailable()) {\n"),
    (CHAT_ACTIVITY,
     "                if (getUserConfig().isPremium()) {\n"
     "                    ActionBarMenuSubItem editTag = ",
     f"                {SAVED_TAGS_COMMENT}\n"
     "                if (getMessagesController().savedTagsAvailable()) {\n"
     "                    ActionBarMenuSubItem editTag = "),
    (SEARCH_TAGS_LIST,
     "            if (!UserConfig.getInstance(currentAccount).isPremium()) {\n"
     "                new PremiumFeatureBottomSheet(fragment, PremiumPreviewFragment.PREMIUM_FEATURE_SAVED_TAGS, true).show();\n"
     "                return;\n",
     f"            {SAVED_TAGS_COMMENT}\n"
     "            if (!MessagesController.getInstance(currentAccount).savedTagsAvailable()) {\n"
     "                new PremiumFeatureBottomSheet(fragment, PremiumPreviewFragment.PREMIUM_FEATURE_SAVED_TAGS, true).show();\n"
     "                return;\n"),
    (SEARCH_TAGS_LIST,
     "            if (position < 0 || position >= items.size() || !UserConfig.getInstance(currentAccount).isPremium())\n"
     "                return false;\n"
     "            if (!UserConfig.getInstance(currentAccount).isPremium()) {\n",
     f"            {SAVED_TAGS_COMMENT}\n"
     "            if (position < 0 || position >= items.size() || !MessagesController.getInstance(currentAccount).savedTagsAvailable())\n"
     "                return false;\n"
     "            if (!MessagesController.getInstance(currentAccount).savedTagsAvailable()) {\n"),
    (SEARCH_TAGS_LIST,
     "        if (shownPremiumLayout = !UserConfig.getInstance(currentAccount).isPremium()) {\n",
     f"        {SAVED_TAGS_COMMENT}\n"
     "        if (shownPremiumLayout = !MessagesController.getInstance(currentAccount).savedTagsAvailable()) {\n"),
    (REACTIONS_CONTAINER,
     "            allReactionsAvailable = UserConfig.getInstance(currentAccount).isPremium();\n"
     "            fillRecentReactionsList(visibleReactions);\n",
     f"            {SAVED_TAGS_COMMENT}\n"
     "            allReactionsAvailable = MessagesController.getInstance(currentAccount).savedTagsAvailable();\n"
     "            fillRecentReactionsList(visibleReactions);\n"),
    (REACTIONS_CONTAINER,
     "        if (type != TYPE_TAGS || UserConfig.getInstance(currentAccount).isPremium()) {\n",
     f"        {SAVED_TAGS_COMMENT}\n"
     "        if (type != TYPE_TAGS || MessagesController.getInstance(currentAccount).savedTagsAvailable()) {\n"),
    (REACTIONS_CONTAINER,
     "            isLocked = type == TYPE_TAGS && !userIsPremium || ",
     f"            {SAVED_TAGS_COMMENT}\n"
     "            isLocked = type == TYPE_TAGS && !MessagesController.getInstance(currentAccount).savedTagsAvailable() || "),
    (SHARED_MEDIA_LAYOUT,
     "                        searchItemIcon.setIcon(hasFilters() && profileActivity.getUserConfig().isPremium() ? ",
     f"                        {SAVED_TAGS_COMMENT}\n"
     "                        searchItemIcon.setIcon(hasFilters() && profileActivity.getMessagesController().savedTagsAvailable() ? "),
    (BULLETIN_FACTORY,
     "        if (!UserConfig.getInstance(UserConfig.selectedAccount).isPremium() || fragment == null) {\n"
     "            return false;\n"
     "        }\n"
     "        final Bulletin.LottieLayoutWithReactions layout",
     f"        {SAVED_TAGS_COMMENT}\n"
     "        if (!MessagesController.getInstance(UserConfig.selectedAccount).savedTagsAvailable() || fragment == null) {\n"
     "            return false;\n"
     "        }\n"
     "        final Bulletin.LottieLayoutWithReactions layout"),
    (BULLETIN_FACTORY,
     "        final Bulletin.LottieLayout layout = UserConfig.getInstance(UserConfig.selectedAccount).isPremium() && fragment != null && ",
     f"        {SAVED_TAGS_COMMENT}\n"
     "        final Bulletin.LottieLayout layout = MessagesController.getInstance(UserConfig.selectedAccount).savedTagsAvailable() && fragment != null && "),
    (MESSAGE_OBJECT,
     "        int maxReactionsCount = MessagesController.getInstance(currentAccount).getMaxUserReactionsCount();\n",
     "        // pluma: tags in Saved Messages take the Premium limit.\n"
     "        int maxReactionsCount = areTags() ? MessagesController.getInstance(currentAccount).reactionsUserMaxPremium : "
     "MessagesController.getInstance(currentAccount).getMaxUserReactionsCount();\n"),
)
# The places that ask savedTagsAvailable(), each file with its count; nothing
# else may ask it.
SAVED_TAGS_USES = {
    MESSAGES_CONTROLLER: 1,
    CHAT_ACTIVITY: 11,
    SEARCH_TAGS_LIST: 4,
    REACTIONS_CONTAINER: 3,
    SHARED_MEDIA_LAYOUT: 1,
    BULLETIN_FACTORY: 2,
}


def saved_tags(tree):
    for rel, old, new in SAVED_TAGS_EDITS:
        tree.replace(rel, old, new)


def verify_saved_tags(tree):
    for rel, old, new in SAVED_TAGS_EDITS:
        text = tree.read(rel)
        # The method is added after the text it is anchored on, which stays.
        if text.count(new) != 1 or old in text.replace(new, ""):
            changed = next(line for line in new.splitlines()
                           if line not in old.splitlines() and "// pluma:" not in line)
            raise PatchError(f"{rel}: the saved tags edit {changed.strip()!r} is not there")
    for rel, count in SAVED_TAGS_USES.items():
        found = tree.read(rel).count(SAVED_TAGS_CALL)
        if found != count:
            raise PatchError(f"{rel}: {found} uses of {SAVED_TAGS_CALL}, expected {count}")
    definition = re.findall(r"public boolean savedTagsAvailable\(\) \{\n\s*return (\w+);\n", tree.read(MESSAGES_CONTROLLER))
    if definition != ["true"]:
        raise PatchError(f"{MESSAGES_CONTROLLER}: savedTagsAvailable() does not return true")


# --- premium stickers ---------------------------------------------------------
# Task 058 of the server repository: a premium sticker (a document with a
# video_thumbs entry of type "f", MessageObject 425) is sent and played by
# every user, as with Premium in Telegram; Pluma sells no Premium, and the
# server sends premium_purchase_blocked. The owner reported the gate as a
# defect. Nothing the server can send opens it: each place asks
# UserConfig.isPremium(), and premiumFeaturesBlocked() (MessagesController
# 739) even drops such stickers from every list. premiumStickersAvailable(),
# true, stands in at these places only; lines are those of upstream 12.9.1:
# - filterPremiumStickers (MessagesController 969): sets in the panel, the
#   set's window and the settings keep their premium stickers;
# - the panel: a tap opens the unlock view instead of sending (EmojiView
#   2350); favourites and recents drop premium stickers (6179);
# - the long press: the unlock view instead of the menu with "Send"
#   (ContentPreviewViewer 714);
# - stickers suggested for an emoji (MentionsAdapter 273, 298);
# - the mark on a sticker: the lock in the middle or the Premium star in the
#   corner (StickerEmojiCell 298-318, StickerCell 212-231);
# - the sender's effect: only a sender with Premium has it played when the
#   sticker has just been sent (ChatActivity 25320, forcePlayEffect, which
#   15985 asks for an outgoing message).
# The recipient plays the effect from the document alone (ChatActivity 15984,
# EmojiAnimationsOverlay 682-687, ImageLocation.getForDocument(videoSize,
# document)), asking no Premium; custom emoji are another matter and stay.
CONTENT_PREVIEW_VIEWER = "TMessagesProj/src/main/java/org/telegram/ui/ContentPreviewViewer.java"
MENTIONS_ADAPTER = "TMessagesProj/src/main/java/org/telegram/ui/Adapters/MentionsAdapter.java"
EMOJI_VIEW = "TMessagesProj/src/main/java/org/telegram/ui/Components/EmojiView.java"
STICKER_CELL = "TMessagesProj/src/main/java/org/telegram/ui/Cells/StickerCell.java"
STICKER_EMOJI_CELL = "TMessagesProj/src/main/java/org/telegram/ui/Cells/StickerEmojiCell.java"
PREMIUM_STICKERS_CALL = "premiumStickersAvailable()"
PREMIUM_STICKERS_COMMENT = "// pluma: premium stickers without Premium."
_MESSAGES_IMPORT = "import org.telegram.messenger.MessagesController;\n"
_USER_CONFIG_IMPORT = "import org.telegram.messenger.UserConfig;\n"
PREMIUM_STICKERS_EDITS = (
    (MESSAGES_CONTROLLER,
     "    public TLRPC.TL_messages_stickerSet filterPremiumStickers(TLRPC.TL_messages_stickerSet stickerSet) {\n"
     "        if (!premiumFeaturesBlocked() || stickerSet == null) {\n",
     "    // pluma: premium stickers are open to every user; Pluma sells no Premium.\n"
     "    public boolean premiumStickersAvailable() {\n"
     "        return true;\n"
     "    }\n"
     "\n"
     "    public TLRPC.TL_messages_stickerSet filterPremiumStickers(TLRPC.TL_messages_stickerSet stickerSet) {\n"
     f"        {PREMIUM_STICKERS_COMMENT}\n"
     "        if (premiumStickersAvailable() || !premiumFeaturesBlocked() || stickerSet == null) {\n"),
    (CONTENT_PREVIEW_VIEWER,
     "                if (MessageObject.isPremiumSticker(currentDocument) && !AccountInstance.getInstance(currentAccount).getUserConfig().isPremium()) {\n",
     f"                {PREMIUM_STICKERS_COMMENT}\n"
     "                if (MessageObject.isPremiumSticker(currentDocument) && !MessagesController.getInstance(currentAccount).premiumStickersAvailable()) {\n"),
    (MENTIONS_ADAPTER,
     "        if (!UserConfig.getInstance(currentAccount).isPremium() && MessageObject.isPremiumSticker(document)) {\n"
     "            return;\n",
     f"        {PREMIUM_STICKERS_COMMENT}\n"
     "        if (!MessagesController.getInstance(currentAccount).premiumStickersAvailable() && MessageObject.isPremiumSticker(document)) {\n"
     "            return;\n"),
    (MENTIONS_ADAPTER,
     "            if (!UserConfig.getInstance(currentAccount).isPremium() && MessageObject.isPremiumSticker(document)) {\n"
     "                continue;\n",
     f"            {PREMIUM_STICKERS_COMMENT}\n"
     "            if (!MessagesController.getInstance(currentAccount).premiumStickersAvailable() && MessageObject.isPremiumSticker(document)) {\n"
     "                continue;\n"),
    (EMOJI_VIEW,
     "                if (cell.getSticker() != null && MessageObject.isPremiumSticker(cell.getSticker()) && !AccountInstance.getInstance(currentAccount).getUserConfig().isPremium()) {\n",
     f"                {PREMIUM_STICKERS_COMMENT}\n"
     "                if (cell.getSticker() != null && MessageObject.isPremiumSticker(cell.getSticker()) && !MessagesController.getInstance(currentAccount).premiumStickersAvailable()) {\n"),
    (EMOJI_VIEW,
     "            if (MessagesController.getInstance(currentAccount).premiumFeaturesBlocked()) {\n"
     "                for (int a = 0; a < favouriteStickers.size(); a++) {\n",
     f"            {PREMIUM_STICKERS_COMMENT}\n"
     "            if (!MessagesController.getInstance(currentAccount).premiumStickersAvailable() && MessagesController.getInstance(currentAccount).premiumFeaturesBlocked()) {\n"
     "                for (int a = 0; a < favouriteStickers.size(); a++) {\n"),
    (CHAT_ACTIVITY,
     "                if (messageObject.wasJustSent && (getUserConfig().isPremium() || messageObject.isAnimatedAnimatedEmoji() || messageObject.getEffect() != null) && ",
     f"                {PREMIUM_STICKERS_COMMENT}\n"
     "                if (messageObject.wasJustSent && (getUserConfig().isPremium() || (getMessagesController().premiumStickersAvailable() && messageObject.isPremiumSticker()) || messageObject.isAnimatedAnimatedEmoji() || messageObject.getEffect() != null) && "),
    (STICKER_CELL, _USER_CONFIG_IMPORT, _MESSAGES_IMPORT + _USER_CONFIG_IMPORT),
    (STICKER_CELL,
     "        FrameLayout.LayoutParams layoutParams = (LayoutParams) premiumIconView.getLayoutParams();\n"
     "        if (!UserConfig.getInstance(UserConfig.selectedAccount).isPremium()) {\n",
     "        FrameLayout.LayoutParams layoutParams = (LayoutParams) premiumIconView.getLayoutParams();\n"
     f"        {PREMIUM_STICKERS_COMMENT}\n"
     "        if (!MessagesController.getInstance(UserConfig.selectedAccount).premiumStickersAvailable()) {\n"),
    (STICKER_CELL,
     "        premiumIconView.setLocked(!UserConfig.getInstance(UserConfig.selectedAccount).isPremium());\n",
     f"        {PREMIUM_STICKERS_COMMENT}\n"
     "        premiumIconView.setLocked(!MessagesController.getInstance(UserConfig.selectedAccount).premiumStickersAvailable());\n"),
    (STICKER_EMOJI_CELL, _USER_CONFIG_IMPORT, _MESSAGES_IMPORT + _USER_CONFIG_IMPORT),
    (STICKER_EMOJI_CELL,
     "        FrameLayout.LayoutParams layoutParams = (LayoutParams) premiumIconView.getLayoutParams();\n"
     "        if (!UserConfig.getInstance(currentAccount).isPremium()) {\n",
     "        FrameLayout.LayoutParams layoutParams = (LayoutParams) premiumIconView.getLayoutParams();\n"
     f"        {PREMIUM_STICKERS_COMMENT}\n"
     "        if (!MessagesController.getInstance(currentAccount).premiumStickersAvailable()) {\n"),
    (STICKER_EMOJI_CELL,
     "        premiumIconView.setLocked(!UserConfig.getInstance(currentAccount).isPremium());\n",
     f"        {PREMIUM_STICKERS_COMMENT}\n"
     "        premiumIconView.setLocked(!MessagesController.getInstance(currentAccount).premiumStickersAvailable());\n"),
)
# The places that ask premiumStickersAvailable(), each file with its count;
# nothing else may ask it.
PREMIUM_STICKERS_USES = {
    MESSAGES_CONTROLLER: 2,
    CONTENT_PREVIEW_VIEWER: 1,
    CHAT_ACTIVITY: 1,
    MENTIONS_ADAPTER: 2,
    EMOJI_VIEW: 2,
    STICKER_CELL: 2,
    STICKER_EMOJI_CELL: 2,
}


def premium_stickers(tree):
    for rel, old, new in PREMIUM_STICKERS_EDITS:
        tree.replace(rel, old, new)


def verify_premium_stickers(tree):
    for rel, old, new in PREMIUM_STICKERS_EDITS:
        text = tree.read(rel)
        if text.count(new) != 1 or old in text.replace(new, ""):
            changed = next(line for line in new.splitlines()
                           if line not in old.splitlines() and "// pluma:" not in line)
            raise PatchError(f"{rel}: the premium stickers edit {changed.strip()!r} is not there")
    for rel, count in PREMIUM_STICKERS_USES.items():
        found = tree.read(rel).count(PREMIUM_STICKERS_CALL)
        if found != count:
            raise PatchError(f"{rel}: {found} uses of {PREMIUM_STICKERS_CALL}, expected {count}")
    definition = re.findall(r"public boolean premiumStickersAvailable\(\) \{\n\s*return (\w+);\n", tree.read(MESSAGES_CONTROLLER))
    if definition != ["true"]:
        raise PatchError(f"{MESSAGES_CONTROLLER}: premiumStickersAvailable() does not return true")


# --- self-update -------------------------------------------------------------
# Task 054 of the server repository (ADR 0035): the APK from the site updates
# itself, as Telegram's own APK from its site does. Upstream checks for updates
# only in the standalone build (LaunchActivity 5958) and keeps the update sheet
# and the side menu panel in its module TMessagesProj_AppStandalone, which
# Pluma does not build: it changes the package (applicationIdSuffix ".web") and
# adds Telegram's SMS jobs. Making TMessagesProj_App standalone
# (isStandalone()) would also turn on what the standalone build shows besides
# updates, the TON row of the settings and the profile (SettingsActivity 712,
# ProfileActivity 10628) among them. So:
# - ApplicationLoader gets isSelfUpdatingBuild(), true, and only the update
#   places ask it instead of isStandaloneBuild(): the check (LaunchActivity
#   5958) and its sheet (6011), the "update the app" buttons of unsupported
#   messages and stories (ChatActivity 41304, PeerStoriesView 4416), the
#   blocking screen (BlockingUpdateView 142, 303), the side menu panel
#   (SharedConfig 771), and the debug menu's "Check app update" (ProfileActivity
#   4653, SettingsActivity 1430);
# - the app's ApplicationLoaderImpl gets the standalone module's install,
#   sheet and panel overrides (its ApplicationLoaderImpl 63-114, without the SMS
#   jobs), and the sheet and the panel files are copied from that module as
#   they are (SHA-256 below).
# The server compares versions as Android does (SharedConfig 811-824: only the
# parts both have, each an integer), so versionName gets Pluma's build number
# as a fourth part, 12.9.1.NNNNN. Five digits, zero-padded: after a restart
# Android keeps a pending update only while the installed versionName is
# below it as a string (SharedConfig 576), and fixed width makes the string
# order the number order (12.9.1.00099 < 12.9.1.00100). It is set in the app
# module only: the library's BuildConfig (BUILD_VERSION_STRING) keeps
# upstream's version, so its compile stays in the Gradle build cache; the
# version the app reports and compares is the package's (ConnectionsManager
# 223, SharedConfig 567, 791). versionCode rises with it: (APP_VERSION_CODE *
# 1000 + N) * 10 + the ABI digit, above every earlier Pluma build (69799); it
# keeps rising across upstream versions. Lines are those of upstream
# 12.9.1.
LAUNCH_ACTIVITY = "TMessagesProj/src/main/java/org/telegram/ui/LaunchActivity.java"
PEER_STORIES_VIEW = "TMessagesProj/src/main/java/org/telegram/ui/Stories/PeerStoriesView.java"
BLOCKING_UPDATE_VIEW = "TMessagesProj/src/main/java/org/telegram/ui/Components/BlockingUpdateView.java"
SHARED_CONFIG = "TMessagesProj/src/main/java/org/telegram/messenger/SharedConfig.java"
PROFILE_ACTIVITY = "TMessagesProj/src/main/java/org/telegram/ui/ProfileActivity.java"
DEBUG_SETTINGS_ACTIVITY = "TMessagesProj/src/main/java/org/telegram/ui/DebugSettingsActivity.java"
ADMIN_LOG_ACTIVITY = "TMessagesProj/src/main/java/org/telegram/ui/ChannelAdminLogActivity.java"
APPLICATION_LOADER = "TMessagesProj/src/main/java/org/telegram/messenger/ApplicationLoader.java"
APP_LOADER_IMPL = "TMessagesProj_App/src/main/java/org/telegram/messenger/ApplicationLoaderImpl.java"
APP_BUILD_GRADLE = "TMessagesProj_App/build.gradle"
SELF_UPDATE_CALL = "ApplicationLoader.isSelfUpdatingBuild()"
SELF_UPDATE_EDITS = (
    (APPLICATION_LOADER,
     "    public static boolean isStandaloneBuild() {\n"
     "        return applicationLoaderInstance.isStandalone();\n"
     "    }\n",
     "    public static boolean isStandaloneBuild() {\n"
     "        return applicationLoaderInstance.isStandalone();\n"
     "    }\n"
     "\n"
     "    // pluma: the APK from the site updates itself from the server (help.getAppUpdate).\n"
     "    public static boolean isSelfUpdatingBuild() {\n"
     "        return true;\n"
     "    }\n"),
    (LAUNCH_ACTIVITY,
     "        if (!ApplicationLoader.isStandaloneBuild() && !ApplicationLoader.isBetaBuild()) {\n",
     "        if (!ApplicationLoader.isSelfUpdatingBuild() && !ApplicationLoader.isBetaBuild()) {\n"),
    (LAUNCH_ACTIVITY,
     "                        } else if (ApplicationLoader.isStandaloneBuild() || BuildVars.DEBUG_VERSION) {\n",
     "                        } else if (ApplicationLoader.isSelfUpdatingBuild() || BuildVars.DEBUG_VERSION) {\n"),
    (CHAT_ACTIVITY,
     "            if (ApplicationLoader.isStandaloneBuild()) {\n",
     "            if (ApplicationLoader.isSelfUpdatingBuild()) {\n"),
    (ADMIN_LOG_ACTIVITY,
     "                        return ChatObject.isForum(currentChat);\n"
     "                    }\n"
     "\n"
     "                    @Override\n"
     "                    public void didPressAppUpdateButton() {\n"
     "                        if (ApplicationLoader.isStandaloneBuild()) {\n",
     "                        return ChatObject.isForum(currentChat);\n"
     "                    }\n"
     "\n"
     "                    @Override\n"
     "                    public void didPressAppUpdateButton() {\n"
     "                        if (ApplicationLoader.isSelfUpdatingBuild()) {\n"),
    (ADMIN_LOG_ACTIVITY,
     "                cell.setDelegate(new ChatMessageCell.ChatMessageCellDelegate() {\n"
     "                    @Override\n"
     "                    public void didPressAppUpdateButton() {\n"
     "                        if (ApplicationLoader.isStandaloneBuild()) {\n",
     "                cell.setDelegate(new ChatMessageCell.ChatMessageCellDelegate() {\n"
     "                    @Override\n"
     "                    public void didPressAppUpdateButton() {\n"
     "                        if (ApplicationLoader.isSelfUpdatingBuild()) {\n"),
    (PEER_STORIES_VIEW,
     "            if (ApplicationLoader.isStandaloneBuild()) {\n",
     "            if (ApplicationLoader.isSelfUpdatingBuild()) {\n"),
    (BLOCKING_UPDATE_VIEW,
     "            if (ApplicationLoader.isStandaloneBuild() || BuildVars.DEBUG_VERSION) {\n",
     "            if (ApplicationLoader.isSelfUpdatingBuild() || BuildVars.DEBUG_VERSION) {\n"),
    (BLOCKING_UPDATE_VIEW,
     "        if (check && ApplicationLoader.isStandaloneBuild()) {\n",
     "        if (check && ApplicationLoader.isSelfUpdatingBuild()) {\n"),
    (SHARED_CONFIG,
     "        if (pendingAppUpdate == null || pendingAppUpdate.document == null || !ApplicationLoader.isStandaloneBuild()) {\n",
     "        if (pendingAppUpdate == null || pendingAppUpdate.document == null || !ApplicationLoader.isSelfUpdatingBuild()) {\n"),
    (PROFILE_ACTIVITY,
     "                                BuildVars.DEBUG_PRIVATE_VERSION || ApplicationLoader.isStandaloneBuild() || ApplicationLoader.isBetaBuild() ? "
     "getString(\"DebugMenuCheckAppUpdate\", R.string.DebugMenuCheckAppUpdate) : null,\n",
     "                                BuildVars.DEBUG_PRIVATE_VERSION || ApplicationLoader.isSelfUpdatingBuild() || ApplicationLoader.isBetaBuild() ? "
     "getString(\"DebugMenuCheckAppUpdate\", R.string.DebugMenuCheckAppUpdate) : null,\n"),
    (DEBUG_SETTINGS_ACTIVITY,
     "        if (BuildVars.DEBUG_PRIVATE_VERSION || ApplicationLoader.isStandaloneBuild() || ApplicationLoader.isBetaBuild()) {\n"
     "            items.add(UItem.asButton(ID_CHECK_APP_UPDATE,",
     "        if (BuildVars.DEBUG_PRIVATE_VERSION || ApplicationLoader.isSelfUpdatingBuild() || ApplicationLoader.isBetaBuild()) {\n"
     "            items.add(UItem.asButton(ID_CHECK_APP_UPDATE,"),
)
# Where the update places ask it, and how often.
SELF_UPDATE_USES = {
    LAUNCH_ACTIVITY: 2, CHAT_ACTIVITY: 1, ADMIN_LOG_ACTIVITY: 2, PEER_STORIES_VIEW: 1, BLOCKING_UPDATE_VIEW: 2,
    SHARED_CONFIG: 1, PROFILE_ACTIVITY: 1, DEBUG_SETTINGS_ACTIVITY: 1,
}
STANDALONE_COMPONENTS = "TMessagesProj_AppStandalone/src/main/java/org/telegram/ui/Components"
APP_COMPONENTS = "TMessagesProj_App/src/main/java/org/telegram/ui/Components"
SELF_UPDATE_FILES = {
    "UpdateAppAlertDialog.java": "4545e52ece790001b1056dbcbd4e7e58e0fe4b9ca454b7788e08f58fb1d0af20",
    "UpdateLayout.java": "e1050c8c68cc6ba015edf354be819ea10ba3ca648779b03b33a76aa521f94c99",
}
APP_LOADER_IMPL_UPSTREAM = """package org.telegram.messenger;

import org.telegram.messenger.regular.BuildConfig;

public class ApplicationLoaderImpl extends ApplicationLoader {
    @Override
    protected String onGetApplicationId() {
        return BuildConfig.APPLICATION_ID;
    }
}
"""
APP_LOADER_IMPL_PLUMA = """package org.telegram.messenger;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.view.ViewGroup;

import androidx.core.content.FileProvider;

import org.telegram.messenger.regular.BuildConfig;
import org.telegram.tgnet.TLRPC;
import org.telegram.ui.Components.AlertsCreator;
import org.telegram.ui.Components.UpdateAppAlertDialog;
import org.telegram.ui.Components.UpdateLayout;
import org.telegram.ui.IUpdateLayout;

import java.io.File;

public class ApplicationLoaderImpl extends ApplicationLoader {
    @Override
    protected String onGetApplicationId() {
        return BuildConfig.APPLICATION_ID;
    }

    // pluma: the install, the update sheet and the side menu panel of the
    // standalone build (TMessagesProj_AppStandalone, ApplicationLoaderImpl):
    // the APK from the site updates itself from the server.
    @Override
    public boolean checkApkInstallPermissions(final Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && !ApplicationLoader.applicationContext.getPackageManager().canRequestPackageInstalls()) {
            AlertsCreator.createApkRestrictedDialog(context, null).show();
            return false;
        }
        return true;
    }

    @Override
    public boolean openApkInstall(Activity activity, TLRPC.Document document) {
        boolean exists = false;
        try {
            File f = FileLoader.getInstance(UserConfig.selectedAccount).getPathToAttach(document, true);
            if (exists = f.exists()) {
                Intent intent = new Intent(Intent.ACTION_VIEW);
                intent.setFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);

                if (Build.VERSION.SDK_INT >= 24) {
                    intent.setDataAndType(FileProvider.getUriForFile(activity, ApplicationLoader.getApplicationId() + ".provider", f), "application/vnd.android.package-archive");
                } else {
                    intent.setDataAndType(Uri.fromFile(f), "application/vnd.android.package-archive");
                }
                try {
                    activity.startActivityForResult(intent, 500);
                } catch (Exception e) {
                    FileLog.e(e);
                }
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
        return exists;
    }

    @Override
    public boolean showUpdateAppPopup(Context context, TLRPC.TL_help_appUpdate update, int account) {
        try {
            (new UpdateAppAlertDialog(context, update, account)).show();
        } catch (Exception e) {
            FileLog.e(e);
        }
        return true;
    }

    @Override
    public IUpdateLayout takeUpdateLayout(Activity activity, ViewGroup sideMenuContainer) {
        return new UpdateLayout(activity, sideMenuContainer);
    }
}
"""
VERSION_CODE = "    defaultConfig.versionCode = Integer.parseInt(APP_VERSION_CODE)\n"
# FileProvider of the install and NestedScrollView of the sheet: the library
# keeps androidx.core to itself (implementation), so the app names it too, at
# the library's version, as the standalone module does.
ANDROIDX_CORE = "    implementation 'androidx.core:core:1.16.0'\n"
APP_DEPENDENCY = "    implementation project(':TMessagesProj')\n"


VERSION_NAME = "        versionName APP_VERSION_NAME\n"


def version_name_line(c):
    return f'        versionName APP_VERSION_NAME + ".{c.build:05d}" // pluma: {c.version_name}, the build number\n'


def version_code_line(build):
    return f"    defaultConfig.versionCode = Integer.parseInt(APP_VERSION_CODE) * 1000 + {build} // pluma: the build number\n"


def self_update(tree, c):
    for rel, old, new in SELF_UPDATE_EDITS:
        tree.replace(rel, old, new)
    tree.replace(APP_LOADER_IMPL, APP_LOADER_IMPL_UPSTREAM, APP_LOADER_IMPL_PLUMA)
    for name, sha in SELF_UPDATE_FILES.items():
        data = (tree.root / STANDALONE_COMPONENTS / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != sha:
            raise PatchError(f"{STANDALONE_COMPONENTS}/{name}: changed upstream (SHA-256); read it again")
        dst = tree.root / APP_COMPONENTS / name
        if dst.exists():
            raise PatchError(f"{APP_COMPONENTS}/{name}: upstream has it now")
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(data)
    tree.replace(APP_BUILD_GRADLE, VERSION_NAME, version_name_line(c))
    tree.replace(APP_BUILD_GRADLE, VERSION_CODE, version_code_line(c.build))
    tree.expect("TMessagesProj/build.gradle", ANDROIDX_CORE)
    tree.replace(APP_BUILD_GRADLE, APP_DEPENDENCY, APP_DEPENDENCY + ANDROIDX_CORE)


def verify_self_update(tree, c):
    for rel, old, new in SELF_UPDATE_EDITS:
        text = tree.read(rel)
        if text.count(new) != 1 or old in text.replace(new, ""):
            raise PatchError(f"{rel}: the self-update edit {new.strip().splitlines()[-1]!r} is not there")
    for rel, count in SELF_UPDATE_USES.items():
        found = tree.read(rel).count(SELF_UPDATE_CALL)
        if found != count:
            raise PatchError(f"{rel}: {found} uses of {SELF_UPDATE_CALL}, expected {count}")
    if tree.read(APP_LOADER_IMPL) != APP_LOADER_IMPL_PLUMA:
        raise PatchError(f"{APP_LOADER_IMPL}: not the self-updating loader")
    for name, sha in SELF_UPDATE_FILES.items():
        if hashlib.sha256((tree.root / APP_COMPONENTS / name).read_bytes()).hexdigest() != sha:
            raise PatchError(f"{APP_COMPONENTS}/{name}: not the standalone module's file")
    if tree.read(APP_BUILD_GRADLE).count(version_name_line(c)) != 1 or VERSION_NAME in tree.read(APP_BUILD_GRADLE):
        raise PatchError(f"{APP_BUILD_GRADLE}: versionName is not {c.version_name}")
    if tree.read(APP_BUILD_GRADLE).count(version_code_line(c.build)) != 1:
        raise PatchError(f"{APP_BUILD_GRADLE}: the versionCode of build {c.build} is not there")
    if tree.read(APP_BUILD_GRADLE).count(APP_DEPENDENCY + ANDROIDX_CORE) != 1:
        raise PatchError(f"{APP_BUILD_GRADLE}: androidx.core is not a dependency")


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
    ("    private class ScanQRCodeView extends FrameLayout implements Theme.Colorable, NotificationCenter.NotificationCenterDelegate {\n"
     "\n"
     "        BackupImageView imageView;\n",
     "    private class ScanQRCodeView extends FrameLayout implements Theme.Colorable {\n"
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
     "            NotificationCenter.getInstance(currentAccount).addWeakObserver(this, NotificationCenter.diceStickersDidLoad);\n"
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
     "    \n"
     "        private int lastButtonColor, lastButtonPressedColor;\n",
     "\n"
     "        private int lastButtonColor, lastButtonPressedColor;\n", 1),
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
     '        markDrawable = new RLottieDrawable(R.raw.pluma_mark_write, markSize, markSize, false, null);\n'
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
    'new RLottieDrawable(R.raw.pluma_mark_write, markSize, markSize,',
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
# The two characters \n of a line break in the text end the word before it,
# though its "n" is a letter to the lookbehind.
TELEGRAM_WORD = re.compile(r"(?:(?<![A-Za-z0-9@/.])|(?<=\\n))(Telegram|TELEGRAM)(?![A-Za-z0-9]|\.\w)")
ELEMENT_TEXT = re.compile(r">[^<]*<")
STRING_RENAMES = {
    "values": (534, 1),
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
    ("ui/LoginActivity.java", "But Telegram says it's", "But Pluma says it's", 2),
    ("ui/SessionsActivity.java", 'session.app_name = "Telegram Android";', 'session.app_name = "Pluma Android";', 1),
    ("ui/ThemePreviewActivity.java", '"Telegram Beta Chat"', '"Pluma Beta Chat"', 1),
)
# The name in Java literals that stays, per file under JAVA: directories on the
# device's storage, the mini app API and the user agent, none of them read by
# the user. A new literal with the name stops the build until it is read and
# put either in JAVA_NAMES or here.
JAVA_NAMES_KEEP = {
    "messenger/AndroidUtilities.java": 1,
    "messenger/FilesMigrationService.java": 3,
    "messenger/ImageLoader.java": 12,
    "messenger/MediaController.java": 11,
    "messenger/SharedConfig.java": 3,
    "ui/Components/ChatAttachAlertDocumentLayout.java": 2,
    "ui/bots/BotSensors.java": 4,
    "ui/web/BotWebViewContainer.java": 4,
}
JAVA_NAME_LITERAL = re.compile(r'"[^"\n]*(?:\b|(?<=\\n))Telegram\b[^"\n]*"')
# Lines with a literal naming telegram.org that stay, per file under JAVA:
# Telegram's own pages behind services Pluma does not have, the sender of
# Telegram's login letters and internal base URIs. A new one stops the build
# until it is read and either rebranded or put here.
TELEGRAM_SITE_KEEP = {
    "messenger/AppGlobalConfig.java": 1,
    "messenger/MessagesController.java": 1,
    "messenger/browser/Browser.java": 3,
    "ui/ArticleViewer.java": 1,
    "ui/Cells/ThemePreviewMessagesCell.java": 2,
    "ui/ChatActivity.java": 3,
    "ui/Components/EmbedBottomSheet.java": 3,
    "ui/Components/PhotoViewerWebView.java": 2,
    "ui/IdenticonActivity.java": 1,
    "ui/LaunchActivity.java": 18,
    "ui/LoginActivity.java": 2,
    "ui/PassportActivity.java": 2,
    "ui/ReportBottomSheet.java": 9,
    "ui/ThemePreviewActivity.java": 1,
    "ui/Wallet/GramWalletTonConnect.java": 2,
    "ui/WearAuthSheet.java": 1,
    "ui/WebviewActivity.java": 1,
    "utils/proxy/ProxySettings.java": 1,
}
# The download link every invitation carries: an SMS from the New Contact
# sheet always, and getInviteText until help.getInviteText answers, which the
# server does not serve.
INVITE_LINK_FILES = ("messenger/ContactsController.java", "ui/NewContactBottomSheet.java")
TELEGRAM_SITE_LITERAL = re.compile(r'"[^"\n]*telegram\.org[^"\n]*"')
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
    "messenger/AndroidUtilities.java": (1, 0),
    "messenger/MusicPlayerService.java": (2, 0),
    "messenger/NotificationsController.java": (1, 0),
    "messenger/browser/Browser.java": (3, 1),
    "ui/Business/BusinessLinksController.java": (1, 0),
    "ui/CameraScanActivity.java": (1, 0),
    "ui/QrShare/QrScanOverlay.java": (1, 0),
    "ui/Cells/ChatMessageBotButtons.java": (2, 1),
    "ui/ChatActivity.java": (13, 0),
    "ui/Components/Premium/boosts/GiftInfoBottomSheet.java": (2, 1),
    "ui/Components/Premium/boosts/UserSelectorBottomSheet.java": (2, 1),
    "ui/Components/UndoView.java": (3, 0),
    "ui/LaunchActivity.java": (158, 2),
    "ui/LinkManager.java": (3, 2),
    "ui/LoginActivity.java": (1, 0),
    "ui/PaymentFormActivity.java": (0, 1),
    "ui/ProfileActivity.java": (75, 0),
    "ui/SessionsActivity.java": (1, 0),
    "ui/WebviewActivity.java": (2, 1),
    "utils/proxy/ProxySettings.java": (7, 1),
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
# The one regular expression with the scheme, which SCHEME_LITERAL cannot see.
SCHEME_REGEX = ("ui/LinkManager.java", '"(?i)^tg:(//)?sendgrams&"', '"(?i)^plm:(//)?sendgrams&"')

# Links: pluma.chat is to Pluma what t.me is to Telegram (task 026 of the
# server repository). The server makes its links with pluma.chat (invites,
# boosts, me_url_prefix of the config, which the app keeps as linkPrefix), and
# the app takes pluma.chat links as its own, as it takes t.me, telegram.me and
# telegram.dog, which stay. Only the exact host: x.pluma.chat is not a
# username, as x.t.me is (PREFIX_T_ME_PATTERN), because web.pluma.chat and the
# like are sites. Exact edits, each with its number of occurrences.
LINK_HOST = "pluma.chat"
# The site's own addresses, by the first segment of the path: its pages and
# files, which look like links to a username. With the root they open in the
# browser, never in the app. Every client keeps the same list.
LINK_SITE_PATHS = (
    "iphone", "ipad", "android", "mac", "windows", "linux", "web", "pero", "app", "en", "dl", "ios",
    "collect", "assets", "_l", ".well-known",
    "favicon.svg", "og.png", "apple-touch-icon.png", "404.html", "progress.json",
)
# The paths of pluma.chat the system hands to the app: those of the links the
# server and the app make and the app opens (LaunchActivity.handleIntent), and
# a username of 5 to 32 characters with whatever follows it. The patterns are
# pathAdvancedPattern, which Android 12 (API 31) and later read; earlier ones
# skip the attribute and hand the app only the prefixed links, since a
# pathPattern there, which has no character classes, would take every path of
# 5 characters or more, the site's pages among them.
LINK_PATH_PREFIXES = (
    "/+", "/joinchat/", "/addstickers/", "/addemoji/", "/addlist/", "/folder/", "/c/", "/s/", "/m/", "/call/",
    "/boost", "/proxy", "/socks", "/webproxy", "/setlanguage/", "/addtheme/", "/bg/", "/login/", "/contact/", "/share",
)
LINK_USERNAME_PATTERNS = ("/[A-Za-z][A-Za-z0-9_]{4,31}", "/[A-Za-z][A-Za-z0-9_]{4,31}/.*")
# Browser.java: the list, the checks the edits below call, and the browser a
# page of the site goes to by name.
PLUMA_SITE_JAVA = (
    "    // pluma: the pages and files of the site pluma.chat, by the first segment of the path. Their\n"
    "    // addresses look like links to a username; they and the root open in the browser, as t.me/iv does.\n"
    "    public static final java.util.Set<String> PLUMA_SITE_PATHS = new java.util.HashSet<>(java.util.Arrays.asList(\n"
    + "".join(f"        {', '.join(chr(34) + p + chr(34) for p in LINK_SITE_PATHS[i:i + 8])}"
              f"{',' if i + 8 < len(LINK_SITE_PATHS) else ''}\n" for i in range(0, len(LINK_SITE_PATHS), 8))
    + "    ));\n"
    "\n"
    "    // pluma: whether a path of pluma.chat, with or without its leading slash, query and fragment, is\n"
    "    // the root or a page of the site.\n"
    "    public static boolean isPlumaSitePath(String path) {\n"
    "        if (path == null) return true;\n"
    "        if (path.startsWith(\"/\")) path = path.substring(1);\n"
    "        int end = path.length();\n"
    "        for (char c : new char[] {'/', '?', '#'}) {\n"
    "            final int i = path.indexOf(c);\n"
    "            if (i >= 0 && i < end) end = i;\n"
    "        }\n"
    "        final String first = path.substring(0, end);\n"
    "        return first.isEmpty() || PLUMA_SITE_PATHS.contains(first.toLowerCase(java.util.Locale.ROOT));\n"
    "    }\n"
    "\n"
    "    // pluma: whether a link is the root or a page of the site pluma.chat.\n"
    "    public static boolean isPlumaSite(Uri uri) {\n"
    "        if (uri == null) return false;\n"
    "        final String scheme = uri.getScheme();\n"
    "        if (!\"http\".equalsIgnoreCase(scheme) && !\"https\".equalsIgnoreCase(scheme)) return false;\n"
    "        return \"pluma.chat\".equalsIgnoreCase(uri.getHost()) && isPlumaSitePath(uri.getPath());\n"
    "    }\n"
    "\n"
    "    // pluma: the username of a link to pluma.chat without its host, or null for a page of the site.\n"
    "    private static String plumaUsername(String path) {\n"
    "        return isPlumaSitePath(path) ? null : path;\n"
    "    }\n"
    "\n"
    "    // pluma: the browser that shows a page of pluma.chat: the default one, or else the first, never\n"
    "    // this app. The app is the verified handler of some of the site's addresses, so an intent left to\n"
    "    // the system could come back here. Null when there is none, and the system chooses.\n"
    "    private static String plumaSiteBrowser(Context context) {\n"
    "        try {\n"
    "            final android.content.pm.PackageManager pm = context.getPackageManager();\n"
    "            final Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(\"https://example.com/\"));\n"
    "            intent.addCategory(Intent.CATEGORY_BROWSABLE);\n"
    "            final ResolveInfo preferred = pm.resolveActivity(intent, android.content.pm.PackageManager.MATCH_DEFAULT_ONLY);\n"
    "            final String preferredPackage = preferred != null && preferred.activityInfo != null ? preferred.activityInfo.packageName : null;\n"
    "            String first = null;\n"
    "            for (ResolveInfo info : pm.queryIntentActivities(intent, android.content.pm.PackageManager.MATCH_DEFAULT_ONLY)) {\n"
    "                final String name = info.activityInfo.packageName;\n"
    "                if (name.equals(context.getPackageName())) continue;\n"
    "                if (name.equals(preferredPackage)) return name;\n"
    "                if (first == null) first = name;\n"
    "            }\n"
    "            return first;\n"
    "        } catch (Exception e) {\n"
    "            FileLog.e(e);\n"
    "        }\n"
    "        return null;\n"
    "    }\n"
    "\n"
)
LINKS_EDITS = (
    # Before the first config arrives the app makes its links with this.
    (f"{JAVA}/messenger/MessagesController.java",
     'linkPrefix = mainPreferences.getString("linkPrefix", "t.me");',
     'linkPrefix = mainPreferences.getString("linkPrefix", "pluma.chat");', 1),
    # The http(s) branch of handleIntent (system intents and Browser.openUrl),
    # LinkManager, and proxy links.
    (f"{JAVA}/ui/LaunchActivity.java",
     'host.equals("t.me") || host.equals("telegram.dog") || isPrefix',
     'host.equals("t.me") || host.equals("telegram.dog") || host.equals("pluma.chat") || isPrefix', 1),
    (f"{JAVA}/ui/LinkManager.java",
     'host.equals("t.me") || host.equals("telegram.dog") || isPrefix',
     'host.equals("t.me") || host.equals("telegram.dog") || host.equals("pluma.chat") || isPrefix', 1),
    (f"{JAVA}/ui/LinkManager.java",
     '!"telegram.dog".equalsIgnoreCase(host) && !isPrefix',
     '!"telegram.dog".equalsIgnoreCase(host) && !"pluma.chat".equalsIgnoreCase(host) && !isPrefix', 1),
    (f"{JAVA}/utils/proxy/ProxySettings.java",
     'if (!host.equals("telegram.me") && !host.equals("t.me") && !host.equals("telegram.dog")) {',
     'if (!host.equals("telegram.me") && !host.equals("t.me") && !host.equals("telegram.dog") && !host.equals("pluma.chat")) {',
     1),
    # In the app or in the browser: every tapped link asks isInternalUri.
    (f"{JAVA}/messenger/browser/Browser.java",
     '} else if ("telegram.me".equals(host) || "t.me".equals(host)) {',
     '} else if ("telegram.me".equals(host) || "t.me".equals(host) || "pluma.chat".equals(host)) {', 1),
    # The username of a scanned QR code (QrActivity, NewContactBottomSheet)
    # and of a pasted link (ChatActivity, PeerStoriesView).
    (f"{JAVA}/messenger/browser/Browser.java",
     '        if (link.startsWith("https://t.me/")) {\n'
     '            return link.substring(13);\n'
     '        }\n',
     '        if (link.startsWith("https://t.me/")) {\n'
     '            return link.substring(13);\n'
     '        }\n'
     '        if (link.startsWith("pluma.chat/")) {\n'
     '            return plumaUsername(link.substring(11));\n'
     '        }\n'
     '        if (link.startsWith("http://pluma.chat/")) {\n'
     '            return plumaUsername(link.substring(18));\n'
     '        }\n'
     '        if (link.startsWith("https://pluma.chat/")) {\n'
     '            return plumaUsername(link.substring(19));\n'
     '        }\n', 1),
    # The pages of the site (LINK_SITE_PATHS) open in the browser, as t.me/iv
    # and t.me/s/: isInternalUri sends them there (forceBrowser), the app
    # never offers them to another app, which on Android 11 and later could be
    # Pluma itself through its verified links, and they go to a browser by
    # name, never to whatever the system resolves (plumaSiteBrowser).
    (f"{JAVA}/messenger/browser/Browser.java",
     '                if (path.equals("iv") || path.startsWith("s/")) {\n',
     '                if (path.equals("iv") || path.startsWith("s/") || "pluma.chat".equals(host) && isPlumaSitePath(path)) {\n',
     1),
    (f"{JAVA}/messenger/browser/Browser.java",
     '            if (isTonsite(url) || isInternalUrl(url, null)) return false;\n',
     '            // pluma: a page of pluma.chat is no other app\'s, and the system could hand it back to this one.\n'
     '            if (isTonsite(url) || isInternalUrl(url, null) || isPlumaSite(Uri.parse(url))) return false;\n', 1),
    (f"{JAVA}/messenger/browser/Browser.java",
     '                    CustomTabsIntent intent = builder.build();\n',
     '                    CustomTabsIntent intent = builder.build();\n'
     '                    // pluma: without a bound session the tab is left to the system, which hands some pages of\n'
     '                    // pluma.chat to this app; it goes to a browser by name instead.\n'
     '                    if (intent.intent.getPackage() == null && isPlumaSite(uri)) {\n'
     '                        intent.intent.setPackage(plumaSiteBrowser(context));\n'
     '                    }\n', 1),
    (f"{JAVA}/messenger/browser/Browser.java",
     '            if (!TextUtils.isEmpty(browser)) {\n'
     '                intent.setPackage(browser);\n'
     '            }\n',
     '            if (!TextUtils.isEmpty(browser)) {\n'
     '                intent.setPackage(browser);\n'
     '            } else if (!isIntentScheme && isPlumaSite(uri)) {\n'
     '                // pluma: a page of pluma.chat goes to a browser by name, not back to this app.\n'
     '                intent.setPackage(plumaSiteBrowser(context));\n'
     '            }\n', 1),
    (f"{JAVA}/messenger/browser/Browser.java",
     '    public static String getBrowserPackageName(String browser) {\n',
     PLUMA_SITE_JAVA + '    public static String getBrowserPackageName(String browser) {\n', 1),
    # A page of the site that reaches the app from another one (a site word
    # that looks like a username matches the manifest's username pattern)
    # opens in the browser.
    (f"{JAVA}/ui/LaunchActivity.java",
     '                    final LinkManager linkManager = new LinkManager(this, intentAccount[0], progress, openedTelegram);\n',
     '                    // pluma: a page of pluma.chat, handed to the app because its address looks like a\n'
     '                    // username link, is shown by the browser.\n'
     '                    if (Browser.isPlumaSite(data)) {\n'
     '                        Browser.openInExternalBrowser(this, data.toString(), false);\n'
     '                        intent.setAction(null);\n'
     '                        if (progress != null) {\n'
     '                            progress.end();\n'
     '                        }\n'
     '                        return false;\n'
     '                    }\n'
     '                    final LinkManager linkManager = new LinkManager(this, intentAccount[0], progress, openedTelegram);\n',
     1),
    # A bot button with a page of the site is no mini app link.
    (f"{JAVA}/ui/LinkManager.java",
     '    public static boolean isWebAppLink(String url) {\n'
     '        if (url == null) return false;\n'
     '        try {\n'
     '            Uri uri = Uri.parse(url);\n',
     '    public static boolean isWebAppLink(String url) {\n'
     '        if (url == null) return false;\n'
     '        try {\n'
     '            Uri uri = Uri.parse(url);\n'
     '            // pluma: a page of pluma.chat is no mini app.\n'
     '            if (Browser.isPlumaSite(uri)) return false;\n', 1),
    # The browsers plumaSiteBrowser chooses from, which package visibility
    # (Android 11 and later) hides otherwise.
    (f"{MAIN}/AndroidManifest.xml",
     '            <data android:scheme="ton"/>\n'
     '        </intent>\n',
     '            <data android:scheme="ton"/>\n'
     '        </intent>\n'
     '        <!-- pluma: the browsers that show the pages of pluma.chat (Browser.plumaSiteBrowser) -->\n'
     '        <intent>\n'
     '            <action android:name="android.intent.action.VIEW"/>\n'
     '            <category android:name="android.intent.category.BROWSABLE"/>\n'
     '            <data android:scheme="https"/>\n'
     '        </intent>\n', 1),
    # A bot's "add to group" button.
    (f"{JAVA}/ui/Cells/ChatMessageBotButtons.java",
     '|| "telegram.dog".equals(host)) ||',
     '|| "telegram.dog".equals(host) || "pluma.chat".equals(host)) ||', 1),
    # An embedded post a mini app opens stays in its web view.
    (f"{JAVA}/ui/web/BotWebViewContainer.java",
     '"1".equals(uriNew.getQueryParameter("embed")) && "t.me".equals(uriNew.getAuthority())',
     '"1".equals(uriNew.getQueryParameter("embed")) && ("t.me".equals(uriNew.getAuthority()) || '
     '"pluma.chat".equals(uriNew.getAuthority()))', 1),
    # The "add stickers" button of a set's link preview, and the links to a
    # message of the open chat, which scroll to it instead of opening the chat
    # again.
    (f"{JAVA}/ui/ChatActivity.java",
     r'Pattern.compile("^https?\\:\\/\\/t\\.me\\/add(?:emoji|stickers)\\/(.+)$");',
     r'Pattern.compile("^https?\\:\\/\\/(?:t\\.me|pluma\\.chat)\\/add(?:emoji|stickers)\\/(.+)$");', 1),
    (f"{JAVA}/ui/ChatActivity.java",
     'Pattern.compile("(https://)?t.me/([0-9a-zA-Z_]+)/([0-9]+)/?([0-9]+)?");',
     r'Pattern.compile("(https://)?(?:t.me|pluma\\.chat)/([0-9a-zA-Z_]+)/([0-9]+)/?([0-9]+)?");', 1),
    (f"{JAVA}/ui/ChatActivity.java",
     r'Pattern.compile("(https://)?t.me/([0-9a-zA-Z_]+)\\?(voicechat+)");',
     r'Pattern.compile("(https://)?(?:t.me|pluma\\.chat)/([0-9a-zA-Z_]+)\\?(voicechat+)");', 1),
    (f"{JAVA}/ui/ChatActivity.java",
     'Pattern.compile("(https://)?t.me/c/([0-9]+)/([0-9]+)/?([0-9]+)?");',
     r'Pattern.compile("(https://)?(?:t.me|pluma\\.chat)/c/([0-9]+)/([0-9]+)/?([0-9]+)?");', 1),
    # A link of the account's own business chat (links the server makes).
    (f"{JAVA}/ui/Business/BusinessLinksController.java",
     '                    TextUtils.equals(chatLink.link, "https://t.me/m/" + slug) ||\n',
     '                    TextUtils.equals(chatLink.link, "https://t.me/m/" + slug) ||\n'
     '                    TextUtils.equals(chatLink.link, "https://pluma.chat/m/" + slug) ||\n', 1),
    # A translated mention, which comes back as a link to the username.
    (f"{JAVA}/ui/Components/TranslateAlert2.java",
     '                    entity.url.startsWith("https://t.me/") &&\n'
     '                    text.startsWith("@") &&\n'
     '                    TextUtils.equals(text.substring(1), entity.url.substring(13))\n',
     '                    (entity.url.startsWith("https://t.me/") || entity.url.startsWith("https://pluma.chat/")) &&\n'
     '                    text.startsWith("@") &&\n'
     "                    TextUtils.equals(text.substring(1), entity.url.substring(entity.url.indexOf('/', 8) + 1))\n",
     1),
    # The system hands the app pluma.chat links, as t.me ones, but only those
    # of links (LINK_PATH_PREFIXES, LINK_USERNAME_PATTERNS), never the site's
    # root or pages; once the site's /.well-known/assetlinks.json names the
    # app and its signing certificate, it opens them in the app without
    # asking. pluma.chat is in no filter without a path: the system verifies
    # a host for all the filters that name it, so one such entry would claim
    # the whole site.
    (f"{MAIN}/AndroidManifest.xml",
     '                <data android:host="t.me" android:scheme="https" />\n'
     '            </intent-filter>\n',
     '                <data android:host="t.me" android:scheme="https" />\n'
     '            </intent-filter>\n'
     '            <!-- pluma: verified app links of pluma.chat, the links and not the site\'s pages -->\n'
     '            <intent-filter android:autoVerify="true">\n'
     '                <action android:name="android.intent.action.VIEW"/>\n'
     '                <category android:name="android.intent.category.DEFAULT" />\n'
     '                <category android:name="android.intent.category.BROWSABLE" />\n'
     '                <data android:host="pluma.chat" android:scheme="http" />\n'
     '                <data android:host="pluma.chat" android:scheme="https" />\n'
     + "".join(f'                <data android:pathPrefix="{p}" />\n' for p in LINK_PATH_PREFIXES)
     + "".join(f'                <data android:pathAdvancedPattern="{p}" />\n' for p in LINK_USERNAME_PATTERNS)
     + '            </intent-filter>\n', 1),
)
# The links the app makes itself, for the user to copy, share, show as a QR
# code or read: message links with a timestamp, public and invite links of
# chats (and the invite link's title, which drops the address), the phone
# number link, boost, story and conference call links, proxy links, the
# connected chatbots named when all other sessions are terminated (Settings >
# Devices), and the address prefixes shown
# before a sticker set's or a bot's name. Per file under JAVA, the number of
# "https://t.me/ and of "t.me/ literals, which become pluma.chat.
LINKS_OUT = {
    "messenger/voip/VoIPService.java": (1, 0),
    "ui/Cells/StickerSetCell.java": (0, 2),
    "ui/ChatActivity.java": (4, 0),
    "ui/ChatEditActivity.java": (0, 1),
    "ui/Components/PermanentLinkBottomSheet.java": (1, 0),
    "ui/Components/StickersAlert.java": (0, 1),
    "ui/FilterChatlistActivity.java": (0, 1),
    "ui/GroupStickersActivity.java": (0, 1),
    "ui/ManageLinksActivity.java": (5, 0),
    "ui/PhotoViewer.java": (2, 0),
    "ui/PrivacyControlActivity.java": (1, 0),
    "ui/ProxySettingsActivity.java": (2, 0),
    "ui/SessionsActivity.java": (1, 0),
    "ui/Stories/ChannelBoostUtilities.java": (2, 0),
    "ui/Stories/PeerStoriesView.java": (4, 0),
    "utils/proxy/ProxySettings.java": (3, 0),
}
# The t.me literals that stay, per file under JAVA:
# - links the app turns back into t.me to open them itself (x.t.me, @username,
#   a mini app's openTgLink, a bot in the chat list) and the t.me forms it still
#   recognises next to pluma.chat (extractUsername, a pasted proxy link, a
#   business chat link, a translated mention);
# - Telegram's own services, which Pluma does not have: Premium and its bot,
#   gift codes, Stars, collectible gifts, BotFather, @stickers, AI styles, the
#   appeal bot of a frozen account, the "+PublicChat" marker of the admin log
#   and instant view (t.me/iv);
# - two commented-out lines of SecretMediaViewer.
LINKS_KEEP = {
    "messenger/MessageObject.java": 1,
    "messenger/MessagesController.java": 3,
    "messenger/browser/Browser.java": 4,
    "ui/Business/BusinessLinksController.java": 1,
    "ui/ChannelAdminLogActivity.java": 1,
    "ui/ChatActivity.java": 1,
    "ui/ChatEditActivity.java": 4,
    "ui/Components/AIEditorAlert.java": 1,
    "ui/Components/CreateBotAlert.java": 1,
    "ui/Components/DialogsBotsAdapter.java": 1,
    "ui/Components/Premium/boosts/PremiumPreviewGiftLinkBottomSheet.java": 1,
    "ui/Components/Premium/boosts/adapters/GiftInfoAdapter.java": 1,
    "ui/Components/Premium/boosts/cells/LinkCell.java": 3,
    "ui/Components/Reactions/ChatCustomReactionsEditActivity.java": 1,
    "ui/Components/TranslateAlert2.java": 1,
    "ui/Components/URLSpanNoUnderline.java": 1,
    "ui/LaunchActivity.java": 1,
    "ui/LinkManager.java": 1,
    "ui/PremiumPreviewFragment.java": 2,
    "ui/SecretMediaViewer.java": 2,
    "ui/Stars/ProfileGiftsView.java": 1,
    "ui/Stars/StarsIntroActivity.java": 1,
    "ui/web/BotWebViewContainer.java": 1,
}
LINK_LITERAL = re.compile(r'"(?:https?://)?t\.me/')
# Lines that name t.me, telegram.me or telegram.dog as a host and not
# pluma.chat, per file under JAVA: the telegram.dog branch of isInternalUri
# (Telegram's blog and FAQ), the gift code and payment checks and the links
# of the wallet (closed by wallet_available, which the server does not send).
HOSTS_KEEP = {
    "messenger/browser/Browser.java": 1,
    "ui/Components/Premium/GiftPremiumBottomSheet.java": 1,
    "ui/Components/Premium/boosts/GiftInfoBottomSheet.java": 1,
    "ui/Components/Premium/boosts/UserSelectorBottomSheet.java": 1,
    "ui/Gifts/SendGiftSheet.java": 1,
    "ui/PaymentFormActivity.java": 2,
    "ui/PremiumPreviewFragment.java": 1,
    "ui/Wallet/WalletActivity.java": 1,
}
HOST_LITERAL = re.compile(r'"(?:t\.me|telegram\.me|telegram\.dog)"')
# Built-in texts with a t.me address: the one about public links of the empty
# group screen (English only, no bundled translation has it) becomes
# pluma.chat; the others are Telegram's (feature tips, Cocoon, the Premium
# limits sheet) and stay.
LINK_STRINGS = (
    ("GroupDescription3", "Public links such as t.me/title", "Public links such as pluma.chat/title", ("values",)),
)
LINK_STRINGS_KEEP = {"TelegramFeaturesUrl", "PublicLinksLimitSubtitle", "CocoonFeature1TextLink", "CocoonFooter",
                     "CocoonFooterLink"}
STRING_ELEMENT = re.compile(r'<string name="(\w+)">([^<]*)</string>')
TME_IN_TEXT = re.compile(r"(?<![\w.])t\.me/")

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
    brand_invite_link(tree)
    brand_scheme(tree)
    brand_assets(tree)
    brand_devices(tree)
    brand_intro(tree)
    brand_theme(tree)


def brand_entry_points(tree):
    # Settings: no Help section (NOT_SERVED_EDITS), and with it no shadow left
    # at the end of the list.
    settings = f"{JAVA}/ui/SettingsActivity.java"
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


def brand_invite_link(tree):
    for rel in INVITE_LINK_FILES:
        tree.replace(f"{JAVA}/{rel}", '"https://telegram.org/dl"', '"https://pluma.chat/"')


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
    tree.replace(f"{JAVA}/{SCHEME_REGEX[0]}", SCHEME_REGEX[1], SCHEME_REGEX[2])
    # Links in message text.
    tree.replace(f"{JAVA}/messenger/AndroidUtilities.java", "|ton|tg|tonsite):", "|ton|plm|tonsite):")
    tree.replace(f"{JAVA}/messenger/LinkifyPort.java", "|ton|tg|tonsite)://", "|ton|plm|tonsite)://")
    # The system hands plm:// links to the app, and no longer tg:// ones.
    tree.replace(f"{MAIN}/AndroidManifest.xml", '<data android:scheme="tg" />', '<data android:scheme="plm" />')
    tree.replace(f"{RES}/xml/shortcuts.xml", 'android:value="tg://', 'android:value="plm://', count=6)


def links(tree):
    for rel, old, new, count in LINKS_EDITS:
        tree.replace(rel, old, new, count)
    for rel, counts in LINKS_OUT.items():
        # A file may keep literals of the other form (t.me/iv of ChatActivity).
        for old, count in zip(('"https://t.me/', '"t.me/'), counts):
            if count:
                tree.replace(f"{JAVA}/{rel}", old, old.replace("t.me", LINK_HOST), count)
    files = {p.parent.name: str(p.relative_to(tree.root)) for p in sorted((tree.root / RES).glob("values*/strings.xml"))}
    for key, old, new, langs in LINK_STRINGS:
        have = {lang for lang, rel in files.items() if f'<string name="{key}">' in tree.read(rel)}
        if have != set(langs):
            raise PatchError(f"{RES}: {key} in {', '.join(sorted(have))}, expected {', '.join(sorted(langs))}; "
                             "upstream changed it")
        for lang in langs:
            tree.write(files[lang], edit_string(tree.read(files[lang]), files[lang], key, old, new))


def verify_links(tree):
    """Checks that the app makes no t.me link of its own and takes pluma.chat
    wherever it takes t.me."""
    for rel, old, new, count in LINKS_EDITS:
        if tree.read(rel).count(new) != count:
            changed = next(line for line in new.splitlines() if line not in old.splitlines())
            raise PatchError(f"{rel}: the link edit {changed.strip()!r} is not there")
    literals, hosts = {}, {}
    for p in sorted((tree.root / JAVA).rglob("*.java")):
        text = p.read_text(encoding="utf-8")
        rel = p.relative_to(tree.root / JAVA).as_posix()
        n = len(LINK_LITERAL.findall(text))
        if n:
            literals[rel] = n
        n = sum(1 for line in text.splitlines() if HOST_LITERAL.search(line) and LINK_HOST not in line)
        if n:
            hosts[rel] = n
    if literals != LINKS_KEEP:
        raise PatchError(f"t.me links left in {literals}, expected only {LINKS_KEEP}")
    if hosts != HOSTS_KEEP:
        raise PatchError(f"t.me host checks without {LINK_HOST} in {hosts}, expected only {HOSTS_KEEP}")
    for p in sorted((tree.root / RES).glob("values*/strings.xml")):
        for key, text in STRING_ELEMENT.findall(p.read_text(encoding="utf-8")):
            if TME_IN_TEXT.search(text) and key not in LINK_STRINGS_KEEP:
                raise PatchError(f"{p.relative_to(tree.root)}: {key} still shows t.me: {text[:80]!r}")


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
        # The strings of task 076 name the real Telegram (verify_login_screens).
        xml = LOGIN_STRING_LINE.sub("", p.read_text(encoding="utf-8"))
        for m in ELEMENT_TEXT.finditer(xml):
            left = (TELEGRAM_WORD.search(m.group(0)) or re.search("|".join(LOCAL_NAMES), m.group(0))
                    or CLIENT_SITES.search(m.group(0)))
            if left:
                raise PatchError(f"{p.relative_to(tree.root)}: {left.group(0)!r} is still in {m.group(0)[:80]!r}")
    sessions = tree.read(SESSIONS)
    if sessions.count("R.raw.pluma_devices") != 1 or "STICKERS_PLACEHOLDER_PACK_NAME" in sessions:
        raise PatchError(f"{SESSIONS}: Settings > Devices does not play the bundled animation")
    verify_intro(tree)
    found, names, sites = {}, {}, {}
    for p in sorted((tree.root / JAVA).rglob("*.java")):
        text = p.read_text(encoding="utf-8")
        rel = p.relative_to(tree.root / JAVA).as_posix()
        if rel == LOGIN_JAVA:
            # The link of task 076 to the real Telegram (verify_login_screens).
            text = text.replace(LOGIN_TELEGRAM_SETTINGS, "", 1)
        n = len(SCHEME_LITERAL.findall(text))
        if n:
            found[rel] = n
        lines = text.splitlines()
        n = sum(1 for line in lines if JAVA_NAME_LITERAL.search(line))
        if n:
            names[rel] = n
        n = sum(1 for line in lines if TELEGRAM_SITE_LITERAL.search(line))
        if n:
            sites[rel] = n
    if found != SCHEME_KEEP:
        raise PatchError(f"tg: literals left in {found}, expected only the internal ones {SCHEME_KEEP}")
    if names != JAVA_NAMES_KEEP:
        raise PatchError(f"Java literals with the name Telegram in {names}, expected only {JAVA_NAMES_KEEP}")
    if sites != TELEGRAM_SITE_KEEP:
        raise PatchError(f"Java literals with telegram.org in {sites}, expected only {TELEGRAM_SITE_KEEP}")
    if SCHEME_REGEX[1] in tree.read(f"{JAVA}/{SCHEME_REGEX[0]}"):
        raise PatchError(f"{SCHEME_REGEX[0]}: the sendgrams link still has the tg: scheme")
    if 'android:scheme="tg"' in tree.read(f"{MAIN}/AndroidManifest.xml").replace(LOGIN_QUERIES[1], ""):
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
    verify_video_quality(tree)
    verify_birthdays(tree)
    verify_sticker_sets(tree)
    verify_saved_tags(tree)
    verify_premium_stickers(tree)
    verify_premium_for_everyone(tree)
    verify_not_served(tree)
    verify_self_update(tree, c)
    verify_links(tree)
    verify_brand(tree)
    verify_login_screens(tree)



# --- Premium for everyone -----------------------------------------------------
# Task 071 (ADR 0041): every user has Premium and every boost-gated feature is
# open, so the server sends the Premium flag for everybody. Only what the flag
# would make wrong is edited: the star by every name, the purchase rows that
# show for anyone with Premium, and what the server does not serve.
PREMIUM_FOR_EVERYONE_EDITS = (
    ("TMessagesProj/src/main/java/org/telegram/ui/LinkManager.java",
     '        if ("getpremium".equalsIgnoreCase(first))\n            return handleGetPremium(uri.getQueryParameter("ref"));\n',
     '        // pluma: no getpremium route, everybody has Premium (ADR 0041).\n'),
    # The same purchase screen behind the other links.
    ("TMessagesProj/src/main/java/org/telegram/ui/LinkManager.java",
     '        if ("premium".equalsIgnoreCase(first)) {\n            presentFragment(new PremiumPreviewFragment("link"));\n            return true;\n        }\n\n'
     '        if ("business".equalsIgnoreCase(first)) {\n            presentFragment(new PremiumPreviewFragment(PremiumPreviewFragment.FEATURES_BUSINESS, "link"));\n'
     '            if ("do-not-hide-ads".equalsIgnoreCase(second)) {\n                scrollTo("showAdsRow");\n            }\n            return true;\n        }\n\n',
     '        // pluma: no settings/premium and settings/business links: everybody has Premium (ADR 0041).\n\n'),
    ("TMessagesProj/src/main/java/org/telegram/ui/LaunchActivity.java",
     '                                        String finalUrl = url.replace("tg:premium_offer", "tg://premium_offer");\n'
     '                                        AndroidUtilities.runOnUIThread(() -> {\n'
     '                                        if (!actionBarLayout.getFragmentStack().isEmpty()) {\n'
     '                                            BaseFragment fragment = actionBarLayout.getFragmentStack().get(0);\n'
     '                                            Uri uri = Uri.parse(finalUrl);\n'
     '                                            fragment.presentFragment(new PremiumPreviewFragment(uri.getQueryParameter("ref")));\n'
     '                                        }});\n',
     '                                        // pluma: the link opens the app and no offer: everybody has Premium (ADR 0041).\n'),
    # The store behind the empty gifts layer of the QR screen; the layer
    # still shows the gifts a user owns.
    ("TMessagesProj/src/main/java/org/telegram/ui/QrShare/QrShareView.java",
     "    private boolean canBuyGifts() {return giftsOwner > 0;}\n",
     "    private boolean canBuyGifts() {return giftsOwner > 0 && !org.telegram.messenger.MessagesController.getInstance(currentAccount).premiumPurchaseBlocked();} // pluma: Pluma sells no gifts\n"),
    ("TMessagesProj/src/main/java/org/telegram/ui/ProfileActivity.java",
     '            if (MessagesController.getInstance(currentAccount).premiumFeaturesBlocked() && !UserConfig.getInstance(currentAccount).isPremium())\n',
     '            if (MessagesController.getInstance(currentAccount).premiumPurchaseBlocked()) // pluma: the search results are the purchase screen\n'),
    ("TMessagesProj/src/main/java/org/telegram/messenger/MessagesController.java",
     "        return currentUser != null && currentUser.premium && !isSupportUser(currentUser);\n",
     "        // pluma: no star by a name: everybody has Premium (ADR 0041).\n        return false;\n"),
    ("TMessagesProj/src/main/java/org/telegram/messenger/ImageReceiver.java",
     "animationEnabled && MessagesController.getInstance(currentAccount).isPremiumUser(user) && user.photo.has_video",
     "animationEnabled && user.premium && user.photo.has_video"),
    ("TMessagesProj/src/main/java/org/telegram/messenger/ImageLocation.java",
     "            if (MessagesController.getInstance(currentAccount).isPremiumUser(user) && user.photo.has_video) {\n",
     "            if (user.premium && user.photo.has_video) {\n"),
    ("TMessagesProj/src/main/java/org/telegram/ui/SettingsActivity.java",
     "        if (!getMessagesController().premiumFeaturesBlocked()) {\n            items.add(SettingCell.Factory.of(11,",
     "        if (!getMessagesController().premiumPurchaseBlocked()) { // pluma: the row is the purchase\n            items.add(SettingCell.Factory.of(11,"),
    ("TMessagesProj/src/main/java/org/telegram/ui/SettingsActivity.java",
     "        if (!getMessagesController().premiumFeaturesBlocked()) {\n            items.add(SettingCell.Factory.of(15,",
     "        if (!getMessagesController().premiumPurchaseBlocked()) { // pluma: the row is the purchase\n            items.add(SettingCell.Factory.of(15,"),
    ("TMessagesProj/src/main/java/org/telegram/ui/SettingsActivity.java",
     "            } else if (user != null && user.premium) {\n                emojiStatusDrawable.set(getContext().getResources().getDrawable(R.drawable.msg_premium_liststar)",
     "            } else if (false) { // pluma: no star: everybody has Premium\n                emojiStatusDrawable.set(getContext().getResources().getDrawable(R.drawable.msg_premium_liststar)"),
    ("TMessagesProj/src/main/java/org/telegram/ui/ProfileActivity.java",
     "                if (!getMessagesController().premiumFeaturesBlocked()) {\n                    premiumRow = rowCount++;\n",
     "                if (!getMessagesController().premiumPurchaseBlocked()) { // pluma: the row is the purchase\n                    premiumRow = rowCount++;\n"),
    ("TMessagesProj/src/main/java/org/telegram/ui/ProfileActivity.java",
     "                if (!getMessagesController().premiumFeaturesBlocked()) {\n                    businessRow = rowCount++;\n",
     "                if (!getMessagesController().premiumPurchaseBlocked()) { // pluma: the row is the purchase\n                    businessRow = rowCount++;\n"),
    ("TMessagesProj/src/main/java/org/telegram/ui/ChatActivity.java",
     "UserObject.getUserName(user))), user.scam, user.fake, user.verified, user.premium, user.emoji_status, animated);",
     "UserObject.getUserName(user))), user.scam, user.fake, user.verified, false, user.emoji_status, animated); // pluma: no star"),
    ("TMessagesProj/src/main/java/org/telegram/ui/Cells/ChatMessageCell.java",
     "            } else if (currentUser.premium) {\n                return ContextCompat.getDrawable(ApplicationLoader.applicationContext, R.drawable.msg_premium_liststar).mutate();",
     "            } else if (false) { // pluma: no star: everybody has Premium\n                return ContextCompat.getDrawable(ApplicationLoader.applicationContext, R.drawable.msg_premium_liststar).mutate();"),
    ("TMessagesProj/src/main/java/org/telegram/ui/Cells/ChatMessageCell.java",
     "        useTranscribeButton = (\n            currentMessageObject != null &&\n",
     "        // pluma: the server has no transcription to offer.\n        useTranscribeButton = (\n            false && currentMessageObject != null &&\n"),
    ("TMessagesProj/src/main/java/org/telegram/ui/Cells/GroupCallUserCell.java",
     "            } else if (currentUser != null && currentUser.premium) {\n",
     "            } else if (false) { // pluma: no star: everybody has Premium\n"),
    ("TMessagesProj/src/main/java/org/telegram/ui/Components/StatusBadgeComponent.java",
     "        } else if (user != null && user.premium) {\n",
     "        } else if (false) { // pluma: no star: everybody has Premium\n"),
    ("TMessagesProj/src/main/java/org/telegram/ui/Components/TableView.java",
     "                isPremium = user != null && user.premium;\n",
     "                isPremium = false; // pluma: no star: everybody has Premium\n"),
    # Boosts do not exist here: nothing waits for a level of a channel, no
    # screen, prompt or link offers one.
    ("TMessagesProj/src/main/java/org/telegram/ui/Components/Reactions/ChatCustomReactionsEditActivity.java",
     "            if (boostsStatus != null && boostsStatus.level < selectedCustomReactions) {\n                ReactionsUtils.showLimitReachedDialogForReactions(",
     "            if (false && boostsStatus != null && boostsStatus.level < selectedCustomReactions) { // pluma: custom reactions need no boost level\n                ReactionsUtils.showLimitReachedDialogForReactions("),
    ("TMessagesProj/src/main/java/org/telegram/ui/Components/Reactions/ChatCustomReactionsEditActivity.java",
     "        if (boostsStatus != null && boostsStatus.level < selectedCustomReactions) {\n            hasChanges = false;\n",
     "        if (false && boostsStatus != null && boostsStatus.level < selectedCustomReactions) { // pluma: custom reactions need no boost level\n            hasChanges = false;\n"),
    ("TMessagesProj/src/main/java/org/telegram/ui/Components/Reactions/ChatCustomReactionsEditActivity.java",
     "        if (boostsStatus.level < selectedCustomReactions) {\n            if (withToast) {\n",
     "        if (false && boostsStatus.level < selectedCustomReactions) { // pluma: custom reactions need no boost level\n            if (withToast) {\n"),
    ("TMessagesProj/src/main/java/org/telegram/messenger/MessagesController.java",
     "            return isGroup ? groupLvl : channelLvl;\n",
     "            return 0; // pluma: no colour needs a boost level (ADR 0041)\n"),
    ("TMessagesProj/src/main/java/org/telegram/ui/ChannelColorActivity.java",
     "                addView(infoLayout, LayoutHelper.createFrame(LayoutHelper.MATCH_PARENT, LayoutHelper.WRAP_CONTENT, Gravity.BOTTOM));\n",
     "                addView(infoLayout, LayoutHelper.createFrame(LayoutHelper.MATCH_PARENT, LayoutHelper.WRAP_CONTENT, Gravity.BOTTOM));\n                infoLayout.setVisibility(View.GONE); // pluma: boosts do not exist here (ADR 0041)\n"),
    ("TMessagesProj/src/main/java/org/telegram/ui/ChatActivity.java",
     "            if (ChatObject.isBoostSupported(currentChat) && (getUserConfig().isPremium() || ChatObject.isBoosted(chatInfo) || ChatObject.hasAdminRights(currentChat))) {\n",
     "            if (false && ChatObject.isBoostSupported(currentChat) && (getUserConfig().isPremium() || ChatObject.isBoosted(chatInfo) || ChatObject.hasAdminRights(currentChat))) { // pluma: boosts do not exist here (ADR 0041)\n"),
    ("TMessagesProj/src/main/java/org/telegram/ui/TopicsFragment.java",
     "        boostGroupSubmenu.setVisibility(ChatObject.isBoostSupported(chatLocal) && (",
     "        boostGroupSubmenu.setVisibility(false && ChatObject.isBoostSupported(chatLocal) && ("),
    ("TMessagesProj/src/main/java/org/telegram/ui/ChatEditActivity.java",
     "            if (ChatObject.isBoostSupported(currentChat)) {\n                statsAndBoosts = new TextCell(context);\n",
     "            if (false && ChatObject.isBoostSupported(currentChat)) { // pluma: boosts do not exist here (ADR 0041)\n                statsAndBoosts = new TextCell(context);\n"),
    ("TMessagesProj/src/main/java/org/telegram/ui/StatisticActivity.java",
     "        boolean isBoostSupported = ChatObject.isBoostSupported(currentChat);\n",
     "        boolean isBoostSupported = false; // pluma: boosts do not exist here (ADR 0041)\n"),
    ("TMessagesProj/src/main/java/org/telegram/ui/LaunchActivity.java",
     "                            if (ChatObject.isBoostSupported(chat)) {\n                                processBoostDialog(peerId, dismissLoading, progress);\n",
     "                            if (false && ChatObject.isBoostSupported(chat)) { // pluma: a boost link opens the channel\n                                processBoostDialog(peerId, dismissLoading, progress);\n"),
    ("TMessagesProj/src/main/java/org/telegram/ui/LaunchActivity.java",
     "                if (chatLocal != null && ChatObject.isBoostSupported(chatLocal) && isBoost) {\n",
     "                if (false && chatLocal != null && ChatObject.isBoostSupported(chatLocal) && isBoost) { // pluma: a boost link opens the channel\n"),
    ("TMessagesProj/src/main/java/org/telegram/ui/LaunchActivity.java",
     "                                            if (chat != null && isBoost && ChatObject.isBoostSupported(chat)) {\n",
     "                                            if (false && chat != null && isBoost && ChatObject.isBoostSupported(chat)) { // pluma: a boost link opens the channel\n"),
    ("TMessagesProj/src/main/java/org/telegram/ui/ChatUsersActivity.java",
     "        return currentChat.megagroup && !currentChat.gigagroup && ChatObject.canUserDoAdminAction(currentChat,ChatObject.ACTION_DELETE_MESSAGES) &&\n",
     "        return false && currentChat.megagroup && !currentChat.gigagroup && ChatObject.canUserDoAdminAction(currentChat,ChatObject.ACTION_DELETE_MESSAGES) && // pluma: boosts do not exist here (ADR 0041)\n"),
    # Without statistics the item opens the boosts screen (StatisticActivity.create).
    ("TMessagesProj/src/main/java/org/telegram/ui/ProfileActivity.java",
     "                    if ((chatInfo.can_view_stats || chatInfo.can_view_revenue || chatInfo.can_view_stars_revenue || getMessagesController().getStoriesController().canPostStories(getDialogId())) && topicId == 0) {\n",
     "                    if ((chatInfo.can_view_stats || chatInfo.can_view_revenue || chatInfo.can_view_stars_revenue) && topicId == 0) { // pluma: boosts do not exist here (ADR 0041)\n"),
)


def premium_for_everyone(tree):
    for rel, old, new in PREMIUM_FOR_EVERYONE_EDITS:
        tree.replace(rel, old, new)


def verify_premium_for_everyone(tree):
    for rel, old, new in PREMIUM_FOR_EVERYONE_EDITS:
        text = tree.read(rel)
        if text.count(new) != 1 or old in text.replace(new, ""):
            raise PatchError(f"{rel}: the edit of task 071 is not there")

# --- Login codes through Telegram ---------------------------------------------
# Task 076 of the server repository. Pluma's login codes are written by a
# Telegram account to the person's own Telegram. The server answers
# auth.sentCodeTypeFragmentSms (url: the chat with that account) when the
# code went there, and auth.sentCodeTypeSms when it did not: the person's
# Telegram does not let others find them by number, or they did not get it.
# Pluma never sends an SMS. The code page of the app (LoginActivitySmsView)
# shows both: the in-app code page says "Check Telegram", the SMS page says
# that the code did not reach Telegram and how to let Telegram find you. Each
# gets a filled button in the look of the Fragment code's: to the chat, or to
# the "Who can find me by my number?" setting of Telegram (Telegram's
# LaunchActivity opens tg://settings/phone_privacy there). The button shows
# only when Telegram is installed. Telegram's support (sms@telegram.org,
# auth.reportMissingCode) is no longer offered: the administrator issues the
# code.
LOGIN_JAVA = "ui/LoginActivity.java"
LOGIN = f"TMessagesProj/src/main/java/org/telegram/{LOGIN_JAVA}"
LOGIN_TELEGRAM_SETTINGS = '"tg://settings/phone_privacy"'
LOGIN_VIEW = "    public class LoginActivitySmsView "
LOGIN_EDITS = (
    # A code in Telegram: the in-app code page, with the link of the button.
    ("            } else if (res.type instanceof TLRPC.TL_auth_sentCodeTypeFragmentSms) {\n"
     "                params.putInt(\"type\", AUTH_TYPE_FRAGMENT_SMS);\n"
     "                params.putString(\"url\", res.type.url);\n"
     "                params.putInt(\"length\", res.type.length);\n"
     "                setPage(VIEW_CODE_FRAGMENT_SMS, animate, params, false);\n",
     "            } else if (res.type instanceof TLRPC.TL_auth_sentCodeTypeFragmentSms) {\n"
     "                // pluma: a code in the person's own Telegram (task 076): the in-app code page,\n"
     "                // its button opens the chat with the account that wrote it.\n"
     "                params.putInt(\"type\", AUTH_TYPE_MESSAGE);\n"
     "                params.putBoolean(\"plumaTelegram\", true);\n"
     "                params.putString(\"url\", res.type.url);\n"
     "                params.putInt(\"length\", res.type.length);\n"
     "                setPage(VIEW_CODE_MESSAGE, animate, params, false);\n"),
)
# Edits inside LoginActivitySmsView: the same lines are in other views of the
# file.
LOGIN_VIEW_EDITS = (
    ("        private LinearLayout openFragmentButton;\n",
     "        private LinearLayout openFragmentButton;\n"
     "        private TextView plumaTelegramButton; // pluma: task 076\n"
     "        private boolean plumaTelegram;\n"),
    # The button over the "Didn't get the code?" link, above the bottom.
    ("                bottomContainer.addView(errorViewSwitcher, LayoutHelper.createFrame(currentType == VIEW_CODE_FRAGMENT_SMS ? LayoutHelper.MATCH_PARENT : LayoutHelper.WRAP_CONTENT, LayoutHelper.WRAP_CONTENT, Gravity.CENTER_HORIZONTAL | Gravity.BOTTOM, 0, 0, 0, 32));\n",
     "                if (currentType == AUTH_TYPE_MESSAGE || currentType == AUTH_TYPE_SMS) {\n"
     "                    // pluma: the code goes through Telegram: a button to it, in the look of the\n"
     "                    // Fragment code's (task 076).\n"
     "                    LinearLayout plumaColumn = new LinearLayout(context);\n"
     "                    plumaColumn.setOrientation(VERTICAL);\n"
     "                    plumaColumn.setGravity(Gravity.CENTER_HORIZONTAL);\n"
     "                    plumaTelegramButton = new TextView(context);\n"
     "                    plumaTelegramButton.setTextColor(Color.WHITE);\n"
     "                    plumaTelegramButton.setTextSize(TypedValue.COMPLEX_UNIT_DIP, 15);\n"
     "                    plumaTelegramButton.setTypeface(AndroidUtilities.bold());\n"
     "                    plumaTelegramButton.setGravity(Gravity.CENTER);\n"
     "                    plumaTelegramButton.setSingleLine(true);\n"
     "                    plumaTelegramButton.setEllipsize(TextUtils.TruncateAt.END);\n"
     "                    plumaTelegramButton.setPadding(AndroidUtilities.dp(34), 0, AndroidUtilities.dp(34), 0);\n"
     "                    ThemeBind.selectorBackground(plumaTelegramButton, Theme.createSimpleSelectorRoundRectDrawable(AndroidUtilities.dp(6), Theme.getColor(Theme.key_changephoneinfo_image2), Theme.getColor(Theme.key_chats_actionPressedBackground)), ThemeBind.of(Theme.key_changephoneinfo_image2), ThemeBind.of(Theme.key_chats_actionPressedBackground));\n"
     "                    plumaTelegramButton.setOnClickListener(v -> {\n"
     "                        Intent intent = plumaTelegramIntent();\n"
     "                        if (intent == null) {\n"
     "                            return;\n"
     "                        }\n"
     "                        try {\n"
     "                            getContext().startActivity(intent);\n"
     "                        } catch (Exception e) {\n"
     "                            FileLog.e(e);\n"
     "                        }\n"
     "                    });\n"
     "                    plumaTelegramButton.setVisibility(GONE);\n"
     "                    plumaColumn.addView(plumaTelegramButton, LayoutHelper.createLinear(LayoutHelper.MATCH_PARENT, 52, 0, 0, 0, 12));\n"
     "                    plumaColumn.addView(errorViewSwitcher, LayoutHelper.createLinear(LayoutHelper.WRAP_CONTENT, LayoutHelper.WRAP_CONTENT, Gravity.CENTER_HORIZONTAL));\n"
     "                    bottomContainer.addView(plumaColumn, LayoutHelper.createFrame(LayoutHelper.MATCH_PARENT, LayoutHelper.WRAP_CONTENT, Gravity.CENTER_HORIZONTAL | Gravity.BOTTOM, 0, 0, 0, 32));\n"
     "                } else\n"
     "                bottomContainer.addView(errorViewSwitcher, LayoutHelper.createFrame(currentType == VIEW_CODE_FRAGMENT_SMS ? LayoutHelper.MATCH_PARENT : LayoutHelper.WRAP_CONTENT, LayoutHelper.WRAP_CONTENT, Gravity.CENTER_HORIZONTAL | Gravity.BOTTOM, 0, 0, 0, 32));\n"),
    # The page of each show: title, button and its text.
    ("            url = params.getString(\"url\");\n",
     "            url = params.getString(\"url\");\n"
     "            // pluma: task 076.\n"
     "            plumaTelegram = params.getBoolean(\"plumaTelegram\", false);\n"
     "            if (!isInCancelAccountDeletionMode()) {\n"
     "                if (currentType == AUTH_TYPE_SMS) {\n"
     "                    titleTextView.setText(getString(R.string.PlumaLoginFallbackTitle));\n"
     "                } else if (currentType == AUTH_TYPE_MESSAGE) {\n"
     "                    titleTextView.setText(getString(plumaTelegram ? R.string.PlumaLoginTelegramTitle : R.string.SentAppCodeTitle));\n"
     "                }\n"
     "            }\n"
     "            if (plumaTelegramButton != null) {\n"
     "                plumaTelegramButton.setText(getString(currentType == AUTH_TYPE_SMS ? R.string.PlumaLoginOpenTelegramSettings : R.string.PlumaLoginOpenTelegram));\n"
     "                Intent intent = plumaTelegramIntent();\n"
     "                plumaTelegramButton.setVisibility(intent != null && intent.resolveActivity(getContext().getPackageManager()) != null ? VISIBLE : GONE);\n"
     "            }\n"),
    ("                if (currentType == AUTH_TYPE_MESSAGE) {\n"
     "                    str = AndroidUtilities.replaceTags(LocaleController.formatString(\"SentAppCodeWithPhone\", R.string.SentAppCodeWithPhone, LocaleController.addNbsp(number)));\n"
     "                } else if (currentType == AUTH_TYPE_SMS) {\n"
     "                    str = AndroidUtilities.replaceTags(LocaleController.formatString(\"SentSmsCode\", R.string.SentSmsCode, LocaleController.addNbsp(number)));\n",
     "                if (currentType == AUTH_TYPE_MESSAGE) {\n"
     "                    str = AndroidUtilities.replaceTags(plumaTelegram\n"
     "                        ? LocaleController.formatString(R.string.PlumaLoginTelegramText, LocaleController.addNbsp(number))\n"
     "                        : LocaleController.formatString(\"SentAppCodeWithPhone\", R.string.SentAppCodeWithPhone, LocaleController.addNbsp(number)));\n"
     "                } else if (currentType == AUTH_TYPE_SMS) {\n"
     "                    // pluma: Pluma sends no SMS: this is the code that did not reach Telegram.\n"
     "                    str = AndroidUtilities.replaceTags(LocaleController.formatString(R.string.PlumaLoginFallbackText, LocaleController.addNbsp(number)));\n"),
    # "Didn't get the code?" leads to the page of a code that did not reach
    # Telegram, not to an SMS.
    ("                        problemText.setText(getString(R.string.DidNotGetTheCodeSms));\n",
     "                        problemText.setText(getString(R.string.PlumaLoginDidNotGetCode)); // pluma: task 076\n"),
    # "Send again", after a countdown.
    ("            } else if (currentType == AUTH_TYPE_SMS && (nextType == AUTH_TYPE_SMS || nextType == AUTH_TYPE_PHRASE || nextType == AUTH_TYPE_WORD || nextType == AUTH_TYPE_CALL || nextType == AUTH_TYPE_FLASH_CALL)) {\n"
     "                if (nextType == AUTH_TYPE_SMS || nextType == AUTH_TYPE_PHRASE || nextType == AUTH_TYPE_WORD) {\n"
     "                    timeText.setText(LocaleController.formatString(\"SmsAvailableIn\", R.string.SmsAvailableIn, 1, 0));\n",
     "            } else if (currentType == AUTH_TYPE_SMS && (nextType == AUTH_TYPE_SMS || nextType == AUTH_TYPE_PHRASE || nextType == AUTH_TYPE_WORD || nextType == AUTH_TYPE_CALL || nextType == AUTH_TYPE_FLASH_CALL)) {\n"
     "                if (nextType == AUTH_TYPE_SMS || nextType == AUTH_TYPE_PHRASE || nextType == AUTH_TYPE_WORD) {\n"
     "                    timeText.setText(LocaleController.formatString(R.string.PlumaLoginSendAgainIn, time / 1000 / 60, time / 1000 % 60)); // pluma: task 076\n"),
    ("                                timeText.setText(LocaleController.formatString(\"ResendSmsAvailableIn\", R.string.ResendSmsAvailableIn, minutes, seconds));\n",
     "                                timeText.setText(LocaleController.formatString(R.string.PlumaLoginSendAgainIn, minutes, seconds)); // pluma: task 076\n"),
    ("                                    timeText.setText(getString(\"RequestSmsButton\", R.string.RequestSmsButton));\n",
     "                                    timeText.setText(getString(currentType == AUTH_TYPE_SMS ? R.string.PlumaLoginSendAgain : R.string.RequestSmsButton)); // pluma: task 076\n"),
    ("                    } else {\n"
     "                        timeText.setText(getString(R.string.SendingSms));\n"
     "                    }\n"
     "                    Bundle params = new Bundle();\n",
     "                    } else {\n"
     "                        timeText.setText(getString(R.string.PlumaLoginSending)); // pluma: task 076, no SMS\n"
     "                    }\n"
     "                    Bundle params = new Bundle();\n"),
    # Where the link to the chat or to the setting goes.
    ("        private void createCodeTimer() {\n",
     "        // pluma: the chat with the account that wrote the code, or the \"Who can find me by\n"
     "        // my number?\" setting of Telegram; null without a link (task 076).\n"
     "        private Intent plumaTelegramIntent() {\n"
     f"            String link = currentType == AUTH_TYPE_SMS ? {LOGIN_TELEGRAM_SETTINGS} : plumaTelegram ? url : null;\n"
     "            if (TextUtils.isEmpty(link)) {\n"
     "                return null;\n"
     "            }\n"
     "            return new Intent(Intent.ACTION_VIEW, Uri.parse(link)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);\n"
     "        }\n"
     "\n"
     "        private void createCodeTimer() {\n"),
)
# "Didn't get the code?" with nothing more to send: the administrator, not a
# letter to Telegram's support and auth.reportMissingCode.
LOGIN_MISSING_HEAD = ("                    } else {\n"
                      "                        TLRPC.TL_auth_reportMissingCode req = new TLRPC.TL_auth_reportMissingCode();\n")
LOGIN_MISSING_TAIL = ("                    }\n"
                      "                });\n"
                      "            }\n")
LOGIN_MISSING_BODY = ("                        // pluma: the administrator issues the code, Telegram's support has nothing\n"
                      "                        // to do with it (task 076).\n"
                      "                        new AlertDialog.Builder(context)\n"
                      "                                .setTitle(getString(R.string.PlumaLoginAdminTitle))\n"
                      "                                .setMessage(getString(R.string.PlumaLoginAdminText))\n"
                      "                                .setPositiveButton(getString(R.string.OK), null)\n"
                      "                                .setNegativeButton(getString(R.string.DidNotGetTheCodeEditNumberButton), (dialog, which) -> setPage(VIEW_PHONE_INPUT, true, null, true))\n"
                      "                                .show();\n")
LOGIN_QUERIES = ('    </queries>\n',
                 '        <!-- pluma: the login code page opens Telegram (task 076) -->\n'
                 '        <intent>\n            <action android:name="android.intent.action.VIEW"/>\n'
                 '            <data android:scheme="tg"/>\n        </intent>\n    </queries>\n')


# The texts, in every language the app bundles; the other languages come from
# the server's language pack (task 076). The path in Telegram's settings is
# Telegram's own words in each language (translations.telegram.org, android:
# Settings, PrivacySettings, PrivacyPhone, PrivacyPhoneTitle2, LastSeenEverybody).
LOGIN_STRINGS = {
    'PlumaLoginTelegramTitle': {
        'values': 'Check Telegram',
        'values-ar': 'تحقق من تيليجرام',
        'values-de': 'Schau in Telegram nach',
        'values-es': 'Revisa Telegram',
        'values-it': 'Controlla Telegram',
        'values-ko': '텔레그램을 확인하세요',
        'values-nl': 'Kijk in Telegram',
        'values-pt-rBR': 'Verifique o Telegram',
        'values-ru': 'Проверьте Telegram',
        'values-uk': 'Перевірте Telegram',
    },
    'PlumaLoginTelegramText': {
        'values': "We\\'ve sent the code for **%1$s** to your Telegram, in a message from the Pluma account.",
        'values-ar': 'أرسلنا رمز **%1$s** إلى تيليجرام الخاص بك في رسالة من حساب Pluma.',
        'values-de': 'Wir haben den Code für **%1$s** an dein Telegram gesendet, als Nachricht vom Pluma-Konto.',
        'values-es': 'Enviamos el código para **%1$s** a tu Telegram, en un mensaje de la cuenta Pluma.',
        'values-it': "Abbiamo inviato il codice per **%1$s** al tuo Telegram, in un messaggio dell\\'account Pluma.",
        'values-ko': '**%1$s** 번호의 코드를 Pluma 계정의 메시지로 텔레그램에 보냈습니다.',
        'values-nl': 'We hebben de code voor **%1$s** naar je Telegram gestuurd, in een bericht van het Pluma-account.',
        'values-pt-rBR': 'Enviamos o código para **%1$s** ao seu Telegram, em uma mensagem da conta Pluma.',
        'values-ru': 'Код для **%1$s** отправлен вам в Telegram сообщением от аккаунта Pluma.',
        'values-uk': 'Код для **%1$s** надіслано вам у Telegram повідомленням від акаунта Pluma.',
    },
    'PlumaLoginOpenTelegram': {
        'values': 'Open Telegram',
        'values-ar': 'فتح تيليجرام',
        'values-de': 'Telegram öffnen',
        'values-es': 'Abrir Telegram',
        'values-it': 'Apri Telegram',
        'values-ko': '텔레그램 열기',
        'values-nl': 'Telegram openen',
        'values-pt-rBR': 'Abrir o Telegram',
        'values-ru': 'Открыть Telegram',
        'values-uk': 'Відкрити Telegram',
    },
    'PlumaLoginDidNotGetCode': {
        'values': "Didn\\'t get the code?",
        'values-ar': 'لم يصلك الرمز؟',
        'values-de': 'Keinen Code erhalten?',
        'values-es': '¿No recibiste el código?',
        'values-it': 'Non hai ricevuto il codice?',
        'values-ko': '코드를 받지 못하셨나요?',
        'values-nl': 'Geen code ontvangen?',
        'values-pt-rBR': 'Não recebeu o código?',
        'values-ru': 'Не пришёл код?',
        'values-uk': 'Не надійшов код?',
    },
    'PlumaLoginFallbackTitle': {
        'values': "Code didn\\'t reach Telegram",
        'values-ar': 'لم يصل الرمز إلى تيليجرام',
        'values-de': 'Der Code kam nicht in Telegram an',
        'values-es': 'El código no llegó a Telegram',
        'values-it': 'Il codice non è arrivato su Telegram',
        'values-ko': '코드가 텔레그램에 전달되지 않았습니다',
        'values-nl': 'De code kwam niet aan in Telegram',
        'values-pt-rBR': 'O código não chegou ao Telegram',
        'values-ru': 'Код не дошёл до Telegram',
        'values-uk': 'Код не дійшов до Telegram',
    },
    'PlumaLoginFallbackText': {
        'values': "The code for **%1$s** didn\\'t reach your Telegram. Let Telegram find you by your number: **Settings → Privacy and Security → Phone Number → Who can find me by my number? → Everybody**.\\n\\nNo Telegram? Ask the administrator for the code and enter it here.",
        'values-ar': 'لم يصل رمز **%1$s** إلى تيليجرام الخاص بك. اسمح لتيليجرام بالعثور عليك برقمك: **الإعدادات ← الخصوصية والأمان ← رقم الهاتف ← من يمكنهم إيجادي برقم هاتفي؟ ← الجميع**.\\n\\nليس لديك تيليجرام؟ اطلب الرمز من المسؤول وأدخله هنا.',
        'values-de': 'Der Code für **%1$s** kam nicht in deinem Telegram an. Erlaube Telegram, dich über deine Nummer zu finden: **Einstellungen → Privatsphäre und Sicherheit → Telefonnummer → Wer darf mich unter meiner Nummer finden? → Jeder**.\\n\\nKein Telegram? Bitte den Administrator um den Code und gib ihn hier ein.',
        'values-es': 'El código para **%1$s** no llegó a tu Telegram. Permite que Telegram te encuentre por tu número: **Ajustes → Privacidad y seguridad → Número de teléfono → ¿Quién puede encontrarme por mi número? → Todos**.\\n\\n¿No tienes Telegram? Pide el código al administrador e introdúcelo aquí.',
        'values-it': "Il codice per **%1$s** non è arrivato sul tuo Telegram. Consenti a Telegram di trovarti tramite il tuo numero: **Impostazioni → Privacy e sicurezza → Numero di telefono → Chi può trovarmi con il mio numero → Tutti**.\\n\\nNon hai Telegram? Chiedi il codice all\\'amministratore e inseriscilo qui.",
        'values-ko': '**%1$s** 번호의 코드가 텔레그램에 전달되지 않았습니다. 텔레그램에서 번호로 나를 찾을 수 있도록 허용하세요: **설정 → 개인 정보 및 보안 → 전화번호 → 내 번호로 나를 찾을 수 있는 사람 → 모두**.\\n\\n텔레그램이 없으신가요? 관리자에게 코드를 요청해 여기에 입력하세요.',
        'values-nl': 'De code voor **%1$s** is niet aangekomen in je Telegram. Laat Telegram je vinden via je nummer: **Instellingen → Privacy en veiligheid → Telefoonnummer → Wie kan me vinden via mijn nummer? → Iedereen**.\\n\\nGeen Telegram? Vraag de beheerder om de code en voer die hier in.',
        'values-pt-rBR': 'O código para **%1$s** não chegou ao seu Telegram. Permita que o Telegram encontre você pelo número: **Configurações → Privacidade e Segurança → Número de Telefone → Quem pode me encontrar pelo meu número? → Todos**.\\n\\nNão tem Telegram? Peça o código ao administrador e digite-o aqui.',
        'values-ru': 'Код для **%1$s** не дошёл до вашего Telegram. Разрешите Telegram находить вас по номеру: **Настройки → Конфиденциальность → Номер телефона → Кто может найти меня по номеру? → Все**.\\n\\nНет Telegram? Попросите код у администратора и введите его здесь.',
        'values-uk': 'Код для **%1$s** не дійшов до вашого Telegram. Дозвольте Telegram знаходити вас за номером: **Налаштування → Приватність і безпека → Номер телефону → Хто може знайти мене за номером? → Усі**.\\n\\nНемає Telegram? Попросіть код в адміністратора й введіть його тут.',
    },
    'PlumaLoginOpenTelegramSettings': {
        'values': 'Open Telegram settings',
        'values-ar': 'فتح إعدادات تيليجرام',
        'values-de': 'Telegram-Einstellungen öffnen',
        'values-es': 'Abrir ajustes de Telegram',
        'values-it': 'Apri le impostazioni di Telegram',
        'values-ko': '텔레그램 설정 열기',
        'values-nl': 'Telegram-instellingen openen',
        'values-pt-rBR': 'Abrir configurações do Telegram',
        'values-ru': 'Открыть настройки Telegram',
        'values-uk': 'Відкрити налаштування Telegram',
    },
    'PlumaLoginSendAgainIn': {
        'values': 'Send again in %1$d:%2$02d',
        'values-ar': 'إعادة الإرسال خلال %1$d:%2$02d',
        'values-de': 'Erneut senden in %1$d:%2$02d',
        'values-es': 'Volver a enviar en %1$d:%2$02d',
        'values-it': 'Invia di nuovo tra %1$d:%2$02d',
        'values-ko': '%1$d:%2$02d 후 다시 보내기',
        'values-nl': 'Opnieuw versturen over %1$d:%2$02d',
        'values-pt-rBR': 'Reenviar em %1$d:%2$02d',
        'values-ru': 'Отправить ещё раз через %1$d:%2$02d',
        'values-uk': 'Надіслати ще раз через %1$d:%2$02d',
    },
    'PlumaLoginSendAgain': {
        'values': 'Send again',
        'values-ar': 'إعادة الإرسال',
        'values-de': 'Erneut senden',
        'values-es': 'Volver a enviar',
        'values-it': 'Invia di nuovo',
        'values-ko': '다시 보내기',
        'values-nl': 'Opnieuw versturen',
        'values-pt-rBR': 'Reenviar',
        'values-ru': 'Отправить ещё раз',
        'values-uk': 'Надіслати ще раз',
    },
    'PlumaLoginSending': {
        'values': 'Sending…',
        'values-ar': 'جارٍ الإرسال…',
        'values-de': 'Wird gesendet…',
        'values-es': 'Enviando…',
        'values-it': 'Invio in corso…',
        'values-ko': '보내는 중…',
        'values-nl': 'Versturen…',
        'values-pt-rBR': 'Enviando…',
        'values-ru': 'Отправляем…',
        'values-uk': 'Надсилаємо…',
    },
    'PlumaLoginAdminTitle': {
        'values': 'Ask the administrator',
        'values-ar': 'اسأل المسؤول',
        'values-de': 'Frag den Administrator',
        'values-es': 'Pregunta al administrador',
        'values-it': "Chiedi all\\'amministratore",
        'values-ko': '관리자에게 문의하세요',
        'values-nl': 'Vraag de beheerder',
        'values-pt-rBR': 'Fale com o administrador',
        'values-ru': 'Код у администратора',
        'values-uk': 'Код в адміністратора',
    },
    'PlumaLoginAdminText': {
        'values': 'Ask the Pluma administrator for your code and enter it here.',
        'values-ar': 'اطلب رمزك من مسؤول Pluma وأدخله هنا.',
        'values-de': 'Bitte den Pluma-Administrator um deinen Code und gib ihn hier ein.',
        'values-es': 'Pide tu código al administrador de Pluma e introdúcelo aquí.',
        'values-it': "Chiedi il tuo codice all\\'amministratore di Pluma e inseriscilo qui.",
        'values-ko': 'Pluma 관리자에게 코드를 요청해 여기에 입력하세요.',
        'values-nl': 'Vraag de beheerder van Pluma om je code en voer die hier in.',
        'values-pt-rBR': 'Peça seu código ao administrador do Pluma e digite-o aqui.',
        'values-ru': 'Попросите код у администратора Pluma и введите его здесь.',
        'values-uk': 'Попросіть код в адміністратора Pluma й введіть його тут.',
    },
}
LOGIN_STRING_LINE = re.compile(r'    <string name="PlumaLogin\w+">[^<]*</string>\n')

def _login_view_span(text):
    start = text.index(LOGIN_VIEW)
    end = text.index("\n    public class ", start + len(LOGIN_VIEW))
    return start, end


def login_screens(tree):
    """Runs after brand(): the strings keep the name of the real Telegram, and
    the link to Telegram's settings keeps its tg: scheme."""
    for old, new in LOGIN_EDITS:
        tree.replace(LOGIN, old, new)
    text = tree.read(LOGIN)
    start, end = _login_view_span(text)
    view = text[start:end]
    for old, new in LOGIN_VIEW_EDITS:
        if view.count(old) != 1:
            raise PatchError(f"{LOGIN}: {view.count(old)} occurrences of {old[:80]!r} in LoginActivitySmsView, expected 1")
        view = view.replace(old, new)
    if view.count(LOGIN_MISSING_HEAD) != 1:
        raise PatchError(f"{LOGIN}: the missing-code branch of LoginActivitySmsView changed")
    head = view.index(LOGIN_MISSING_HEAD) + len(LOGIN_MISSING_HEAD)
    tail = view.index(LOGIN_MISSING_TAIL, head)
    if "sms@telegram.org" not in view[head:tail]:
        raise PatchError(f"{LOGIN}: the missing-code branch no longer writes to Telegram's support")
    view = (view[:head - len("                        TLRPC.TL_auth_reportMissingCode req = new TLRPC.TL_auth_reportMissingCode();\n")]
            + LOGIN_MISSING_BODY + view[tail:])
    tree.write(LOGIN, text[:start] + view + text[end:])
    tree.replace(f"{MAIN}/AndroidManifest.xml", LOGIN_QUERIES[0], LOGIN_QUERIES[1])
    files = {p.parent.name: str(p.relative_to(tree.root)) for p in sorted((tree.root / RES).glob("values*/strings.xml"))}
    if set(files) != set(STRING_RENAMES):
        raise PatchError(f"{RES}: strings.xml in {', '.join(sorted(files))}, expected {', '.join(sorted(STRING_RENAMES))}")
    for lang, rel in files.items():
        text = tree.read(rel)
        lines = []
        for key, texts in LOGIN_STRINGS.items():
            if f'<string name="{key}">' in text:
                raise PatchError(f"{rel}: upstream has a string {key}")
            lines.append(f'    <string name="{key}">{texts[lang]}</string>\n')
        tree.replace(rel, "</resources>", "".join(lines) + "</resources>")


def verify_login_screens(tree):
    text = tree.read(LOGIN)
    for _, new in LOGIN_EDITS:
        if text.count(new) != 1:
            raise PatchError(f"{LOGIN}: the routing of a code in Telegram (task 076) is not there")
    start, end = _login_view_span(text)
    view = text[start:end]
    for _, new in LOGIN_VIEW_EDITS:
        if view.count(new) != 1:
            raise PatchError(f"{LOGIN}: an edit of the login code page (task 076) is not there")
    if text.count(LOGIN_TELEGRAM_SETTINGS) != 1:
        raise PatchError(f"{LOGIN}: the link to Telegram's setting is not there once")
    if view.count(LOGIN_MISSING_BODY) != 1 or "sms@telegram.org" in view or "TL_auth_reportMissingCode" in view:
        raise PatchError(f"{LOGIN}: the login code page still leads to Telegram's support")
    manifest = tree.read(f"{MAIN}/AndroidManifest.xml")
    if manifest.count(LOGIN_QUERIES[1]) != 1:
        raise PatchError("AndroidManifest.xml: the app cannot see whether Telegram is installed")
    used = set(re.findall(r"R\.string\.(PlumaLogin\w+)", text))
    if used != set(LOGIN_STRINGS):
        raise PatchError(f"{LOGIN}: strings used {sorted(used)}, defined {sorted(LOGIN_STRINGS)}")
    for p in sorted((tree.root / RES).glob("values*/strings.xml")):
        xml = p.read_text(encoding="utf-8")
        for key, texts in LOGIN_STRINGS.items():
            if xml.count(f'    <string name="{key}">{texts[p.parent.name]}</string>\n') != 1:
                raise PatchError(f"{p.relative_to(tree.root)}: {key} is not the text of task 076")

# --- What the server does not serve ------------------------------------------
# Every way into a service Pluma does not have, not only the visible one. The
# edits are exact, so a row or a branch upstream adds next to them stops the
# patch until it is read.
SETTINGS_ACTIVITY = "TMessagesProj/src/main/java/org/telegram/ui/SettingsActivity.java"
NOT_SERVED_LINK_MANAGER = "TMessagesProj/src/main/java/org/telegram/ui/LinkManager.java"
NOT_SERVED_EDITS = (
    # Help leads to Telegram's support, FAQ, feature tips and privacy policy
    # only; the experimental section after it stays.
    (SETTINGS_ACTIVITY,
     "        items.add(UItem.asHeader(getString(R.string.SettingsHelp)));\n"
     "        items.add(SettingCell.Factory.of(17, IconBackgroundColors.ORANGE.top, IconBackgroundColors.ORANGE.bottom, R.drawable.settings_ask, getString(R.string.AskAQuestion)));\n"
     "        items.add(SettingCell.Factory.of(18, IconBackgroundColors.BLUE_LIGHT.top, IconBackgroundColors.BLUE_LIGHT.bottom, R.drawable.settings_faq, getString(R.string.TelegramFAQ)));\n"
     "        items.add(SettingCell.Factory.of(23, IconBackgroundColors.PURPLE.top, IconBackgroundColors.PURPLE.bottom, R.drawable.settings_features, getString(R.string.TelegramFeatures)));\n"
     "        items.add(SettingCell.Factory.of(19, IconBackgroundColors.GREEN.top, IconBackgroundColors.GREEN.bottom, R.drawable.settings_policy, getString(R.string.PrivacyPolicy)));\n"
     "\n"
     "        if (SharedSettings.experimentalSettingsAllowed.get()) {\n"
     "            items.add(UItem.asShadow(null));\n",
     "        // pluma: no Help section; it leads to Telegram's support, FAQ, feature tips and\n"
     "        // privacy policy only.\n"
     "\n"
     "        if (SharedSettings.experimentalSettingsAllowed.get()) {\n"),
    (SETTINGS_ACTIVITY,
     "        if (BuildVars.LOGS_ENABLED || BuildVars.DEBUG_PRIVATE_VERSION) {\n"
     "            items.add(UItem.asShadow(null));\n"
     "            items.add(UItem.asHeader(getString(R.string.SettingsDebug)));\n",
     "        if (BuildVars.LOGS_ENABLED || BuildVars.DEBUG_PRIVATE_VERSION) {\n"
     "            if (items.get(items.size() - 1).viewType != UniversalAdapter.VIEW_TYPE_SHADOW) // pluma: Help no longer ends in a row\n"
     "                items.add(UItem.asShadow(null));\n"
     "            items.add(UItem.asHeader(getString(R.string.SettingsDebug)));\n"),
    # The same support chat from the Log Out screen and the same pages from
    # links.
    ("TMessagesProj/src/main/java/org/telegram/ui/LogoutActivity.java",
     "        supportRow = rowCount++;\n",
     "        supportRow = -1; // pluma: help.getSupport is not served\n"),
    (NOT_SERVED_LINK_MANAGER,
     '        if ("ask-question".equalsIgnoreCase(first) || "ask-a-question".equalsIgnoreCase(first)) {\n'
     "            AlertsCreator.createSupportAlert(getLastFragment(), null).show();\n"
     "            return true;\n"
     "        }\n"
     '        if ("faq".equalsIgnoreCase(first)) {\n'
     "            Browser.openUrl(activity, LocaleController.getString(R.string.TelegramFaqUrl));\n"
     "            return true;\n"
     "        }\n"
     '        if ("features".equalsIgnoreCase(first)) {\n'
     "            Browser.openUrl(activity, LocaleController.getString(R.string.TelegramFeaturesUrl));\n"
     "            return true;\n"
     "        }\n"
     '        if ("privacy-policy".equalsIgnoreCase(first)) {\n'
     "            Browser.openUrl(activity, LocaleController.getString(R.string.PrivacyPolicyUrl));\n"
     "            return true;\n"
     "        }\n",
     "        // pluma: the links of the Help section open Settings: no Help section.\n"),
    # TON Connect waits for a wallet the server does not provide: the gate of
    # the other wallet links, and no claim on tc:// links of other apps.
    (NOT_SERVED_LINK_MANAGER,
     "    private boolean handleTc(Uri uri) {\n        uri = normalizeTgUri(uri);\n",
     "    private boolean handleTc(Uri uri) {\n"
     "        if (!getMessagesController().config.walletAvailable.get()) return false; // pluma: as handleTon\n"
     "        uri = normalizeTgUri(uri);\n"),
    ("TMessagesProj/src/main/AndroidManifest.xml",
     '            <intent-filter android:icon="@mipmap/ic_launcher" android:roundIcon="@mipmap/ic_launcher_round" android:priority="1">\n'
     '                <action android:name="android.intent.action.VIEW" />\n'
     '                <category android:name="android.intent.category.DEFAULT" />\n'
     '                <category android:name="android.intent.category.BROWSABLE" />\n'
     '                <data android:scheme="tc" />\n'
     "            </intent-filter>\n",
     "            <!-- pluma: no tc:// links, the wallet is closed -->\n"),
)


def not_served(tree):
    for rel, old, new in NOT_SERVED_EDITS:
        tree.replace(rel, old, new)


def verify_not_served(tree):
    for rel, old, new in NOT_SERVED_EDITS:
        text = tree.read(rel)
        if text.count(new) != 1 or old in text:
            raise PatchError(f"{rel}: the path to a service that is not served is open again")
    if tree.read(SETTINGS_ACTIVITY).count("R.string.SettingsExperimental") != 1:
        raise PatchError(f"{SETTINGS_ACTIVITY}: the experimental section is gone")


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
    ap.add_argument("--build", type=int, default=0, help="Pluma's build number, the fourth part of versionName")
    a = ap.parse_args(argv)
    try:
        app = load_env(a.app)
        c = Config(load_env(a.upstream), app, a.server_ipv4, a.server_port, a.server_ipv6,
                   pathlib.Path(a.rsa_public_key).read_text(), a.abis or app.get("PLUMA_ABIS", ""),
                   a.ccache, a.google_services, a.build)
        tree = Tree(a.source)
        patch(tree, c)
        verify(tree, c)
    except PatchError as e:
        print(f"patch: {e}", file=sys.stderr)
        return 1
    print(f"patch: {c.package} \"{c.app_name}\" {c.version_name}, layer {c.layer}, server key {c.fingerprint:#018x}, "
          f"ABIs {' '.join(c.abis)}, Firebase {'given' if c.google_services else 'placeholder'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
