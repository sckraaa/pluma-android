#!/usr/bin/env python3
"""Turns a checkout of DrKLO/Telegram into the Pluma client.

Every change is an exact edit: the text it replaces must occur the expected
number of times, or the whole run fails. An upstream update that moves any
of these places stops the build here instead of producing a client that
talks to Telegram or does not sign in. The brand assets of brand/android
replace upstream files only when those are byte for byte the ones expected.
After the edits the result is checked again (no Telegram datacenter address
or server key is left, no Telegram name in the built-in strings, no tg://
link scheme).

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

    brand(tree)


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
# "Link desktop device": brand/android/qr_login_logo.json replaces the shapes
# of its "Logo full" layer.
QR_LOGIN_SHA256 = "40cccd31a7f01608dd1e8a3bd4597b05832585f10cdc7a5914204b22c507ab79"

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

# Palette "graphite and sage" (docs/tasks/017-rebranding.md of the server
# repository) in the default themes: the day theme "Blue" with its home accent
# and the night theme "Dark Blue". The accent engine shifts every remaining
# colour near the theme's blue base to the sage accent; these keys get the
# palette's exact values, which lie outside the shifted hues. Each entry is
# (key, the upstream value or None when the key is not set, the new colour).
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
    ("chats_actionPressedBackground", -11166764, "#4F6E52"),
    ("featuredStickers_addButtonPressed", -12412453, "#4F6E52"),
    # text on the accent
    ("chats_unreadCounterText", None, "#FFFFFF"),
    ("chats_actionIcon", None, "#FFFFFF"),
    ("featuredStickers_buttonText", None, "#FFFFFF"),
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
# The accent arrays of Theme.java: (row, column, upstream, new). Rows: 0
# accent, 1 my messages, 2 their gradient, 3-6 wallpaper colours, 7 ids.
ACCENTS = {
    # The home accent (id 99, first column): sage; the bubbles come from the
    # theme file instead of the green of my-messages.
    "Blue": ((7, 0, "99", "99"), (0, 0, "0xFF5890C5", "0xFF5B7A5E"), (1, 0, "0xFFB8E18D", "0x00000000")),
    # The home accent (id 0, ninth column): sage, on a dark green wallpaper.
    "Dark Blue": ((7, 8, "0", "0"), (0, 8, "0xff3685fa", "0xff9DBB9F"), (3, 8, "0xff0e141a", "0xff0F120F"),
                  (4, 8, "0xff172431", "0xff1A211B"), (5, 8, "0xff0f171e", "0xff121612"),
                  (6, 8, "0xff141c2b", "0xff171D18")),
}
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


def argb(colour):
    """#RRGGBB or #AARRGGBB as the signed int of a .attheme file."""
    v = int(colour[1:], 16) | (0xFF000000 if len(colour) == 7 else 0)
    return v - (1 << 32) if v & 0x80000000 else v


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


def edit_accents(text, theme, edits):
    """Edits cells of the accent arrays of a theme in Theme.java."""
    head = f'        themeInfo.name = "{theme}";\n'
    if text.count(head) != 1:
        raise PatchError(f"Theme.java: {text.count(head)} themes {theme!r}, expected 1")
    start = text.index("        themeInfo.setAccentColorOptions(\n", text.index(head))
    end = text.index("\n                );\n", start)
    lines = text[start:end].split("\n")
    rows = [i for i, l in enumerate(lines) if l.lstrip().startswith(("new int[]", "new String[]"))]
    if len(rows) != 11:
        raise PatchError(f"Theme.java: {theme}: {len(rows)} accent arrays, expected 11")
    for row, column, old, new in edits:
        line = lines[rows[row]]
        first = line.index("{") + 1
        cells = list(re.finditer(r"[^\s,{}]+", line[first:line.index("}")]))
        if column >= len(cells) or cells[column].group(0) != old:
            found = cells[column].group(0) if column < len(cells) else None
            raise PatchError(f"Theme.java: {theme}: accent array {row}, column {column} is {found}, expected {old}")
        a, b = first + cells[column].start(), first + cells[column].end()
        lines[rows[row]] = line[:a] + new + line[b:]
    return text[:start] + "\n".join(lines) + text[end:]


def edit_attheme(text, name, table, known_keys):
    """Sets keys of a .attheme file; each must have its upstream value, or be
    absent when that is None."""
    lines = text.split("\n")
    if lines[-1] != "":
        raise PatchError(f"{name}: no newline at the end")
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
    return "\n".join(lines[:-1] + added) + "\n"


def brand(tree):
    brand_entry_points(tree)
    brand_strings(tree)
    brand_scheme(tree)
    brand_assets(tree)
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


def brand_assets(tree):
    have = {p.relative_to(BRAND / "res").as_posix() for p in (BRAND / "res").rglob("*") if p.is_file()}
    if have != set(BRAND_ASSETS):
        raise PatchError(f"brand/android/res and BRAND_ASSETS differ: {sorted(have ^ set(BRAND_ASSETS))}")
    for rel, sha in sorted(BRAND_ASSETS.items()):
        dst = tree.root / RES / rel
        if not dst.is_file() or hashlib.sha256(dst.read_bytes()).hexdigest() != sha:
            raise PatchError(f"{RES}/{rel}: not the upstream file the brand asset replaces; upstream changed it")
        new = (BRAND / "res" / rel).read_bytes()
        if dst.suffix in (".png", ".webp") and image_size(new) != image_size(dst.read_bytes()):
            raise PatchError(f"brand/android/res/{rel}: {image_size(new)} pixels, upstream has {image_size(dst.read_bytes())}")
        dst.write_bytes(new)
    rel = f"{RES}/raw/qr_login.json"
    data = (tree.root / rel).read_bytes()
    if hashlib.sha256(data).hexdigest() != QR_LOGIN_SHA256:
        raise PatchError(f"{rel}: not the animation the patch expects; upstream changed it")
    anim = json.loads(data)
    logo = [layer for layer in anim["layers"] if layer.get("nm") == "Logo full"]
    if len(logo) != 1:
        raise PatchError(f"{rel}: {len(logo)} layers \"Logo full\", expected 1")
    logo[0]["shapes"] = json.loads((BRAND / "qr_login_logo.json").read_text())
    tree.write(rel, json.dumps(anim, separators=(",", ":")))
    # The background of the adaptive icon: white, as in the brand kit.
    tree.replace(f"{RES}/drawable/icon_background_sa.xml", 'android:startColor="#289AD1"', 'android:startColor="#FFFFFF"')
    tree.replace(f"{RES}/drawable/icon_background_sa.xml", 'android:endColor="#38AEEB"', 'android:endColor="#FFFFFF"')
    # The intro texture of the mark is centred; the plane was not.
    tree.replace("TMessagesProj/jni/intro/IntroRenderer.c", "telegram_plane.params.anchor = xyzMake(6, -5, 0);",
                 "telegram_plane.params.anchor = xyzMake(0, 0, 0); // pluma: the mark is centred in its texture")
    # The sphere under it: the white disc of the app icon.
    tree.replace(f"{JAVA}/ui/IntroActivity.java",
                 "paint.setColor(ThemeColors.TELEGRAM_COLOR); // It's logo color, it should not be colored by the theme",
                 "paint.setColor(0xFFFFFFFF); // pluma: the white disc of the app icon, under the mark")


def brand_theme(tree):
    rel = f"{JAVA}/ui/ActionBar/Theme.java"
    text = tree.read(rel)
    for theme, edits in ACCENTS.items():
        text = edit_accents(text, theme, edits)
    tree.write(rel, text)
    # Dark Blue keeps Telegram's blue as the base of the hue shift, so that its
    # sage home accent recolours the theme (the base is the accent of id 0).
    tree.replace(rel, '        sortAccents(themeInfo);\n        themes.add(themeInfo);\n'
                      '        themesDict.put("Dark Blue", currentNightTheme = themeInfo);\n',
                 "        // pluma: Telegram's blue stays the base the sage home accent shifts from.\n"
                 "        themeInfo.accentBaseColor = 0xff3685fa;\n"
                 '        sortAccents(themeInfo);\n        themes.add(themeInfo);\n'
                 '        themesDict.put("Dark Blue", currentNightTheme = themeInfo);\n')
    # Its bubbles come from darkblue.attheme, not from Telegram's blue to purple
    # gradient (which the alternative "Night" theme keeps).
    tree.replace(rel, '                if (isHome(themeAccent) && name.equals("Dark Blue") || name.equals("Night")) {\n',
                 "                // pluma: the default dark theme takes its bubbles from darkblue.attheme.\n"
                 '                if (name.equals("Night")) {\n')
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
    for name, table in (("bluebubbles.attheme", PALETTE_LIGHT), ("darkblue.attheme", PALETTE_DARK)):
        rel = f"{MAIN}/assets/{name}"
        tree.write(rel, edit_attheme(tree.read(rel), name, table, known))

    for rel, old, new, count in BRAND_COLOURS:
        tree.replace(rel, old, new, count)


def verify_brand(tree):
    for rel, sha in BRAND_ASSETS.items():
        if (tree.root / RES / rel).read_bytes() != (BRAND / "res" / rel).read_bytes():
            raise PatchError(f"{RES}/{rel}: not the brand asset")
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
