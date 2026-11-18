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
Messages that ask for no Premium, premium stickers sent without Premium,
no way into the AI message editor, no group call joined without its key, no
way into RTMP streams, live stories or call recording, none of Telegram's
colours on the call screens, the server's HTTPS CDN reached over https://
only in a server build, maps drawn by MapLibre from the server's tiles with
no source on Google's maps and no key for them in a manifest).

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
    def __init__(self, upstream, app, server_ipv4, server_port, server_ipv6, rsa_pem, abis, ccache, google_services, build=0,
                 target="server", edge_ws_urls=""):
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

        # A development build reaches the stand's HTTPS CDN over plain http:// (task 107):
        # the server address of the build and the emulator's host; a server build never.
        if target not in ("server", "dev"):
            raise PatchError(f"target {target!r}: server or dev")
        self.target = target
        self.dev_http_hosts = sorted({self.ipv4, CDN_HTTPS_EMULATOR_HOST}) if target == "dev" else []
        # The server's edges (task 109): wss:// URLs in the order tried; none, no edit.
        self.edge_urls = parse_edge_urls(edge_ws_urls)


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
    call_parameters(tree)
    group_calls_e2e(tree)
    call_colours(tree)
    birthdays(tree)
    sticker_sets(tree)
    saved_tags(tree)
    round_video(tree)
    cdn_https(tree, c)
    maps(tree)
    premium_stickers(tree)
    premium_for_everyone(tree)
    business(tree)
    not_served(tree)
    edges(tree, c)
    no_ai_editor(tree)
    service_account(tree)
    self_update(tree, c)
    links(tree)
    brand(tree)
    login_screens(tree)


# --- the server's edges -------------------------------------------------------
# Task 109 of the server repository (ADR 0072): when the direct address of the
# server does not answer, the client reaches the server through an edge, a
# WebSocket over TLS to a CDN or a node (wss://<host>/apiws, protocol "binary"),
# which carries the same bytes as the direct TCP connection: the obfuscated
# header and the frames of the transport. The edges of the build come from
# PLUMA_EDGE_WS_URLS (ci/configure.sh; empty: no edit at all), the server may
# give others and their order in the app config (pluma_edge).
#
# tgnet, as read in 7be672ea, before the edit:
# - An address of a datacenter is tried on four port slots {-1, 443, 5222, -1}
#   (-1: the address's own port) before the next address; after the last
#   address the list starts over (Datacenter.h 84, Datacenter.cpp 374-439). The
#   index is stored in dc<N>conf.dat once data came (Connection.cpp 128-129,
#   Datacenter.cpp 468-482) and read back at start (Datacenter.cpp 170-183).
# - A connection that closes moves on after 2 failures in a row (4 if it had
#   useful data), or at once on a timeout of a connection that got no byte
#   (Connection.cpp 660, 684-700); any received byte sets the failures to 0
#   (Connection.cpp 74). A timeout closes a connection only while a request
#   waits (ConnectionSocket.cpp 708-719); the generic connection's is 12 s,
#   up to 16 s after timeouts (Connection.cpp 144, 383, 662-664).
# - So a direct connection that gets its first bytes and then freezes (the 16 KB
#   stall of brief 092) is never left: each reconnect gets bytes again. The edit
#   counts it: two timeouts in a row of an established generic connection of
#   DC 1 (each within 60 s of the previous) put DC 1 on its first edge.
# - help.getConfig replaces the addresses only for the datacenters of
#   dc_options (ConnectionsManager.cpp 3488-3514), which the Pluma server sends
#   empty; a push DC_UPDATE replaces them too (applyDatacenterAddress, 3588-3596).
#   Either way the labels are applied again after the replacement, and an
#   address of the server is never taken for a label.
#
# So:
# - Each edge is an address label of DC 1 ("pluma-edge-<n>", in the order of
#   the edges), after the direct addresses, or before them when the server
#   orders the edges first; the IPv6 list gets them only if it has a direct
#   address. A label has no port slots: the next address follows it.
# - ConnectionSocket opens a label as 127.0.0.1:<port of that edge's bridge>;
#   with a proxy of the user (or a proxy check) on, or with no bridge, it fails
#   at once and tgnet goes on.
# - PlumaEdgeBridge (org.telegram.utils.proxy, after WebProxyTransport's local
#   ServerSocket, WebProxyTransport.java 323, 370-400) listens on 127.0.0.1 with
#   one port per edge; each connection tgnet opens is one WebSocket of
#   nv-websocket-client 2.14 (upstream's dependency, TMessagesProj/build.gradle
#   57) to that edge: "binary", User-Agent Pluma (the library sends none,
#   HandshakeBuilder), bytes both ways as they come, a message at most 64 KB;
#   the library answers pings itself (ReadingThread.handlePingFrame). 45 s
#   without a byte from the edge (pings included) closes both sides; closing
#   one side closes the other.
# - The first connection through an edge starts sticky_s (1800 s); then the
#   next connection of DC 1 tries the direct address first (returnFromPlumaEdge
#   through JNI; the open one stays). The labels are dropped from the stored
#   addresses at start, so a new run starts on the direct address.
# - pluma_edge of help.getAppConfig (v 1, 1-4 wss:// URLs, order a permutation
#   of direct and edge, sticky_s 60-86400) is kept in the preferences and
#   applied at once; absent or not valid, the build's list applies.
#
# A-129, task 113 of the server repository (ADR 0073): the path is chosen by the
# gateway's probe (pluma.probe, answered before the key exchange with more bytes
# than the stall lets through), not by the first answer.
# - tgnet's DC 1 takes an order of all paths (0 the direct addresses, n + 1 the
#   label of edge n) instead of edges-first-or-not; PlumaPathProber gives it
#   before native_init, from the memory of the network, so tgnet connects at once.
# - PlumaPathProber races gate probes (obfuscated2 + intermediate over its own
#   TCP socket, or its own WebSocket to an edge) and, when the first path does
#   not pass and another does, gives a new order with reconnect: every
#   connection of DC 1 drops and opens on the new first path, as a new proxy
#   does (ConnectionsManager.cpp 3809-3818, Datacenter::suspendConnections).
# - Measurements in the background (start, network change, a request of DC 1
#   that waits suspect_ms with no byte, every reprobe_s) switch with hysteresis;
#   a switch waits for a file transfer (data on a download or upload
#   connection), at most 2 minutes.
# - While the prober chooses, sticky_s is not used; with a proxy of the user on,
#   or after the gateway closed right after resPQ (no probe there), the rules
#   above hold until the next pluma_probe.
# - The rules, the probe's bytes and the memory are PlumaPathPolicy, plain Java
#   that ci/PlumaPathPolicyTest.java runs on a JVM.
EDGE_URLS_LIMIT = 4
EDGE_TELEGRAM_DOMAINS = ("telegram.org", "telegram.me", "t.me", "telegram.dog", "telesco.pe", "tdesktop.com",
                         "telegra.ph", "graph.org", "fragment.com")
EDGE_URL = re.compile(r"wss://([a-z0-9.-]+)(?::([0-9]{1,5}))?(/[A-Za-z0-9._~/-]*)")
EDGE_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def parse_edge_urls(value):
    """The build's edges (PLUMA_EDGE_WS_URLS): 0 to 4 wss:// URLs of host names, in the order tried."""
    value = value.strip()
    if not value:
        return []
    urls = [u.strip() for u in value.split(",")]
    if len(urls) > EDGE_URLS_LIMIT:
        raise PatchError(f"PLUMA_EDGE_WS_URLS: {len(urls)} URLs, at most {EDGE_URLS_LIMIT}")
    for url in urls:
        m = EDGE_URL.fullmatch(url)
        if not m:
            raise PatchError(f"PLUMA_EDGE_WS_URLS: {url!r} is not wss://<host>[:port]/<path> in lowercase")
        host, port = m.group(1), m.group(2)
        labels = host.split(".")
        if (len(host) > 253 or len(labels) < 2 or not all(EDGE_HOST_LABEL.fullmatch(l) for l in labels)
                or labels[-1].isdigit()):
            raise PatchError(f"PLUMA_EDGE_WS_URLS: {url!r}: the host must be a name, not an address")
        if any(host == d or host.endswith("." + d) for d in EDGE_TELEGRAM_DOMAINS):
            raise PatchError(f"PLUMA_EDGE_WS_URLS: {url!r} is a host of Telegram")
        if port is not None and not 0 < int(port) < 65536:
            raise PatchError(f"PLUMA_EDGE_WS_URLS: {url!r}: the port is not a port")
    if len(set(urls)) != len(urls):
        raise PatchError("PLUMA_EDGE_WS_URLS: a URL is there twice")
    return urls


EDGE_TGNET = "TMessagesProj/jni/tgnet"
EDGE_JAVA_DIR = "TMessagesProj/src/main/java/org/telegram"
EDGE_MANAGER_CPP = f"{EDGE_TGNET}/ConnectionsManager.cpp"
EDGE_DATACENTER_CPP = f"{EDGE_TGNET}/Datacenter.cpp"
EDGE_DATACENTER_H = f"{EDGE_TGNET}/Datacenter.h"
EDGE_CONNECTION_CPP = f"{EDGE_TGNET}/Connection.cpp"
EDGE_SOCKET_CPP = f"{EDGE_TGNET}/ConnectionSocket.cpp"
EDGE_MANAGER_H = f"{EDGE_TGNET}/ConnectionsManager.h"
EDGE_WRAPPER = "TMessagesProj/jni/TgNetWrapper.cpp"
EDGE_SOCKET_H = f"{EDGE_TGNET}/ConnectionSocket.h"
EDGE_DEFINES = f"{EDGE_TGNET}/Defines.h"
EDGE_MANAGER_JAVA = f"{EDGE_JAVA_DIR}/tgnet/ConnectionsManager.java"
EDGE_MESSAGES = f"{EDGE_JAVA_DIR}/messenger/MessagesController.java"
EDGE_FILE = f"{EDGE_JAVA_DIR}/utils/proxy/PlumaEdgeBridge.java"
PATH_POLICY_FILE = f"{EDGE_JAVA_DIR}/utils/proxy/PlumaPathPolicy.java"
PATH_PROBER_FILE = f"{EDGE_JAVA_DIR}/utils/proxy/PlumaPathProber.java"
EDGE_LABEL = "pluma-edge-"
EDGE_BUILT_IN_LINE = "    private static final String[] BUILT_IN = {};\n"
# The end of DC 1 in initDatacenters as the tgnet edit above (A-002) writes it.
EDGE_INIT_ANCHOR = "        datacenters[1] = datacenter;\n    }\n}\n"

EDGE_JAVA = r"""package org.telegram.utils.proxy;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.SystemClock;

import com.neovisionaries.ws.client.WebSocket;
import com.neovisionaries.ws.client.WebSocketAdapter;
import com.neovisionaries.ws.client.WebSocketException;
import com.neovisionaries.ws.client.WebSocketFactory;
import com.neovisionaries.ws.client.WebSocketFrame;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.telegram.messenger.ApplicationLoader;
import org.telegram.messenger.FileLog;
import org.telegram.messenger.UserConfig;
import org.telegram.tgnet.ConnectionsManager;
import org.telegram.tgnet.TLRPC;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

// The server's edges (task 109 of the Pluma server, ADR 0072): a local bridge per
// edge on 127.0.0.1, which tgnet reaches through the edge's address label of DC 1.
// Each connection tgnet opens to a bridge is one WebSocket to its edge
// (wss://<host>/apiws, protocol "binary"), carrying the bytes of the connection as
// they are, both ways. The edges are the build's, or the ones the server gives in
// the app config (pluma_edge).
public final class PlumaEdgeBridge {
    private static final String[] BUILT_IN = {};
    private static final int BUILT_IN_STICKY_S = 1800;
    private static final String APP_CONFIG_KEY = "pluma_edge";
    private static final String PREFERENCES = "pluma_edge";
    private static final String PREFERENCES_KEY = "settings";
    private static final int MAX_EDGES = 4;
    private static final int MIN_STICKY_S = 60;
    private static final int MAX_STICKY_S = 86400;
    // One message of the WebSocket at most; tgnet's bytes go as they are read.
    private static final int MAX_MESSAGE = 64 * 1024;
    private static final int MAX_CONNECTIONS = 64;
    private static final int FRAME_QUEUE = 16;
    private static final int CONNECT_TIMEOUT = 10_000;
    // No byte from the edge for this long (the server pings every 20 s): the connection is dead.
    private static final long SILENCE = 45_000;
    private static final long WATCH_PERIOD = 5_000;

    private static final Object lock = new Object();
    private static final ExecutorService io = Executors.newCachedThreadPool();
    private static final ScheduledExecutorService timer = Executors.newSingleThreadScheduledExecutor();
    private static final boolean[] attached = new boolean[UserConfig.MAX_ACCOUNT_COUNT];
    private static final List<Edge> edges = new ArrayList<>();
    private static Settings settings;
    private static boolean started;
    private static ScheduledFuture<?> stickyReturn;

    private PlumaEdgeBridge() {
    }

    // ConnectionsManager.init of an account, before native_init: the account's tgnet takes the
    // edges, and the order of the paths PlumaPathProber chose, from now on.
    public static void attach(int account) {
        synchronized (lock) {
            start();
            attached[account] = true;
            ConnectionsManager.native_setPlumaEdges(account, ports(), PlumaPathProber.order(settings.urls, settings.edgesFirst),
                    PlumaPathProber.suspectMs(), false);
        }
    }

    // PlumaPathProber chose another order of the paths: every account's tgnet takes it; with
    // reconnect, the connections of DC 1 open again on the first path of the new order.
    static void reorder(boolean reconnect) {
        synchronized (lock) {
            if (started) {
                push(reconnect);
            }
        }
    }

    // The paths in the order of pluma_edge (or of the build): "direct" and the URL of each edge.
    static List<String> paths() {
        synchronized (lock) {
            Settings current = started ? settings : loadSettings();
            List<String> paths = new ArrayList<>(current.urls);
            paths.add(current.edgesFirst ? paths.size() : 0, PlumaPathProber.DIRECT);
            return paths;
        }
    }

    // The accounts whose tgnet takes the edges.
    static List<Integer> attachedAccounts() {
        synchronized (lock) {
            List<Integer> accounts = new ArrayList<>();
            for (int a = 0; a < attached.length; a++) {
                if (attached[a]) {
                    accounts.add(a);
                }
            }
            return accounts;
        }
    }

    // MessagesController.applyAppConfig: pluma_edge of help.getAppConfig, or the build's edges
    // when the key is absent or not valid.
    public static void applyAppConfig(TLRPC.TL_jsonObject object) {
        TLRPC.JSONValue value = null;
        for (TLRPC.TL_jsonObjectValue item : object.value) {
            if (APP_CONFIG_KEY.equals(item.key)) {
                value = item.value;
                break;
            }
        }
        Settings received = value != null ? Settings.parse(value) : null;
        timer.execute(() -> apply(received));
    }

    private static void start() {
        if (started) {
            return;
        }
        started = true;
        settings = loadSettings();
        bind(settings.urls);
        timer.scheduleWithFixedDelay(PlumaEdgeBridge::watch, WATCH_PERIOD, WATCH_PERIOD, TimeUnit.MILLISECONDS);
        PlumaPathProber.start();
    }

    private static void apply(Settings received) {
        synchronized (lock) {
            Settings next = received != null ? received : Settings.builtIn();
            if (started && !next.equals(settings)) {
                boolean rebind = !next.urls.equals(settings.urls);
                settings = next;
                if (rebind) {
                    bind(next.urls);
                }
                if (next.edgesFirst && stickyReturn != null) {
                    stickyReturn.cancel(false);
                    stickyReturn = null;
                }
                push(false);
                PlumaPathProber.onPathsChanged();
            }
            storeSettings(received);
        }
    }

    // Under the lock: the ports of the bridges and the order of the paths to every account's tgnet.
    private static void push(boolean reconnect) {
        int[] ports = ports();
        int[] order = PlumaPathProber.order(settings.urls, settings.edgesFirst);
        int suspectMs = PlumaPathProber.suspectMs();
        for (int a = 0; a < attached.length; a++) {
            if (attached[a]) {
                ConnectionsManager.native_setPlumaEdges(a, ports, order, suspectMs, reconnect);
            }
        }
    }

    // Under the lock: a bridge per URL, in their order; an edge that stays keeps its port.
    private static void bind(List<String> urls) {
        List<Edge> next = new ArrayList<>();
        for (String url : urls) {
            Edge kept = null;
            for (Edge edge : edges) {
                if (edge.url.equals(url)) {
                    kept = edge;
                    break;
                }
            }
            next.add(kept != null ? kept : Edge.open(url));
        }
        for (Edge edge : edges) {
            if (!next.contains(edge)) {
                edge.close();
            }
        }
        edges.clear();
        edges.addAll(next);
    }

    // Under the lock: the port of each edge's bridge, 0 for one that could not listen.
    private static int[] ports() {
        int[] ports = new int[edges.size()];
        for (int i = 0; i < ports.length; i++) {
            ports[i] = edges.get(i).port();
        }
        return ports;
    }

    // Under the lock: tgnet went through an edge; sticky_s later its next connection tries the
    // direct address first again. Not while PlumaPathProber chooses the path: its memory and
    // measurements take the place of sticky_s (task 113).
    private static void onEdgeUsed() {
        if (settings.edgesFirst || stickyReturn != null || PlumaPathProber.selecting()) {
            return;
        }
        stickyReturn = timer.schedule(PlumaEdgeBridge::returnToDirect, settings.stickyS, TimeUnit.SECONDS);
    }

    private static void returnToDirect() {
        synchronized (lock) {
            stickyReturn = null;
            if (PlumaPathProber.selecting()) {
                return;
            }
            for (int a = 0; a < attached.length; a++) {
                if (attached[a]) {
                    ConnectionsManager.native_returnFromPlumaEdge(a);
                }
            }
        }
    }

    private static void watch() {
        long now = SystemClock.elapsedRealtime();
        List<Connection> silent = new ArrayList<>();
        synchronized (lock) {
            for (Edge edge : edges) {
                for (Connection connection : edge.connections) {
                    if (now - connection.lastReceived > SILENCE) {
                        silent.add(connection);
                    }
                }
            }
        }
        for (Connection connection : silent) {
            connection.close();
        }
    }

    private static Settings loadSettings() {
        try {
            SharedPreferences preferences = ApplicationLoader.applicationContext.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE);
            String stored = preferences.getString(PREFERENCES_KEY, null);
            Settings loaded = stored != null ? Settings.fromJson(stored) : null;
            if (loaded != null) {
                return loaded;
            }
        } catch (RuntimeException e) {
            FileLog.e(e);
        }
        return Settings.builtIn();
    }

    private static void storeSettings(Settings received) {
        try {
            SharedPreferences.Editor editor = ApplicationLoader.applicationContext.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE).edit();
            if (received != null) {
                editor.putString(PREFERENCES_KEY, received.toJson());
            } else {
                editor.remove(PREFERENCES_KEY);
            }
            editor.apply();
        } catch (RuntimeException e) {
            FileLog.e(e);
        }
    }

    private static void closeQuietly(Closeable closeable) {
        if (closeable == null) {
            return;
        }
        try {
            closeable.close();
        } catch (IOException ignore) {
        }
    }

    private static final class Settings {
        final List<String> urls;
        final boolean edgesFirst;
        final int stickyS;

        private Settings(List<String> urls, boolean edgesFirst, int stickyS) {
            this.urls = Collections.unmodifiableList(new ArrayList<>(urls));
            this.edgesFirst = edgesFirst;
            this.stickyS = stickyS;
        }

        // The build's edges: the direct address first.
        static Settings builtIn() {
            return new Settings(Arrays.asList(BUILT_IN), false, BUILT_IN_STICKY_S);
        }

        // {"v":1,"ws":["wss://…"],"order":["direct","edge"],"sticky_s":1800}; null if not valid.
        static Settings parse(TLRPC.JSONValue value) {
            if (!(value instanceof TLRPC.TL_jsonObject)) {
                return null;
            }
            double version = Double.NaN;
            double sticky = Double.NaN;
            List<String> urls = null;
            List<String> order = null;
            for (TLRPC.TL_jsonObjectValue item : ((TLRPC.TL_jsonObject) value).value) {
                switch (item.key) {
                    case "v":
                        version = number(item.value);
                        break;
                    case "ws":
                        urls = strings(item.value);
                        break;
                    case "order":
                        order = strings(item.value);
                        break;
                    case "sticky_s":
                        sticky = number(item.value);
                        break;
                }
            }
            return of(version, urls, order, sticky);
        }

        static Settings fromJson(String text) {
            try {
                JSONObject object = new JSONObject(text);
                return of(object.getDouble("v"), strings(object.getJSONArray("ws")),
                        strings(object.getJSONArray("order")), object.getDouble("sticky_s"));
            } catch (JSONException e) {
                return null;
            }
        }

        String toJson() {
            try {
                JSONObject object = new JSONObject();
                object.put("v", 1);
                object.put("ws", new JSONArray(urls));
                object.put("order", new JSONArray(edgesFirst ? Arrays.asList("edge", "direct") : Arrays.asList("direct", "edge")));
                object.put("sticky_s", stickyS);
                return object.toString();
            } catch (JSONException e) {
                throw new IllegalStateException(e);
            }
        }

        private static Settings of(double version, List<String> urls, List<String> order, double sticky) {
            if (version != 1 || urls == null || order == null) {
                return null;
            }
            if (urls.isEmpty() || urls.size() > MAX_EDGES || new HashSet<>(urls).size() != urls.size()) {
                return null;
            }
            for (String url : urls) {
                if (!isEdgeUrl(url)) {
                    return null;
                }
            }
            if (order.size() != 2 || !new HashSet<>(order).equals(new HashSet<>(Arrays.asList("direct", "edge")))) {
                return null;
            }
            if (sticky != Math.rint(sticky) || sticky < MIN_STICKY_S || sticky > MAX_STICKY_S) {
                return null;
            }
            return new Settings(urls, order.get(0).equals("edge"), (int) sticky);
        }

        private static boolean isEdgeUrl(String url) {
            try {
                URI uri = new URI(url);
                return "wss".equals(uri.getScheme()) && uri.getHost() != null && !uri.getHost().isEmpty()
                        && uri.getRawUserInfo() == null && uri.getRawQuery() == null && uri.getRawFragment() == null
                        && uri.getRawPath() != null && uri.getRawPath().startsWith("/")
                        && (uri.getPort() == -1 || uri.getPort() > 0 && uri.getPort() < 65536);
            } catch (URISyntaxException e) {
                return false;
            }
        }

        private static double number(TLRPC.JSONValue value) {
            return value instanceof TLRPC.TL_jsonNumber ? ((TLRPC.TL_jsonNumber) value).value : Double.NaN;
        }

        private static List<String> strings(TLRPC.JSONValue value) {
            if (!(value instanceof TLRPC.TL_jsonArray)) {
                return null;
            }
            List<String> out = new ArrayList<>();
            for (TLRPC.JSONValue item : ((TLRPC.TL_jsonArray) value).value) {
                if (!(item instanceof TLRPC.TL_jsonString)) {
                    return null;
                }
                out.add(((TLRPC.TL_jsonString) item).value);
            }
            return out;
        }

        private static List<String> strings(JSONArray array) throws JSONException {
            List<String> out = new ArrayList<>();
            for (int i = 0; i < array.length(); i++) {
                out.add(array.getString(i));
            }
            return out;
        }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof Settings)) {
                return false;
            }
            Settings other = (Settings) o;
            return urls.equals(other.urls) && edgesFirst == other.edgesFirst && stickyS == other.stickyS;
        }

        @Override
        public int hashCode() {
            return (urls.hashCode() * 31 + (edgesFirst ? 1 : 0)) * 31 + stickyS;
        }
    }

    private static final class Edge {
        final String url;
        final String host;
        final ServerSocket server;
        final Set<Connection> connections = new HashSet<>();
        boolean closed;

        private Edge(String url, ServerSocket server) {
            this.url = url;
            this.host = URI.create(url).getHost();
            this.server = server;
        }

        static Edge open(String url) {
            ServerSocket server = null;
            try {
                server = new ServerSocket(0, MAX_CONNECTIONS, InetAddress.getByName("127.0.0.1"));
            } catch (IOException e) {
                FileLog.e(e);
            }
            Edge edge = new Edge(url, server);
            if (server != null) {
                io.execute(edge::acceptLoop);
            }
            return edge;
        }

        int port() {
            return server != null ? server.getLocalPort() : 0;
        }

        private void acceptLoop() {
            while (true) {
                Socket socket;
                try {
                    socket = server.accept();
                } catch (IOException e) {
                    synchronized (lock) {
                        if (!closed) {
                            FileLog.e(e);
                        }
                    }
                    return;
                }
                Connection connection = new Connection(this, socket);
                synchronized (lock) {
                    if (closed || connections.size() >= MAX_CONNECTIONS) {
                        closeQuietly(socket);
                        continue;
                    }
                    connections.add(connection);
                    onEdgeUsed();
                }
                io.execute(connection::run);
            }
        }

        // Under the lock.
        void close() {
            closed = true;
            closeQuietly(server);
            for (Connection connection : new ArrayList<>(connections)) {
                connection.close();
            }
            connections.clear();
        }
    }

    // One connection of tgnet: its local socket and its WebSocket to the edge.
    private static final class Connection extends WebSocketAdapter {
        private final Edge edge;
        private final Socket local;
        private volatile WebSocket socket;
        private volatile boolean open;
        private volatile long lastReceived = SystemClock.elapsedRealtime();
        private boolean closed;

        Connection(Edge edge, Socket local) {
            this.edge = edge;
            this.local = local;
        }

        void run() {
            try {
                local.setTcpNoDelay(true);
                WebSocket ws = new WebSocketFactory()
                        .setConnectionTimeout(CONNECT_TIMEOUT)
                        .setSocketTimeout((int) SILENCE)
                        .setServerName(edge.host)
                        .createSocket(edge.url);
                ws.addProtocol("binary");
                ws.addHeader("User-Agent", "Pluma");
                ws.setFrameQueueSize(FRAME_QUEUE);
                ws.addListener(this);
                synchronized (lock) {
                    if (closed) {
                        return;
                    }
                    socket = ws;
                }
                ws.connect();
                open = true;
                synchronized (lock) {
                    if (closed) {
                        ws.disconnect();
                        return;
                    }
                }
                lastReceived = SystemClock.elapsedRealtime();
                InputStream in = local.getInputStream();
                byte[] buffer = new byte[MAX_MESSAGE];
                int count;
                while ((count = in.read(buffer)) > 0) {
                    ws.sendBinary(Arrays.copyOf(buffer, count));
                }
            } catch (IOException | WebSocketException | RuntimeException e) {
                // The edge or tgnet went away; both sides close.
            } finally {
                close();
            }
        }

        @Override
        public void onFrame(WebSocket websocket, WebSocketFrame frame) {
            lastReceived = SystemClock.elapsedRealtime();
        }

        @Override
        public void onBinaryMessage(WebSocket websocket, byte[] binary) {
            lastReceived = SystemClock.elapsedRealtime();
            try {
                local.getOutputStream().write(binary);
            } catch (IOException e) {
                close();
            }
        }

        @Override
        public void onDisconnected(WebSocket websocket, WebSocketFrame serverCloseFrame, WebSocketFrame clientCloseFrame, boolean closedByServer) {
            close();
        }

        void close() {
            WebSocket ws;
            synchronized (lock) {
                if (closed) {
                    return;
                }
                closed = true;
                edge.connections.remove(this);
                ws = socket;
            }
            closeQuietly(local);
            if (ws != null) {
                if (open) {
                    ws.disconnect();
                } else {
                    closeQuietly(ws.getSocket());
                }
            }
        }
    }
}
"""

# A-129 (task 113 of the server repository, ADR 0073): the choice of the path by the gateway's
# probe. PlumaPathPolicy holds the rules and the probe's bytes, plain Java that ci/patch_test.py
# runs on a JVM; PlumaPathProber runs them on the device. The direct address is the build's, the
# one the tgnet edit (A-002) gives DC 1.
PATH_POLICY_JAVA = r"""package org.telegram.utils.proxy;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

// The rules of the choice of the path to the server (task 113 of the Pluma server, ADR 0073):
// the probe the gateway answers before the key exchange, the measure of one probe, the score of a
// path, the memory per network and the decisions that switch paths. Plain Java, no Android: it
// runs as it is on a JVM.
final class PlumaPathPolicy {
    static final String DIRECT = "direct";
    // The score is the time of an answer of this size (an average piece of media).
    static final int SCORE_BYTES = 256 * 1024;
    // Scores within 30 % of the best are a tie, which pluma_edge's order breaks.
    static final double TIE = 1.3;
    // A path with 2 probes that were not ok among its last 4 in a network scores twice as high.
    static final int LOSS_WINDOW = 4;
    static final int LOSS_LIMIT = 2;
    static final int MAX_NETWORKS = 16;
    static final long FRESH_MS = 7L * 24 * 60 * 60 * 1000;
    // A second winning measurement confirms the first within this many confirm_s.
    static final int CONFIRM_SLACK = 3;

    private PlumaPathPolicy() {
    }

    // --- pluma_probe ------------------------------------------------------------------------

    // The settings of pluma_probe: the numbers of the brief's section 7, with its defaults and
    // the ranges bff accepts (app/bff/configuration/internal/appconfig/probe.go).
    static final class Params {
        static final String[] NAMES = {"gate_down", "rank_down", "up", "stall_ms", "deadline_ms", "suspect_ms",
                "reprobe_s", "rank_min_interval_s", "min_dwell_s", "switch_ratio", "switch_ratio_now",
                "edge_probe_if_direct_ms", "bad_ttl_s", "failed_ttl_s", "race_stagger_ms", "confirm_s"};
        static final double[] DEFAULTS = {65536, 196608, 20480, 1500, 6000, 4000,
                21600, 1800, 600, 0.7, 0.25,
                1500, 86400, 300, 800, 60};
        static final double[] MIN = {16384, 16384, 0, 300, 1000, 1000,
                600, 60, 0, 0.05, 0.05,
                100, 60, 10, 0, 10};
        static final double[] MAX = {524288, 524288, 65536, 10000, 30000, 30000,
                604800, 86400, 86400, 0.95, 0.95,
                60000, 604800, 86400, 10000, 3600};
        private static final int SWITCH_RATIO = 9;
        private static final int SWITCH_RATIO_NOW = 10;

        final String country;
        private final double[] values;

        private Params(String country, double[] values) {
            this.country = country;
            this.values = values;
        }

        static Params defaults() {
            return new Params("", DEFAULTS.clone());
        }

        // pluma_probe as a map of its fields (numbers as Double, strings as String); null if it
        // is not valid. A field it does not have takes its default; a field it has must be in
        // range, a whole number but for the ratios; the deadline is longer than the stall and
        // the ratio that switches at once is below the one that switches after two probes.
        static Params of(Map<String, Object> fields) {
            Object version = fields.get("v");
            if (!(version instanceof Double) || (Double) version != 1) {
                return null;
            }
            String country = "";
            Object c = fields.get("country");
            if (c != null) {
                if (!(c instanceof String) || !((String) c).isEmpty() && !((String) c).matches("[A-Z]{2}")) {
                    return null;
                }
                country = (String) c;
            }
            double[] values = new double[NAMES.length];
            for (int i = 0; i < NAMES.length; i++) {
                Object x = fields.get(NAMES[i]);
                double value = x == null ? DEFAULTS[i] : x instanceof Double ? (Double) x : Double.NaN;
                boolean ratio = i == SWITCH_RATIO || i == SWITCH_RATIO_NOW;
                if (!(value >= MIN[i] && value <= MAX[i]) || !ratio && value != Math.rint(value)) {
                    return null;
                }
                values[i] = value;
            }
            Params p = new Params(country, values);
            if (p.deadlineMs() <= p.stallMs() || p.switchRatioNow() >= p.switchRatio()) {
                return null;
            }
            return p;
        }

        int gateDown() { return (int) values[0]; }
        int rankDown() { return (int) values[1]; }
        int up() { return (int) values[2]; }
        long stallMs() { return (long) values[3]; }
        long deadlineMs() { return (long) values[4]; }
        int suspectMs() { return (int) values[5]; }
        long reprobeMs() { return (long) values[6] * 1000; }
        long rankMinIntervalMs() { return (long) values[7] * 1000; }
        long minDwellMs() { return (long) values[8] * 1000; }
        double switchRatio() { return values[SWITCH_RATIO]; }
        double switchRatioNow() { return values[SWITCH_RATIO_NOW]; }
        double edgeProbeIfDirectMs() { return values[11]; }
        long badTtlMs() { return (long) values[12] * 1000; }
        long failedTtlMs() { return (long) values[13] * 1000; }
        long raceStaggerMs() { return (long) values[14]; }
        long confirmMs() { return (long) values[15] * 1000; }

        // One "name=value" per line, the country first; read back by fromText.
        String toText() {
            StringBuilder out = new StringBuilder("country=").append(country).append('\n');
            for (int i = 0; i < NAMES.length; i++) {
                out.append(NAMES[i]).append('=').append(values[i]).append('\n');
            }
            return out.toString();
        }

        // null if the text is not one toText wrote.
        static Params fromText(String text) {
            Map<String, Object> fields = new HashMap<>();
            fields.put("v", 1.0);
            for (String line : text.split("\n")) {
                int eq = line.indexOf('=');
                if (eq < 0) {
                    return null;
                }
                String name = line.substring(0, eq);
                String value = line.substring(eq + 1);
                if (name.equals("country")) {
                    fields.put(name, value);
                } else {
                    try {
                        fields.put(name, Double.parseDouble(value));
                    } catch (NumberFormatException e) {
                        return null;
                    }
                }
            }
            return of(fields);
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof Params && country.equals(((Params) o).country) && Arrays.equals(values, ((Params) o).values);
        }

        @Override
        public int hashCode() {
            return country.hashCode() * 31 + Arrays.hashCode(values);
        }
    }

    // --- the probe ------------------------------------------------------------------------------
    // Both messages are unencrypted MTProto messages (auth_key_id 0, msg_id, length, data), one
    // per frame of the transport, little-endian; the constructors are the CRC32 of their TL lines
    // (the gateway's pkg/mtserver/handshake/probe.go):
    //   pluma.probe#5c316d30 nonce:int128 down:int pad:bytes = pluma.Probe;
    //   pluma.probeData#6ab3780b nonce:int128 seq:int total:int server_ms:long pad:bytes = pluma.ProbeData;
    // The client sends req_pq_multi, waits for resPQ and sends pluma.probe on the same
    // connection; the gateway answers with ceil(D / 16384) pluma.probeData in seq order, D being
    // down clamped to [16384, 524288], each pad 16384 bytes but the last, which holds the rest.

    static final int REQ_PQ_MULTI = 0xbe7e8ef1;
    static final int RES_PQ = 0x05162463;
    static final int PROBE = 0x5c316d30;
    static final int PROBE_DATA = 0x6ab3780b;
    static final int CHUNK = 16384;
    static final int MIN_DOWN = 16384;
    static final int MAX_DOWN = 524288;
    static final int MAX_UP = 65536;
    // The intermediate transport inside obfuscated2: 0xeeeeeeee.
    static final byte TAG = (byte) 0xee;
    // Larger than any frame of a probe's answer.
    static final int MAX_FRAME = 64 * 1024;

    static int clampDown(int down) {
        return Math.max(MIN_DOWN, Math.min(MAX_DOWN, down));
    }

    static int chunks(int down) {
        return (clampDown(down) + CHUNK - 1) / CHUNK;
    }

    // A client msg_id of unixMs: seconds in the high half, a fraction in the low, a multiple of 4.
    static long msgId(long unixMs) {
        return (unixMs / 1000) << 32 | ((unixMs % 1000) << 32) / 1000 & ~3L;
    }

    static byte[] reqPqMulti(long msgId, byte[] nonce) {
        ByteBuffer body = little(20);
        body.putInt(REQ_PQ_MULTI).put(nonce);
        return unencrypted(msgId, body.array());
    }

    static byte[] probe(long msgId, byte[] nonce, int down, byte[] pad) {
        byte[] bytes = tlBytes(pad);
        ByteBuffer body = little(24 + bytes.length);
        body.putInt(PROBE).put(nonce).putInt(down).put(bytes);
        return unencrypted(msgId, body.array());
    }

    static byte[] unencrypted(long msgId, byte[] body) {
        ByteBuffer out = little(20 + body.length);
        out.putLong(0).putLong(msgId).putInt(body.length).put(body);
        return out.array();
    }

    // TL bytes: a length byte under 254, else 0xfe and 3 bytes of length; the data; zeros to a
    // multiple of 4.
    static byte[] tlBytes(byte[] data) {
        int head = data.length < 254 ? 1 : 4;
        byte[] out = new byte[(head + data.length + 3) / 4 * 4];
        if (head == 1) {
            out[0] = (byte) data.length;
        } else {
            out[0] = (byte) 0xfe;
            out[1] = (byte) data.length;
            out[2] = (byte) (data.length >> 8);
            out[3] = (byte) (data.length >> 16);
        }
        System.arraycopy(data, 0, out, head, data.length);
        return out;
    }

    static int tlBytesLength(int length) {
        return ((length < 254 ? 1 : 4) + length + 3) / 4 * 4;
    }

    // A frame of the intermediate transport: the length, little-endian, and the payload.
    static byte[] frame(byte[] payload) {
        return little(4 + payload.length).putInt(payload.length).put(payload).array();
    }

    private static ByteBuffer little(int size) {
        return ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN);
    }

    // obfuscated2 without a secret, as tgnet makes it (Connection.cpp, sendData): 64 random
    // bytes that do not look like another protocol, the tag at 56; the client encrypts with the
    // key and IV of bytes 8-55 and decrypts with those of the same bytes reversed; the header
    // goes out with its last 8 bytes encrypted.
    static final class Obfuscation {
        final byte[] header;
        private final Cipher encrypt;
        private final Cipher decrypt;

        private Obfuscation(byte[] header, Cipher encrypt, Cipher decrypt) {
            this.header = header;
            this.encrypt = encrypt;
            this.decrypt = decrypt;
        }

        static Obfuscation create(SecureRandom random) throws GeneralSecurityException {
            byte[] bytes = new byte[64];
            while (true) {
                random.nextBytes(bytes);
                ByteBuffer b = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
                int first = b.getInt(0);
                if (bytes[0] != (byte) 0xef && first != 0x44414548 && first != 0x54534f50 && first != 0x20544547
                        && first != 0x4954504f && first != 0xeeeeeeee && first != 0xdddddddd && first != 0x02010316
                        && b.getInt(4) != 0) {
                    break;
                }
            }
            bytes[56] = bytes[57] = bytes[58] = bytes[59] = TAG;
            byte[] reversed = new byte[48];
            for (int a = 0; a < 48; a++) {
                reversed[a] = bytes[55 - a];
            }
            Cipher encrypt = ctr(Arrays.copyOfRange(bytes, 8, 40), Arrays.copyOfRange(bytes, 40, 56));
            Cipher decrypt = ctr(Arrays.copyOfRange(reversed, 0, 32), Arrays.copyOfRange(reversed, 32, 48));
            byte[] sealed = encrypt.update(bytes);
            byte[] header = bytes.clone();
            System.arraycopy(sealed, 56, header, 56, 8);
            return new Obfuscation(header, encrypt, decrypt);
        }

        static Cipher ctr(byte[] key, byte[] iv) throws GeneralSecurityException {
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            return cipher;
        }

        byte[] seal(byte[] plain) {
            byte[] out = encrypt.update(plain);
            return out != null ? out : new byte[0];
        }

        byte[] open(byte[] data, int offset, int length) {
            byte[] out = decrypt.update(data, offset, length);
            return out != null ? out : new byte[0];
        }
    }

    // The answer of the gateway, decrypted, as it comes: frames of the intermediate transport,
    // resPQ to req_pq_multi first, then pluma.probeData. Anything else is a protocol error.
    static final class Reader {
        private final byte[] requestNonce;
        private final byte[] probeNonce;
        private final int total;
        private final int lastPad;
        private final byte[] head = new byte[4];
        private int headFill;
        private byte[] body;
        private int bodyFill;
        boolean resPq;
        int received;
        boolean done;
        String error;

        Reader(byte[] requestNonce, byte[] probeNonce, int down) {
            this.requestNonce = requestNonce;
            this.probeNonce = probeNonce;
            int d = clampDown(down);
            this.total = chunks(d);
            this.lastPad = d - CHUNK * (total - 1);
        }

        // Feeds the bytes and returns how many of them are the probe's answer: the bytes after
        // the frame of resPQ.
        int feed(byte[] data, int offset, int length) {
            int answer = 0;
            int end = offset + length;
            while (offset < end && error == null && !done) {
                boolean answering = resPq;
                int before = offset;
                if (body == null) {
                    int n = Math.min(4 - headFill, end - offset);
                    System.arraycopy(data, offset, head, headFill, n);
                    headFill += n;
                    offset += n;
                    if (headFill == 4) {
                        int size = ByteBuffer.wrap(head).order(ByteOrder.LITTLE_ENDIAN).getInt();
                        if (size < 20 + 4 || size > MAX_FRAME || size % 4 != 0) {
                            error = "frame of " + size + " bytes";
                        } else {
                            body = new byte[size];
                            bodyFill = 0;
                        }
                    }
                } else {
                    int n = Math.min(body.length - bodyFill, end - offset);
                    System.arraycopy(data, offset, body, bodyFill, n);
                    bodyFill += n;
                    offset += n;
                    if (bodyFill == body.length) {
                        message(body);
                        body = null;
                        headFill = 0;
                    }
                }
                if (answering) {
                    answer += offset - before;
                }
            }
            return answer;
        }

        private void message(byte[] frame) {
            ByteBuffer b = ByteBuffer.wrap(frame).order(ByteOrder.LITTLE_ENDIAN);
            long authKeyId = b.getLong();
            b.getLong();
            int length = b.getInt();
            if (authKeyId != 0 || length < 4 || length > frame.length - 20) {
                error = "not an unencrypted message";
                return;
            }
            int constructor = b.getInt();
            if (!resPq) {
                if (constructor != RES_PQ || length < 20 || !nonce(b, requestNonce)) {
                    error = "not resPQ to the request";
                    return;
                }
                resPq = true;
                return;
            }
            if (constructor != PROBE_DATA || length < 36 || !nonce(b, probeNonce)) {
                error = "not pluma.probeData of the probe";
                return;
            }
            int seq = b.getInt();
            int count = b.getInt();
            b.getLong();
            int pad = seq == total - 1 ? lastPad : CHUNK;
            if (seq != received || count != total || length != 36 + tlBytesLength(pad) || !padLength(b, pad)) {
                error = "chunk " + seq + " of " + count;
                return;
            }
            received++;
            done = received == total;
        }

        private static boolean nonce(ByteBuffer b, byte[] expected) {
            byte[] nonce = new byte[16];
            b.get(nonce);
            return Arrays.equals(nonce, expected);
        }

        private static boolean padLength(ByteBuffer b, int pad) {
            int first = b.get() & 0xff;
            if (pad < 254) {
                return first == pad;
            }
            int length = (b.get() & 0xff) | (b.get() & 0xff) << 8 | (b.get() & 0xff) << 16;
            return first == 0xfe && length == pad;
        }
    }

    // --- one probe ------------------------------------------------------------------------------

    enum Outcome {
        // All of the answer came.
        OK,
        // At the deadline part of the answer came, and it was still coming.
        SLOW,
        // The path gave a byte, then stall_ms passed with none and the answer is not complete.
        FROZEN,
        // No connection, a close, a protocol error, or no byte by the deadline.
        FAILED,
        // The gateway closed the connection right after a valid resPQ: it does not know the probe.
        UNSUPPORTED
    }

    // The times of one probe, in ms of one monotonic clock, and its outcome (the brief's section 2).
    static final class Measure {
        private final long stallMs;
        private final long deadlineMs;
        private final long start;
        private long connected = -1;
        private long lastByte = -1;
        private long requestSent = -1;
        private long resPqAt = -1;
        private long probeSent = -1;
        private long firstAnswer = -1;
        private long firstAnswerBytes;
        private long answerBytes;
        private boolean done;
        private boolean closed;
        private boolean error;

        Measure(Params p, long start) {
            this.stallMs = p.stallMs();
            this.deadlineMs = p.deadlineMs();
            this.start = start;
        }

        // The connection is up; answered: the path gave bytes on the way (the WebSocket handshake).
        void connected(long now, boolean answered) {
            connected = now;
            if (answered) {
                lastByte = now;
            }
        }

        void requestSent(long now) {
            requestSent = now;
        }

        void probeSent(long now) {
            probeSent = now;
        }

        // Bytes came: count of them, answer of which belong to the probe's answer.
        void received(long now, int count, int answer, Reader reader) {
            if (count <= 0) {
                return;
            }
            if (resPqAt < 0) {
                resPqAt = now;
            }
            lastByte = now;
            if (answer > 0) {
                if (firstAnswer < 0) {
                    firstAnswer = now;
                    firstAnswerBytes = answer;
                }
                answerBytes += answer;
            }
            if (reader.error != null) {
                error = true;
            }
            done = reader.done;
        }

        void closed() {
            closed = true;
        }

        void failed() {
            error = true;
        }

        boolean probeSent() {
            return probeSent >= 0;
        }

        // The outcome at now, null while the probe runs.
        Outcome outcome(long now) {
            if (done) {
                return Outcome.OK;
            }
            if (error) {
                return Outcome.FAILED;
            }
            if (closed) {
                return probeSent >= 0 && answerBytes == 0 && resPqAt >= 0 ? Outcome.UNSUPPORTED : Outcome.FAILED;
            }
            if (lastByte >= 0) {
                // The stall counts from the last byte, or from the write of the request plus the
                // time an answer takes, whichever is later: a request lost on its way up stalls too.
                long anchor = lastByte;
                if (probeSent >= 0) {
                    anchor = Math.max(anchor, probeSent + rtt());
                } else if (requestSent >= 0 && connected >= 0) {
                    anchor = Math.max(anchor, requestSent + (connected - start));
                }
                if (now - anchor >= stallMs) {
                    return Outcome.FROZEN;
                }
            }
            if (now - start >= deadlineMs) {
                return answerBytes > 0 ? Outcome.SLOW : Outcome.FAILED;
            }
            return null;
        }

        // From the write of req_pq_multi to the first byte of resPQ.
        long rtt() {
            return resPqAt >= 0 && requestSent >= 0 ? resPqAt - requestSent : -1;
        }

        // The answer's bytes after its first read over the time from that read to the last;
        // all of it over the time from the probe's write when it came in one read.
        double bytesPerSecond() {
            if (answerBytes == 0) {
                return 0;
            }
            if (lastByte > firstAnswer && answerBytes > firstAnswerBytes) {
                return (answerBytes - firstAnswerBytes) * 1000.0 / (lastByte - firstAnswer);
            }
            return answerBytes * 1000.0 / Math.max(1, lastByte - probeSent);
        }

        long answerBytes() {
            return answerBytes;
        }
    }

    // --- scores and decisions -------------------------------------------------------------------

    // rtt + 256 KiB at the path's speed, in ms.
    static double score(long rttMs, double bytesPerSecond) {
        if (rttMs < 0 || !(bytesPerSecond > 0)) {
            return Double.POSITIVE_INFINITY;
        }
        return rttMs + SCORE_BYTES * 1000.0 / bytesPerSecond;
    }

    static boolean passed(Outcome outcome) {
        return outcome == Outcome.OK || outcome == Outcome.SLOW;
    }

    // The path with the lowest score of those scored; among the scores within TIE of the lowest,
    // the first in order (pluma_edge's). null if none is scored.
    static String best(List<String> order, Map<String, Double> scores) {
        double min = Double.POSITIVE_INFINITY;
        for (String path : order) {
            Double s = scores.get(path);
            if (s != null && s < min) {
                min = s;
            }
        }
        if (min == Double.POSITIVE_INFINITY) {
            return null;
        }
        for (String path : order) {
            Double s = scores.get(path);
            if (s != null && s <= min * TIE) {
                return path;
            }
        }
        return null;
    }

    enum Decision {
        STAY,
        // A win by switch_ratio: measure again after confirm_s.
        CONFIRM,
        SWITCH
    }

    // Whether a measured candidate takes the place of the current path (the brief's section 4):
    // switch_ratio_now of the current score at once, switch_ratio twice in a row (confirmed), and
    // not within min_dwell_s of the last switch.
    static Decision decide(double current, double candidate, boolean confirmed, long sinceSwitchMs, Params p) {
        if (sinceSwitchMs < p.minDwellMs() || !(candidate < Double.POSITIVE_INFINITY)) {
            return Decision.STAY;
        }
        if (candidate <= p.switchRatioNow() * current) {
            return Decision.SWITCH;
        }
        if (candidate <= p.switchRatio() * current) {
            return confirmed ? Decision.SWITCH : Decision.CONFIRM;
        }
        return Decision.STAY;
    }

    // Whether a rank measures the edges besides the direct path and the current one: the country
    // puts the edges first, or the direct path did not pass or scores above edge_probe_if_direct_ms.
    static boolean rankEdges(boolean edgesFirst, Outcome direct, double directScore, Params p) {
        return edgesFirst || !passed(direct) || directScore > p.edgeProbeIfDirectMs();
    }

    // --- memory per network ---------------------------------------------------------------------

    static final class PathState {
        double score = Double.NaN;
        Outcome last;
        long time;
        // The last LOSS_WINDOW probes, newest in bit 0, 1 for one that was not ok.
        int history;
        int count;
        long excludedUntil;

        double effectiveScore() {
            if (Double.isNaN(score)) {
                return Double.POSITIVE_INFINITY;
            }
            int window = (1 << Math.min(count, LOSS_WINDOW)) - 1;
            return Integer.bitCount(history & window) >= LOSS_LIMIT ? score * 2 : score;
        }
    }

    static final class Network {
        String best;
        long used;
        long ranked;
        long switched;
        final Map<String, PathState> paths = new LinkedHashMap<>();

        PathState state(String path) {
            PathState s = paths.get(path);
            if (s == null) {
                s = new PathState();
                paths.put(path, s);
            }
            return s;
        }

        boolean excluded(String path, long now) {
            PathState s = paths.get(path);
            return s != null && s.excludedUntil > now;
        }

        boolean fresh(long now) {
            return used > 0 && now >= used && now - used <= FRESH_MS;
        }

        // A probe of path ended: frozen excludes it from races for bad_ttl_s, failed for
        // failed_ttl_s, ok clears both. The caller records nothing when every path of a race
        // failed: that is the network, not the paths.
        void record(String path, Outcome outcome, double score, long now, Params p) {
            PathState s = state(path);
            s.last = outcome;
            s.time = now;
            s.history = (s.history << 1 | (outcome == Outcome.OK ? 0 : 1)) & ((1 << LOSS_WINDOW) - 1);
            s.count = Math.min(LOSS_WINDOW, s.count + 1);
            if (passed(outcome)) {
                s.score = score;
            }
            if (outcome == Outcome.OK) {
                s.excludedUntil = 0;
            } else if (outcome == Outcome.FROZEN) {
                s.excludedUntil = now + p.badTtlMs();
            } else if (outcome == Outcome.FAILED) {
                s.excludedUntil = Math.max(s.excludedUntil, now + p.failedTtlMs());
            }
            used = now;
        }

        // The paths in the order tgnet tries them: the remembered best while the memory is fresh,
        // then the others in order (pluma_edge's), those excluded last.
        List<String> order(List<String> paths, long now) {
            List<String> out = new ArrayList<>();
            if (fresh(now) && best != null && paths.contains(best) && !excluded(best, now)) {
                out.add(best);
            }
            for (String path : paths) {
                if (!out.contains(path) && !excluded(path, now)) {
                    out.add(path);
                }
            }
            for (String path : paths) {
                if (!out.contains(path)) {
                    out.add(path);
                }
            }
            return out;
        }

        // The paths a race starts at once: the remembered best while fresh, else the first group
        // of pluma_edge's order (the edges when the country puts them first, else the direct
        // path), without those excluded; all paths not excluded if that leaves none.
        List<String> firstGroup(List<String> paths, long now) {
            if (fresh(now) && best != null && paths.contains(best) && !excluded(best, now)) {
                return Collections.singletonList(best);
            }
            boolean edgesFirst = !paths.isEmpty() && !paths.get(0).equals(DIRECT);
            List<String> group = new ArrayList<>();
            for (String path : paths) {
                if (path.equals(DIRECT) != edgesFirst && !excluded(path, now)) {
                    group.add(path);
                }
            }
            if (group.isEmpty()) {
                for (String path : paths) {
                    if (!excluded(path, now)) {
                        group.add(path);
                    }
                }
            }
            return group;
        }
    }

    // The networks by key, at most MAX_NETWORKS, the one used longest ago going first.
    static final class Memory {
        final Map<String, Network> networks = new LinkedHashMap<>();

        Network network(String key) {
            Network n = networks.get(key);
            if (n == null) {
                n = new Network();
                networks.put(key, n);
            }
            return n;
        }

        void prune() {
            while (networks.size() > MAX_NETWORKS) {
                String oldest = null;
                long used = Long.MAX_VALUE;
                for (Map.Entry<String, Network> e : networks.entrySet()) {
                    if (e.getValue().used < used) {
                        used = e.getValue().used;
                        oldest = e.getKey();
                    }
                }
                networks.remove(oldest);
            }
        }

        // A line per network ("n key best used ranked switched") followed by a line per path
        // ("p path score outcome time history count excludedUntil"), the strings URL-encoded.
        String toText() {
            StringBuilder out = new StringBuilder();
            for (Map.Entry<String, Network> e : networks.entrySet()) {
                Network n = e.getValue();
                out.append("n ").append(encode(e.getKey())).append(' ').append(n.best == null ? "-" : encode(n.best))
                        .append(' ').append(n.used).append(' ').append(n.ranked).append(' ').append(n.switched).append('\n');
                for (Map.Entry<String, PathState> p : n.paths.entrySet()) {
                    PathState s = p.getValue();
                    out.append("p ").append(encode(p.getKey())).append(' ').append(s.score).append(' ')
                            .append(s.last == null ? "-" : s.last.name()).append(' ').append(s.time).append(' ')
                            .append(s.history).append(' ').append(s.count).append(' ').append(s.excludedUntil).append('\n');
                }
            }
            return out.toString();
        }

        // An empty memory if the text is not one toText wrote: a lost memory costs one race.
        static Memory fromText(String text) {
            Memory m = new Memory();
            try {
                Network n = null;
                for (String line : text.split("\n")) {
                    if (line.isEmpty()) {
                        continue;
                    }
                    String[] f = line.split(" ", -1);
                    if (f[0].equals("n") && f.length == 6) {
                        n = m.network(decode(f[1]));
                        n.best = f[2].equals("-") ? null : decode(f[2]);
                        n.used = Long.parseLong(f[3]);
                        n.ranked = Long.parseLong(f[4]);
                        n.switched = Long.parseLong(f[5]);
                    } else if (f[0].equals("p") && f.length == 8 && n != null) {
                        PathState s = n.state(decode(f[1]));
                        s.score = Double.parseDouble(f[2]);
                        s.last = f[3].equals("-") ? null : Outcome.valueOf(f[3]);
                        s.time = Long.parseLong(f[4]);
                        s.history = Integer.parseInt(f[5]) & ((1 << LOSS_WINDOW) - 1);
                        s.count = Math.max(0, Math.min(LOSS_WINDOW, Integer.parseInt(f[6])));
                        s.excludedUntil = Long.parseLong(f[7]);
                    } else {
                        return new Memory();
                    }
                }
            } catch (IllegalArgumentException e) {
                return new Memory();
            }
            m.prune();
            return m;
        }

        private static String encode(String s) {
            try {
                return URLEncoder.encode(s, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                throw new IllegalStateException(e);
            }
        }

        private static String decode(String s) {
            try {
                return URLDecoder.decode(s, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                throw new IllegalStateException(e);
            }
        }
    }

    // The key of a network: the country of the client's address the server last gave, and a hash
    // of what the device sees of the network (the kind of transport and the parts the caller
    // gives: gateways, DNS servers, operator). Raw addresses are never kept.
    static String networkKey(String country, String transport, Collection<String> parts) {
        List<String> sorted = new ArrayList<>(parts);
        Collections.sort(sorted);
        StringBuilder text = new StringBuilder(transport);
        for (String part : sorted) {
            text.append('\n').append(part);
        }
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(text.toString().getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(country).append(':');
            for (int i = 0; i < 8; i++) {
                hex.append(String.format("%02x", hash[i] & 0xff));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
"""

PATH_PROBER_JAVA = r"""package org.telegram.utils.proxy;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.RouteInfo;
import android.os.Build;
import android.os.PowerManager;
import android.os.SystemClock;
import android.telephony.TelephonyManager;

import com.neovisionaries.ws.client.WebSocket;
import com.neovisionaries.ws.client.WebSocketAdapter;
import com.neovisionaries.ws.client.WebSocketException;
import com.neovisionaries.ws.client.WebSocketFactory;
import com.neovisionaries.ws.client.WebSocketFrame;

import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.ApplicationLoader;
import org.telegram.messenger.FileLog;
import org.telegram.messenger.MessagesController;
import org.telegram.tgnet.ConnectionsManager;
import org.telegram.tgnet.TLRPC;
import org.telegram.ui.Components.ForegroundDetector;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

// The path to the server (task 113 of the Pluma server, ADR 0073): the direct address of DC 1
// or an edge of PlumaEdgeBridge. A path is measured with the gateway's probe, more bytes than
// the stall of brief 092 lets through, on a connection of its own; tgnet connects at once by
// the order chosen from the memory of the network, and the race of the probes changes that
// order, and reconnects DC 1, when the first path does not pass and another does. Measurements
// in the background (at start, on a change of the network, when a request waits with no byte,
// every reprobe_s) switch to a path that is clearly better. One choice for all accounts of the
// process. No probe while a proxy of the user is on, nor after the gateway showed it does not
// know the probe, until the next pluma_probe: then the rules of task 109 hold.
public final class PlumaPathProber {
    static final String DIRECT = PlumaPathPolicy.DIRECT;
    // The direct address of DC 1, as the tgnet edit of the build writes it.
    private static final String DIRECT_IPV4 = "";
    private static final String DIRECT_IPV6 = "";
    private static final int DIRECT_PORT = 0;
    private static final String APP_CONFIG_KEY = "pluma_probe";
    private static final String PREFERENCES = "pluma_paths";
    private static final String PARAMS_KEY = "params";
    private static final String MEMORY_KEY = "networks";
    // A measurement waits this long after the first connection that passed, and runs again when
    // the app comes back after this long in the background (the brief's section 6).
    private static final long LAUNCH_RANK_DELAY = 5_000;
    private static final long BACKGROUND_RANK = 30 * 60_000L;
    private static final long NETWORK_RANK_INTERVAL = 120_000;
    private static final long SUSPECT_INTERVAL = 60_000;
    // A switch waits for a file transfer, at most this long.
    private static final long TRANSFER_RECENT = 3_000;
    private static final long TRANSFER_CHECK = 10_000;
    private static final long TRANSFER_DEFER = 120_000;
    // A race every path of which failed is the network: it runs again, while the app is on the
    // screen, after 5 s, then twice as long each time, at most a minute.
    private static final long RETRY_MIN = 5_000;
    private static final long RETRY_MAX = 60_000;
    private static final long NETWORK_SETTLE = 1_000;
    private static final long TICK = 60_000;
    private static final int READ_SLICE = 50;
    private static final int READ_BUFFER = 32 * 1024;

    private static final Object lock = new Object();
    private static final ScheduledExecutorService worker = Executors.newSingleThreadScheduledExecutor();
    private static final ExecutorService io = Executors.newCachedThreadPool();
    private static final SecureRandom random = new SecureRandom();

    // Under the lock; the bridge reads them for tgnet's order.
    private static boolean started;
    private static PlumaPathPolicy.Params params = PlumaPathPolicy.Params.defaults();
    private static String paramsText = "";
    private static PlumaPathPolicy.Memory memory = new PlumaPathPolicy.Memory();
    private static String networkKey = "";
    private static String current;
    private static boolean unsupported;

    // The worker's own.
    private static boolean gateRunning;
    private static boolean gateAgain;
    private static boolean rankRunning;
    private static boolean launchRanked;
    private static boolean networkRankDue;
    private static long retryDelay = RETRY_MIN;
    private static ScheduledFuture<?> retry;
    private static ScheduledFuture<?> networkCheck;
    private static ScheduledFuture<?> confirm;
    private static String pendingCandidate;
    private static long pendingAt;
    private static long lastNetworkRank;
    private static long lastSuspect;
    private static long backgroundSince = -1;
    private static volatile boolean foreground;
    private static boolean listening;
    private static String fingerprint = "";

    private PlumaPathProber() {
    }

    // PlumaEdgeBridge.start, under the bridge's lock: the memory, the network, the first race.
    static void start() {
        synchronized (lock) {
            if (started) {
                return;
            }
            started = true;
            SharedPreferences preferences = preferences();
            String text = preferences.getString(PARAMS_KEY, null);
            PlumaPathPolicy.Params stored = text != null ? PlumaPathPolicy.Params.fromText(text) : null;
            if (stored != null) {
                params = stored;
                paramsText = text;
            }
            memory = PlumaPathPolicy.Memory.fromText(preferences.getString(MEMORY_KEY, ""));
            fingerprint = fingerprint();
            networkKey = params.country + fingerprint;
        }
        worker.execute(() -> {
            listen();
            gate();
        });
        worker.scheduleWithFixedDelay(PlumaPathProber::tick, TICK, TICK, TimeUnit.MILLISECONDS);
    }

    // The order of the paths for tgnet, 0 the direct addresses and n + 1 the edge n of urls; the
    // current path first. Called by the bridge under its lock.
    static int[] order(List<String> urls, boolean edgesFirst) {
        List<String> paths = new ArrayList<>(urls);
        paths.add(edgesFirst ? paths.size() : 0, DIRECT);
        List<String> ordered;
        synchronized (lock) {
            if (!selecting()) {
                ordered = paths;
            } else {
                long now = System.currentTimeMillis();
                PlumaPathPolicy.Network n = memory.networks.get(networkKey);
                ordered = n != null ? n.order(paths, now) : paths;
                if (current == null || !paths.contains(current)) {
                    current = ordered.get(0);
                } else {
                    ordered.remove(current);
                    ordered.add(0, current);
                }
            }
        }
        int[] out = new int[ordered.size()];
        for (int i = 0; i < out.length; i++) {
            out[i] = ordered.get(i).equals(DIRECT) ? 0 : urls.indexOf(ordered.get(i)) + 1;
        }
        return out;
    }

    // How long a request of DC 1 waits with no byte before tgnet reports it; 0 never.
    static int suspectMs() {
        synchronized (lock) {
            return selecting() ? params.suspectMs() : 0;
        }
    }

    // Whether the probes choose the path now; otherwise the rules of task 109 (sticky_s) hold.
    static boolean selecting() {
        synchronized (lock) {
            return started && !unsupported && !proxied();
        }
    }

    // A proxy of the user is on, as ConnectionsManager.init reads it for tgnet.
    private static boolean proxied() {
        SharedPreferences main = ApplicationLoader.applicationContext.getSharedPreferences("mainconfig", Context.MODE_PRIVATE);
        return main.getBoolean("proxy_enabled", false) && ProxySettings.fromSharedPreferences(main).isValid();
    }

    // The bridge took other edges or another order of pluma_edge.
    static void onPathsChanged() {
        worker.execute(PlumaPathProber::gate);
    }

    // MessagesController.applyAppConfig: pluma_probe of help.getAppConfig; the built-in values
    // when it is absent or not valid.
    public static void applyAppConfig(TLRPC.TL_jsonObject object) {
        TLRPC.JSONValue value = null;
        for (TLRPC.TL_jsonObjectValue item : object.value) {
            if (APP_CONFIG_KEY.equals(item.key)) {
                value = item.value;
                break;
            }
        }
        PlumaPathPolicy.Params received = null;
        if (value instanceof TLRPC.TL_jsonObject) {
            Map<String, Object> fields = new HashMap<>();
            for (TLRPC.TL_jsonObjectValue item : ((TLRPC.TL_jsonObject) value).value) {
                if (item.value instanceof TLRPC.TL_jsonNumber) {
                    fields.put(item.key, ((TLRPC.TL_jsonNumber) item.value).value);
                } else if (item.value instanceof TLRPC.TL_jsonString) {
                    fields.put(item.key, ((TLRPC.TL_jsonString) item.value).value);
                } else {
                    fields.put(item.key, item.value);
                }
            }
            received = PlumaPathPolicy.Params.of(fields);
        }
        PlumaPathPolicy.Params next = received != null ? received : PlumaPathPolicy.Params.defaults();
        worker.execute(() -> applyParams(next));
    }

    // ConnectionsManager.onPlumaPathSuspect, on tgnet's thread: a request of DC 1 waits with no
    // byte for suspect_ms.
    public static void onSuspect(int account) {
        worker.execute(() -> {
            long now = SystemClock.elapsedRealtime();
            if (now - lastSuspect < SUSPECT_INTERVAL) {
                return;
            }
            lastSuspect = now;
            rank();
        });
    }

    // --- the worker ---------------------------------------------------------------------------

    private static void applyParams(PlumaPathPolicy.Params next) {
        boolean networkChanged;
        synchronized (lock) {
            String text = next.toText();
            if (text.equals(paramsText)) {
                return;
            }
            // Another pluma_probe: the gateway may know the probe now.
            unsupported = false;
            params = next;
            paramsText = text;
            preferences().edit().putString(PARAMS_KEY, text).apply();
            String key = next.country + fingerprint;
            networkChanged = !key.equals(networkKey);
            networkKey = key;
            if (networkChanged) {
                current = null;
            }
        }
        PlumaEdgeBridge.reorder(networkChanged);
        if (networkChanged) {
            networkRankDue = true;
        }
        gate();
    }

    private static void tick() {
        listen();
        PlumaPathPolicy.Network n;
        PlumaPathPolicy.Params p;
        synchronized (lock) {
            n = memory.networks.get(networkKey);
            p = params;
        }
        if (n != null && foreground && !saving() && System.currentTimeMillis() - n.ranked >= p.reprobeMs()) {
            rank();
        }
    }

    // The callbacks of the network and of the app's screen, once each; the screen's detector
    // exists only after ApplicationLoader.onCreate, so a later tick tries again.
    private static void listen() {
        if (listening) {
            return;
        }
        ForegroundDetector detector = ForegroundDetector.getInstance();
        if (detector == null) {
            return;
        }
        listening = true;
        foreground = detector.isForeground();
        detector.addListener(new ForegroundDetector.Listener() {
            @Override
            public void onBecameForeground() {
                worker.execute(PlumaPathProber::onForeground);
            }

            @Override
            public void onBecameBackground() {
                worker.execute(() -> {
                    foreground = false;
                    backgroundSince = SystemClock.elapsedRealtime();
                });
            }
        });
        try {
            ConnectivityManager manager = connectivity();
            ConnectivityManager.NetworkCallback callback = new ConnectivityManager.NetworkCallback() {
                @Override
                public void onAvailable(Network network) {
                    networkEvent();
                }

                @Override
                public void onLost(Network network) {
                    networkEvent();
                }

                @Override
                public void onCapabilitiesChanged(Network network, NetworkCapabilities capabilities) {
                    networkEvent();
                }

                @Override
                public void onLinkPropertiesChanged(Network network, LinkProperties properties) {
                    networkEvent();
                }
            };
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                manager.registerDefaultNetworkCallback(callback);
            } else {
                manager.registerNetworkCallback(new NetworkRequest.Builder()
                        .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET).build(), callback);
            }
        } catch (RuntimeException e) {
            FileLog.e(e);
        }
        if (foreground) {
            onForeground();
        }
    }

    private static void onForeground() {
        foreground = true;
        long away = backgroundSince < 0 ? 0 : SystemClock.elapsedRealtime() - backgroundSince;
        backgroundSince = -1;
        if (away >= BACKGROUND_RANK) {
            launchRanked = false;
        }
        worker.schedule(PlumaPathProber::rankIfDue, LAUNCH_RANK_DELAY, TimeUnit.MILLISECONDS);
    }

    private static void networkEvent() {
        worker.execute(() -> {
            if (networkCheck != null) {
                networkCheck.cancel(false);
            }
            networkCheck = worker.schedule(PlumaPathProber::onNetwork, NETWORK_SETTLE, TimeUnit.MILLISECONDS);
        });
    }

    // Another network: its memory gives tgnet's order, a race checks the first path, the app
    // config is read again for the country of the new address, and the paths are measured.
    private static void onNetwork() {
        networkCheck = null;
        String next = fingerprint();
        boolean changed;
        synchronized (lock) {
            changed = !next.equals(fingerprint);
            fingerprint = next;
            if (changed) {
                networkKey = params.country + next;
                current = null;
            }
        }
        if (!changed) {
            return;
        }
        PlumaEdgeBridge.reorder(true);
        for (int account : PlumaEdgeBridge.attachedAccounts()) {
            AndroidUtilities.runOnUIThread(() -> MessagesController.getInstance(account).loadAppConfig(true));
        }
        networkRankDue = true;
        retryDelay = RETRY_MIN;
        gate();
    }

    // The race of the gate probes (the brief's section 3). The current path, tgnet's first, is
    // already connecting: the race only confirms it, or replaces it with the first path that
    // passes when it does not pass, or does not pass within race_stagger_ms of another.
    private static void gate() {
        if (gateRunning) {
            gateAgain = true;
            return;
        }
        if (!selecting()) {
            return;
        }
        List<String> paths = PlumaEdgeBridge.paths();
        if (paths.size() < 2) {
            return;
        }
        PlumaPathPolicy.Params p;
        String cur;
        List<String> first;
        List<String> rest = new ArrayList<>();
        List<String> last = new ArrayList<>();
        synchronized (lock) {
            p = params;
            long now = System.currentTimeMillis();
            PlumaPathPolicy.Network n = memory.network(networkKey);
            if (current == null || !paths.contains(current)) {
                current = n.order(paths, now).get(0);
            }
            cur = current;
            first = new ArrayList<>(n.firstGroup(paths, now));
            if (!first.contains(cur)) {
                first.add(0, cur);
            }
            for (String path : paths) {
                if (!first.contains(path)) {
                    (n.excluded(path, now) ? last : rest).add(path);
                }
            }
        }
        if (retry != null) {
            retry.cancel(false);
            retry = null;
        }
        gateRunning = true;
        gateAgain = false;
        io.execute(() -> {
            Race race = new Race(cur, first, rest, last, p);
            race.run();
            worker.execute(() -> gateDone(race, cur));
        });
    }

    private static void gateDone(Race race, String cur) {
        gateRunning = false;
        if (race.unsupported) {
            markUnsupported();
            return;
        }
        long now = System.currentTimeMillis();
        PlumaPathPolicy.Params p;
        boolean switched = false;
        synchronized (lock) {
            p = params;
            PlumaPathPolicy.Network n = memory.network(networkKey);
            boolean any = race.winner != null;
            for (Map.Entry<String, PlumaPathPolicy.Outcome> r : race.outcomes.entrySet()) {
                if (PlumaPathPolicy.passed(r.getValue())) {
                    any = true;
                }
            }
            // Every path failed: the network, not the paths; nothing is remembered.
            if (any) {
                for (Map.Entry<String, PlumaPathPolicy.Outcome> r : race.outcomes.entrySet()) {
                    Double score = race.scores.get(r.getKey());
                    n.record(r.getKey(), r.getValue(), score != null ? score : Double.NaN, now, p);
                }
                if (race.winner != null && race.winner.equals(current) && cur.equals(current)) {
                    n.best = cur;
                } else if (race.winner != null && cur.equals(current)) {
                    current = race.winner;
                    n.best = race.winner;
                    n.switched = now;
                    switched = true;
                }
                memory.prune();
                store();
            }
        }
        if (switched) {
            PlumaEdgeBridge.reorder(true);
        }
        if (race.winner == null) {
            if (foreground) {
                retry = worker.schedule(PlumaPathProber::gate, retryDelay, TimeUnit.MILLISECONDS);
                retryDelay = Math.min(RETRY_MAX, retryDelay * 2);
            }
        } else {
            retryDelay = RETRY_MIN;
            worker.schedule(PlumaPathProber::rankIfDue, LAUNCH_RANK_DELAY, TimeUnit.MILLISECONDS);
        }
        if (gateAgain) {
            gate();
        }
    }

    // The measurements after a passed race, with the app on the screen: one after a change of the
    // network (at most every NETWORK_RANK_INTERVAL), one after the start or a return from the
    // background, when the last in this network is older than rank_min_interval_s.
    private static void rankIfDue() {
        if (!foreground || gateRunning) {
            return;
        }
        long elapsed = SystemClock.elapsedRealtime();
        if (networkRankDue && (lastNetworkRank == 0 || elapsed - lastNetworkRank >= NETWORK_RANK_INTERVAL)) {
            if (rank()) {
                networkRankDue = false;
                lastNetworkRank = elapsed;
                launchRanked = true;
            }
            return;
        }
        if (launchRanked) {
            return;
        }
        PlumaPathPolicy.Network n;
        PlumaPathPolicy.Params p;
        synchronized (lock) {
            n = memory.networks.get(networkKey);
            p = params;
        }
        if (n != null && System.currentTimeMillis() - n.ranked < p.rankMinIntervalMs() || rank()) {
            launchRanked = true;
        }
    }

    // A measurement of the paths, one after another on connections of their own (the brief's
    // section 6): the direct path and the current one always, the other edges only when the
    // country puts the edges first or the direct path is bad. Only with the app on the screen.
    private static boolean rank() {
        if (rankRunning || gateRunning || !foreground || !selecting()) {
            return false;
        }
        List<String> paths = PlumaEdgeBridge.paths();
        if (paths.size() < 2) {
            return false;
        }
        String cur;
        PlumaPathPolicy.Params p;
        synchronized (lock) {
            p = params;
            if (current == null || !paths.contains(current)) {
                current = memory.network(networkKey).order(paths, System.currentTimeMillis()).get(0);
            }
            cur = current;
        }
        rankRunning = true;
        boolean edgesFirst = !paths.get(0).equals(DIRECT);
        io.execute(() -> {
            Map<String, Probe> done = new LinkedHashMap<>();
            for (String path : new String[]{DIRECT, cur}) {
                if (!done.containsKey(path)) {
                    done.put(path, Probe.run(path, p.rankDown(), p));
                }
            }
            Probe direct = done.get(DIRECT);
            if (direct.outcome != PlumaPathPolicy.Outcome.UNSUPPORTED
                    && PlumaPathPolicy.rankEdges(edgesFirst, direct.outcome, direct.score(), p)) {
                for (String path : paths) {
                    if (!done.containsKey(path)) {
                        done.put(path, Probe.run(path, p.rankDown(), p));
                    }
                }
            }
            worker.execute(() -> rankDone(done, cur, paths));
        });
        return true;
    }

    private static void rankDone(Map<String, Probe> done, String cur, List<String> paths) {
        rankRunning = false;
        for (Probe probe : done.values()) {
            if (probe.outcome == PlumaPathPolicy.Outcome.UNSUPPORTED) {
                markUnsupported();
                return;
            }
        }
        long now = System.currentTimeMillis();
        String target = null;
        boolean emergency = false;
        synchronized (lock) {
            PlumaPathPolicy.Params p = params;
            PlumaPathPolicy.Network n = memory.network(networkKey);
            boolean any = false;
            for (Probe probe : done.values()) {
                any |= PlumaPathPolicy.passed(probe.outcome);
            }
            if (!any) {
                return;
            }
            Map<String, Double> scores = new HashMap<>();
            for (Map.Entry<String, Probe> e : done.entrySet()) {
                n.record(e.getKey(), e.getValue().outcome, e.getValue().score(), now, p);
                if (PlumaPathPolicy.passed(e.getValue().outcome)) {
                    scores.put(e.getKey(), n.state(e.getKey()).effectiveScore());
                }
            }
            n.ranked = now;
            if (!cur.equals(current)) {
                // A race moved the path meanwhile; this measurement judged another one.
                pendingCandidate = null;
            } else if (!scores.containsKey(cur)) {
                // The current path did not pass: the best that did, at once.
                target = PlumaPathPolicy.best(paths, scores);
                emergency = true;
            } else {
                Map<String, Double> others = new HashMap<>(scores);
                others.remove(cur);
                String candidate = PlumaPathPolicy.best(paths, others);
                if (candidate != null) {
                    boolean confirmed = candidate.equals(pendingCandidate)
                            && now - pendingAt <= PlumaPathPolicy.CONFIRM_SLACK * p.confirmMs();
                    switch (PlumaPathPolicy.decide(scores.get(cur), others.get(candidate), confirmed, now - n.switched, p)) {
                        case SWITCH:
                            target = candidate;
                            pendingCandidate = null;
                            break;
                        case CONFIRM:
                            pendingCandidate = candidate;
                            pendingAt = now;
                            if (confirm != null) {
                                confirm.cancel(false);
                            }
                            confirm = worker.schedule(PlumaPathProber::rank, p.confirmMs(), TimeUnit.MILLISECONDS);
                            break;
                        default:
                            pendingCandidate = null;
                    }
                } else {
                    pendingCandidate = null;
                }
            }
            memory.prune();
            store();
        }
        if (target != null) {
            if (emergency) {
                switchTo(target);
            } else {
                switchWhenIdle(target, SystemClock.elapsedRealtime());
            }
        }
    }

    // A switch by measurement waits for a file transfer, at most TRANSFER_DEFER.
    private static void switchWhenIdle(String target, long since) {
        if (transferring() && SystemClock.elapsedRealtime() - since < TRANSFER_DEFER) {
            worker.schedule(() -> switchWhenIdle(target, since), TRANSFER_CHECK, TimeUnit.MILLISECONDS);
            return;
        }
        switchTo(target);
    }

    private static void switchTo(String target) {
        // The bridge's lock goes before this one, never inside it.
        List<String> paths = PlumaEdgeBridge.paths();
        synchronized (lock) {
            if (target.equals(current) || !paths.contains(target)) {
                return;
            }
            long now = System.currentTimeMillis();
            PlumaPathPolicy.Network n = memory.network(networkKey);
            current = target;
            n.best = target;
            n.switched = now;
            n.used = now;
            store();
        }
        PlumaEdgeBridge.reorder(true);
    }

    // The gateway closed right after resPQ: it does not know the probe. The rules of task 109 hold
    // until another pluma_probe comes; nothing is remembered.
    private static void markUnsupported() {
        synchronized (lock) {
            unsupported = true;
            current = null;
        }
        PlumaEdgeBridge.reorder(false);
    }

    private static boolean transferring() {
        for (int account : PlumaEdgeBridge.attachedAccounts()) {
            long age = ConnectionsManager.native_getPlumaPathTransferAge(account);
            if (age >= 0 && age < TRANSFER_RECENT) {
                return true;
            }
        }
        return false;
    }

    // Data Saver of the system for this app, or Battery Saver.
    private static boolean saving() {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N
                    && connectivity().getRestrictBackgroundStatus() == ConnectivityManager.RESTRICT_BACKGROUND_STATUS_ENABLED) {
                return true;
            }
            PowerManager power = (PowerManager) ApplicationLoader.applicationContext.getSystemService(Context.POWER_SERVICE);
            return power != null && power.isPowerSaveMode();
        } catch (RuntimeException e) {
            FileLog.e(e);
            return false;
        }
    }

    // Under the lock.
    private static void store() {
        preferences().edit().putString(MEMORY_KEY, memory.toText()).apply();
    }

    private static SharedPreferences preferences() {
        return ApplicationLoader.applicationContext.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE);
    }

    private static ConnectivityManager connectivity() {
        return (ConnectivityManager) ApplicationLoader.applicationContext.getSystemService(Context.CONNECTIVITY_SERVICE);
    }

    // The part of the network's key the device sees: the kind of the default network, its
    // gateways and DNS servers, the operator of a mobile one. No SSID, no location: no permission.
    private static String fingerprint() {
        String transport = "none";
        List<String> parts = new ArrayList<>();
        try {
            ConnectivityManager manager = connectivity();
            Network network = manager.getActiveNetwork();
            NetworkCapabilities capabilities = network != null ? manager.getNetworkCapabilities(network) : null;
            LinkProperties properties = network != null ? manager.getLinkProperties(network) : null;
            if (capabilities != null) {
                if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                    transport = "vpn";
                } else if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                    transport = "wifi";
                } else if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) {
                    transport = "ethernet";
                } else if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
                    transport = "cellular";
                    parts.add("op=" + operator());
                } else {
                    transport = "other";
                }
            }
            if (properties != null) {
                for (RouteInfo route : properties.getRoutes()) {
                    InetAddress gateway = route.getGateway();
                    if (route.isDefaultRoute() && gateway != null && !gateway.isAnyLocalAddress()) {
                        parts.add("gw=" + gateway.getHostAddress());
                    }
                }
                for (InetAddress dns : properties.getDnsServers()) {
                    parts.add("dns=" + dns.getHostAddress());
                }
            }
        } catch (RuntimeException e) {
            FileLog.e(e);
        }
        String key = PlumaPathPolicy.networkKey("", transport, parts);
        return key.substring(key.indexOf(':'));
    }

    // The MCC and MNC of the mobile network, "" when the system does not tell them.
    private static String operator() {
        try {
            TelephonyManager telephony = (TelephonyManager) ApplicationLoader.applicationContext.getSystemService(Context.TELEPHONY_SERVICE);
            String operator = telephony != null ? telephony.getNetworkOperator() : null;
            return operator != null ? operator : "";
        } catch (RuntimeException e) {
            FileLog.e(e);
            return "";
        }
    }

    // --- the race ------------------------------------------------------------------------------

    private static final class Race {
        final String current;
        final List<String> first;
        final List<String> rest;
        final List<String> last;
        final PlumaPathPolicy.Params p;
        final LinkedBlockingQueue<Probe> results = new LinkedBlockingQueue<>();
        final List<Probe> running = new ArrayList<>();
        final Map<String, PlumaPathPolicy.Outcome> outcomes = new LinkedHashMap<>();
        final Map<String, Double> scores = new HashMap<>();
        String winner;
        boolean unsupported;

        Race(String current, List<String> first, List<String> rest, List<String> last, PlumaPathPolicy.Params p) {
            this.current = current;
            this.first = first;
            this.rest = rest;
            this.last = last;
            this.p = p;
        }

        void run() {
            long start = SystemClock.elapsedRealtime();
            launch(first);
            boolean restStarted = rest.isEmpty();
            boolean lastStarted = last.isEmpty();
            String passed = null;
            long passedAt = 0;
            try {
                while (true) {
                    long now = SystemClock.elapsedRealtime();
                    if (passed != null && (passed.equals(current) || outcomes.containsKey(current)
                            && !PlumaPathPolicy.passed(outcomes.get(current)) || now - passedAt >= p.raceStaggerMs())) {
                        winner = outcomes.get(current) == PlumaPathPolicy.Outcome.OK ? current : passed;
                        break;
                    }
                    boolean firstOut = true;
                    for (String path : first) {
                        firstOut &= outcomes.containsKey(path);
                    }
                    if (!restStarted && passed == null && (firstOut || now - start >= p.raceStaggerMs())) {
                        launch(rest);
                        restStarted = true;
                    }
                    if (restStarted && !lastStarted && passed == null && outcomes.size() == running.size()) {
                        launch(last);
                        lastStarted = true;
                    }
                    if (restStarted && lastStarted && outcomes.size() == running.size()) {
                        break;
                    }
                    long wait = passed != null ? passedAt + p.raceStaggerMs() - now
                            : restStarted ? p.deadlineMs() : start + p.raceStaggerMs() - now;
                    Probe probe = results.poll(Math.max(1, wait), TimeUnit.MILLISECONDS);
                    if (probe == null) {
                        continue;
                    }
                    outcomes.put(probe.path, probe.outcome);
                    if (probe.outcome == PlumaPathPolicy.Outcome.UNSUPPORTED) {
                        unsupported = true;
                        break;
                    }
                    if (PlumaPathPolicy.passed(probe.outcome)) {
                        scores.put(probe.path, probe.score());
                    }
                    if (probe.outcome == PlumaPathPolicy.Outcome.OK && passed == null) {
                        passed = probe.path;
                        passedAt = SystemClock.elapsedRealtime();
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                for (Probe probe : running) {
                    probe.cancel();
                }
            }
        }

        private void launch(List<String> paths) {
            for (String path : paths) {
                Probe probe = new Probe(path, p.gateDown(), p);
                running.add(probe);
                io.execute(() -> results.add(probe.execute()));
            }
        }
    }

    // --- one probe -----------------------------------------------------------------------------

    private static final class Probe extends WebSocketAdapter {
        final String path;
        final int down;
        final PlumaPathPolicy.Params p;
        final PlumaPathPolicy.Measure measure;
        private final byte[] requestNonce = new byte[16];
        private final byte[] probeNonce = new byte[16];
        private final PlumaPathPolicy.Reader reader;
        private PlumaPathPolicy.Obfuscation obfuscation;
        private Socket socket;
        private WebSocket webSocket;
        private boolean cancelled;
        private boolean closing;
        PlumaPathPolicy.Outcome outcome;

        Probe(String path, int down, PlumaPathPolicy.Params p) {
            this.path = path;
            this.down = down;
            this.p = p;
            this.measure = new PlumaPathPolicy.Measure(p, SystemClock.elapsedRealtime());
            random.nextBytes(requestNonce);
            random.nextBytes(probeNonce);
            this.reader = new PlumaPathPolicy.Reader(requestNonce, probeNonce, down);
        }

        static Probe run(String path, int down, PlumaPathPolicy.Params p) {
            return new Probe(path, down, p).execute();
        }

        double score() {
            return PlumaPathPolicy.score(measure.rtt(), measure.bytesPerSecond());
        }

        // Runs the probe on this thread and returns it with its outcome. A write that blocks on
        // a frozen path is cut by closing the socket a second after the deadline; the outcome is
        // then what the measure says at that time.
        Probe execute() {
            ScheduledFuture<?> watchdog = worker.schedule(this::cancel, p.deadlineMs() + 1000, TimeUnit.MILLISECONDS);
            try {
                obfuscation = PlumaPathPolicy.Obfuscation.create(random);
                if (path.equals(DIRECT)) {
                    direct();
                } else {
                    edge();
                }
            } catch (IOException | WebSocketException | GeneralSecurityException | RuntimeException e) {
                synchronized (this) {
                    if (outcome == null && !cancelled) {
                        measure.failed();
                    }
                }
            } finally {
                watchdog.cancel(false);
                close();
            }
            synchronized (this) {
                if (outcome == null) {
                    outcome = measure.outcome(SystemClock.elapsedRealtime());
                    if (outcome == null) {
                        outcome = PlumaPathPolicy.Outcome.FAILED;
                    }
                }
            }
            return this;
        }

        // The request: the obfuscated2 header and req_pq_multi in one write.
        private byte[] request() {
            byte[] sealed = obfuscation.seal(PlumaPathPolicy.frame(PlumaPathPolicy.reqPqMulti(
                    PlumaPathPolicy.msgId(System.currentTimeMillis()), requestNonce)));
            byte[] out = new byte[64 + sealed.length];
            System.arraycopy(obfuscation.header, 0, out, 0, 64);
            System.arraycopy(sealed, 0, out, 64, sealed.length);
            return out;
        }

        private byte[] probeMessage() {
            byte[] pad = new byte[Math.min(p.up(), PlumaPathPolicy.MAX_UP)];
            random.nextBytes(pad);
            return obfuscation.seal(PlumaPathPolicy.frame(PlumaPathPolicy.probe(
                    PlumaPathPolicy.msgId(System.currentTimeMillis()), probeNonce, down, pad)));
        }

        // Bytes of the gateway; returns the probe to send once resPQ came, null otherwise.
        private synchronized byte[] received(byte[] data, int length) {
            byte[] plain = obfuscation.open(data, 0, length);
            boolean before = reader.resPq;
            int answer = reader.feed(plain, 0, plain.length);
            measure.received(SystemClock.elapsedRealtime(), plain.length, answer, reader);
            if (!before && reader.resPq && reader.error == null && !measure.probeSent()) {
                measure.probeSent(SystemClock.elapsedRealtime());
                return probeMessage();
            }
            return null;
        }

        // The outcome once there is one; a cancelled probe stops with what its measure says then.
        private synchronized PlumaPathPolicy.Outcome check() {
            if (outcome == null) {
                PlumaPathPolicy.Outcome now = measure.outcome(SystemClock.elapsedRealtime());
                outcome = now == null && cancelled ? PlumaPathPolicy.Outcome.FAILED : now;
            }
            return outcome;
        }

        // obfuscated2 over TCP to the direct address of DC 1, as tgnet goes; IPv6 if IPv4 has no
        // route.
        private void direct() throws IOException {
            Socket s = new Socket();
            synchronized (this) {
                if (cancelled) {
                    return;
                }
                socket = s;
            }
            try {
                s.connect(new InetSocketAddress(InetAddress.getByName(DIRECT_IPV4), DIRECT_PORT), (int) p.deadlineMs());
            } catch (SocketTimeoutException e) {
                throw e;
            } catch (IOException e) {
                if (DIRECT_IPV6.isEmpty()) {
                    throw e;
                }
                s.close();
                s = new Socket();
                synchronized (this) {
                    if (cancelled) {
                        return;
                    }
                    socket = s;
                }
                s.connect(new InetSocketAddress(InetAddress.getByName(DIRECT_IPV6), DIRECT_PORT), (int) p.deadlineMs());
            }
            measure.connected(SystemClock.elapsedRealtime(), false);
            s.setTcpNoDelay(true);
            s.setSoTimeout(READ_SLICE);
            OutputStream out = s.getOutputStream();
            InputStream in = s.getInputStream();
            out.write(request());
            measure.requestSent(SystemClock.elapsedRealtime());
            byte[] buffer = new byte[READ_BUFFER];
            while (check() == null) {
                int count;
                try {
                    count = in.read(buffer);
                } catch (SocketTimeoutException e) {
                    continue;
                }
                if (count < 0) {
                    synchronized (this) {
                        measure.closed();
                    }
                    continue;
                }
                byte[] probe = received(buffer, count);
                if (probe != null) {
                    out.write(probe);
                }
            }
        }

        // The edge's WebSocket, as PlumaEdgeBridge opens it.
        private void edge() throws IOException, WebSocketException {
            WebSocket ws = new WebSocketFactory()
                    .setConnectionTimeout((int) p.deadlineMs())
                    .setSocketTimeout((int) p.deadlineMs())
                    .setServerName(URI.create(path).getHost())
                    .createSocket(path);
            ws.addProtocol("binary");
            ws.addHeader("User-Agent", "Pluma");
            ws.addListener(this);
            synchronized (this) {
                if (cancelled) {
                    return;
                }
                webSocket = ws;
            }
            ws.connect();
            synchronized (this) {
                measure.connected(SystemClock.elapsedRealtime(), true);
                ws.sendBinary(request());
                measure.requestSent(SystemClock.elapsedRealtime());
            }
            synchronized (this) {
                while (check() == null) {
                    try {
                        wait(READ_SLICE);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        measure.failed();
                    }
                }
            }
        }

        @Override
        public void onBinaryMessage(WebSocket websocket, byte[] binary) {
            byte[] probe = received(binary, binary.length);
            if (probe != null) {
                websocket.sendBinary(probe);
            }
            synchronized (this) {
                notifyAll();
            }
        }

        // A close of the edge's side; one of our own is not the gateway's answer.
        @Override
        public void onDisconnected(WebSocket websocket, WebSocketFrame serverCloseFrame, WebSocketFrame clientCloseFrame, boolean closedByServer) {
            synchronized (this) {
                if (!closing && !cancelled) {
                    measure.closed();
                }
                notifyAll();
            }
        }

        // From the race: it ended, this probe is not needed any more.
        void cancel() {
            synchronized (this) {
                cancelled = true;
                notifyAll();
            }
            close();
        }

        private void close() {
            Socket s;
            WebSocket ws;
            synchronized (this) {
                closing = true;
                s = socket;
                ws = webSocket;
            }
            if (s != null) {
                try {
                    s.close();
                } catch (IOException ignore) {
                    // Closing a probe's socket; nothing is left to do with it.
                }
            }
            if (ws != null) {
                ws.disconnect();
                Socket raw = ws.getSocket();
                if (raw != null) {
                    try {
                        raw.close();
                    } catch (IOException ignore) {
                        // As above.
                    }
                }
            }
        }
    }
}
"""
PATH_DIRECT_LINES = ('    private static final String DIRECT_IPV4 = "";\n'
                     '    private static final String DIRECT_IPV6 = "";\n'
                     '    private static final int DIRECT_PORT = 0;\n')

EDGE_EDITS = (
    # DC 1: the labels after A-002's direct addresses, none until the bridge gives them.
    (EDGE_MANAGER_CPP,
     EDGE_INIT_ANCHOR,
     "        datacenters[1] = datacenter;\n    }\n"
     "    // pluma: the edge labels of DC 1 (A-128); none until PlumaEdgeBridge gives them, so a\n"
     "    // label stored by the last run goes and the client starts on the direct address.\n"
     "    datacenters[1]->applyPlumaEdges();\n}\n"),
    (EDGE_MANAGER_CPP,
     "void ConnectionsManager::setLangCode(std::string langCode) {\n",
     "// pluma: the edges of the server (task 109 of the server repository, A-128). An edge is an\n"
     "// address label of DC 1, which ConnectionSocket opens as the local bridge of that edge\n"
     "// (PlumaEdgeBridge.java); the ports of the bridges come in the order of the edges, 0 for a\n"
     "// bridge that is not open.\n"
     f'static const char *const PLUMA_EDGE_LABEL = "{EDGE_LABEL}";\n'
     f"static const size_t PLUMA_MAX_EDGES = {EDGE_URLS_LIMIT};\n"
     "\n"
     "// The order of the paths of DC 1 (A-129, PlumaPathProber.java): 0 is the direct addresses, n + 1\n"
     "// the edge n; anything but a permutation of them is the default order, the direct addresses first.\n"
     "// suspectMs: a request of the generic connection that waits this long with no byte is reported\n"
     "// (onPlumaPathSuspect), 0 never. With reconnect, a new order drops the connections of DC 1, which\n"
     "// open again on its first path, as a new proxy does (setProxySettings).\n"
     "void ConnectionsManager::setPlumaEdges(std::vector<uint16_t> ports, std::vector<int32_t> order, int32_t suspectMs, bool reconnect) {\n"
     "    if (ports.size() > PLUMA_MAX_EDGES) {\n"
     "        ports.resize(PLUMA_MAX_EDGES);\n"
     "    }\n"
     "    std::vector<bool> seen(ports.size() + 1, false);\n"
     "    bool valid = order.size() == ports.size() + 1;\n"
     "    for (size_t a = 0; valid && a < order.size(); a++) {\n"
     "        valid = order[a] >= 0 && (size_t) order[a] <= ports.size() && !seen[order[a]];\n"
     "        if (valid) {\n"
     "            seen[order[a]] = true;\n"
     "        }\n"
     "    }\n"
     "    if (!valid) {\n"
     "        order.clear();\n"
     "        for (size_t a = 0; a <= ports.size(); a++) {\n"
     "            order.push_back((int32_t) a);\n"
     "        }\n"
     "    }\n"
     "    scheduleTask([&, ports, order, suspectMs, reconnect] {\n"
     "        bool changed = plumaEdgePorts != ports || plumaPathOrder != order;\n"
     "        plumaEdgePorts = ports;\n"
     "        plumaPathOrder = order;\n"
     "        plumaPathSuspectMs = suspectMs > 0 ? suspectMs : 0;\n"
     "        Datacenter *datacenter = getDatacenterWithId(1);\n"
     "        if (datacenter != nullptr) {\n"
     "            datacenter->applyPlumaEdges();\n"
     "            saveConfig();\n"
     "            if (reconnect && changed) {\n"
     "                datacenter->suspendConnections(true);\n"
     "                if (datacenter->isHandshakingAny()) {\n"
     "                    datacenter->beginHandshake(HandshakeTypeCurrent, true);\n"
     "                }\n"
     "                processRequestQueue(0, 0);\n"
     "            }\n"
     "        }\n"
     "    });\n"
     "}\n"
     "\n"
     "// pluma: how long ago a file transfer last received data, in ms, -1 if never (A-129). Called from\n"
     "// Java: it reads the clock of getCurrentTimeMonotonicMillis itself, whose buffer is the network\n"
     "// thread's.\n"
     "int64_t ConnectionsManager::plumaPathTransferAge() {\n"
     "    int64_t last = plumaPathLastTransfer.load();\n"
     "    if (last == 0) {\n"
     "        return -1;\n"
     "    }\n"
     "    struct timespec now;\n"
     "    clock_gettime(CLOCK_BOOTTIME, &now);\n"
     "    return (int64_t) now.tv_sec * 1000 + (int64_t) now.tv_nsec / 1000000 - last;\n"
     "}\n"
     "\n"
     "// pluma: sticky_s after the client went through an edge, the next connection of DC 1 tries the\n"
     "// direct address first again; the open one stays.\n"
     "void ConnectionsManager::returnFromPlumaEdge() {\n"
     "    scheduleTask([&] {\n"
     "        Datacenter *datacenter = getDatacenterWithId(1);\n"
     "        if (datacenter != nullptr) {\n"
     "            datacenter->returnFromPlumaEdge();\n"
     "        }\n"
     "    });\n"
     "}\n"
     "\n"
     "int32_t ConnectionsManager::plumaEdgeIndex(const std::string &address) {\n"
     "    static const std::string label = PLUMA_EDGE_LABEL;\n"
     "    if (address.size() != label.size() + 1 || address.compare(0, label.size(), label) != 0) {\n"
     "        return -1;\n"
     "    }\n"
     "    int32_t index = address[label.size()] - '0';\n"
     "    return index >= 0 && (size_t) index < PLUMA_MAX_EDGES ? index : -1;\n"
     "}\n"
     "\n"
     "std::string ConnectionsManager::plumaEdgeLabel(size_t index) {\n"
     "    return PLUMA_EDGE_LABEL + to_string_int32((int32_t) index);\n"
     "}\n"
     "\n"
     "// pluma: the port of an edge's bridge; never through a proxy of the user or a proxy check.\n"
     "uint16_t ConnectionsManager::plumaEdgePort(int32_t index, bool proxied) {\n"
     "    if (proxied || !proxyAddress.empty() || index < 0 || (size_t) index >= plumaEdgePorts.size()) {\n"
     "        return 0;\n"
     "    }\n"
     "    return plumaEdgePorts[index];\n"
     "}\n"
     "\n"
     "void ConnectionsManager::setLangCode(std::string langCode) {\n"),
    (EDGE_MANAGER_H,
     "    void setProxySettings(std::string address, uint16_t port, std::string username, std::string password, std::string secret);\n",
     "    void setProxySettings(std::string address, uint16_t port, std::string username, std::string password, std::string secret);\n"
     "    // pluma: the edges of the server (A-128, PlumaEdgeBridge.java).\n"
     "    void setPlumaEdges(std::vector<uint16_t> ports, std::vector<int32_t> order, int32_t suspectMs, bool reconnect);\n"
     "    int64_t plumaPathTransferAge();\n"
     "    void returnFromPlumaEdge();\n"
     "    static int32_t plumaEdgeIndex(const std::string &address);\n"
     "    static std::string plumaEdgeLabel(size_t index);\n"),
    (EDGE_MANAGER_H,
     "    uint16_t proxyPort = 1080;\n",
     "    uint16_t proxyPort = 1080;\n"
     "    // pluma: the ports of the edge bridges in the order of the edges (A-128); the order of the\n"
     "    // paths of DC 1, the wait of a request that is reported, and the last data of a file\n"
     "    // transfer, monotonic ms, read by Java (A-129).\n"
     "    std::vector<uint16_t> plumaEdgePorts;\n"
     "    std::vector<int32_t> plumaPathOrder;\n"
     "    int32_t plumaPathSuspectMs = 0;\n"
     "    std::atomic<int64_t> plumaPathLastTransfer{0};\n"
     "    uint16_t plumaEdgePort(int32_t index, bool proxied);\n"),
    (EDGE_DATACENTER_H,
     "    bool isRepeatCheckingAddresses();\n",
     "    bool isRepeatCheckingAddresses();\n"
     "    // pluma: the edges of the server (A-128, ConnectionsManager::setPlumaEdges).\n"
     "    void applyPlumaEdges();\n"
     "    void returnFromPlumaEdge();\n"
     "    bool plumaDirectFroze(const std::string &address, bool frozen);\n"),
    (EDGE_DATACENTER_H,
     "    bool repeatCheckingAddresses = false;\n",
     "    bool repeatCheckingAddresses = false;\n"
     "    // pluma: the layout of the edge labels last applied, and the frozen direct connections in a row.\n"
     "    size_t plumaEdgeCount = 0;\n"
     "    std::vector<int32_t> plumaPathOrder;\n"
     "    uint32_t plumaFrozenCount = 0;\n"
     "    int64_t plumaLastFrozenTime = 0;\n"
     "    void applyPlumaEdges(std::vector<TcpAddress> &addresses, uint32_t &addressNum, uint32_t &portNum, uint32_t flags, bool layoutChanged);\n"
     "    static bool plumaMoveTo(std::vector<TcpAddress> &addresses, uint32_t &addressNum, uint32_t &portNum, bool toEdge);\n"),
    # A label has no port slots: the next address follows it.
    (EDGE_DATACENTER_CPP,
     "        tryNextPort = (currentAddress->flags & TcpAddressFlagStatic) == 0;\n",
     "        // pluma: an edge label has no ports to try (A-128).\n"
     "        tryNextPort = (currentAddress->flags & TcpAddressFlagStatic) == 0 && ConnectionsManager::plumaEdgeIndex(currentAddress->address) < 0;\n"),
    (EDGE_DATACENTER_CPP,
     "void Datacenter::replaceAddresses(std::vector<TcpAddress> &newAddresses, uint32_t flags) {\n",
     "// pluma: the edges of the server (task 109 of the server repository, A-128). The paths of DC 1,\n"
     "// its direct addresses and a label per edge, go in the order PlumaPathProber chose (A-129), the\n"
     "// direct addresses first by default; a list without a direct address gets no label. A new layout\n"
     "// starts the list from its first address, the same layout keeps the current one.\n"
     "void Datacenter::applyPlumaEdges() {\n"
     "    if (datacenterId != 1) {\n"
     "        return;\n"
     "    }\n"
     "    ConnectionsManager &manager = ConnectionsManager::getInstance(instanceNum);\n"
     "    std::vector<int32_t> order = manager.plumaPathOrder;\n"
     "    if (order.size() != manager.plumaEdgePorts.size() + 1) {\n"
     "        order.clear();\n"
     "        for (size_t a = 0; a <= manager.plumaEdgePorts.size(); a++) {\n"
     "            order.push_back((int32_t) a);\n"
     "        }\n"
     "    }\n"
     "    bool layoutChanged = manager.plumaEdgePorts.size() != plumaEdgeCount || order != plumaPathOrder;\n"
     "    plumaEdgeCount = manager.plumaEdgePorts.size();\n"
     "    plumaPathOrder = order;\n"
     "    applyPlumaEdges(addressesIpv4, currentAddressNumIpv4, currentPortNumIpv4, 0, layoutChanged);\n"
     "    applyPlumaEdges(addressesIpv6, currentAddressNumIpv6, currentPortNumIpv6, TcpAddressFlagIpv6, layoutChanged);\n"
     "    plumaFrozenCount = 0;\n"
     "    storeCurrentAddressAndPortNum();\n"
     "}\n"
     "\n"
     "void Datacenter::applyPlumaEdges(std::vector<TcpAddress> &addresses, uint32_t &addressNum, uint32_t &portNum, uint32_t flags, bool layoutChanged) {\n"
     "    std::string current = addressNum < addresses.size() ? addresses[addressNum].address : \"\";\n"
     "    std::vector<TcpAddress> direct;\n"
     "    for (auto &address : addresses) {\n"
     "        if (ConnectionsManager::plumaEdgeIndex(address.address) < 0) {\n"
     "            direct.push_back(address);\n"
     "        }\n"
     "    }\n"
     "    std::vector<TcpAddress> result;\n"
     "    for (int32_t path : plumaPathOrder) {\n"
     "        if (path == 0) {\n"
     "            result.insert(result.end(), direct.begin(), direct.end());\n"
     "        } else if (!direct.empty() && (size_t) path <= plumaEdgeCount) {\n"
     "            result.emplace_back(ConnectionsManager::plumaEdgeLabel((size_t) path - 1), 443, flags, \"\");\n"
     "        }\n"
     "    }\n"
     "    uint32_t num = 0;\n"
     "    bool found = false;\n"
     "    if (!layoutChanged) {\n"
     "        for (size_t a = 0; a < result.size(); a++) {\n"
     "            if (result[a].address == current) {\n"
     "                num = (uint32_t) a;\n"
     "                found = true;\n"
     "                break;\n"
     "            }\n"
     "        }\n"
     "    }\n"
     "    addresses = result;\n"
     "    addressNum = num;\n"
     "    if (!found) {\n"
     "        portNum = 0;\n"
     "    }\n"
     "}\n"
     "\n"
     "// pluma: the current address of the list to the first edge label (toEdge) or the first direct\n"
     "// address, unless it is one already.\n"
     "bool Datacenter::plumaMoveTo(std::vector<TcpAddress> &addresses, uint32_t &addressNum, uint32_t &portNum, bool toEdge) {\n"
     "    if (addressNum < addresses.size() && (ConnectionsManager::plumaEdgeIndex(addresses[addressNum].address) >= 0) == toEdge) {\n"
     "        return false;\n"
     "    }\n"
     "    for (size_t a = 0; a < addresses.size(); a++) {\n"
     "        if ((ConnectionsManager::plumaEdgeIndex(addresses[a].address) >= 0) == toEdge) {\n"
     "            addressNum = (uint32_t) a;\n"
     "            portNum = 0;\n"
     "            return true;\n"
     "        }\n"
     "    }\n"
     "    return false;\n"
     "}\n"
     "\n"
     "void Datacenter::returnFromPlumaEdge() {\n"
     "    plumaFrozenCount = 0;\n"
     "    bool moved = plumaMoveTo(addressesIpv4, currentAddressNumIpv4, currentPortNumIpv4, false);\n"
     "    moved = plumaMoveTo(addressesIpv6, currentAddressNumIpv6, currentPortNumIpv6, false) || moved;\n"
     "    if (moved) {\n"
     "        storeCurrentAddressAndPortNum();\n"
     "    }\n"
     "}\n"
     "\n"
     "// pluma: a generic connection of DC 1 to a direct address closed; frozen: it was established\n"
     "// and timed out waiting for an answer (ConnectionSocket::checkTimeout). Twice in a row, each\n"
     "// within 60 s of the previous, put DC 1 on its first edge; true then.\n"
     "bool Datacenter::plumaDirectFroze(const std::string &address, bool frozen) {\n"
     "    ConnectionsManager &manager = ConnectionsManager::getInstance(instanceNum);\n"
     "    if (datacenterId != 1 || plumaEdgeCount == 0 || !frozen || !manager.proxyAddress.empty() || ConnectionsManager::plumaEdgeIndex(address) >= 0) {\n"
     "        plumaFrozenCount = 0;\n"
     "        return false;\n"
     "    }\n"
     "    int64_t now = manager.getCurrentTimeMonotonicMillis();\n"
     "    if (plumaFrozenCount != 0 && now - plumaLastFrozenTime > 60 * 1000) {\n"
     "        plumaFrozenCount = 0;\n"
     "    }\n"
     "    plumaLastFrozenTime = now;\n"
     "    if (++plumaFrozenCount < 2) {\n"
     "        return false;\n"
     "    }\n"
     "    plumaFrozenCount = 0;\n"
     "    bool moved = plumaMoveTo(addressesIpv4, currentAddressNumIpv4, currentPortNumIpv4, true);\n"
     "    moved = plumaMoveTo(addressesIpv6, currentAddressNumIpv6, currentPortNumIpv6, true) || moved;\n"
     "    return moved;\n"
     "}\n"
     "\n"
     "void Datacenter::replaceAddresses(std::vector<TcpAddress> &newAddresses, uint32_t flags) {\n"),
    # Addresses from the server (help.getConfig, DC_UPDATE) never bring a label, and keep the edges.
    (EDGE_DATACENTER_CPP,
     "    }\n}\n\nvoid Datacenter::serializeToStream(NativeByteBuffer *stream) {\n",
     "    }\n"
     "    // pluma: addresses of the server never carry an edge label; the labels of DC 1 stay (A-128).\n"
     "    if (datacenterId == 1 && (flags & ~TcpAddressFlagIpv6) == 0) {\n"
     "        applyPlumaEdges();\n"
     "    }\n"
     "}\n\nvoid Datacenter::serializeToStream(NativeByteBuffer *stream) {\n"),
    # A frozen direct connection: twice in a row, the first edge instead of the next port.
    (EDGE_CONNECTION_CPP,
     "    bool switchToNextPort = reason == 2 && wasConnected && (!hasSomeDataSinceLastConnect || currentDatacenter->isCustomPort(currentAddressFlags)) || forceNextPort;\n",
     "    bool switchToNextPort = reason == 2 && wasConnected && (!hasSomeDataSinceLastConnect || currentDatacenter->isCustomPort(currentAddressFlags)) || forceNextPort;\n"
     "    // pluma: a direct connection that froze twice in a row goes to the first edge (A-128).\n"
     "    bool toPlumaEdge = connectionType == ConnectionTypeGeneric && currentDatacenter->plumaDirectFroze(hostAddress, reason == 2 && wasConnected);\n"),
    (EDGE_CONNECTION_CPP,
     "            if (failedConnectionCount > willRetryConnectCount || switchToNextPort) {\n",
     "            if (toPlumaEdge) {\n"
     "                failedConnectionCount = 0;\n"
     "            } else if (failedConnectionCount > willRetryConnectCount || switchToNextPort) {\n"),
    # A label is the local bridge of its edge.
    (EDGE_SOCKET_CPP,
     "    ConnectionsManager::getInstance(instanceNum).attachConnection(this);\n",
     "    ConnectionsManager::getInstance(instanceNum).attachConnection(this);\n"
     "\n"
     "    // pluma: an edge label of DC 1 is the local bridge of that edge (A-128). With a proxy on, or\n"
     "    // with no bridge, the label fails at once and tgnet goes on to the next address.\n"
     "    int32_t plumaEdge = ConnectionsManager::plumaEdgeIndex(address);\n"
     "    if (plumaEdge >= 0) {\n"
     "        uint16_t bridgePort = ConnectionsManager::getInstance(instanceNum).plumaEdgePort(plumaEdge, !overrideProxyAddress.empty());\n"
     "        if (bridgePort == 0) {\n"
     "            closeSocket(1, -1);\n"
     "            return;\n"
     "        }\n"
     "        address = \"127.0.0.1\";\n"
     "        port = bridgePort;\n"
     "        ipv6 = false;\n"
     "        isIpv6 = false;\n"
     "        currentAddress = address;\n"
     "        currentPort = port;\n"
     "    }\n"),
    # JNI: the ports of the bridges and the return to the direct address.
    (EDGE_WRAPPER,
     "void setProxySettings(JNIEnv *env, jclass c, jint instanceNum, jstring address, jint port, jstring username, jstring password, jstring secret) {\n",
     "// pluma: the edges of the server (A-128): the ports of the bridges of PlumaEdgeBridge.java, and the\n"
     "// order of the paths PlumaPathProber.java chose (A-129).\n"
     "static std::vector<int32_t> plumaEdgeInts(JNIEnv *env, jintArray array) {\n"
     "    std::vector<int32_t> values;\n"
     "    jsize count = array != nullptr ? env->GetArrayLength(array) : 0;\n"
     "    if (count > 0) {\n"
     "        jint *elements = env->GetIntArrayElements(array, nullptr);\n"
     "        if (elements != nullptr) {\n"
     "            values.assign(elements, elements + count);\n"
     "            env->ReleaseIntArrayElements(array, elements, JNI_ABORT);\n"
     "        }\n"
     "    }\n"
     "    return values;\n"
     "}\n"
     "\n"
     "void setPlumaEdges(JNIEnv *env, jclass c, jint instanceNum, jintArray ports, jintArray order, jint suspectMs, jboolean reconnect) {\n"
     "    std::vector<uint16_t> values;\n"
     "    for (int32_t port : plumaEdgeInts(env, ports)) {\n"
     "        values.push_back(port > 0 && port < 65536 ? (uint16_t) port : 0);\n"
     "    }\n"
     "    ConnectionsManager::getInstance(instanceNum).setPlumaEdges(values, plumaEdgeInts(env, order), suspectMs, reconnect);\n"
     "}\n"
     "\n"
     "jlong getPlumaPathTransferAge(JNIEnv *env, jclass c, jint instanceNum) {\n"
     "    return (jlong) ConnectionsManager::getInstance(instanceNum).plumaPathTransferAge();\n"
     "}\n"
     "\n"
     "void returnFromPlumaEdge(JNIEnv *env, jclass c, jint instanceNum) {\n"
     "    ConnectionsManager::getInstance(instanceNum).returnFromPlumaEdge();\n"
     "}\n"
     "\n"
     "void setProxySettings(JNIEnv *env, jclass c, jint instanceNum, jstring address, jint port, jstring username, jstring password, jstring secret) {\n"),
    (EDGE_WRAPPER,
     '        {"native_setProxySettings", "(ILjava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V", (void *) setProxySettings},\n',
     '        {"native_setProxySettings", "(ILjava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V", (void *) setProxySettings},\n'
     '        {"native_setPlumaEdges", "(I[I[IIZ)V", (void *) setPlumaEdges},\n'
     '        {"native_returnFromPlumaEdge", "(I)V", (void *) returnFromPlumaEdge},\n'
     '        {"native_getPlumaPathTransferAge", "(I)J", (void *) getPlumaPathTransferAge},\n'),
    (EDGE_MANAGER_JAVA,
     "    public static native void native_setProxySettings(int currentAccount, String address, int port, String username, String password, String secret);\n",
     "    public static native void native_setProxySettings(int currentAccount, String address, int port, String username, String password, String secret);\n"
     "    // pluma: the edges of the server (A-128, PlumaEdgeBridge) and the order of the paths (A-129,\n"
     "    // PlumaPathProber).\n"
     "    public static native void native_setPlumaEdges(int currentAccount, int[] ports, int[] order, int suspectMs, boolean reconnect);\n"
     "    public static native void native_returnFromPlumaEdge(int currentAccount);\n"
     "    public static native long native_getPlumaPathTransferAge(int currentAccount);\n"),
    # The account's tgnet takes the edges before it starts.
    (EDGE_MANAGER_JAVA,
     "        native_init(currentAccount, ",
     "        org.telegram.utils.proxy.PlumaEdgeBridge.attach(currentAccount); // pluma: the server's edges (A-128)\n"
     "        native_init(currentAccount, "),
    (EDGE_MESSAGES,
     "        changed = config.apply(editor, object);\n",
     "        changed = config.apply(editor, object);\n"
     "        org.telegram.utils.proxy.PlumaEdgeBridge.applyAppConfig(object); // pluma: pluma_edge (A-128)\n"
     "        org.telegram.utils.proxy.PlumaPathProber.applyAppConfig(object); // pluma: pluma_probe (A-129)\n"),
    # A-129: a request of the generic connection of DC 1 that waits suspect_ms with no byte is
    # reported to PlumaPathProber, which measures the paths at once.
    (EDGE_SOCKET_H,
     "    uint16_t overrideProxyPort = 1080;\n",
     "    uint16_t overrideProxyPort = 1080;\n"
     "    // pluma: the generic connection of DC 1 reports a request that waits with no byte (A-129);\n"
     "    // when the oldest unanswered write went out, monotonic ms, 0 if none.\n"
     "    bool plumaPathWatched = false;\n"
     "    int64_t plumaPathWaitSince = 0;\n"),
    (EDGE_SOCKET_CPP,
     "void ConnectionSocket::openConnection(std::string address, uint16_t port, std::string secret, bool ipv6, int32_t networkType) {\n",
     "void ConnectionSocket::openConnection(std::string address, uint16_t port, std::string secret, bool ipv6, int32_t networkType) {\n"
     "    plumaPathWaitSince = 0; // pluma: a new connection waits for nothing yet (A-129)\n"),
    (EDGE_SOCKET_CPP,
     "void ConnectionSocket::writeBuffer(uint8_t *data, uint32_t size) {\n",
     "void ConnectionSocket::writeBuffer(uint8_t *data, uint32_t size) {\n"
     "    if (plumaPathWaitSince == 0) { // pluma: the wait starts (A-129)\n"
     "        plumaPathWaitSince = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();\n"
     "    }\n"),
    (EDGE_SOCKET_CPP,
     "void ConnectionSocket::writeBuffer(NativeByteBuffer *buffer) {\n",
     "void ConnectionSocket::writeBuffer(NativeByteBuffer *buffer) {\n"
     "    if (plumaPathWaitSince == 0) { // pluma: the wait starts (A-129)\n"
     "        plumaPathWaitSince = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();\n"
     "    }\n"),
    (EDGE_SOCKET_CPP,
     "                if (readCount > 0) {\n"
     "                    buffer->limit((uint32_t) readCount);\n"
     "                    lastEventTime = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();\n",
     "                if (readCount > 0) {\n"
     "                    buffer->limit((uint32_t) readCount);\n"
     "                    lastEventTime = ConnectionsManager::getInstance(instanceNum).getCurrentTimeMonotonicMillis();\n"
     "                    plumaPathWaitSince = 0; // pluma: a byte came (A-129)\n"),
    (EDGE_SOCKET_CPP,
     "bool ConnectionSocket::checkTimeout(int64_t now) {\n",
     "bool ConnectionSocket::checkTimeout(int64_t now) {\n"
     "    // pluma: a request waits suspect_ms with no byte since the write: once per wait, PlumaPathProber\n"
     "    // measures the paths (A-129). Writes with no request waiting, acknowledgements, end the wait.\n"
     "    if (plumaPathWatched && plumaPathWaitSince != 0 && onConnectedSent) {\n"
     "        ConnectionsManager &plumaManager = ConnectionsManager::getInstance(instanceNum);\n"
     "        if (!hasPendingRequests()) {\n"
     "            plumaPathWaitSince = 0;\n"
     "        } else if (plumaManager.plumaPathSuspectMs > 0 && now - plumaPathWaitSince >= plumaManager.plumaPathSuspectMs) {\n"
     "            plumaPathWaitSince = 0;\n"
     "            if (plumaManager.delegate != nullptr) {\n"
     "                plumaManager.delegate->onPlumaPathSuspect(instanceNum);\n"
     "            }\n"
     "        }\n"
     "    }\n"),
    (EDGE_CONNECTION_CPP,
     "    connectionType = type;\n    genereateNewSessionId();\n",
     "    connectionType = type;\n"
     "    plumaPathWatched = type == ConnectionTypeGeneric && datacenter->getDatacenterId() == 1; // pluma: A-129\n"
     "    genereateNewSessionId();\n"),
    (EDGE_CONNECTION_CPP,
     "    failedConnectionCount = 0;\n\n"
     "    if (connectionType == ConnectionTypeGeneric || connectionType == ConnectionTypeTemp || connectionType == ConnectionTypeGenericMedia) {\n",
     "    failedConnectionCount = 0;\n"
     "\n"
     "    // pluma: data of a file transfer; PlumaPathProber does not switch the path under it (A-129).\n"
     "    if ((connectionType & (ConnectionTypeDownload | ConnectionTypeUpload)) != 0) {\n"
     "        ConnectionsManager &plumaManager = ConnectionsManager::getInstance(currentDatacenter->instanceNum);\n"
     "        plumaManager.plumaPathLastTransfer = plumaManager.getCurrentTimeMonotonicMillis();\n"
     "    }\n"
     "\n"
     "    if (connectionType == ConnectionTypeGeneric || connectionType == ConnectionTypeTemp || connectionType == ConnectionTypeGenericMedia) {\n"),
    (EDGE_DEFINES,
     "    virtual void onProxyError(int32_t instanceNum) = 0;\n",
     "    virtual void onProxyError(int32_t instanceNum) = 0;\n"
     "    virtual void onPlumaPathSuspect(int32_t instanceNum) = 0; // pluma: A-129\n"),
    (EDGE_WRAPPER,
     "jmethodID jclass_ConnectionsManager_onProxyError;\n",
     "jmethodID jclass_ConnectionsManager_onProxyError;\n"
     "jmethodID jclass_ConnectionsManager_onPlumaPathSuspect; // pluma: A-129\n"),
    (EDGE_WRAPPER,
     "    void onProxyError(int32_t instanceNum) {\n",
     "    // pluma: a request of DC 1 waits with no byte (A-129, PlumaPathProber.onSuspect).\n"
     "    void onPlumaPathSuspect(int32_t instanceNum) {\n"
     "        jniEnv[instanceNum]->CallStaticVoidMethod(jclass_ConnectionsManager, jclass_ConnectionsManager_onPlumaPathSuspect, instanceNum);\n"
     "    }\n"
     "\n"
     "    void onProxyError(int32_t instanceNum) {\n"),
    (EDGE_WRAPPER,
     '    jclass_ConnectionsManager_onProxyError = env->GetStaticMethodID(jclass_ConnectionsManager, "onProxyError", "()V");\n'
     "    if (jclass_ConnectionsManager_onProxyError == 0) {\n"
     "        return JNI_FALSE;\n"
     "    }\n",
     '    jclass_ConnectionsManager_onProxyError = env->GetStaticMethodID(jclass_ConnectionsManager, "onProxyError", "()V");\n'
     "    if (jclass_ConnectionsManager_onProxyError == 0) {\n"
     "        return JNI_FALSE;\n"
     "    }\n"
     '    jclass_ConnectionsManager_onPlumaPathSuspect = env->GetStaticMethodID(jclass_ConnectionsManager, "onPlumaPathSuspect", "(I)V");\n'
     "    if (jclass_ConnectionsManager_onPlumaPathSuspect == 0) {\n"
     "        return JNI_FALSE;\n"
     "    }\n"),
    (EDGE_MANAGER_JAVA,
     "    public static void onProxyError() {\n",
     "    // pluma: a request of DC 1 waits with no byte; the paths are measured (A-129).\n"
     "    public static void onPlumaPathSuspect(int currentAccount) {\n"
     "        org.telegram.utils.proxy.PlumaPathProber.onSuspect(currentAccount);\n"
     "    }\n"
     "\n"
     "    public static void onProxyError() {\n"),
)

# What PlumaEdgeBridge relies on in upstream: its package (the WEB proxy's, whose local
# ServerSocket it follows), the WebSocket library, the accounts, the context for its
# preferences, the JSON of the app config.
EDGE_USES = (
    (f"{EDGE_JAVA_DIR}/utils/proxy/WebProxyTransport.java",
     "public final class WebProxyTransport implements ForegroundDetector.Listener {\n"),
    ("TMessagesProj/build.gradle", "    implementation 'com.neovisionaries:nv-websocket-client:2.14'\n"),
    (f"{EDGE_JAVA_DIR}/messenger/UserConfig.java", "    public final static int MAX_ACCOUNT_COUNT = 4;\n"),
    (f"{EDGE_JAVA_DIR}/messenger/ApplicationLoader.java", "    public static volatile Context applicationContext;\n"),
    (f"{EDGE_JAVA_DIR}/tgnet/TLRPC.java", "    public static abstract class JSONValue extends TLObject {\n"),
    # tgnet: initDatacenters, where DC 1 gets its labels, and the timeout of a connection with a
    # request waiting, which makes a frozen direct connection count.
    (EDGE_MANAGER_CPP, "    return ipStrategy;\n}\n\nvoid ConnectionsManager::initDatacenters() {\n"),
    (EDGE_SOCKET_CPP, "        if (!onConnectedSent || hasPendingRequests()) {\n            closeSocket(2, 0);\n"),
    # A-129: PlumaPathProber reads the proxy of the user as ConnectionsManager.init does, follows
    # the app's screen, reads the app config again on a new network, and a new order drops the
    # connections of DC 1 as a new proxy does.
    (EDGE_MANAGER_JAVA,
     '        final SharedPreferences preferences = ApplicationLoader.applicationContext.getSharedPreferences("mainconfig", Activity.MODE_PRIVATE);\n'
     "        final ProxySettings proxySettings = ProxySettings.fromSharedPreferences(preferences);\n"
     '        if (preferences.getBoolean("proxy_enabled", false) && proxySettings.isValid()) {\n'),
    (f"{EDGE_JAVA_DIR}/utils/proxy/ProxySettings.java",
     "    public static ProxySettings fromSharedPreferences(SharedPreferences preferences) {\n"),
    (f"{EDGE_JAVA_DIR}/ui/Components/ForegroundDetector.java",
     "    public interface Listener {\n        void onBecameForeground();\n        void onBecameBackground();\n    }\n"),
    (EDGE_MESSAGES, "    public void loadAppConfig(boolean force) {\n"),
    (EDGE_DATACENTER_H, "    void suspendConnections(bool suspendPush);\n"),
)


def edge_java(c):
    """PlumaEdgeBridge.java with the build's edges."""
    urls = ", ".join(f'"{u}"' for u in c.edge_urls)
    return EDGE_JAVA.replace(EDGE_BUILT_IN_LINE, f"    private static final String[] BUILT_IN = {{{urls}}};\n")


def path_prober_java(c):
    """PlumaPathProber.java with the build's direct address of DC 1 (A-002's)."""
    lines = (f'    private static final String DIRECT_IPV4 = "{c.ipv4}";\n'
             f'    private static final String DIRECT_IPV6 = "{c.ipv6 or ""}";\n'
             f"    private static final int DIRECT_PORT = {c.port};\n")
    return PATH_PROBER_JAVA.replace(PATH_DIRECT_LINES, lines)


EDGE_FILES = (EDGE_FILE, PATH_POLICY_FILE, PATH_PROBER_FILE)


def edge_files(c):
    """The files the edges add: the bridge (A-128), the path policy and the prober (A-129)."""
    return {EDGE_FILE: edge_java(c), PATH_POLICY_FILE: PATH_POLICY_JAVA, PATH_PROBER_FILE: path_prober_java(c)}


def edges(tree, c):
    # A build without edges gets no edit at all (PLUMA_EDGE_WS_URLS empty).
    if not c.edge_urls:
        return
    # Every anchor first, and none of the files yet: a tree that is already patched fails
    # before anything is written twice.
    for rel in EDGE_FILES:
        if (tree.root / rel).exists():
            raise PatchError(f"{rel}: the file is already there")
    for rel, old, _ in EDGE_EDITS:
        tree.expect(rel, old)
    for rel, text in EDGE_USES:
        tree.expect(rel, text)
    for rel, old, new in EDGE_EDITS:
        tree.replace(rel, old, new)
    for rel, text in edge_files(c).items():
        tree.write(rel, text)


def edge_marked(text):
    """Whether text carries an edit of the edges: A-128's names and label, or A-129's."""
    return "plumaedge" in text.lower() or "plumapath" in text.lower() or EDGE_LABEL in text


def verify_edges(tree, c):
    java = tree.root / EDGE_FILE
    if not c.edge_urls:
        for rel in EDGE_FILES:
            if (tree.root / rel).exists():
                raise PatchError(f"{rel}: a build without edges has the bridge or the prober")
        for rel in sorted({rel for rel, _, _ in EDGE_EDITS}):
            if edge_marked(tree.read(rel)):
                raise PatchError(f"{rel}: an edge edit in a build without edges")
        return
    for rel, old, new in EDGE_EDITS:
        text = tree.read(rel)
        if text.count(new) != 1 or text.count(old) != new.count(old):
            changed = next(line for line in new.splitlines() if line not in old.splitlines())
            raise PatchError(f"{rel}: the edge edit {changed.strip()!r} is not there")
    for rel, used in EDGE_USES:
        tree.expect(rel, used)
    if not java.is_file() or java.read_text(encoding="utf-8") != edge_java(c):
        raise PatchError(f"{EDGE_FILE}: not the bridge of this build's edges")
    for rel, text in edge_files(c).items():
        if rel != EDGE_FILE and (not (tree.root / rel).is_file() or tree.read(rel) != text):
            raise PatchError(f"{rel}: not the path prober of this build")
    # The contract: the build's edges are wss://, the direct address goes first by default, and
    # one label prefix ties tgnet to the bridge.
    text = java.read_text(encoding="utf-8")
    built_in = re.findall(r'"([^"]*)"', re.search(r"String\[\] BUILT_IN = \{([^}]*)\};", text).group(1))
    if built_in != c.edge_urls or not all(u.startswith("wss://") for u in built_in):
        raise PatchError(f"{EDGE_FILE}: the build's edges are not its wss:// URLs")
    if text.count("return new Settings(Arrays.asList(BUILT_IN), false, BUILT_IN_STICKY_S);") != 1:
        raise PatchError(f"{EDGE_FILE}: the build's edges do not come after the direct address")
    manager = tree.read(EDGE_MANAGER_CPP)
    if manager.count(f'PLUMA_EDGE_LABEL = "{EDGE_LABEL}";') != 1 or manager.count("datacenters[1]->applyPlumaEdges();") != 1:
        raise PatchError(f"{EDGE_MANAGER_CPP}: DC 1 has no edge labels")
    # The prober goes to the direct address the tgnet edit gives DC 1 (A-002), and probes nothing
    # with a proxy of the user on.
    prober = tree.read(PATH_PROBER_FILE)
    direct = re.findall(r'DIRECT_IPV4 = "([^"]*)";\n.*DIRECT_IPV6 = "([^"]*)";\n.*DIRECT_PORT = (\d+);', prober, re.S)
    if direct != [(c.ipv4, c.ipv6 or "", str(c.port))]:
        raise PatchError(f"{PATH_PROBER_FILE}: the direct address is not DC 1's")
    if (prober.count("return started && !unsupported && !proxied();") != 1
            or prober.count('return main.getBoolean("proxy_enabled", false) && ProxySettings.fromSharedPreferences(main).isValid();') != 1):
        raise PatchError(f"{PATH_PROBER_FILE}: probes with a proxy of the user on")


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


# --- call quality parameters ---------------------------------------------------
# Task 077 of the server repository (stage 2, ADR 0004): the quality values of
# a private call come from phoneCall.custom_parameters, the JSON the server sets
# per call. VoIPService already passes it to tgcalls (Instance.Config
# customParameters, VoIPService.java 3529 at 13.2.1), and InstanceV2Impl, the
# engine of library 9.0.0 the server negotiates between native clients, parses
# it into _customParameters but reads only network_* keys from it. The patch
# reads the keys below at the places tgcalls sets the value today (tgcalls
# 545f5ae, the submodule TMessagesProj/jni/tgcalls of 13.2.1). An absent key,
# a value that is not a number or one out of range keeps upstream's value, so a
# call without custom_parameters is Telegram's call and the server can compare
# both by switching keys (the stock values are in docs/ops/calls.md of the
# server repository). The keys, their units and ranges are the server's
# (pkg/phonecalls/parameters.go): a rate in kbit/s counts 1000 bit/s there,
# while upstream writes its own rates as kbit * 1024 (32 * 1024), so a rate
# member holds bit/s and an absent key keeps upstream's number of bit/s.
# - audio_ptime_ms: Opus packet duration of the sender, upstream 60
#   (OutgoingAudioChannel, kCodecParamPTime). At 60 ms Opus sends three 20 ms
#   frames and in-band FEC repairs only the last of a lost packet (research
#   audio.md, "In-band FEC").
# - audio_max_bitrate_kbps: the audio cap, upstream 32 (adjustBitratePreferences).
# - audio_min_bitrate_kbps: no upstream value. With it the field trial
#   WebRTC-Audio-Allocation/min,max lets the bandwidth estimate move Opus between
#   the two; without it the send stream holds Opus at the cap (min = max,
#   WebRtcAudioSendStream::UpdateAllowedBitrateRange). Field trials are global
#   and webrtc keeps the pointer, so each distinct string is kept for the life
#   of the process (persistentFieldTrials).
# - audio_jitter_min_ms: the receiver's jitter buffer floor, upstream 50
#   (IncomingV2AudioChannel, audio_jitter_buffer_min_delay_ms).
# - audio_rnnoise: RNNoise on the captured voice, the capture post-processor of
#   group calls (GroupAudioCapturePostProcessor, already built on Android);
#   upstream has none in private calls.
# - video_max_bitrate_kbps: the camera cap, upstream 1000.
# - screen_max_bitrate_kbps: the screen cap; upstream sets none, WebRTC's
#   default by frame size applies (research video.md, "Screen-share send cap").
# - start_bitrate_kbps: the start of the bandwidth estimate (CallConfig
#   bitrate_config); upstream sets none, WebRTC starts at 300 kbit/s.
# - screen_max_size_px (Java): the long side of the screen capture,
#   upstream about 1000 px (VideoCapturerDevice.getScreenCaptureSize). The call
#   sets it in NativeInstance.make and clears it in stop(); group calls keep
#   upstream's limit.
# The server's video_fps and screen_fps are not read: Android captures both at
# 30 (VideoCapturerDevice.CAPTURE_FPS), the value the server sends.
TGCALLS = "TMessagesProj/jni/tgcalls/tgcalls"
TGCALLS_V2 = f"{TGCALLS}/v2/InstanceV2Impl.cpp"
TGCALLS_CUSTOM_PARAMETERS = f"{TGCALLS}/v2/CustomParameters.h"
VOIP = "TMessagesProj/src/main/java/org/telegram/messenger/voip"
VIDEO_CAPTURER_DEVICE = f"{VOIP}/VideoCapturerDevice.java"
NATIVE_INSTANCE = f"{VOIP}/NativeInstance.java"

# Key, the C++ member it sets, upstream's value as upstream writes it ("0":
# upstream sets none), the range the server accepts. A *_kbps key is read in
# kbit/s of 1000 bit/s into a member of bit/s. The Java key is apart
# (SCREEN_CAPTURE_KEY).
CALL_PARAMETERS = (
    ("audio_ptime_ms", "_audioPtimeMs", "60", 10, 120),
    ("audio_max_bitrate_kbps", "_audioMaxBitrateBps", "32 * 1024", 6, 128),
    ("audio_min_bitrate_kbps", "audioMinBitrateBps", "0", 6, 128),
    ("audio_jitter_min_ms", "_audioJitterBufferMinDelayMs", "50", 1, 500),
    ("video_max_bitrate_kbps", "_videoMaxBitrateBps", "1000 * 1024", 100, 20000),
    ("screen_max_bitrate_kbps", "_screencastMaxBitrateBps", "0", 100, 20000),
    ("start_bitrate_kbps", "_startBitrateBps", "0", 30, 20000),
)
CALL_RNNOISE_KEY = "audio_rnnoise"
SCREEN_CAPTURE_KEY = "screen_max_size_px"
SCREEN_CAPTURE_RANGE = (320, 3840)
UPSTREAM_FIELD_TRIALS = (
    '            "WebRTC-DataChannel-Dcsctp/Enabled/"\n'
    '            "WebRTC-Audio-MinimizeResamplingOnMobile/Enabled/"\n'
    '            "WebRTC-Audio-iOS-Holding/Enabled/"\n'
    '            "WebRTC-IceFieldTrials/skip_relay_to_non_relay_connections:true/"')


def _call_parameter_reads():
    lines = []
    for key, member, default, low, high in CALL_PARAMETERS:
        target = f"const int {member}" if not member.startswith("_") else member
        read = "getCustomParameterKbpsAsBps" if key.endswith("_kbps") else "getCustomParameterIntOr"
        lines.append(f'        {target} = {read}(_customParameters, "{key}", {default}, {low}, {high});\n')
    lines.append(f'        _audioNoiseSuppression = getCustomParameterBool(_customParameters, "{CALL_RNNOISE_KEY}");\n')
    return "".join(lines)


CALL_PARAMETERS_EDITS = (
    (TGCALLS_CUSTOM_PARAMETERS,
     "} // namespace tgcalls\n\n#endif\n",
     "// pluma: an integer key read against upstream's own value. An absent key, a\n"
     "// value that is not a number or one outside [minValue, maxValue] reads as\n"
     "// defaultValue, so a server value of 0 differs from an absent key and a value\n"
     "// out of range keeps upstream's behaviour. A fraction is truncated.\n"
     "inline int getCustomParameterIntOr(std::map<std::string, json11::Json> const &parameters, std::string const &name, "
     "int defaultValue, int minValue, int maxValue) {\n"
     "    const auto value = parameters.find(name);\n"
     "    if (value != parameters.end() && value->second.is_number()) {\n"
     "        const double number = value->second.number_value();\n"
     "        if (number >= minValue && number <= maxValue) {\n"
     "            return static_cast<int>(number);\n"
     "        }\n"
     "    }\n"
     "    return defaultValue;\n"
     "}\n"
     "\n"
     "// pluma: a rate key in kbit/s of the server, which counts 1000 bit/s, as\n"
     "// bit/s; defaultBps (upstream's own value, which counts a kbit as 1024 bit)\n"
     "// when the key is absent, not a number or outside [minKbps, maxKbps].\n"
     "// minKbps is above 0.\n"
     "inline int getCustomParameterKbpsAsBps(std::map<std::string, json11::Json> const &parameters, std::string const &name, "
     "int defaultBps, int minKbps, int maxKbps) {\n"
     "    const int kbps = getCustomParameterIntOr(parameters, name, 0, minKbps, maxKbps);\n"
     "    return kbps > 0 ? kbps * 1000 : defaultBps;\n"
     "}\n"
     "\n"
     "} // namespace tgcalls\n\n#endif\n"),
    (TGCALLS_V2,
     '#include "v2/CustomParameters.h"\n',
     '#include "v2/CustomParameters.h"\n'
     "// pluma: RNNoise in private calls and the field trials of a call.\n"
     '#include "group/GroupAudioCapturePostProcessor.h"\n'
     "\n"
     "#include <mutex>\n"
     "#include <set>\n"),
    (TGCALLS_V2,
     "namespace {\n\nenum class SignalingProtocolVersion {\n",
     "namespace {\n"
     "\n"
     "// pluma: webrtc::field_trial keeps the pointer it is given\n"
     "// (InitFieldTrialsFromString), so the trial string of a call must outlive the\n"
     "// call. Each distinct string is kept once for the life of the process; the\n"
     "// server sends a few distinct values at most.\n"
     "const char *persistentFieldTrials(std::string const &fieldTrials) {\n"
     "    static std::mutex mutex;\n"
     "    static std::set<std::string> *strings = new std::set<std::string>();\n"
     "    std::lock_guard<std::mutex> lock(mutex);\n"
     "    return strings->insert(fieldTrials).first->c_str();\n"
     "}\n"
     "\n"
     "enum class SignalingProtocolVersion {\n"),
    (TGCALLS_V2,
     "        signaling::MediaContent const &mediaContent,\n"
     "        std::shared_ptr<Threads> threads\n"
     "    ) :\n"
     "    _threads(threads),\n"
     "    _ssrc(mediaContent.ssrc),\n"
     "    _call(call),\n"
     "    _channelManager(channelManager),\n"
     "    _audioSource(audioSource) {\n",
     "        signaling::MediaContent const &mediaContent,\n"
     "        std::shared_ptr<Threads> threads,\n"
     "        int ptimeMs // pluma: the Opus packet duration, upstream 60 ms\n"
     "    ) :\n"
     "    _threads(threads),\n"
     "    _ssrc(mediaContent.ssrc),\n"
     "    _call(call),\n"
     "    _channelManager(channelManager),\n"
     "    _audioSource(audioSource) {\n"),
    (TGCALLS_V2,
     "                codec.SetParam(cricket::kCodecParamPTime, 60);\n",
     "                codec.SetParam(cricket::kCodecParamPTime, ptimeMs); // pluma: upstream 60\n"),
    (TGCALLS_V2,
     "        std::function<void(float, float)> onAudioLevelsUpdated,\n"
     "        std::shared_ptr<Threads> threads) :\n",
     "        std::function<void(float, float)> onAudioLevelsUpdated,\n"
     "        std::shared_ptr<Threads> threads,\n"
     "        int jitterBufferMinDelayMs) : // pluma: the jitter buffer floor, upstream 50 ms\n"),
    (TGCALLS_V2,
     "        audioOptions.audio_jitter_buffer_min_delay_ms = 50;\n",
     "        audioOptions.audio_jitter_buffer_min_delay_ms = jitterBufferMinDelayMs; // pluma: upstream 50\n"),
    (TGCALLS_V2,
     "                            outgoingAudioContent.value(),\n"
     "                            _threads\n"
     "                        ));\n",
     "                            outgoingAudioContent.value(),\n"
     "                            _threads,\n"
     "                            _audioPtimeMs\n"
     "                        ));\n"),
    (TGCALLS_V2,
     "                            content,\n"
     "                            _audioLevelsUpdated,\n"
     "                            _threads\n"
     "                        ));\n",
     "                            content,\n"
     "                            _audioLevelsUpdated,\n"
     "                            _threads,\n"
     "                            _audioJitterBufferMinDelayMs\n"
     "                        ));\n"),
    (TGCALLS_V2,
     f"        webrtc::field_trial::InitFieldTrialsFromString(\n{UPSTREAM_FIELD_TRIALS}\n        );\n",
     "        // pluma: the field trials are set below, once the custom parameters are read.\n"),
    (TGCALLS_V2,
     "            if (customParametersJson.is_object()) {\n"
     "                _customParameters = customParametersJson.object_items();\n"
     "            }\n"
     "        }\n",
     "            if (customParametersJson.is_object()) {\n"
     "                _customParameters = customParametersJson.object_items();\n"
     "            }\n"
     "        }\n"
     "\n"
     "        // pluma: the quality of the call from the server's custom parameters\n"
     "        // (task 077 of the server repository). An absent key keeps upstream's\n"
     "        // value; the server's kbit/s count 1000 bit/s, the members hold bit/s.\n"
     + _call_parameter_reads() +
     "\n"
     f"        std::string fieldTrials =\n{UPSTREAM_FIELD_TRIALS};\n"
     "        // Without a range the send stream holds Opus at its target (min = max,\n"
     "        // WebRtcAudioSendStream::UpdateAllowedBitrateRange); the trial lets the\n"
     "        // bandwidth estimate move it between the two\n"
     "        // (AudioSendStream::GetMinMaxBitrateConstraints).\n"
     "        if (audioMinBitrateBps != 0 && audioMinBitrateBps <= _audioMaxBitrateBps) {\n"
     '            fieldTrials += "WebRTC-Audio-Allocation/min:" + std::to_string(audioMinBitrateBps) + "bps,max:" + '
     'std::to_string(_audioMaxBitrateBps) + "bps/";\n'
     "        }\n"
     "        webrtc::field_trial::InitFieldTrialsFromString(persistentFieldTrials(fieldTrials));\n"
     '        RTC_LOG(LS_INFO) << "Call quality: ptime " << _audioPtimeMs << " ms, audio " << audioMinBitrateBps << "-" '
     '<< _audioMaxBitrateBps << " bps, jitter floor " << _audioJitterBufferMinDelayMs << " ms, rnnoise " '
     '<< _audioNoiseSuppression << ", video " << _videoMaxBitrateBps << ", screen " << _screencastMaxBitrateBps '
     '<< ", start " << _startBitrateBps << " bps";\n'),
    (TGCALLS_V2,
     "            callConfig.audio_state = _channelManager->media_engine()->voice().GetAudioState();\n",
     "            callConfig.audio_state = _channelManager->media_engine()->voice().GetAudioState();\n"
     "            // pluma: the start of the bandwidth estimate; upstream keeps WebRTC's 300 kbit/s.\n"
     "            if (_startBitrateBps != 0) {\n"
     "                callConfig.bitrate_config.start_bitrate_bps = _startBitrateBps;\n"
     "            }\n"),
    (TGCALLS_V2,
     "        webrtc::AudioProcessingBuilder builder;\n"
     "        peerConnectionFactoryDependencies.audio_processing = builder.Create();\n",
     "        webrtc::AudioProcessingBuilder builder;\n"
     "#if USE_RNNOISE\n"
     "        // pluma: RNNoise on the captured voice, the capture post-processor of\n"
     "        // group calls (GroupInstanceCustomImpl), when the server switches it on.\n"
     "        if (_audioNoiseSuppression) {\n"
     "            builder.SetCapturePostProcessing(std::make_unique<AudioCapturePostProcessor>(\n"
     "                [](GroupLevelValue const &) {},\n"
     "                std::make_shared<NoiseSuppressionConfiguration>(true),\n"
     "                nullptr,\n"
     "                nullptr\n"
     "            ));\n"
     "        }\n"
     "#endif\n"
     "        peerConnectionFactoryDependencies.audio_processing = builder.Create();\n"),
    (TGCALLS_V2,
     "        if (_outgoingAudioChannel) {\n"
     "            _outgoingAudioChannel->setMaxBitrate(32 * 1024);\n"
     "        }\n"
     "        if (_outgoingVideoChannel) {\n"
     "            _outgoingVideoChannel->setMaxBitrate(1000 * 1024);\n"
     "        }\n",
     "        // pluma: the caps of the custom parameters; upstream's are 32 and 1000 kbit, the screen has none.\n"
     "        if (_outgoingAudioChannel) {\n"
     "            _outgoingAudioChannel->setMaxBitrate(_audioMaxBitrateBps);\n"
     "        }\n"
     "        if (_outgoingVideoChannel) {\n"
     "            _outgoingVideoChannel->setMaxBitrate(_videoMaxBitrateBps);\n"
     "        }\n"
     "        if (_outgoingScreencastChannel && _screencastMaxBitrateBps != 0) {\n"
     "            _outgoingScreencastChannel->setMaxBitrate(_screencastMaxBitrateBps);\n"
     "        }\n"),
    (TGCALLS_V2,
     "    std::map<std::string, json11::Json> _customParameters;\n",
     "    std::map<std::string, json11::Json> _customParameters;\n"
     "    // pluma: the quality of the call, read from _customParameters in the constructor.\n"
     "    int _audioPtimeMs = 60;\n"
     "    int _audioMaxBitrateBps = 32 * 1024;\n"
     "    int _audioJitterBufferMinDelayMs = 50;\n"
     "    bool _audioNoiseSuppression = false;\n"
     "    int _videoMaxBitrateBps = 1000 * 1024;\n"
     "    int _screencastMaxBitrateBps = 0;\n"
     "    int _startBitrateBps = 0;\n"),
    (VIDEO_CAPTURER_DEVICE,
     "    private static final int CAPTURE_FPS = 30;\n",
     "    private static final int CAPTURE_FPS = 30;\n"
     "\n"
     "    // pluma: the long side of a screen capture in a private call, from the\n"
     "    // call's custom_parameters (NativeInstance.make); 0 keeps upstream's limit\n"
     "    // of about 1000 px. The call writes it, the capture reads it on the UI thread.\n"
     "    public static volatile int screenCaptureMaxSide;\n"),
    (VIDEO_CAPTURER_DEVICE,
     "        if (dx != -1 && aspect != 1) {\n"
     "            while (size.x > 1000 || size.y > 1000 || size.x % roundBy != 0 || size.y % roundBy != 0) {\n"
     "                size.x -= dx;\n"
     "                size.y -= dy;\n"
     "                if (size.x < 800 && size.y < 800) {\n"
     "                    dx = -1;\n"
     "                    break;\n"
     "                }\n"
     "            }\n"
     "        }\n"
     "        if (dx == -1 || aspect == 1) {\n"
     "            float scale = Math.max(size.x / 970.0f, size.y / 970.0f);\n",
     "        // pluma: upstream's 1000, 800 and 970 px, or the call's limit in the same proportions.\n"
     "        final int maxSide = screenCaptureMaxSide;\n"
     "        final int limit = maxSide > 0 ? maxSide : 1000;\n"
     "        final int floor = maxSide > 0 ? maxSide * 4 / 5 : 800;\n"
     "        final float fallback = maxSide > 0 ? maxSide * 0.97f : 970.0f;\n"
     "        if (dx != -1 && aspect != 1) {\n"
     "            while (size.x > limit || size.y > limit || size.x % roundBy != 0 || size.y % roundBy != 0) {\n"
     "                size.x -= dx;\n"
     "                size.y -= dy;\n"
     "                if (size.x < floor && size.y < floor) {\n"
     "                    dx = -1;\n"
     "                    break;\n"
     "                }\n"
     "            }\n"
     "        }\n"
     "        if (dx == -1 || aspect == 1) {\n"
     "            float scale = Math.max(size.x / fallback, size.y / fallback);\n"
     "            if (maxSide > 0) {\n"
     "                scale = Math.max(1.0f, scale); // pluma: a screen under the limit is not enlarged\n"
     "            }\n"),
    (NATIVE_INSTANCE,
     "import org.telegram.messenger.AndroidUtilities;\n",
     "import org.json.JSONException;\n"
     "import org.json.JSONObject;\n"
     "import org.telegram.messenger.AndroidUtilities;\n"),
    (NATIVE_INSTANCE,
     "        instance.nativePtr = makeNativeInstance(version, instance, config, path, endpoints, proxy, networkType, "
     "encryptionKey, remoteSink, videoCapturer, aspectRatio);\n",
     "        // pluma: the screen capture limit of this call (task 077 of the server repository).\n"
     "        VideoCapturerDevice.screenCaptureMaxSide = screenCaptureMaxSide(config.customParameters);\n"
     "        instance.nativePtr = makeNativeInstance(version, instance, config, path, endpoints, proxy, networkType, "
     "encryptionKey, remoteSink, videoCapturer, aspectRatio);\n"),
    (NATIVE_INSTANCE,
     "    public Instance.FinalState stop() {\n"
     "        stopBarrier = new CountDownLatch(1);\n",
     f'    // pluma: "{SCREEN_CAPTURE_KEY}" of the call\'s custom_parameters, 0 when\n'
     f"    // it is absent or outside {SCREEN_CAPTURE_RANGE[0]}-{SCREEN_CAPTURE_RANGE[1]} px.\n"
     "    private static int screenCaptureMaxSide(String customParameters) {\n"
     "        if (customParameters == null || customParameters.isEmpty()) {\n"
     "            return 0;\n"
     "        }\n"
     "        try {\n"
     f'            final Object value = new JSONObject(customParameters).opt("{SCREEN_CAPTURE_KEY}");\n'
     "            if (value instanceof Number) {\n"
     "                final double side = ((Number) value).doubleValue();\n"
     f"                if (side >= {SCREEN_CAPTURE_RANGE[0]} && side <= {SCREEN_CAPTURE_RANGE[1]}) {{\n"
     "                    return (int) side;\n"
     "                }\n"
     "            }\n"
     "        } catch (JSONException e) {\n"
     "            FileLog.e(e);\n"
     "        }\n"
     "        return 0;\n"
     "    }\n"
     "\n"
     "    public Instance.FinalState stop() {\n"
     "        VideoCapturerDevice.screenCaptureMaxSide = 0; // pluma: upstream's limit outside a private call\n"
     "        stopBarrier = new CountDownLatch(1);\n"),
)


def call_parameters(tree):
    # Every anchor first: several edits keep their anchor in the new text, and a
    # tree that is already patched must fail before anything is written twice.
    for rel, old, _ in CALL_PARAMETERS_EDITS:
        tree.expect(rel, old)
    for rel, old, new in CALL_PARAMETERS_EDITS:
        tree.replace(rel, old, new)


def verify_call_parameters(tree):
    for rel, old, new in CALL_PARAMETERS_EDITS:
        text = tree.read(rel)
        if text.count(new) != 1 or text.count(old) != new.count(old):
            changed = next(line for line in new.splitlines() if line not in old.splitlines())
            raise PatchError(f"{rel}: the call quality edit {changed.strip()!r} is not there")
    engine = tree.read(TGCALLS_V2)
    # Upstream's fixed values must be gone, and nothing may set the field trials but the call's string.
    for fixed in ("kCodecParamPTime, 60)", "audio_jitter_buffer_min_delay_ms = 50;", "setMaxBitrate(32 * 1024)",
                  "setMaxBitrate(1000 * 1024)"):
        if fixed in engine:
            raise PatchError(f"{TGCALLS_V2}: upstream's {fixed!r} is still there")
    if engine.count("InitFieldTrialsFromString(") != 1:
        raise PatchError(f"{TGCALLS_V2}: the field trials are set {engine.count('InitFieldTrialsFromString(')} times")
    for key, *_ in CALL_PARAMETERS:
        if engine.count(f'"{key}"') != 1:
            raise PatchError(f"{TGCALLS_V2}: the key {key!r} is read {engine.count(chr(34) + key + chr(34))} times")


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
# a link) and the language code of Tajik (TranslateController, and PlumaMapsProvider
# for the language of map labels).
SCHEME_KEEP = {
    "messenger/FileStreamLoadOperation.java": 1,
    "messenger/MediaController.java": 2,
    "messenger/PlumaMapsProvider.java": 1,
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
    # the verified badge, Telegram's blue rosette with a white check: the accent with the
    # text on the accent
    ("chats_verifiedBackground", -13458971, "#5B7A5E"),
    ("chats_verifiedCheck", None, "#FFFFFF"),
    ("profile_verifiedBackground", None, "#5B7A5E"),
    ("profile_verifiedCheck", None, "#FFFFFF"),
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
    # the verified badge, Telegram's blue rosette with a white check: the accent with the
    # text on the accent
    ("chats_verifiedBackground", -10177041, "#9DBB9F"),
    ("chats_verifiedCheck", None, "#131513"),
    ("profile_verifiedBackground", -10177027, "#9DBB9F"),
    ("profile_verifiedCheck", -1, "#131513"),
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
    # the verified badge, Telegram's blue rosette with a white check: the accent with the
    # text on the accent
    ("chats_verifiedBackground", -11358728, "#5B7A5E"),
    ("chats_verifiedCheck", None, "#FFFFFF"),
    ("profile_verifiedBackground", -11296533, "#5B7A5E"),
    ("profile_verifiedCheck", -1, "#FFFFFF"),
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
    # the verified badge, Telegram's blue rosette with a white check: the accent with the
    # text on the accent
    ("chats_verifiedBackground", -12998152, "#5B7A5E"),
    ("chats_verifiedCheck", None, "#FFFFFF"),
    ("profile_verifiedBackground", -12211980, "#5B7A5E"),
    ("profile_verifiedCheck", -1, "#FFFFFF"),
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
    # the verified badge, Telegram's blue rosette with a white check: the accent with the
    # text on the accent
    ("chats_verifiedBackground", -12145929, "#9DBB9F"),
    ("chats_verifiedCheck", None, "#131513"),
    ("profile_verifiedBackground", -10636552, "#9DBB9F"),
    ("profile_verifiedCheck", -1, "#131513"),
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
    # The verified badge in the participant list of a voice chat, which is
    # always dark and takes no theme colour: Telegram's light blue rosette with
    # a white check becomes the badge of the dark themes, the dark accent with
    # the text on it.
    (f"{JAVA}/ui/Cells/GroupCallUserCell.java",
     "            drawables[0].setColorFilter(new PorterDuffColorFilter(0xff75B3EE, PorterDuff.Mode.MULTIPLY));\n"
     "            drawables[1] = context.getResources().getDrawable(R.drawable.verified_check).mutate();\n",
     "            // pluma: the verified badge of the dark themes, the sage accent with the text on it.\n"
     "            drawables[0].setColorFilter(new PorterDuffColorFilter(0xff9DBB9F, PorterDuff.Mode.MULTIPLY));\n"
     "            drawables[1] = context.getResources().getDrawable(R.drawable.verified_check).mutate();\n"
     "            drawables[1].setColorFilter(new PorterDuffColorFilter(0xff131513, PorterDuff.Mode.MULTIPLY));\n",
     1),
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


# The verified badge (Theme.dialogs_verifiedDrawable and
# profile_verifiedDrawable, the drawables verified_area and verified_check
# that every place tints by these keys) and the colour each part must match in
# every default theme: the rosette the accent of the unread counter, the check
# the text on it. The accent engine alone moves the blue rosette only near the
# accent, a different shade in each theme, and leaves the check white on the
# light sage of the dark themes.
VERIFIED_BADGE = (("chats_verifiedBackground", "chats_unreadCounter"),
                  ("chats_verifiedCheck", "chats_unreadCounterText"),
                  ("profile_verifiedBackground", "chats_unreadCounter"),
                  ("profile_verifiedCheck", "chats_unreadCounterText"))


def default_theme_badges(theme_java, colors_java, theme_files):
    """{theme file: the parts of the verified badge not in the colour they
    must match} for the accents of the default themes, modelled as
    default_theme_blues does."""
    names, defaults = theme_defaults(colors_java)
    fallback, excluded = theme_engine(theme_java)
    by_name = {n: k for k, n in names.items()}
    for key, like in VERIFIED_BADGE:
        if key not in by_name or like not in by_name:
            raise PatchError(f"ThemeColors.java: no colour key {key} or {like}; upstream changed it")
    out = {}
    for theme, (asset, accent_ids, dark) in DEFAULT_THEMES.items():
        wrong = set()
        for accent_id in accent_ids:
            base, accent = theme_accent(theme_java, theme, accent_id)
            colours = theme_colours(theme_files[asset], names, defaults, fallback, excluded, base, accent, dark)
            wrong.update(key for key, like in VERIFIED_BADGE if colours[by_name[key]] != colours[by_name[like]])
        out[asset] = sorted(wrong)
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
    BRAND_COLOURS included, and the verified badge in their accent."""
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
    for asset, wrong in default_theme_badges(theme_java, colors_java, themes).items():
        if wrong:
            raise PatchError(f"{asset}: the verified badge is not the accent with the text on it: {', '.join(wrong)}")


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
    verify_call_parameters(tree)
    verify_group_calls_e2e(tree)
    verify_call_colours(tree)
    verify_birthdays(tree)
    verify_sticker_sets(tree)
    verify_saved_tags(tree)
    verify_round_video(tree)
    verify_cdn_https(tree, c)
    verify_maps(tree)
    verify_premium_stickers(tree)
    verify_premium_for_everyone(tree)
    verify_business(tree)
    verify_not_served(tree)
    verify_edges(tree, c)
    verify_no_ai_editor(tree)
    verify_service_account(tree)
    verify_self_update(tree, c)
    verify_links(tree)
    verify_brand(tree)
    verify_login_screens(tree)



# --- Round videos across chats -------------------------------------------------
# A round video of a channel plays on, item after item, while its comments
# (the discussion group's chat) are open. Upstream's messagePlayingDidStart
# makes the chat on top take the video's texture for any round video: the
# comments chat takes the channel's, does not find the message in its list,
# hides the video (setCurrentVideoVisible(false)) and keeps doing so on every
# scroll update, also while the channel comes back; the channel's round video
# then plays with its picture frozen and the sound going on
# (ChatActivity.java 23658, 16480-16488, 16989-17005; MediaController.java
# 3279-3355). The chat takes the texture only for a message of its own, the
# rule its onAttachedToWindow already follows (18124), with the history of a
# migrated group (mergeDialogId) as its own.
ROUND_VIDEO_EDITS = (
    (CHAT_ACTIVITY,
     "            if ((messageObject.isRoundVideo() || messageObject.isVideo()) && fragmentView != null && fragmentView.getParent() != null) {\n"
     "                if (!messageObject.isVoiceTranscriptionOpen()) {\n",
     "            // pluma: only a message of this chat takes its texture; the comments of a channel\n"
     "            // post would take the channel's round video and freeze its picture.\n"
     "            if ((messageObject.isRoundVideo() || messageObject.isVideo()) && fragmentView != null && fragmentView.getParent() != null\n"
     "                    && (messageObject.getDialogId() == dialog_id || mergeDialogId != 0 && messageObject.getDialogId() == mergeDialogId)) {\n"
     "                if (!messageObject.isVoiceTranscriptionOpen()) {\n"),
)


def round_video(tree):
    for rel, old, new in ROUND_VIDEO_EDITS:
        tree.replace(rel, old, new)


def verify_round_video(tree):
    for rel, old, new in ROUND_VIDEO_EDITS:
        text = tree.read(rel)
        if text.count(new) != 1 or old in text:
            raise PatchError(f"{rel}: the round video edit is not there")

# --- Premium for everyone -----------------------------------------------------
# Task 071 (ADR 0041): every user has Premium and every boost-gated feature is
# open, so the server sends the Premium flag for everybody. Only what the flag
# would make wrong is edited: the star by every name, the purchase rows that
# show for anyone with Premium, and what the server does not serve.
# Voice and round messages keep upstream's transcribe button: the server
# serves messages.transcribeAudio to everyone with Premium (owner, 2026-11-12).
PREMIUM_FOR_EVERYONE_EDITS = (
    ("TMessagesProj/src/main/java/org/telegram/ui/LinkManager.java",
     '        if ("getpremium".equalsIgnoreCase(first))\n            return handleGetPremium(uri.getQueryParameter("ref"));\n',
     '        // pluma: no getpremium route, everybody has Premium (ADR 0041).\n'),
    # The same purchase screen behind the settings/premium link. The
    # settings/business link stays: that screen opens the Business editors
    # (task 105, BUSINESS_EDITS).
    ("TMessagesProj/src/main/java/org/telegram/ui/LinkManager.java",
     '        if ("premium".equalsIgnoreCase(first)) {\n            presentFragment(new PremiumPreviewFragment("link"));\n            return true;\n        }\n\n',
     '        // pluma: no settings/premium link: everybody has Premium (ADR 0041).\n\n'),
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
     "            } else if (user != null && user.premium) {\n                emojiStatusDrawable.set(getContext().getResources().getDrawable(R.drawable.msg_premium_liststar)",
     "            } else if (false) { // pluma: no star: everybody has Premium\n                emojiStatusDrawable.set(getContext().getResources().getDrawable(R.drawable.msg_premium_liststar)"),
    ("TMessagesProj/src/main/java/org/telegram/ui/ProfileActivity.java",
     "                if (!getMessagesController().premiumFeaturesBlocked()) {\n                    premiumRow = rowCount++;\n",
     "                if (!getMessagesController().premiumPurchaseBlocked()) { // pluma: the row is the purchase\n                    premiumRow = rowCount++;\n"),
    ("TMessagesProj/src/main/java/org/telegram/ui/ChatActivity.java",
     "UserObject.getUserName(user))), user.scam, user.fake, user.verified, user.premium, user.emoji_status, animated);",
     "UserObject.getUserName(user))), user.scam, user.fake, user.verified, false, user.emoji_status, animated); // pluma: no star"),
    ("TMessagesProj/src/main/java/org/telegram/ui/Cells/ChatMessageCell.java",
     "            } else if (currentUser.premium) {\n                return ContextCompat.getDrawable(ApplicationLoader.applicationContext, R.drawable.msg_premium_liststar).mutate();",
     "            } else if (false) { // pluma: no star: everybody has Premium\n                return ContextCompat.getDrawable(ApplicationLoader.applicationContext, R.drawable.msg_premium_liststar).mutate();"),
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
    verify_transcribe_button(tree)


# The transcribe button of a voice or round message is upstream's, untouched:
# Premium shows it, and its condition leaves it off a view-once message
# (media.ttl_seconds, set on such a message, is not 0). The view-once player
# (SecretVoicePlayer) draws the same MessageObject in a ChatMessageCell. The
# server refuses to transcribe view-once media, so the button must not show
# there; a build whose condition lost either part stops here.
TRANSCRIBE_CELL = f"{JAVA}/ui/Cells/ChatMessageCell.java"
TRANSCRIBE_START = "        useTranscribeButton = (\n            currentMessageObject != null &&\n"
TRANSCRIBE_PREMIUM = "                UserConfig.getInstance(currentAccount).isPremium()\n                ||\n"
TRANSCRIBE_VIEW_ONCE = ("            (currentMessageObject.messageOwner.media == null"
                        " || currentMessageObject.messageOwner.media.ttl_seconds == 0)\n        );\n")


def verify_transcribe_button(tree):
    text = tree.read(TRANSCRIBE_CELL)
    start = text.find(TRANSCRIBE_START)
    end = text.find(TRANSCRIBE_VIEW_ONCE, start)
    # The view-once part must close the same statement, not a later one.
    if (text.count(TRANSCRIBE_START) != 1 or text.count("useTranscribeButton = (") != 1
            or start < 0 or end < 0 or ";" in text[start:end]):
        raise PatchError(f"{TRANSCRIBE_CELL}: the transcribe button's condition is not upstream's; read it")
    condition = text[start:end + len(TRANSCRIBE_VIEW_ONCE)]
    if condition.count(TRANSCRIBE_PREMIUM) != 1 or "false &&" in condition or "pluma" in condition:
        raise PatchError(f"{TRANSCRIBE_CELL}: the transcribe button is not upstream's for Premium; read its condition")

# --- Telegram Business -------------------------------------------------------
# Task 105 (ADR 0067): the server serves Telegram Business to everybody with
# Premium (everybody, ADR 0041), so the Business rows of the settings and the
# profile are upstream's again (they show when Premium features are not
# blocked) and the settings/business link opens the screen. With Premium the
# screen opens the editors (PremiumPreviewFragment's click listener). Its
# "Do not hide ads" switch is hidden: Pluma has no ads and does not serve
# account.toggleSponsoredMessages, and the settings/business/do-not-hide-ads
# link only opens the screen.
PREMIUM_PREVIEW = f"{JAVA}/ui/PremiumPreviewFragment.java"
BUSINESS_EDITS = (
    (PREMIUM_PREVIEW,
     "        if (type == FEATURES_BUSINESS && getUserConfig().isPremium()) {\n            showAdsHeaderRow = rowCount++;\n",
     "        if (false && type == FEATURES_BUSINESS && getUserConfig().isPremium()) { // pluma: no ads to hide (ADR 0067)\n"
     "            showAdsHeaderRow = rowCount++;\n"),
    (f"{JAVA}/ui/LinkManager.java",
     '            presentFragment(new PremiumPreviewFragment(PremiumPreviewFragment.FEATURES_BUSINESS, "link"));\n'
     '            if ("do-not-hide-ads".equalsIgnoreCase(second)) {\n                scrollTo("showAdsRow");\n            }\n',
     '            presentFragment(new PremiumPreviewFragment(PremiumPreviewFragment.FEATURES_BUSINESS, "link"));\n'
     '            // pluma: no ads switch to scroll to (ADR 0067).\n'),
)
# Upstream's Business rows, which task 071 had hidden; a build that hides
# them again, or an upstream that moved them, stops here.
BUSINESS_ROWS = (
    (f"{JAVA}/ui/SettingsActivity.java",
     "        if (!getMessagesController().premiumFeaturesBlocked()) {\n"
     "            items.add(SettingCell.Factory.of(15, 0xFFF45255, 0xFFDF3955, R.drawable.settings_business, getString(R.string.TelegramBusiness)));\n"),
    (f"{JAVA}/ui/ProfileActivity.java",
     "                if (!getMessagesController().premiumFeaturesBlocked()) {\n                    businessRow = rowCount++;\n"),
    (f"{JAVA}/ui/LinkManager.java",
     '        if ("business".equalsIgnoreCase(first)) {\n'
     '            presentFragment(new PremiumPreviewFragment(PremiumPreviewFragment.FEATURES_BUSINESS, "link"));\n'),
)


def business(tree):
    for rel, old, new in BUSINESS_EDITS:
        tree.replace(rel, old, new)


def verify_business(tree):
    for rel, old, new in BUSINESS_EDITS:
        text = tree.read(rel)
        if text.count(new) != 1 or old in text:
            raise PatchError(f"{rel}: the Business edit of task 105 is not there")
    for rel, row in BUSINESS_ROWS:
        if tree.read(rel).count(row) != 1:
            raise PatchError(f"{rel}: the Business row is not upstream's; read it")
    # The switch's rows stay unset (-1), so nothing else draws or scrolls to it.
    text = tree.read(PREMIUM_PREVIEW)
    if text.count("showAdsRow = rowCount++;") != 1:
        raise PatchError(f"{PREMIUM_PREVIEW}: the ads switch is set elsewhere; read it")

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
     "                plumaTelegramButton.setVisibility(intent != null && !isInCancelAccountDeletionMode() && intent.resolveActivity(getContext().getPackageManager()) != null ? VISIBLE : GONE);\n"
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
    # Back: only the phrase and word codes return to an earlier page. A resend
    # between the pages of task 076 keeps prevType too (AUTH_TYPE_* and VIEW_*
    # share values), and Back would land on the same page or swing between two.
    ("            if (prevType != 0) {\n"
     "                setPage(prevType, true, null, true);\n"
     "                return false;\n"
     "            }\n",
     "            if (prevType == AUTH_TYPE_PHRASE || prevType == AUTH_TYPE_WORD) { // pluma: task 076\n"
     "                setPage(prevType, true, null, true);\n"
     "                return false;\n"
     "            }\n"),
    # "Send again": one request at a time, and a failure is said and leaves the
    # link working.
    ("                if (time > 0 && timeTimer != null) {\n"
     "                    return;\n"
     "                }\n"
     "                isResendingCode = true;\n",
     "                if (time > 0 && timeTimer != null || isResendingCode) { // pluma: one resend at a time (task 076)\n"
     "                    return;\n"
     "                }\n"
     "                isResendingCode = true;\n"),
    ("                        } else if (error != null && error.text != null) {\n"
     "                            AndroidUtilities.runOnUIThread(() -> lastError = error.text);\n"
     "                        }\n",
     "                        } else if (error != null && error.text != null) {\n"
     "                            AndroidUtilities.runOnUIThread(() -> {\n"
     "                                lastError = error.text;\n"
     "                                plumaResendFailed(error); // pluma: task 076\n"
     "                            });\n"
     "                        }\n"),
    # Nothing more can be sent: the administrator gives the code.
    ("                } else {\n"
     "                    if (error.text != null) {\n"
     "                        if (error.text.contains(\"PHONE_NUMBER_INVALID\")) {\n",
     "                } else {\n"
     "                    if (error.text != null && error.text.contains(\"SEND_CODE_UNAVAILABLE\")) {\n"
     "                        plumaAskAdministrator(); // pluma: task 076\n"
     "                    } else if (error.text != null) {\n"
     "                        if (error.text.contains(\"PHONE_NUMBER_INVALID\")) {\n"),
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
     "        // pluma: a \"Send again\" that failed: the link works again and the error is said (task 076).\n"
     "        private void plumaResendFailed(TLRPC.TL_error error) {\n"
     "            isResendingCode = false;\n"
     "            destroyCodeTimer();\n"
     "            timeText.setText(getString(currentType == AUTH_TYPE_SMS ? R.string.PlumaLoginSendAgain : R.string.RequestSmsButton));\n"
     "            ThemeBind.textColor(timeText, Theme.key_chats_actionBackground);\n"
     "            timeText.setTag(R.id.color_key_tag, Theme.key_chats_actionBackground);\n"
     "            timeText.invalidate();\n"
     "            if (error.text.contains(\"PHONE_CODE_EXPIRED\")) {\n"
     "                onBackPressed(true);\n"
     "                setPage(VIEW_PHONE_INPUT, true, null, true);\n"
     "                needShowAlert(getString(R.string.RestorePasswordNoEmailTitle), getString(R.string.CodeExpired));\n"
     "            } else if (error.text.contains(\"SEND_CODE_UNAVAILABLE\")) {\n"
     "                plumaAskAdministrator();\n"
     "            } else if (error.text.startsWith(\"FLOOD_WAIT\")) {\n"
     "                needShowAlert(getString(R.string.RestorePasswordNoEmailTitle), getString(R.string.FloodWait));\n"
     "            } else if (error.code != -1000) {\n"
     "                needShowAlert(getString(R.string.RestorePasswordNoEmailTitle), getString(R.string.ErrorOccurred) + \"\\n\" + error.text);\n"
     "            }\n"
     "        }\n"
     "\n"
     "        // pluma: nothing more can be sent: the administrator issues the code, Telegram's\n"
     "        // support has nothing to do with it (task 076).\n"
     "        private void plumaAskAdministrator() {\n"
     "            new AlertDialog.Builder(getContext())\n"
     "                    .setTitle(getString(R.string.PlumaLoginAdminTitle))\n"
     "                    .setMessage(getString(R.string.PlumaLoginAdminText))\n"
     "                    .setPositiveButton(getString(R.string.OK), null)\n"
     "                    .setNegativeButton(getString(R.string.DidNotGetTheCodeEditNumberButton), (dialog, which) -> setPage(VIEW_PHONE_INPUT, true, null, true))\n"
     "                    .show();\n"
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
LOGIN_MISSING_BODY = "                        plumaAskAdministrator(); // pluma: not Telegram's support (task 076)\n"
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
LOGIN_STRING_LINE = re.compile(r'    <string name="(?:' + "|".join(LOGIN_STRINGS) + r')">[^<]*</string>\n')

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


# --- No AI message editor (task 079) ----------------------------------------
# The AI editor rewrites, proofreads, restyles and translates a typed message
# through messages.composeMessageWithAI, messages.composeRichMessageWithAI and
# the aicompose.* tones; Pluma runs no language model to answer them (the
# owner's decision, 2026-11-11). Upstream offers it from the AI button of the
# message field (ChatActivityEnterView), of the attachment caption
# (ChatAttachAlert, both of its fields), of the media caption
# (CaptionPhotoViewer) and from the rich editor, both the full-screen one
# (RichEditor) and the attachment layout's toolbar (RichEditorToolbar): the
# bottom AI button and the AI style button of the formatting panel. The three
# caption buttons show only through showAiButton, which never shows them now;
# the rich editors' buttons are hidden where they are made, and the formatting
# panels no longer reserve room for the group that holds only the style
# button. AIEditorAlert, RichAIComposeSheet and the tones controller stay in
# the source unreached.
AI_ENTER_VIEW = "TMessagesProj/src/main/java/org/telegram/ui/Components/ChatActivityEnterView.java"
AI_ATTACH_ALERT = "TMessagesProj/src/main/java/org/telegram/ui/Components/ChatAttachAlert.java"
AI_CAPTION_VIEWER = "TMessagesProj/src/main/java/org/telegram/ui/Components/CaptionPhotoViewer.java"
AI_RICH_EDITOR = "TMessagesProj/src/main/java/org/telegram/ui/iv/RichEditor.java"
AI_RICH_TOOLBAR = "TMessagesProj/src/main/java/org/telegram/ui/iv/RichEditorToolbar.java"
AI_RICH_LAYOUT = "TMessagesProj/src/main/java/org/telegram/ui/iv/ChatAttachAlertRichLayout.java"
AI_STYLE_GROUP = "        formattingLayout1.addView(aiStyleButton, LayoutHelper.createLinear(38, 38, Gravity.CENTER_VERTICAL));\n"
AI_STYLE_MEASURE = "                if (formattingLayout1 != null) {\n                    formattingLayout1.measure(\n"
AI_BOTTOM_BUTTON = "        bottomPanel.addView(aiButton, LayoutHelper.createLinear(44, 44, 0, Gravity.LEFT | Gravity.CENTER_VERTICAL, 0, 0, 8, 0));\n"
AI_EDITOR_EDITS = (
    (AI_ENTER_VIEW,
     "    private void showAiButton(boolean show_) {\n"
     "        final boolean show = (show_ || richDraftActive) && parentFragment != null && !parentFragment.isSecretChat();\n",
     "    private void showAiButton(boolean show_) {\n"
     "        final boolean show = false; // pluma: no AI editor, Pluma runs no language model\n"),
    (AI_ATTACH_ALERT,
     "    private void showAiButton(boolean show_) {\n"
     "        final boolean show = show_ && (baseFragment instanceof ChatActivity && !((ChatActivity) baseFragment).isSecretChat());\n",
     "    private void showAiButton(boolean show_) {\n"
     "        final boolean show = false; // pluma: no AI editor, Pluma runs no language model\n"),
    (AI_CAPTION_VIEWER,
     "    private void showAiButton(boolean show_) {\n"
     "        final boolean show = show_;\n",
     "    private void showAiButton(boolean show_) {\n"
     "        final boolean show = false; // pluma: no AI editor, Pluma runs no language model\n"),
    (AI_RICH_EDITOR,
     AI_BOTTOM_BUTTON,
     AI_BOTTOM_BUTTON + "        aiButton.setVisibility(View.GONE); // pluma: no AI editor, Pluma runs no language model\n"),
    (AI_RICH_TOOLBAR,
     AI_BOTTOM_BUTTON,
     AI_BOTTOM_BUTTON + "        aiButton.setVisibility(View.GONE); // pluma: no AI editor, Pluma runs no language model\n"),
) + tuple(
    edit for rel in (AI_RICH_EDITOR, AI_RICH_TOOLBAR) for edit in (
        (rel, AI_STYLE_GROUP, AI_STYLE_GROUP + "        formattingLayout1.setVisibility(View.GONE); // pluma: holds only the AI editor button\n"),
        (rel, AI_STYLE_MEASURE,
         "                if (formattingLayout1 != null && formattingLayout1.getVisibility() != View.GONE) { // pluma: hidden, no AI editor\n"
         "                    formattingLayout1.measure(\n"),
    )
)


def no_ai_editor(tree):
    for rel, old, new in AI_EDITOR_EDITS:
        tree.replace(rel, old, new)


def verify_no_ai_editor(tree):
    for rel, old, new in AI_EDITOR_EDITS:
        text = tree.read(rel)
        # An edit that only adds a line keeps the line it follows.
        if text.count(new) != 1 or text.count(old) != (1 if old in new else 0):
            raise PatchError(f"{rel}: the AI editor is offered again")
    # Every other way to make a button visible or to open the editor would
    # bypass the edits above; upstream adding one stops the patch here.
    for rel, sheet, opens in ((AI_ENTER_VIEW, "new AIEditorAlert(", 2), (AI_ATTACH_ALERT, "new AIEditorAlert(", 2),
                              (AI_CAPTION_VIEWER, "new AIEditorAlert(", 1), (AI_RICH_EDITOR, "new AIEditorAlert(", 1),
                              (AI_RICH_LAYOUT, "new AIEditorAlert(", 1), (AI_RICH_EDITOR, "new RichAIComposeSheet(", 1),
                              (AI_RICH_LAYOUT, "new RichAIComposeSheet(", 1)):
        found = tree.read(rel).count(sheet)
        if found != opens:
            raise PatchError(f"{rel}: {found} ways into the AI editor, expected {opens}; upstream changed them")
    for rel, buttons in ((AI_ENTER_VIEW, ("aiButton",)), (AI_ATTACH_ALERT, ("aiButton", "topAiButton")),
                         (AI_CAPTION_VIEWER, ("aiButton",))):
        text = tree.read(rel)
        for b in buttons:
            if text.count(f"{b}.setVisibility(View.VISIBLE);") != 1:
                raise PatchError(f"{rel}: {b} is shown outside showAiButton; upstream changed it")
    for rel in (AI_RICH_EDITOR, AI_RICH_TOOLBAR):
        text = tree.read(rel)
        if ("aiButton.setVisibility(View.VISIBLE)" in text or "formattingLayout1.setVisibility(View.VISIBLE)" in text
                or text.count("addView(aiStyleButton") != 1):
            raise PatchError(f"{rel}: an AI button of the rich editor is shown again")

# --- Service account (task 080) ----------------------------------------------
# The support account (user.support, which the server sends with no last
# seen) is Pluma's service account and says so where a last seen goes (the
# owner's decision, 2026-11-11). Upstream writes SupportStatus, "support", in
# the chat header (ChatAvatarContainer), both profiles (ProfileActivity,
# ProfileActivity2) and the search row (ProfileSearchCell). The key keeps its
# name and gets the new text in every language the app bundles; upstream has
# it in English only. Every other list (contacts, members, pickers) writes
# LocaleController.formatUserStatus, which says "last seen a long time ago"
# of an account with no status: it answers the same text for a support
# account. A language pack from the server comes before the bundled texts
# (LocaleController.getStringV2), so the server serves these words under
# SupportStatus of the android pack.
SERVICE_ACCOUNT_KEY = "SupportStatus"
SERVICE_ACCOUNT_UPSTREAM = '    <string name="SupportStatus">support</string>\n'
# Lower case where the language writes "online" and "bot" so.
SERVICE_ACCOUNT_STATUS = {
    "values": "service account",
    "values-ar": "حساب خدمة",
    "values-de": "Dienstkonto",
    "values-es": "cuenta de servicio",
    "values-it": "account di servizio",
    "values-ko": "서비스 계정",
    "values-nl": "serviceaccount",
    "values-pt-rBR": "conta de serviço",
    "values-ru": "сервисный аккаунт",
    "values-uk": "сервісний акаунт",
}
# Where upstream writes the key, per file under JAVA. A new place stops the
# patch until it is read: the text no longer says "support".
SERVICE_ACCOUNT_USES = {
    "ui/Cells/ProfileSearchCell.java": 1,
    "ui/Components/ChatAvatarContainer.java": 1,
    "ui/ProfileActivity.java": 1,
    "ui/ProfileActivity2.java": 1,
}
SERVICE_ACCOUNT_LOCALE = f"{JAVA}/messenger/LocaleController.java"
SERVICE_ACCOUNT_FORMAT = (
    "    public static String formatUserStatus(int currentAccount, TLRPC.User user, boolean[] isOnline, boolean[] madeShorter) {\n",
    "    public static String formatUserStatus(int currentAccount, TLRPC.User user, boolean[] isOnline, boolean[] madeShorter) {\n"
    "        if (user != null && user.support) { // pluma: the service account has no last seen\n"
    "            return getString(R.string.SupportStatus);\n"
    "        }\n",
)


def _service_account_line(folder):
    return f'    <string name="{SERVICE_ACCOUNT_KEY}">{SERVICE_ACCOUNT_STATUS[folder]}</string>\n'


def _service_account_uses(tree):
    uses = {}
    for p in sorted((tree.root / JAVA).rglob("*.java")):
        found = p.read_text(encoding="utf-8").count(f"R.string.{SERVICE_ACCOUNT_KEY}")
        if found:
            uses[p.relative_to(tree.root / JAVA).as_posix()] = found
    return uses


def service_account(tree):
    uses = _service_account_uses(tree)
    if uses != SERVICE_ACCOUNT_USES:
        raise PatchError(f"{JAVA}: {SERVICE_ACCOUNT_KEY} is written in {uses}, expected {SERVICE_ACCOUNT_USES}; upstream changed it")
    files = {p.parent.name: str(p.relative_to(tree.root)) for p in sorted((tree.root / RES).glob("values*/strings.xml"))}
    if set(files) != set(SERVICE_ACCOUNT_STATUS):
        raise PatchError(f"{RES}: strings.xml in {', '.join(sorted(files))}, expected {', '.join(sorted(SERVICE_ACCOUNT_STATUS))}")
    for folder, rel in files.items():
        if folder == "values":
            tree.replace(rel, SERVICE_ACCOUNT_UPSTREAM, _service_account_line(folder))
        elif f'<string name="{SERVICE_ACCOUNT_KEY}">' in tree.read(rel):
            raise PatchError(f"{rel}: upstream has a string {SERVICE_ACCOUNT_KEY}; read its text")
        else:
            tree.replace(rel, "</resources>", _service_account_line(folder) + "</resources>")
    tree.replace(SERVICE_ACCOUNT_LOCALE, *SERVICE_ACCOUNT_FORMAT)


def verify_service_account(tree):
    for p in sorted((tree.root / RES).glob("values*/strings.xml")):
        xml = p.read_text(encoding="utf-8")
        folder = p.parent.name
        if (folder not in SERVICE_ACCOUNT_STATUS or xml.count(_service_account_line(folder)) != 1
                or xml.count(f'<string name="{SERVICE_ACCOUNT_KEY}">') != 1):
            raise PatchError(f"{p.relative_to(tree.root)}: {SERVICE_ACCOUNT_KEY} is not the service account's text")
    if tree.read(SERVICE_ACCOUNT_LOCALE).count(SERVICE_ACCOUNT_FORMAT[1]) != 1:
        raise PatchError(f"{SERVICE_ACCOUNT_LOCALE}: formatUserStatus does not name the service account")
    uses = _service_account_uses(tree)
    if uses != {**SERVICE_ACCOUNT_USES, "messenger/LocaleController.java": 1}:
        raise PatchError(f"{JAVA}: {SERVICE_ACCOUNT_KEY} is written in {uses}; a place upstream added is not read")


# --- Group calls end to end (task 094) ----------------------------------------
# ADR 0060 of the server repository: every group call is end-to-end, those of
# groups and channels too, and the server serves no other. Upstream encrypts
# only a conference (VoIPService.isConference(): joinConference or conference
# set); a chat call joins without a key (VoIPService.startGroupCall) and tgcalls
# gets no frame encryption (makeGroup(..., conference != null)). The patch
# gives a chat or channel call the conference's tde2e call object
# (ConferenceCall) and keeps the interface of a chat call:
# - VoIPService.isConference() is the interface's flag (a conference has no
#   chat); `conference != null` stays the crypto flag. Every place that tests
#   either (VoIPService, ChatObject, MessagesController, GroupCallActivity and
#   the call's other views) was read: the chat call's updates are applied by
#   MessagesController (processParticipantsUpdate, processGroupCallUpdate), so
#   VoIPService applies them itself only in a conference; ChatObject keeps the
#   participants who are in the chain but not in the call for every end-to-end
#   call; the rest of `conference != null` is crypto and now holds for every
#   group call, and the rest of isConference() is the conference's interface.
# - The join (startGroupCall) asks the chain's last block, makes the block that
#   adds the user on it and sends it with the user's key, as the conference's
#   join does; the join's chain blocks go to the call object, which polls the
#   chain from then on. A join that lost its height to another block
#   (CONF_WRITE_CHAIN_INVALID) is made again on the new last block, as tdesktop
#   does (GroupCall::joinFail), in the conference too, where upstream ends the
#   call (stopSelf()). ADR 0060 §5: 10 refusals in a row after which the last
#   block did not change end the join; while the chain moves it keeps trying, at
#   most 100 attempts (everyone rejoining at once after an SFU restart gets one
#   join through per round). A join of the instance after the first one (a lost
#   connection, a duplicate SSRC) resets the call object: a new key.
# - tgcalls encrypts the frames of every group call; a chat call keeps three
#   video layers (only a conference sends one, GroupInstanceCustomImpl
#   generateSsrcs), as ADR 0060 decides; NativeInstance.makeGroup takes both
#   flags.
# - The emoji row of the key in the call's list (GroupCallActivity) shows in
#   every end-to-end call.
# - Self-recovery (ADR 0060 §5): any tde2e failure in the call object (upstream
#   logs it and stops the queue, ConferenceCall.readQueue), a chain this client
#   stays behind for 12 s, or GROUPCALL_FORBIDDEN on reading the chain (the
#   server's answer to one removed from it) makes the client join again with a
#   new key, as tdesktop does on any failure ("TdE2E: Got failure, scheduling
#   rejoin!"; tde2e_api.cpp Call::apply fails on every error); at most three
#   times in five minutes, then the call ends with PlumaCallEncryptionFailed.
# - The E2E status report (ADR 0060 §5): every 5 s, over the data channel to the
#   SFU, a JSON message of colibriClass "PlumaE2EStatus" (E2E_STATUS_FIELDS):
#   the heights the client has applied, a prefix of the hash of its last block
#   as the server stores it, the error of its call object, and the frame
#   counters per sender from the encrypt/decrypt callback of tgcalls (the JNI
#   of NativeInstance), with 8-byte prefixes of the epoch hashes the frames name
#   in the clear. No key, nonce, emoji or frame bytes. tgcalls gets a method to
#   send a message of the client's own over its data channel.
# - Removal of who has left (ConferenceCall.updateParticipants) waits for the
#   whole participant list: a chat call loads it in pages of 20, so an end-to-
#   end call loads up to conference_call_size_limit at once.
# - No "join as": the call is joined as the user (the key in the chain is the
#   user's; tdesktop passes userId 0 for a channel and cannot decrypt). The
#   join-as list is never asked for (JoinCallAlert), a channel or chat peer
#   from the intent is dropped, and the "display as" row stays hidden.
# - No RTMP and no live stories: the "stream with another app" row of the
#   sheet that starts a call (CreateGroupCallBottomSheet), the stream mode a
#   join answer could switch to (its parts come from the server unencrypted),
#   the RTMP flag of a new call, the Live tab of the story camera
#   (StoryModeTabs), the link that opens the camera in the live mode
#   (LinkManager, "post/live") and the RTMP rows of the live story settings.
# Group call messages stay as upstream has them (the server does not serve
# them, ADR 0060).
CONFERENCE_CALL = f"{VOIP}/ConferenceCall.java"
VOIP_SERVICE = f"{VOIP}/VoIPService.java"
GROUP_CALL_ACTIVITY = "TMessagesProj/src/main/java/org/telegram/ui/GroupCallActivity.java"
CHAT_OBJECT = "TMessagesProj/src/main/java/org/telegram/messenger/ChatObject.java"
JOIN_CALL_ALERT = "TMessagesProj/src/main/java/org/telegram/ui/Components/JoinCallAlert.java"
CREATE_GROUP_CALL_SHEET = "TMessagesProj/src/main/java/org/telegram/ui/Components/CreateGroupCallBottomSheet.java"
CREATE_RTMP_SHEET = "TMessagesProj/src/main/java/org/telegram/ui/Components/CreateRtmpStreamBottomSheet.java"
STORY_MODE_TABS = "TMessagesProj/src/main/java/org/telegram/ui/Stories/recorder/StoryModeTabs.java"
STORY_PRIVACY_SHEET = "TMessagesProj/src/main/java/org/telegram/ui/Stories/recorder/StoryPrivacyBottomSheet.java"
STORY_RECORDER = "TMessagesProj/src/main/java/org/telegram/ui/Stories/recorder/StoryRecorder.java"
LINK_MANAGER = "TMessagesProj/src/main/java/org/telegram/ui/LinkManager.java"
NATIVE_GROUP_JNI = "TMessagesProj/jni/voip/org_telegram_messenger_voip_Instance.cpp"
TDE2E_BRIDGE = "TMessagesProj/jni/tde2e/bridge.cpp"
TGCALLS_GROUP = f"{TGCALLS}/group/GroupInstanceCustomImpl.cpp"
TGCALLS_GROUP_H = f"{TGCALLS}/group/GroupInstanceCustomImpl.h"
E2E_STATUS_CLASS = "PlumaE2EStatus"
# PlumaE2EStatus v1 (ADR 0060 §5 of the server repository): every field is
# required and no other is allowed. Native (the frame counters of tgcalls):
# "colibriClass", "v" (1), "encrypted" and "encryptFailed" (own frames encrypted
# and failed since the last report), "sendEpochs" (hash prefixes of the epochs
# the last own frame names, at most 15), "decryptEpochs" (those the frames
# decrypted since the last report name, at most 15), "unknownEpochs" (those of
# the frames refused with Decrypt_UnknownEpoch since the last report, the first
# 8), "senders" (per sender with frames since the last report: "user", "ok",
# "unknownEpoch", "tooOld", "duplicate", "failed", "lastOkMs": milliseconds
# since its last decrypted frame, -1 for never). Java: "seq" (from 1 after every
# join), "height" (the applied height of sub-chain 0, -1 without a state),
# "lastBlock" (hash prefix of the block at that height as the server stores it,
# "" without a state), "offset0" and "offset1" (the next offset each sub-chain
# is polled from, -1 before it is known), "error" (the sticky tde2e error code
# of the call object, 0 while it works). Counters and the epoch lists of an
# interval are deltas since the last report; the rest are current values.
E2E_STATUS_NATIVE_FIELDS = ("colibriClass", "v", "encrypted", "encryptFailed", "sendEpochs", "decryptEpochs",
                            "unknownEpochs", "senders")
E2E_STATUS_JAVA_FIELDS = ("seq", "height", "lastBlock", "offset0", "offset1", "error")
E2E_STATUS_FIELDS = E2E_STATUS_NATIVE_FIELDS + E2E_STATUS_JAVA_FIELDS
E2E_STATUS_SENDER_FIELDS = ("user", "ok", "unknownEpoch", "tooOld", "duplicate", "failed", "lastOkMs")
E2E_FAILED_KEY = "PlumaCallEncryptionFailed"
E2E_FAILED_TEXT = {
    "values": "The call\\'s end-to-end encryption could not be restored. Join the call again.",
    "values-ar": "تعذّرت استعادة التشفير التام بين الطرفين للمكالمة. انضم إلى المكالمة مرة أخرى.",
    "values-de": "Die Ende-zu-Ende-Verschlüsselung des Anrufs konnte nicht wiederhergestellt werden. Tritt dem Anruf erneut bei.",
    "values-es": "No se pudo restablecer el cifrado de extremo a extremo de la llamada. Vuelve a unirte a la llamada.",
    "values-it": "Impossibile ripristinare la crittografia end-to-end della chiamata. Unisciti di nuovo alla chiamata.",
    "values-ko": "통화의 종단 간 암호화를 복원하지 못했습니다. 통화에 다시 참여하세요.",
    "values-nl": "De end-to-end-versleuteling van het gesprek kon niet worden hersteld. Neem opnieuw deel aan het gesprek.",
    "values-pt-rBR": "Não foi possível restaurar a criptografia de ponta a ponta da chamada. Entre na chamada novamente.",
    "values-ru": "Не удалось восстановить сквозное шифрование звонка. Войдите в звонок снова.",
    "values-uk": "Не вдалося відновити наскрізне шифрування дзвінка. Увійдіть у дзвінок знову.",
}


def _tabbed(text):
    """VoIPService indents with tabs: the edits are written with four spaces."""
    return re.sub(r"(?m)^((?:    )+)", lambda m: "\t" * (len(m.group(1)) // 4), text)


_VOIP_HELPERS = """\
    // pluma: every group call is end-to-end (ADR 0060). A chat or channel call keeps the
    // interface of a chat call and takes the conference's tde2e call object: it joins with a
    // key and a block, applies the chain's blocks, encrypts its frames and shows the emoji.
    private ConferenceCall plumaChatConference() {
        final ConferenceCall call = new ConferenceCall(currentAccount, UserConfig.getInstance(currentAccount).getClientUserId()) {
            @Override
            protected void gotCallId(long call_id) {
                for (int a = 0; a < 2; ++a) {
                    if (tgVoip[a] != null) {
                        tgVoip[a].setConferenceCallId(call_id);
                    }
                }
            }
        };
        call.inputGroupCall = groupCall.getInputGroupCall();
        call.groupCall = groupCall.call;
        return call;
    }

    // pluma: the join block is made on the chain's last block, as the conference's join does.
    private void plumaJoinOnLastBlock(int ssrc, String json, boolean create) {
        conference.requestLastBlock(() -> {
            if (sharedInstance != this || conference == null || groupCall == null) {
                return;
            }
            if (!plumaChainJoinBase()) {
                NotificationCenter.getInstance(currentAccount).postNotificationName(NotificationCenter.needShowAlert, 6, "CONF_WRITE_CHAIN_INVALID");
                hangUp(0);
                return;
            }
            plumaChainJoinBlock = conference.generateAddSelfBlock();
            plumaSendJoinGroupCall(ssrc, json, create);
        });
    }

    // pluma: a join block that lost its height to another block (CONF_WRITE_CHAIN_INVALID) is made
    // again on the chain's new last block, as tdesktop does (GroupCall::joinFail). ADR 0060 §5: a
    // refusal counts toward the limit of 10 in a row only when the last block read after it is
    // still the one the refused join was made on (the chain stands still, so the refusal is not a
    // race); while the chain moves the join keeps trying, at most 100 attempts in all
    // (conference_call_size_limit): when everyone joins again at once after an SFU restart, each
    // round lets one join through. These retries keep the key and do not count toward the limit
    // of the self-recovery.
    private static final int PLUMA_CHAIN_STALLED_RETRIES = 10;
    private static final int PLUMA_CHAIN_JOIN_ATTEMPTS = 100;
    private int plumaChainRetries;
    private int plumaChainStalledRetries;
    private byte[] plumaChainJoinBase; // the last block the join sent was made on
    private byte[] plumaChainJoinBlock; // the join block sent

    // On CONF_WRITE_CHAIN_INVALID: whether the join may be made once more, and the retry counted.
    private boolean plumaChainRetry() {
        if (plumaChainRetries + 1 >= PLUMA_CHAIN_JOIN_ATTEMPTS) {
            return false;
        }
        plumaChainRetries++;
        return true;
    }

    // With the last block just read, before the join block is made on it: false when it is the
    // 10th refusal in a row after which the chain did not move. A read that brought no block
    // leaves the refused join block as the call object's last block, and counts as no move.
    private boolean plumaChainJoinBase() {
        final byte[] base = conference.getLastBlock();
        if (plumaChainRetries > 0) {
            final boolean moved = !Arrays.equals(base, plumaChainJoinBase) && !Arrays.equals(base, plumaChainJoinBlock);
            plumaChainStalledRetries = moved ? 0 : plumaChainStalledRetries + 1;
            if (plumaChainStalledRetries >= PLUMA_CHAIN_STALLED_RETRIES) {
                FileLog.e("[tde2e] the join is refused " + PLUMA_CHAIN_STALLED_RETRIES + " times in a row on a chain that does not move");
                return false;
            }
        }
        plumaChainJoinBase = base;
        return true;
    }

    // A join that went through, or one that starts over.
    private void plumaChainJoinReset() {
        plumaChainRetries = 0;
        plumaChainStalledRetries = 0;
        plumaChainJoinBase = null;
        plumaChainJoinBlock = null;
    }

    // pluma: self-recovery (ADR 0060 §5). A sticky tde2e error, a chain this client stays behind
    // for 12 s, GROUPCALL_FORBIDDEN on the chain, or 15 s in which no sender's frame decrypts
    // makes it join again with a new key, as tdesktop does on any tde2e failure ("TdE2E: Got
    // failure, scheduling rejoin!"). At most three times in a rolling five minutes, after 0, 2
    // and 5 s plus up to 1 s at random (simultaneous rejoins collide on the chain's height),
    // then the call ends with a message. While a rejoin is pending or under way no condition is
    // checked: the call object is not joined and the reports wait for the new join.
    private static final int PLUMA_E2E_REJOINS = 3;
    private static final long PLUMA_E2E_REJOIN_WINDOW_MS = 5 * 60 * 1000;
    private static final long[] PLUMA_E2E_REJOIN_DELAYS_MS = {0, 2000, 5000};
    private static final int PLUMA_E2E_REJOIN_JITTER_MS = 1000;
    private final ArrayList<Long> plumaE2ERejoins = new ArrayList<>();
    private boolean plumaRejoinPending;

    private final Runnable plumaRejoinRunnable = () -> {
        plumaRejoinPending = false;
        if (sharedInstance != this || conference == null || tgVoip[CAPTURE_DEVICE_CAMERA] == null
                || currentState == STATE_HANGING_UP || currentState == STATE_ENDED) {
            return;
        }
        createGroupInstance(CAPTURE_DEVICE_CAMERA, false, false);
    };

    public void plumaE2EFailed() {
        if (sharedInstance != this || conference == null || tgVoip[CAPTURE_DEVICE_CAMERA] == null || plumaRejoinPending
                || currentState == STATE_HANGING_UP || currentState == STATE_ENDED) {
            return;
        }
        final long now = SystemClock.elapsedRealtime();
        while (!plumaE2ERejoins.isEmpty() && now - plumaE2ERejoins.get(0) > PLUMA_E2E_REJOIN_WINDOW_MS) {
            plumaE2ERejoins.remove(0);
        }
        if (plumaE2ERejoins.size() >= PLUMA_E2E_REJOINS) {
            FileLog.e("[tde2e] the call's encryption failed again, leaving the call");
            final BaseFragment lastFragment = LaunchActivity.getSafeLastFragment();
            if (lastFragment != null) {
                BulletinFactory.of(lastFragment)
                    .createSimpleBulletin(R.raw.error, LocaleController.getString(R.string.PlumaCallEncryptionFailed))
                    .show()
                    .hideAfterBottomSheet = false;
            }
            hangUp(0);
            return;
        }
        final long delay = PLUMA_E2E_REJOIN_DELAYS_MS[plumaE2ERejoins.size()] + Utilities.random.nextInt(PLUMA_E2E_REJOIN_JITTER_MS + 1);
        plumaE2ERejoins.add(now);
        plumaRejoinPending = true;
        AndroidUtilities.cancelRunOnUIThread(plumaE2EStatusRunnable);
        FileLog.d("[tde2e] the call's encryption failed, joining again with a new key in " + delay + " ms");
        AndroidUtilities.runOnUIThread(plumaRejoinRunnable, delay);
    }

    // pluma: the E2E status report, PlumaE2EStatus v1 (ADR 0060 §5): every 5 s after a join,
    // over the data channel of the main connection to the SFU, only while that channel is open;
    // a report not sent leaves its counters to the next one. The frame counters come from
    // tgcalls, the chain's state from the call object; no key, nonce, emoji or frame bytes.
    private static final long PLUMA_E2E_STATUS_INTERVAL_MS = 5000;
    private static final int PLUMA_E2E_STATUS_MAX_BYTES = 16 * 1024;
    private static final int PLUMA_E2E_STATUS_MAX_SENDERS = 100;
    // Rule 4 of the self-recovery: frames come in and none decrypts for 15 s while the client's
    // own chain is current; Web K's synchronization watchdog waits as long
    // (groupCallInstance.ts:51).
    private static final long PLUMA_E2E_UNDECRYPTED_LIMIT_MS = 15_000;
    private final Runnable plumaE2EStatusRunnable = this::plumaSendE2EStatus;
    private int plumaE2EStatusSeq;
    private long plumaE2EStatusAt;
    private long plumaUndecryptedSince;

    // At every join: seq from 1, the counters of the frames before it dropped.
    private void plumaStartE2EStatus() {
        AndroidUtilities.cancelRunOnUIThread(plumaE2EStatusRunnable);
        plumaE2EStatusSeq = 0;
        plumaE2EStatusAt = SystemClock.elapsedRealtime();
        plumaUndecryptedSince = 0;
        for (int a = 0; a < 2; ++a) {
            if (tgVoip[a] != null) {
                tgVoip[a].takeE2EStats();
            }
        }
        AndroidUtilities.runOnUIThread(plumaE2EStatusRunnable, PLUMA_E2E_STATUS_INTERVAL_MS);
    }

    private void plumaSendE2EStatus() {
        final NativeInstance instance = tgVoip[CAPTURE_DEVICE_CAMERA];
        if (sharedInstance != this || conference == null || instance == null || plumaRejoinPending || !conference.joined) {
            return;
        }
        conference.checkError();
        try {
            if (instance.isDataChannelOpen()) {
                final String frames = instance.takeE2EStats();
                if (frames != null) {
                    final JSONObject status = new JSONObject(frames);
                    final NativeInstance screen = tgVoip[CAPTURE_DEVICE_SCREEN];
                    final String screenFrames = screen != null ? screen.takeE2EStats() : null;
                    if (screenFrames != null) {
                        final JSONObject screenStatus = new JSONObject(screenFrames);
                        status.put("encrypted", status.getLong("encrypted") + screenStatus.getLong("encrypted"));
                        status.put("encryptFailed", status.getLong("encryptFailed") + screenStatus.getLong("encryptFailed"));
                    }
                    status.put("seq", ++plumaE2EStatusSeq);
                    conference.putE2EStatus(status);
                    plumaCheckDecryption(status.getJSONArray("senders"));
                    instance.sendDataChannelMessage(plumaFitE2EStatus(status));
                }
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
        if (!plumaRejoinPending) {
            AndroidUtilities.runOnUIThread(plumaE2EStatusRunnable, PLUMA_E2E_STATUS_INTERVAL_MS);
        }
    }

    // Rule 4: every sender with frames in the interval decrypted none of them and had frames
    // refused (an unknown epoch or another failure), for 15 s, while the own chain is current.
    // A sender that alone fails to decrypt is the sender's fault and ends the 15 s; an interval
    // without frames neither starts nor ends them.
    private void plumaCheckDecryption(org.json.JSONArray senders) throws org.json.JSONException {
        final long now = SystemClock.elapsedRealtime();
        final long intervalStart = plumaE2EStatusAt;
        plumaE2EStatusAt = now;
        if (senders.length() == 0) {
            return;
        }
        boolean undecrypted = true;
        for (int i = 0; i < senders.length(); i++) {
            final JSONObject sender = senders.getJSONObject(i);
            undecrypted &= sender.getLong("ok") == 0 && sender.getLong("unknownEpoch") + sender.getLong("failed") > 0;
        }
        if (!undecrypted || conference.chainBehind()) {
            plumaUndecryptedSince = 0;
            return;
        }
        if (plumaUndecryptedSince == 0) {
            plumaUndecryptedSince = intervalStart;
        }
        if (now - plumaUndecryptedSince >= PLUMA_E2E_UNDECRYPTED_LIMIT_MS) {
            plumaUndecryptedSince = 0;
            FileLog.e("[tde2e] no frame decrypted for " + (PLUMA_E2E_UNDECRYPTED_LIMIT_MS / 1000) + " s");
            plumaE2EFailed();
        }
    }

    // At most 100 senders and 16 KiB: the senders whose last decrypted frame is the oldest go
    // first (PlumaE2EStatus v1); the rest stay sorted by user, as tgcalls writes them.
    private static String plumaFitE2EStatus(JSONObject status) throws org.json.JSONException {
        String text = status.toString();
        final org.json.JSONArray senders = status.getJSONArray("senders");
        if (senders.length() <= PLUMA_E2E_STATUS_MAX_SENDERS && text.length() <= PLUMA_E2E_STATUS_MAX_BYTES) {
            return text;
        }
        final ArrayList<JSONObject> kept = new ArrayList<>();
        for (int i = 0; i < senders.length(); i++) {
            kept.add(senders.getJSONObject(i));
        }
        final ArrayList<JSONObject> byAge = new ArrayList<>(kept);
        Collections.sort(byAge, (a, b) -> Long.compare(b.optLong("lastOkMs"), a.optLong("lastOkMs")));
        for (JSONObject oldest : byAge) {
            if (kept.size() <= PLUMA_E2E_STATUS_MAX_SENDERS && text.length() <= PLUMA_E2E_STATUS_MAX_BYTES) {
                break;
            }
            kept.remove(oldest);
            status.put("senders", new org.json.JSONArray(kept));
            text = status.toString();
        }
        return text;
    }

"""

_VOIP_EDITS = (
    # The interface's conference; `conference` itself is the crypto flag.
    ("    public ConferenceCall conference;\n"
     "    @Override\n"
     "    public boolean isConference() {\n"
     "        return joinConference != null || conference != null;\n"
     "    }\n",
     "    public ConferenceCall conference;\n"
     "    // pluma: a conference as the interface sees it. Every group call carries the tde2e call\n"
     "    // object (ADR 0060); a chat or channel call keeps the interface of a chat call.\n"
     "    @Override\n"
     "    public boolean isConference() {\n"
     "        return joinConference != null || conference != null && chat == null;\n"
     "    }\n"),
    ('        isRtmpStream = intent.getBooleanExtra("isRtmpStream", false);\n',
     "        isRtmpStream = false; // pluma: no RTMP streams (ADR 0060)\n"),
    ('        scheduleDate = intent.getIntExtra("scheduleDate", 0);\n',
     "        // pluma: a group call is joined as the user only (ADR 0060): the key in the call's chain\n"
     "        // is the user's, and the server refuses another join_as.\n"
     "        if (groupCallPeer != null && !(groupCallPeer instanceof TLRPC.TL_inputPeerUser)) {\n"
     "            groupCallPeer = null;\n"
     "        }\n"
     "        hasFewPeers = false;\n"
     '        scheduleDate = intent.getIntExtra("scheduleDate", 0);\n'),
    # MessagesController applies a chat call's updates to the same ChatObject.Call.
    ("        if (conference != null) {\n"
     "            groupCall.processParticipantsUpdate(update, false);\n",
     "        if (conference != null) {\n"
     "            if (isConference()) { // pluma: MessagesController applies a chat call's update\n"
     "                groupCall.processParticipantsUpdate(update, false);\n"
     "            }\n"),
    ("        if (conference != null) {\n"
     "            groupCall.processGroupCallUpdate(call);\n"
     "        }\n",
     "        if (isConference()) { // pluma: MessagesController applies a chat call's update\n"
     "            groupCall.processGroupCallUpdate(call);\n"
     "        }\n"),
    ('                newModeStreaming = object.optBoolean("stream");\n',
     "                // pluma: never the stream mode (ADR 0060): its parts come from the server unencrypted.\n"
     "                newModeStreaming = false;\n"),
    ("    private void startGroupCall(int ssrc, String json, boolean create) {\n"
     "        if (sharedInstance != this) {\n",
     _VOIP_HELPERS +
     "    private void startGroupCall(int ssrc, String json, boolean create) {\n"
     "        startGroupCall(ssrc, json, create, false);\n"
     "    }\n"
     "\n"
     "    // pluma: rejoin: the instance joins again (a lost connection, a duplicate SSRC); the call\n"
     "    // object starts over with a new key, as a conference's does (ADR 0060).\n"
     "    private void startGroupCall(int ssrc, String json, boolean create, boolean rejoin) {\n"
     "        if (sharedInstance != this) {\n"),
    ("            if (groupCall == null && chat != null) {\n"
     "                groupCall = MessagesController.getInstance(currentAccount).getGroupCall(chat.id, false);\n"
     "                if (groupCall != null) {\n"
     "                    groupCall.setSelfPeer(groupCallPeer);\n"
     "                }\n"
     "            }\n",
     "            if (groupCall == null && chat != null) {\n"
     "                groupCall = MessagesController.getInstance(currentAccount).getGroupCall(chat.id, false);\n"
     "                if (groupCall != null) {\n"
     "                    groupCall.setSelfPeer(groupCallPeer);\n"
     "                }\n"
     "            }\n"
     "            if (groupCall != null && conference == null) {\n"
     "                conference = plumaChatConference(); // pluma: before the instance, which encrypts with it\n"
     "            }\n"),
    # The join goes out on the chain's last block, from a method of its own.
    ("            dispatchStateChanged(STATE_WAIT_INIT);\n"
     "            if (BuildVars.LOGS_ENABLED) {\n"
     '                FileLog.d("initital source = " + ssrc);\n'
     "            }\n"
     "            final TL_phone.joinGroupCall req = new TL_phone.joinGroupCall();\n",
     "            dispatchStateChanged(STATE_WAIT_INIT);\n"
     "            if (BuildVars.LOGS_ENABLED) {\n"
     '                FileLog.d("initital source = " + ssrc);\n'
     "            }\n"
     "            // pluma: the join carries the user's key and the block that adds them to the call's\n"
     "            // chain (ADR 0060). An instance made without frame encryption never joins.\n"
     "            if (conference == null) {\n"
     '                FileLog.e("[tde2e] a group call without its call object, leaving it");\n'
     "                hangUp(0);\n"
     "                return;\n"
     "            }\n"
     "            if (rejoin) {\n"
     "                conference.reset();\n"
     "            }\n"
     "            plumaChainJoinReset();\n"
     "            plumaJoinOnLastBlock(ssrc, json, create);\n"
     "        }\n"
     "    }\n"
     "\n"
     "    private void plumaSendJoinGroupCall(int ssrc, String json, boolean create) {\n"
     "        {\n"
     "            final TL_phone.joinGroupCall req = new TL_phone.joinGroupCall();\n"),
    ("            req.call = groupCall.getInputGroupCall();\n"
     "            req.params = new TLRPC.TL_dataJSON();\n"
     "            req.params.data = json;\n",
     "            req.call = groupCall.getInputGroupCall();\n"
     "            req.params = new TLRPC.TL_dataJSON();\n"
     "            req.params.data = json;\n"
     "            req.flags |= 8; // pluma: the key and the join block (ADR 0060)\n"
     "            req.public_key = conference.getMyPublicKey();\n"
     "            req.block = conference.getLastBlock();\n"),
    ("                    TLRPC.Updates updates = (TLRPC.Updates) response;\n"
     "                    long selfId = getSelfId();\n"
     "                    for (int a = 0, N = updates.updates.size(); a < N; a++) {\n",
     "                    TLRPC.Updates updates = (TLRPC.Updates) response;\n"
     "                    long selfId = getSelfId();\n"
     "                    // pluma: the chain's blocks of the join go to the call object (ADR 0060).\n"
     "                    final ArrayList<TL_update.TL_updateGroupCallChainBlocks> blockUpdates = findUpdatesAndRemove(updates, TL_update.TL_updateGroupCallChainBlocks.class);\n"
     "                    for (int a = 0, N = updates.updates.size(); a < N; a++) {\n"),
    ("                    MessagesController.getInstance(currentAccount).processUpdates(updates, false);\n"
     "                    AndroidUtilities.runOnUIThread(() -> groupCall.loadMembers(create));\n"
     "                    startGroupCheckShortpoll();\n",
     "                    MessagesController.getInstance(currentAccount).processUpdates(updates, false);\n"
     "                    AndroidUtilities.runOnUIThread(() -> {\n"
     "                        // pluma: the call object takes the join's blocks and polls the chain, as a\n"
     "                        // conference's does (ADR 0060).\n"
     "                        if (conference != null) {\n"
     "                            plumaChainJoinReset();\n"
     "                            conference.joined();\n"
     "                            for (TL_update.TL_updateGroupCallChainBlocks upd : blockUpdates) {\n"
     "                                conference.applyUpdate(0, upd, true, null);\n"
     "                            }\n"
     "                            conference.forcePoll();\n"
     "                            for (int a = 0; a < 2; ++a) {\n"
     "                                if (tgVoip[a] != null) {\n"
     "                                    tgVoip[a].setConferenceCallId(conference.getCallId());\n"
     "                                }\n"
     "                            }\n"
     "                            plumaStartE2EStatus();\n"
     "                        }\n"
     "                        groupCall.loadMembers(create);\n"
     "                    });\n"
     "                    startGroupCheckShortpoll();\n"),
    ('                        } else if ("GROUPCALL_SSRC_DUPLICATE_MUCH".equals(error.text)) {\n'
     "                            createGroupInstance(CAPTURE_DEVICE_CAMERA, false, false);\n"
     "                        } else {\n",
     '                        } else if ("GROUPCALL_SSRC_DUPLICATE_MUCH".equals(error.text)) {\n'
     "                            createGroupInstance(CAPTURE_DEVICE_CAMERA, false, false);\n"
     '                        } else if (error.text.startsWith("CONF_WRITE_CHAIN_INVALID") && conference != null && plumaChainRetry()) {\n'
     "                            // pluma: another block took the height first (ADR 0060 §5): the join block is\n"
     "                            // made again on the chain's new last block, as tdesktop does (GroupCall::joinFail).\n"
     "                            plumaJoinOnLastBlock(ssrc, json, create);\n"
     "                        } else {\n"),
    # The conference's join: the same retry instead of ending the call. A join that starts over
    # (reconnect) starts its counts over; one that follows a refusal checks whether the chain moved.
    ("            if (reconnect) {\n"
     "                conference.reset();\n"
     "            }\n"
     "            conference.requestLastBlock(() -> {\n"
     "                if (conference == null) {\n"
     "                    return;\n"
     "                }\n"
     "                conference.generateAddSelfBlock();\n"
     "                join.run();\n",
     "            if (reconnect) {\n"
     "                conference.reset();\n"
     "                plumaChainJoinReset(); // pluma: ADR 0060 §5\n"
     "            }\n"
     "            conference.requestLastBlock(() -> {\n"
     "                if (conference == null) {\n"
     "                    return;\n"
     "                }\n"
     "                if (!plumaChainJoinBase()) { // pluma: the chain does not move (ADR 0060 §5)\n"
     "                    stopSelf();\n"
     "                    return;\n"
     "                }\n"
     "                plumaChainJoinBlock = conference.generateAddSelfBlock();\n"
     "                join.run();\n"),
    ('                            } else if (error.text.startsWith("CONF_WRITE_CHAIN_INVALID")) {\n'
     "                                stopSelf();\n",
     '                            } else if (error.text.startsWith("CONF_WRITE_CHAIN_INVALID")) {\n'
     "                                // pluma: another block took the height first (ADR 0060): join again on the\n"
     "                                // chain's new last block, as tdesktop does (GroupCall::joinFail).\n"
     "                                if (plumaChainRetry()) {\n"
     "                                    startConferenceGroupCall(false, ssrc, json, false);\n"
     "                                } else {\n"
     "                                    stopSelf();\n"
     "                                }\n"),
    ("                            if (conference == null) return;\n"
     "                            conference.joined();\n",
     "                            if (conference == null) return;\n"
     "                            conference.joined();\n"
     "                            plumaChainJoinReset(); // pluma: ADR 0060\n"
     "                            plumaStartE2EStatus();\n"),
    ("                    if (conference != null) {\n"
     "                        startConferenceGroupCall(false, ssrc, json, !first[0]);\n"
     "                    } else {\n"
     "                        startGroupCall(ssrc, json, true);\n"
     "                    }\n",
     "                    if (isConference()) {\n"
     "                        startConferenceGroupCall(false, ssrc, json, !first[0]);\n"
     "                    } else {\n"
     "                        startGroupCall(ssrc, json, true, !first[0]); // pluma: a new key when joining again\n"
     "                    }\n"),
    ("            }, conference != null);\n",
     "            }, conference != null, isConference()); // pluma: frames encrypted in every group call, one video layer in a conference only\n"),
    ("        if (conference != null) {\n"
     "            conference.destroy();\n"
     "        }\n"
     "        super.onDestroy();\n",
     "        AndroidUtilities.cancelRunOnUIThread(plumaE2EStatusRunnable); // pluma: ADR 0060\n"
     "        AndroidUtilities.cancelRunOnUIThread(plumaRejoinRunnable);\n"
     "        if (conference != null) {\n"
     "            conference.destroy();\n"
     "        }\n"
     "        super.onDestroy();\n"),
)

_CONFERENCE_STATUS = """\
    // pluma: self-recovery and the E2E status report (ADR 0060 §5).
    private static final long BEHIND_LIMIT_MS = 12_000;
    private byte[] lastAppliedBlock;
    private int serverNextOffset = -1;
    private long behindSince;
    private boolean failureReported;

    // Any tde2e failure makes the client join again with a new key, as tdesktop does
    // (tde2e_api.cpp Call::apply fails on every error; GroupCall: "TdE2E: Got failure,
    // scheduling rejoin!"). VoIPService limits how often.
    private void fail(String why) {
        if (destroyed || !joined || failureReported) {
            return;
        }
        failureReported = true;
        FileLog.e("[tde2e] " + why + ", joining again");
        AndroidUtilities.runOnUIThread(() -> {
            final VoIPService voip = VoIPService.getSharedInstance();
            if (voip != null && voip.conference == this) {
                voip.plumaE2EFailed();
            }
        });
    }

    // The server is ahead of the blocks this client has applied for longer than a key change
    // takes: the client no longer follows the chain.
    private void checkBehind() {
        if (call_id < 0 || last_offset[0] < 0 || last_offset[0] >= serverNextOffset) {
            behindSince = 0;
            return;
        }
        final long now = System.currentTimeMillis();
        if (behindSince == 0) {
            behindSince = now;
        } else if (now - behindSince > BEHIND_LIMIT_MS) {
            fail("sub-chain 0 is at " + serverNextOffset + ", applied up to " + last_offset[0]);
        }
    }

    // Rule 2 of the self-recovery is under way or the state is not built: the own chain is not
    // current, and frames that fail to decrypt say nothing about this client (rule 4).
    public boolean chainBehind() {
        return call_id < 0 || last_offset[0] < 0 || last_offset[0] < serverNextOffset;
    }

    // Rule 1: a sticky tde2e error of the call object, which every call of it answers
    // (tde2e Call::get_status); the report's tick looks for one that no block apply has shown.
    public void checkError() {
        if (call_id >= 0) {
            final int code = call_get_error_code(call_id);
            if (code != 0) {
                fail("the call object failed with tde2e error " + code);
            }
        }
    }

    // The chain's part of PlumaE2EStatus v1: the applied height of sub-chain 0 (-1 without a
    // state, before the join or after a failure), a prefix of the hash of the block at that
    // height as the server stores it, the offsets each sub-chain is polled from, the sticky
    // error of the call object.
    public void putE2EStatus(JSONObject status) throws JSONException {
        int height = -1;
        if (call_id >= 0) {
            try {
                height = call_get_height(call_id);
            } catch (Exception e) {
                height = -1;
            }
        }
        status.put("height", height);
        status.put("lastBlock", height >= 0 && lastAppliedBlock != null ? blockHashPrefix(lastAppliedBlock) : "");
        status.put("offset0", last_offset[0]);
        status.put("offset1", last_offset[1]);
        status.put("error", call_id >= 0 ? call_get_error_code(call_id) : 0);
    }

    // The server sends a block with its first int32 one more than it stores (tde2e
    // Blockchain::from_server_to_local); the hash is that of the stored block.
    private static String blockHashPrefix(byte[] block) {
        if (block.length < 4) {
            return "";
        }
        final byte[] stored = block.clone();
        int magic = (stored[0] & 0xff) | (stored[1] & 0xff) << 8 | (stored[2] & 0xff) << 16 | (stored[3] & 0xff) << 24;
        magic--;
        stored[0] = (byte) magic;
        stored[1] = (byte) (magic >> 8);
        stored[2] = (byte) (magic >> 16);
        stored[3] = (byte) (magic >> 24);
        final byte[] hash = Utilities.computeSHA256(stored);
        return Utilities.bytesToHex(Arrays.copyOf(hash, 8)).toLowerCase(Locale.ROOT);
    }

"""

_CONFERENCE_EDITS = (
    ("import org.telegram.messenger.AndroidUtilities;\n",
     "import org.json.JSONException;\n"
     "import org.json.JSONObject;\n"
     "import org.telegram.messenger.AndroidUtilities;\n"),
    ("import java.util.Iterator;\n",
     "import java.util.Iterator;\n"
     "import java.util.Locale;\n"),
    ("    public static native void call_destroy_all();\n",
     "    public static native void call_destroy_all();\n"
     "    // pluma: the tde2e error code the call object has failed with, 0 while it works (ADR 0060).\n"
     "    public static native int call_get_error_code(long call_id);\n"),
    ("    public TLRPC.InputGroupCall inputGroupCall;\n",
     "    public TLRPC.InputGroupCall inputGroupCall;\n"
     "\n" + _CONFERENCE_STATUS.rstrip("\n") + "\n"),
    ("                        call_id = call_create(my_user_id, my_private_key_id, last_block = block);\n",
     "                        call_id = call_create(my_user_id, my_private_key_id, last_block = block);\n"
     "                        lastAppliedBlock = block;\n"),
    ('                                FileLog.d("[tde2e] #" + index + " call_apply_block(" + call_id + ", " + blockStr(block) + ") = " + call_apply_block(call_id, block));\n',
     '                                FileLog.d("[tde2e] #" + index + " call_apply_block(" + call_id + ", " + blockStr(block) + ") = " + call_apply_block(call_id, block));\n'
     "                                lastAppliedBlock = block;\n"),
    ('                    FileLog.e("[tde2e] {subchain: " + sub_chain + "} #" + index + " block got into error: ", e);\n'
     "                    return;\n",
     '                    FileLog.e("[tde2e] {subchain: " + sub_chain + "} #" + index + " block got into error: ", e);\n'
     '                    fail("block #" + index + " of sub-chain " + sub_chain + " failed"); // pluma: ADR 0060\n'
     "                    return;\n"),
    ("                if (sub_chain == 0 && !had_call && has_call) {\n"
     "                    readQueue(1);\n"
     "                }\n"
     "            }\n",
     "                if (sub_chain == 0 && !had_call && has_call) {\n"
     "                    readQueue(1);\n"
     "                }\n"
     "            }\n"
     "            if (sub_chain == 0) { // pluma: how far the server's chain is (ADR 0060)\n"
     "                if (requested_offset == null || requested_offset != -1) {\n"
     "                    serverNextOffset = Math.max(serverNextOffset, next_offset);\n"
     "                }\n"
     "                checkBehind();\n"
     "            }\n"),
    ("        polling = true;\n"
     "        final AtomicInteger received = new AtomicInteger(0);\n",
     "        checkBehind(); // pluma: ADR 0060\n"
     "        polling = true;\n"
     "        final AtomicInteger received = new AtomicInteger(0);\n"),
    # Every answer of the chain goes through processUpdates: the poll and the last
    # block (reads), the broadcasts and the removals (writes).
    ("    private boolean processUpdates(Integer requested_offset, Long requestTime, TLObject res, TLRPC.TL_error err) {\n"
     "        boolean hadBlocks = false;\n",
     "    private boolean processUpdates(Integer requested_offset, Long requestTime, TLObject res, TLRPC.TL_error err) {\n"
     "        boolean hadBlocks = false;\n"
     '        if (err != null && "GROUPCALL_FORBIDDEN".equals(err.text)) {\n'
     "            // pluma: rule 3 of the self-recovery (ADR 0060 §5): the chain refuses this client, on\n"
     "            // a write (a broadcast, a removal) or a read, as tdesktop rejoins on both\n"
     "            // (calls_group_call.cpp:848-853, 1909-1917, 1930-1934). Before the join it is ignored.\n"
     '            fail("the call\'s chain answered GROUPCALL_FORBIDDEN");\n'
     "        }\n"),
    ("        final Set<Long> leftParticipants = getShadyLeftParticipants(participants);\n"
     "        if (!leftParticipants.isEmpty()) {\n",
     "        final Set<Long> leftParticipants = getShadyLeftParticipants(participants);\n"
     "        // pluma: who has left is known from the whole list of participants only, which a chat\n"
     "        // call loads in pages (ADR 0060).\n"
     "        final VoIPService voip = VoIPService.getSharedInstance();\n"
     "        final boolean listLoaded = voip == null || voip.groupCall == null || voip.groupCall.membersLoadEndReached;\n"
     "        if (listLoaded && !leftParticipants.isEmpty()) {\n"),
    ("    public void reset() {\n"
     "        AndroidUtilities.cancelRunOnUIThread(pollRunnable);\n"
     "        if (call_id != -1) {\n"
     "            for (int a = 0; a < 2; ++a) {\n"
     "                if (pollRequestId[a] != 0) {\n"
     "                    ConnectionsManager.getInstance(currentAccount).cancelRequest(pollRequestId[a], true);\n"
     "                    pollRequestId[a] = 0;\n"
     "                }\n"
     "            }\n"
     "\n"
     "            call_destroy(call_id);\n",
     "    public void reset() {\n"
     "        AndroidUtilities.cancelRunOnUIThread(pollRunnable);\n"
     "        // pluma: a poll in flight belongs to the old key, with or without a call object, and the\n"
     "        // client is not joined until the new join answers (ADR 0060).\n"
     "        for (int a = 0; a < 2; ++a) {\n"
     "            if (pollRequestId[a] != 0) {\n"
     "                ConnectionsManager.getInstance(currentAccount).cancelRequest(pollRequestId[a], true);\n"
     "                pollRequestId[a] = 0;\n"
     "            }\n"
     "        }\n"
     "        polling = false;\n"
     "        joined = false;\n"
     "        failureReported = false;\n"
     "        lastAppliedBlock = null;\n"
     "        serverNextOffset = -1;\n"
     "        behindSince = 0;\n"
     "        if (call_id != -1) {\n"
     "            call_destroy(call_id);\n"),
)

_PLUMA_E2E_STATS = r"""// pluma: frame counters of an end-to-end group call for the E2E status report, PlumaE2EStatus
// v1 (ADR 0060 §5), taken every 5 s by VoIPService. A tde2e frame (tde2e Call.cpp
// CallEncryption::decrypt) is the clear prefix, an int32 head whose low byte is the number of
// epochs, a 32-byte hash per epoch, the encrypted rest and the prefix length as the last
// uint32. Only the epoch hashes, which the SFU sees in every frame, leave the device, as 8-byte
// prefixes; no key and no frame bytes. The counters and the epochs of decrypted and refused
// frames are deltas since the last take; sendEpochs and lastOkMs are current values.
struct PlumaE2EStats {
    struct Sender {
        uint32_t ok = 0;
        uint32_t unknownEpoch = 0;
        uint32_t tooOld = 0;
        uint32_t duplicate = 0;
        uint32_t failed = 0;
        int64_t lastOkAt = -1;
    };
    static constexpr size_t kHashPrefix = 8;
    static constexpr size_t kMaxSendEpochs = 15;
    static constexpr size_t kMaxDecryptEpochs = 15;
    static constexpr size_t kMaxUnknownEpochs = 8;

    std::mutex mutex;
    std::map<int64_t, Sender> senders;
    std::vector<uint64_t> sendEpochs;
    std::set<uint64_t> decryptEpochs;
    std::set<uint64_t> unknownEpochs;
    uint32_t encrypted = 0;
    uint32_t encryptFailed = 0;

    static int64_t nowMs() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
    }

    // The 8-byte prefixes of the epoch hashes of a frame whose encrypted part starts at offset.
    static std::vector<uint64_t> epochs(const uint8_t *data, size_t size, size_t offset, size_t limit) {
        std::vector<uint64_t> result;
        if (offset > size || size - offset < 4) {
            return result;
        }
        const size_t count = data[offset];
        offset += 4;
        for (size_t i = 0; i < count && result.size() < limit && size - offset >= 32; i++, offset += 32) {
            uint64_t prefix = 0;
            for (size_t j = 0; j < kHashPrefix; j++) {
                prefix = (prefix << 8) | data[offset + j];
            }
            result.push_back(prefix);
        }
        return result;
    }

    // The epochs a received frame names: its clear prefix length is its last uint32.
    static std::vector<uint64_t> receivedEpochs(const std::vector<uint8_t> &frame, size_t limit) {
        if (frame.size() < 4) {
            return {};
        }
        const size_t end = frame.size() - 4;
        const uint32_t prefixSize = uint32_t(frame[end]) | (uint32_t(frame[end + 1]) << 8) | (uint32_t(frame[end + 2]) << 16) | (uint32_t(frame[end + 3]) << 24);
        return epochs(frame.data(), end, prefixSize, limit);
    }

    static void addEpochs(std::set<uint64_t> &to, const std::vector<uint64_t> &found, size_t limit) {
        for (uint64_t prefix : found) {
            if (to.size() >= limit) {
                return;
            }
            to.insert(prefix);
        }
    }

    static std::string hex(uint64_t prefix) {
        static const char digits[] = "0123456789abcdef";
        std::string out(kHashPrefix * 2, '0');
        for (size_t i = 0; i < kHashPrefix * 2; i++) {
            out[kHashPrefix * 2 - 1 - i] = digits[prefix & 15];
            prefix >>= 4;
        }
        return out;
    }

    template <typename Container>
    static std::string hexList(const Container &prefixes) {
        std::string json = "[";
        for (uint64_t prefix : prefixes) {
            json += (json.size() > 1 ? ",\"" : "\"") + hex(prefix) + "\"";
        }
        return json + "]";
    }

    void encryptedOnce(const std::string &frame, int32_t prefixSize) {
        auto found = epochs(reinterpret_cast<const uint8_t *>(frame.data()), frame.size(), size_t(prefixSize), kMaxSendEpochs);
        std::lock_guard<std::mutex> lock(mutex);
        encrypted++;
        sendEpochs = std::move(found);
    }

    void encryptFailedOnce() {
        std::lock_guard<std::mutex> lock(mutex);
        encryptFailed++;
    }

    void decrypted(int64_t userId, const std::vector<uint8_t> &frame) {
        std::lock_guard<std::mutex> lock(mutex);
        auto &sender = senders[userId];
        sender.ok++;
        sender.lastOkAt = nowMs();
        if (decryptEpochs.size() < kMaxDecryptEpochs) {
            addEpochs(decryptEpochs, receivedEpochs(frame, kMaxDecryptEpochs), kMaxDecryptEpochs);
        }
    }

    void decryptFailed(int64_t userId, const tde2e_api::Error &error, const std::vector<uint8_t> &frame) {
        std::lock_guard<std::mutex> lock(mutex);
        auto &sender = senders[userId];
        if (error.code == tde2e_api::ErrorCode::Decrypt_UnknownEpoch) {
            sender.unknownEpoch++;
            if (unknownEpochs.size() < kMaxUnknownEpochs) {
                addEpochs(unknownEpochs, receivedEpochs(frame, kMaxUnknownEpochs), kMaxUnknownEpochs);
            }
        } else if (error.message.find("Message is too old") != std::string::npos) {
            sender.tooOld++;
        } else if (error.message.find("Message is already processed") != std::string::npos) {
            sender.duplicate++;
        } else {
            sender.failed++;
        }
    }

    // The report's part of tgcalls: the deltas since the last call, then zero. Senders come in
    // the order of their user id, those without frames since the last call left out.
    std::string take() {
        std::lock_guard<std::mutex> lock(mutex);
        const int64_t now = nowMs();
        std::string json = "{\"colibriClass\":\"PlumaE2EStatus\",\"v\":1"
                ",\"encrypted\":" + std::to_string(encrypted)
                + ",\"encryptFailed\":" + std::to_string(encryptFailed)
                + ",\"sendEpochs\":" + hexList(sendEpochs)
                + ",\"decryptEpochs\":" + hexList(decryptEpochs)
                + ",\"unknownEpochs\":" + hexList(unknownEpochs)
                + ",\"senders\":[";
        bool first = true;
        for (auto &[userId, sender] : senders) {
            if (sender.ok + sender.unknownEpoch + sender.tooOld + sender.duplicate + sender.failed == 0) {
                continue;
            }
            json += first ? "{" : ",{";
            first = false;
            json += "\"user\":" + std::to_string(userId)
                    + ",\"ok\":" + std::to_string(sender.ok)
                    + ",\"unknownEpoch\":" + std::to_string(sender.unknownEpoch)
                    + ",\"tooOld\":" + std::to_string(sender.tooOld)
                    + ",\"duplicate\":" + std::to_string(sender.duplicate)
                    + ",\"failed\":" + std::to_string(sender.failed)
                    + ",\"lastOkMs\":" + std::to_string(sender.lastOkAt < 0 ? -1 : now - sender.lastOkAt) + "}";
            sender.ok = sender.unknownEpoch = sender.tooOld = sender.duplicate = sender.failed = 0;
        }
        json += "]}";
        decryptEpochs.clear();
        unknownEpochs.clear();
        encrypted = 0;
        encryptFailed = 0;
        return json;
    }
};

"""

_NATIVE_EDITS = (
    (NATIVE_GROUP_JNI,
     "#include <map>\n#include <mutex>\n",
     "#include <map>\n#include <mutex>\n#include <chrono>\n#include <set>\n"),
    (NATIVE_GROUP_JNI,
     "struct InstanceHolder {\n",
     _PLUMA_E2E_STATS + "struct InstanceHolder {\n"),
    (NATIVE_GROUP_JNI,
     "    std::shared_ptr<long> conferenceCallId;\n    bool useScreencast = false;\n",
     "    std::shared_ptr<long> conferenceCallId;\n"
     "    std::shared_ptr<PlumaE2EStats> e2eStats; // pluma: ADR 0060\n"
     "    bool useScreencast = false;\n"),
    (NATIVE_GROUP_JNI,
     "jboolean screencast, jboolean noiseSupression, jboolean conference) {\n",
     "jboolean screencast, jboolean noiseSupression, jboolean e2e, jboolean conference) {\n"),
    (NATIVE_GROUP_JNI,
     "    std::shared_ptr<long> conferenceCallIdPtr = nullptr;\n"
     "    if (conference) {\n"
     "        conferenceCallIdPtr = std::make_shared<long>();\n"
     "        e2eEncryptDecrypt = [conferenceCallIdPtr](",
     "    std::shared_ptr<long> conferenceCallIdPtr = nullptr;\n"
     "    std::shared_ptr<PlumaE2EStats> e2eStats = nullptr;\n"
     "    if (e2e) { // pluma: frames are encrypted in every group call (ADR 0060)\n"
     "        conferenceCallIdPtr = std::make_shared<long>();\n"
     "        e2eStats = std::make_shared<PlumaE2EStats>();\n"
     "        e2eEncryptDecrypt = [conferenceCallIdPtr, e2eStats]("),
    (NATIVE_GROUP_JNI,
     "                auto result = tde2e_api::call_encrypt(call_id, 0, std::string_view{ (const char*) input.data(), input.size() }, unencrypted_prefix_size);\n"
     "                if (result.is_ok()) {\n",
     "                auto result = tde2e_api::call_encrypt(call_id, 0, std::string_view{ (const char*) input.data(), input.size() }, unencrypted_prefix_size);\n"
     "                if (result.is_ok()) {\n"
     "                    e2eStats->encryptedOnce(result.value(), unencrypted_prefix_size);\n"),
    (NATIVE_GROUP_JNI,
     '                    DEBUG_D("[tde2e] e2eEncryptDecrypt failed: err %s", result.error().message.c_str());\n'
     "                }\n"
     "            } else {\n",
     '                    DEBUG_D("[tde2e] e2eEncryptDecrypt failed: err %s", result.error().message.c_str());\n'
     "                    e2eStats->encryptFailedOnce();\n"
     "                }\n"
     "            } else {\n"),
    (NATIVE_GROUP_JNI,
     "                auto result = tde2e_api::call_decrypt(call_id, userId, 0, std::string_view{ (const char*) input.data(), input.size() });\n"
     "                if (result.is_ok()) {\n",
     "                auto result = tde2e_api::call_decrypt(call_id, userId, 0, std::string_view{ (const char*) input.data(), input.size() });\n"
     "                if (result.is_ok()) {\n"
     "                    e2eStats->decrypted(userId, input);\n"),
    (NATIVE_GROUP_JNI,
     '                    DEBUG_D("[tde2e] e2eEncryptDecrypt failed: err %s", result.error().message.c_str());\n'
     "                }\n"
     "            }\n"
     "            return std::vector<uint8_t>{};\n",
     '                    DEBUG_D("[tde2e] e2eEncryptDecrypt failed: err %s", result.error().message.c_str());\n'
     "                    e2eStats->decryptFailed(userId, result.error(), input);\n"
     "                }\n"
     "            }\n"
     "            return std::vector<uint8_t>{};\n"),
    (NATIVE_GROUP_JNI,
     "    holder->conferenceCallId = std::move(conferenceCallIdPtr);\n",
     "    holder->conferenceCallId = std::move(conferenceCallIdPtr);\n"
     "    holder->e2eStats = std::move(e2eStats);\n"),
    (NATIVE_GROUP_JNI,
     '    DEBUG_D("setConferenceCallId %d", call_id);\n'
     "    *instance->conferenceCallId = (long) call_id;\n"
     "}\n",
     '    DEBUG_D("setConferenceCallId %d", call_id);\n'
     "    *instance->conferenceCallId = (long) call_id;\n"
     "}\n"
     "\n"
     "// pluma: the E2E status report (ADR 0060): the frame counters since the last call, null in an\n"
     "// instance without frame encryption, and a message to the SFU over the data channel.\n"
     'extern "C"\n'
     "JNIEXPORT jstring JNICALL\n"
     "Java_org_telegram_messenger_voip_NativeInstance_takeE2EStats(JNIEnv *env, jobject obj) {\n"
     "    InstanceHolder *instance = getInstanceHolder(env, obj);\n"
     "    if (instance->e2eStats == nullptr) {\n"
     "        return nullptr;\n"
     "    }\n"
     "    return env->NewStringUTF(instance->e2eStats->take().c_str());\n"
     "}\n"
     "\n"
     'extern "C"\n'
     "JNIEXPORT void JNICALL\n"
     "Java_org_telegram_messenger_voip_NativeInstance_sendDataChannelMessage(JNIEnv *env, jobject obj, jstring message) {\n"
     "    InstanceHolder *instance = getInstanceHolder(env, obj);\n"
     "    if (instance->groupNativeInstance == nullptr) {\n"
     "        return;\n"
     "    }\n"
     "    instance->groupNativeInstance->sendDataChannelMessage(tgvoip::jni::JavaStringToStdString(env, message));\n"
     "}\n"
     "\n"
     'extern "C"\n'
     "JNIEXPORT jboolean JNICALL\n"
     "Java_org_telegram_messenger_voip_NativeInstance_isDataChannelOpen(JNIEnv *env, jobject obj) {\n"
     "    InstanceHolder *instance = getInstanceHolder(env, obj);\n"
     "    if (instance->groupNativeInstance == nullptr) {\n"
     "        return JNI_FALSE;\n"
     "    }\n"
     "    return instance->groupNativeInstance->isDataChannelOpen() ? JNI_TRUE : JNI_FALSE;\n"
     "}\n"),
    (TDE2E_BRIDGE,
     "    auto result = tde2e_api::call_describe_message(view);\n"
     "    env->ReleaseByteArrayElements(message, bytes, JNI_ABORT);\n"
     "    if (!result.is_ok()) {\n"
     "        java_throw(env, result.error());\n"
     "        return nullptr;\n"
     "    }\n"
     "    return java_string(env, result.value());\n"
     "}",
     "    auto result = tde2e_api::call_describe_message(view);\n"
     "    env->ReleaseByteArrayElements(message, bytes, JNI_ABORT);\n"
     "    if (!result.is_ok()) {\n"
     "        java_throw(env, result.error());\n"
     "        return nullptr;\n"
     "    }\n"
     "    return java_string(env, result.value());\n"
     "}\n"
     "\n"
     "// pluma: the error code the call object has failed with, 0 while it works. A failure is\n"
     "// sticky: every call of the object answers it (tde2e Call::get_status). ADR 0060.\n"
     'extern "C"\n'
     "JNIEXPORT jint JNICALL\n"
     "Java_org_telegram_messenger_voip_ConferenceCall_call_1get_1error_1code(JNIEnv *env, jclass clazz, jlong call_id) {\n"
     "    auto result = tde2e_api::call_get_height(call_id);\n"
     "    if (result.is_ok()) {\n"
     "        return 0;\n"
     "    }\n"
     "    return static_cast<jint>(result.error().code);\n"
     "}"),
    # tgcalls: a message of the client's own over the data channel, next to
    # the video constraints it sends there.
    (TGCALLS_GROUP_H,
     "    void internal_addCustomNetworkEvent(bool isRemoteConnected);\n",
     "    void internal_addCustomNetworkEvent(bool isRemoteConnected);\n"
     "\n"
     "    // pluma: a message of the client's own to the SFU over the data channel, such as the\n"
     "    // E2E status report of Pluma (ADR 0060). Sent only while the channel is open, which\n"
     "    // isDataChannelOpen tells from any thread; a report waits for it instead of being lost.\n"
     "    void sendDataChannelMessage(std::string const &message);\n"
     "    bool isDataChannelOpen() const;\n"),
    (TGCALLS_GROUP_H,
     "#include <memory>\n#include <map>\n",
     "#include <memory>\n#include <map>\n#include <atomic>\n"),
    (TGCALLS_GROUP_H,
     "    std::unique_ptr<LogSinkImpl> _logSink;\n",
     "    std::unique_ptr<LogSinkImpl> _logSink;\n"
     "    // pluma: the state of the data channel, written by the media thread (ADR 0060).\n"
     "    std::shared_ptr<std::atomic<bool>> _isDataChannelOpen = std::make_shared<std::atomic<bool>>(false);\n"),
    (TGCALLS_GROUP,
     "    void setConnectionMode(GroupConnectionMode connectionMode, bool keepBroadcastIfWasEnabled, bool isUnifiedBroadcast) {\n"
     "        if (_connectionMode != connectionMode",
     "    // pluma: see GroupInstanceCustomImpl::sendDataChannelMessage and isDataChannelOpen.\n"
     "    void setDataChannelOpenFlag(std::shared_ptr<std::atomic<bool>> flag) {\n"
     "        _isDataChannelOpenFlag = std::move(flag);\n"
     "        _isDataChannelOpenFlag->store(_isDataChannelOpen);\n"
     "    }\n"
     "\n"
     "    void sendDataChannelMessage(std::string const &message) {\n"
     "        if (!_isDataChannelOpen) {\n"
     "            return;\n"
     "        }\n"
     "        _networkManager->perform([message](GroupNetworkManager *networkManager) {\n"
     "            networkManager->sendDataChannelMessage(message);\n"
     "        });\n"
     "    }\n"
     "\n"
     "    void setConnectionMode(GroupConnectionMode connectionMode, bool keepBroadcastIfWasEnabled, bool isUnifiedBroadcast) {\n"
     "        if (_connectionMode != connectionMode"),
    (TGCALLS_GROUP,
     "void GroupInstanceCustomImpl::internal_addCustomNetworkEvent(bool isRemoteConnected) {\n"
     "    _internal->perform([isRemoteConnected](GroupInstanceCustomInternal *internal) {\n"
     "        internal->internal_addCustomNetworkEvent(isRemoteConnected);\n"
     "    });\n"
     "}\n",
     "void GroupInstanceCustomImpl::internal_addCustomNetworkEvent(bool isRemoteConnected) {\n"
     "    _internal->perform([isRemoteConnected](GroupInstanceCustomInternal *internal) {\n"
     "        internal->internal_addCustomNetworkEvent(isRemoteConnected);\n"
     "    });\n"
     "}\n"
     "\n"
     "void GroupInstanceCustomImpl::sendDataChannelMessage(std::string const &message) {\n"
     "    _internal->perform([message](GroupInstanceCustomInternal *internal) {\n"
     "        internal->sendDataChannelMessage(message);\n"
     "    });\n"
     "}\n"
     "\n"
     "bool GroupInstanceCustomImpl::isDataChannelOpen() const {\n"
     "    return _isDataChannelOpen->load();\n"
     "}\n"),
    (TGCALLS_GROUP,
     "        _isDataChannelOpen = isDataChannelOpen;\n"
     "\n"
     "        if (_isDataChannelOpen) {\n"
     "            maybeUpdateRemoteVideoConstraints();\n",
     "        _isDataChannelOpen = isDataChannelOpen;\n"
     "        if (_isDataChannelOpenFlag) { // pluma: ADR 0060\n"
     "            _isDataChannelOpenFlag->store(isDataChannelOpen);\n"
     "        }\n"
     "\n"
     "        if (_isDataChannelOpen) {\n"
     "            maybeUpdateRemoteVideoConstraints();\n"),
    (TGCALLS_GROUP,
     "    bool _isDataChannelOpen = false;\n",
     "    bool _isDataChannelOpen = false;\n"
     "    std::shared_ptr<std::atomic<bool>> _isDataChannelOpenFlag; // pluma: ADR 0060\n"),
    (TGCALLS_GROUP,
     "    _internal->perform([](GroupInstanceCustomInternal *internal) {\n"
     "        internal->start();\n"
     "    });\n",
     "    _internal->perform([flag = _isDataChannelOpen](GroupInstanceCustomInternal *internal) {\n"
     "        internal->setDataChannelOpenFlag(flag); // pluma: ADR 0060\n"
     "        internal->start();\n"
     "    });\n"),
)

_MAKE_GROUP_PARAMS = ("String logPath, long videoCapturer, boolean screencast, boolean noiseSupression, PayloadCallback payloadCallback, "
                      "AudioLevelsCallback audioLevelsCallback, VideoSourcesCallback unknownParticipantsCallback, "
                      "RequestBroadcastPartCallback requestBroadcastPartCallback, RequestBroadcastPartCallback cancelRequestBroadcastPartCallback, "
                      "RequestCurrentTimeCallback requestCurrentTimeCallback")

_UI_EDITS = (
    (NATIVE_INSTANCE,
     f"    public static NativeInstance makeGroup({_MAKE_GROUP_PARAMS}, boolean isConference) {{\n",
     f"    public static NativeInstance makeGroup({_MAKE_GROUP_PARAMS}, boolean isConference) {{\n"
     "        return makeGroup(logPath, videoCapturer, screencast, noiseSupression, payloadCallback, audioLevelsCallback, unknownParticipantsCallback, "
     "requestBroadcastPartCallback, cancelRequestBroadcastPartCallback, requestCurrentTimeCallback, isConference, isConference);\n"
     "    }\n"
     "\n"
     "    // pluma: e2e encrypts the frames, in every group call (ADR 0060); isConference stays the\n"
     "    // conference's, which tgcalls sends with one video layer.\n"
     f"    public static NativeInstance makeGroup({_MAKE_GROUP_PARAMS}, boolean e2e, boolean isConference) {{\n"),
    (NATIVE_INSTANCE,
     "        instance.nativePtr = makeGroupNativeInstance(instance, logPath, SharedConfig.disableVoiceAudioEffects, videoCapturer, screencast, noiseSupression, isConference);\n",
     "        instance.nativePtr = makeGroupNativeInstance(instance, logPath, SharedConfig.disableVoiceAudioEffects, videoCapturer, screencast, noiseSupression, e2e, isConference);\n"),
    (NATIVE_INSTANCE,
     "    private static native long makeGroupNativeInstance(NativeInstance instance, String persistentStateFilePath, boolean highQuality, long videoCapturer, boolean screencast, boolean noiseSupression, boolean conference);\n",
     "    private static native long makeGroupNativeInstance(NativeInstance instance, String persistentStateFilePath, boolean highQuality, long videoCapturer, boolean screencast, boolean noiseSupression, boolean e2e, boolean conference);\n"),
    (NATIVE_INSTANCE,
     "    public native void setConferenceCallId(long call_id);\n",
     "    public native void setConferenceCallId(long call_id);\n"
     "    // pluma: the E2E status report (ADR 0060): the frame counters since the last call as JSON,\n"
     "    // null without frame encryption; a message to the SFU over the data channel.\n"
     "    public native String takeE2EStats();\n"
     "    public native void sendDataChannelMessage(String message);\n"
     "    public native boolean isDataChannelOpen();\n"),
    # The emoji of the key in every end-to-end call. The drawable is made
    # lazily by the list (VIEW_TYPE_ENCRYPTION) when the row comes later.
    (GROUP_CALL_ACTIVITY,
     "        } else if (id == NotificationCenter.conferenceEmojiUpdated) {\n",
     "        } else if (id == NotificationCenter.conferenceEmojiUpdated && encryptionDrawable != null) { // pluma: ADR 0060\n"),
    (GROUP_CALL_ACTIVITY,
     "        if (isConference()) {\n"
     "            encryptionDrawable = new CallEncryptionCellDrawable(context);\n",
     "        if (isE2E()) { // pluma: every group call is end-to-end (ADR 0060)\n"
     "            encryptionDrawable = new CallEncryptionCellDrawable(context);\n"),
    (GROUP_CALL_ACTIVITY,
     "            if (isConference()/* && call.participants.size() > 1*/) {\n"
     "                encryptionRow = rowsCount++;\n",
     "            if (isE2E()) { // pluma: every group call is end-to-end (ADR 0060)\n"
     "                encryptionRow = rowsCount++;\n"),
    (GROUP_CALL_ACTIVITY,
     "    public boolean isConference() {\n"
     "        final VoIPService voip = VoIPService.getSharedInstance();\n"
     "        return voip != null && voip.isConference();\n"
     "    }\n",
     "    public boolean isConference() {\n"
     "        final VoIPService voip = VoIPService.getSharedInstance();\n"
     "        return voip != null && voip.isConference();\n"
     "    }\n"
     "\n"
     "    // pluma: the call carries the tde2e call object: every group call (ADR 0060).\n"
     "    public boolean isE2E() {\n"
     "        final VoIPService voip = VoIPService.getSharedInstance();\n"
     "        return voip != null && voip.conference != null;\n"
     "    }\n"),
    (CHAT_OBJECT,
     "            req.limit = isConference ? currentAccount.getMessagesController().conferenceCallSizeLimit : 20;\n",
     "            // pluma: an end-to-end call loads all its participants at once: who has left the\n"
     "            // call's chain is known from the whole list only (ADR 0060).\n"
     "            final VoIPService plumaVoip = VoIPService.getSharedInstance();\n"
     "            final boolean plumaE2E = plumaVoip != null && plumaVoip.groupCall == this && plumaVoip.conference != null;\n"
     "            req.limit = isConference || plumaE2E ? currentAccount.getMessagesController().conferenceCallSizeLimit : 20;\n"),
    (CHAT_OBJECT,
     "            if (call != null && voip != null && voip.isConference() && voip.groupCall == this) {\n",
     "            if (call != null && voip != null && voip.conference != null && voip.groupCall == this) { // pluma: every end-to-end call\n"),
    # No recording: phone.toggleGroupCallRecord is not served (ADR 0060 §4), and a
    # call encrypted end to end cannot be recorded on the server. Upstream already
    # hides the item in a conference.
    (GROUP_CALL_ACTIVITY,
     "            if (isRtmpStream()) {\n"
     "                recordItem.setVisibility(View.VISIBLE);\n"
     "                screenItem.setVisibility(View.GONE);\n"
     "            } else {\n"
     "                if (call.isScheduled()) {\n"
     "                    recordItem.setVisibility(View.GONE);\n"
     "                    screenItem.setVisibility(View.GONE);\n"
     "                } else {\n"
     "                    recordItem.setVisibility(View.VISIBLE);\n"
     "                }\n"
     "            }\n",
     "            // pluma: no recording (ADR 0060 §4): the server does not record calls.\n"
     "            if (isRtmpStream()) {\n"
     "                recordItem.setVisibility(View.GONE);\n"
     "                screenItem.setVisibility(View.GONE);\n"
     "            } else {\n"
     "                if (call.isScheduled()) {\n"
     "                    recordItem.setVisibility(View.GONE);\n"
     "                    screenItem.setVisibility(View.GONE);\n"
     "                } else {\n"
     "                    recordItem.setVisibility(View.GONE);\n"
     "                }\n"
     "            }\n"),
    # No join-as list: the user alone.
    (JOIN_CALL_ALERT,
     "    public static void checkFewUsers(Context context, long did, AccountInstance accountInstance, MessagesStorage.BooleanCallback callback) {\n"
     "        if (lastCachedAccount == accountInstance.getCurrentAccount() && lastCacheDid == did && cachedChats != null && SystemClock.elapsedRealtime() - lastCacheTime < 4 * 60 * 1000) {\n"
     "            callback.run(cachedChats.size() == 1);\n"
     "            return;\n"
     "        }\n"
     "        final AlertDialog progressDialog = new AlertDialog(context, AlertDialog.ALERT_TYPE_SPINNER);\n"
     "        TL_phone.getGroupCallJoinAs req = new TL_phone.getGroupCallJoinAs();\n"
     "        req.peer = accountInstance.getMessagesController().getInputPeer(did);\n"
     "        int reqId = accountInstance.getConnectionsManager().sendRequest(req, (response, error) -> AndroidUtilities.runOnUIThread(() -> {\n"
     "            try {\n"
     "                progressDialog.dismiss();\n"
     "            } catch (Exception e) {\n"
     "                FileLog.e(e);\n"
     "            }\n"
     "            if (response != null) {\n"
     "                TL_phone.joinAsPeers res = (TL_phone.joinAsPeers) response;\n"
     "                cachedChats = res.peers;\n"
     "                lastCacheDid = did;\n"
     "                lastCacheTime = SystemClock.elapsedRealtime();\n"
     "                lastCachedAccount = accountInstance.getCurrentAccount();\n"
     "                accountInstance.getMessagesController().putChats(res.chats, false);\n"
     "                accountInstance.getMessagesController().putUsers(res.users, false);\n"
     "                callback.run(res.peers.size() == 1);\n"
     "            }\n"
     "        }));\n"
     "        progressDialog.setOnCancelListener(dialog -> accountInstance.getConnectionsManager().cancelRequest(reqId, true));\n"
     "        try {\n"
     "            progressDialog.showDelayed(500);\n"
     "        } catch (Exception ignore) {\n"
     "\n"
     "        }\n"
     "    }\n",
     "    public static void checkFewUsers(Context context, long did, AccountInstance accountInstance, MessagesStorage.BooleanCallback callback) {\n"
     "        // pluma: a group call is joined as the user only (ADR 0060): one peer, nothing to ask.\n"
     "        callback.run(true);\n"
     "    }\n"),
    (JOIN_CALL_ALERT,
     "    public static void open(Context context, long did, AccountInstance accountInstance, BaseFragment fragment, int type, TLRPC.Peer scheduledPeer, JoinCallAlertDelegate delegate) {\n"
     "        if (context == null || delegate == null) {\n"
     "            return;\n"
     "        }\n"
     "        if (lastCachedAccount == accountInstance.getCurrentAccount() && lastCacheDid == did && cachedChats != null && SystemClock.elapsedRealtime() - lastCacheTime < 5 * 60 * 1000) {\n"
     "            if (cachedChats.size() == 1 && type != TYPE_CREATE) {\n"
     "                TLRPC.InputPeer peer = accountInstance.getMessagesController().getInputPeer(MessageObject.getPeerId(cachedChats.get(0)));\n"
     "                delegate.didSelectChat(peer, false, false, false);\n"
     "            } else {\n"
     "                showAlert(context, did, cachedChats, fragment, type, scheduledPeer, delegate);\n"
     "            }\n"
     "        } else {\n"
     "            final AlertDialog progressDialog = new AlertDialog(context, AlertDialog.ALERT_TYPE_SPINNER);\n"
     "            TL_phone.getGroupCallJoinAs req = new TL_phone.getGroupCallJoinAs();\n"
     "            req.peer = accountInstance.getMessagesController().getInputPeer(did);\n"
     "            int reqId = accountInstance.getConnectionsManager().sendRequest(req, (response, error) -> AndroidUtilities.runOnUIThread(() -> {\n"
     "                try {\n"
     "                    progressDialog.dismiss();\n"
     "                } catch (Exception e) {\n"
     "                    FileLog.e(e);\n"
     "                }\n"
     "                if (response != null) {\n"
     "                    TL_phone.joinAsPeers res = (TL_phone.joinAsPeers) response;\n"
     "                    if (res.peers.size() == 1) {\n"
     "                        TLRPC.InputPeer peer = accountInstance.getMessagesController().getInputPeer(MessageObject.getPeerId(res.peers.get(0)));\n"
     "                        delegate.didSelectChat(peer, false, false, false);\n"
     "                        return;\n"
     "                    }\n"
     "                    cachedChats = res.peers;\n"
     "                    lastCacheDid = did;\n"
     "                    lastCacheTime = SystemClock.elapsedRealtime();\n"
     "                    lastCachedAccount = accountInstance.getCurrentAccount();\n"
     "                    accountInstance.getMessagesController().putChats(res.chats, false);\n"
     "                    accountInstance.getMessagesController().putUsers(res.users, false);\n"
     "                    showAlert(context, did, res.peers, fragment, type, scheduledPeer, delegate);\n"
     "                }\n"
     "            }));\n"
     "            progressDialog.setOnCancelListener(dialog -> accountInstance.getConnectionsManager().cancelRequest(reqId, true));\n"
     "            try {\n"
     "                progressDialog.showDelayed(500);\n"
     "            } catch (Exception ignore) {\n"
     "\n"
     "            }\n"
     "        }\n"
     "    }\n",
     "    public static void open(Context context, long did, AccountInstance accountInstance, BaseFragment fragment, int type, TLRPC.Peer scheduledPeer, JoinCallAlertDelegate delegate) {\n"
     "        if (context == null || delegate == null) {\n"
     "            return;\n"
     "        }\n"
     "        // pluma: a group call is started and joined as the user only (ADR 0060): the key in the\n"
     "        // call's chain is the user's. Starting a call still shows the sheet to start or schedule it.\n"
     "        final long selfId = accountInstance.getUserConfig().getClientUserId();\n"
     "        if (type == TYPE_CREATE) {\n"
     "            final ArrayList<TLRPC.Peer> peers = new ArrayList<>();\n"
     "            peers.add(accountInstance.getMessagesController().getPeer(selfId));\n"
     "            showAlert(context, did, peers, fragment, type, scheduledPeer, delegate);\n"
     "        } else {\n"
     "            delegate.didSelectChat(accountInstance.getMessagesController().getInputPeer(selfId), false, false, false);\n"
     "        }\n"
     "    }\n"),
    # No RTMP: the sheet that starts a call loses its "stream with another app".
    (CREATE_GROUP_CALL_SHEET,
     "        this.canRtmpStream = ChatObject.canManageCalls(chat);\n",
     "        this.canRtmpStream = false; // pluma: no RTMP streams (ADR 0060)\n"),
    (CREATE_GROUP_CALL_SHEET,
     "                    TextInfoPrivacyCell cell = (TextInfoPrivacyCell) holder.itemView;\n"
     "                    CharSequence text = AndroidUtilities.replaceArrows(AndroidUtilities.replaceSingleTag(LocaleController.getString(R.string.VoipChatStreamWithAnotherApp), Theme.key_windowBackgroundWhiteBlueHeader, AndroidUtilities.REPLACING_TAG_TYPE_LINK, () -> {\n"
     "                        CreateRtmpStreamBottomSheet.show(selectedPeer, fragment, dialogId, chats.size() > 1, joinCallDelegate);\n"
     "                    }), true, dp(1), dp(1f));\n"
     "                    cell.setText(text);\n",
     "                    TextInfoPrivacyCell cell = (TextInfoPrivacyCell) holder.itemView;\n"
     "                    cell.setText(null); // pluma: no RTMP streams (ADR 0060); the row offered one\n"),
    (CREATE_GROUP_CALL_SHEET,
     "                return needSelector ? CONTENT_VIEWS_COUNT + chats.size() : (canRtmpStream ? 2 : 1);\n",
     "                return 1; // pluma: the header only: no join-as list, no RTMP stream (ADR 0060)\n"),
    # No live stories: the Live tab of the story camera and the RTMP rows of
    # its settings.
    (STORY_MODE_TABS,
     "        layout.addView(liveLayout, LayoutHelper.createLinear(LayoutHelper.WRAP_CONTENT, LayoutHelper.MATCH_PARENT, Gravity.FILL_VERTICAL, 0, 0, 6.66f, 0));\n"
     "        liveLayout.setOnClickListener(v -> switchModeInternal(-1));\n",
     "        // pluma: no live stories (ADR 0060): a live story is a group call streamed without\n"
     "        // end-to-end encryption, and the server does not serve it.\n"),
    (STORY_PRIVACY_SHEET,
     "                    if (isLive && !liveSettings) {\n"
     "                        if (isRtmpStream) {\n"
     '                            items.add(ItemInner.asButton(5, getString(R.string.LiveStoryRTMPSettings), ""));\n'
     "                            pad.subtractHeight += dp(50);\n"
     '                            items.add(ItemInner.asButton(6, getString(R.string.LiveStoryRTMPDisable), ""));\n'
     "                            pad.subtractHeight += dp(50);\n"
     "                            items.add(ItemInner.asShadow(null));\n"
     "                            pad.subtractHeight += dp(12);\n"
     "                        } else {\n"
     '                            items.add(ItemInner.asButton(5, getString(R.string.LiveStoryRTMPEnable), ""));\n'
     "                            pad.subtractHeight += dp(50);\n"
     "                            items.add(ItemInner.asShadow(getString(R.string.LiveStoryRTMPEnableInfo)));\n"
     "                            pad.subtractHeight += dp(30);\n"
     "                        }\n"
     "                    }\n",
     "                    // pluma: no RTMP streams (ADR 0060).\n"),
    (STORY_PRIVACY_SHEET,
     "                if (liveSettings) {\n"
     '                    items.add(ItemInner.asButton(5, getString(R.string.LiveStoryRTMPSettings), ""));\n'
     "                    pad.subtractHeight += dp(50);\n"
     "                    items.add(ItemInner.asShadow(null));\n"
     "                    pad.subtractHeight += dp(12 + 40);\n"
     "                }\n",
     "                // pluma: no RTMP settings of a live story (ADR 0060).\n"),
    # The link to the story camera in the live mode opens it for a photo.
    (LINK_MANAGER,
     '            if ("live".equalsIgnoreCase(second))\n'
     "                mode = StoryRecorder.MODE_LIVE;\n",
     "            // pluma: no live stories (ADR 0060): the link to the live camera opens the photo one.\n"),
)

GROUP_CALLS_E2E_EDITS = (
    tuple((VOIP_SERVICE, _tabbed(old), _tabbed(new)) for old, new in _VOIP_EDITS)
    + tuple((CONFERENCE_CALL, old, new) for old, new in _CONFERENCE_EDITS)
    + _NATIVE_EDITS
    + _UI_EDITS
)
# The places that may name the RTMP sheet once the patch has run: the class
# itself, and the handler of a live story row no list adds any more.
RTMP_SHEET_USES = {
    "ui/Components/CreateRtmpStreamBottomSheet.java",
    "ui/Stories/recorder/StoryPrivacyBottomSheet.java",
}


def _e2e_failed_line(folder):
    return f'    <string name="{E2E_FAILED_KEY}">{E2E_FAILED_TEXT[folder]}</string>\n'


def group_calls_e2e(tree):
    # Every anchor first: several edits keep their anchor in the new text, and a
    # tree that is already patched must fail before anything is written twice.
    for rel, old, _ in GROUP_CALLS_E2E_EDITS:
        tree.expect(rel, old)
    files = {p.parent.name: str(p.relative_to(tree.root)) for p in sorted((tree.root / RES).glob("values*/strings.xml"))}
    if set(files) != set(E2E_FAILED_TEXT):
        raise PatchError(f"{RES}: strings.xml in {', '.join(sorted(files))}, expected {', '.join(sorted(E2E_FAILED_TEXT))}")
    for rel in files.values():
        if f'<string name="{E2E_FAILED_KEY}">' in tree.read(rel):
            raise PatchError(f"{rel}: upstream has a string {E2E_FAILED_KEY}")
    for rel, old, new in GROUP_CALLS_E2E_EDITS:
        tree.replace(rel, old, new)
    for folder, rel in files.items():
        tree.replace(rel, "</resources>", _e2e_failed_line(folder) + "</resources>")


def _java_files_naming(tree, name):
    found = set()
    for p in sorted((tree.root / JAVA).rglob("*.java")):
        if name in p.read_text(encoding="utf-8"):
            found.add(p.relative_to(tree.root / JAVA).as_posix())
    return found


def verify_group_calls_e2e(tree):
    for rel, old, new in GROUP_CALLS_E2E_EDITS:
        text = tree.read(rel)
        if text.count(new) != 1 or text.count(old) != new.count(old):
            changed = next(line for line in new.splitlines() if line not in old.splitlines())
            raise PatchError(f"{rel}: the group call edit {changed.strip()!r} is not there")
    voip = tree.read(VOIP_SERVICE)
    # Nothing joins a group call without a key, enters the stream mode or asks for RTMP.
    for gone in ('optBoolean("stream")', 'getBooleanExtra("isRtmpStream"', "startGroupCall(ssrc, json, true);",
                 "}, conference != null);"):
        if gone in voip:
            raise PatchError(f"{VOIP_SERVICE}: upstream's {gone!r} is still there")
    if voip.count("new TL_phone.joinGroupCall()") != 2 or voip.count("req.public_key = conference.getMyPublicKey();") != 2:
        raise PatchError(f"{VOIP_SERVICE}: a group call is joined without the user's key")
    if voip.count(f"R.string.{E2E_FAILED_KEY}") != 1:
        raise PatchError(f"{VOIP_SERVICE}: the message of a failed self-recovery is not there")
    if "getGroupCallJoinAs" in tree.read(JOIN_CALL_ALERT):
        raise PatchError(f"{JOIN_CALL_ALERT}: the join-as list is asked for again")
    # The record item never shows, and nothing but its handler starts a recording.
    shown = re.findall(r"recordItem\.setVisibility\((?!View\.GONE\))", tree.read(GROUP_CALL_ACTIVITY))
    if shown:
        raise PatchError(f"{GROUP_CALL_ACTIVITY}: the record item is shown again")
    recording = _java_files_naming(tree, ".toggleRecord(")
    if recording - {"ui/GroupCallActivity.java"}:
        raise PatchError(f"{JAVA}: a call is recorded from {sorted(recording)}; a way into recording is open")
    uses = _java_files_naming(tree, "CreateRtmpStreamBottomSheet")
    if uses != RTMP_SHEET_USES:
        raise PatchError(f"{JAVA}: the RTMP sheet is named in {sorted(uses)}, expected {sorted(RTMP_SHEET_USES)}; a way into it is open")
    if "ItemInner.asButton(5," in tree.read(STORY_PRIVACY_SHEET):
        raise PatchError(f"{STORY_PRIVACY_SHEET}: a live story row leads to RTMP again")
    modes = set(re.findall(r"switchModeInternal\((-?\d+)\)", tree.read(STORY_MODE_TABS)))
    if modes != {"0", "1"}:
        raise PatchError(f"{STORY_MODE_TABS}: the camera switches to the modes {sorted(modes)}; the Live tab is back")
    # The live mode is only compared with, never set: no tab, link or caller leads the camera there.
    live = _java_files_naming(tree, "MODE_LIVE")
    if live != {"ui/Stories/recorder/StoryRecorder.java"}:
        raise PatchError(f"{JAVA}: the live story mode is named in {sorted(live)}; a way into it is open")
    if re.search(r"(?<![=!<>])=\s*MODE_LIVE\b|\(\s*MODE_LIVE\s*\)", tree.read(STORY_RECORDER)):
        raise PatchError(f"{STORY_RECORDER}: the camera is set to the live story mode")
    for p in sorted((tree.root / RES).glob("values*/strings.xml")):
        xml = p.read_text(encoding="utf-8")
        folder = p.parent.name
        if (folder not in E2E_FAILED_TEXT or xml.count(_e2e_failed_line(folder)) != 1
                or xml.count(f'<string name="{E2E_FAILED_KEY}">') != 1):
            raise PatchError(f"{p.relative_to(tree.root)}: {E2E_FAILED_KEY} is not the text of task 094")


# --- Call colours (the owner's decision of 2026-11-12) -------------------------
# The call screens take variant A "Sage" instead of Telegram's colours. Telegram
# iOS draws three four-point gradients (CallBackgroundLayer.swift:108-124):
# connecting 568FD6/626ED5/A667D5/7664DA, connected ACBD65/459F8D/53A4D1/3E917A,
# weak signal C0508D/F09536/CE5081/FC7C4C. Pluma's, in the same order of points,
# are CALL_CONNECTING, CALL_CONNECTED and CALL_WEAK. Android has gradients of its
# own for the same states (VoIpGradientLayout: blue-violet and blue-green while
# calling, green when connected, orange-red on a weak signal, each with a darker
# variant the buttons are tinted from and a lighter one), and the group call
# paints its states from the voipgroup_* colour keys and from literals. Every
# such colour is mapped by meaning: Telegram's blue and purple take the
# connecting set, its green the connected set, its red and orange the weak set;
# the accents of the dark call screens (checks, progress, the listening text,
# selectors) the dark accent of the palette (docs/tasks/017-rebranding.md of the
# server repository), links its dark link colour, and the bluish greys of the
# panels the sage grey of the same lightness. The darker and lighter variants of
# VoIpGradientLayout are derived from the sets as upstream's are from its own:
# value x0.82, and value x1.22 with saturation x0.8.
# Kept as Telegram has them, being actions rather than states (decisions to
# confirm with the owner): the green accept and red decline and end-call
# buttons of a private call and the red "end" and green "answer" of its
# notification, the red leave button and leave item of a group call, the red of
# dragging the call bubble away to close it, the recording dot
# of the record item (hidden, ADR 0060 §4) and the red of a message over its
# length limit.
CALL_CONNECTING = (0xFF3A4A3C, 0xFF4F6E52, 0xFF2C3A2D, 0xFF5B7A5E)
CALL_CONNECTED = (0xFF5B7A5E, 0xFF6F8F72, 0xFF4F6E52, 0xFF7FA082)
CALL_WEAK = (0xFF8A5A44, 0xFFA86B4C, 0xFF7A4E3B, 0xFFB97A55)
CALL_ACCENT = 0xFF9DBB9F
CALL_LINK = 0xFFB2CEB4
CALL_SAGE_HUE = 125  # the hue of the accent #5B7A5E, in degrees
CALL_DARK = 0.82
CALL_LIGHT = 1.22


def _rgb(c):
    return (c >> 16 & 255) / 255, (c >> 8 & 255) / 255, (c & 255) / 255


def _argb(alpha, rgb):
    r, g, b = (round(x * 255) for x in rgb)
    return alpha & 0xFF000000 | r << 16 | g << 8 | b


def call_neutral(c):
    """The sage grey of the lightness of c, with its alpha."""
    _, lightness, saturation = colorsys.rgb_to_hls(*_rgb(c))
    return _argb(c, colorsys.hls_to_rgb(CALL_SAGE_HUE / 360, lightness, min(saturation, 0.1)))


def call_darker(c):
    h, s, v = colorsys.rgb_to_hsv(*_rgb(c))
    return _argb(c, colorsys.hsv_to_rgb(h, s, v * CALL_DARK))


def call_lighter(c):
    h, s, v = colorsys.rgb_to_hsv(*_rgb(c))
    return _argb(c, colorsys.hsv_to_rgb(h, s * 0.8, min(v * CALL_LIGHT, 1)))


def telegram_call_colour(c):
    """A colour of Telegram's call screens: a blue, cyan, purple or pink, even a
    bluish grey (the muted icon and the grey texts of the group call, #6F7980 and
    the like, are 0.1 saturated); a vivid green; a bright red, orange or yellow,
    or a light coral red (#EC7777). The sage sets, neutral greys and the
    terracotta of the weak set (hue 18-22) are none of them."""
    if c >> 24 < 0x20:
        return False
    h, s, v = _hsv(c)
    return (170 <= h < 345 and s >= 0.08 and v >= 0.08
            or 70 <= h < 170 and s >= 0.4 and v >= 0.3
            or (h >= 345 or h < 70) and s >= 0.5 and v >= 0.75
            or (h >= 345 or h < 12) and s >= 0.35 and v >= 0.6)


def jhex(c):
    return f"0x{c:08X}"


C1, C2, C3, C4 = CALL_CONNECTING
G1, G2, G3, G4 = CALL_CONNECTED
W1, W2, W3, W4 = CALL_WEAK

# The defaults of the colour keys of the group call (ThemeColors), by meaning.
# The keys are dark whatever the theme; the accent engine leaves them alone
# (Theme.themeAccentExclusionKeys). Some of them colour dark sheets elsewhere
# (sharing, the photo viewer), which take the sage greys with them.
VOIPGROUP_COLOURS = {
    "voipgroup_checkMenu": CALL_ACCENT,
    # "Tap to mute": speaking, the connected set (radial: centre, middle, edge).
    "voipgroup_muteButton": G4,
    "voipgroup_muteButton2": G2,
    "voipgroup_muteButton3": G1,
    "voipgroup_searchBackground": call_neutral(0xFF303B47),
    "voipgroup_scrollUp": call_neutral(0xFF394654),
    "voipgroup_soundButton": call_neutral(0x7D2C414D),
    "voipgroup_soundButtonActive": 0x7D000000 | C2 & 0xFFFFFF,
    "voipgroup_soundButtonActiveScrolled": 0x82000000 | C4 & 0xFFFFFF,
    "voipgroup_soundButton2": 0x7D000000 | G3 & 0xFFFFFF,
    "voipgroup_soundButtonActive2": 0x7D000000 | G2 & 0xFFFFFF,
    "voipgroup_soundButtonActive2Scrolled": 0x82000000 | G4 & 0xFFFFFF,
    "voipgroup_connectingProgress": CALL_ACCENT,
    "voipgroup_disabledButton": call_neutral(0xFF1C2229),
    "voipgroup_rtmpButton": call_neutral(0xFF2A3853),
    "voipgroup_disabledButtonActive": call_neutral(0xFF2C3A45),
    "voipgroup_disabledButtonActiveScrolled": 0x82000000 | C4 & 0xFFFFFF,
    # "Tap to unmute": muted, the connecting set (radial: edge, centre).
    "voipgroup_unmuteButton": C2,
    "voipgroup_unmuteButton2": C4,
    "voipgroup_actionBarUnscrolled": call_neutral(0xFF191F26),
    "voipgroup_listViewBackgroundUnscrolled": call_neutral(0xFF222A33),
    "voipgroup_actionBar": call_neutral(0xFF0F1317),
    "voipgroup_actionBarItemsSelector": 0x1E000000 | CALL_LINK & 0xFFFFFF,
    "voipgroup_mutedByAdminIcon": W4,
    "voipgroup_listViewBackground": call_neutral(0xFF1C2229),
    "voipgroup_dialogBackground": call_neutral(0xFF1C2229),
    "voipgroup_listeningText": CALL_ACCENT,
    "voipgroup_speakingText": G4,
    "voipgroup_inviteMembersBackground": call_neutral(0xFF222A33),
    "voipgroup_overlayBlue1": C4,
    "voipgroup_overlayBlue2": C2,
    "voipgroup_overlayGreen1": G4,
    "voipgroup_overlayGreen2": G2,
    "voipgroup_topPanelBlue1": C4,
    "voipgroup_topPanelBlue2": C2,
    "voipgroup_topPanelGreen1": G4,
    "voipgroup_topPanelGreen2": G1,
    "voipgroup_topPanelGray": call_neutral(0xFF8599AA),
    "voipgroup_overlayAlertGradientMuted": C2,
    "voipgroup_overlayAlertGradientMuted2": C3,
    "voipgroup_overlayAlertGradientUnmuted": G1,
    "voipgroup_overlayAlertGradientUnmuted2": C1,
    # Muted by an admin, a raised hand, a scheduled call: Telegram's blue, red
    # and purple gradient, by colour.
    "voipgroup_mutedByAdminGradient": C4,
    "voipgroup_mutedByAdminGradient2": W2,
    "voipgroup_mutedByAdminGradient3": C2,
    "voipgroup_overlayAlertMutedByAdmin": C2,
    "voipgroup_overlayAlertMutedByAdmin2": C3,
    "voipgroup_mutedByAdminMuteButton": 0x7F000000 | C4 & 0xFFFFFF,
    "voipgroup_mutedByAdminMuteButtonDisabled": 0x33000000 | C4 & 0xFFFFFF,
    "voipgroup_windowBackgroundWhiteInputFieldActivated": CALL_ACCENT,
    # The muted icon and the grey texts: Telegram's bluish greys, the sage grey of
    # the same lightness.
    "voipgroup_mutedIcon": call_neutral(0xFF6F7980),
    "voipgroup_mutedIconUnscrolled": call_neutral(0xFF7E868C),
    "voipgroup_lastSeenText": call_neutral(0xFF79838A),
    "voipgroup_lastSeenTextUnscrolled": call_neutral(0xFF858D94),
    "voipgroup_searchPlaceholder": call_neutral(0xFF858D94),
}
# The keys kept as Telegram has them: the leave button and the leave item.
VOIPGROUP_KEPT = ("voipgroup_leaveCallMenu", "voipgroup_leaveButton", "voipgroup_leaveButtonScrolled")
# darkblue.attheme ("Dark Blue") sets one of the keys itself, a darker grey:
# (theme file, key, upstream value, Pluma's).
VOIPGROUP_THEME_FILE = ("darkblue.attheme", "voipgroup_topPanelGray", -10521727, call_neutral(0xFF5F7381))

THEME_COLORS = f"{JAVA}/ui/ActionBar/ThemeColors.java"
UI = f"{JAVA}/ui"
VOIP_UI = f"{UI}/Components/voip"
GRADIENT_LAYOUT = f"{VOIP_UI}/VoIpGradientLayout.java"
PREVIEW_DIALOG = f"{VOIP_UI}/PrivateVideoPreviewDialog.java"
PREVIEW_DIALOG_NEW = f"{VOIP_UI}/PrivateVideoPreviewDialogNew.java"
RECORD_ALERT = f"{UI}/Components/GroupCallRecordAlert.java"
NO_VIDEO = ("0xff212E3A", "0xff2B5B4D", "0xff245863", "0xff274558")

# The background of a private call, VoIpGradientLayout's constructor. Each
# line: the drawable, whether "black" (the call without the user's photo
# behind) replaces it with a plain colour, upstream's four points, Pluma's.
_GRADIENTS = (
    ("bgBlueViolet", True, ("0xFFB456D8", "0xFF8148EC", "0xFF20A4D7", "0xFF3F8BEA"), CALL_CONNECTING),
    ("bgBlueGreen", True, ("0xFF4576E9", "0xFF3B7AF1", "0xFF08B0A3", "0xFF17AAE4"), CALL_CONNECTING),
    ("bgGreen", False, ("0xFF07A9AC", "0xFF07BA63", "0xFFA9CC66", "0xFF5AB147"), CALL_CONNECTED),
    ("bgOrangeRed", False, ("0xFFE86958", "0xFFE7618F", "0xFFDB904C", "0xFFDE7238"), CALL_WEAK),
    None,
    ("bgBlueVioletDark", True, ("0xFFA736D0", "0xFF6A2BDD", "0xFF0F95C9", "0xFF287AE1"), tuple(map(call_darker, CALL_CONNECTING))),
    ("bgBlueGreenDark", True, ("0xFF2D60D6", "0xFF2C6ADF", "0xFF009595", "0xFF0291C9"), tuple(map(call_darker, CALL_CONNECTING))),
    ("bgGreenDark", False, ("0xFF008B8E", "0xFF01934C", "0xFF8FBD37", "0xFF319D27"), tuple(map(call_darker, CALL_CONNECTED))),
    ("bgOrangeRedDark", False, ("0xFFE23F29", "0xFFE6306F", "0xFFC77616", "0xFFD75A16"), tuple(map(call_darker, CALL_WEAK))),
    None,
    ("bgBlueVioletLight", True, ("0xFFD664FF", "0xFF9258FD", "0xFF2DC0F9", "0xFF57A1FF"), tuple(map(call_lighter, CALL_CONNECTING))),
    ("bgBlueGreenLight", True, ("0xFF558BFF", "0xFF5FABFF", "0xFF04DCCC", "0xFF28C2FF"), tuple(map(call_lighter, CALL_CONNECTING))),
    ("bgGreenLight", False, ("0xFF00D2D5", "0xFF09E279", "0xFFC7EF60", "0xFF6DD957"), tuple(map(call_lighter, CALL_CONNECTED))),
    ("bgOrangeRedLight", False, ("0xFFFF7866", "0xFFFF82A5", "0xFFFEB055", "0xFFFF8E51"), tuple(map(call_lighter, CALL_WEAK))),
    ("bgGreenLightReveal", False, ("0xFF00D2D5", "0xFF09E279", "0xFFC7EF60", "0xFF6DD957"), tuple(map(call_lighter, CALL_CONNECTED))),
    ("bgGreenDarkReveal", False, ("0xFF008B8E", "0xFF01934C", "0xFF8FBD37", "0xFF319D27"), tuple(map(call_darker, CALL_CONNECTED))),
)


def _gradient_lines(black, upstream):
    lines = []
    for g in _GRADIENTS:
        if g is None:
            lines.append("\n")
            continue
        name, plain, old, new = g
        points = ", ".join(old if upstream else map(jhex, new))
        motion = f"new MotionBackgroundDrawable({points}, 0, false, true)"
        lines.append(f"        {name} = black ? new PureColorDrawable({black}) : {motion};\n" if plain
                     else f"        {name} = {motion};\n")
    return "".join(lines)


_GRADIENT_EDIT = (GRADIENT_LAYOUT, _gradient_lines("0xFF191F26", True),
                  "        // pluma: the call background of Pluma, variant A \"Sage\" (owner, 2026-11-12).\n"
                  + _gradient_lines(jhex(call_neutral(0xFF191F26)), False))


def _recoloured(text, colours):
    """text with each literal of colours (by its exact spelling) in Pluma's colour."""
    def one(m):
        return jhex(colours[m.group(0)]) if m.group(0) in colours else m.group(0)
    out = re.sub(r"0x[0-9A-Fa-f]{8}\b", one, text)
    for literal in colours:
        if literal not in text:
            raise PatchError(f"call colours: {literal} is not in {text!r}")
    return out


# The literals of the call screens, by meaning: (file, the upstream text, its
# literals and their new colours, how many times the text is there).
_CALL_LITERALS = (
    (f"{UI}/VoIPFragment.java",
     "new BackgroundGradientDrawable(GradientDrawable.Orientation.TOP_BOTTOM, new int[]{0xFF1b354e, 0xFF255b7d});",
     {"0xFF1b354e": C3, "0xFF255b7d": C2}, 1),
    (f"{UI}/VoIPFragment.java", "            backgroundPaint.setColor(0xFF222A33);\n",
     {"0xFF222A33": call_neutral(0xFF222A33)}, 1),
    (f"{UI}/GroupCallActivity.java",
     "                currentColor = 0xffCC5757;\n"
     "            } else if (currentProgress > 0.25f && currentProgress < 0.5f) {\n"
     "                currentColor = 0xffC9A53B;\n"
     "            } else if (currentProgress >= 0.5f && currentProgress <= 0.75f) {\n"
     "                currentColor = 0xff57BC6B;\n"
     "            } else {\n"
     "                currentColor = 0xff4DA6DF;\n",
     {"0xffCC5757": W2, "0xffC9A53B": W4, "0xff57BC6B": G4, "0xff4DA6DF": CALL_ACCENT}, 1),
    (f"{UI}/GroupCallActivity.java", "        liveLabelPaint.setColor(0xff3d4657);\n",
     {"0xff3d4657": call_neutral(0xFF3D4657)}, 1),
    (f"{UI}/GroupCallActivity.java", "isLive ? 0xffee3e4c : 0xff3d4657;",
     {"0xffee3e4c": W2, "0xff3d4657": call_neutral(0xFF3D4657)}, 1),
    (f"{UI}/GroupCallActivity.java", "VoIPService.STATE_ESTABLISHED ? 0xffee3e4c : 0xff3d4657);",
     {"0xffee3e4c": W2, "0xff3d4657": call_neutral(0xFF3D4657)}, 2),
    (f"{UI}/GroupCallActivity.java", "callMessageEnterView.getEditText().setLinkTextColor(0xFF4db8ff);",
     {"0xFF4db8ff": CALL_LINK}, 1),
    (f"{UI}/GroupCallActivity.java", "backgroundPaint.setColor(0xFF1c2229);",
     {"0xFF1c2229": call_neutral(0xFF1C2229)}, 2),
    (f"{UI}/GroupCallActivity.java", "ColorUtils.compositeColors(0x0DFFFFFF, 0xFF1c2229)",
     {"0xFF1c2229": call_neutral(0xFF1C2229)}, 1),
    (f"{UI}/GroupCallActivity.java", "Picker.setSelectorColor(0xff6D89ED);",
     {"0xff6D89ED": CALL_ACCENT}, 3),
    (f"{UI}/GroupCallActivity.java", "setTextColor(0xff7B8389);",
     {"0xff7B8389": call_neutral(0xFF7B8389)}, 2),
    (f"{UI}/CreateGroupCallSheet.java", "closeButton.setColorFilter(new PorterDuffColorFilter(0xFF848D94, PorterDuff.Mode.SRC_IN));",
     {"0xFF848D94": call_neutral(0xFF848D94)}, 1),
    (f"{UI}/GroupCallActivity.java", "tmpPaint.setColor(0xFF00FF00);",
     {"0xFF00FF00": G1}, 2),
    (f"{UI}/GroupCallActivity.java", "otherItem.redrawPopup(0xff232A33);",
     {"0xff232A33": call_neutral(0xFF232A33)}, 1),
    (f"{UI}/GroupCallActivity.java", "HintView.setBackgroundColor(0xea272f38, 0xffffffff);",
     {"0xea272f38": call_neutral(0xEA272F38)}, 2),
    (f"{UI}/GroupCallActivity.java", "bgPaint.setColor(0xFF212b35);",
     {"0xFF212b35": call_neutral(0xFF212B35)}, 1),
    (f"{UI}/GroupCallSheet.java", "separator.setBackgroundColor(0xFF2A3036);",
     {"0xFF2A3036": call_neutral(0xFF2A3036)}, 1),
    (f"{VOIP_UI}/CallPipSelfView.java", "frame.setBackgroundColor(0xFF1B1F23);",
     {"0xFF1B1F23": call_neutral(0xFF1B1F23)}, 1),
    (f"{VOIP_UI}/CallSystemPipView.java", "setBackgroundColor(0xFF1B1F23);",
     {"0xFF1B1F23": call_neutral(0xFF1B1F23)}, 1),
    (f"{VOIP_UI}/GroupCallPipContent.java", "setBackgroundColor(0xFF1B1F23);",
     {"0xFF1B1F23": call_neutral(0xFF1B1F23)}, 1),
    (f"{VOIP_UI}/RtmpStreamPipContent.java", "canvas.drawColor(0xFF1B1F23);",
     {"0xFF1B1F23": call_neutral(0xFF1B1F23)}, 1),
    (f"{VOIP_UI}/VoIPTextureView.java", "backgroundView.setBackgroundColor(0xff1b1f23);\n",
     {"0xff1b1f23": call_neutral(0xFF1B1F23)}, 1),
    # The tile of a participant without video and of a screencast.
    (f"{VOIP_UI}/VoIPTextureView.java", "new MotionBackgroundDrawable(0xff212E3A, 0xff2B5B4D, 0xff245863, 0xff274558, true)",
     dict(zip(NO_VIDEO, CALL_CONNECTING)), 1),
    (f"{VOIP_UI}/GroupCallMiniTextureView.java", "new MotionBackgroundDrawable(0xff212E3A, 0xff2B5B4D, 0xff245863, 0xff274558, true)",
     dict(zip(NO_VIDEO, CALL_CONNECTING)), 1),
    (PREVIEW_DIALOG, "new MotionBackgroundDrawable(0xff212E3A, 0xff2B5B4D, 0xff245863, 0xff274558, true)",
     dict(zip(NO_VIDEO, CALL_CONNECTING)), 1),
    (PREVIEW_DIALOG_NEW, "new MotionBackgroundDrawable(0xff212E3A, 0xff2B5B4D, 0xff245863, 0xff274558, true)",
     dict(zip(NO_VIDEO, CALL_CONNECTING)), 1),
    # The camera preview of a private call: connected and calling.
    (PREVIEW_DIALOG_NEW, "bgGreen = new MotionBackgroundDrawable(0xFF5FD051, 0xFF00B48E, 0xFFA9CC66, 0xFF5AB147, 0, false, true);",
     dict(zip(("0xFF5FD051", "0xFF00B48E", "0xFFA9CC66", "0xFF5AB147"), CALL_CONNECTED)), 1),
    (PREVIEW_DIALOG_NEW, "bgBlueViolet = new MotionBackgroundDrawable(0xFF00A3E6, 0xFF296EF7, 0xFF18CEE2, 0xFF3FB2FF, 0, false, true);",
     dict(zip(("0xFF00A3E6", "0xFF296EF7", "0xFF18CEE2", "0xFF3FB2FF"), CALL_CONNECTING)), 1),
    # The pages of the camera preview of a group call and of the record alert:
    # green and cyan, blue and purple, purple, red and yellow.
    (PREVIEW_DIALOG,
     "                        color1 = 0xff77E55C;\n"
     "                        color2 = 0xff56C7FE;\n",
     {"0xff77E55C": G4, "0xff56C7FE": G1}, 1),
    (PREVIEW_DIALOG,
     "                        color1 = 0xff57A4FE;\n"
     "                        color2 = 0xff766EE9;\n",
     {"0xff57A4FE": C4, "0xff766EE9": C2}, 1),
    (PREVIEW_DIALOG,
     "                        color1 = 0xff766EE9;\n"
     "                        color2 = 0xffF05459;\n"
     "                        color3 = 0xffE4A756;\n",
     {"0xff766EE9": C2, "0xffF05459": W2, "0xffE4A756": W4}, 1),
    (RECORD_ALERT,
     "                        color1 = 0xff77E55C;\n"
     "                        color2 = 0xff56C7FE;\n",
     {"0xff77E55C": G4, "0xff56C7FE": G1}, 1),
    (RECORD_ALERT,
     "                        color1 = 0xff57A4FE;\n"
     "                        color2 = 0xff766EE9;\n",
     {"0xff57A4FE": C4, "0xff766EE9": C2}, 1),
    (RECORD_ALERT,
     "                        color1 = 0xff766EE9;\n"
     "                        color2 = 0xffF05459;\n"
     "                        color3 = 0xffE4A756;\n",
     {"0xff766EE9": C2, "0xffF05459": W2, "0xffE4A756": W4}, 1),
    # The tint of a call's avatar when the photo gives no dark colour of its own.
    (f"{VOIP_UI}/VoIPOverlayBackground.java", "palette.getDarkMutedColor(0xFF547499)",
     {"0xFF547499": C2}, 1),
    # The call bubble over the app while it is dragged.
    (f"{UI}/Components/GroupCallPip.java", "ColorUtils.blendARGB(0x66050D15, 0x66350C12, prepareToRemoveProgress)",
     {"0x66050D15": call_neutral(0x66050D15)}, 1),
    # The chat's call panel: the waves before the theme colours are read, the
    # "notify me" button of a scheduled call.
    (f"{UI}/Components/CapsuleBlobDrawable.java", "        int color = 0xFF534AB7;\n",
     {"0xFF534AB7": C4}, 1),
    (f"{UI}/Components/FragmentContextView.java", "new int[]{0xff658ffe, 0xff956ffd}",
     {"0xff658ffe": C4, "0xff956ffd": C2}, 1),
    # The notification of a call: Android 8 and later colour it with this.
    (VOIP_SERVICE, "builder.setColor(0xff282e31);", {"0xff282e31": call_neutral(0xFF282E31)}, 1),
)

CALL_COLOUR_EDITS = (
    tuple((rel, old, _recoloured(old, colours), count) for rel, old, colours, count in _CALL_LITERALS)
    + ((_GRADIENT_EDIT[0], _GRADIENT_EDIT[1], _GRADIENT_EDIT[2], 1),
       (f"{RES}/drawable/call_notification_bg.xml", '<solid android:color="#282e31"/>',
        f'<solid android:color="#{call_neutral(0xFF282E31) & 0xFFFFFF:06x}"/>', 1))
)

# The files of the call screens the check reads in full: the private call, the
# group call with its sheets, cells, bubble and alerts, the chat's call panel,
# the notifications of a call.
CALL_UI_FILES = (
    f"{UI}/VoIPFragment.java", f"{UI}/GroupCallActivity.java", f"{UI}/GroupCallSheet.java",
    f"{UI}/CreateGroupCallSheet.java", f"{UI}/GroupCallTabletGridAdapter.java",
    f"{UI}/Components/GroupVoipInviteAlert.java", f"{UI}/Components/JoinCallAlert.java",
    f"{UI}/Components/JoinCallByUrlAlert.java", f"{UI}/Components/CreateGroupCallBottomSheet.java",
    f"{UI}/Components/CapsuleBlobDrawable.java", f"{UI}/Components/FragmentContextView.java",
    f"{UI}/Components/FragmentContextViewWavesDrawable.java", f"{RES}/drawable/call_notification_bg.xml",
    VOIP_SERVICE, f"{VOIP}/VoIPGroupNotification.java", f"{VOIP}/VoIPPreNotificationService.java",
)
CALL_UI_GLOBS = (f"{VOIP_UI}/*.java", f"{UI}/Cells/GroupCall*.java", f"{UI}/Components/GroupCall*.java")
# The literals kept as Telegram has them (see above), with how many times.
CALL_COLOURS_KEPT = {
    (f"{UI}/VoIPFragment.java", "0xfff01d2c"): 2,
    (f"{VOIP_UI}/AcceptDeclineView.java", "0xff40c749"): 1,
    (f"{VOIP_UI}/AcceptDeclineView.java", "0xfff01d2c"): 2,
    (f"{VOIP_UI}/AcceptDeclineView.java", "0xffff3846"): 1,
    (f"{VOIP_UI}/AcceptDeclineView.java", "0xff4dd156"): 1,
    (f"{VOIP_UI}/EndCloseLayout.java", "0xfff4606c"): 1,
    (f"{UI}/Components/GroupCallPipAlertView.java", "0xffce4a4a"): 1,
    (f"{UI}/Components/GroupCallPipButton.java", "0xffd54141"): 1,
    (f"{UI}/Components/GroupCallPipButton.java", "0xfff76e7e"): 1,
    (f"{UI}/GroupCallActivity.java", "0xffee7d79"): 2,
    (f"{UI}/GroupCallActivity.java", "0xffec7777"): 1,
    # The red "end" and green "answer" actions of a call's notification.
    (VOIP_SERVICE, "0xfff44336"): 1,
    (VOIP_SERVICE, "0xff00aa00"): 1,
    (f"{VOIP}/VoIPGroupNotification.java", "0xfff44336"): 1,
    (f"{VOIP}/VoIPGroupNotification.java", "0xff00aa00"): 1,
    (f"{VOIP}/VoIPPreNotificationService.java", "0xfff44336"): 1,
    (f"{VOIP}/VoIPPreNotificationService.java", "0xff00aa00"): 1,
}


def _call_ui_files(tree):
    files = set(CALL_UI_FILES)
    for pattern in CALL_UI_GLOBS:
        files.update(str(p.relative_to(tree.root)) for p in tree.root.glob(pattern))
    return sorted(files)


def _colour_literals(text):
    """The colour literals of a Java or XML file outside line comments, lower-case."""
    found = []
    for line in text.split("\n"):
        code = line.split("//", 1)[0] if not line.lstrip().startswith("<!--") else ""
        found += [m.lower() for m in re.findall(r"\b0x[0-9A-Fa-f]{8}\b", code)]
        found += ["0xff" + m.lower() for m in re.findall(r'"#([0-9A-Fa-f]{6})"', code)]
        found += ["0x" + m.lower() for m in re.findall(r'"#([0-9A-Fa-f]{8})"', code)]
    return found


def _voipgroup_line(key, colour):
    return f"        defaultColors[key_{key}] = {colour};\n"


def call_colours(tree):
    # Every anchor first, so that a changed upstream fails before anything is written.
    colours = tree.read(THEME_COLORS)
    for rel, old, _, count in CALL_COLOUR_EDITS:
        tree.expect(rel, old, count)
    asset, theme_key, theme_old, theme_new = VOIPGROUP_THEME_FILE
    theme_file = f"{MAIN}/assets/{asset}"
    tree.expect(theme_file, f"\n{theme_key}={theme_old}\n")
    names, defaults = theme_defaults(colours)
    keys = {k[4:]: v for k, v in defaults.items() if k.startswith("key_voipgroup_")}
    for key in VOIPGROUP_COLOURS:
        if key not in keys or len(re.findall(rf"        defaultColors\[key_{key}\] = [^;]+;\n", colours)) != 1:
            raise PatchError(f"{THEME_COLORS}: no colour key {key}, or more than one; upstream changed it")
    missed = sorted(k for k, v in keys.items() if telegram_call_colour(v) and k not in VOIPGROUP_COLOURS and k not in VOIPGROUP_KEPT)
    if missed:
        raise PatchError(f"{THEME_COLORS}: Telegram's call colours in {', '.join(missed)}, which the patch does not map")
    for rel, old, new, count in CALL_COLOUR_EDITS:
        tree.replace(rel, old, new, count)
    for key, colour in VOIPGROUP_COLOURS.items():
        line = re.search(rf"        defaultColors\[key_{key}\] = ([^;]+);\n", tree.read(THEME_COLORS))
        tree.replace(THEME_COLORS, line.group(0), _voipgroup_line(key, jhex(colour)))
    tree.replace(theme_file, f"\n{theme_key}={theme_old}\n", f"\n{theme_key}={_signed(theme_new)}\n")


def _signed(c):
    """A colour as the signed int of a .attheme file."""
    return c - (1 << 32) if c & 0x80000000 else c


def verify_call_colours(tree):
    for rel, old, new, count in CALL_COLOUR_EDITS:
        text = tree.read(rel)
        if old in text or text.count(new) != count:
            raise PatchError(f"{rel}: the call colour edit {new.strip().splitlines()[-1][:80]!r} is not there")
    # Every colour key of the group call, in ThemeColors and in each default theme.
    names, defaults = theme_defaults(tree.read(THEME_COLORS))
    keys = {k[4:]: v for k, v in defaults.items() if k.startswith("key_voipgroup_")}
    for key, colour in VOIPGROUP_COLOURS.items():
        if keys.get(key) != colour:
            raise PatchError(f"{THEME_COLORS}: {key} is not the call colour of Pluma")
    asset, key, old, new = VOIPGROUP_THEME_FILE
    if f"\n{key}={_signed(new)}\n" not in tree.read(f"{MAIN}/assets/{asset}"):
        raise PatchError(f"{asset}: {key} is not the call colour of Pluma")
    for asset, _, _ in DEFAULT_THEMES.values():
        theme = dict(keys)
        for name, value in theme_file_values(tree.read(f"{MAIN}/assets/{asset}")).items():
            if name.startswith("voipgroup_"):
                theme[name] = value
        left = sorted(k for k, v in theme.items() if telegram_call_colour(v) and k not in VOIPGROUP_KEPT)
        if left:
            raise PatchError(f"{asset}: Telegram's call colours are left in {', '.join(left)}")
    # Every colour literal of the call screens.
    for rel in _call_ui_files(tree):
        if not (tree.root / rel).is_file():
            raise PatchError(f"{rel}: the call screen is gone; upstream changed it")
        found = collections.Counter(_colour_literals(tree.read(rel)))
        for literal, n in found.items():
            if telegram_call_colour(int(literal, 16)) and CALL_COLOURS_KEPT.get((rel, literal)) != n:
                raise PatchError(f"{rel}: Telegram's call colour {literal} is still there ({n} times)")
        for (kept_rel, literal), n in CALL_COLOURS_KEPT.items():
            if kept_rel == rel and found[literal] != n:
                raise PatchError(f"{rel}: {literal}, which the call keeps, is there {found[literal]} times, expected {n}")


# --- HTTPS CDN (task 107 of the server repository, ADR 0071) ---------------------
# Large files come over HTTPS from a CDN that only ever holds their ciphertext;
# the key, the IV and the hash of every 128 KB come from the server over MTProto.
# The client says it can do this with "pluma_cdn": 1 in the params of
# initConnection (Android always sets cdn_supported, FileLoadOperation.java
# 2469, so the flag alone cannot tell a patched client), and the server
# redirects only such a session, with upload.fileCdnRedirect whose file_token is
# "PLH1" | id[32] | expiry uint32 BE | URL. The client never connects to the
# redirect's dc_id (an unpatched client would wait for that datacenter forever,
# jni/tgnet/ConnectionsManager.cpp 2585-2590, 2849-2856, 3166-3168).
#
# FileLoadOperation keeps its parts, offsets, streams and files as upstream: a
# part of a redirected download is fetched by PlumaCdnHttps instead of
# upload.getCdnFile (2449-2455, 2525), decrypted as upload.cdnFile is (1900-1906:
# AES-256-CTR, bytes 12-15 of the IV = offset / 16), checked against the
# server's SHA-256 of each 128 KB before it is handed over, and handed over as
# upload.file, through the same callback (the lambda of sendRequestSync becomes
# a RequestDelegate). So the hash branches of a tgnet CDN download (isCdn, 1889,
# 2002) never run for it, and the bytes count in the network statistics as any
# file's (2667-2681). 403 and 410 ask the server for a new URL, as
# FILE_TOKEN_INVALID of upload.getCdnFile does (2583-2589), at most 3 times; any
# other failure makes the download take the rest from the server without
# cdn_supported, keeping what it has; upload.reuploadCdnFile is never sent. Such
# a part has a negative request token, unknown to tgnet: it is cancelled in
# PlumaCdnHttps (911, 1466-1490, 2210-2225) and holds up no tgnet connection
# (1497, 2236). cdn_supported is sent only while the download has not fallen
# back, no proxy is on (SharedConfig.isProxyEnabled, any kind: Android goes to
# the CDN only directly) and the CDN is not paused after 3 transport failures
# in a row.
# A development build also takes http:// to the stand (the server address of the
# build and the emulator's host 10.0.2.2); a server build takes https:// only.
FILE_LOAD = f"{JAVA}/messenger/FileLoadOperation.java"
CDN_HTTPS_FILE = f"{JAVA}/messenger/PlumaCdnHttps.java"
CONNECTIONS_CPP = "TMessagesProj/jni/tgnet/ConnectionsManager.cpp"
CDN_HTTPS_DEV_HOSTS_LINE = "    private static final String[] DEV_HTTP_HOSTS = {};\n"
CDN_HTTPS_EMULATOR_HOST = "10.0.2.2"

CDN_HTTPS_JAVA = r"""package org.telegram.messenger;

import android.os.SystemClock;

import org.telegram.tgnet.ConnectionsManager;
import org.telegram.tgnet.NativeByteBuffer;
import org.telegram.tgnet.RequestDelegate;
import org.telegram.tgnet.TLRPC;
import org.telegram.tgnet.Vector;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLException;

// pluma: large files from the HTTPS CDN of the Pluma server (ADR 0071 of the server repository).
// A redirect whose file_token starts with "PLH1" carries the address of the file's ciphertext:
// "PLH1" | id[32] | expiry, uint32 big-endian | URL, UTF-8. The CDN holds only the ciphertext; the
// key, the IV and the SHA-256 of every 128 KB of plain text come from the server over MTProto. A
// part is fetched as an HTTP range of whole 128 KB blocks, decrypted as upload.cdnFile is and
// handed to the download only once every block matched its hash. 403 and 410 ask for a new URL;
// any other failure makes the download take the rest from the server.
public final class PlumaCdnHttps {

    // The errors a part fails with: a new URL is needed, or the download goes back to the server.
    public static final String ERROR_REFRESH = "PLUMA_CDN_HTTPS_REFRESH";
    public static final String ERROR_FALLBACK = "PLUMA_CDN_HTTPS_FALLBACK";
    // New URLs a download may ask for; the next 403 or 410 sends it back to the server.
    public static final int MAX_REFRESHES = 3;

    private static final byte[] TOKEN_TAG = {'P', 'L', 'H', '1'};
    private static final int TOKEN_HEADER = 4 + 32 + 4;
    private static final int BLOCK = 128 * 1024;
    private static final int CACHED_BLOCKS = 8;
    private static final int CONNECT_TIMEOUT = 5000;
    private static final int READ_TIMEOUT = 10000;
    private static final int REQUEST_TIMEOUT = 30000;
    private static final int HASHES_TIMEOUT = 15000;
    private static final int RETRY_DELAY_MIN = 300;
    private static final int RETRY_DELAY_SPREAD = 500;
    private static final int FAILURES_TO_PAUSE = 3;
    private static final long PAUSE = 10 * 60 * 1000L;
    // The hosts a development build may reach over plain http:// (the stand); none in a server build.
    private static final String[] DEV_HTTP_HOSTS = {};

    private static final Object pauseLock = new Object();
    private static int transportFailures;
    private static long pausedUntil;
    private static final AtomicInteger lastToken = new AtomicInteger();
    private static final ThreadPoolExecutor pool = new ThreadPoolExecutor(4, 4, 30, TimeUnit.SECONDS,
            new LinkedBlockingQueue<>(), r -> daemon(r, "PlumaCdnHttps"));
    private static final ScheduledThreadPoolExecutor deadlines = new ScheduledThreadPoolExecutor(1,
            r -> daemon(r, "PlumaCdnHttpsDeadline"));

    static {
        pool.allowCoreThreadTimeOut(true);
        deadlines.setKeepAliveTime(30, TimeUnit.SECONDS);
        deadlines.allowCoreThreadTimeOut(true);
        deadlines.setRemoveOnCancelPolicy(true);
    }

    private PlumaCdnHttps() {
    }

    private static Thread daemon(Runnable r, String name) {
        Thread thread = new Thread(r, name);
        thread.setDaemon(true);
        return thread;
    }

    // Whether a download may ask the server for the CDN (cdn_supported): not while the CDN is
    // paused after transport failures, and never through a proxy.
    public static boolean isAllowed() {
        synchronized (pauseLock) {
            if (pausedUntil != 0 && SystemClock.elapsedRealtime() < pausedUntil) {
                return false;
            }
        }
        return !SharedConfig.isProxyEnabled();
    }

    public static boolean isPlumaToken(byte[] token) {
        return token != null && token.length >= TOKEN_TAG.length
                && Arrays.equals(Arrays.copyOf(token, TOKEN_TAG.length), TOKEN_TAG);
    }

    // The download a "PLH1" redirect describes, or null when the client cannot use it.
    public static Download open(int currentAccount, int datacenterId, TLRPC.TL_upload_fileCdnRedirect redirect, long size) {
        byte[] token = redirect.file_token;
        if (!isPlumaToken(token) || token.length <= TOKEN_HEADER || size <= 0
                || redirect.encryption_key == null || redirect.encryption_key.length != 32
                || redirect.encryption_iv == null || redirect.encryption_iv.length != 16) {
            return null;
        }
        String address;
        try {
            address = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(token, TOKEN_HEADER, token.length - TOKEN_HEADER))
                    .toString();
        } catch (CharacterCodingException e) {
            return null;
        }
        URL url = parseUrl(address);
        if (url == null) {
            return null;
        }
        Download download = new Download(currentAccount, datacenterId, token, url, redirect.encryption_key, redirect.encryption_iv, size);
        if (redirect.file_hashes != null) {
            for (TLRPC.TL_fileHash hash : redirect.file_hashes) {
                download.hashes.put(hash.offset, hash);
            }
        }
        return download;
    }

    private static URL parseUrl(String address) {
        boolean secure = address.startsWith("https://");
        if (!secure && !address.startsWith("http://")) {
            return null;
        }
        try {
            URI uri = new URI(address);
            String host = uri.getHost();
            if (host == null || uri.getRawUserInfo() != null || uri.getRawFragment() != null) {
                return null;
            }
            if (!secure && !Arrays.asList(DEV_HTTP_HOSTS).contains(host)) {
                return null;
            }
            return uri.toURL();
        } catch (URISyntaxException | IllegalArgumentException | IOException e) {
            return null;
        }
    }

    private static int nextToken() {
        while (true) {
            int token = lastToken.decrementAndGet();
            if (token < 0) {
                return token;
            }
            lastToken.compareAndSet(token, 0);
        }
    }

    private static void transportSucceeded() {
        synchronized (pauseLock) {
            transportFailures = 0;
        }
    }

    private static void transportFailed(String host) {
        synchronized (pauseLock) {
            if (++transportFailures < FAILURES_TO_PAUSE) {
                return;
            }
            transportFailures = 0;
            pausedUntil = SystemClock.elapsedRealtime() + PAUSE;
        }
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("cdn https " + host + " paused");
        }
    }

    private static TLRPC.TL_error error(String text) {
        TLRPC.TL_error error = new TLRPC.TL_error();
        error.code = 400;
        error.text = text;
        return error;
    }

    private static final class Failure extends Exception {
        final String error;
        final boolean transport;
        final boolean retry;

        Failure(String reason, String error, boolean transport, boolean retry) {
            super(reason);
            this.error = error;
            this.transport = transport;
            this.retry = retry;
        }
    }

    // A part a download asked for: its blocks, filled in as they arrive.
    private static final class Part {
        final int token;
        final long offset;
        final RequestDelegate delegate;
        int length;
        long first;
        byte[][] data;
        int missing;
        boolean done;

        Part(int token, long offset, RequestDelegate delegate) {
            this.token = token;
            this.offset = offset;
            this.delegate = delegate;
        }
    }

    // One HTTP range: blocks from start to end, the parts that wait for them.
    private static final class Fetch {
        final long start;
        long end;
        final LinkedHashSet<Part> parts = new LinkedHashSet<>();

        Fetch(long start) {
            this.start = start;
        }
    }

    public static final class Download {
        private final int currentAccount;
        private final int datacenterId;
        private final byte[] fileToken;
        private final URL url;
        private final String host;
        private final SecretKeySpec key;
        private final byte[] iv;
        private final long size;
        private final HashMap<Long, TLRPC.TL_fileHash> hashes = new HashMap<>();
        private final LinkedHashMap<Long, byte[]> blocks = new LinkedHashMap<Long, byte[]>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<Long, byte[]> eldest) {
                return size() > CACHED_BLOCKS;
            }
        };
        private final HashMap<Long, Fetch> loading = new HashMap<>();
        private final HashMap<Integer, Part> parts = new HashMap<>();
        private final HashSet<HttpURLConnection> connections = new HashSet<>();
        private final Object hashesRequest = new Object();
        private boolean closed;
        private boolean transportFailed;

        private Download(int currentAccount, int datacenterId, byte[] fileToken, URL url, byte[] key, byte[] iv, long size) {
            this.currentAccount = currentAccount;
            this.datacenterId = datacenterId;
            this.fileToken = fileToken;
            this.url = url;
            this.host = url.getHost();
            this.key = new SecretKeySpec(key, "AES");
            this.iv = iv.clone();
            this.size = size;
        }

        // Asks for the bytes [offset, offset + limit) of the file; the delegate gets them as
        // upload.file on the stage queue, or an error. Returns the part's token, always negative.
        public int fetch(long offset, int limit, RequestDelegate delegate) {
            final Part part = new Part(nextToken(), offset, delegate);
            final ArrayList<Fetch> started = new ArrayList<>();
            boolean valid;
            synchronized (this) {
                valid = !closed && offset >= 0 && limit > 0 && offset < size;
                if (valid) {
                    long end = Math.min(offset + limit, size);
                    part.length = (int) (end - offset);
                    part.first = offset / BLOCK * BLOCK;
                    part.data = new byte[(int) ((end - 1) / BLOCK - offset / BLOCK + 1)][];
                    Fetch run = null;
                    for (int i = 0; i < part.data.length; i++) {
                        long block = part.first + (long) i * BLOCK;
                        byte[] cached = blocks.get(block);
                        if (cached != null) {
                            part.data[i] = cached;
                            run = null;
                            continue;
                        }
                        part.missing++;
                        Fetch fetch = loading.get(block);
                        if (fetch == null) {
                            if (run == null) {
                                run = new Fetch(block);
                                started.add(run);
                            }
                            run.end = Math.min(block + BLOCK, size);
                            loading.put(block, run);
                            fetch = run;
                        } else {
                            run = null;
                        }
                        fetch.parts.add(part);
                    }
                    part.done = part.missing == 0;
                }
                parts.put(part.token, part);
            }
            if (!valid) {
                fail(part, ERROR_FALLBACK);
            } else if (part.done) {
                deliver(part);
            }
            for (Fetch fetch : started) {
                pool.execute(() -> load(fetch));
            }
            return part.token;
        }

        public void cancel(int token) {
            synchronized (this) {
                parts.remove(token);
            }
        }

        // Drops every part and aborts every request; nothing is delivered afterwards.
        public void close() {
            ArrayList<HttpURLConnection> open;
            synchronized (this) {
                if (closed) {
                    return;
                }
                closed = true;
                parts.clear();
                blocks.clear();
                loading.clear();
                hashes.clear();
                open = new ArrayList<>(connections);
                connections.clear();
            }
            for (HttpURLConnection connection : open) {
                connection.disconnect();
            }
        }

        private void load(Fetch fetch) {
            byte[][] data = null;
            Failure failure = null;
            try {
                data = verify(fetch, download(fetch.start, fetch.end - 1));
            } catch (Failure e) {
                failure = e;
            } catch (RuntimeException e) {
                // A fault of the HTTP stack or the cipher must not leave the range in loading and
                // its parts waiting forever: the download takes the rest from the server.
                failure = new Failure(e.getClass().getSimpleName(), ERROR_FALLBACK, false, false);
            }
            ArrayList<Part> ready = new ArrayList<>();
            ArrayList<Part> failed = new ArrayList<>();
            boolean countFailure = false;
            synchronized (this) {
                for (long block = fetch.start; block < fetch.end; block += BLOCK) {
                    if (loading.get(block) == fetch) {
                        loading.remove(block);
                    }
                }
                if (closed) {
                    return;
                }
                if (failure != null && failure.transport && !transportFailed) {
                    transportFailed = true;
                    countFailure = true;
                }
                for (int i = 0; data != null && i < data.length; i++) {
                    blocks.put(fetch.start + (long) i * BLOCK, data[i]);
                }
                for (Part part : fetch.parts) {
                    if (part.done || parts.get(part.token) != part) {
                        continue;
                    }
                    if (data == null) {
                        part.done = true;
                        failed.add(part);
                        continue;
                    }
                    int from = (int) ((fetch.start - part.first) / BLOCK);
                    for (int i = 0; i < data.length; i++) {
                        if (from + i >= 0 && from + i < part.data.length && part.data[from + i] == null) {
                            part.data[from + i] = data[i];
                            part.missing--;
                        }
                    }
                    if (part.missing == 0) {
                        part.done = true;
                        ready.add(part);
                    }
                }
            }
            if (failure != null && BuildVars.LOGS_ENABLED) {
                FileLog.d("cdn https " + host + " failed: " + failure.getMessage() + " offset=" + fetch.start);
            }
            if (countFailure) {
                transportFailed(host);
            }
            for (Part part : ready) {
                deliver(part);
            }
            for (Part part : failed) {
                fail(part, failure.error);
            }
        }

        // One retry of the same range after a network failure, a timeout or a 5xx.
        private byte[] download(long first, long last) throws Failure {
            for (int attempt = 0; ; attempt++) {
                try {
                    return request(first, last);
                } catch (Failure e) {
                    if (!e.retry || attempt > 0) {
                        throw e;
                    }
                }
                try {
                    Thread.sleep(RETRY_DELAY_MIN + ThreadLocalRandom.current().nextInt(RETRY_DELAY_SPREAD + 1));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new Failure("interrupted", ERROR_FALLBACK, false, false);
                }
            }
        }

        private byte[] request(long first, long last) throws Failure {
            if (SharedConfig.isProxyEnabled()) {
                throw new Failure("proxy", ERROR_FALLBACK, false, false);
            }
            final HttpURLConnection connection;
            try {
                connection = (HttpURLConnection) url.openConnection();
            } catch (IOException e) {
                throw new Failure(e.getClass().getSimpleName(), ERROR_FALLBACK, true, true);
            }
            synchronized (this) {
                if (closed) {
                    throw new Failure("closed", ERROR_FALLBACK, false, false);
                }
                connections.add(connection);
            }
            final AtomicBoolean late = new AtomicBoolean();
            ScheduledFuture<?> deadline = deadlines.schedule(() -> {
                late.set(true);
                connection.disconnect();
            }, REQUEST_TIMEOUT, TimeUnit.MILLISECONDS);
            boolean read = false;
            try {
                connection.setConnectTimeout(CONNECT_TIMEOUT);
                connection.setReadTimeout(READ_TIMEOUT);
                connection.setUseCaches(false);
                connection.setInstanceFollowRedirects(false);
                connection.setRequestProperty("Range", "bytes=" + first + "-" + last);
                connection.setRequestProperty("Accept-Encoding", "identity");
                connection.setRequestProperty("User-Agent", "Pluma");
                int code = connection.getResponseCode();
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.d("cdn https " + host + " " + code + " offset=" + first);
                }
                if (code == 403 || code == 410) {
                    throw new Failure("status " + code, ERROR_REFRESH, false, false);
                }
                if (code >= 500 && code < 600) {
                    throw new Failure("status " + code, ERROR_FALLBACK, true, true);
                }
                if (code != 206) {
                    throw new Failure("status " + code, ERROR_FALLBACK, false, false);
                }
                String encoding = connection.getHeaderField("Content-Encoding");
                if (encoding != null && !encoding.trim().equalsIgnoreCase("identity")) {
                    throw new Failure("encoding", ERROR_FALLBACK, false, false);
                }
                String range = connection.getHeaderField("Content-Range");
                if (range == null || !range.trim().equals("bytes " + first + "-" + last + "/" + size)) {
                    throw new Failure("content range", ERROR_FALLBACK, false, false);
                }
                int length = (int) (last - first + 1);
                String declared = connection.getHeaderField("Content-Length");
                if (declared != null && !declared.trim().equals(Integer.toString(length))) {
                    throw new Failure("content length", ERROR_FALLBACK, false, false);
                }
                byte[] body = new byte[length];
                InputStream in = connection.getInputStream();
                for (int at = 0; at < length; ) {
                    int n = in.read(body, at, length - at);
                    if (n < 0) {
                        throw new IOException("short body");
                    }
                    at += n;
                }
                if (in.read() != -1) {
                    throw new Failure("content length", ERROR_FALLBACK, false, false);
                }
                in.close();
                read = true;
                transportSucceeded();
                return body;
            } catch (SSLException e) {
                throw new Failure(e.getClass().getSimpleName(), ERROR_FALLBACK, true, false);
            } catch (IOException e) {
                if (late.get()) {
                    throw new Failure("deadline", ERROR_FALLBACK, true, false);
                }
                synchronized (this) {
                    if (closed) {
                        throw new Failure("closed", ERROR_FALLBACK, false, false);
                    }
                }
                throw new Failure(e.getClass().getSimpleName(), ERROR_FALLBACK, true, true);
            } finally {
                deadline.cancel(false);
                synchronized (this) {
                    connections.remove(connection);
                }
                if (!read) {
                    connection.disconnect();
                }
            }
        }

        // Decrypts the blocks of a range and checks each against the server's hash.
        private byte[][] verify(Fetch fetch, byte[] body) throws Failure {
            byte[][] out = new byte[(int) ((fetch.end - fetch.start + BLOCK - 1) / BLOCK)][];
            try {
                Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
                MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
                for (int i = 0; i < out.length; i++) {
                    long offset = fetch.start + (long) i * BLOCK;
                    int length = (int) Math.min(BLOCK, fetch.end - offset);
                    byte[] counter = iv.clone();
                    long n = offset / 16;
                    counter[12] = (byte) (n >> 24);
                    counter[13] = (byte) (n >> 16);
                    counter[14] = (byte) (n >> 8);
                    counter[15] = (byte) n;
                    cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(counter));
                    byte[] plain = cipher.doFinal(body, i * BLOCK, length);
                    TLRPC.TL_fileHash hash = hash(offset);
                    if (hash.limit != length || hash.hash == null || !MessageDigest.isEqual(sha256.digest(plain), hash.hash)) {
                        throw new Failure("hash", ERROR_FALLBACK, false, false);
                    }
                    out[i] = plain;
                }
            } catch (GeneralSecurityException e) {
                throw new Failure(e.getClass().getSimpleName(), ERROR_FALLBACK, false, false);
            }
            return out;
        }

        private TLRPC.TL_fileHash hash(long offset) throws Failure {
            synchronized (hashesRequest) {
                synchronized (this) {
                    if (closed) {
                        throw new Failure("closed", ERROR_FALLBACK, false, false);
                    }
                    TLRPC.TL_fileHash hash = hashes.get(offset);
                    if (hash != null) {
                        return hash;
                    }
                }
                ArrayList<TLRPC.TL_fileHash> answer = requestHashes(offset);
                synchronized (this) {
                    for (TLRPC.TL_fileHash hash : answer) {
                        hashes.put(hash.offset, hash);
                    }
                    TLRPC.TL_fileHash hash = hashes.get(offset);
                    if (hash == null) {
                        throw new Failure("no hash", ERROR_FALLBACK, false, false);
                    }
                    return hash;
                }
            }
        }

        // upload.getCdnFileHashes on the file's datacenter, as FileLoadOperation.requestFileOffsets.
        private ArrayList<TLRPC.TL_fileHash> requestHashes(long offset) throws Failure {
            TLRPC.TL_upload_getCdnFileHashes req = new TLRPC.TL_upload_getCdnFileHashes();
            req.file_token = fileToken;
            req.offset = offset;
            final ArrayList<TLRPC.TL_fileHash> answer = new ArrayList<>();
            final CountDownLatch answered = new CountDownLatch(1);
            int token = ConnectionsManager.getInstance(currentAccount).sendRequest(req, (response, error) -> {
                if (response instanceof Vector) {
                    synchronized (answer) {
                        for (Object object : ((Vector<?>) response).objects) {
                            if (object instanceof TLRPC.TL_fileHash) {
                                answer.add((TLRPC.TL_fileHash) object);
                            }
                        }
                    }
                }
                answered.countDown();
            }, null, null, 0, datacenterId, ConnectionsManager.ConnectionTypeGeneric, true);
            boolean inTime;
            try {
                inTime = answered.await(HASHES_TIMEOUT, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                inTime = false;
            }
            if (!inTime) {
                ConnectionsManager.getInstance(currentAccount).cancelRequest(token, false);
                throw new Failure("hashes", ERROR_FALLBACK, false, false);
            }
            synchronized (answer) {
                return new ArrayList<>(answer);
            }
        }

        private void deliver(Part part) {
            final byte[] bytes = new byte[part.length];
            int skip = (int) (part.offset - part.first);
            for (int i = 0, at = 0; at < bytes.length; i++) {
                byte[] block = part.data[i];
                int from = i == 0 ? skip : 0;
                int n = Math.min(block.length - from, bytes.length - at);
                System.arraycopy(block, from, bytes, at, n);
                at += n;
            }
            part.data = null;
            Utilities.stageQueue.postRunnable(() -> {
                if (!take(part)) {
                    return;
                }
                TLRPC.TL_upload_file file = new TLRPC.TL_upload_file();
                file.type = new TLRPC.TL_storage_filePartial();
                file.networkType = ApplicationLoader.getCurrentNetworkType();
                try {
                    file.bytes = new NativeByteBuffer(bytes.length);
                } catch (Exception e) {
                    FileLog.e(e);
                }
                if (file.bytes == null || file.bytes.buffer == null) {
                    part.delegate.run(null, error(ERROR_FALLBACK));
                    return;
                }
                file.bytes.buffer.put(bytes);
                file.bytes.buffer.position(0);
                part.delegate.run(file, null);
                file.freeResources();
            });
        }

        private void fail(Part part, String text) {
            Utilities.stageQueue.postRunnable(() -> {
                if (take(part)) {
                    part.delegate.run(null, error(text));
                }
            });
        }

        private synchronized boolean take(Part part) {
            return !closed && parts.remove(part.token) == part;
        }
    }
}
"""

CDN_HTTPS_EDITS = (
    # A part of the CDN remembers the download it was asked from.
    (FILE_LOAD,
     "        public boolean cancelling, cancelled;\n        public Runnable whenCancelled;\n    }\n",
     "        public boolean cancelling, cancelled;\n        public Runnable whenCancelled;\n"
     "        // pluma: the HTTPS CDN download the part was asked from; null for a request of tgnet.\n"
     "        public PlumaCdnHttps.Download httpsCall;\n    }\n"),
    (FILE_LOAD,
     "    private boolean requestingCdnOffsets;\n",
     "    private boolean requestingCdnOffsets;\n"
     "    // pluma: the HTTPS CDN of the server: the open download, whether this download takes the\n"
     "    // rest from the server, and how many new URLs it asked for.\n"
     "    private PlumaCdnHttps.Download cdnHttps;\n"
     "    private boolean cdnHttpsDisabled;\n"
     "    private int cdnHttpsRefreshes;\n"),
    (FILE_LOAD,
     "            if (isCdn) {\n                TLRPC.TL_upload_getCdnFile req = new TLRPC.TL_upload_getCdnFile();\n",
     "            if (cdnHttps != null) {\n"
     "                request = null; // pluma: the part comes from the HTTPS CDN\n"
     "            } else if (isCdn) {\n                TLRPC.TL_upload_getCdnFile req = new TLRPC.TL_upload_getCdnFile();\n"),
    (FILE_LOAD,
     "                    req.cdn_supported = true;\n",
     "                    req.cdn_supported = !cdnHttpsDisabled && PlumaCdnHttps.isAllowed(); // pluma: HTTPS CDN\n"),
    (FILE_LOAD,
     "            final int requestToken = requestInfo.requestToken = ConnectionsManager.getInstance(currentAccount)"
     ".sendRequestSync(request, (response, error) -> {\n",
     "            // pluma: one callback for a part of tgnet and a part of the HTTPS CDN.\n"
     "            final org.telegram.tgnet.RequestDelegate onPart = (response, error) -> {\n"),
    (FILE_LOAD,
     "                    if (error.code == -2000) {\n",
     "                    if (requestInfo.httpsCall != null) {\n"
     "                        // pluma: the HTTPS CDN failed the part: a new URL, or the rest from the server.\n"
     "                        plumaHttpsFailed(requestInfo, error, connectionType);\n"
     "                        return;\n"
     "                    }\n"
     "                    if (error.code == -2000) {\n"),
    (FILE_LOAD,
     "                if (response instanceof TLRPC.TL_upload_fileCdnRedirect) {\n"
     "                    TLRPC.TL_upload_fileCdnRedirect res = (TLRPC.TL_upload_fileCdnRedirect) response;\n",
     "                if (response instanceof TLRPC.TL_upload_fileCdnRedirect) {\n"
     "                    TLRPC.TL_upload_fileCdnRedirect res = (TLRPC.TL_upload_fileCdnRedirect) response;\n"
     "                    if (PlumaCdnHttps.isPlumaToken(res.file_token)) {\n"
     "                        // pluma: the server's HTTPS CDN; nothing connects to res.dc_id.\n"
     "                        plumaHttpsRedirect(res, requestInfo, connectionType);\n"
     "                        return;\n"
     "                    }\n"),
    (FILE_LOAD,
     "            }, null, null, flags, datacenterId, connectionType, isLast);\n",
     "            };\n"
     "            final int requestToken;\n"
     "            if (cdnHttps != null) {\n"
     "                requestInfo.httpsCall = cdnHttps;\n"
     "                requestToken = requestInfo.requestToken = cdnHttps.fetch(requestInfo.offset, requestInfo.chunkSize, onPart);\n"
     "            } else {\n"
     "                requestToken = requestInfo.requestToken = ConnectionsManager.getInstance(currentAccount)"
     ".sendRequestSync(request, onPart, null, null, flags, datacenterId, connectionType, isLast);\n"
     "            }\n"),
    # A part of the CDN is no request of tgnet: it is cancelled in PlumaCdnHttps, and it holds
    # up no tgnet connection that would need a reconnect.
    (FILE_LOAD,
     "                            ConnectionsManager.getInstance(currentAccount).cancelRequest(priorityRequestInfo.requestToken, true);\n",
     "                            plumaCancelRequest(priorityRequestInfo, null);\n"),
    (FILE_LOAD,
     "                        ConnectionsManager.getInstance(currentAccount).cancelRequest(requestInfo.requestToken, true);\n",
     "                        plumaCancelRequest(requestInfo, null);\n"),
    (FILE_LOAD,
     "                        ConnectionsManager.getInstance(currentAccount).cancelRequest(requestInfo.requestToken, true, () -> {\n",
     "                        plumaCancelRequest(requestInfo, () -> {\n"),
    (FILE_LOAD,
     "                    int index = requestInfo.connectionType >>> 16;\n"
     "                    waitingDownloadSize[index] += requestInfo.chunkSize;\n",
     "                    if (requestInfo.httpsCall == null) { // pluma: an HTTPS CDN part holds up no connection\n"
     "                        int index = requestInfo.connectionType >>> 16;\n"
     "                        waitingDownloadSize[index] += requestInfo.chunkSize;\n"
     "                    }\n"),
    (FILE_LOAD,
     "                    ConnectionsManager.getInstance(currentAccount).cancelRequest(info.requestToken, true, () -> {\n",
     "                    plumaCancelRequest(info, () -> {\n"),
    (FILE_LOAD,
     "                    ConnectionsManager.getInstance(currentAccount).cancelRequest(info.requestToken, true);\n",
     "                    plumaCancelRequest(info, null);\n"),
    (FILE_LOAD,
     "                if (!DownloadSpeedEstimator.isFast()) {\n",
     "                if (info.httpsCall == null && !DownloadSpeedEstimator.isFast()) { // pluma: not for an HTTPS CDN part\n"),
    (FILE_LOAD,
     "    private void cleanup() {\n",
     "    private void cleanup() {\n"
     "        plumaHttpsClose(); // pluma: the HTTPS CDN download ends with the operation\n"),
    (FILE_LOAD,
     "    protected void startDownloadRequest(int useConnectionType) {\n",
     "    // pluma: a \"PLH1\" redirect of the server's HTTPS CDN (ADR 0071 of the server repository). A token\n"
     "    // the client cannot use makes this download take the rest from the server without cdn_supported.\n"
     "    private void plumaHttpsRedirect(TLRPC.TL_upload_fileCdnRedirect res, RequestInfo requestInfo, int connectionType) {\n"
     "        PlumaCdnHttps.Download download = cdnHttpsDisabled ? null\n"
     "                : PlumaCdnHttps.open(currentAccount, datacenterId, res, totalBytesCount);\n"
     "        plumaHttpsClose();\n"
     "        if (download == null) {\n"
     "            cdnHttpsDisabled = true;\n"
     "        }\n"
     "        cdnHttps = download;\n"
     "        isCdn = false;\n"
     "        clearOperation(requestInfo, false, false);\n"
     "        startDownloadRequest(connectionType);\n"
     "    }\n"
     "\n"
     "    // pluma: 403 and 410 ask the server for a new URL, as FILE_TOKEN_INVALID does, at most\n"
     "    // PlumaCdnHttps.MAX_REFRESHES times; any other failure takes the rest from the server,\n"
     "    // keeping the parts already written.\n"
     "    private void plumaHttpsFailed(RequestInfo requestInfo, TLRPC.TL_error error, int connectionType) {\n"
     "        if (PlumaCdnHttps.ERROR_REFRESH.equals(error.text) && cdnHttpsRefreshes < PlumaCdnHttps.MAX_REFRESHES) {\n"
     "            cdnHttpsRefreshes++;\n"
     "        } else {\n"
     "            cdnHttpsDisabled = true;\n"
     "        }\n"
     "        plumaHttpsClose();\n"
     "        clearOperation(requestInfo, false, false);\n"
     "        startDownloadRequest(connectionType);\n"
     "    }\n"
     "\n"
     "    private void plumaHttpsClose() {\n"
     "        PlumaCdnHttps.Download download = cdnHttps;\n"
     "        cdnHttps = null;\n"
     "        if (download != null) {\n"
     "            download.close();\n"
     "        }\n"
     "    }\n"
     "\n"
     "    // pluma: a part of the HTTPS CDN has a negative token unknown to tgnet; it is dropped by its\n"
     "    // download, and the callback runs on the stage queue as tgnet's does.\n"
     "    private void plumaCancelRequest(RequestInfo info, Runnable onCancelled) {\n"
     "        if (info.httpsCall == null) {\n"
     "            ConnectionsManager.getInstance(currentAccount).cancelRequest(info.requestToken, true, onCancelled);\n"
     "            return;\n"
     "        }\n"
     "        info.httpsCall.cancel(info.requestToken);\n"
     "        if (onCancelled != null) {\n"
     "            Utilities.stageQueue.postRunnable(onCancelled);\n"
     "        }\n"
     "    }\n"
     "\n"
     "    protected void startDownloadRequest(int useConnectionType) {\n"),
    # The client tells the server it takes the CDN over HTTPS (initConnection params, next to tz_offset).
    (CONNECTIONS_CPP,
     '            objectValue->key = "tz_offset";\n'
     "            objectValue->value = std::unique_ptr<JSONValue>(jsonNumber);\n",
     '            objectValue->key = "tz_offset";\n'
     "            objectValue->value = std::unique_ptr<JSONValue>(jsonNumber);\n"
     "\n"
     "            // pluma: large files from the server's HTTPS CDN (PlumaCdnHttps.java).\n"
     "            objectValue = new TL_jsonObjectValue();\n"
     "            jsonObject->value.push_back(std::unique_ptr<TL_jsonObjectValue>(objectValue));\n"
     "            jsonNumber = new TL_jsonNumber();\n"
     "            jsonNumber->value = 1;\n"
     '            objectValue->key = "pluma_cdn";\n'
     "            objectValue->value = std::unique_ptr<JSONValue>(jsonNumber);\n"),
)

# What PlumaCdnHttps relies on in upstream: whether a proxy is on (any kind
# takes the CDN off on Android), the network type of the statistics, the
# native buffer of upload.file, and the cancel of tgnet with its callback.
CDN_HTTPS_USES = (
    (f"{JAVA}/messenger/SharedConfig.java", "    public static boolean isProxyEnabled() {\n"),
    (f"{JAVA}/messenger/ApplicationLoader.java", "    public static int getCurrentNetworkType() {\n"),
    (f"{JAVA}/tgnet/NativeByteBuffer.java", "    public NativeByteBuffer(int size) throws Exception {\n"),
    (f"{JAVA}/tgnet/ConnectionsManager.java",
     "    public void cancelRequest(int token, boolean notifyServer, Runnable onCancelled) {\n"),
)

# What upstream's tgnet CDN path keeps doing for a "PLH1" download if an edit is
# lost; none of it may be reached: no request goes to upload.getCdnFile with
# such a token, none is cancelled in tgnet by its negative token.
CDN_HTTPS_GONE = (
    "req.cdn_supported = true;",
    "cancelRequest(priorityRequestInfo.requestToken",
    "cancelRequest(requestInfo.requestToken",
    "cancelRequest(info.requestToken, true);",
    "cancelRequest(info.requestToken, true, () ->",
)


def cdn_https_java(c):
    """PlumaCdnHttps.java for the build's target: http:// to the stand in a development build only."""
    if c.target == "server":
        return CDN_HTTPS_JAVA
    hosts = ", ".join(f'"{h}"' for h in c.dev_http_hosts)
    return CDN_HTTPS_JAVA.replace(CDN_HTTPS_DEV_HOSTS_LINE,
                                  f"    private static final String[] DEV_HTTP_HOSTS = {{{hosts}}};\n")


def cdn_https(tree, c):
    # Every anchor first, and no PlumaCdnHttps yet: several edits keep their anchor,
    # and a tree that is already patched must fail before anything is written twice.
    if (tree.root / CDN_HTTPS_FILE).exists():
        raise PatchError(f"{CDN_HTTPS_FILE}: the file is already there")
    for rel, old, _ in CDN_HTTPS_EDITS:
        tree.expect(rel, old)
    for rel, text in CDN_HTTPS_USES:
        tree.expect(rel, text)
    for rel, old, new in CDN_HTTPS_EDITS:
        tree.replace(rel, old, new)
    tree.write(CDN_HTTPS_FILE, cdn_https_java(c))


def verify_cdn_https(tree, c):
    for rel, old, new in CDN_HTTPS_EDITS:
        text = tree.read(rel)
        if text.count(new) != 1 or text.count(old) != new.count(old):
            changed = next(line for line in new.splitlines() if line not in old.splitlines())
            raise PatchError(f"{rel}: the HTTPS CDN edit {changed.strip()!r} is not there")
    text = tree.read(FILE_LOAD)
    for gone in CDN_HTTPS_GONE:
        if gone in text:
            raise PatchError(f"{FILE_LOAD}: upstream's {gone!r} is still there")
    if text.count("PlumaCdnHttps.isPlumaToken(") != 1 or text.count(".fetch(requestInfo.offset,") != 1:
        raise PatchError(f"{FILE_LOAD}: the HTTPS CDN is not where the parts are asked for")
    for rel, used in CDN_HTTPS_USES:
        tree.expect(rel, used)
    if tree.read(CONNECTIONS_CPP).count('"pluma_cdn"') != 1:
        raise PatchError(f"{CONNECTIONS_CPP}: initConnection does not say pluma_cdn once")
    java = tree.root / CDN_HTTPS_FILE
    if not java.is_file() or java.read_text(encoding="utf-8") != cdn_https_java(c):
        raise PatchError(f"{CDN_HTTPS_FILE}: not the HTTPS CDN of a {c.target} build")
    # A server build reaches the CDN over https:// only.
    if c.target == "server" and CDN_HTTPS_DEV_HOSTS_LINE not in java.read_text(encoding="utf-8"):
        raise PatchError(f"{CDN_HTTPS_FILE}: a server build takes http://")


# --- Maps on MapLibre (task 112 of the server repository) -----------------------
# The location screens (the attachment, live locations, a group's place, a
# business address, a story's place) draw their map through IMapsProvider
# (messenger/IMapsProvider.java), made by ApplicationLoader.onCreateMapsProvider
# (ApplicationLoader 105-107). Upstream's GoogleMapsProvider takes Google's tiles
# with Telegram's key from the manifests, which do not serve another package: the
# map stays empty. PlumaMapsProvider draws it with MapLibre Native from the
# vector tiles, styles, fonts and icons of the Pluma server, whose address the
# server gives in the app config (pluma_maps_url, pluma_maps_styles; kept by
# AppGlobalConfig). So:
# - onCreateMapsProvider makes PlumaMapsProvider; GoogleMapsProvider and the key
#   of the five manifests are gone, and no source names com.google.android.gms.maps
#   (play-services-wallet 19.1.0 still pulls play-services-maps into the APK,
#   unused);
# - the library depends on MapLibre's OpenGL ES build, android-sdk-opengl 13.7.1:
#   android-sdk 13.7.1 is the Vulkan build, which requires Vulkan 1.0
#   (uses-feature android.hardware.vulkan.version, required, in its manifest);
#   Gradle checks the MapLibre artifacts against their SHA-256
#   (gradle/verification-metadata.xml, Maven Central's .sha256 files, recomputed);
# - R8 keeps MapLibre's classes whole: libmaplibre.so finds classes, fields and
#   methods by name, and the release build runs R8 in full mode;
# - the satellite and hybrid choice is hidden (ChatAttachAlertLocationLayout 330-357,
#   LocationActivity 451-455): the server has no imagery;
# - AndroidUtilities.isMapsInstalled (1864-1886) is left as it is: the provider
#   names the app itself as the map app, always installed.
# Lines are those of upstream 13.2.1.
MAPS_PROVIDER_FILE = f"{JAVA}/messenger/PlumaMapsProvider.java"
GOOGLE_MAPS_PROVIDER = f"{JAVA}/messenger/GoogleMapsProvider.java"
APP_GLOBAL_CONFIG = f"{JAVA}/messenger/AppGlobalConfig.java"
ATTACH_LOCATION = f"{JAVA}/ui/Components/ChatAttachAlertLocationLayout.java"
LOCATION_ACTIVITY = f"{JAVA}/ui/LocationActivity.java"
LIBRARY_GRADLE = "TMessagesProj/build.gradle"
PROGUARD_RULES = "TMessagesProj/proguard-rules.pro"
VERIFICATION_METADATA = "gradle/verification-metadata.xml"
GOOGLE_MAPS_DEPENDENCY = "    implementation 'com.google.android.gms:play-services-maps:18.1.0'\n"
MAPLIBRE_DEPENDENCY = "    implementation 'org.maplibre.gl:android-sdk-opengl:13.7.1'\n"
# The manifests that carry Telegram's key for Google's maps, the line and the empty line after it.
MAPS_KEY_MANIFESTS = (
    "TMessagesProj/config/debug/AndroidManifest.xml",
    "TMessagesProj/config/debug/AndroidManifest_SDK23.xml",
    "TMessagesProj/config/release/AndroidManifest.xml",
    "TMessagesProj/config/release/AndroidManifest_SDK23.xml",
    "TMessagesProj/config/release/AndroidManifest_standalone.xml",
)
MAPS_KEY_NAME = "com.google.android.maps.v2.API_KEY"
MAPS_KEY_LINE = re.compile(r'        <meta-data android:name="com\.google\.android\.maps\.v2\.API_KEY" android:value="[^"\n]*" />\n\n')
GOOGLE_MAPS_PACKAGE = "com.google.android.gms.maps"
MAPS_EDITS = (
    (APPLICATION_LOADER,
     "    protected IMapsProvider onCreateMapsProvider() {\n"
     "        return new GoogleMapsProvider();\n"
     "    }\n",
     "    protected IMapsProvider onCreateMapsProvider() {\n"
     "        return new PlumaMapsProvider(); // pluma: MapLibre with the server's maps (task 112)\n"
     "    }\n"),
    (APP_GLOBAL_CONFIG,
     '    public final ConfigBoolean widgetsDisabled = ofBoolean("widgets_disabled", false);\n',
     '    public final ConfigBoolean widgetsDisabled = ofBoolean("widgets_disabled", false);\n'
     "\n"
     "    // pluma: the server's maps (PlumaMapsProvider): https://<host>/<key> and the label languages it has styles for.\n"
     '    public final ConfigString plumaMapsUrl = ofString("pluma_maps_url", null);\n'
     '    public final ConfigStringSet plumaMapsStyles = ofStringSet("pluma_maps_styles", Collections.emptySet());\n'),
    (ATTACH_LOCATION,
     "        mapViewClip.addView(mapTypeButton, LayoutHelper.createFrame(40, 40, Gravity.RIGHT | Gravity.TOP, 0, 12, 12, 0));\n",
     "        mapViewClip.addView(mapTypeButton, LayoutHelper.createFrame(40, 40, Gravity.RIGHT | Gravity.TOP, 0, 12, 12, 0));\n"
     "        mapTypeButton.setVisibility(GONE); // pluma: one map type, the server has no satellite imagery\n"),
    (LOCATION_ACTIVITY,
     "        mapTypeButton.setContentDescription(getString(R.string.AccDescrMoreOptions));\n",
     "        mapTypeButton.setContentDescription(getString(R.string.AccDescrMoreOptions));\n"
     "        mapTypeButton.setVisibility(View.GONE); // pluma: one map type, the server has no satellite imagery\n"),
    (LIBRARY_GRADLE,
     GOOGLE_MAPS_DEPENDENCY,
     "    // pluma: maps on MapLibre Native, its OpenGL ES build (task 112 of the server repository).\n"
     + MAPLIBRE_DEPENDENCY),
    (PROGUARD_RULES,
     "# Use -keep to explicitly keep any other classes shrinking would remove\n",
     "# pluma: MapLibre Native (PlumaMapsProvider). libmaplibre.so finds its classes, fields and methods by\n"
     "# name across the SDK; R8's full mode would drop or rename what the library's own rules leave out,\n"
     "# which fails only on a device.\n"
     "-keep class org.maplibre.android.** { *; }\n"
     "\n"
     "# Use -keep to explicitly keep any other classes shrinking would remove\n"),
)
# What PlumaMapsProvider relies on in upstream: the interface it implements (with
# the snapshot method a provider without a GL view need not have), the night
# style the screens ask for, the account's app config and the session's language.
MAPS_USES = (
    (f"{JAVA}/messenger/IMapsProvider.java", "        default GLSurfaceView getGlSurfaceView() {\n"),
    (f"{JAVA}/messenger/IMapsProvider.java", "    IMapStyleOptions loadRawResourceStyle(Context context, int resId);\n"),
    (ATTACH_LOCATION,
     "                                IMapsProvider.IMapStyleOptions style = ApplicationLoader.getMapsProvider()"
     ".loadRawResourceStyle(ApplicationLoader.applicationContext, R.raw.mapstyle_night);\n"),
    (LOCATION_ACTIVITY, "            return R.raw.mapstyle_night;\n        }\n        return 0;\n"),
    (MESSAGES_CONTROLLER, "    public final AppGlobalConfig config = new AppGlobalConfig();\n"),
    (APP_GLOBAL_CONFIG, "    private ConfigStringSet ofStringSet(String name, Set<String> defaultValue) {\n"),
    (f"{JAVA}/messenger/LocaleController.java", "    public static String getLocaleStringIso639() {\n"),
    (f"{JAVA}/messenger/AndroidUtilities.java",
     "        String pkg = ApplicationLoader.getMapsProvider().getMapsAppPackageName();\n"
     "        try {\n"
     "            ApplicationLoader.applicationContext.getPackageManager().getApplicationInfo(pkg, 0);\n"
     "            return true;\n"),
)

MAPS_JAVA = r"""package org.telegram.messenger;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Color;
import android.graphics.Point;
import android.graphics.PointF;
import android.location.Location;
import android.net.Uri;
import android.os.Bundle;
import android.os.Looper;
import android.text.TextUtils;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;

import androidx.core.util.Consumer;

import org.maplibre.android.MapLibre;
import org.maplibre.android.camera.CameraUpdate;
import org.maplibre.android.camera.CameraUpdateFactory;
import org.maplibre.android.geometry.LatLngBounds;
import org.maplibre.android.location.LocationComponent;
import org.maplibre.android.location.LocationComponentActivationOptions;
import org.maplibre.android.location.engine.LocationEngine;
import org.maplibre.android.location.engine.LocationEngineCallback;
import org.maplibre.android.location.engine.LocationEngineDefault;
import org.maplibre.android.location.engine.LocationEngineRequest;
import org.maplibre.android.location.engine.LocationEngineResult;
import org.maplibre.android.location.modes.CameraMode;
import org.maplibre.android.location.modes.RenderMode;
import org.maplibre.android.log.Logger;
import org.maplibre.android.maps.MapLibreMap;
import org.maplibre.android.maps.MapLibreMapOptions;
import org.maplibre.android.maps.MapView;
import org.maplibre.android.maps.Style;
import org.maplibre.android.maps.UiSettings;
import org.maplibre.android.style.layers.FillLayer;
import org.maplibre.android.style.layers.LineLayer;
import org.maplibre.android.style.layers.Property;
import org.maplibre.android.style.layers.PropertyFactory;
import org.maplibre.android.style.layers.PropertyValue;
import org.maplibre.android.style.layers.SymbolLayer;
import org.maplibre.android.style.sources.GeoJsonSource;
import org.maplibre.geojson.Polygon;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

// pluma: maps on MapLibre Native with the vector tiles, styles, fonts and icons of the Pluma server
// (task 112 of the server repository). The server gives their address in the app config: pluma_maps_url,
// https://<host>/<key>, and the label languages it has styles for in pluma_maps_styles; a style is
// <url>/styles/<language>[-dark]/style.json. Without the address no map is made: the location screens
// work without one, as with no map service on the phone.
public class PlumaMapsProvider implements IMapsProvider {

    // The screens ask for getMaxZoomLevel() - 4 (a street) and getMinZoomLevel() + 4 (a country), as with
    // zoom levels of 256-pixel tiles; MapLibre's levels are of 512-pixel tiles, one lower for the same scale.
    private static final double MIN_ZOOM = 1;
    private static final double MAX_ZOOM = 20;
    // The languages that see Russian labels when the server has no style of their own: the bff's rule
    // (pkg/staticmap/params.go of the server repository, StyleFor).
    private static final Set<String> RUSSIAN_LABELS = new HashSet<>(Arrays.asList("be", "kk", "ky", "tg", "uz", "hy", "az"));
    private static final Pattern STYLE_ID = Pattern.compile("[a-z0-9]+(-[a-z0-9]+)*");
    private static final double EARTH_RADIUS = 6371009;
    private static final int CIRCLE_POINTS = 72;
    private static final long LOCATION_INTERVAL = 1000;

    private static boolean initialized;

    @Override
    public void initializeMaps(Context context) {
        initialize(context);
    }

    private static void initialize(Context context) {
        if (initialized) {
            return;
        }
        MapLibre.getInstance(context.getApplicationContext());
        // The addresses of tiles and styles carry the server's key and where the user looks: nothing of the
        // map engine goes to the system log.
        Logger.setVerbosity(Logger.NONE);
        initialized = true;
    }

    @Override
    public IMapView onCreateMapView(Context context) {
        String base = mapsUrl();
        String language = base == null ? null : styleLanguage(LocaleController.getLocaleStringIso639(), mapsStyles());
        if (base == null || language == null) {
            return new PlumaMapView(context, null);
        }
        initialize(context);
        return new PlumaMapView(context, base + "/styles/" + language);
    }

    // The address of the server's maps, or null: https only, a host, no query or fragment, no slash at the end.
    private static String mapsUrl() {
        String url = MessagesController.getInstance(UserConfig.selectedAccount).config.plumaMapsUrl.get();
        if (TextUtils.isEmpty(url) || !url.startsWith("https://") || url.endsWith("/")
                || url.indexOf('?') >= 0 || url.indexOf('#') >= 0) {
            return null;
        }
        Uri uri = Uri.parse(url);
        if (TextUtils.isEmpty(uri.getHost())) {
            return null;
        }
        return url;
    }

    private static Set<String> mapsStyles() {
        Set<String> styles = MessagesController.getInstance(UserConfig.selectedAccount).config.plumaMapsStyles.get();
        Set<String> out = new TreeSet<>();
        if (styles != null) {
            for (String style : styles) {
                if (style != null && STYLE_ID.matcher(style).matches()) {
                    out.add(style);
                }
            }
        }
        return out;
    }

    // The style of the interface language, as the bff picks one for a session's lang_code: the language's own
    // (by the full code, then by its base language), Russian for RUSSIAN_LABELS, otherwise English, otherwise
    // the first; null when the server names none.
    static String styleLanguage(String langCode, Set<String> styles) {
        if (styles.isEmpty()) {
            return null;
        }
        String code = langCode == null ? "" : langCode.toLowerCase(Locale.ROOT).replace('_', '-');
        int dash = code.indexOf('-');
        String base = dash < 0 ? code : code.substring(0, dash);
        if (!code.isEmpty() && styles.contains(code)) {
            return code;
        }
        if (!base.isEmpty() && styles.contains(base)) {
            return base;
        }
        if (RUSSIAN_LABELS.contains(base) && styles.contains("ru")) {
            return "ru";
        }
        if (styles.contains("en")) {
            return "en";
        }
        return new TreeSet<>(styles).first();
    }

    @Override
    public IMarkerOptions onCreateMarkerOptions() {
        return new PlumaMarkerOptions();
    }

    @Override
    public ICircleOptions onCreateCircleOptions() {
        return new PlumaCircleOptions();
    }

    @Override
    public ILatLngBoundsBuilder onCreateLatLngBoundsBuilder() {
        return new PlumaLatLngBoundsBuilder();
    }

    @Override
    public ICameraUpdate newCameraUpdateLatLng(LatLng latLng) {
        return new PlumaCameraUpdate(CameraUpdateFactory.newLatLng(toMapLibre(latLng)), false);
    }

    @Override
    public ICameraUpdate newCameraUpdateLatLngZoom(LatLng latLng, float zoom) {
        return new PlumaCameraUpdate(CameraUpdateFactory.newLatLngZoom(toMapLibre(latLng), zoom), false);
    }

    @Override
    public ICameraUpdate newCameraUpdateLatLngBounds(ILatLngBounds bounds, int padding) {
        return new PlumaCameraUpdate(CameraUpdateFactory.newLatLngBounds(((PlumaLatLngBounds) bounds).bounds, padding), true);
    }

    // The screens ask for the night style by its resource; any other resource and setMapStyle(null) are the day style.
    @Override
    public IMapStyleOptions loadRawResourceStyle(Context context, int resId) {
        return new PlumaMapStyle(resId == R.raw.mapstyle_night);
    }

    // The map is in the app itself: the check before the location screens always finds it installed.
    @Override
    public String getMapsAppPackageName() {
        return ApplicationLoader.applicationContext.getPackageName();
    }

    @Override
    public int getInstallMapsString() {
        return R.string.InstallGoogleMaps;
    }

    private static org.maplibre.android.geometry.LatLng toMapLibre(LatLng latLng) {
        return new org.maplibre.android.geometry.LatLng(latLng.latitude, latLng.longitude);
    }

    private static LatLng fromMapLibre(org.maplibre.android.geometry.LatLng latLng) {
        return latLng == null ? new LatLng(0, 0) : new LatLng(latLng.getLatitude(), latLng.getLongitude());
    }

    private static org.maplibre.geojson.Point toPoint(LatLng latLng) {
        return org.maplibre.geojson.Point.fromLngLat(latLng.longitude, latLng.latitude);
    }

    // A circle of radius metres around center on the sphere, as a polygon.
    private static Polygon circlePolygon(LatLng center, double radius) {
        double lat = Math.toRadians(center.latitude);
        double lng = Math.toRadians(center.longitude);
        double d = radius / EARTH_RADIUS;
        List<org.maplibre.geojson.Point> ring = new ArrayList<>(CIRCLE_POINTS + 1);
        for (int i = 0; i < CIRCLE_POINTS; i++) {
            double bearing = 2 * Math.PI * i / CIRCLE_POINTS;
            double lat2 = Math.asin(Math.sin(lat) * Math.cos(d) + Math.cos(lat) * Math.sin(d) * Math.cos(bearing));
            double lng2 = lng + Math.atan2(Math.sin(bearing) * Math.sin(d) * Math.cos(lat), Math.cos(d) - Math.sin(lat) * Math.sin(lat2));
            ring.add(org.maplibre.geojson.Point.fromLngLat(Math.toDegrees(lng2), Math.toDegrees(lat2)));
        }
        ring.add(ring.get(0));
        return Polygon.fromLngLats(Collections.singletonList(ring));
    }

    // A bitmap shown pixel for pixel, as the screens draw them: MapLibre takes an image's scale from its density.
    private static Bitmap screenBitmap(Bitmap bitmap) {
        int dpi = ApplicationLoader.applicationContext.getResources().getDisplayMetrics().densityDpi;
        if (bitmap.getDensity() == dpi) {
            return bitmap;
        }
        Bitmap copy = bitmap.copy(Bitmap.Config.ARGB_8888, false);
        if (copy == null) {
            return bitmap;
        }
        copy.setDensity(dpi);
        return copy;
    }

    public final static class PlumaMapView implements IMapView {
        private final FrameLayout view;
        private final MapView mapView;
        private final String styleBase;

        private ITouchInterceptor dispatchInterceptor;
        private ITouchInterceptor interceptInterceptor;
        private Runnable onLayoutListener;

        private PlumaMap map;
        private boolean created;
        private boolean started;
        private boolean resumed;
        private boolean destroyed;

        private PlumaMapView(Context context, String styleBase) {
            this.styleBase = styleBase;
            view = new FrameLayout(context) {
                @Override
                public boolean dispatchTouchEvent(MotionEvent ev) {
                    if (dispatchInterceptor != null) {
                        return dispatchInterceptor.onInterceptTouchEvent(ev, super::dispatchTouchEvent);
                    }
                    return super.dispatchTouchEvent(ev);
                }

                @Override
                public boolean onInterceptTouchEvent(MotionEvent ev) {
                    if (interceptInterceptor != null) {
                        return interceptInterceptor.onInterceptTouchEvent(ev, super::onInterceptTouchEvent);
                    }
                    return super.onInterceptTouchEvent(ev);
                }

                @Override
                protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
                    super.onLayout(changed, left, top, right, bottom);
                    if (map != null) {
                        map.onLayout();
                    }
                    if (onLayoutListener != null) {
                        onLayoutListener.run();
                    }
                }
            };
            if (styleBase == null) {
                mapView = null;
                return;
            }
            // A texture, not a surface: the map moves, fades and is clipped with the sheets over it, and the
            // glass of the location screen draws it from its texture (LocationActivity, attachMapSurface).
            MapLibreMapOptions options = MapLibreMapOptions.createFromAttributes(context)
                    .textureMode(true)
                    .foregroundLoadColor(Color.TRANSPARENT)
                    .minZoomPreference(MIN_ZOOM)
                    .maxZoomPreference(MAX_ZOOM)
                    .compassEnabled(false)
                    .logoEnabled(false)
                    // The data is OpenStreetMap's: its attribution stays on the map (ODbL).
                    .attributionEnabled(true);
            mapView = new MapView(context, options);
            view.addView(mapView, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        }

        private String styleUrl(boolean dark) {
            return styleBase + (dark ? "-dark" : "") + "/style.json";
        }

        @Override
        public void setOnDispatchTouchEventInterceptor(ITouchInterceptor touchInterceptor) {
            dispatchInterceptor = touchInterceptor;
        }

        @Override
        public void setOnInterceptTouchEventInterceptor(ITouchInterceptor touchInterceptor) {
            interceptInterceptor = touchInterceptor;
        }

        @Override
        public void setOnLayoutListener(Runnable callback) {
            onLayoutListener = callback;
        }

        @Override
        public View getView() {
            return view;
        }

        // Without the server's maps the callback never comes, as with no map service: the screens keep no map.
        @Override
        public void getMapAsync(Consumer<IMap> callback) {
            if (mapView == null || destroyed) {
                return;
            }
            mapView.getMapAsync(maplibreMap -> {
                if (destroyed) {
                    return;
                }
                if (map == null) {
                    map = new PlumaMap(this, maplibreMap);
                }
                callback.accept(map);
                map.start();
            });
        }

        // The screens call onCreate once off the main thread to warm up the map service; MapLibre's views
        // are made on the main thread only, once.
        @Override
        public void onCreate(Bundle savedInstance) {
            if (mapView == null || created || destroyed || Looper.myLooper() != Looper.getMainLooper()) {
                return;
            }
            created = true;
            mapView.onCreate(savedInstance);
        }

        // MapLibre also has onStart and onStop, which the screens do not call: tiles load only between them.
        @Override
        public void onResume() {
            if (mapView == null || destroyed || resumed) {
                return;
            }
            if (!started) {
                started = true;
                mapView.onStart();
            }
            resumed = true;
            mapView.onResume();
            if (map != null) {
                map.onResume();
            }
        }

        @Override
        public void onPause() {
            if (mapView == null || destroyed) {
                return;
            }
            if (resumed) {
                resumed = false;
                if (map != null) {
                    map.onPause();
                }
                mapView.onPause();
            }
            if (started) {
                started = false;
                mapView.onStop();
            }
        }

        @Override
        public void onDestroy() {
            if (mapView == null || destroyed) {
                return;
            }
            onPause();
            destroyed = true;
            if (map != null) {
                map.onDestroy();
            }
            mapView.onDestroy();
        }

        @Override
        public void onLowMemory() {
            if (mapView != null && !destroyed) {
                mapView.onLowMemory();
            }
        }
    }

    public final static class PlumaMap implements IMap {
        private final PlumaMapView owner;
        private final MapLibreMap map;
        private final int[] attributionMargins;

        private boolean started;
        private boolean dark;
        private String styleUrl;
        private CameraUpdate pendingBounds;
        private Style style;
        private boolean rendered;
        private Runnable onMapLoaded;

        private final ArrayList<PlumaMarker> markers = new ArrayList<>();
        private final ArrayList<PlumaCircle> circles = new ArrayList<>();
        private int lastId;

        private Runnable onCameraIdle;
        private Runnable onCameraMove;
        private OnCameraMoveStartedListener onCameraMoveStarted;
        private OnMarkerClickListener onMarkerClick;

        private boolean myLocation;
        private boolean locationUpdates;
        private Consumer<Location> onMyLocationChange;
        private LocationEngine locationEngine;
        private final LocationEngineRequest locationRequest = new LocationEngineRequest.Builder(LOCATION_INTERVAL)
                .setPriority(LocationEngineRequest.PRIORITY_HIGH_ACCURACY)
                .build();
        private final LocationEngineCallback<LocationEngineResult> locationCallback = new LocationEngineCallback<LocationEngineResult>() {
            @Override
            public void onSuccess(LocationEngineResult result) {
                Location location = result == null ? null : result.getLastLocation();
                if (location != null && onMyLocationChange != null && locationUpdates) {
                    onMyLocationChange.accept(location);
                }
            }

            @Override
            public void onFailure(Exception exception) {
                FileLog.e(exception);
            }
        };

        private PlumaMap(PlumaMapView owner, MapLibreMap map) {
            this.owner = owner;
            this.map = map;
            UiSettings ui = map.getUiSettings();
            attributionMargins = new int[]{ui.getAttributionMarginLeft(), ui.getAttributionMarginTop(),
                    ui.getAttributionMarginRight(), ui.getAttributionMarginBottom()};
            map.addOnCameraIdleListener(() -> {
                if (onCameraIdle != null) {
                    onCameraIdle.run();
                }
            });
            map.addOnCameraMoveListener(() -> {
                if (onCameraMove != null) {
                    onCameraMove.run();
                }
            });
            // The reasons are matched by name: MapLibre numbers them differently.
            map.addOnCameraMoveStartedListener(reason -> {
                if (onCameraMoveStarted == null) {
                    return;
                }
                int outReason;
                switch (reason) {
                    default:
                    case MapLibreMap.OnCameraMoveStartedListener.REASON_API_GESTURE:
                        outReason = OnCameraMoveStartedListener.REASON_GESTURE;
                        break;
                    case MapLibreMap.OnCameraMoveStartedListener.REASON_API_ANIMATION:
                        outReason = OnCameraMoveStartedListener.REASON_API_ANIMATION;
                        break;
                    case MapLibreMap.OnCameraMoveStartedListener.REASON_DEVELOPER_ANIMATION:
                        outReason = OnCameraMoveStartedListener.REASON_DEVELOPER_ANIMATION;
                        break;
                }
                onCameraMoveStarted.onCameraMoveStarted(outReason);
            });
            map.addOnMapClickListener(this::onMapClick);
            owner.mapView.addOnDidFinishRenderingMapListener(fully -> {
                if (!fully || rendered || style == null) {
                    return;
                }
                rendered = true;
                if (onMapLoaded != null) {
                    onMapLoaded.run();
                }
            });
        }

        // After the screen's own setup in the callback of getMapAsync, so that a night style it sets there is
        // the first one loaded.
        private void start() {
            if (started) {
                return;
            }
            started = true;
            loadStyle();
        }

        private void loadStyle() {
            if (!started || owner.destroyed) {
                return;
            }
            String url = owner.styleUrl(dark);
            if (url.equals(styleUrl)) {
                return;
            }
            styleUrl = url;
            style = null;
            for (PlumaMarker marker : markers) {
                marker.attached = false;
            }
            for (PlumaCircle circle : circles) {
                circle.attached = false;
            }
            map.setStyle(new Style.Builder().fromUri(url), this::onStyleLoaded);
        }

        // A new style has none of the map's own sources, layers and images: they are added again, the circles
        // under the markers, each in the order it was added.
        private void onStyleLoaded(Style loaded) {
            if (owner.destroyed) {
                return;
            }
            style = loaded;
            for (PlumaCircle circle : circles) {
                circle.attach();
            }
            for (PlumaMarker marker : markers) {
                marker.attach();
            }
            updateMyLocation();
        }

        private boolean ready() {
            return style != null && style.isFullyLoaded() && !owner.destroyed;
        }

        private String nextId(String kind) {
            return "pluma-" + kind + "-" + (++lastId);
        }

        private void onResume() {
            updateLocationUpdates();
        }

        private void onPause() {
            updateLocationUpdates();
        }

        private void onDestroy() {
            myLocation = false;
            updateLocationUpdates();
        }

        private boolean onMapClick(org.maplibre.android.geometry.LatLng point) {
            if (onMarkerClick == null || !ready()) {
                return false;
            }
            PointF screen = map.getProjection().toScreenLocation(point);
            for (int i = markers.size() - 1; i >= 0; i--) {
                PlumaMarker marker = markers.get(i);
                if (marker.attached && !map.queryRenderedFeatures(screen, marker.id).isEmpty()) {
                    return onMarkerClick.onClick(marker);
                }
            }
            return false;
        }

        // Satellite and hybrid maps need imagery the server does not have: always the map.
        @Override
        public void setMapType(int mapType) {
        }

        @Override
        public float getMaxZoomLevel() {
            return (float) map.getMaxZoomLevel();
        }

        @Override
        public float getMinZoomLevel() {
            return (float) map.getMinZoomLevel();
        }

        @Override
        public void setMyLocationEnabled(boolean enabled) {
            myLocation = enabled;
            updateMyLocation();
        }

        private static boolean hasLocationPermission(Context context) {
            return context.checkSelfPermission(android.Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
                    || context.checkSelfPermission(android.Manifest.permission.ACCESS_COARSE_LOCATION) == PackageManager.PERMISSION_GRANTED;
        }

        // The location dot and its updates come from the system's location service, only with the permission;
        // without it the map shows no location and nothing is asked.
        @SuppressLint("MissingPermission")
        private void updateMyLocation() {
            if (!ready()) {
                updateLocationUpdates();
                return;
            }
            Context context = owner.view.getContext();
            LocationComponent component = map.getLocationComponent();
            boolean show = myLocation && hasLocationPermission(context);
            try {
                if (show && !component.isLocationComponentActivated()) {
                    if (locationEngine == null) {
                        locationEngine = LocationEngineDefault.INSTANCE.getDefaultLocationEngine(context);
                    }
                    component.activateLocationComponent(LocationComponentActivationOptions.builder(context, style)
                            .locationEngine(locationEngine)
                            .locationEngineRequest(locationRequest)
                            .build());
                }
                if (component.isLocationComponentActivated()) {
                    component.setLocationComponentEnabled(show);
                    if (show) {
                        component.setCameraMode(CameraMode.NONE);
                        component.setRenderMode(RenderMode.NORMAL);
                    }
                }
            } catch (SecurityException e) {
                FileLog.e(e);
            }
            updateLocationUpdates();
        }

        // The screens' own listener gets the updates while the map is on screen.
        @SuppressLint("MissingPermission")
        private void updateLocationUpdates() {
            boolean want = myLocation && onMyLocationChange != null && owner.resumed && !owner.destroyed
                    && locationEngine != null && hasLocationPermission(owner.view.getContext());
            if (want == locationUpdates) {
                return;
            }
            locationUpdates = want;
            if (want) {
                try {
                    // The last known location first, as the screens place their marker by the first one.
                    locationEngine.getLastLocation(locationCallback);
                    locationEngine.requestLocationUpdates(locationRequest, locationCallback, Looper.getMainLooper());
                } catch (SecurityException e) {
                    locationUpdates = false;
                    FileLog.e(e);
                }
            } else {
                locationEngine.removeLocationUpdates(locationCallback);
            }
        }

        @Override
        public IUISettings getUiSettings() {
            return new PlumaUISettings(map.getUiSettings());
        }

        @Override
        public void setOnCameraMoveStartedListener(OnCameraMoveStartedListener onCameraMoveStartedListener) {
            onCameraMoveStarted = onCameraMoveStartedListener;
        }

        @Override
        public void setOnCameraIdleListener(Runnable callback) {
            onCameraIdle = callback;
        }

        @Override
        public void setOnCameraMoveListener(Runnable callback) {
            onCameraMove = callback;
        }

        @Override
        public CameraPosition getCameraPosition() {
            org.maplibre.android.camera.CameraPosition position = map.getCameraPosition();
            return new CameraPosition(fromMapLibre(position.target), (float) position.zoom);
        }

        // Called once the map has drawn its first full frame of the style.
        @Override
        public void setOnMapLoadedCallback(Runnable callback) {
            onMapLoaded = callback;
            if (rendered && callback != null) {
                callback.run();
            }
        }

        @Override
        public IProjection getProjection() {
            return latLng -> {
                PointF point = map.getProjection().toScreenLocation(toMapLibre(latLng));
                return new Point(Math.round(point.x), Math.round(point.y));
            };
        }

        // The padding moves the camera's centre, not the map: the point under the new centre becomes the
        // target, as the screens expect (ChatAttachAlertLocationLayout, applyMapSpace). The attribution keeps
        // clear of the padding.
        @Override
        public void setPadding(int left, int top, int right, int bottom) {
            View view = owner.mapView;
            if (view.getWidth() > 0 && view.getHeight() > 0) {
                PointF center = new PointF((left + view.getWidth() - right) / 2f, (top + view.getHeight() - bottom) / 2f);
                org.maplibre.android.geometry.LatLng target = map.getProjection().fromScreenLocation(center);
                map.moveCamera(CameraUpdateFactory.newLatLngPadding(target, left, top, right, bottom));
            } else {
                map.moveCamera(CameraUpdateFactory.paddingTo(left, top, right, bottom));
            }
            map.getUiSettings().setAttributionMargins(attributionMargins[0] + left, attributionMargins[1] + top,
                    attributionMargins[2] + right, attributionMargins[3] + bottom);
        }

        @Override
        public void setMapStyle(IMapStyleOptions style) {
            boolean night = style instanceof PlumaMapStyle && ((PlumaMapStyle) style).dark;
            if (night == dark) {
                return;
            }
            dark = night;
            loadStyle();
        }

        @Override
        public IMarker addMarker(IMarkerOptions markerOptions) {
            PlumaMarker marker = new PlumaMarker(nextId("marker"), (PlumaMarkerOptions) markerOptions);
            markers.add(marker);
            marker.attach();
            return marker;
        }

        @Override
        public ICircle addCircle(ICircleOptions circleOptions) {
            PlumaCircle circle = new PlumaCircle(nextId("circle"), (PlumaCircleOptions) circleOptions);
            circles.add(circle);
            circle.attach();
            return circle;
        }

        @Override
        public void setOnMyLocationChangeListener(Consumer<Location> callback) {
            onMyLocationChange = callback;
            updateLocationUpdates();
        }

        @Override
        public void setOnMarkerClickListener(OnMarkerClickListener markerClickListener) {
            onMarkerClick = markerClickListener;
        }

        @Override
        public void animateCamera(ICameraUpdate update) {
            if (!deferred(update, null)) {
                map.animateCamera(((PlumaCameraUpdate) update).update);
            }
        }

        @Override
        public void animateCamera(ICameraUpdate update, ICancelableCallback callback) {
            if (!deferred(update, callback)) {
                map.animateCamera(((PlumaCameraUpdate) update).update, cancelable(callback));
            }
        }

        @Override
        public void animateCamera(ICameraUpdate update, int duration, ICancelableCallback callback) {
            if (!deferred(update, callback)) {
                map.animateCamera(((PlumaCameraUpdate) update).update, duration, cancelable(callback));
            }
        }

        @Override
        public void moveCamera(ICameraUpdate update) {
            if (!deferred(update, null)) {
                map.moveCamera(((PlumaCameraUpdate) update).update);
            }
        }

        // Bounds are fitted to the map's size. Before the map is laid out they would be fitted to nothing, and
        // the screens move to them as soon as they have their markers (LocationActivity 2518-2524), so the
        // camera keeps them and moves there at the first layout with a size; a later camera move replaces them.
        // An animation put off this way is cancelled for its callback.
        private boolean deferred(ICameraUpdate update, ICancelableCallback callback) {
            PlumaCameraUpdate camera = (PlumaCameraUpdate) update;
            View view = owner.mapView;
            if (camera.bounds && (view.getWidth() == 0 || view.getHeight() == 0)) {
                pendingBounds = camera.update;
                if (callback != null) {
                    callback.onCancel();
                }
                return true;
            }
            pendingBounds = null;
            return false;
        }

        private void onLayout() {
            View view = owner.mapView;
            if (pendingBounds != null && view.getWidth() > 0 && view.getHeight() > 0 && !owner.destroyed) {
                CameraUpdate update = pendingBounds;
                pendingBounds = null;
                map.moveCamera(update);
            }
        }

        private static MapLibreMap.CancelableCallback cancelable(ICancelableCallback callback) {
            return callback == null ? null : new MapLibreMap.CancelableCallback() {
                @Override
                public void onCancel() {
                    callback.onCancel();
                }

                @Override
                public void onFinish() {
                    callback.onFinish();
                }
            };
        }

        // A marker is a source with its point and a symbol layer of its own, so that it is drawn over the
        // markers added before it; its icon is an image of the style under the same id.
        public final class PlumaMarker implements IMarker {
            private final String id;
            private Object tag;
            private LatLng position;
            private Bitmap icon;
            private float anchorU;
            private float anchorV;
            private boolean flat;
            private int rotation;
            private boolean attached;
            private boolean removed;

            private PlumaMarker(String id, PlumaMarkerOptions options) {
                this.id = id;
                position = options.position == null ? new LatLng(0, 0) : options.position;
                icon = options.icon;
                anchorU = options.anchorU;
                anchorV = options.anchorV;
                flat = options.flat;
            }

            private void attach() {
                if (removed || attached || icon == null || icon.isRecycled() || !ready()) {
                    return;
                }
                style.addImage(id, icon);
                style.addSource(new GeoJsonSource(id, toPoint(position)));
                SymbolLayer layer = new SymbolLayer(id, id);
                layer.setProperties(properties());
                style.addLayer(layer);
                attached = true;
            }

            private PropertyValue<?>[] properties() {
                float ratio = icon.getDensity() / 160f;
                String alignment = flat ? Property.ICON_ROTATION_ALIGNMENT_MAP : Property.ICON_ROTATION_ALIGNMENT_VIEWPORT;
                return new PropertyValue<?>[]{
                        PropertyFactory.iconImage(id),
                        PropertyFactory.iconAllowOverlap(true),
                        PropertyFactory.iconIgnorePlacement(true),
                        PropertyFactory.iconAnchor(Property.ICON_ANCHOR_CENTER),
                        PropertyFactory.iconOffset(new Float[]{(0.5f - anchorU) * icon.getWidth() / ratio, (0.5f - anchorV) * icon.getHeight() / ratio}),
                        PropertyFactory.iconRotate((float) rotation),
                        PropertyFactory.iconRotationAlignment(alignment),
                        PropertyFactory.iconPitchAlignment(flat ? Property.ICON_PITCH_ALIGNMENT_MAP : Property.ICON_PITCH_ALIGNMENT_VIEWPORT),
                };
            }

            private void updateLayer() {
                if (!attached || !ready()) {
                    return;
                }
                SymbolLayer layer = style.getLayerAs(id);
                if (layer != null) {
                    layer.setProperties(properties());
                }
            }

            @Override
            public Object getTag() {
                return tag;
            }

            @Override
            public void setTag(Object tag) {
                this.tag = tag;
            }

            @Override
            public LatLng getPosition() {
                return position;
            }

            @Override
            public void setPosition(LatLng latLng) {
                position = latLng;
                if (!attached || !ready()) {
                    return;
                }
                GeoJsonSource source = style.getSourceAs(id);
                if (source != null) {
                    source.setGeoJson(toPoint(latLng));
                }
            }

            @Override
            public void setRotation(int rotation) {
                this.rotation = rotation;
                updateLayer();
            }

            @Override
            public void setIcon(Bitmap bitmap) {
                if (bitmap == null || bitmap.isRecycled()) {
                    return;
                }
                icon = screenBitmap(bitmap);
                if (!attached) {
                    attach();
                    return;
                }
                if (ready()) {
                    style.addImage(id, icon);
                    updateLayer();
                }
            }

            @Override
            public void setIcon(int resId) {
                Bitmap bitmap = BitmapFactory.decodeResource(ApplicationLoader.applicationContext.getResources(), resId);
                if (bitmap != null) {
                    setIcon(bitmap);
                }
            }

            @Override
            public void remove() {
                if (removed) {
                    return;
                }
                removed = true;
                markers.remove(this);
                if (attached && ready()) {
                    style.removeLayer(id);
                    style.removeSource(id);
                    style.removeImage(id);
                }
                attached = false;
            }
        }

        // A circle is a polygon of its points on the sphere, filled by one layer and outlined by another.
        public final class PlumaCircle implements ICircle {
            private final String id;
            private LatLng center;
            private double radius;
            private int strokeColor;
            private int fillColor;
            private int strokeWidth;
            private Float[] dashes;
            private boolean attached;
            private boolean removed;

            private PlumaCircle(String id, PlumaCircleOptions options) {
                this.id = id;
                center = options.center == null ? new LatLng(0, 0) : options.center;
                radius = options.radius;
                strokeColor = options.strokeColor;
                fillColor = options.fillColor;
                strokeWidth = options.strokeWidth;
                dashes = dashArray(options.pattern, strokeWidth);
            }

            private String fillId() {
                return id + "-fill";
            }

            private String lineId() {
                return id + "-line";
            }

            private void attach() {
                if (removed || attached || !ready()) {
                    return;
                }
                style.addSource(new GeoJsonSource(id, circlePolygon(center, radius)));
                FillLayer fill = new FillLayer(fillId(), id);
                fill.setProperties(PropertyFactory.fillColor(fillColor));
                LineLayer line = new LineLayer(lineId(), id);
                line.setProperties(lineProperties());
                String below = firstMarkerLayer();
                if (below == null) {
                    style.addLayer(fill);
                    style.addLayer(line);
                } else {
                    style.addLayerBelow(fill, below);
                    style.addLayerBelow(line, below);
                }
                attached = true;
            }

            private String firstMarkerLayer() {
                for (PlumaMarker marker : markers) {
                    if (marker.attached) {
                        return marker.id;
                    }
                }
                return null;
            }

            private PropertyValue<?>[] lineProperties() {
                float density = ApplicationLoader.applicationContext.getResources().getDisplayMetrics().density;
                ArrayList<PropertyValue<?>> out = new ArrayList<>();
                out.add(PropertyFactory.lineColor(strokeColor));
                out.add(PropertyFactory.lineWidth(strokeWidth / density));
                if (dashes != null) {
                    out.add(PropertyFactory.lineDasharray(dashes));
                }
                return out.toArray(new PropertyValue<?>[0]);
            }

            private void updateShape() {
                if (!attached || !ready()) {
                    return;
                }
                GeoJsonSource source = style.getSourceAs(id);
                if (source != null) {
                    source.setGeoJson(circlePolygon(center, radius));
                }
            }

            @Override
            public void setStrokeColor(int color) {
                strokeColor = color;
                if (attached && ready()) {
                    LineLayer line = style.getLayerAs(lineId());
                    if (line != null) {
                        line.setProperties(lineProperties());
                    }
                }
            }

            @Override
            public void setFillColor(int color) {
                fillColor = color;
                if (attached && ready()) {
                    FillLayer fill = style.getLayerAs(fillId());
                    if (fill != null) {
                        fill.setProperties(PropertyFactory.fillColor(color));
                    }
                }
            }

            @Override
            public void setRadius(double radius) {
                this.radius = radius;
                updateShape();
            }

            @Override
            public double getRadius() {
                return radius;
            }

            @Override
            public void setCenter(LatLng latLng) {
                center = latLng;
                updateShape();
            }

            @Override
            public void remove() {
                if (removed) {
                    return;
                }
                removed = true;
                circles.remove(this);
                if (attached && ready()) {
                    style.removeLayer(lineId());
                    style.removeLayer(fillId());
                    style.removeSource(id);
                }
                attached = false;
            }
        }
    }

    // A stroke pattern of dashes and gaps in pixels as MapLibre's dash array: lengths in line widths, starting
    // with a dash, in pairs.
    private static Float[] dashArray(List<PatternItem> pattern, int strokeWidth) {
        if (pattern == null || pattern.isEmpty() || strokeWidth <= 0) {
            return null;
        }
        ArrayList<Float> out = new ArrayList<>();
        for (PatternItem item : pattern) {
            boolean dash = item instanceof PatternItem.Dash;
            if (!dash && !(item instanceof PatternItem.Gap)) {
                continue;
            }
            int length = dash ? ((PatternItem.Dash) item).length : ((PatternItem.Gap) item).length;
            if (out.size() % 2 == (dash ? 1 : 0)) {
                out.add(0f);
            }
            out.add(length / (float) strokeWidth);
        }
        if (out.size() % 2 == 1) {
            out.add(0f);
        }
        return out.isEmpty() ? null : out.toArray(new Float[0]);
    }

    public final static class PlumaUISettings implements IUISettings {
        private final UiSettings uiSettings;

        private PlumaUISettings(UiSettings settings) {
            uiSettings = settings;
        }

        // MapLibre draws no zoom buttons and no location button.
        @Override
        public void setZoomControlsEnabled(boolean enabled) {
        }

        @Override
        public void setMyLocationButtonEnabled(boolean enabled) {
        }

        @Override
        public void setCompassEnabled(boolean enabled) {
            uiSettings.setCompassEnabled(enabled);
        }
    }

    // A marker without an anchor stands on the middle of its bottom edge, as a pin does.
    public final static class PlumaMarkerOptions implements IMarkerOptions {
        private LatLng position;
        private Bitmap icon;
        private float anchorU = 0.5f;
        private float anchorV = 1f;
        private boolean flat;

        private PlumaMarkerOptions() {
        }

        @Override
        public IMarkerOptions position(LatLng latLng) {
            position = latLng;
            return this;
        }

        @Override
        public IMarkerOptions icon(Bitmap bitmap) {
            if (bitmap != null && !bitmap.isRecycled()) {
                icon = screenBitmap(bitmap);
            }
            return this;
        }

        @Override
        public IMarkerOptions icon(int resId) {
            Bitmap bitmap = BitmapFactory.decodeResource(ApplicationLoader.applicationContext.getResources(), resId);
            if (bitmap != null) {
                icon = screenBitmap(bitmap);
            }
            return this;
        }

        @Override
        public IMarkerOptions anchor(float lat, float lng) {
            anchorU = lat;
            anchorV = lng;
            return this;
        }

        // The screens give no marker a title or a snippet to show: MapLibre's layers have no info windows.
        @Override
        public IMarkerOptions title(String title) {
            return this;
        }

        @Override
        public IMarkerOptions snippet(String snippet) {
            return this;
        }

        @Override
        public IMarkerOptions flat(boolean flat) {
            this.flat = flat;
            return this;
        }
    }

    // The screens set every property of their circles; these are only the values of a circle that sets none.
    public final static class PlumaCircleOptions implements ICircleOptions {
        private LatLng center;
        private double radius;
        private int strokeColor = Color.BLACK;
        private int fillColor = Color.TRANSPARENT;
        private int strokeWidth = 10;
        private List<PatternItem> pattern;

        private PlumaCircleOptions() {
        }

        @Override
        public ICircleOptions center(LatLng latLng) {
            center = latLng;
            return this;
        }

        @Override
        public ICircleOptions radius(double radius) {
            this.radius = radius;
            return this;
        }

        @Override
        public ICircleOptions strokeColor(int color) {
            strokeColor = color;
            return this;
        }

        @Override
        public ICircleOptions fillColor(int color) {
            fillColor = color;
            return this;
        }

        @Override
        public ICircleOptions strokePattern(List<PatternItem> patternItems) {
            pattern = patternItems == null ? null : new ArrayList<>(patternItems);
            return this;
        }

        @Override
        public ICircleOptions strokeWidth(int width) {
            strokeWidth = width;
            return this;
        }
    }

    // The bounds of the points included by their smallest and largest latitude and longitude (not across the
    // 180th meridian); one point is bounds of no size.
    public final static class PlumaLatLngBoundsBuilder implements ILatLngBoundsBuilder {
        private double north = -90, south = 90, east = -Double.MAX_VALUE, west = Double.MAX_VALUE;
        private boolean empty = true;

        private PlumaLatLngBoundsBuilder() {
        }

        @Override
        public ILatLngBoundsBuilder include(LatLng latLng) {
            north = Math.max(north, latLng.latitude);
            south = Math.min(south, latLng.latitude);
            east = Math.max(east, latLng.longitude);
            west = Math.min(west, latLng.longitude);
            empty = false;
            return this;
        }

        @Override
        public ILatLngBounds build() {
            if (empty) {
                throw new IllegalStateException("no included points");
            }
            return new PlumaLatLngBounds(LatLngBounds.from(north, east, south, west));
        }
    }

    public final static class PlumaLatLngBounds implements ILatLngBounds {
        private final LatLngBounds bounds;

        private PlumaLatLngBounds(LatLngBounds bounds) {
            this.bounds = bounds;
        }

        @Override
        public LatLng getCenter() {
            return fromMapLibre(bounds.getCenter());
        }
    }

    public final static class PlumaCameraUpdate implements ICameraUpdate {
        private final CameraUpdate update;
        private final boolean bounds;

        private PlumaCameraUpdate(CameraUpdate update, boolean bounds) {
            this.update = update;
            this.bounds = bounds;
        }
    }

    public final static class PlumaMapStyle implements IMapStyleOptions {
        private final boolean dark;

        private PlumaMapStyle(boolean dark) {
            this.dark = dark;
        }
    }
}
"""

# MapLibre's artifacts, by the SHA-256 Maven Central publishes for each (recomputed
# from the files); every other group stays as upstream resolves it.
MAPS_ARTIFACTS = (
    ("android-sdk-opengl", "13.7.1", (
        ("android-sdk-opengl-13.7.1.aar", "4a6762e878ae8f392a27d89138c19196a519121d1449f824e542058147a8a072"),
        ("android-sdk-opengl-13.7.1.module", "8399f6b9b895477d234636af59768f1f416831d86e7abebea2da50c1469d0528"),
        ("android-sdk-opengl-13.7.1.pom", "56349b4aae6f886c5a2befeaeb375e28c91cd457791555fd3a5851692d897de9"),
    )),
    ("android-sdk-geojson", "6.0.1", (
        ("android-sdk-geojson-6.0.1.jar", "0c4e4258ce258da9740c17c76f3ae90f89fcfa5822a797f5d466b35410571363"),
        ("android-sdk-geojson-6.0.1.module", "27df402a9eef70bb45ea077ba63084b6da62e97831dda124f466bedce68f81f3"),
        ("android-sdk-geojson-6.0.1.pom", "c4c5d3ca85dc344e0fbdf2c40a22eb2e55bdc5892b44e94377e54fa7bd0c28e2"),
    )),
    ("android-sdk-turf", "6.0.1", (
        ("android-sdk-turf-6.0.1.jar", "c0fd543d17fbd3b7c2e946515caf2d53b602f0eac1438ad4dca731d9a508af79"),
        ("android-sdk-turf-6.0.1.module", "e36383ee48cfb210c4c6b3743fffb00aa119a5666ddf5ba2650e6b62e5b5e23c"),
        ("android-sdk-turf-6.0.1.pom", "d1412707b1caac09be5bc25338189b9d89250806f7eb6be90655c0ff54b3f6f9"),
    )),
    ("maplibre-android-gestures", "0.0.4", (
        ("maplibre-android-gestures-0.0.4-sources.jar", "155574301748bbae2aa39cac8a94865eb671e0215b1140a022d5c5bbe554d26b"),
        ("maplibre-android-gestures-0.0.4.aar", "44ff4fc2dd8bfbcf54a06f219e7ab40a2062eb6b4a10dcbf1f4e02b4a30c61af"),
        ("maplibre-android-gestures-0.0.4.module", "4cf75cda22d02ffb6ac43bc2f5bc54282bac1576df8cd9abbc0ead27b2fd80fc"),
        ("maplibre-android-gestures-0.0.4.pom", "4f7f178c649295c89a4b5fa3927bc714ffb9e29866d66ca635c5f0415ea83f2e"),
    )),
)
MAPS_GROUP = "org.maplibre.gl"


def maps_verification_metadata():
    """Gradle's dependency verification of the MapLibre group only: every other group is trusted."""
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        "<!-- pluma: the artifacts of MapLibre Native (task 112 of the server repository) are checked against",
        "     their SHA-256; every other group is resolved as upstream resolves it. Written by ci/patch.py. -->",
        '<verification-metadata xmlns="https://schema.gradle.org/dependency-verification"'
        ' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
        ' xsi:schemaLocation="https://schema.gradle.org/dependency-verification'
        ' https://schema.gradle.org/dependency-verification/dependency-verification-1.3.xsd">',
        "   <configuration>",
        "      <verify-metadata>true</verify-metadata>",
        "      <verify-signatures>false</verify-signatures>",
        "      <trusted-artifacts>",
        '         <trust group="^(?!org[.]maplibre[.]gl$).*$" regex="true"/>',
        "      </trusted-artifacts>",
        "   </configuration>",
        "   <components>",
    ]
    for name, version, files in MAPS_ARTIFACTS:
        lines.append(f'      <component group="{MAPS_GROUP}" name="{name}" version="{version}">')
        for file, sha in files:
            lines.append(f'         <artifact name="{file}">')
            lines.append(f'            <sha256 value="{sha}" origin="Maven Central"/>')
            lines.append("         </artifact>")
        lines.append("      </component>")
    lines += ["   </components>", "</verification-metadata>", ""]
    return "\n".join(lines)


def _maps_sources(tree):
    for module in ("TMessagesProj/src", "TMessagesProj_App/src"):
        root = tree.root / module
        if root.is_dir():
            yield from sorted(p for p in root.rglob("*.java") if p.is_file())


def maps(tree):
    # Every anchor first, and no PlumaMapsProvider or verification metadata yet:
    # a tree that is already patched must fail before anything is written twice.
    for rel in (MAPS_PROVIDER_FILE, VERIFICATION_METADATA):
        if (tree.root / rel).exists():
            raise PatchError(f"{rel}: the file is already there")
    if not (tree.root / GOOGLE_MAPS_PROVIDER).is_file():
        raise PatchError(f"{GOOGLE_MAPS_PROVIDER}: not there; upstream changed its maps")
    for rel, old, _ in MAPS_EDITS:
        tree.expect(rel, old)
    for rel, text in MAPS_USES:
        tree.expect(rel, text)
    for rel in MAPS_KEY_MANIFESTS:
        found = len(MAPS_KEY_LINE.findall(tree.read(rel)))
        if found != 1:
            raise PatchError(f"{rel}: {found} keys for Google's maps, expected 1; upstream changed it")
    for rel, old, new in MAPS_EDITS:
        tree.replace(rel, old, new)
    for rel in MAPS_KEY_MANIFESTS:
        tree.sub(rel, MAPS_KEY_LINE.pattern, "")
    (tree.root / GOOGLE_MAPS_PROVIDER).unlink()
    tree.write(MAPS_PROVIDER_FILE, MAPS_JAVA)
    (tree.root / VERIFICATION_METADATA).parent.mkdir(exist_ok=True)
    tree.write(VERIFICATION_METADATA, maps_verification_metadata())


def verify_maps(tree):
    for rel, old, new in MAPS_EDITS:
        text = tree.read(rel)
        if text.count(new) != 1 or old in text.replace(new, ""):
            changed = next(line for line in new.splitlines() if line not in old.splitlines())
            raise PatchError(f"{rel}: the maps edit {changed.strip()!r} is not there")
    for rel, text in MAPS_USES:
        tree.expect(rel, text)
    java = tree.root / MAPS_PROVIDER_FILE
    if not java.is_file() or java.read_text(encoding="utf-8") != MAPS_JAVA:
        raise PatchError(f"{MAPS_PROVIDER_FILE}: not the MapLibre provider")
    if (tree.root / GOOGLE_MAPS_PROVIDER).exists():
        raise PatchError(f"{GOOGLE_MAPS_PROVIDER}: Google's provider is still there")
    meta = tree.root / VERIFICATION_METADATA
    if not meta.is_file() or meta.read_text(encoding="utf-8") != maps_verification_metadata():
        raise PatchError(f"{VERIFICATION_METADATA}: not the checksums of MapLibre")
    gradle = tree.read(LIBRARY_GRADLE)
    if "play-services-maps" in gradle or gradle.count(MAPLIBRE_DEPENDENCY) != 1:
        raise PatchError(f"{LIBRARY_GRADLE}: the maps are not MapLibre's")
    # No manifest carries the key, no source Google's maps.
    for p in sorted((tree.root / "TMessagesProj").rglob("AndroidManifest*.xml")):
        if MAPS_KEY_NAME in p.read_text(encoding="utf-8", errors="replace"):
            raise PatchError(f"{p.relative_to(tree.root)}: the key for Google's maps is still there")
    for p in _maps_sources(tree):
        text = p.read_text(encoding="utf-8", errors="replace")
        if GOOGLE_MAPS_PACKAGE in text or "GoogleMapsProvider" in text:
            raise PatchError(f"{p.relative_to(tree.root)}: Google's maps are still used")


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
    ap.add_argument("--target", choices=("server", "dev"), default="server",
                    help="dev also takes http:// to the stand's CDN (ci/configure.sh)")
    ap.add_argument("--edge-ws-urls", default="", help="the server's edges, wss:// URLs separated by commas")
    a = ap.parse_args(argv)
    try:
        app = load_env(a.app)
        c = Config(load_env(a.upstream), app, a.server_ipv4, a.server_port, a.server_ipv6,
                   pathlib.Path(a.rsa_public_key).read_text(), a.abis or app.get("PLUMA_ABIS", ""),
                   a.ccache, a.google_services, a.build, a.target, a.edge_ws_urls)
        tree = Tree(a.source)
        patch(tree, c)
        verify(tree, c)
    except PatchError as e:
        print(f"patch: {e}", file=sys.stderr)
        return 1
    print(f"patch: {c.package} \"{c.app_name}\" {c.version_name}, layer {c.layer}, server key {c.fingerprint:#018x}, "
          f"ABIs {' '.join(c.abis)}, Firebase {'given' if c.google_services else 'placeholder'}, {c.target} build, "
          f"{len(c.edge_urls)} edges")
    return 0


if __name__ == "__main__":
    sys.exit(main())
