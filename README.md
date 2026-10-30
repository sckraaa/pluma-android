# Pluma for Android

Builds of the official Telegram Android app ([DrKLO/Telegram](https://github.com/DrKLO/Telegram)) for a [Pluma](https://github.com/sckraaa/pluma) server, a self-hosted Telegram-compatible server. This project is not affiliated with Telegram.

The repository holds no copy of the app's code. CI fetches the upstream release pinned in [`upstream.env`](upstream.env), patches it with [`ci/patch.py`](ci/patch.py) and builds the APK. Every edit must match the upstream source exactly. If an update moves any of the edited places, the build fails; it never quietly produces a client that talks to Telegram.

## What the patch changes

- **Datacenter.** tgnet gets a single datacenter, the Pluma server (IPv4 address, optional IPv6 address, port). It is used for both the production and the test backend, and a fresh install starts on it.
- **Server key.** The server's RSA key and its fingerprint replace Telegram's keys.
- **Backup addresses.** The client does not look up backup addresses in Telegram's DNS and Firebase records.
- **App identity.** The app ID is `chat.pluma.app`, the name is "Pluma", and the app uses Pluma's `api_id`/`api_hash` ([`config/app.env`](config/app.env)).
- **Coexistence with Telegram.** The contacts account type and the MIME types of contact actions are Pluma's own, so the app can sit next to Telegram on one phone.
- **Build scope.**
  - Only the modules Pluma builds are included; the Huawei repository and plugin are removed.
  - The ABIs come from `config/app.env`: `arm64-v8a`, plus `x86_64` for an emulator.
- **Firebase.** The patch uses the given Firebase config, or a placeholder when none is given. With the placeholder there are no push notifications.
- **Brand.** Name, logo, link scheme and colours are Pluma's; see [Branding](#branding).

After the edits, the result is checked again: no Telegram datacenter address or server key may remain, no "Telegram" and no link to Telegram's desktop or web client in the text of the built-in strings, no `tg:` link scheme, and no Telegram blue in the default themes. For that last check the patch works out the colour the theme engine gives each key of the two themes, and fails on any blue outside the keys the engine leaves alone (user colours, calls, statistics, Premium, stories).

## Branding

The user sees Pluma, not Telegram (task 017 of the server repository).

- **Name.** Every "Telegram" in the built-in strings of all languages becomes "Pluma", feature names too ("Pluma Premium", "Pluma Stars"); Korean and Arabic, which write the name in their own script, get "Pluma" in Latin letters. The same goes for the names in Java string literals the user sees (contact rows in the system Contacts app, the passcode screen, the placeholders of the service accounts). String keys, code, package and folder names (`Pictures/Telegram`), the mini app API (`window.Telegram`) and URLs (telegram.org, t.me) stay, except the links to the clients (below).
- **Links.** The app takes and makes `plm://` links instead of `tg://`, the QR login (`plm://login?token=…`) included. Telegram keeps `tg://` when it is installed next to Pluma. Only the internal `tg://` URIs ExoPlayer streams files through stay.
- **Client links.** Where the QR login sends the user to get a client, the links open Pluma's site https://pluma.chat/ and its web client https://web.pluma.chat/, not Telegram's: "Pluma Desktop" and "Pluma Web" in the text under the laptop in Settings → Devices, and the addresses in the steps of "Link Desktop Device" and in the scanner's hint, which read pluma.chat and web.pluma.chat instead of getdesktop.telegram.org, desktop.telegram.org and web.telegram.org. These are the only telegram.org links the patch changes: the strings `AuthAnotherClientDownloadClientUrl`, `AuthAnotherWebClientUrl`, `AuthAnotherClientInfo1` and `AuthAnotherClientInfo5`, by key in every language that has them (`CLIENT_LINKS` in `ci/patch.py`).
- **Devices.** Settings → Devices shows Pluma's laptop animation above "Link Desktop Device", bundled with the app. Upstream shows a sticker there that it asks the server for (the set `tg_placeholders_android`); the Pluma server has no such set, and the place stayed empty. The animation plays as the sticker did: at the same size, once when the screen opens and again on a tap. It is the `Devices.tgs` animation of Telegram-iOS (release 12.9.2, commit `6ad963e5`) in the palette, with the mark, centred on the disc, in place of the plane on the lid and in the QR code.
- **Logo.** The launcher icon (adaptive, with the monochrome layer for themed icons, and the legacy icons), the splash screen, the notification icon, the intro, the chat list title, the icons of the contacts account and calls, the QR code centres, the caller in the login's call-log permission explanation and the round video watermark.
- **Colours.** The palette "graphite and sage" in the default day and night themes. The home accent is sage. Text, accent, links and bubbles have the palette's exact colours (`bluebubbles.attheme`, `darkblue.attheme`), and the accent engine shifts the remaining blue of the themes to sage.
  - Upstream gives the home accent of the day theme Telegram's built-in colours and skips both its theme file and the accent engine. The patch makes it go through both, like every other accent.
  - Also Pluma's: the notification and call accents, the platform styles, the splash background and the intro.
  - The alternative themes (Day, Night, Arctic Blue) stay as Telegram has them. The other accent colours of the two default themes tint as in Telegram, except the keys that have the palette's exact colours.
- **Hidden.** The Help section of the settings (support chat, FAQ, feature tips and privacy policy: Telegram's services only) and the app icon picker (the alternative icons are Telegram's).

The assets come from the brand kit in [`brand/svg`](brand/svg). [`brand/render.py`](brand/render.py) renders them into `brand/android` with `rsvg-convert` and `cwebp`, at the sizes and in the formats of the upstream files they replace. The patch copies each one over its upstream file only when that file is byte for byte the one it expects (`BRAND_ASSETS` in `ci/patch.py`, SHA-256).

One file is not drawn: the laptop animation [`brand/lottie/pluma-devices.json`](brand/lottie/pluma-devices.json), which `render.py` copies to `brand/android/res/raw/pluma_devices.json`. Upstream has no such resource, so the patch adds it (`BRAND_ADDED`): only the file of that SHA-256, and only while no upstream file of `res/raw` has its name, whatever the extension. After a change of the animation, render again and update its SHA-256 in `BRAND_ADDED`.

After a change of the SVGs:

```sh
python3 brand/render.py   # rewrites brand/android
python3 ci/patch_test.py
```

When an update changes an upstream icon, the patch names the file; check it, render again if its size changed, and update its SHA-256.

## Configuration

Set these in the repository's *Settings → Secrets and variables → Actions → Variables*:

| Variable | |
|---|---|
| `PLUMA_SERVER_IPV4` | The server's IPv4 address. tgnet takes an address, not a host name. |
| `PLUMA_SERVER_PORT` | The port of the server's MTProto gateway (gnetway). |
| `PLUMA_SERVER_IPV6` | Optional. The server's IPv6 address. |
| `PLUMA_RSA_PUBLIC_KEY` | The server key as a PKCS#1 PEM: `openssl rsa -in server_pkcs1.key -RSAPublicKey_out` |
| `PLUMA_GOOGLE_SERVICES_JSON` | Optional. The Firebase config of `chat.pluma.app`, for push notifications. |
| `PLUMA_SIGNING_CERT_SHA256` | Optional. The SHA-256 of the release certificate. Signing with any other key fails. |
| `PLUMA_AGE_RECIPIENT` | The owner's [age](https://age-encryption.org) public key (`age1...`); see [Signing](#signing). |

None of these values is a secret: every APK carries them.

- **No server variables set.** The build targets the development server of [`config/dev`](config/dev): an Android emulator on the machine that runs the server's `docker compose` stack, at `10.0.2.2:10443`. Such builds are never signed.
- **Some but not all set.** The build fails.

### Development builds for a phone

A manual run with `dev_address` set makes a development build (the development key, never signed) for the stand at that IPv4, port 10443, whatever the server variables say:
- the Wi-Fi address of the machine that runs the stand, for a phone on the same network: `test/e2e/run.sh lan` of the server repository forwards that address to the stand;
- `127.0.0.1`, for a phone connected with `adb` (USB or wireless debugging): `adb reverse tcp:10443 tcp:10443` brings the phone's port to the machine.

```sh
gh workflow run android.yml -f abis=arm64-v8a -f dev_address=192.168.0.10
```

The procedure, with the stand, is in `docs/ops/clients.md` of the server repository.

## Signing

The build job never sees the release key. The `sign` job runs in the protected `release` environment and signs only builds for a real server.

Anyone can read the workflow artifacts of a public repository. So an APK built for a real server leaves a job only encrypted with the owner's age key. Development builds stay plain.

1. Create the release key once:
   ```sh
   keytool -genkeypair -keystore pluma-release.p12 -storetype PKCS12 -alias pluma \
     -keyalg RSA -keysize 4096 -validity 36500 -dname "CN=Pluma"
   ```
   Back up the keystore and its password off-line. Android installs an update only if it is signed with the same key.
2. Create the age key once, and back it up the same way:
   ```sh
   age-keygen -o pluma-apk.agekey        # prints the public key, age1...
   gh variable set PLUMA_AGE_RECIPIENT --body age1...
   ```
3. Create the environment in *Settings → Environments → New environment*, named `release`:
   - *Required reviewers*: yourself;
   - *Deployment branches and tags*: `main` only.
4. Add the secrets to the environment:
   ```sh
   base64 -i pluma-release.p12 | gh secret set PLUMA_KEYSTORE_B64 --env release
   gh secret set PLUMA_KEYSTORE_PASSWORD --env release
   gh secret set PLUMA_KEY_ALIAS --env release --body pluma
   gh secret set PLUMA_AGE_IDENTITY --env release < pluma-apk.agekey
   ```
   A JKS keystore with a separate key password also needs `PLUMA_KEY_PASSWORD`.
5. Set `PLUMA_SIGNING_CERT_SHA256` from `keytool -list -keystore pluma-release.p12`.

Each signing waits for your approval in the run. The signed APK is the `pluma-android` artifact of the run, kept for 30 days:

```sh
gh run download <run id> -n pluma-android
for f in pluma-android-*.apk.age; do age -d -i pluma-apk.agekey -o "${f%.age}" "$f"; done
shasum -a 256 -c pluma-android-*.apk.sha256
```

A failed signing (a wrong password, say) costs minutes: fix the secret and use *Re-run failed jobs*. The build's artifact is kept for three days.

## When it builds

| Trigger | Build | Signed |
|---|---|---|
| Push to `main` | yes | yes, if it targets a server and the key is set |
| Manual run (*Actions → android → Run workflow*) | yes, with any ABIs | yes, if it targets a server and the key is set |
| Pull request | yes | no |
| Weekly canary | the pinned upstream on a fresh runner image | no |

Native code is compiled through ccache and Java through the Gradle build cache, both kept in the GitHub Actions cache. A repeat build therefore spends most of its time on R8 and packaging.

Since the repository is public, set *Settings → Actions → General → Fork pull request workflows* to require approval for all outside collaborators.

## Local build

You need Linux or macOS with JDK 17, the Android SDK (`ANDROID_HOME`), the NDK and CMake versions from `upstream.env`, and Python 3:

```sh
ci/fetch-upstream.sh
ci/configure.sh          # the development server; DEV_SERVER_IPV4 for one at another address; SERVER_IPV4, SERVER_PORT, RSA_PUBLIC_KEY for a real one
ci/build.sh dev          # out/pluma-android-<version>-dev.apk
```

## Updating the upstream

1. Change `upstream.env` (release commit, version, layer, toolchain). The layer must be one the server speaks.
2. Run `python3 ci/patch_test.py`.
3. Push. Where the upstream moved something, `ci/patch.py` names the file and the text it expected.

## License

GPL-2.0, as the upstream ([LICENSE](LICENSE)).
