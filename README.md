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

After the edits, the result is checked again: no Telegram datacenter address or server key may remain.

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

None of these values is a secret: every APK carries them.

- **No server variables set.** The build targets the development server of [`config/dev`](config/dev): an Android emulator on the machine that runs the server's `docker compose` stack, at `10.0.2.2:10443`. Such builds are never signed.
- **Some but not all set.** The build fails.

## Signing

The build job never sees the release key. The `sign` job runs in the protected `release` environment and signs only builds for a real server.

1. Create the key once:
   ```sh
   keytool -genkeypair -keystore pluma-release.p12 -storetype PKCS12 -alias pluma \
     -keyalg RSA -keysize 4096 -validity 36500 -dname "CN=Pluma"
   ```
   Back up the keystore and its password off-line. Android installs an update only if it is signed with the same key.
2. Add the key to the `release` environment:
   ```sh
   base64 -i pluma-release.p12 | gh secret set PLUMA_KEYSTORE_B64 --env release
   gh secret set PLUMA_KEYSTORE_PASSWORD --env release
   gh secret set PLUMA_KEY_ALIAS --env release --body pluma
   ```
   A JKS keystore with a separate key password also needs `PLUMA_KEY_PASSWORD`.
3. Protect the environment in *Settings → Environments → release*: *Deployment branches and tags* → `main` only.

The signed APK is the `pluma-android` artifact of the run, kept for 30 days:

```sh
gh run download <run id> -n pluma-android
```

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
ci/configure.sh          # the development server; set SERVER_IPV4, SERVER_PORT, RSA_PUBLIC_KEY for another
ci/build.sh dev          # out/pluma-android-<version>-dev.apk
```

## Updating the upstream

1. Change `upstream.env` (release commit, version, layer, toolchain). The layer must be one the server speaks.
2. Run `python3 ci/patch_test.py`.
3. Push. Where the upstream moved something, `ci/patch.py` names the file and the text it expected.

## License

GPL-2.0, as the upstream ([LICENSE](LICENSE)).
