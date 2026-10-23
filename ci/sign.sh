#!/usr/bin/env bash
# Signs an APK with the release key: sign.sh <in.apk> <out.apk>.
#
# Environment: PLUMA_KEYSTORE (the keystore file), PLUMA_KEYSTORE_PASSWORD,
# PLUMA_KEY_ALIAS, PLUMA_KEY_PASSWORD (a PKCS12 keystore uses the store
# password), PLUMA_SIGNING_CERT_SHA256 (optional: the certificate the
# signature must have, so a wrong keystore cannot sign a release).
set -euo pipefail
cd "$(dirname "$0")/.."
. ./upstream.env
in=${1:?usage: sign.sh in.apk out.apk}
out=${2:?usage: sign.sh in.apk out.apk}
: "${ANDROID_HOME:?ANDROID_HOME is not set}"
: "${PLUMA_KEYSTORE:?PLUMA_KEYSTORE is not set}"
: "${PLUMA_KEYSTORE_PASSWORD:?PLUMA_KEYSTORE_PASSWORD is not set}"
: "${PLUMA_KEY_ALIAS:?PLUMA_KEY_ALIAS is not set}"
export PLUMA_KEYSTORE_PASSWORD
export PLUMA_KEY_PASSWORD="${PLUMA_KEY_PASSWORD:-$PLUMA_KEYSTORE_PASSWORD}"
tools="$ANDROID_HOME/build-tools/$BUILD_TOOLS"

# The build output is aligned; signing (v1 to v3) keeps the alignment.
"$tools/zipalign" -c 4 "$in"
"$tools/apksigner" sign --ks "$PLUMA_KEYSTORE" --ks-key-alias "$PLUMA_KEY_ALIAS" \
	--ks-pass env:PLUMA_KEYSTORE_PASSWORD --key-pass env:PLUMA_KEY_PASSWORD --out "$out" "$in"
"$tools/apksigner" verify "$out"
rm -f "$out.idsig"

cert=$("$tools/apksigner" verify --print-certs "$out" | sed -n 's/^Signer #1 certificate SHA-256 digest: //p')
if [ -z "$cert" ]; then
	echo "sign: no certificate in $out" >&2
	exit 1
fi
if [ -n "${PLUMA_SIGNING_CERT_SHA256:-}" ]; then
	want=$(printf '%s' "$PLUMA_SIGNING_CERT_SHA256" | tr -d ': ' | tr 'A-F' 'a-f')
	if [ "$cert" != "$want" ]; then
		echo "sign: the keystore's certificate is $cert, the release certificate is $want" >&2
		exit 1
	fi
fi
(cd "$(dirname "$out")" && sha256sum "$(basename "$out")" >"$(basename "$out").sha256")
echo "sign: $out, certificate SHA-256 $cert"
