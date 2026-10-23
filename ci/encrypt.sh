#!/usr/bin/env bash
# Encrypts the APKs in a directory for the owner: encrypt.sh <dir>. Each
# <name>.apk becomes <name>.apk.age (with its .sha256 kept next to it) and
# the plain APK is removed: workflow artifacts of a public repository are
# readable by anyone (ADR 0010 of the server repository).
#
# Environment: PLUMA_AGE_RECIPIENT, an age public key (age1...).
set -euo pipefail
dir=${1:?usage: encrypt.sh dir}
if [[ ! "${PLUMA_AGE_RECIPIENT:-}" =~ ^age1[0-9a-z]+$ ]]; then
	echo "encrypt: PLUMA_AGE_RECIPIENT is not an age public key (README, Signing)" >&2
	exit 1
fi
shopt -s nullglob
apks=("$dir"/*.apk)
if [ ${#apks[@]} = 0 ]; then
	echo "encrypt: no APK in $dir" >&2
	exit 1
fi
for apk in "${apks[@]}"; do
	age --encrypt --recipient "$PLUMA_AGE_RECIPIENT" --output "$apk.age" "$apk"
	rm -f "$apk"
	echo "encrypt: $apk.age"
done
