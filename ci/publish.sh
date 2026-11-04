#!/usr/bin/env bash
# Hands a signed APK to the releases service of the server, which serves it
# on the site and offers it to installed apps (task 054 and ADR 0035 of the
# server repository): publish.sh <signed.apk> <build>.
#
# The version is the patched versionName, <UPSTREAM_VERSION>.<build>; the
# notes are release/notes.en.txt and release/notes.ru.txt.
#
# Environment: PLUMA_RELEASES_URL (the site, https://pluma.chat),
# RELEASES_UPLOAD_TOKEN (the service's upload token, never printed).
set -euo pipefail
cd "$(dirname "$0")/.."
. ./upstream.env
apk=${1:?usage: publish.sh signed.apk build}
build=${2:?usage: publish.sh signed.apk build}
: "${PLUMA_RELEASES_URL:?PLUMA_RELEASES_URL is not set}"
: "${RELEASES_UPLOAD_TOKEN:?RELEASES_UPLOAD_TOKEN is not set}"
if [[ ! "$build" =~ ^[0-9]{1,6}$ ]]; then
	echo "publish: build $build is not a number" >&2
	exit 1
fi
version="$UPSTREAM_VERSION.$build"
for f in release/notes.en.txt release/notes.ru.txt; do
	[ -s "$f" ] || { echo "publish: $f is missing or empty" >&2; exit 1; }
done

# The token goes through a file curl reads, not its arguments.
headers=$(mktemp)
trap 'rm -f "$headers"' EXIT
printf 'Authorization: Bearer %s\n' "$RELEASES_UPLOAD_TOKEN" >"$headers"
code=$(curl -sS -o /dev/stderr -w '%{http_code}' --retry 3 --retry-all-errors --max-time 900 \
	-H @"$headers" \
	-F platform=android -F "version=$version" -F "build=$build" \
	-F "notes_en=<release/notes.en.txt" -F "notes_ru=<release/notes.ru.txt" \
	-F "installer=@$apk;filename=Pluma-$version.apk" \
	"${PLUMA_RELEASES_URL%/}/dl/upload")
echo
case $code in
200) echo "publish: Pluma $version (build $build) is on the site" ;;
409) echo "publish: build $build is published already" ;;
*)
	echo "publish: the releases service answered $code" >&2
	exit 1
	;;
esac
