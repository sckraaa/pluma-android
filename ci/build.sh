#!/usr/bin/env bash
# Builds the release APK of the patched ./upstream into ./out:
# pluma-android-<version>-<target>.apk and its SHA-256. The APK carries the
# upstream's public test signature; ci/sign.sh signs it with the release key.
set -euo pipefail
cd "$(dirname "$0")/.."
. ./upstream.env
target=${1:?usage: build.sh server|dev}

(
	cd upstream
	./gradlew --build-cache --stacktrace \
		-Dorg.gradle.jvmargs="-Xmx6g -XX:MaxMetaspaceSize=1g -XX:+HeapDumpOnOutOfMemoryError -Dfile.encoding=UTF-8" \
		:TMessagesProj_App:assembleAfatRelease
)

name="pluma-android-$UPSTREAM_VERSION-$target"
mkdir -p out
cp upstream/TMessagesProj_App/build/outputs/apk/afat/release/app.apk "out/$name.apk"
(cd out && sha256sum "$name.apk" >"$name.apk.sha256")
echo "build: out/$name.apk ($(du -h "out/$name.apk" | cut -f1))"
echo "apk=$name.apk" >>"${GITHUB_OUTPUT:-/dev/null}"
