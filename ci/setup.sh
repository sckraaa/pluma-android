#!/usr/bin/env bash
# Installs what the build needs on a GitHub runner: ccache and the Android
# SDK packages of upstream.env (the NDK and CMake versions the upstream build
# declares; ci/patch.py checks they match).
set -euo pipefail
cd "$(dirname "$0")/.."
. ./upstream.env
: "${ANDROID_HOME:?ANDROID_HOME is not set}"

retry() {
	local attempt
	for attempt in 1 2 3; do
		if "$@"; then
			return 0
		fi
		echo "setup: attempt $attempt of '$*' failed" >&2
		sleep $((attempt * 15))
	done
	return 1
}

retry timeout 5m sudo apt-get -qq -o Acquire::Retries=3 -o Acquire::http::Timeout=30 update
retry timeout 5m sudo apt-get -qq -o Acquire::Retries=3 -o Acquire::http::Timeout=30 install -y --no-install-recommends ccache

sdkmanager="$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager"
{ yes || true; } | "$sdkmanager" --licenses >/dev/null
log="${RUNNER_TEMP:-/tmp}/sdkmanager.log"
if ! retry timeout 20m "$sdkmanager" --install \
	"platforms;$PLATFORM" "build-tools;$BUILD_TOOLS" "ndk;$NDK_VERSION" "cmake;$CMAKE_PACKAGE" >"$log"; then
	tail -n 50 "$log" >&2
	exit 1
fi
test -x "$ANDROID_HOME/ndk/$NDK_VERSION/ndk-build"
test -x "$ANDROID_HOME/cmake/$CMAKE_PACKAGE/bin/cmake"

# ccache keys on the NDK version instead of hashing the compiler binary in
# every call; the NDK is reinstalled on every run, so its mtime says nothing.
if [ -n "${GITHUB_ENV:-}" ]; then
	echo "CCACHE_COMPILERCHECK=string:$NDK_VERSION" >>"$GITHUB_ENV"
fi
echo "setup: ccache $(ccache --version | head -n 1 | awk '{print $3}'), NDK $NDK_VERSION, CMake $CMAKE_VERSION"
