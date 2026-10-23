#!/usr/bin/env bash
# Installs what a job needs on a GitHub runner:
#   setup.sh build  ccache, age and the Android SDK packages of upstream.env
#                   (the NDK and CMake versions the upstream build declares;
#                   ci/patch.py checks they match);
#   setup.sh sign   age and the build tools (apksigner).
set -euo pipefail
cd "$(dirname "$0")/.."
. ./upstream.env
mode=${1:?usage: setup.sh build|sign}
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

apt_install() {
	local apt=(sudo apt-get -qq -o Acquire::Retries=3 -o Acquire::http::Timeout=30)
	retry timeout 5m "${apt[@]}" update
	retry timeout 5m "${apt[@]}" install -y --no-install-recommends "$@"
}

sdk_install() {
	local sdkmanager="$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager"
	local log="${RUNNER_TEMP:-/tmp}/sdkmanager.log"
	{ yes || true; } | "$sdkmanager" --licenses >/dev/null
	if ! retry timeout 20m "$sdkmanager" --install "$@" >"$log"; then
		tail -n 50 "$log" >&2
		exit 1
	fi
}

case $mode in
build)
	apt_install ccache age
	sdk_install "platforms;$PLATFORM" "build-tools;$BUILD_TOOLS" "ndk;$NDK_VERSION" "cmake;$CMAKE_PACKAGE"
	test -x "$ANDROID_HOME/ndk/$NDK_VERSION/ndk-build"
	test -x "$ANDROID_HOME/cmake/$CMAKE_PACKAGE/bin/cmake"
	# ccache keys on the NDK version instead of hashing the compiler binary
	# in every call; the NDK is reinstalled on every run, so its mtime says
	# nothing.
	if [ -n "${GITHUB_ENV:-}" ]; then
		echo "CCACHE_COMPILERCHECK=string:$NDK_VERSION" >>"$GITHUB_ENV"
	fi
	echo "setup: ccache $(ccache --version | head -n 1 | awk '{print $3}'), NDK $NDK_VERSION, CMake $CMAKE_VERSION"
	;;
sign)
	apt_install age
	sdk_install "build-tools;$BUILD_TOOLS"
	test -x "$ANDROID_HOME/build-tools/$BUILD_TOOLS/apksigner"
	;;
*)
	echo "usage: setup.sh build|sign" >&2
	exit 2
	;;
esac
