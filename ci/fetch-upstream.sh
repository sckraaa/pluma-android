#!/usr/bin/env bash
# Fetches the upstream commit upstream.env pins into ./upstream, with the
# submodules it records (.gitmodules: the native libraries, jlatexmath and
# media): one commit of each, no history.
set -euo pipefail
cd "$(dirname "$0")/.."
. ./upstream.env

# retry <what> <minutes> <command...>: three attempts of a network step.
retry() {
	local what=$1 minutes=$2 attempt
	shift 2
	for attempt in 1 2 3; do
		if timeout "${minutes}m" "$@"; then
			return 0
		fi
		if [ "$attempt" = 3 ]; then
			echo "fetch-upstream: $what failed" >&2
			exit 1
		fi
		sleep $((attempt * 15))
	done
}

rm -rf upstream
git init -q upstream
git -C upstream remote add origin "$UPSTREAM_REPO"
retry "$UPSTREAM_REPO $UPSTREAM_REF" 10 git -C upstream fetch -q --depth 1 origin "$UPSTREAM_REF"
git -C upstream -c advice.detachedHead=false checkout -q FETCH_HEAD
test "$(git -C upstream rev-parse HEAD)" = "$UPSTREAM_REF"

# A later attempt keeps what the earlier ones fetched.
retry "the submodules of $UPSTREAM_REF" 40 \
	git -C upstream -c advice.detachedHead=false submodule update -q --init --recursive --depth 1 --jobs 4
# A status line that starts with "-", "+" or "U" is a submodule that is
# missing, on another commit than the upstream records, or conflicted.
status=$(git -C upstream submodule status --recursive)
if grep -q '^[^ ]' <<<"$status"; then
	echo "$status" >&2
	echo "fetch-upstream: the submodules do not match $UPSTREAM_REF" >&2
	exit 1
fi
echo "fetch-upstream: $UPSTREAM_VERSION ($UPSTREAM_REF), $(wc -l <<<"$status") submodules"
