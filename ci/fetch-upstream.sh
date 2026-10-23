#!/usr/bin/env bash
# Fetches the upstream commit upstream.env pins into ./upstream: one commit, no
# history.
set -euo pipefail
cd "$(dirname "$0")/.."
. ./upstream.env

rm -rf upstream
git init -q upstream
git -C upstream remote add origin "$UPSTREAM_REPO"
for attempt in 1 2 3; do
	if timeout 10m git -C upstream fetch -q --depth 1 origin "$UPSTREAM_REF"; then
		break
	fi
	if [ "$attempt" = 3 ]; then
		echo "fetch-upstream: $UPSTREAM_REPO $UPSTREAM_REF failed" >&2
		exit 1
	fi
	sleep $((attempt * 15))
done
git -C upstream -c advice.detachedHead=false checkout -q FETCH_HEAD
test "$(git -C upstream rev-parse HEAD)" = "$UPSTREAM_REF"
echo "fetch-upstream: $UPSTREAM_VERSION ($UPSTREAM_REF)"
