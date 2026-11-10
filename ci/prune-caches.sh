#!/usr/bin/env bash
# Deletes the caches of this run's branch that a newer one of the same
# kind replaced: prune-caches.sh <key prefix>... Cache entries cannot be
# updated, so every build saves a new one; keeping only the newest of each
# kind on a branch keeps the entries of main from being evicted by those of
# pull requests.
#
# Environment: GH_TOKEN with actions: write, GITHUB_REPOSITORY, GITHUB_REF.
set -euo pipefail
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is not set}" "${GITHUB_REF:?GITHUB_REF is not set}"
if [ $# = 0 ]; then
	echo "usage: prune-caches.sh <key prefix>..." >&2
	exit 2
fi
for prefix in "$@"; do
	ids=$(gh cache list --repo "$GITHUB_REPOSITORY" --ref "$GITHUB_REF" --key "$prefix" \
		--sort created_at --order desc --limit 100 --json id --jq '.[1:][].id')
	n=0
	for id in $ids; do
		gh cache delete --repo "$GITHUB_REPOSITORY" "$id"
		n=$((n + 1))
	done
	echo "prune-caches: $prefix: $n older entries deleted"
done
