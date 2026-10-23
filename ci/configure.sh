#!/usr/bin/env bash
# Patches ./upstream for the server the repository variables name or, when
# none is named, for the development server of config/dev. Prints
# target=server|dev to $GITHUB_OUTPUT: only a server build gets signed.
#
# Environment: SERVER_IPV4, SERVER_PORT, SERVER_IPV6 (optional),
# RSA_PUBLIC_KEY (PKCS#1 PEM), GOOGLE_SERVICES_JSON (optional), ABIS
# (optional), CCACHE=1 to compile the native code through ccache.
set -euo pipefail
cd "$(dirname "$0")/.."

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

if [ -n "${SERVER_IPV4:-}${SERVER_PORT:-}${RSA_PUBLIC_KEY:-}" ]; then
	# Half a configuration would build a client that cannot sign in.
	for v in SERVER_IPV4 SERVER_PORT RSA_PUBLIC_KEY; do
		if [ -z "${!v:-}" ]; then
			echo "configure: PLUMA_$v is not set, while other server variables are" >&2
			exit 1
		fi
	done
	printf '%s\n' "$RSA_PUBLIC_KEY" >"$tmp/key.pem"
	target=server
else
	. config/dev/server.env
	SERVER_IPV4=$PLUMA_SERVER_IPV4
	SERVER_PORT=$PLUMA_SERVER_PORT
	cp config/dev/server_public.pem "$tmp/key.pem"
	target=dev
fi

args=(--source upstream --upstream upstream.env --app config/app.env
	--server-ipv4 "$SERVER_IPV4" --server-port "$SERVER_PORT" --rsa-public-key "$tmp/key.pem")
if [ -n "${SERVER_IPV6:-}" ]; then
	args+=(--server-ipv6 "$SERVER_IPV6")
fi
if [ -n "${GOOGLE_SERVICES_JSON:-}" ]; then
	printf '%s' "$GOOGLE_SERVICES_JSON" >"$tmp/google-services.json"
	args+=(--google-services "$tmp/google-services.json")
fi
if [ -n "${ABIS:-}" ]; then
	args+=(--abis "$ABIS")
fi
if [ "${CCACHE:-}" = 1 ]; then
	args+=(--ccache)
fi
python3 -I ci/patch.py "${args[@]}"
echo "configure: $target build"
echo "target=$target" >>"${GITHUB_OUTPUT:-/dev/null}"
