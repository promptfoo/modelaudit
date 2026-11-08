#!/usr/bin/env bash
# Reuse only verified bytes, including on a cache hit.
set -euo pipefail

destination=$1
sha256=$2
release_url=$3
asset_api_url=$4

verify() {
  printf '%s  %s\n' "$sha256" "$1" | sha256sum --check --status
}

if [[ -f "$destination" && ! -L "$destination" ]] && verify "$destination"; then
  exit 0
fi

rm -f -- "$destination"
partial=$(mktemp "${destination}.XXXXXX")
trap 'rm -f -- "$partial"' EXIT
download() {
  curl --fail --silent --show-error --location --retry 3 --retry-max-time 90 --connect-timeout 15 --max-time 60 \
    --proto '=https' --proto-redir '=https' --header 'Accept: application/octet-stream' \
    --output "$partial" "$1"
}

download "$release_url" || download "$asset_api_url"
if ! verify "$partial"; then
  echo "SHA-256 mismatch for ${destination##*/}" >&2
  exit 1
fi
mv -- "$partial" "$destination"
