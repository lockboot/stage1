#!/bin/bash
# Download a Fedora RPM and verify BOTH its SHA256 pin and its Fedora GPG signature. All four args are
# required -- there is deliberately no way to fetch an RPM here without signature verification. (Busybox
# is an Alpine .apk with no Fedora signature and uses download-and-verify.sh instead.)
set -euo pipefail

OUT="${1:-}"
SHA="${2:-}"
URL="${3:-}"
KEY="${4:-}"
if [ -z "$OUT" ] || [ -z "$SHA" ] || [ -z "$URL" ] || [ -z "$KEY" ]; then
    echo "usage: $0 <output_file> <expected_sha256> <url> <gpg_key>" >&2
    exit 1
fi

HERE="$(dirname "$0")"
mkdir -p "$(dirname "$OUT")"

[ -f "$OUT" ] || wget -q -O "$OUT" "$URL"

if ! echo "${SHA}  ${OUT}" | sha256sum -c - >/dev/null 2>&1; then
    echo "SHA256 mismatch: $OUT" >&2
    rm -f "$OUT"
    exit 1
fi

if ! "$HERE/verify-rpm-gpg.sh" "$OUT" "$KEY"; then
    rm -f "$OUT"
    exit 1
fi
