#!/bin/bash
# Verify an RPM's GPG signature against a pinned Fedora key, hermetically (throwaway rpmdb, so the
# host/container keyring is never touched). Exits non-zero unless the RPM carries a valid signature
# made by exactly the given key. Used by both download-verify-rpm.sh (build time) and
# update-fedora-deps.py (bump time), so the trust check lives in one place.
set -euo pipefail

RPM="${1:-}"
KEY="${2:-}"
if [ -z "$RPM" ] || [ -z "$KEY" ]; then
    echo "usage: $0 <rpm-file> <gpg-key-file>" >&2
    exit 2
fi
[ -f "$RPM" ] || { echo "no such rpm: $RPM" >&2; exit 2; }
[ -f "$KEY" ] || { echo "no such gpg key: $KEY" >&2; exit 2; }

DB="$(mktemp -d)"
trap 'rm -rf "$DB"' EXIT

rpm --dbpath="$DB" --import "$KEY"
out="$(rpm --dbpath="$DB" -Kv "$RPM" 2>&1)"
echo "$out"

# NOKEY = signed but not by our imported key; BAD / NOT OK = tampered or bad signature.
if echo "$out" | grep -qiE 'NOKEY|BAD|NOT OK'; then
    echo "GPG verify FAILED (untrusted or bad signature): $RPM" >&2
    exit 1
fi
# Require at least one actual signature line to report OK (a digest-only "OK" is not enough).
if ! echo "$out" | grep -qiE 'signature.*key id.*: *OK'; then
    echo "GPG verify FAILED (no valid signature by the pinned key): $RPM" >&2
    exit 1
fi
