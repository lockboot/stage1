#!/bin/bash
# Publish a netboot UKI (linux.efi) so stage0 can fetch it, and print the matching
# _stage1 user-data block (sha256 admission mode).
#
# Unlike the stage0 publishers (which bake a cloud image), the UKI is just a file
# served over HTTP(S): stage0 downloads it, verifies the pinned sha256, measures
# it into PCR 14, and chain-loads it. The pin MUST be the sha256 of the FINAL
# (post-sbsign) linux.efi — exactly the bytes uploaded here.
#
# Usage: ./publish.sh <dest-uri> <arch> [version]
#   dest-uri : s3://bucket/prefix   or   gs://bucket/prefix
#   arch     : x86_64 | aarch64
#   version  : a uki-v* release tag, or 'local' (default) to use a local build
#
# Example: ./publish.sh s3://lockboot/uki x86_64 uki-v0.1.0
#          ./publish.sh gs://lockboot/uki aarch64 local

set -euo pipefail

if [ $# -lt 2 ]; then
    echo "Usage: $0 <s3://bucket/prefix | gs://bucket/prefix> <x86_64|aarch64> [version]"
    exit 1
fi

DEST_URI="${1%/}"   # strip trailing slash
ARCH="$2"
VERSION="${3:-local}"

if [ "${ARCH}" != "x86_64" ] && [ "${ARCH}" != "aarch64" ]; then
    echo "Error: arch must be x86_64 or aarch64"; exit 1
fi

# Resolve the UKI: local build, or a verified uki-v* release artifact.
if [ "${VERSION}" != "local" ]; then
    TEMP_DIR=$(mktemp -d); trap "rm -rf ${TEMP_DIR}" EXIT
    GH_REPO=$(git remote get-url origin | sed 's/.*github.com[:/]\(.*\)\.git/\1/' || echo "")
    [ -n "${GH_REPO}" ] || { echo "Error: could not determine GitHub repository"; exit 1; }
    echo "Downloading uki-${ARCH}.zip from release ${VERSION}..."
    gh release download "${VERSION}" --repo "${GH_REPO}" --pattern "uki-${ARCH}.zip" --dir "${TEMP_DIR}"
    gh attestation verify "${TEMP_DIR}/uki-${ARCH}.zip" --repo "${GH_REPO}" \
        || { echo "Error: attestation verification failed"; exit 1; }
    unzip -q "${TEMP_DIR}/uki-${ARCH}.zip" -d "${TEMP_DIR}"
    WORK_DIR="${TEMP_DIR}"
else
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
    WORK_DIR="${REPO_ROOT}/tools/build-uki/${ARCH}"
fi

UKI_FILE="${WORK_DIR}/linux.efi"
[ -f "${UKI_FILE}" ] || { echo "Error: ${UKI_FILE} not found (build the UKI first)"; exit 1; }

# Pin = sha256 of the bytes we upload. Cross-check against the build's recorded
# pin if present, to catch a stale/mismatched linux.efi.sha256.
SHA256=$(sha256sum "${UKI_FILE}" | awk '{print $1}')
if [ -f "${WORK_DIR}/linux.efi.sha256" ]; then
    RECORDED=$(awk '{print $1}' "${WORK_DIR}/linux.efi.sha256")
    if [ "${RECORDED}" != "${SHA256}" ]; then
        echo "Error: linux.efi.sha256 (${RECORDED}) != actual (${SHA256})"; exit 1
    fi
fi

KEY="linux-${ARCH}.efi"
OBJECT="${DEST_URI}/${KEY}"

case "${DEST_URI}" in
    s3://*)
        BUCKET="${DEST_URI#s3://}"; BUCKET="${BUCKET%%/*}"
        PREFIX="${DEST_URI#s3://${BUCKET}}"; PREFIX="${PREFIX#/}"
        aws s3 cp "${UKI_FILE}" "${OBJECT}"
        URL="https://${BUCKET}.s3.amazonaws.com/${PREFIX:+${PREFIX}/}${KEY}"
        ;;
    gs://*)
        BUCKET="${DEST_URI#gs://}"; BUCKET="${BUCKET%%/*}"
        PREFIX="${DEST_URI#gs://${BUCKET}}"; PREFIX="${PREFIX#/}"
        gcloud storage cp "${UKI_FILE}" "${OBJECT}"
        URL="https://storage.googleapis.com/${BUCKET}/${PREFIX:+${PREFIX}/}${KEY}"
        ;;
    *)
        echo "Error: dest-uri must start with s3:// or gs://"; exit 1
        ;;
esac

echo "Uploaded: ${OBJECT}"
echo "sha256:   ${SHA256}"
echo ""
echo "Paste into instance user-data (_stage1, sha256 admission mode):"
cat <<SNIPPET
{
  "_stage1": {
    "${ARCH}": { "url": "${URL}", "sha256": "${SHA256}" }
  }
}
SNIPPET
