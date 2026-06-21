#!/bin/bash
# Script to create a GCP custom image from disk image (one-shot)
# Usage: ./create-image.sh <project> <arch> [version]
# version can be a GitHub release tag (e.g., v0.1.0) or 'local' to use locally built files

set -euo pipefail

# Find gcloud: check local installation first, then system
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -x "${SCRIPT_DIR}/gcloud" ]; then
    GCLOUD="${SCRIPT_DIR}/gcloud"
elif [ -x "${SCRIPT_DIR}/google-cloud-sdk/bin/gcloud" ]; then
    GCLOUD="${SCRIPT_DIR}/google-cloud-sdk/bin/gcloud"
elif command -v gcloud &> /dev/null; then
    GCLOUD="gcloud"
else
    echo "Error: gcloud not found. Install it with:"
    echo "  ./install-gcloud.sh"
    exit 1
fi

if [ $# -lt 2 ]; then
    echo "Usage: $0 <project> <arch> [version]"
    echo "Example: $0 my-gcp-project x86_64 v0.1.0    # Use GitHub release"
    echo "Example: $0 my-gcp-project x86_64 local     # Use local build"
    exit 1
fi

PROJECT="$1"
ARCH="$2"
VERSION="${3:-local}"

# Validate architecture
if [ "${ARCH}" != "x86_64" ] && [ "${ARCH}" != "aarch64" ]; then
    echo "Error: Architecture must be either 'x86_64' or 'aarch64'"
    exit 1
fi

# Map to GCP architecture naming
if [ "${ARCH}" == "aarch64" ]; then
    GCP_ARCH="ARM64"
else
    GCP_ARCH="X86_64"
fi

# Download and verify from GitHub release or use local files
if [ "${VERSION}" != "local" ]; then
    echo "=== Downloading release ${VERSION} from GitHub ==="

    # Create temporary directory for downloads
    TEMP_DIR=$(mktemp -d)
    trap "rm -rf ${TEMP_DIR}" EXIT

    # Determine GitHub repository from git remote
    GH_REPO=$(git remote get-url origin | sed 's/.*github.com[:/]\(.*\)\.git/\1/' || echo "")
    if [ -z "${GH_REPO}" ]; then
        echo "Error: Could not determine GitHub repository"
        exit 1
    fi

    echo "Repository: ${GH_REPO}"
    echo "Downloading stage0-${ARCH}.zip from release ${VERSION}..."

    # The image boots stage0 (the firmware-admitted root of trust), so it is built
    # from the stage0 release artifacts (boot.disk + Secure Boot certs). Use a
    # stage0-v* release tag here.
    gh release download "${VERSION}" \
        --repo "${GH_REPO}" \
        --pattern "stage0-${ARCH}.zip" \
        --dir "${TEMP_DIR}"

    echo "Verifying attestation..."
    # Verify the attestation using gh
    gh attestation verify "${TEMP_DIR}/stage0-${ARCH}.zip" \
        --repo "${GH_REPO}" \
        || { echo "Error: Attestation verification failed"; exit 1; }

    echo "Extracting files..."
    unzip -q "${TEMP_DIR}/stage0-${ARCH}.zip" -d "${TEMP_DIR}"

    # Use extracted files
    WORK_DIR="${TEMP_DIR}"
    echo "Using verified release files from ${VERSION}"
else
    echo "=== Using local build files ==="
    # Get script directory and compute repo root
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
    WORK_DIR="${REPO_ROOT}/tools/build-stage0/${ARCH}"
fi

IMAGE_FILE="${WORK_DIR}/boot.disk"
OS_RELEASE_FILE="${WORK_DIR}/os-release"

# Get keys directory: from extracted release (flat) or from repo (keys/ subdir)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
if [ -f "${WORK_DIR}/db.cer" ]; then
    KEYS_DIR="${WORK_DIR}"
else
    KEYS_DIR="${REPO_ROOT}/tools/build-uki/keys"
fi

if [ ! -f "${OS_RELEASE_FILE}" ]; then
    echo "Error: ${OS_RELEASE_FILE} not found"
    exit 1
fi

if [ ! -f "${IMAGE_FILE}" ]; then
    echo "Error: ${IMAGE_FILE} not found"
    exit 1
fi

# Check for UEFI Secure Boot keys
if [ ! -f "${KEYS_DIR}/PK.cer" ] || [ ! -f "${KEYS_DIR}/KEK.cer" ] || [ ! -f "${KEYS_DIR}/db.cer" ]; then
    echo "Error: UEFI Secure Boot keys not found in ${KEYS_DIR}"
    echo "Required: PK.cer, KEK.cer, db.cer"
    exit 1
fi

# Source os-release to get ID, VERSION_ID, BUILD_ID, NAME, VERSION
source "${OS_RELEASE_FILE}"

# Create simple image name: lockboot-x86-64-26-02-al2023
# (Only one release per month, so BUILD_ID hash not needed in name)
# GCP image names: lowercase, numbers, hyphens only (no underscores)
VERSION_DASH=$(echo "${VERSION_ID}" | tr '.' '-')
ARCH_DASH=$(echo "${ARCH}" | tr '_' '-')
IMAGE_NAME="${ID}-${ARCH_DASH}-${VERSION_DASH}"
IMAGE_DESC="${PRETTY_NAME} version: ${VERSION_ID} build: ${BUILD_ID} arch: ${ARCH}"
IMAGE_FAMILY="${ID}"  # Just "lockboot" - family groups all architectures together

# Map to GCP architecture naming for --architecture flag
if [ "${ARCH}" == "aarch64" ]; then
    GCP_ARCH="ARM64"
else
    GCP_ARCH="X86_64"
fi

# Set guest OS features based on architecture
if [ "${ARCH}" == "x86_64" ]; then
    # x86_64: Enable SEV and SEV-SNP for Confidential VMs
    # GVNIC required for Confidential Compute (gve driver needed in kernel)
    GUEST_OS_FEATURES="UEFI_COMPATIBLE,SEV_CAPABLE,SEV_SNP_CAPABLE,GVNIC"
else
    # aarch64: UEFI + GVNIC (Confidential Compute automatic)
    GUEST_OS_FEATURES="UEFI_COMPATIBLE,GVNIC"
fi

echo ""
echo "=== Checking for existing image ==="
EXISTING_IMAGE=$(${GCLOUD} compute images list \
    --project="${PROJECT}" \
    --filter="name=${IMAGE_NAME}" \
    --format="value(name)" \
    2>/dev/null || echo "")

if [ -n "${EXISTING_IMAGE}" ]; then
    echo "Found existing image: ${EXISTING_IMAGE}"
    echo "Image already exists, skipping creation"
    IMAGE_FINAL="${EXISTING_IMAGE}"
else
    echo "No existing image found, creating new one..."
    echo ""

    # Use bucket name from os-release ID
    GCS_BUCKET="${ID}"
    # GCP requires .tar.gz format containing disk.raw
    # Path: gs://lockboot/26.02.al2023/kernel-...-7f25e43a.tar.gz
    GCS_PATH="${VERSION_ID}/${BUILD_ID}.tar.gz"
    GCS_URI="gs://${GCS_BUCKET}/${GCS_PATH}"

    echo "=== Checking/Creating Google Cloud Storage Bucket ==="
    echo "Bucket: ${GCS_BUCKET}"
    echo ""

    # Check if bucket exists, create if not
    if ${GCLOUD} storage buckets describe "gs://${GCS_BUCKET}" --project="${PROJECT}" &>/dev/null; then
        echo "Bucket already exists: gs://${GCS_BUCKET}"
    else
        # Get default region from gcloud config (falls back to compute/region or us-central1)
        DEFAULT_LOCATION=$(${GCLOUD} config get-value compute/region 2>/dev/null || echo "us-central1")
        echo "Creating bucket: gs://${GCS_BUCKET} in ${DEFAULT_LOCATION}"
        ${GCLOUD} storage buckets create "gs://${GCS_BUCKET}" \
            --project="${PROJECT}" \
            --location="${DEFAULT_LOCATION}" \
            --uniform-bucket-level-access
    fi

    echo ""
    echo "=== Preparing disk image for GCP ==="
    echo "GCP requires: .tar.gz containing disk.raw"
    echo ""

    # Create temporary tar.gz if it doesn't exist in GCS
    if ${GCLOUD} storage ls "${GCS_URI}" --project="${PROJECT}" &>/dev/null; then
        echo "Image already exists in GCS: ${GCS_URI}"
    else
        # Create tar.gz with disk.raw inside (GCP requirement)
        # Use --format=oldgnu and -S for sparse file handling
        TEMP_DIR=$(mktemp -d)
        trap "rm -rf ${TEMP_DIR}" EXIT

        echo "Creating tar.gz with disk.raw inside..."
        cp "${IMAGE_FILE}" "${TEMP_DIR}/disk.raw"

        echo "Compressing (this may take a minute)..."
        tar --format=oldgnu -Sczf "${TEMP_DIR}/${BUILD_ID}.tar.gz" -C "${TEMP_DIR}" disk.raw

        echo ""
        echo "=== Uploading to Google Cloud Storage ==="
        echo "Path: ${GCS_PATH}"
        echo ""

        echo "Uploading ${BUILD_ID}.tar.gz to ${GCS_URI} with metadata..."
        # Upload with metadata from os-release
        ${GCLOUD} storage cp "${TEMP_DIR}/${BUILD_ID}.tar.gz" "${GCS_URI}" \
            --project="${PROJECT}" \
            --custom-metadata="version-id=${VERSION_ID},build-id=${BUILD_ID},name=${NAME},pretty-name=${PRETTY_NAME},id=${ID},arch=${ARCH}"
    fi

    echo ""
    echo "=== Creating GCP Image from GCS ==="
    echo "Image name: ${IMAGE_NAME}"
    echo "Family: ${IMAGE_FAMILY}"
    echo "Architecture: ${GCP_ARCH}"
    echo "Guest OS features: ${GUEST_OS_FEATURES}"
    echo "UEFI Secure Boot: Custom keys (PK, KEK, db)"
    echo ""

    # Create image from GCS with custom guest OS features and Secure Boot keys
    # Note: Full build details are in the image name and description
    ${GCLOUD} compute images create "${IMAGE_NAME}" \
        --project="${PROJECT}" \
        --source-uri="${GCS_URI}" \
        --guest-os-features="${GUEST_OS_FEATURES}" \
        --architecture="${GCP_ARCH}" \
        --family="${IMAGE_FAMILY}" \
        --description="${IMAGE_DESC}" \
        --platform-key-file="${KEYS_DIR}/PK.cer" \
        --key-exchange-key-file="${KEYS_DIR}/KEK.cer" \
        --signature-database-file="${KEYS_DIR}/db.cer"

    IMAGE_FINAL="${IMAGE_NAME}"
fi

echo ""
echo "=== Image Created Successfully ==="
echo "Image: ${IMAGE_FINAL}"
echo "Project: ${PROJECT}"
echo "Family: ${IMAGE_FAMILY}"
echo "Architecture: ${GCP_ARCH}"
echo ""

# Get default zone from gcloud config
DEFAULT_ZONE=$(${GCLOUD} config get-value compute/zone 2>/dev/null || echo "us-central1-a")

# Suggest appropriate machine type based on architecture
if [ "${ARCH}" == "aarch64" ]; then
    MACHINE_TYPE="t2a-standard-1"
    TECH="ARM TrustZone"
else
    MACHINE_TYPE="n2d-standard-2"
    TECH="AMD SEV-SNP"
fi

echo "Launch a Confidential VM instance using:"
echo ""
echo "  ./launch-instance.sh my-instance ${DEFAULT_ZONE} ${MACHINE_TYPE} ${IMAGE_FINAL} config.json"
echo ""
echo "Or use gcloud directly:"
echo "  ${GCLOUD} compute instances create my-instance \\"
echo "    --zone=${DEFAULT_ZONE} \\"
echo "    --machine-type=${MACHINE_TYPE} \\"
echo "    --image=${IMAGE_FINAL} \\"
echo "    --metadata-from-file=user-data=config.json \\"
echo "    --confidential-compute-type=SEV \\"
echo "    --maintenance-policy=TERMINATE \\"
echo "    --shielded-secure-boot \\"
echo "    --shielded-vtpm \\"
echo "    --shielded-integrity-monitoring"
echo ""
echo "Confidential compute technology: ${TECH}"
echo "Default zone: ${DEFAULT_ZONE} (configure with: ${GCLOUD} config set compute/zone <zone>)"
