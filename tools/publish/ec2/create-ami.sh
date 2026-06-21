#!/bin/bash
# Script to upload disk image to S3 and create an AMI
# Usage: ./create-ami.sh <region> <arch> [version]
# S3 bucket name is derived from os-release ID field
# version can be a GitHub release tag (e.g., v0.1.0) or 'local' to use locally built files

set -euo pipefail

if [ $# -lt 2 ]; then
    echo "Usage: $0 <region> <arch> [version]"
    echo "Example: $0 us-east-1 x86_64 v0.1.0    # Use GitHub release"
    echo "Example: $0 us-east-1 x86_64 local     # Use local build"
    exit 1
fi

REGION="$1"
ARCH="$2"
VERSION="${3:-local}"

# Validate architecture
if [ "${ARCH}" != "x86_64" ] && [ "${ARCH}" != "aarch64" ]; then
    echo "Error: Architecture must be either 'x86_64' or 'aarch64'"
    exit 1
fi

# Map to EC2 architecture naming
if [ "${ARCH}" == "aarch64" ]; then
    EC2_ARCH="arm64"
else
    EC2_ARCH="${ARCH}"
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

    # The AMI boots stage0 (the firmware-admitted root of trust), so the cloud
    # image is built from the stage0 release artifacts, not the UKI. Use a
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
UEFI_DATA_FILE="${WORK_DIR}/efi-vars.aws"
OS_RELEASE_FILE="${WORK_DIR}/os-release"

if [ ! -f "${OS_RELEASE_FILE}" ]; then
    echo "Error: ${OS_RELEASE_FILE} not found"
    exit 1
fi

if [ ! -f "${IMAGE_FILE}" ]; then
    echo "Error: ${IMAGE_FILE} not found"
    exit 1
fi

if [ ! -f "${UEFI_DATA_FILE}" ]; then
    echo "Error: ${UEFI_DATA_FILE} not found"
    exit 1
fi

# Source os-release to get ID, VERSION_ID, BUILD_ID, NAME, VERSION
source "${OS_RELEASE_FILE}"

# Use ID from os-release as the S3 bucket name
S3_BUCKET="${ID}"

# Compute SHA256 hash of the image file
echo "Computing SHA256 hash of ${IMAGE_FILE}..."
IMAGE_SHA256=$(sha256sum "${IMAGE_FILE}" | awk '{print $1}')

# Construct S3 key without ID prefix (since bucket name is ID)
S3_KEY="${VERSION_ID}/uefi-bootdisk/${BUILD_ID}"

# Create consistent naming and descriptions
AMI_NAME="${ID}-${ARCH}-${VERSION_ID}-${BUILD_ID}"
SNAPSHOT_DESC="${AMI_NAME}"
AMI_DESC="${PRETTY_NAME} build: ${BUILD_ID}"

echo "=== Checking for existing snapshot ==="
EXISTING_SNAPSHOT=$(aws ec2 describe-snapshots \
    --region "${REGION}" \
    --owner-ids self \
    --filters "Name=tag:BuildID,Values=${BUILD_ID}" \
    --query 'Snapshots[0].SnapshotId' \
    --output text 2>/dev/null || echo "None")

if [ "${EXISTING_SNAPSHOT}" != "None" ] && [ "${EXISTING_SNAPSHOT}" != "" ] && [ "${EXISTING_SNAPSHOT}" != "null" ]; then
    echo "Found existing snapshot: ${EXISTING_SNAPSHOT}"
    SNAPSHOT_ID="${EXISTING_SNAPSHOT}"
else
    echo "No existing snapshot found, creating new one..."
    echo ""
    echo "=== Checking if image exists in S3 ==="
    S3_KEY="${S3_KEY}.vmdk"
    if aws s3api head-object --bucket "${S3_BUCKET}" --key "${S3_KEY}" --region "${REGION}" &>/dev/null; then
        echo "Image already exists in S3: s3://${S3_BUCKET}/${S3_KEY}"
    else
        echo "Converting raw disk to stream-optimized VMDK (compresses sparse regions)..."
        VMDK_FILE="${WORK_DIR}/boot.vmdk"
        qemu-img convert -f raw -O vmdk -o subformat=streamOptimized "${IMAGE_FILE}" "${VMDK_FILE}"
        RAW_SIZE=$(stat -c%s "${IMAGE_FILE}" 2>/dev/null || stat -f%z "${IMAGE_FILE}")
        VMDK_SIZE=$(stat -c%s "${VMDK_FILE}" 2>/dev/null || stat -f%z "${VMDK_FILE}")
        echo "Compressed: $(( RAW_SIZE / 1024 / 1024 ))MB raw -> $(( VMDK_SIZE / 1024 / 1024 ))MB vmdk"

        echo "Uploading VMDK to S3..."
        echo "Bucket: s3://${S3_BUCKET}/${S3_KEY}"
        aws s3 cp "${VMDK_FILE}" "s3://${S3_BUCKET}/${S3_KEY}" --region "${REGION}"
        rm -f "${VMDK_FILE}"
    fi

    echo ""
    echo "=== Creating snapshot from S3 image ==="

    # Create containers.json for import using metadata
    cat > containers.json << EOF
{
  "Description": "${SNAPSHOT_DESC}",
  "Format": "vmdk",
  "UserBucket": {
    "S3Bucket": "${S3_BUCKET}",
    "S3Key": "${S3_KEY}"
  }
}
EOF

    # Import snapshot
    echo "Importing snapshot..."
    IMPORT_TASK_ID=$(aws ec2 import-snapshot \
        --region "${REGION}" \
        --disk-container "file://containers.json" \
        --query 'ImportTaskId' \
        --output text)

    rm containers.json

    echo "Import task ID: ${IMPORT_TASK_ID}"
    echo "Waiting for snapshot import to complete..."

    # Wait for import to complete
    while true; do
        STATUS=$(aws ec2 describe-import-snapshot-tasks \
            --region "${REGION}" \
            --import-task-ids "${IMPORT_TASK_ID}" \
            --query 'ImportSnapshotTasks[0].SnapshotTaskDetail.Status' \
            --output text)

        if [ "${STATUS}" = "completed" ]; then
            SNAPSHOT_ID=$(aws ec2 describe-import-snapshot-tasks \
                --region "${REGION}" \
                --import-task-ids "${IMPORT_TASK_ID}" \
                --query 'ImportSnapshotTasks[0].SnapshotTaskDetail.SnapshotId' \
                --output text)
            echo "Snapshot created: ${SNAPSHOT_ID}"

            # Tag the snapshot for easier identification
            echo "Tagging snapshot..."
            aws ec2 create-tags \
                --region "${REGION}" \
                --resources "${SNAPSHOT_ID}" \
                --tags "Key=Name,Value=${SNAPSHOT_DESC}" \
                       "Key=BuildID,Value=${BUILD_ID}" \
                       "Key=VersionID,Value=${VERSION_ID}"
            break
        elif [ "${STATUS}" = "deleted" ] || [ "${STATUS}" = "deleting" ]; then
            echo "Error: Import task failed or was deleted"
            exit 1
        fi

        echo "Status: ${STATUS} - waiting..."
        sleep 10
    done
fi

# Check for existing AMI
echo ""
echo "=== Checking for existing AMI ==="
EXISTING_AMI=$(aws ec2 describe-images \
    --region "${REGION}" \
    --owners self \
    --filters "Name=name,Values=${AMI_NAME}" \
    --query 'Images[0].ImageId' \
    --output text 2>/dev/null || echo "None")

if [ "${EXISTING_AMI}" != "None" ] && [ "${EXISTING_AMI}" != "" ] && [ "${EXISTING_AMI}" != "null" ]; then
    echo "Found existing AMI: ${EXISTING_AMI}"
    AMI_ID="${EXISTING_AMI}"
else
    echo "No existing AMI found, registering new one..."

    # Register AMI from snapshot
    echo "Registering AMI from snapshot..."
    AMI_ID=$(aws ec2 register-image \
        --region "${REGION}" \
        --name "${AMI_NAME}" \
        --description "${AMI_DESC}" \
        --architecture "${EC2_ARCH}" \
        --root-device-name /dev/xvda \
        --boot-mode uefi \
        --uefi-data "$(cat ${UEFI_DATA_FILE})" \
        --tpm-support v2.0 \
        --imds-support v2.0 \
        --virtualization-type hvm \
        --ena-support \
        --block-device-mappings "DeviceName=/dev/xvda,Ebs={SnapshotId=${SNAPSHOT_ID}}" \
        --query 'ImageId' \
        --output text)

    echo "AMI registered: ${AMI_ID}"

    # Tag the AMI for easier identification
    echo "Tagging AMI..."
    aws ec2 create-tags \
        --region "${REGION}" \
        --resources "${AMI_ID}" \
        --tags "Key=Name,Value=${PRETTY_NAME}" \
               "Key=BuildID,Value=${BUILD_ID}" \
               "Key=VersionID,Value=${VERSION_ID}"
fi

echo ""
echo "=== AMI Created Successfully ==="
echo "AMI ID: ${AMI_ID}"
echo "Region: ${REGION}"
echo "Architecture: ${EC2_ARCH}"
echo ""

# Suggest appropriate instance type based on architecture
if [ "${ARCH}" == "aarch64" ]; then
    INSTANCE_TYPE="c7g.medium"
else
    INSTANCE_TYPE="c6i.large"
fi

echo "Launch an instance:"
echo "  aws ec2 run-instances --image-id ${AMI_ID} --instance-type ${INSTANCE_TYPE} --region ${REGION} --user-data file://config.json"
echo ""
echo "Launch with spot pricing (up to 90% cheaper):"
echo "  aws ec2 run-instances --image-id ${AMI_ID} --instance-type ${INSTANCE_TYPE} --region ${REGION} --user-data file://config.json \\"
echo "    --instance-market-options '{\"MarketType\":\"spot\",\"SpotOptions\":{\"SpotInstanceType\":\"one-time\"}}'"
echo ""
echo "Get serial console output:"
echo "  aws ec2 get-console-output --output text --latest --region ${REGION} --instance-id <instance-id>"
