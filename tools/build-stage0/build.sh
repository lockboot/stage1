#!/bin/bash
# Build a bootable disk image that boots stage0.efi directly (no kernel/UKI).
#
# Mirrors tools/build-uki/build.sh's ESP/disk logic, but the payload on the ESP
# is the signed stage0 UEFI application instead of a Unified Kernel Image.
#
# Requires privilege for losetup/mount (run inside the privileged build docker,
# or with sudo on the host). Reuses the Secure Boot keys from tools/build-uki/keys.
set -euox pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

ARCH="${ARCH:-x86_64}"
KEYDIR="${REPO_ROOT}/tools/build-uki/keys"
OUTPUT_DIR="${OUTPUT_DIR:-${SCRIPT_DIR}/${ARCH}}"
STAGE0_EFI="${STAGE0_EFI:-${OUTPUT_DIR}/stage0.efi}"

case "${ARCH}" in
  x86_64)  BOOT_EFI="BOOTX64.EFI" ;;
  aarch64) BOOT_EFI="BOOTAA64.EFI" ;;
  *) echo "Unsupported ARCH: ${ARCH}"; exit 1 ;;
esac

if [ ! -f "${STAGE0_EFI}" ]; then
    echo "Error: stage0 EFI binary not found at ${STAGE0_EFI}"
    echo "Build it first: make tools/build-stage0/${ARCH}/stage0.efi"
    exit 1
fi

mkdir -p "${OUTPUT_DIR}"

# --- Sign stage0.efi for Secure Boot (same db key as the UKI) ---
SIGNED_EFI="${OUTPUT_DIR}/${BOOT_EFI}"
echo "=== Signing stage0.efi ==="
sbsign --key "${KEYDIR}/db.crt.key" --cert "${KEYDIR}/db.crt" --output "${SIGNED_EFI}" "${STAGE0_EFI}"

# --- Create the bootable GPT + FAT32 disk ---
echo "=== Creating bootable disk image ==="
EFI_SIZE_BYTES=$(stat -c%s "${SIGNED_EFI}")
EFI_SIZE_MB=$((EFI_SIZE_BYTES / 1024 / 1024 + 1))
PARTITION_SIZE_MB=$((EFI_SIZE_MB * 3 / 2))
if [ ${PARTITION_SIZE_MB} -lt 64 ]; then PARTITION_SIZE_MB=64; fi
DISK_SIZE_MB=$((PARTITION_SIZE_MB + 2))

DISK_IMAGE="${OUTPUT_DIR}/boot.disk"
dd if=/dev/zero of="${DISK_IMAGE}" bs=1M count=${DISK_SIZE_MB} status=none

# Deterministic GUIDs/volume-id derived from the signed binary's hash.
EFI_HASH=$(sha256sum "${SIGNED_EFI}" | cut -d' ' -f1)
DISK_GUID="${EFI_HASH:0:8}-${EFI_HASH:8:4}-${EFI_HASH:12:4}-${EFI_HASH:16:4}-${EFI_HASH:20:12}"
PART_GUID="${EFI_HASH:32:8}-${EFI_HASH:36:4}-${EFI_HASH:40:4}-${EFI_HASH:44:4}-${EFI_HASH:48:12}"
VOLUME_ID="${EFI_HASH:0:8}"

sfdisk "${DISK_IMAGE}" <<EOF
label: gpt
label-id: ${DISK_GUID}
first-lba: 2048
unit: sectors

start=2048, size=$((((DISK_SIZE_MB - 1) * 1024 * 1024 / 512) - 2048)), type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, uuid=${PART_GUID}, name="EFI System Partition"
EOF

PART_INFO=$(sfdisk -d "${DISK_IMAGE}" | grep "start=" | head -1)
PART_START_SECTOR=$(echo "${PART_INFO}" | sed -n 's/.*start=\s*\([0-9]*\).*/\1/p')
PART_OFFSET=$((PART_START_SECTOR * 512))

LOOP_DEVICE=$(losetup -f --show -o "${PART_OFFSET}" "${DISK_IMAGE}")
mkfs.vfat -F 32 -n "EFISYS" -i "${VOLUME_ID}" "${LOOP_DEVICE}"

MOUNT_DIR="${OUTPUT_DIR}/tmp/esp-mount-$$"
mkdir -p "${MOUNT_DIR}"
mount -o noatime,nodiratime,tz=UTC "${LOOP_DEVICE}" "${MOUNT_DIR}"
mkdir -p "${MOUNT_DIR}/EFI/BOOT"
cp "${SIGNED_EFI}" "${MOUNT_DIR}/EFI/BOOT/${BOOT_EFI}"
find "${MOUNT_DIR}" -exec touch -h -d "1980-01-01 00:00:00 UTC" {} +
sync
umount "${MOUNT_DIR}"
rmdir "${MOUNT_DIR}"
losetup -d "${LOOP_DEVICE}"
rm -rf "${OUTPUT_DIR}/tmp"

if [ -x "${REPO_ROOT}/tools/build-uki/normalize-fat-timestamps.py" ]; then
    "${REPO_ROOT}/tools/build-uki/normalize-fat-timestamps.py" "${DISK_IMAGE}" "${PART_OFFSET}" || true
fi

echo "Disk image created: ${DISK_IMAGE}"
ls -lh "${DISK_IMAGE}"

# --- Generate Secure Boot variables (OVMF + AWS), same keys as the UKI ---
if [ "${ARCH}" = "x86_64" ]; then
    OVMF_VARS_ORIG="/usr/share/OVMF/OVMF_VARS_4M.fd"
else
    OVMF_VARS_ORIG="/usr/share/AAVMF/AAVMF_VARS.snakeoil.fd"
fi
EFI_VARS_OVMF="${OUTPUT_DIR}/efi-vars.ovmf"
EFI_VARS_AWS="${OUTPUT_DIR}/efi-vars.aws"
if [ -f "${OVMF_VARS_ORIG}" ]; then
    virt-fw-vars --input "${OVMF_VARS_ORIG}" --output "${EFI_VARS_OVMF}" --output-aws "${EFI_VARS_AWS}" \
      --add-db "$(cat "${KEYDIR}/db.guid")" "${KEYDIR}/db.crt" \
      --add-kek "$(cat "${KEYDIR}/KEK.guid")" "${KEYDIR}/KEK.crt" \
      --set-pk "$(cat "${KEYDIR}/PK.guid")" "${KEYDIR}/PK.crt" \
      --set-true DeployedMode \
      --secure-boot
    echo "EFI vars written: ${EFI_VARS_OVMF}"
else
    echo "Warning: ${OVMF_VARS_ORIG} not found; skipping EFI vars generation."
fi

# Emit os-release so the cloud publishers can name/tag the image (mirrors
# build-uki). BUILD_ID is derived from the signed stage0 hash so each build is
# traceable and distinct from UKI AMIs.
OSREL_PATH="${OUTPUT_DIR}/os-release"
YEAR_MONTH=$(date +%y.%m)
{
  echo "ID=lockboot"
  echo "VERSION_ID=${YEAR_MONTH}"
  echo "NAME=\"Lock.Boot stage0\""
  echo "PRETTY_NAME=\"Lock.Boot stage0 ${YEAR_MONTH} ${ARCH}\""
  echo "BUILD_ID=stage0-${EFI_HASH:0:12}"
} > "${OSREL_PATH}"

# Copy the public Secure Boot enrollment material next to boot.disk + efi-vars so
# the GCP publisher (and manual enrollment) gets the certs in one release bundle.
# The private *.crt.key is intentionally NOT copied (ephemeral, stays in keys/).
for f in db.cer db.guid PK.cer PK.guid KEK.cer KEK.guid; do
    [ -f "${KEYDIR}/${f}" ] && cp "${KEYDIR}/${f}" "${OUTPUT_DIR}/"
done

if [ -n "${OWNER_UID:-}" ] && [ -n "${OWNER_GID:-}" ]; then
    chown -R "${OWNER_UID}:${OWNER_GID}" "${OUTPUT_DIR}"
fi
