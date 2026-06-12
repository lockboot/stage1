#!/bin/bash
set -euo pipefail

# Get the absolute path of the script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Setup secure boot keys (relative to script directory)
KEYDIR="${SCRIPT_DIR}/keys"

# Get architecture from environment (default to x86_64)
ARCH=${ARCH:-x86_64}

echo "=== Building UKI for Fedora 41 (${ARCH}) ==="

# Output directory (same as dependencies - everything self-contained)
OUTPUT_DIR="${SCRIPT_DIR}/${ARCH}"
mkdir -p "${OUTPUT_DIR}/tmp"

# Determine the correct systemd-efistub filename, PE format, and objcopy command based on architecture
if [ "${ARCH}" = "x86_64" ]; then
    PE_FORMAT="pei-x86-64"
    OBJCOPY="x86_64-linux-gnu-objcopy"
elif [ "${ARCH}" = "aarch64" ]; then
    PE_FORMAT="pei-aarch64-little"
    OBJCOPY="aarch64-linux-gnu-objcopy"
else
    echo "ERROR: Unsupported architecture: ${ARCH}"
    exit 1
fi

# Use systemd-boot stub extracted by Makefile from Fedora 41 RPM (systemd v256)
if [ ! -f "${OUTPUT_DIR}/stub.efi" ]; then
    echo "ERROR: systemd-boot stub not found at ${OUTPUT_DIR}/stub.efi"
    echo "Please run 'make tools/build-uki/${ARCH}/stub.efi' first"
    exit 1
fi

echo "Extracting kernel-core RPM (vmlinuz)..."
rpm2cpio "${OUTPUT_DIR}"/kernel-core-*.rpm | (cd "${OUTPUT_DIR}/tmp" && cpio --quiet -idmu)

echo "Extracting kernel-modules-core RPM (core drivers including gve and ena)..."
rpm2cpio "${OUTPUT_DIR}"/kernel-modules-core-*.rpm | (cd "${OUTPUT_DIR}/tmp" && cpio --quiet -idmu)

if [ ! -d "${OUTPUT_DIR}/tmp/lib/modules" ]; then
    echo "ERROR: kernel modules directory not found after extraction!"
    exit 1
fi
echo "Kernel and modules extracted successfully"

# Find the installed kernel version
KERNEL_VERSION=$(ls "${OUTPUT_DIR}/tmp/lib/modules/" | head -n1)
echo "Kernel version: ${KERNEL_VERSION}"

# Extract kernel config
echo "Extracting kernel config..."
KERNEL_CONFIG_PATH="${OUTPUT_DIR}/config-${KERNEL_VERSION}"

# Config is at output/tmp/lib/modules/${KERNEL_VERSION}/config
MODULES_CONFIG="${OUTPUT_DIR}/tmp/lib/modules/${KERNEL_VERSION}/config"
if [ -f "${MODULES_CONFIG}" ]; then
    cp "${MODULES_CONFIG}" "${KERNEL_CONFIG_PATH}"
    echo "Copied config from ${MODULES_CONFIG}"
else
    echo "Warning: Kernel config not found at ${MODULES_CONFIG}"
fi

# Check for nitro_enclaves config
if [ -f "${KERNEL_CONFIG_PATH}" ]; then
    echo ""
    echo "=== Nitro Enclaves Configuration ==="
    grep -i "NITRO" "${KERNEL_CONFIG_PATH}" || echo "No NITRO_ENCLAVES config found in kernel"
    echo ""
fi

# Build minimal initramfs
echo "Building minimal initramfs..."
INITRD_PATH="${OUTPUT_DIR}/initrd-${KERNEL_VERSION}.img"
INITRAMFS_DIR="${OUTPUT_DIR}/tmp/initramfs-$$"

# Create directory structure
mkdir -p "${INITRAMFS_DIR}"/{bin,sbin,etc,proc,sys,dev,lib,lib64,tmp}

# Copy busybox and create symlinks
echo "Installing busybox..."
cp "${OUTPUT_DIR}/busybox" "${INITRAMFS_DIR}/bin/"

# Copy stage1 binary
echo "Installing stage1..."
cp "${OUTPUT_DIR}/stage1" "${INITRAMFS_DIR}/bin/stage1"
chmod +x "${INITRAMFS_DIR}/bin/stage1"

# Copy required kernel modules
echo "Copying kernel modules..."
MODULES_SRC="${OUTPUT_DIR}/tmp/lib/modules/${KERNEL_VERSION}"
MODULES_DST="${INITRAMFS_DIR}/lib/modules/${KERNEL_VERSION}"
mkdir -p "${MODULES_DST}/kernel/drivers"

# Copy required modules for cloud instances (AWS EC2, GCP Confidential VMs)
# Note: Some modules like virtio, virtio_pci, hw_random, efivarfs are built into the kernel (=y)
REQUIRED_MODULES=(
    # Hardware RNG modules (base is built-in, vendor-specific are modules)
    "drivers/char/hw_random/intel-rng.ko"
    "drivers/char/hw_random/amd-rng.ko"

    # Network modules needed by virtio_net
    "net/core/failover.ko"
    "drivers/net/net_failover.ko"
    "drivers/net/virtio_net.ko"

    # EC2 ENA network driver (for AWS EC2 instances)
    "drivers/net/ethernet/amazon/ena/ena.ko"

    # GCP GVE network driver (for GCP Confidential VMs)
    "drivers/net/ethernet/google/gve/gve.ko"

    # Vsock modules
    "net/vmw_vsock/vsock.ko"
    "net/vmw_vsock/vmw_vsock_virtio_transport_common.ko"

    # Vhost dependencies
    "drivers/vhost/vhost_iotlb.ko"
    "drivers/vhost/vhost.ko"
    "drivers/vhost/vhost_vsock.ko"

    # Nitro Enclaves
    "drivers/misc/nsm.ko"
    "drivers/virt/nitro_enclaves/nitro_enclaves.ko"
)

for mod_path in "${REQUIRED_MODULES[@]}"; do
    # Try both .ko and .ko.xz (Fedora compresses modules, need to decompress for busybox modprobe)
    if [ -f "${MODULES_SRC}/kernel/${mod_path}" ]; then
        mod_dir=$(dirname "${mod_path}")
        mkdir -p "${MODULES_DST}/kernel/${mod_dir}"
        cp "${MODULES_SRC}/kernel/${mod_path}" "${MODULES_DST}/kernel/${mod_dir}/"
        echo "  Copied ${mod_path}"
    elif [ -f "${MODULES_SRC}/kernel/${mod_path}.xz" ]; then
        mod_dir=$(dirname "${mod_path}")
        mkdir -p "${MODULES_DST}/kernel/${mod_dir}"
        # Decompress xz modules for busybox modprobe (kernel doesn't support compressed modules)
        xz -dc "${MODULES_SRC}/kernel/${mod_path}.xz" > "${MODULES_DST}/kernel/${mod_path}"
        echo "  Copied and decompressed ${mod_path}.xz"
    else
        echo "  Warning: Module ${mod_path} not found (may be built into kernel)"
    fi
done

# Copy modules.* files for modprobe to work
for modfile in modules.order modules.builtin modules.builtin.modinfo; do
    if [ -f "${MODULES_SRC}/${modfile}" ]; then
        cp "${MODULES_SRC}/${modfile}" "${MODULES_DST}/"
    fi
done

# Run depmod to generate modules.dep
depmod -b "${INITRAMFS_DIR}" "${KERNEL_VERSION}"

# Copy init script
cp "${SCRIPT_DIR}/init" "${INITRAMFS_DIR}/init"
chmod +x "${INITRAMFS_DIR}/init"

cp "${SCRIPT_DIR}/udhcpc.script" "${INITRAMFS_DIR}/bin/udhcpc.script"
chmod +x "${INITRAMFS_DIR}/bin/udhcpc.script"

# Create the initramfs archive (reproducible build)
echo "Creating initramfs archive..."
# Set all file timestamps to epoch for reproducibility (do this LAST after all file operations)
find "${INITRAMFS_DIR}" -exec touch -h -t 197001010000 {} +
# Create reproducible cpio archive with sorted file list and no timestamps in gzip
(cd "${INITRAMFS_DIR}" && find . -print0 | LC_ALL=C sort -z | cpio -o -H newc -0 --reproducible 2>/dev/null || cpio -o -H newc -0) | gzip -n > "${INITRD_PATH}"

# Cleanup
rm -rf "${INITRAMFS_DIR}"

echo "Initrd created: ${INITRD_PATH}"

# Get kernel image path
KERNEL_PATH="${OUTPUT_DIR}/tmp/lib/modules/${KERNEL_VERSION}/vmlinuz"
if [ ! -f "${KERNEL_PATH}" ]; then
    # Alternative location
    KERNEL_PATH="${OUTPUT_DIR}/tmp/boot/vmlinuz-${KERNEL_VERSION}"
fi

if [ ! -f "${KERNEL_PATH}" ]; then
    echo "Error: Kernel image not found at ${KERNEL_PATH}"
    exit 1
fi

echo "Kernel image: ${KERNEL_PATH}"

# Check if we have systemd-boot stub (for UKI)
STUB_PATH="${OUTPUT_DIR}/stub.efi"
if [ ! -f "${STUB_PATH}" ]; then
    echo "Error: systemd-boot stub not found, UKI creation may not be possible"
    exit 1
fi

# Build UKI using objcopy
echo "Building UKI..."
UKI_PATH="${OUTPUT_DIR}/linux.efi"

# Create cmdline file with architecture-specific console settings
# The kernel command line is embedded in the signed UKI, so the VM operator cannot change it.
#
# Security flags (threat model: VM operator is the adversary):
#   hibernate=no              - Disable hibernation; prevents memory being written to operator-controlled EBS volume
#   lockdown=confidentiality  - Kernel lockdown LSM; blocks /dev/mem, /proc/kcore, unsigned modules, unsigned kexec
#   debugfs=off               - Disable debugfs entirely; lockdown restricts some access but this removes the surface
#   oops=panic                - Halt on kernel oops; don't continue in a potentially exploitable state
#   iommu.strict=1            - Strict IOMMU TLB invalidation on DMA unmap; prevents DMA-based attacks from virtual devices
#   slab_nomerge              - Prevent slab cache merging; makes slab-based kernel exploits harder
#   randomize_kstack_offset=on - Randomize kernel stack offset per syscall; makes stack-based exploits less reliable
#   page_alloc.shuffle=1      - Randomize page allocator freelists; makes heap layout less predictable
#   init_on_alloc=1           - Zero-fill memory on allocation; prevents info leaks from recycled memory
#   init_on_free=1            - Zero-fill memory on free; makes use-after-free exploitation harder
#   crashkernel=0             - Reserve no memory for kdump; prevents crash dumps even if NMI is sent via cloud API
#   vsyscall=none             - (x86_64 only) Remove legacy vsyscall page; eliminates a fixed-address ROP gadget
#
# NOTE: SysRq is disabled via /proc/sys/kernel/sysrq in the init script, not here.
# "sysrq=" is not a valid kernel cmdline parameter (the kernel ignores it).
CMDLINE_PATH="${OUTPUT_DIR}/cmdline.txt"
CMDLINE_COMMON="earlycon hibernate=no lockdown=confidentiality debugfs=off oops=panic crashkernel=0 iommu.strict=1 slab_nomerge randomize_kstack_offset=on page_alloc.shuffle=1 init_on_alloc=1 init_on_free=1 ro"
if [ "${ARCH}" = "x86_64" ]; then
    # console=ttyS0: EC2 PCI UART (only serial device, gets ttyS0)
    # console=ttyS1: QEMU q35 ISA serial (default COM1 is ttyS0 with no backend,
    #                explicit isa-serial device becomes ttyS1)
    CMDLINE_SERIAL="console=ttyS0,115200n8 console=ttyS1,115200n8 vsyscall=none"
else
    # console=ttyAMA0: PL011 UART on QEMU virt
    # console=ttyS0: 16550 PCI UART on EC2 Graviton and QEMU (PCI serial)
    CMDLINE_SERIAL="console=ttyAMA0,115200n8 console=ttyS0,115200n8"
fi
echo "${CMDLINE_SERIAL} ${CMDLINE_COMMON}" > "${CMDLINE_PATH}"

UNAME_PATH="${OUTPUT_DIR}/uname.txt"
echo "${KERNEL_VERSION}" > "${UNAME_PATH}"

# Set SOURCE_DATE_EPOCH for reproducible builds
export SOURCE_DATE_EPOCH=0

# Generate version with year.month format (e.g., 26.02)
YEAR_MONTH=$(date +%y.%m)
OSREL_VERSION="${YEAR_MONTH} ${ARCH} (Fedora 41)"
OSREL_NAME="Lock.Boot"
# Combine stub + kernel + initrd into UKI
# Use os-release from extracted RPM if available, otherwise create minimal one
OSREL_PATH="${OUTPUT_DIR}/os-release"
echo "ID=lockboot" > "${OSREL_PATH}"
echo "VERSION_ID=${YEAR_MONTH}.fc41" >> "${OSREL_PATH}"
echo "VERSION=\"${OSREL_VERSION}\"" >> "${OSREL_PATH}"
echo "NAME=\"${OSREL_NAME}\"" >> "${OSREL_PATH}"
echo "PRETTY_NAME=\"${OSREL_NAME} ${OSREL_VERSION}\"" >> "${OSREL_PATH}"

# Calculate BUILD_ID from component hashes
INITRD_HASH=$(sha256sum "${INITRD_PATH}" | cut -d' ' -f1 | cut -c1-8)
KERNEL_HASH=$(sha256sum "${KERNEL_PATH}" | cut -d' ' -f1 | cut -c1-8)
CMDLINE_HASH=$(sha256sum "${CMDLINE_PATH}" | cut -d' ' -f1 | cut -c1-8)
BUILD_ID="kernel-${KERNEL_VERSION}-${KERNEL_HASH}.cmdline-${CMDLINE_HASH}.initrd-${INITRD_HASH}"
echo "BUILD_ID=${BUILD_ID}" >> "${OSREL_PATH}"

# Calculate section VMAs dynamically based on the stub's layout.
# Newer systemd stubs (v256+) use high VMAs that differ from v252's layout,
# so we append our sections after the stub's last section (same approach as ukify).
SECTION_ALIGN=0x1000
NEXT_VMA=$(${OBJCOPY%%objcopy}objdump -h "${STUB_PATH}" | \
    awk '/^  [0-9]/ { print $3, $4 }' | \
    while read size_hex vma_hex; do
        echo $(( 0x${vma_hex} + 0x${size_hex} ))
    done | sort -n | tail -1)
NEXT_VMA=$(( (NEXT_VMA + SECTION_ALIGN - 1) / SECTION_ALIGN * SECTION_ALIGN ))

# Place each section sequentially, aligned to SECTION_ALIGN
calc_next_vma() {
    local current_vma=$1
    local file=$2
    local size
    size=$(stat -c%s "$file")
    echo $(( (current_vma + size + SECTION_ALIGN - 1) / SECTION_ALIGN * SECTION_ALIGN ))
}

OSREL_VMA=${NEXT_VMA}
CMDLINE_VMA=$(calc_next_vma ${OSREL_VMA} "${OSREL_PATH}")
UNAME_VMA=$(calc_next_vma ${CMDLINE_VMA} "${CMDLINE_PATH}")
LINUX_VMA=$(calc_next_vma ${UNAME_VMA} "${UNAME_PATH}")
INITRD_VMA=$(calc_next_vma ${LINUX_VMA} "${KERNEL_PATH}")

echo "UKI section layout:"
printf "  .osrel   @ 0x%x\n" ${OSREL_VMA}
printf "  .cmdline @ 0x%x\n" ${CMDLINE_VMA}
printf "  .uname   @ 0x%x\n" ${UNAME_VMA}
printf "  .linux   @ 0x%x\n" ${LINUX_VMA}
printf "  .initrd  @ 0x%x\n" ${INITRD_VMA}

${OBJCOPY} \
    --input-target="${PE_FORMAT}" \
    --output-target="${PE_FORMAT}" \
    --add-section .osrel="${OSREL_PATH}" --change-section-vma .osrel=${OSREL_VMA} \
    --add-section .cmdline="${CMDLINE_PATH}" --change-section-vma .cmdline=${CMDLINE_VMA} \
    --add-section .uname="${UNAME_PATH}" --change-section-vma .uname=${UNAME_VMA} \
    --add-section .linux="${KERNEL_PATH}" --change-section-vma .linux=${LINUX_VMA} \
    --add-section .initrd="${INITRD_PATH}" --change-section-vma .initrd=${INITRD_VMA} \
    "${STUB_PATH}" "${UKI_PATH}"

sbsign --key "$KEYDIR/db.crt.key" --cert "$KEYDIR/db.crt" --output "${UKI_PATH}" "${UKI_PATH}"

echo "UKI created: ${UKI_PATH}"
ls -lh "${UKI_PATH}"

# Copy kernel separately for reference
cp "${KERNEL_PATH}" "${OUTPUT_DIR}/vmlinuz-${KERNEL_VERSION}"

echo ""
echo "=== Creating bootable disk image ==="

# Calculate required disk size based on UKI file size
# Add overhead for: GPT headers (1MB front + 1MB back), FAT32 overhead (~10%), alignment, and safety margin
if [ -f "${UKI_PATH}" ]; then
    UKI_SIZE_BYTES=$(stat -c%s "${UKI_PATH}")
    UKI_SIZE_MB=$((UKI_SIZE_BYTES / 1024 / 1024 + 1))
    # Calculate total size: 1MB (front GPT) + partition size + 1MB (back GPT)
    # Partition size = UKI size * 1.5 (50% overhead for FAT32, alignment, and safety)
    PARTITION_SIZE_MB=$((UKI_SIZE_MB * 3 / 2))
    # Ensure minimum partition size of 33MB (FAT32 minimum)
    if [ ${PARTITION_SIZE_MB} -lt 100 ]; then
        PARTITION_SIZE_MB=100
    fi
    DISK_SIZE_MB=$((PARTITION_SIZE_MB + 2))
    echo "UKI size: ${UKI_SIZE_MB}MB"
    echo "Partition size: ${PARTITION_SIZE_MB}MB"
    echo "Total disk size: ${DISK_SIZE_MB}MB"
else
    echo "Error: UKI file not found at ${UKI_PATH}"
    exit 1
fi

DISK_IMAGE="${OUTPUT_DIR}/boot.disk"

echo "Creating ${DISK_SIZE_MB}MB disk image..."
dd if=/dev/zero of="${DISK_IMAGE}" bs=1M count=${DISK_SIZE_MB} status=progress

# Generate deterministic GUIDs from UKI hash for reproducible builds
echo "Generating deterministic GUIDs from UKI content..."
UKI_HASH=$(sha256sum "${UKI_PATH}" | cut -d' ' -f1)
# Create disk GUID from first 32 hex chars of hash
DISK_GUID="${UKI_HASH:0:8}-${UKI_HASH:8:4}-${UKI_HASH:12:4}-${UKI_HASH:16:4}-${UKI_HASH:20:12}"
# Create partition GUID from next 32 hex chars
PART_GUID="${UKI_HASH:32:8}-${UKI_HASH:36:4}-${UKI_HASH:40:4}-${UKI_HASH:44:4}-${UKI_HASH:48:12}"
echo "Disk GUID: ${DISK_GUID}"
echo "Partition GUID: ${PART_GUID}"

# Create GPT partition table with deterministic GUIDs using sfdisk
echo "Creating reproducible GPT partition table..."
sfdisk "${DISK_IMAGE}" <<EOF
label: gpt
label-id: ${DISK_GUID}
first-lba: 2048
unit: sectors

start=2048, size=$((((DISK_SIZE_MB - 1) * 1024 * 1024 / 512) - 2048)), type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, uuid=${PART_GUID}, name="EFI System Partition"
EOF

# Calculate partition offset for mtools access
PART_INFO=$(sfdisk -d "${DISK_IMAGE}" | grep "start=" | head -1)
PART_START_SECTOR=$(echo "${PART_INFO}" | sed -n 's/.*start=\s*\([0-9]*\).*/\1/p')
PART_OFFSET=$((PART_START_SECTOR * 512))

# Format the ESP partition as FAT32 with deterministic volume ID
echo "Formatting EFI System Partition..."
# Use first 8 hex chars of hash as volume ID for reproducibility
VOLUME_ID="${UKI_HASH:0:8}"

# Setup loop device for the partition
LOOP_DEVICE=$(losetup -f --show -o "${PART_OFFSET}" "${DISK_IMAGE}")
mkfs.vfat -F 32 -n "EFISYS" -i "${VOLUME_ID}" "${LOOP_DEVICE}"
losetup -d "${LOOP_DEVICE}"

# Create EFI boot directory structure by mounting with timestamp control
echo "Creating EFI boot structure..."
# Setup loop device for the partition to mount it
LOOP_DEVICE=$(losetup -f --show -o "${PART_OFFSET}" "${DISK_IMAGE}")

# Mount with options to minimize timestamp updates
MOUNT_DIR="${OUTPUT_DIR}/tmp/esp-mount-$$"
mkdir -p "${MOUNT_DIR}"
mount -o noatime,nodiratime,tz=UTC "${LOOP_DEVICE}" "${MOUNT_DIR}"

# Create EFI boot directory structure
mkdir -p "${MOUNT_DIR}/EFI/BOOT"

# Determine the correct boot filename based on architecture
if [ "${ARCH}" = "x86_64" ]; then
    BOOT_EFI="BOOTX64.EFI"
elif [ "${ARCH}" = "aarch64" ]; then
    BOOT_EFI="BOOTAA64.EFI"
fi

# Copy the UKI as the correct boot file
cp "${UKI_PATH}" "${MOUNT_DIR}/EFI/BOOT/${BOOT_EFI}"
echo "Copied UKI to EFI/BOOT/${BOOT_EFI}"

# Set all timestamps to FAT32 minimum (1980-01-01) for reproducibility
# This must be done before unmount
find "${MOUNT_DIR}" -exec touch -h -d "1980-01-01 00:00:00 UTC" {} +

# Verify the file was copied
echo "Contents of EFI/BOOT:"
ls -lh "${MOUNT_DIR}/EFI/BOOT/"

# Sync and unmount
sync
umount "${MOUNT_DIR}"
rmdir "${MOUNT_DIR}"
losetup -d "${LOOP_DEVICE}"

# Normalize all FAT timestamps for reproducibility
echo "Normalizing FAT timestamps for reproducibility..."
"${SCRIPT_DIR}/normalize-fat-timestamps.py" "${DISK_IMAGE}" "${PART_OFFSET}"

echo "Disk image created: ${DISK_IMAGE}"
ls -lh "${DISK_IMAGE}"

# Verify the disk image
echo ""
echo "=== Verifying disk image ==="
sfdisk -l "${DISK_IMAGE}"

# Get disk image size for AWS import
IMAGE_SIZE_BYTES=$(stat -c%s "${DISK_IMAGE}")
IMAGE_SIZE_GB=$((IMAGE_SIZE_BYTES / 1024 / 1024 / 1024 + 1))
echo "Disk image size: ${IMAGE_SIZE_BYTES} bytes (~${IMAGE_SIZE_GB}GB)"


# Use architecture-specific OVMF vars template
if [ "${ARCH}" = "x86_64" ]; then
    OVMF_VARS_ORIG="/usr/share/OVMF/OVMF_VARS_4M.fd"
elif [ "${ARCH}" = "aarch64" ]; then
    # Use snakeoil (test keys) version which has proper structure for virt-fw-vars
    OVMF_VARS_ORIG="/usr/share/AAVMF/AAVMF_VARS.snakeoil.fd"
fi

EFI_VARS_OVMF="${OUTPUT_DIR}/efi-vars.ovmf"
EFI_VARS_AWS="${OUTPUT_DIR}/efi-vars.aws"
if [ ! -f "${OVMF_VARS_ORIG}" ]; then
    echo "Error: ${OVMF_VARS_ORIG} not found. Install ovmf/qemu-efi-aarch64 package."
    exit 1
fi

# Copy OVMF_VARS if it doesn't exist (preserves any previous state)
# With DeployedMode=1 the KEK and PK can't be used to update the variables
echo "Creating EFI vars (OVMF+AWS)"
#cert-to-efi-sig-list -g `cat "$KEYDIR/PK.guid"` "$KEYDIR/PK.crt" "$KEYDIR/PK.esl"
#cert-to-efi-sig-list -g `cat "$KEYDIR/KEK.guid"` "$KEYDIR/KEK.crt" "$KEYDIR/KEK.esl"
#cert-to-efi-sig-list -g `cat "$KEYDIR/db.guid"` "$KEYDIR/db.crt" "$KEYDIR/db.esl"
virt-fw-vars --input "${OVMF_VARS_ORIG}" --output "${EFI_VARS_OVMF}" --output-aws "${EFI_VARS_AWS}" \
  --add-db `cat "$KEYDIR/db.guid"` "$KEYDIR/db.crt" \
  --add-kek `cat "$KEYDIR/KEK.guid"` "$KEYDIR/KEK.crt" \
  --set-pk `cat "$KEYDIR/PK.guid"` "$KEYDIR/PK.crt" \
  --set-true DeployedMode \
  --secure-boot

# Clean up temporary extraction directory
rm -rf "${OUTPUT_DIR}/tmp"

# Fix ownership of output files to match the host user
if [ -n "${OWNER_UID:-}" ] && [ -n "${OWNER_GID:-}" ]; then
    chown -R "${OWNER_UID}:${OWNER_GID}" "${OUTPUT_DIR}"
fi
