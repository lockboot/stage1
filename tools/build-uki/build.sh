#!/bin/bash
set -euo pipefail

# Get the absolute path of the script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Get architecture from environment (default to x86_64)
ARCH=${ARCH:-x86_64}

echo "=== Building UKI for Fedora 41 (${ARCH}) ==="

# Output directory (same as dependencies - everything self-contained)
OUTPUT_DIR="${SCRIPT_DIR}/${ARCH}"
mkdir -p "${OUTPUT_DIR}/tmp"

# Validate the target architecture (mkuki handles PE assembly in-process, so no
# arch-specific objcopy/PE-format selection is needed here anymore).
if [ "${ARCH}" != "x86_64" ] && [ "${ARCH}" != "aarch64" ]; then
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

# Build the layered initramfs as two reproducible layers that mkuki concatenates
# into one .initrd (the kernel unpacks concatenated cpios as one rootfs):
#   platform = kernel modules + depmod metadata (version-locked to the kernel)
#   userland = busybox + init + udhcpc + stage1 (kernel-agnostic)
echo "Staging initramfs layers..."
PLATFORM_DIR="${OUTPUT_DIR}/tmp/layer-platform-$$"
USERLAND_DIR="${OUTPUT_DIR}/tmp/layer-userland-$$"

# --- userland layer ---
mkdir -p "${USERLAND_DIR}"/{bin,sbin,etc,proc,sys,dev,lib,lib64,tmp}
echo "Installing busybox..."
cp "${OUTPUT_DIR}/busybox" "${USERLAND_DIR}/bin/"
echo "Installing stage1..."
cp "${OUTPUT_DIR}/stage1" "${USERLAND_DIR}/bin/stage1"
chmod +x "${USERLAND_DIR}/bin/stage1"
cp "${SCRIPT_DIR}/init" "${USERLAND_DIR}/init"
chmod +x "${USERLAND_DIR}/init"
cp "${SCRIPT_DIR}/udhcpc.script" "${USERLAND_DIR}/bin/udhcpc.script"
chmod +x "${USERLAND_DIR}/bin/udhcpc.script"

# --- platform layer (kernel modules) ---
echo "Copying kernel modules..."
MODULES_SRC="${OUTPUT_DIR}/tmp/lib/modules/${KERNEL_VERSION}"
MODULES_DST="${PLATFORM_DIR}/lib/modules/${KERNEL_VERSION}"
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

    # Storage stack for stage2. init loads these explicitly, in dependency order, before
    # the modules_disabled latch (the payload cannot load them itself, and once the latch
    # is set an unresolved dependency can never be pulled on demand -- so we list deps too,
    # not relying on modprobe auto-pull). What each provides / can be used for:
    #   dm-crypt      block-device encryption (stage2 uses it for the encrypted /data)
    #   dm-verity     integrity-checked read-only device (stage2's dm-verity'd erofs runtime)
    #   reed_solomon  dm-verity forward-error-correction dependency
    #   overlay       overlay filesystem (stage2's ephemeral overlay root)
    #   erofs/netfs   read-only image filesystem (+ its netfs dependency)
    # Extension point: authenticated (not just confidential) /data would additionally need
    # dm-integrity + its async_xor -> async_tx (ASYNC_XOR journal) deps; omitted while stage2
    # uses confidentiality-only dm-crypt, to keep the measured initramfs minimal.
    "drivers/md/dm-crypt.ko"
    "drivers/md/dm-verity.ko"
    "lib/reed_solomon/reed_solomon.ko"
    "fs/overlayfs/overlay.ko"
    "fs/erofs/erofs.ko"
    "fs/netfs/netfs.ko"

    # NVMe disk driver, so stage2 can see the persistent volume (EC2 EBS is NVMe;
    # the harness also attaches its disk as NVMe). Never needed to boot (initramfs +
    # in-memory payload), so it was previously absent. Dep chain, loaded in order by
    # init: hkdf -> nvme-auth, nvme-keyring -> nvme-core -> nvme.
    "crypto/hkdf.ko"
    "drivers/nvme/common/nvme-auth.ko"
    "drivers/nvme/common/nvme-keyring.ko"
    "drivers/nvme/host/nvme-core.ko"
    "drivers/nvme/host/nvme.ko"
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

# Run depmod to generate modules.dep inside the platform layer.
depmod -b "${PLATFORM_DIR}" "${KERNEL_VERSION}"

# init + udhcpc.script were staged into the userland layer above. mkuki builds one
# reproducible gzipped cpio per layer (zeroed uid/gid/mtime, sorted) and concatenates
# them into .initrd, so no manual cpio/gzip/touch step is needed here.
echo "Initramfs layers staged: platform + userland"

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

# BUILD_ID from kernel + cmdline. The authoritative per-layer and full .initrd
# sha256 are printed by mkuki below (it owns the cpio layer assembly now).
KERNEL_HASH=$(sha256sum "${KERNEL_PATH}" | cut -d' ' -f1 | cut -c1-8)
CMDLINE_HASH=$(sha256sum "${CMDLINE_PATH}" | cut -d' ' -f1 | cut -c1-8)
BUILD_ID="kernel-${KERNEL_VERSION}-${KERNEL_HASH}.cmdline-${CMDLINE_HASH}"
echo "BUILD_ID=${BUILD_ID}" >> "${OSREL_PATH}"

# Assemble the UKI with mkuki (no binutils/objcopy/objdump): it builds one
# reproducible gzipped cpio per --layer, concatenates them into .initrd, computes
# the section VMAs from the stub, and grafts the PE sections in-process. Layer
# order is significant: platform first (provides /lib/modules), then userland
# (provides /init and /bin/*; later layers overlay earlier ones).
MKUKI="${SCRIPT_DIR}/mkuki"
"${MKUKI}" \
    --layer "${PLATFORM_DIR}" \
    --layer "${USERLAND_DIR}" \
    --kernel "${KERNEL_PATH}" \
    --stub "${STUB_PATH}" \
    --cmdline "$(cat "${CMDLINE_PATH}")" \
    --uname "${KERNEL_VERSION}" \
    --os-release "${OSREL_PATH}" \
    --out "${UKI_PATH}" \
    --arch "${ARCH}"

# Drop the staged layer trees now that they are baked into the UKI.
rm -rf "${PLATFORM_DIR}" "${USERLAND_DIR}"

# stage0 admits and loads the UKI by ed25519/sha256, bypassing the firmware db
# check (github.com/lockboot/stage0, crates/stage0/src/secauth.rs), so the UKI is netboot-only — it needs no
# disk image, efi-vars, or db signature (those belong to the stage0 release).
# stage0 is the ONLY db/Authenticode-signed link in the chain: the UKI is admitted
# by the sha256 pinned in _stage1 (or an ed25519 .sig) plus the PCR 14 measurement,
# so mkuki's output is shipped verbatim with no sbsign step.
echo "UKI created: ${UKI_PATH}"
ls -lh "${UKI_PATH}"

# Copy kernel separately for reference
cp "${KERNEL_PATH}" "${OUTPUT_DIR}/vmlinuz-${KERNEL_VERSION}"

# Pin = sha256 of the bytes stage0 fetches and verifies (mkuki's output verbatim).
UKI_SHA256=$(sha256sum "${UKI_PATH}" | cut -d' ' -f1)
echo "${UKI_SHA256}  linux.efi" > "${OUTPUT_DIR}/linux.efi.sha256"

# Ready-to-paste _stage1 user-data snippet (sha256 admission mode). Deployers who
# want signed-mode rollforward re-sign linux.efi with their own ed25519 key.
cat > "${OUTPUT_DIR}/stage0-snippet.json" <<SNIPPET
{
  "_stage1": {
    "${ARCH}": { "url": "https://YOUR-HOST/path/to/linux.efi", "sha256": "${UKI_SHA256}" }
  }
}
SNIPPET
echo "UKI sha256: ${UKI_SHA256}"
echo "Wrote ${OUTPUT_DIR}/linux.efi.sha256 and ${OUTPUT_DIR}/stage0-snippet.json"

# Clean up temporary extraction directory
rm -rf "${OUTPUT_DIR}/tmp"

# Fix ownership of output files to match the host user
if [ -n "${OWNER_UID:-}" ] && [ -n "${OWNER_GID:-}" ]; then
    chown -R "${OWNER_UID}:${OWNER_GID}" "${OUTPUT_DIR}"
fi
