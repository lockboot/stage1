#!/bin/bash
set -euox pipefail

# Get the absolute path of the script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Repository root (computed from script location: tools/qemu-test -> ../..)
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

usage() {
    cat <<'EOF'
Usage: boot.sh [OPTIONS]

Boot a lockboot disk image under QEMU with Secure Boot, an emulated TPM 2.0,
and a mocked EC2 metadata service.

Options:
  --kind <uki|stage0>      What to boot (default: uki).
                             uki    = Linux Unified Kernel Image (stage1 path)
                             stage0 = pure-UEFI network bootloader
  --arch <x86_64|aarch64>  Target architecture (default: $ARCH or x86_64).
  --boot-disk <path>       Override the disk image to boot.
  --user-data <path>       Override the metadata user-data JSON.
  --ovmf-vars <path>       Override the OVMF/EFI variables file.
  --payload <path>         (stage0) Serve this UEFI payload over HTTP at
                           http://10.0.2.1:8000/payload.efi for stage0 to fetch.
  --serve-dir <path>       (stage0) Serve this whole directory at
                           http://10.0.2.1:8000/ instead of a single payload. Used
                           by the full chain (UKI at /linux.efi, stage2 at /stage2).
  --trace                  Capture the guest's TCP traffic on tap0 to a pcap at
                           stage0-trace.pcap in the repo root (bind-mounted, so it
                           persists on the host). Open in Wireshark / tshark to
                           reassemble the HTTP streams.
  -h, --help               Show this help and exit.

Defaults by --kind:
  uki    : disk tools/build-uki/<arch>/boot.disk,    user-data.json
  stage0 : disk tools/build-stage0/<arch>/boot.disk, user-data.stage0.json

The tap/iptables setup needs NET_ADMIN; run via 'make boot-...' (privileged
dev container) or with sudo and YES_INSIDE_DOCKER_DO_DANGEROUS_IPTABLES=1.
EOF
}

# Defaults (ARCH may still come from the environment for Makefile compatibility)
ARCH="${ARCH:-x86_64}"
BOOT_KIND="uki"
BOOT_DISK=""
USER_DATA=""
OVMF_VARS_OVERRIDE=""
PAYLOAD=""
SERVE_DIR=""
TRACE=0

while [ $# -gt 0 ]; do
    case "$1" in
        --kind)      BOOT_KIND="$2"; shift 2 ;;
        --arch)      ARCH="$2"; shift 2 ;;
        --boot-disk) BOOT_DISK="$2"; shift 2 ;;
        --user-data) USER_DATA="$2"; shift 2 ;;
        --ovmf-vars) OVMF_VARS_OVERRIDE="$2"; shift 2 ;;
        --payload)   PAYLOAD="$2"; shift 2 ;;
        --serve-dir) SERVE_DIR="$2"; shift 2 ;;
        --trace)     TRACE=1; shift ;;
        -h|--help)   usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

if [ "${YES_INSIDE_DOCKER_DO_DANGEROUS_IPTABLES:-}" != 1 ]; then
    echo "Error: not inside docker, refusing to do dangerous stuff!!"
    echo "Run via 'make boot-...' or sudo with YES_INSIDE_DOCKER_DO_DANGEROUS_IPTABLES=1."
    exit 1
fi

case "${ARCH}" in x86_64|aarch64) ;; *) echo "Unsupported ARCH: ${ARCH}"; exit 1 ;; esac
case "${BOOT_KIND}" in uki|stage0) ;; *) echo "Unknown --kind: ${BOOT_KIND}"; exit 1 ;; esac

KEYDIR="${REPO_ROOT}/tools/build-uki/keys"
TMP=/tmp

# Resolve disk / user-data defaults from the selected kind (flags win).
if [ "${BOOT_KIND}" = "stage0" ]; then
    DISK_DIR="${REPO_ROOT}/tools/build-stage0/${ARCH}"
    : "${USER_DATA:=${REPO_ROOT}/user-data.stage0.json}"
else
    DISK_DIR="${REPO_ROOT}/tools/build-uki/${ARCH}"
    : "${USER_DATA:=${REPO_ROOT}/user-data.json}"
fi
: "${BOOT_DISK:=${DISK_DIR}/boot.disk}"

echo "=== Booting ${BOOT_KIND} with Secure Boot + TPM 2.0 (${ARCH}) ==="
echo "User-data file: ${USER_DATA}"
echo "Boot disk:      ${BOOT_DISK}"

AMMM=${SCRIPT_DIR}/ec2-metadata-mock-linux-amd64

# Check dependencies
if [ ! -f ${AMMM} ]; then
    echo "Error: ${AMMM} not found. Run 'make ec2-metadata-mock-linux-amd64' first."
    exit 1
fi

if [ ! -f "${USER_DATA}" ]; then
    echo "Error: User-data file '${USER_DATA}' not found."
    exit 1
fi

# Boot disk resolved above from --kind/--boot-disk.
if [ ! -f "${BOOT_DISK}" ]; then
    echo "Error: ${BOOT_DISK} not found. Build it first (see --help)."
    exit 1
fi

# OVMF firmware paths (architecture-specific)
if [ "${ARCH}" = "x86_64" ]; then
    OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.secboot.fd"
    QEMU_CMD="qemu-system-x86_64"
    QEMU_MACHINE="-machine q35,smm=on"
    QEMU_CPU=""
    QEMU_EXTRA="-enable-kvm"
    # ISA serial at 0x3f8 = ttyS0, matches how GRUB/Fedora expects serial on x86_64
    QEMU_SERIAL="-serial none"
    QEMU_SERIAL_DEVICE="-device isa-serial,chardev=char0"
    TPM_DEVICE="tpm-tis"
elif [ "${ARCH}" = "aarch64" ]; then
    OVMF_CODE="/usr/share/AAVMF/AAVMF_CODE.fd"
    QEMU_CMD="qemu-system-aarch64"
    # GIC version 3 is more modern, try gic-version=2 if it doesn't work
    QEMU_MACHINE="-machine virt"
    #QEMU_MACHINE="-machine virt,gic-version=2"
    #QEMU_MACHINE="-machine sbsa-ref"
    # Try different CPU models if one doesn't work:
    # -cpu cortex-a57 (older, well-supported)
    # -cpu cortex-a72 (similar to a57)
    # -cpu max (all features, but may cause issues)
    QEMU_CPU="-cpu cortex-a72"
    #QEMU_CPU=""
    QEMU_EXTRA=""
    # -serial none: PL011 exists but with no backend, PCI serial is ttyS0
    QEMU_SERIAL="-serial none"
    QEMU_SERIAL_DEVICE="-device pci-serial,id=serial0,chardev=char0"
    TPM_DEVICE="tpm-tis-device"
else
    echo "Error: Unsupported architecture: ${ARCH}"
    exit 1
fi

OVMF_VARS_ORIG="${OVMF_VARS_OVERRIDE:-${DISK_DIR}/efi-vars.ovmf}"
OVMF_VARS="/tmp/efi-vars.ovmf"

if [ ! -f "${OVMF_CODE}" ]; then
    echo "Error: ${OVMF_CODE} not found. Install ovmf package."
    exit 1
fi

cp "${OVMF_VARS_ORIG}" "${OVMF_VARS}"

# Setup TPM state directory
mkdir -p $TMP/tpm-state

# Provision NV indices for GCP-style attestation (idempotent)
# This starts its own swtpm instance with tpm2-tools-compatible sockets, then shuts it down
${SCRIPT_DIR}/provision-test-tpm.sh $TMP/tpm-state

# Start swtpm for QEMU (original way - just ctrl socket)
swtpm socket --tpmstate dir=$TMP/tpm-state \
    --ctrl type=unixio,path=$TMP/swtpm-sock \
    --tpm2 \
    --pid file=$TMP/swtpm.pid \
    --daemon
sleep 1

# Cleanup function
cleanup() {
    kill $(cat $TMP/swtpm.pid 2>/dev/null) 2>/dev/null || true
    kill $(cat $TMP/ec2-mock.pid 2>/dev/null) 2>/dev/null || true
    kill $(cat $TMP/payload-http.pid 2>/dev/null) 2>/dev/null || true
    kill $(cat $TMP/tcpdump.pid 2>/dev/null) 2>/dev/null || true
    # The boot runs as root; hand the trace back to the host user.
    if [ "${TRACE}" = 1 ] && [ -n "${OWNER_UID:-}" ] && [ -f "${TRACE_FILE:-}" ]; then
        chown "${OWNER_UID}:${OWNER_GID:-${OWNER_UID}}" "${TRACE_FILE}" 2>/dev/null || true
    fi
}

# Set trap to cleanup on exit
trap cleanup EXIT INT TERM

# Boot the UKI
echo "Press Ctrl-A, then X to exit QEMU"

#-netdev "user,id=net0,net=169.254.169.0/24,guestfwd=tcp:169.254.169.254:80-cmd:/usr/bin/nc 192.168.3.5 1338" \

ip tuntap add dev tap0 mode tap
ip link set tap0 up
ip addr add 10.0.2.1/24 dev tap0
ip addr add 169.254.169.254/24 dev tap0

# Optional: capture the guest's full TCP traffic to a pcap (full packets, so the
# HTTP streams can be reassembled/extracted in Wireshark/tshark). Written into
# the bind-mounted repo so it survives the container.
TRACE_FILE="${REPO_ROOT}/stage0-trace.pcap"
if [ "${TRACE}" = 1 ]; then
    echo "Capturing tap0 TCP -> ${TRACE_FILE} (repo root; open in Wireshark)"
    tcpdump -i tap0 -s 0 -U -w "${TRACE_FILE}" tcp 2>/dev/null &
    echo $! > $TMP/tcpdump.pid
    sleep 0.5
fi

# Create AEMM config with user-data
echo "Starting EC2 metadata mock..."
echo '{"userdata":{"values":{"userdata":"'$(base64 -w0 "${USER_DATA}")'"}}}' > $TMP/aemm-config.json

# Start EC2 metadata mock
${AMMM} \
    --imdsv2 \
    -n 169.254.169.254 \
    --port 80 \
    --config-file $TMP/aemm-config.json &
echo $! > $TMP/ec2-mock.pid

# Give services time to start
sleep 1

# Serve a local tree over HTTP on the tap gateway, so `_stage1`/`_stage2` user-data
# can point at http://10.0.2.1:8000/<file>. --serve-dir serves a prepared directory
# (full chain: /linux.efi for stage0, /stage2 for stage1); --payload wraps a single
# file as /payload.efi (stage0 isolation).
SERVE_ROOT=""
if [ -n "${SERVE_DIR}" ]; then
    [ -d "${SERVE_DIR}" ] || { echo "Error: serve-dir ${SERVE_DIR} not found"; exit 1; }
    SERVE_ROOT="${SERVE_DIR}"
elif [ -n "${PAYLOAD}" ]; then
    [ -f "${PAYLOAD}" ] || { echo "Error: payload ${PAYLOAD} not found"; exit 1; }
    SERVE_ROOT=$(mktemp -d)
    cp "${PAYLOAD}" "${SERVE_ROOT}/payload.efi"
    # In signed mode stage0 also fetches a detached signature at <url>.sig.
    [ -f "${PAYLOAD}.sig" ] && cp "${PAYLOAD}.sig" "${SERVE_ROOT}/payload.efi.sig"
fi
if [ -n "${SERVE_ROOT}" ]; then
    # Serve HTTP/1.1 (Content-Length + keep-alive). The stdlib `http.server` default
    # is HTTP/1.0 `Connection: close`, which OVMF's HttpDxe never completes the
    # response token for. Real object stores (S3/GCS) serve HTTP/1.1.
    ( cd "${SERVE_ROOT}" && exec python3 -c 'import http.server; http.server.SimpleHTTPRequestHandler.protocol_version="HTTP/1.1"; http.server.ThreadingHTTPServer(("10.0.2.1",8000), http.server.SimpleHTTPRequestHandler).serve_forever()' ) &
    echo $! > $TMP/payload-http.pid
    echo "Serving ${SERVE_ROOT} (HTTP/1.1) at http://10.0.2.1:8000/ :"
    ls -l "${SERVE_ROOT}" | sed 's/^/  /'
fi

echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Create dnsmasq hosts file with EC2-style hostnames
echo "Generating /tmp/dnsmasq-hosts..."
cat > /tmp/dnsmasq-hosts <<EOF
10.0.2.10 ip-10-0-2-10
10.0.2.11 ip-10-0-2-11
10.0.2.12 ip-10-0-2-12
10.0.2.13 ip-10-0-2-13
10.0.2.14 ip-10-0-2-14
10.0.2.15 ip-10-0-2-15
10.0.2.16 ip-10-0-2-16
10.0.2.17 ip-10-0-2-17
10.0.2.18 ip-10-0-2-18
10.0.2.19 ip-10-0-2-19
10.0.2.20 ip-10-0-2-20
10.0.2.1 payload.lockboot.test
EOF

# Start DHCP with EC2-like configuration
# Option 3: Default gateway (10.0.2.1)
# Option 6: DNS server (10.0.2.1 for local DNS, also 8.8.8.8)
# Option 15: Domain name (ec2.internal)
# Option 121: Classless Static Routes - route 169.254.169.254/32 via 10.0.2.1
# Option 119: Domain search list (.ec2.internal, .local.compute.internal)
dnsmasq --interface=tap0 --bind-interfaces \
    --dhcp-range=10.0.2.10,10.0.2.20,12h \
    --dhcp-option=3,10.0.2.1 \
    --dhcp-option=6,10.0.2.1,8.8.8.8 \
    --dhcp-option=15,ec2.internal \
    --dhcp-option=option:classless-static-route,169.254.169.254/32,10.0.2.1 \
    --dhcp-option=119,ec2.internal,local.compute.internal \
    --domain=ec2.internal \
    --expand-hosts \
    --addn-hosts=/tmp/dnsmasq-hosts \
    --log-queries

# Set pflash secure option only for x86_64
if [ "${ARCH}" = "x86_64" ]; then
    PFLASH_SECURE="-global driver=cfi.pflash01,property=secure,value=on"
else
    PFLASH_SECURE=""
fi

${QEMU_CMD} \
    ${QEMU_CPU} \
    ${QEMU_EXTRA} \
    ${QEMU_MACHINE} \
    ${PFLASH_SECURE} \
    -smp cores=2,threads=1 -m 512 \
    -object rng-random,filename=/dev/urandom,id=rng0 \
    -device virtio-rng-pci,rng=rng0 \
    -chardev socket,id=chrtpm,path=$TMP/swtpm-sock \
    -tpmdev emulator,id=tpm0,chardev=chrtpm \
    -device ${TPM_DEVICE},tpmdev=tpm0 \
    -drive file=${BOOT_DISK},format=raw,if=none,id=boot \
    -device nvme,serial=boot,drive=boot,bootindex=0 \
    -netdev tap,id=net0,ifname=tap0,script=no \
    -device virtio-net-pci,netdev=net0 \
    -display none \
    ${QEMU_SERIAL} \
    -chardev stdio,mux=on,id=char0 \
    ${QEMU_SERIAL_DEVICE} \
    -drive if=pflash,format=raw,unit=0,file="${OVMF_CODE}",readonly=on \
    -drive if=pflash,format=raw,unit=1,file="${OVMF_VARS}" || true
