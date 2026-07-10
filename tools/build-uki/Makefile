.PHONY: all help clean check-urls

# Alpine Linux version (stable)
ALPINE_VERSION := v3.22
ALPINE_BASE_URL := https://dl-cdn.alpinelinux.org/alpine/$(ALPINE_VERSION)/main

# Busybox (static) from Alpine Linux
BUSYBOX_VERSION := 1.37.0-r20
BUSYBOX_SHA256_x86_64 := 488ad6efd04b5a722719e79f8e0dcc2c24afd6758867af3ce41b04839e60c74b
BUSYBOX_SHA256_aarch64 := ee469aee2958feffd7f64dd96655704025ff60af614f77a1d7323dc237c34da2
BUSYBOX_APK := busybox-static-$(BUSYBOX_VERSION).apk
BUSYBOX_URL_x86_64 := $(ALPINE_BASE_URL)/x86_64/$(BUSYBOX_APK)
BUSYBOX_URL_aarch64 := $(ALPINE_BASE_URL)/aarch64/$(BUSYBOX_APK)

# ---- Fedora kernel + systemd-boot EFI stub ----
# Versions + SHA256 pins live in fedora-deps.mk (GENERATED, GPG-verified); bump them with
#   make update-fedora-deps FCOS=<version> [SYSTEMD=<nvr>]   (target in ../../Makefile).
# The systemd stub provides the EFI stub (linuxx64/aa64.efi.stub, PE-vmlinuz capable on aarch64);
# kernel-modules-core carries the ena (AWS) + gve (GCP) NIC drivers. RPMs come from koji's SIGNED
# path and are GPG-verified against $(FEDORA_KEY) on every download (download-verify-rpm.sh).
include fedora-deps.mk

FEDORA_KEY := keys/RPM-GPG-KEY-fedora-$(FEDORA_RELEASE)-primary

SYSTEMD_BOOT_RPM_x86_64 := systemd-boot-unsigned-$(SYSTEMD_BOOT_VERSION).x86_64.rpm
SYSTEMD_BOOT_RPM_aarch64 := systemd-boot-unsigned-$(SYSTEMD_BOOT_VERSION).aarch64.rpm
SYSTEMD_BOOT_URL_x86_64 := $(SYSTEMD_BOOT_BASE_URL)/x86_64/$(SYSTEMD_BOOT_RPM_x86_64)
SYSTEMD_BOOT_URL_aarch64 := $(SYSTEMD_BOOT_BASE_URL)/aarch64/$(SYSTEMD_BOOT_RPM_aarch64)

FEDORA_KERNEL_CORE_RPM_x86_64 := kernel-core-$(FEDORA_KERNEL_VERSION).x86_64.rpm
FEDORA_KERNEL_CORE_RPM_aarch64 := kernel-core-$(FEDORA_KERNEL_VERSION).aarch64.rpm
FEDORA_KERNEL_CORE_URL_x86_64 := $(FEDORA_KERNEL_BASE_URL)/x86_64/$(FEDORA_KERNEL_CORE_RPM_x86_64)
FEDORA_KERNEL_CORE_URL_aarch64 := $(FEDORA_KERNEL_BASE_URL)/aarch64/$(FEDORA_KERNEL_CORE_RPM_aarch64)

FEDORA_KERNEL_MODULES_RPM_x86_64 := kernel-modules-core-$(FEDORA_KERNEL_VERSION).x86_64.rpm
FEDORA_KERNEL_MODULES_RPM_aarch64 := kernel-modules-core-$(FEDORA_KERNEL_VERSION).aarch64.rpm
FEDORA_KERNEL_MODULES_URL_x86_64 := $(FEDORA_KERNEL_BASE_URL)/x86_64/$(FEDORA_KERNEL_MODULES_RPM_x86_64)
FEDORA_KERNEL_MODULES_URL_aarch64 := $(FEDORA_KERNEL_BASE_URL)/aarch64/$(FEDORA_KERNEL_MODULES_RPM_aarch64)

ARCHS = x86_64 aarch64
TARGETS = busybox stub.efi kernel-core.rpm kernel-modules-core.rpm

all: $(ARCHS)

x86_64: $(addprefix x86_64/,$(TARGETS))
aarch64: $(addprefix aarch64/,$(TARGETS))

%/$(BUSYBOX_APK):
	@./download-and-verify.sh "$@" "$(BUSYBOX_SHA256_$*)" "$(BUSYBOX_URL_$*)"

%/busybox: %/$(BUSYBOX_APK)
	@mkdir -p $*
	@tar --warning=no-unknown-keyword -xzOf $< bin/busybox.static > "$@"
	@chmod +x "$@"

# Download + SHA256 + GPG-verify systemd-boot-unsigned RPM (signed Fedora koji path)
x86_64/$(SYSTEMD_BOOT_RPM_x86_64):
	@./download-verify-rpm.sh "$@" "$(SYSTEMD_BOOT_SHA256_x86_64)" "$(SYSTEMD_BOOT_URL_x86_64)" "$(FEDORA_KEY)"

aarch64/$(SYSTEMD_BOOT_RPM_aarch64):
	@./download-verify-rpm.sh "$@" "$(SYSTEMD_BOOT_SHA256_aarch64)" "$(SYSTEMD_BOOT_URL_aarch64)" "$(FEDORA_KEY)"

# Extract EFI stub from systemd-boot RPM
x86_64/stub.efi: x86_64/$(SYSTEMD_BOOT_RPM_x86_64)
	@mkdir -p x86_64
	@rpm2cpio $< | cpio -i --quiet --to-stdout ./usr/lib/systemd/boot/efi/linuxx64.efi.stub > $@
	@chmod +x $@

aarch64/stub.efi: aarch64/$(SYSTEMD_BOOT_RPM_aarch64)
	@mkdir -p aarch64
	@rpm2cpio $< | cpio -i --quiet --to-stdout ./usr/lib/systemd/boot/efi/linuxaa64.efi.stub > $@
	@chmod +x $@

# Download + SHA256 + GPG-verify Fedora kernel-core RPMs (signed koji path)
x86_64/$(FEDORA_KERNEL_CORE_RPM_x86_64):
	@./download-verify-rpm.sh "$@" "$(FEDORA_KERNEL_CORE_SHA256_x86_64)" "$(FEDORA_KERNEL_CORE_URL_x86_64)" "$(FEDORA_KEY)"

x86_64/kernel-core.rpm: x86_64/$(FEDORA_KERNEL_CORE_RPM_x86_64)
	@ln -sf $(notdir $<) $@

aarch64/$(FEDORA_KERNEL_CORE_RPM_aarch64):
	@./download-verify-rpm.sh "$@" "$(FEDORA_KERNEL_CORE_SHA256_aarch64)" "$(FEDORA_KERNEL_CORE_URL_aarch64)" "$(FEDORA_KEY)"

aarch64/kernel-core.rpm: aarch64/$(FEDORA_KERNEL_CORE_RPM_aarch64)
	@ln -sf $(notdir $<) $@

# Download + SHA256 + GPG-verify Fedora kernel-modules-core RPMs (signed koji path; has ena + gve)
x86_64/$(FEDORA_KERNEL_MODULES_RPM_x86_64):
	@./download-verify-rpm.sh "$@" "$(FEDORA_KERNEL_MODULES_SHA256_x86_64)" "$(FEDORA_KERNEL_MODULES_URL_x86_64)" "$(FEDORA_KEY)"

x86_64/kernel-modules-core.rpm: x86_64/$(FEDORA_KERNEL_MODULES_RPM_x86_64)
	@ln -sf $(notdir $<) $@

aarch64/$(FEDORA_KERNEL_MODULES_RPM_aarch64):
	@./download-verify-rpm.sh "$@" "$(FEDORA_KERNEL_MODULES_SHA256_aarch64)" "$(FEDORA_KERNEL_MODULES_URL_aarch64)" "$(FEDORA_KEY)"

aarch64/kernel-modules-core.rpm: aarch64/$(FEDORA_KERNEL_MODULES_RPM_aarch64)
	@ln -sf $(notdir $<) $@

clean:
	rm -rf x86_64 aarch64

# Check all download URLs are still valid
check-urls:
	@echo "Checking URLs..."
	@curl -sfI "$(BUSYBOX_URL_x86_64)" > /dev/null && echo "OK: busybox x86_64" || echo "FAIL: busybox x86_64"
	@curl -sfI "$(BUSYBOX_URL_aarch64)" > /dev/null && echo "OK: busybox aarch64" || echo "FAIL: busybox aarch64"
	@curl -sfI "$(SYSTEMD_BOOT_URL_x86_64)" > /dev/null && echo "OK: systemd-boot x86_64" || echo "FAIL: systemd-boot x86_64"
	@curl -sfI "$(SYSTEMD_BOOT_URL_aarch64)" > /dev/null && echo "OK: systemd-boot aarch64" || echo "FAIL: systemd-boot aarch64"
	@curl -sfI "$(FEDORA_KERNEL_CORE_URL_x86_64)" > /dev/null && echo "OK: kernel-core x86_64" || echo "FAIL: kernel-core x86_64"
	@curl -sfI "$(FEDORA_KERNEL_CORE_URL_aarch64)" > /dev/null && echo "OK: kernel-core aarch64" || echo "FAIL: kernel-core aarch64"
	@curl -sfI "$(FEDORA_KERNEL_MODULES_URL_x86_64)" > /dev/null && echo "OK: kernel-modules-core x86_64" || echo "FAIL: kernel-modules-core x86_64"
	@curl -sfI "$(FEDORA_KERNEL_MODULES_URL_aarch64)" > /dev/null && echo "OK: kernel-modules-core aarch64" || echo "FAIL: kernel-modules-core aarch64"
