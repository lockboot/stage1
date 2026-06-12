.PRECIOUS: tools/build-uki/keys/% tools/build-uki/% \
	tools/build-stage0/%/stage0.efi tools/build-stage0/%/payload.efi tools/build-stage0/%/boot.disk

all: build

ARCHS=x86_64 aarch64
build: $(ARCHS)

amd64 x86_64: tools/build-uki/x86_64/boot.disk
arm64 aarch64: tools/build-uki/aarch64/boot.disk

DEFAULT_STAGE2_URL = https://lockboot.s3.us-east-1.amazonaws.com/examples/stage2/user-data.json
user-data.json:
	wget -O "$@" $(DEFAULT_STAGE2_URL)

# Docker image names
BUILD_IMAGE = lockboot:build
DEV_IMAGE = lockboot:dev
RUNTIME_IMAGE ?= lockboot:latest

tools/build-uki/keys/%:
	$(MAKE) -C tools/build-uki/keys

clean:
	rm -rf tools/build-uki/x86_64/boot.disk tools/build-uki/x86_64/stage1 tools/build-uki/x86_64/tmp tools/build-uki/x86_64/*.img tools/build-uki/x86_64/*.efi tools/build-uki/x86_64/config-* tools/build-uki/x86_64/efi-vars.ovmf
	rm -rf tools/build-uki/aarch64/boot.disk tools/build-uki/aarch64/stage1 tools/build-uki/aarch64/tmp tools/build-uki/aarch64/*.img tools/build-uki/aarch64/*.efi tools/build-uki/aarch64/config-* tools/build-uki/aarch64/efi-vars.ovmf
	rm -rf tools/build-stage0/x86_64 tools/build-stage0/aarch64

distclean: clean
	$(MAKE) -C tools/build-uki clean
	$(MAKE) -C tools/build-uki/keys clean
	$(MAKE) -C tools/qemu-test clean

# Download dependencies via tools/build-uki Makefile
tools/build-uki/%/busybox:
	$(MAKE) -C tools/build-uki $*/busybox

tools/build-uki/%/stub.efi:
	$(MAKE) -C tools/build-uki $*/stub.efi

tools/build-uki/%/kernel-core.rpm:
	$(MAKE) -C tools/build-uki $*/kernel-core.rpm

tools/build-uki/%/kernel-modules-core.rpm:
	$(MAKE) -C tools/build-uki $*/kernel-modules-core.rpm

tools/qemu-test/%:
	$(MAKE) -C tools/qemu-test $*


#####################################################################
# Docker build

docker-build-base:
	docker build -f Dockerfile.build -t $(BUILD_IMAGE) .

# Build the dev image (extends build image)
docker-build-dev: docker-build-base
	docker build -f Dockerfile.dev -t $(DEV_IMAGE) .

# Alias for building both
docker-build: docker-build-dev

docker-clean:
	docker rmi $(BUILD_IMAGE) $(DEV_IMAGE) || true

docker-dev: build run

docker-prune-system-wide:
	docker image prune -f
	docker system prune -f
	docker system prune -f --volumes
	docker system df

# Setup buildx builder (run once)
docker-buildx-setup:
	docker buildx create --name lockboot-builder --use || docker buildx use lockboot-builder
	docker buildx inspect --bootstrap

# Build runtime image for current platform only and load into Docker
docker-runtime: tools/build-uki/x86_64/busybox tools/build-uki/x86_64/stage1 tools/build-uki/aarch64/busybox tools/build-uki/aarch64/stage1
	docker buildx build \
		-f Dockerfile.runtime \
		-t $(RUNTIME_IMAGE) \
		--load \
		.

# Build multi-arch and export to OCI tar (for local multi-arch without registry)
docker-runtime-oci: tools/build-uki/x86_64/busybox tools/build-uki/x86_64/stage1 tools/build-uki/aarch64/busybox tools/build-uki/aarch64/stage1
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		-f Dockerfile.runtime \
		-t $(RUNTIME_IMAGE) \
		--output type=oci,dest=lockboot.oci \
		.

.PHONY: docker-buildx-setup docker-runtime docker-runtime-push docker-runtime-oci


#####################################################################
# Docker run

USER_ID := $(shell id -u)
GROUP_ID := $(shell id -g)

# Options for giving docker kvm access
KVM_GID := $(shell stat -c %g /dev/kvm 2>/dev/null || echo "")
KVM_MOUNT := $(shell test -e /dev/kvm && echo "-v /dev/kvm:/dev/kvm")
DOCKER_GROUP_KVM := $(if $(KVM_GID),--group-add $(KVM_GID))
DOCKER_OPT_KVM := $(DOCKER_GROUP_KVM) $(KVM_MOUNT)

# Options for recursive docker
DOCKER_SOCK_GID := $(shell stat -c %g /var/run/docker.sock 2>/dev/null || echo "")
DOCKER_SOCK_MOUNT := $(shell test -e /var/run/docker.sock && echo "-v /var/run/docker.sock:/var/run/docker.sock")
DOCKER_GROUP_DOCKER := $(if $(DOCKER_SOCK_GID),--group-add $(DOCKER_SOCK_GID))
DOCKER_OPT_DOCKER := $(DOCKER_SOCK_MOUNT) $(DOCKER_GROUP_DOCKER)

DOCKER_SAMEUSER := -u $(USER_ID):$(GROUP_ID)

# Base docker run command with all common flags
DOCKER_RUN = docker run --rm \
	--privileged \
	-v $(CURDIR):/src \
	-h lockboot \
	--add-host lockboot:127.0.0.1 \
	-e OWNER_UID=$(USER_ID) \
	-e OWNER_GID=$(GROUP_ID) \
	-w /src

docker-shell-base: docker-build-base
	$(DOCKER_RUN) -ti $(DOCKER_SAMEUSER) $(BUILD_IMAGE) bash

docker-shell-dev: docker-build-dev
	$(DOCKER_RUN) -ti $(DOCKER_SAMEUSER) $(DOCKER_OPT_DOCKER) $(DOCKER_OPT_KVM) $(DEV_IMAGE) bash

# Build the UKI and boot disk for a specific architecture
# This creates: UKI, disk image with EFI boot structure
tools/build-uki/%/boot.disk: tools/build-uki/%/busybox tools/build-uki/%/stage1 tools/build-uki/%/stub.efi tools/build-uki/%/kernel-core.rpm tools/build-uki/%/kernel-modules-core.rpm tools/build-uki/keys/db.crt
	$(DOCKER_RUN) $(DOCKER_OPT_DOCKER) -e ARCH=$* \
		$(BUILD_IMAGE) ./tools/build-uki/build.sh

boot-%: tools/qemu-test/ec2-metadata-mock-linux-amd64 tools/build-uki/%/boot.disk user-data.json
	$(DOCKER_RUN) -e ARCH=$* $(DOCKER_OPT_KVM) \
		-e YES_INSIDE_DOCKER_DO_DANGEROUS_IPTABLES=1 --cap-add=NET_ADMIN --device=/dev/net/tun \
		$(DEV_IMAGE) ./tools/qemu-test/boot.sh

tools/build-uki/%/stage1: docker-build-base
	mkdir -p tools/build-uki/$*
	$(DOCKER_RUN) -e ARCH=$* $(DOCKER_SAMEUSER) $(BUILD_IMAGE) \
		bash -c "rustup target add $*-unknown-linux-musl && cargo build --release --locked --all --target $*-unknown-linux-musl"
	cp target/$*-unknown-linux-musl/release/stage1 $@


#####################################################################
# stage0 (pure-UEFI network bootloader)

STAGE0_DIR = crates/stage0

# Guard the arch-less forms: without these, `make boot-stage0` would match the
# generic `boot-%` pattern (stem "stage0") and try to build a UKI for a bogus
# architecture named "stage0". Require an explicit arch suffix instead.
.PHONY: stage0 boot-stage0 test-stage0
stage0 boot-stage0 test-stage0:
	@echo "'$@' needs an architecture suffix, e.g. 'make $@-x86_64' or 'make $@-aarch64'." >&2
	@exit 2

# Build the stage0 UEFI binary inside the build container. Same model as stage1:
# cargo runs in the container (never the host) and vaportpm is pulled from git,
# so only this repo is mounted.
tools/build-stage0/%/stage0.efi: docker-build-base
	mkdir -p tools/build-stage0/$*
	$(DOCKER_RUN) -e ARCH=$* $(DOCKER_SAMEUSER) $(BUILD_IMAGE) \
		bash -c "rustup target add $*-unknown-uefi && cargo build --release --manifest-path $(STAGE0_DIR)/Cargo.toml --target $*-unknown-uefi"
	cp $(STAGE0_DIR)/target/$*-unknown-uefi/release/stage0.efi $@

# Assemble + sign the stage0 boot disk (losetup/mount -> privileged container).
tools/build-stage0/%/boot.disk: tools/build-stage0/%/stage0.efi tools/build-uki/keys/db.crt
	$(DOCKER_RUN) -e ARCH=$* $(BUILD_IMAGE) ./tools/build-stage0/build.sh

stage0-amd64 stage0-x86_64: tools/build-stage0/x86_64/boot.disk
stage0-arm64 stage0-aarch64: tools/build-stage0/aarch64/boot.disk

# Boot stage0 under QEMU. Pass PAYLOAD=path/to/payload.efi (repo-relative) to
# serve a local UEFI payload at http://10.0.2.1:8000/payload.efi; otherwise
# point user-data.stage0.json at any URL reachable from the guest.
# Set TRACE=1 to capture the guest TCP conversation to stage0-trace.txt (needs
# the dev image rebuilt for tcpdump: 'make docker-build-dev').
boot-stage0-%: tools/qemu-test/ec2-metadata-mock-linux-amd64 tools/build-stage0/%/boot.disk user-data.stage0.json
	$(DOCKER_RUN) $(DOCKER_OPT_KVM) \
		-e YES_INSIDE_DOCKER_DO_DANGEROUS_IPTABLES=1 --cap-add=NET_ADMIN --device=/dev/net/tun \
		$(DEV_IMAGE) ./tools/qemu-test/boot.sh --kind stage0 --arch $* $(if $(PAYLOAD),--payload $(PAYLOAD)) $(if $(TRACE),--trace)

# Long-term ed25519 release signing key for stage0 "signed mode". This is the
# vendor key that signs payloads; it never touches a deployed machine — stage0
# only ever sees the *public* key, pinned in the metadata doc. Generated once in
# the build container (gitignored). release.pub.b64 is the raw 32-byte public
# key, base64-encoded, ready to drop straight into the _stage0 `ed25519` field.
tools/build-stage0/keys/release.pem: docker-build-base
	mkdir -p tools/build-stage0/keys
	$(DOCKER_RUN) $(DOCKER_SAMEUSER) $(BUILD_IMAGE) bash -c "\
		openssl genpkey -algorithm ed25519 -out tools/build-stage0/keys/release.pem && \
		openssl pkey -in tools/build-stage0/keys/release.pem -pubout -outform DER \
			| tail -c 32 | base64 -w0 > tools/build-stage0/keys/release.pub.b64"

# Build the end-to-end test payload (a chain-loaded UEFI app that reads PCRs) and
# attach a detached ed25519 signature (payload.efi.sig) made with the release
# key. The payload is NOT Secure Boot db-signed: stage0 verifies the signature
# against the pinned pubkey and loads it via a FileAuthentication override.
# Hostname (not an IP literal) so the end-to-end test also exercises EFI_DNS4;
# boot.sh maps payload.lockboot.test -> 10.0.2.1 in the QEMU DNS. Override with
# PAYLOAD_URL=http://10.0.2.1:8000/payload.efi to skip DNS.
PAYLOAD_URL ?= http://payload.lockboot.test:8000/payload.efi
tools/build-stage0/%/payload.efi: docker-build-base tools/build-stage0/keys/release.pem
	mkdir -p tools/build-stage0/$*
	$(DOCKER_RUN) -e ARCH=$* $(DOCKER_SAMEUSER) $(BUILD_IMAGE) \
		bash -c "rustup target add $*-unknown-uefi && \
			cargo build --release --manifest-path crates/stage0-test-payload/Cargo.toml --target $*-unknown-uefi && \
			cp crates/stage0-test-payload/target/$*-unknown-uefi/release/stage0-test-payload.efi $@ && \
			openssl pkeyutl -sign -inkey tools/build-stage0/keys/release.pem -rawin -in $@ -out $@.sig"

# One-shot end-to-end test: build + sign the payload, pin the release pubkey into
# a _stage0 user-data doc (signed mode), then boot stage0 serving the payload
# and its detached .sig locally over HTTP.
test-stage0-%: tools/build-stage0/%/payload.efi tools/build-stage0/%/boot.disk tools/qemu-test/ec2-metadata-mock-linux-amd64
	@PUB=$$(cat tools/build-stage0/keys/release.pub.b64); \
	printf '{\n  "_stage0": {\n    "%s": { "url": "%s", "ed25519": "%s" }\n  }\n}\n' \
		"$*" "$(PAYLOAD_URL)" "$$PUB" > user-data.stage0.json; \
	echo "Wrote user-data.stage0.json (signed mode, release pubkey $$PUB)"
	$(MAKE) boot-stage0-$* PAYLOAD=tools/build-stage0/$*/payload.efi TRACE=$(TRACE)


#####################################################################

# Git tagging helpers
TAG ?= v0.1.0

# Create and push a new tag (or recreate if it exists)
tag:
	@echo "Creating tag: $(TAG)"
	git tag -d $(TAG) 2>/dev/null || true
	git push origin :refs/tags/$(TAG) 2>/dev/null || true
	git tag -a $(TAG) -m "Release $(TAG)"
	git push origin $(TAG)

# Delete a tag locally and remotely
untag:
	@echo "Deleting tag: $(TAG)"
	git tag -d $(TAG) 2>/dev/null || true
	git push origin :refs/tags/$(TAG) 2>/dev/null || true

# List all tags
list-tags:
	git tag -l

# Amend the most recent commit with staged changes
git-edit:
	git commit --amend --no-edit
