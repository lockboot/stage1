.PRECIOUS: tools/build-uki/keys/% tools/build-uki/% \
	tools/build-stage0/%/stage0.efi tools/build-stage0/%/payload.efi tools/build-stage0/%/stage2 tools/build-stage0/%/boot.disk

all: build

ARCHS=x86_64 aarch64
build: $(ARCHS)

amd64 x86_64: tools/build-uki/x86_64/linux.efi
arm64 aarch64: tools/build-uki/aarch64/linux.efi

DEFAULT_STAGE2_URL = https://lockboot.s3.us-east-1.amazonaws.com/examples/stage2/user-data.json
user-data.json:
	wget -O "$@" $(DEFAULT_STAGE2_URL)

# Docker image names
BUILD_IMAGE = lockboot:build
DEV_IMAGE = lockboot:dev
RUNTIME_IMAGE ?= lockboot:latest

# Snakeoil Secure Boot keys, generated fresh per build (openssl + uuidgen). Run in
# the build container so a slim host / CI runner without those tools still works.
tools/build-uki/keys/%: docker-build-base
	$(DOCKER_RUN) $(DOCKER_SAMEUSER) $(BUILD_IMAGE) make -C tools/build-uki/keys

clean:
	rm -rf tools/build-uki/x86_64/boot.disk tools/build-uki/x86_64/stage1 tools/build-uki/x86_64/tmp tools/build-uki/x86_64/*.img tools/build-uki/x86_64/*.efi tools/build-uki/x86_64/config-* tools/build-uki/x86_64/efi-vars.ovmf
	rm -rf tools/build-uki/aarch64/boot.disk tools/build-uki/aarch64/stage1 tools/build-uki/aarch64/tmp tools/build-uki/aarch64/*.img tools/build-uki/aarch64/*.efi tools/build-uki/aarch64/config-* tools/build-uki/aarch64/efi-vars.ovmf
	rm -rf tools/build-stage0/x86_64 tools/build-stage0/aarch64
	rm -f tools/build-uki/mkuki

distclean: clean
	$(MAKE) -C tools/build-uki clean
	$(MAKE) -C tools/build-uki/keys clean
	$(MAKE) -C tools/qemu-test clean

# Download + extract UKI dependencies in the build container, which has the tools
# (rpm2cpio, cpio, curl, xz); the host / CI runner may not (e.g. act's slim image).
# Each sub-make writes into the mounted tools/build-uki/$*/ tree.
tools/build-uki/%/busybox: docker-build-base
	$(DOCKER_RUN) $(DOCKER_SAMEUSER) $(BUILD_IMAGE) make -C tools/build-uki $*/busybox

tools/build-uki/%/stub.efi: docker-build-base
	$(DOCKER_RUN) $(DOCKER_SAMEUSER) $(BUILD_IMAGE) make -C tools/build-uki $*/stub.efi

tools/build-uki/%/kernel-core.rpm: docker-build-base
	$(DOCKER_RUN) $(DOCKER_SAMEUSER) $(BUILD_IMAGE) make -C tools/build-uki $*/kernel-core.rpm

tools/build-uki/%/kernel-modules-core.rpm: docker-build-base
	$(DOCKER_RUN) $(DOCKER_SAMEUSER) $(BUILD_IMAGE) make -C tools/build-uki $*/kernel-modules-core.rpm

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

# Build the netboot UKI (linux.efi) for a specific architecture. stage0 serves
# this as a file and admits it by sha256 + PCR 14; it is not a bootable disk.
tools/build-uki/%/linux.efi: tools/build-uki/%/busybox tools/build-uki/%/stage1 tools/build-uki/%/stub.efi tools/build-uki/%/kernel-core.rpm tools/build-uki/%/kernel-modules-core.rpm tools/build-uki/mkuki
	$(DOCKER_RUN) $(DOCKER_OPT_DOCKER) -e ARCH=$* \
		$(BUILD_IMAGE) ./tools/build-uki/build.sh

# Build AND extract stage1 inside the one container step, so the cp runs where
# target/ exists rather than in the host/make context, which may not see the build
# container's target dir under nested docker (e.g. `act`). `cp -v` also surfaces the
# real artifact path in the log if it ever goes missing again. --exclude mkuki: it
# is a build-host tool, built separately for x86_64 by the tools/build-uki/mkuki
# rule, so it must not be cross-compiled for $* here.
tools/build-uki/%/stage1: docker-build-base
	mkdir -p tools/build-uki/$*
	$(DOCKER_RUN) -e ARCH=$* $(DOCKER_SAMEUSER) $(BUILD_IMAGE) \
		bash -c "rustup target add $*-unknown-linux-musl && cargo build --release --locked --workspace --exclude mkuki --target $*-unknown-linux-musl && cp -v target/$*-unknown-linux-musl/release/stage1 $@"

# mkuki assembles the UKI from inside build.sh. Unlike stage1 (which runs on the
# target arch), mkuki is a build-host tool that runs in the x86_64 build container
# regardless of the UKI's target arch, so it is built once for the host musl target.
tools/build-uki/mkuki: docker-build-base
	$(DOCKER_RUN) $(DOCKER_SAMEUSER) $(BUILD_IMAGE) \
		bash -c "cargo build --release --locked -p mkuki --target x86_64-unknown-linux-musl && cp -v target/x86_64-unknown-linux-musl/release/mkuki $@"


#####################################################################
# stage0 (pure-UEFI network bootloader)

STAGE0_DIR = crates/stage0

# Guard the arch-less forms so `make stage0` / `boot-stage0` / `test-stage0` print
# a helpful message instead of "no rule to make target". Require an explicit arch.
.PHONY: stage0 boot-stage0 test-stage0 test-chain
stage0 boot-stage0 test-stage0 test-chain:
	@echo "'$@' needs an architecture suffix, e.g. 'make $@-x86_64' or 'make $@-aarch64'." >&2
	@exit 2

# Build the stage0 UEFI binary inside the build container. Same model as stage1:
# cargo runs in the container (never the host) and vaportpm is pulled from git,
# so only this repo is mounted.
tools/build-stage0/%/stage0.efi: docker-build-base
	mkdir -p tools/build-stage0/$*
	$(DOCKER_RUN) -e ARCH=$* $(DOCKER_SAMEUSER) $(BUILD_IMAGE) \
		bash -c "rustup target add $*-unknown-uefi && cargo build --release --manifest-path $(STAGE0_DIR)/Cargo.toml --target $*-unknown-uefi && cp -v $(STAGE0_DIR)/target/$*-unknown-uefi/release/stage0.efi $@"

# Assemble + sign the stage0 boot disk (losetup/mount -> privileged container).
tools/build-stage0/%/boot.disk: tools/build-stage0/%/stage0.efi tools/build-uki/keys/db.crt
	$(DOCKER_RUN) -e ARCH=$* $(BUILD_IMAGE) ./tools/build-stage0/build.sh

stage0-amd64 stage0-x86_64: tools/build-stage0/x86_64/boot.disk
stage0-arm64 stage0-aarch64: tools/build-stage0/aarch64/boot.disk

# Host:port the local payload server answers on. A hostname (not an IP literal) so
# the test also exercises EFI_DNS4 / the guest resolver; boot.sh maps it to
# 10.0.2.1 in the QEMU DNS. Override SERVE_HOST=10.0.2.1:8000 to skip DNS.
SERVE_HOST ?= payload.lockboot.test:8000
PAYLOAD_URL ?= http://$(SERVE_HOST)/payload.efi

# Shared QEMU-in-dev-container invocation for stage0 boots. The tap/iptables setup
# needs NET_ADMIN + a tun device; KVM is added when available.
STAGE0_QEMU = $(DOCKER_RUN) $(DOCKER_OPT_KVM) \
	-e YES_INSIDE_DOCKER_DO_DANGEROUS_IPTABLES=1 --cap-add=NET_ADMIN --device=/dev/net/tun \
	$(DEV_IMAGE) ./tools/qemu-test/boot.sh --kind stage0

# Boot stage0 under QEMU. With no arguments this builds and serves the signed
# end-to-end test payload, so `make boot-stage0-x86_64` works on its own. Knobs:
#   PAYLOAD=path/to/your.efi  serve a custom payload instead. Pinned by sha256, or
#                             by the release ed25519 key when a `<payload>.sig` and
#                             tools/build-stage0/keys/release.pub.b64 both exist.
#   USER_DATA=path/to.json    serve this `_stage1` doc verbatim (point its URL at
#                             anything the guest reaches); skips doc generation.
#   TRACE=1                   capture the guest TCP stream to stage0-trace.pcap
#                             (needs the dev image rebuilt: 'make docker-build-dev').
#
# user-data.stage0.json (gitignored) is regenerated every run to match the payload,
# so it can never go stale. It is deliberately NOT a make-prerequisite: a missing
# one must not disqualify this rule.
boot-stage0-%: tools/qemu-test/ec2-metadata-mock-linux-amd64 tools/build-stage0/%/boot.disk tools/build-stage0/%/payload.efi
	@P="$(PAYLOAD)"; [ -n "$$P" ] || P="tools/build-stage0/$*/payload.efi"; \
	if [ -n "$(USER_DATA)" ]; then \
		cp "$(USER_DATA)" user-data.stage0.json; \
		echo "Using user-data from $(USER_DATA)"; \
	elif [ -f "$$P.sig" ] && [ -f tools/build-stage0/keys/release.pub.b64 ]; then \
		PUB=$$(cat tools/build-stage0/keys/release.pub.b64); \
		printf '{\n  "_stage1": {\n    "%s": { "url": "%s", "ed25519": "%s" }\n  }\n}\n' \
			"$*" "$(PAYLOAD_URL)" "$$PUB" > user-data.stage0.json; \
		echo "Wrote user-data.stage0.json (signed mode, release pubkey $$PUB)"; \
	else \
		SHA=$$(sha256sum "$$P" | cut -d' ' -f1); \
		printf '{\n  "_stage1": {\n    "%s": { "url": "%s", "sha256": "%s" }\n  }\n}\n' \
			"$*" "$(PAYLOAD_URL)" "$$SHA" > user-data.stage0.json; \
		echo "Wrote user-data.stage0.json (sha256 mode, $$SHA)"; \
	fi; \
	$(STAGE0_QEMU) --arch $* --payload "$$P" $(if $(TRACE),--trace)

# Long-term ed25519 release signing key for stage0 "signed mode". This is the
# vendor key that signs payloads; it never touches a deployed machine — stage0
# only ever sees the *public* key, pinned in the metadata doc. Generated once in
# the build container (gitignored). release.pub.b64 is the raw 32-byte public
# key, base64-encoded, ready to drop straight into the _stage1 `ed25519` field.
tools/build-stage0/keys/release.pem: docker-build-base
	mkdir -p tools/build-stage0/keys
	$(DOCKER_RUN) $(DOCKER_SAMEUSER) $(BUILD_IMAGE) bash -c "\
		openssl genpkey -algorithm ed25519 -out tools/build-stage0/keys/release.pem && \
		openssl pkey -in tools/build-stage0/keys/release.pem -pubout -outform DER \
			| tail -c 32 | base64 -w0 > tools/build-stage0/keys/release.pub.b64"

# Build the end-to-end test payload (a chain-loaded UEFI app that reads PCRs) and
# attach a detached ed25519 signature (payload.efi.sig) made with the release
# key. The payload is NOT Secure Boot db-signed: stage0 verifies the signature
# against the pinned pubkey and loads it via a FileAuthentication override. It is
# served at $(PAYLOAD_URL) (a hostname, so the test exercises EFI_DNS4).
tools/build-stage0/%/payload.efi: docker-build-base tools/build-stage0/keys/release.pem
	mkdir -p tools/build-stage0/$*
	$(DOCKER_RUN) -e ARCH=$* $(DOCKER_SAMEUSER) $(BUILD_IMAGE) \
		bash -c "rustup target add $*-unknown-uefi && \
			cargo build --release --manifest-path crates/stage0-test-payload/Cargo.toml --target $*-unknown-uefi && \
			cp crates/stage0-test-payload/target/$*-unknown-uefi/release/stage0-test-payload.efi $@ && \
			openssl pkeyutl -sign -inkey tools/build-stage0/keys/release.pem -rawin -in $@ -out $@.sig"

# The signed end-to-end test (build + sign the test payload, pin the release
# pubkey, boot stage0, fetch/verify/measure/chain-load it) is now the default for
# `boot-stage0`. This stays as a named alias for it.
test-stage0-%:
	$(MAKE) boot-stage0-$* TRACE=$(TRACE)

# Build the example stage2 binary (the leaf stage1 downloads and runs) for the
# target musl. Served locally by the full-chain test below.
tools/build-stage0/%/stage2: docker-build-base
	mkdir -p tools/build-stage0/$*
	$(DOCKER_RUN) -e ARCH=$* $(DOCKER_SAMEUSER) $(BUILD_IMAGE) \
		bash -c "rustup target add $*-unknown-linux-musl && cargo build --release --locked -p example-stage2 --target $*-unknown-linux-musl && cp -v target/$*-unknown-linux-musl/release/example-stage2 $@"

# Full-chain end-to-end test: stage0 -> UKI -> stage1 -> example-stage2, all served
# from one local directory (no S3). A single served user-data carries `_stage1`
# (stage0 admits the UKI by sha256) and `_stage2` (stage1 admits stage2 by sha256);
# the two parsers coexist on distinct keys. Both hashes are computed from the local
# files, so the doc can never go stale.
test-chain-%: tools/build-uki/%/linux.efi tools/build-stage0/%/stage2 tools/build-stage0/%/boot.disk tools/qemu-test/ec2-metadata-mock-linux-amd64
	@D="tools/build-stage0/$*/chain"; rm -rf "$$D"; mkdir -p "$$D"; \
	cp tools/build-uki/$*/linux.efi "$$D/linux.efi"; \
	cp tools/build-stage0/$*/stage2 "$$D/stage2"; \
	UKI_SHA=$$(sha256sum "$$D/linux.efi" | cut -d' ' -f1); \
	S2_SHA=$$(sha256sum "$$D/stage2" | cut -d' ' -f1); \
	printf '{\n  "_stage1": { "%s": { "url": "http://%s/linux.efi", "sha256": "%s" } },\n  "_stage2": { "%s": { "url": "http://%s/stage2", "sha256": "%s" } }\n}\n' \
		"$*" "$(SERVE_HOST)" "$$UKI_SHA" "$*" "$(SERVE_HOST)" "$$S2_SHA" > user-data.stage0.json; \
	echo "Wrote user-data.stage0.json (chain: UKI $$UKI_SHA, stage2 $$S2_SHA)"; \
	$(STAGE0_QEMU) --arch $* --serve-dir "$$D" $(if $(TRACE),--trace)


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
