# stage1 - the netboot UKI (Linux stage1 + example leaf). Standalone build + test.
#
#   make / make build         build the netboot UKI linux.efi (both arches)
#   make x86_64 | aarch64     build the UKI for one arch
#   make stage2-<arch>        build the example-stage2 leaf payload
#   make test-chain-<arch>    boot the whole chain under QEMU, using the EXTERNAL
#                             stage0 as the harness (../stage0/build/<arch>/boot.disk)
# Knobs for test-chain:
#   SIGN=1                    admit the UKI by ed25519 signature instead of sha256
#   STAGE0_DIR=../stage0      where the sibling stage0 boot.disk is built
#   STAGE0_BOOT_DISK=<path>   explicit boot.disk (out-of-workspace escape hatch)
#   TRACE=1                   capture the guest TCP stream to ./stage0-trace.pcap

.PRECIOUS: tools/build-uki/% build/%/stage2 build/%/linux.efi.sig

all: build

ARCHS = x86_64 aarch64
.PHONY: build
build: $(ARCHS)

.PHONY: amd64 x86_64 arm64 aarch64
amd64 x86_64: tools/build-uki/x86_64/linux.efi
arm64 aarch64: tools/build-uki/aarch64/linux.efi

# Reference production _stage1/_stage2 doc (served from S3 in prod).
DEFAULT_STAGE2_URL = https://lockboot.s3.us-east-1.amazonaws.com/examples/stage2/user-data.json
user-data.json:
	wget -O "$@" $(DEFAULT_STAGE2_URL)

# ---- Docker images (shared lockboot family; built locally, never published) ----
# BUILD_IMAGE compiles everything; HARNESS_IMAGE (from stage0) runs the qemu chain
# test. Both are built by the workspace `make image` from stage0 (the canonical
# Dockerfiles); a standalone CI clone builds BUILD_IMAGE itself via docker-build-base.
BUILD_IMAGE   = lockboot:build
HARNESS_IMAGE = lockboot:harness
RUNTIME_IMAGE ?= lockboot:latest

.PHONY: docker-build-base
docker-build-base:
	docker build -f Dockerfile.build -t $(BUILD_IMAGE) .

# ---- Docker run plumbing (keep identical across repos; mirrors stage0/Makefile) ----
# Own build artifacts by whoever owns the checkout, not the caller's euid. Under
# `gh act` the caller is root but the bind-mounted tree is still yours, so stat
# keeps output user-owned instead of trampling the project dir with root files.
USER_ID  := $(shell stat -c %u .)
GROUP_ID := $(shell stat -c %g .)

KVM_GID   := $(shell stat -c %g /dev/kvm 2>/dev/null || echo "")
KVM_MOUNT := $(shell test -e /dev/kvm && echo "-v /dev/kvm:/dev/kvm")
DOCKER_OPT_KVM := $(if $(KVM_GID),--group-add $(KVM_GID)) $(KVM_MOUNT)

# Recursive-docker passthrough: the UKI rule and runtime-image build shell out to
# the HOST docker daemon (rootfs extraction / buildx), so forward the socket + gid.
DOCKER_SOCK_GID   := $(shell stat -c %g /var/run/docker.sock 2>/dev/null || echo "")
DOCKER_SOCK_MOUNT := $(shell test -e /var/run/docker.sock && echo "-v /var/run/docker.sock:/var/run/docker.sock")
DOCKER_OPT_DOCKER := $(DOCKER_SOCK_MOUNT) $(if $(DOCKER_SOCK_GID),--group-add $(DOCKER_SOCK_GID))

DOCKER_SAMEUSER := -u $(USER_ID):$(GROUP_ID)

# Host-path translation for docker-in-devcontainer. Inside the devcontainer /src is
# a host bind mount and the inner Docker talks to the HOST daemon, which cannot
# resolve /src/... paths; translate $(CURDIR) to the real host path (the bracketed
# subpath findmnt reports for the /src bind). On the host CURDIR is not under /src,
# so this is a pass-through and your workflow is unchanged. Keep identical across repos.
HOST_DIR := $(CURDIR)
ifneq ($(filter /src/%,$(CURDIR)),)
  SRC_BIND := $(shell findmnt -fnro SOURCE --target /src 2>/dev/null | sed -n 's/.*\[\(.*\)\]$$/\1/p')
  ifneq ($(SRC_BIND),)
    HOST_DIR := $(SRC_BIND)$(CURDIR:/src%=%)
  endif
endif

# Mount the WORKSPACE (parent of this repo) at /src so builds reuse the shared
# workspace-level .cargo/.rustup (matching the devcontainer), instead of creating
# per-repo copies. The repo then lives at /src/$(REPO_NAME).
REPO_NAME := $(notdir $(HOST_DIR))
HOST_WS   := $(patsubst %/,%,$(dir $(HOST_DIR)))

# Under CI / `gh act` (CI=true, runs as root) keep cargo/rustup caches ephemeral
# inside the container, so root-owned dirs never land in the bind-mounted project.
# Locally (no CI) the image's CARGO_HOME=/src/.cargo + RUSTUP_HOME=/src/.rustup win,
# i.e. the shared workspace caches.
CACHE_ENV := $(if $(CI),-e CARGO_HOME=/tmp/.cargo -e RUSTUP_HOME=/tmp/.rustup)

DOCKER_RUN = docker run --rm \
	--privileged \
	-v $(HOST_WS):/src \
	-h lockboot \
	--add-host lockboot:127.0.0.1 \
	-e OWNER_UID=$(USER_ID) \
	-e OWNER_GID=$(GROUP_ID) \
	$(CACHE_ENV) \
	-w /src/$(REPO_NAME)

docker-shell-base: docker-build-base
	$(DOCKER_RUN) -ti $(DOCKER_SAMEUSER) $(DOCKER_OPT_DOCKER) $(DOCKER_OPT_KVM) $(BUILD_IMAGE) bash

docker-clean:
	docker rmi $(BUILD_IMAGE) || true


#####################################################################
# UKI build (stage0 serves linux.efi over the network and admits it by
# sha256 + PCR 14; it is a netboot payload, not a bootable disk).

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

# Build the netboot UKI (linux.efi) for a specific architecture. build.sh extracts
# a rootfs via the HOST docker daemon, so DOCKER_OPT_DOCKER forwards the socket.
tools/build-uki/%/linux.efi: tools/build-uki/%/busybox tools/build-uki/%/stage1 tools/build-uki/%/stub.efi tools/build-uki/%/kernel-core.rpm tools/build-uki/%/kernel-modules-core.rpm tools/build-uki/mkuki
	$(DOCKER_RUN) $(DOCKER_OPT_DOCKER) -e ARCH=$* \
		$(BUILD_IMAGE) ./tools/build-uki/build.sh

# Build AND extract stage1 inside the one container step, so the cp runs where
# target/ exists rather than in the host/make context, which may not see the build
# container's target dir under nested docker (e.g. `act`). --exclude mkuki/deploy: they
# are build-host tools (mkuki assembles the UKI; deploy generates deployment config), so
# they must not be cross-compiled for the payload target $* here.
tools/build-uki/%/stage1: docker-build-base
	mkdir -p tools/build-uki/$*
	$(DOCKER_RUN) -e ARCH=$* $(DOCKER_SAMEUSER) $(BUILD_IMAGE) \
		bash -c "rustup target add $*-unknown-linux-musl && cargo build --release --locked --workspace --exclude mkuki --exclude deploy --target $*-unknown-linux-musl && cp -v target/$*-unknown-linux-musl/release/stage1 $@"

# mkuki assembles the UKI from inside build.sh. Unlike stage1 (which runs on the
# target arch), mkuki is a build-host tool that runs in the x86_64 build container
# regardless of the UKI's target arch, so it is built once for the host musl target.
tools/build-uki/mkuki: docker-build-base
	$(DOCKER_RUN) $(DOCKER_SAMEUSER) $(BUILD_IMAGE) \
		bash -c "cargo build --release --locked -p mkuki --target x86_64-unknown-linux-musl && cp -v target/x86_64-unknown-linux-musl/release/mkuki $@"


#####################################################################
# Runtime container image (busybox + stage1) -> ghcr on uki-v* tags.

docker-buildx-setup:
	docker buildx create --name lockboot-builder --use || docker buildx use lockboot-builder
	docker buildx inspect --bootstrap

docker-runtime: tools/build-uki/x86_64/busybox tools/build-uki/x86_64/stage1 tools/build-uki/aarch64/busybox tools/build-uki/aarch64/stage1
	docker buildx build -f Dockerfile.runtime -t $(RUNTIME_IMAGE) --load .

docker-runtime-oci: tools/build-uki/x86_64/busybox tools/build-uki/x86_64/stage1 tools/build-uki/aarch64/busybox tools/build-uki/aarch64/stage1
	docker buildx build --platform linux/amd64,linux/arm64 -f Dockerfile.runtime -t $(RUNTIME_IMAGE) --output type=oci,dest=lockboot.oci .

.PHONY: docker-buildx-setup docker-runtime docker-runtime-oci


#####################################################################
# example-stage2 leaf (the binary stage1 downloads, verifies, and execs).

build/%/stage2: docker-build-base
	$(DOCKER_RUN) -e ARCH=$* $(DOCKER_SAMEUSER) $(BUILD_IMAGE) \
		bash -c "mkdir -p build/$* && rustup target add $*-unknown-linux-musl && cargo build --release --locked -p example-stage2 --target $*-unknown-linux-musl && cp -v target/$*-unknown-linux-musl/release/example-stage2 build/$*/stage2"

.PHONY: stage2-amd64 stage2-x86_64 stage2-arm64 stage2-aarch64
stage2-amd64 stage2-x86_64: build/x86_64/stage2
stage2-arm64 stage2-aarch64: build/aarch64/stage2


#####################################################################
# Full-chain test: stage0 (EXTERNAL harness) -> UKI -> stage1 -> example-stage2
#
# stage1 owns no boot apparatus. stage0 IS the harness: we borrow its boot.disk
# (built in the sibling repo) and the shared lockboot:harness image, and provide
# only {UKI, leaf, signed/pinned _stage1+_stage2 manifest} - stage0's whole
# integration surface. Local-only: needs nested KVM, so it never runs on CI.

# Where the external stage0 boot.disk comes from. In-workspace this is the sibling
# clone; out-of-workspace, point STAGE0_BOOT_DISK at one unpacked from a stage0 release.
STAGE0_DIR ?= ../stage0
STAGE0_BOOT_DISK ?= $(STAGE0_DIR)/build/$*/boot.disk

# Host:port the local payload server answers on. Default to the tap gateway IP so
# BOTH hops are DNS-free: stage0 fetches the UKI (its own DNS4 is exercised by the
# stage0 repo's tests), and — crucially — stage1 fetches _stage2 from inside the
# booted Linux guest, whose DNS the shared stage0 harness does not wire for the
# mapped hostname. Override SERVE_HOST=payload.lockboot.test:8000 to also drive
# stage0's DNS4 on the _stage1 hop (the _stage2 hop then needs guest DNS).
SERVE_HOST ?= 10.0.2.1:8000

# ed25519 release key for SIGN=1 (signed-mode admission). stage0 only ever sees the
# public half, pinned in the _stage1 doc; the private key signs the UKI. Generated
# in the build container (gitignored under build/keys).
build/keys/release.pem: docker-build-base
	$(DOCKER_RUN) $(DOCKER_SAMEUSER) $(BUILD_IMAGE) bash -c "\
		mkdir -p build/keys && \
		openssl genpkey -algorithm ed25519 -out build/keys/release.pem && \
		openssl pkey -in build/keys/release.pem -pubout -outform DER \
			| tail -c 32 | base64 -w0 > build/keys/release.pub.b64"

# In ed25519 mode each hop is admitted via a signed **manifest** ({ url, sha256, args,
# version }); the manifests are built + signed inside the test-chain recipe (below) because
# their `args` and mirror lists vary per run. ed25519 is deterministic, so `openssl pkeyutl
# -rawin` yields the exact bytes stage0/stage1 verify against the pinned pubkey.

# Guard the arch-less form with a helpful message instead of "no rule to make target".
.PHONY: test-chain
test-chain:
	@echo "'$@' needs an arch suffix, e.g. 'make $@-x86_64' or 'make $@-aarch64'." >&2
	@exit 2

# Full-chain end-to-end test: stage0 -> UKI -> stage1 -> example-stage2, served from one
# local dir. One served user-data carries `_stage1` (stage0 admits the UKI) and `_stage2`
# (stage1 admits the leaf); the two parsers coexist on distinct keys. Hashes are computed
# from the local files so the doc can't go stale. Modes:
#   (default)    sha256 pins for both hops (inline in the trusted user-data).
#   SIGN=1       ed25519 for BOTH hops: build + sign a manifest per hop ({ url, sha256, args,
#                version }), pin the release pubkey + manifest_url in _stage1 / _stage2.
#   ARGS='[..]'  stage2 args (JSON array). In SIGN mode they ride inside the signed manifest;
#                in sha256 mode they are inline _stage2.args. Used by the smoke-args-% target.
#   FALLBACK=1   make the _stage2 fetch URL a list [dead 127.0.0.1:9, real] so stage1's mirror
#                fallback is exercised (SIGN: the manifest_url list; sha256: the payload url).
test-chain-%: tools/build-uki/%/linux.efi build/%/stage2 $(if $(SIGN),build/keys/release.pem)
	@if [ ! -f "$(STAGE0_BOOT_DISK)" ]; then \
		echo "Missing external stage0 boot disk: $(STAGE0_BOOT_DISK)" >&2; \
		echo "Build it first:  (cd $(STAGE0_DIR) && make build-$*)" >&2; \
		echo "or set STAGE0_BOOT_DISK=<path> to one unpacked from a stage0 release." >&2; \
		exit 1; \
	fi
	@D="build/$*/chain"; rm -rf "$$D"; mkdir -p "$$D"; H="http://$(SERVE_HOST)"; \
	cp tools/build-uki/$*/linux.efi "$$D/linux.efi"; \
	cp build/$*/stage2 "$$D/stage2"; \
	UKI_SHA=$$(sha256sum "$$D/linux.efi" | cut -d' ' -f1); \
	S2_SHA=$$(sha256sum "$$D/stage2" | cut -d' ' -f1); \
	ARGSJSON="[]"; if [ -n '$(ARGS)' ]; then ARGSJSON=$$(printf '%s' '$(ARGS)'); fi; \
	if [ -n "$(SIGN)" ]; then \
		PUB=$$(cat build/keys/release.pub.b64); \
		printf '{ "url": "%s/linux.efi", "sha256": "%s", "args": [], "version": 1 }\n' "$$H" "$$UKI_SHA" > "$$D/linux.efi.manifest.json"; \
		printf '{ "url": "%s/stage2", "sha256": "%s", "args": %s, "version": 1 }\n' "$$H" "$$S2_SHA" "$$ARGSJSON" > "$$D/stage2.manifest.json"; \
		$(DOCKER_RUN) $(DOCKER_SAMEUSER) $(BUILD_IMAGE) bash -c "\
			openssl pkeyutl -sign -inkey build/keys/release.pem -rawin -in $$D/linux.efi.manifest.json -out $$D/linux.efi.manifest.json.sig && \
			openssl pkeyutl -sign -inkey build/keys/release.pem -rawin -in $$D/stage2.manifest.json -out $$D/stage2.manifest.json.sig"; \
		S2MURL="\"$$H/stage2.manifest.json\""; \
		if [ -n "$(FALLBACK)" ]; then S2MURL="[ \"http://127.0.0.1:9/stage2.manifest.json\", \"$$H/stage2.manifest.json\" ]"; echo "fallback: stage2 manifest_url = [dead 127.0.0.1:9, real]"; fi; \
		S1="\"$*\": { \"ed25519\": \"$$PUB\", \"manifest_url\": \"$$H/linux.efi.manifest.json\" }"; \
		S2="\"$*\": { \"ed25519\": \"$$PUB\", \"manifest_url\": $$S2MURL }"; \
		echo "user-data: signed manifest mode (pubkey $$PUB, stage2 args $$ARGSJSON)"; \
		printf '{\n  "_stage1": { %s },\n  "_stage2": { %s }\n}\n' "$$S1" "$$S2" > user-data.stage0.json; \
	else \
		S2URL="\"$$H/stage2\""; \
		if [ -n "$(FALLBACK)" ]; then S2URL="[ \"http://127.0.0.1:9/stage2\", \"$$H/stage2\" ]"; echo "fallback: stage2 url = [dead 127.0.0.1:9, real]"; fi; \
		S1="\"$*\": { \"url\": \"$$H/linux.efi\", \"sha256\": \"$$UKI_SHA\" }"; \
		S2="\"$*\": { \"url\": $$S2URL, \"sha256\": \"$$S2_SHA\" }"; \
		S2ARGS=""; if [ -n '$(ARGS)' ]; then S2ARGS="\"args\": $$ARGSJSON, "; fi; \
		echo "user-data: sha256 mode (UKI $$UKI_SHA, stage2 $$S2_SHA, args $$ARGSJSON)"; \
		printf '{\n  "_stage1": { %s },\n  "_stage2": { %s%s }\n}\n' "$$S1" "$$S2ARGS" "$$S2" > user-data.stage0.json; \
	fi; \
	$(DOCKER_RUN) $(DOCKER_OPT_KVM) \
		-e YES_INSIDE_DOCKER_DO_DANGEROUS_IPTABLES=1 --cap-add=NET_ADMIN --device=/dev/net/tun \
		$(HARNESS_IMAGE) --kind stage0 --arch $* \
			--boot-disk "$(STAGE0_BOOT_DISK)" \
			--serve-dir "$$D" --user-data user-data.stage0.json $(if $(TRACE),--trace)

# ---- Smoke test: _stage2 args reach the payload's argv (via the signed manifest) ----
# Boot the full chain in ed25519 signed mode with a known args array (one arg contains a
# space, to prove a real argv vector and not shell word-splitting) carried inside the signed
# manifest, and assert the payload echoed it. Also exercises the manifest->stdin merge. The
# sha256 inline-args path is the simpler subset (`test-chain-% ARGS=...` with no SIGN).
.PHONY: smoke-args-%
smoke-args-%:
	@log="build/$*/smoke-args.log"; mkdir -p "build/$*"; \
	$(MAKE) test-chain-$* SIGN=1 ARGS='["--smoke","hello world"]' 2>&1 | tee "$$log"; \
	echo "=== smoke-args assertion ==="; \
	if grep -q 'arg\[1\]: --smoke' "$$log" && grep -q 'arg\[2\]: hello world' "$$log"; then \
		echo "PASS: signed-manifest _stage2.args reached the payload argv (spaces preserved)"; \
	else \
		echo "FAIL: expected 'arg[1]: --smoke' and 'arg[2]: hello world' in the console output"; \
		exit 1; \
	fi


#####################################################################
# Housekeeping

.PHONY: clean distclean
# Remove per-arch build output. Plain rm (no docker needed). build/keys/ (SIGN=1
# release key) is left in place.
clean:
	rm -rf tools/build-uki/x86_64/boot.disk tools/build-uki/x86_64/stage1 tools/build-uki/x86_64/tmp tools/build-uki/x86_64/*.img tools/build-uki/x86_64/*.efi tools/build-uki/x86_64/config-* tools/build-uki/x86_64/efi-vars.ovmf
	rm -rf tools/build-uki/aarch64/boot.disk tools/build-uki/aarch64/stage1 tools/build-uki/aarch64/tmp tools/build-uki/aarch64/*.img tools/build-uki/aarch64/*.efi tools/build-uki/aarch64/config-* tools/build-uki/aarch64/efi-vars.ovmf
	rm -rf build/x86_64 build/aarch64
	rm -f tools/build-uki/mkuki

distclean: clean
	$(MAKE) -C tools/build-uki clean


#####################################################################
# Git tagging helpers

TAG ?= v0.1.0

tag:
	@echo "Creating tag: $(TAG)"
	git tag -d $(TAG) 2>/dev/null || true
	git push origin :refs/tags/$(TAG) 2>/dev/null || true
	git tag -a $(TAG) -m "Release $(TAG)"
	git push origin $(TAG)

untag:
	@echo "Deleting tag: $(TAG)"
	git tag -d $(TAG) 2>/dev/null || true
	git push origin :refs/tags/$(TAG) 2>/dev/null || true

list-tags:
	git tag -l

git-edit:
	git commit --amend --no-edit
