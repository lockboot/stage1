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

# ---- Shared build harness (docker images + DOCKER_RUN plumbing) ----
# Vendored byte-identically from stage0/build.mk (the canonical source) via the workspace
# `make sync-harness`; do not hand-edit. `make check-harness` guards against drift.
include build.mk

# stage1-only: runtime OCI image tag for the docker-runtime / buildx targets below.
RUNTIME_IMAGE ?= lockboot:latest

docker-shell-base: docker-build-base
	$(DOCKER_RUN) -ti $(DOCKER_SAMEUSER) $(DOCKER_OPT_DOCKER) $(DOCKER_OPT_KVM) $(BUILD_IMAGE) bash

docker-clean:
	docker rmi $(BUILD_IMAGE) || true

# ---- CI gate: fmt + clippy + unit tests across the workspace (what the branch ruleset requires) ----
.PHONY: ci fmt-fix
ci: docker-build-base
	$(DOCKER_RUN) $(DOCKER_SAMEUSER) $(BUILD_IMAGE) bash -c "\
		cargo fmt --all --check && \
		cargo clippy --workspace --all-targets --locked -- -D warnings && \
		cargo test --workspace --locked"
fmt-fix: docker-build-base ## Apply rustfmt across the whole workspace (no --check)
	$(DOCKER_RUN) $(DOCKER_SAMEUSER) $(BUILD_IMAGE) cargo fmt --all


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

# Regenerate tools/build-uki/fedora-deps.mk (pinned, GPG-verified kernel + systemd-boot stub).
#   make update-fedora-deps FCOS=44.20260621.3.1 [SYSTEMD=259.6-1.fc44] [KERNEL=<nvr>]
# Kernel NVR is read from the FCOS build manifest; the stub is pulled from Fedora (explicit SYSTEMD,
# else latest stable via Bodhi). Every RPM's Fedora GPG signature is verified before it is pinned.
.PHONY: update-fedora-deps
update-fedora-deps: docker-build-base
	@[ -n "$(FCOS)" ] || [ -n "$(KERNEL)" ] || { echo "set FCOS=<version> (and optionally SYSTEMD=<nvr>)"; exit 1; }
	$(DOCKER_RUN) $(DOCKER_SAMEUSER) $(BUILD_IMAGE) \
		python3 tools/build-uki/update-fedora-deps.py \
			$(if $(FCOS),--fcos $(FCOS)) $(if $(SYSTEMD),--systemd $(SYSTEMD)) $(if $(KERNEL),--kernel $(KERNEL))


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

# The deploy CLI (lockboot-deploy) is the canonical signer + keygen; the tests dogfood it so the
# exact signing + domain-separation code paths are exercised.
# Built in the container; a musl static binary that runs there. cargo no-ops when up to date.
DEPLOY := target/x86_64-unknown-linux-musl/debug/lockboot-deploy
.PHONY: deploy-bin
deploy-bin: docker-build-base
	$(DOCKER_RUN) $(DOCKER_SAMEUSER) $(BUILD_IMAGE) cargo build -p deploy

# ed25519 release key for SIGN=1 (signed-mode admission). stage0 only ever sees the public half,
# pinned in the _stage1 doc; the private key signs the UKI. Generated in the build container
# (gitignored under build/keys) by `lockboot-deploy keygen`.
build/keys/release.pem: docker-build-base | deploy-bin
	$(DOCKER_RUN) $(DOCKER_SAMEUSER) $(BUILD_IMAGE) bash -c "\
		mkdir -p build/keys && \
		$(DEPLOY) keygen --out build/keys/release.pem --pub build/keys/release.pub.b64"

# Detached, domain-separated ed25519 sigs over the UKI and stage2 (SIGN=1): lockboot-deploy signs
# sha256(domain)||sha256(payload), which stage0/stage1 verify against the pinned pubkey. Served as
# <name>.sig; each verifier fetches <url>.sig in ed25519 mode.
build/%/linux.efi.sig: tools/build-uki/%/linux.efi build/keys/release.pem | deploy-bin
	$(DOCKER_RUN) $(DOCKER_SAMEUSER) $(BUILD_IMAGE) bash -c "\
		mkdir -p build/$* && \
		$(DEPLOY) sign --domain stage1.uki --key build/keys/release.pem \
			--in tools/build-uki/$*/linux.efi --out build/$*/linux.efi.sig"

build/%/stage2.sig: build/%/stage2 build/keys/release.pem | deploy-bin
	$(DOCKER_RUN) $(DOCKER_SAMEUSER) $(BUILD_IMAGE) bash -c "\
		mkdir -p build/$* && \
		$(DEPLOY) sign --domain stage2.payload --key build/keys/release.pem \
			--in build/$*/stage2 --out build/$*/stage2.sig"

# Signed remote args for SIGN_ARGS=1: a JSON array of strings, domain-signed like the payloads.
# stage1 fetches args.json + args.json.sig, verifies against the pinned key, and uses them as argv.
build/%/args.json.sig: build/keys/release.pem | deploy-bin
	$(DOCKER_RUN) $(DOCKER_SAMEUSER) $(BUILD_IMAGE) bash -c "\
		mkdir -p build/$* && \
		printf '%s' '[\"--from\",\"signed-args\"]' > build/$*/args.json && \
		$(DEPLOY) sign --domain stage2.args --key build/keys/release.pem \
			--in build/$*/args.json --out build/$*/args.json.sig"

# Guard the arch-less form with a helpful message instead of "no rule to make target".
.PHONY: test-chain
test-chain:
	@echo "'$@' needs an arch suffix, e.g. 'make $@-x86_64' or 'make $@-aarch64'." >&2
	@exit 2

# Full-chain end-to-end test: stage0 -> UKI -> stage1 -> example-stage2, served from one
# local dir. One served user-data carries `_stage1` (stage0 admits the UKI) and `_stage2`
# (stage1 admits the leaf); the two parsers coexist on distinct keys. Hashes are computed
# from the local files so the doc can't go stale. Each arch entry is the discriminated union
# `{ "payload": {…} }` (admit a binary) or `{ "manifest": {…} }` (resolve a signed manifest). Modes:
#   (default)    sha256 pins for both hops (payload entries).
#   SIGN=1       ed25519 for BOTH hops: serve linux.efi.sig + stage2.sig, pin the release
#                pubkey in the _stage1 / _stage2 payloads (roll forward under a stable key).
#   SIGN_ARGS=1  (implies SIGN) also serve signed args.json (+ .sig) and set the _stage2 payload's
#                args_url, exercising stage1's signed-remote-args path.
#   MANIFEST=1   (with SIGN=1) resolve _stage2 through a signed manifest: build + sign a
#                `{ "_stage2": { "<arch>": { "payload": {…} } } }` fragment, serve it, and pin
#                `{ "manifest": { url, ed25519 } }` — exercising stage1's manifest resolution +
#                top-level merge. Pair with ARGS (bound inside the manifest), not SIGN_ARGS.
#   ARGS='[..]'  set the _stage2 payload's inline args to this JSON array (ignored when SIGN_ARGS
#                is set, which supplies its own signed args). Used by the smoke-args-% target.
#   FALLBACK=1   make the _stage2 url a list [dead 127.0.0.1:9, real] so stage1's mirror
#                fallback is exercised (the first url refuses, the second serves).
test-chain-%: tools/build-uki/%/linux.efi build/%/stage2 \
		$(if $(SIGN),build/%/linux.efi.sig build/%/stage2.sig) \
		$(if $(SIGN_ARGS),build/%/args.json.sig)
	@if [ ! -f "$(STAGE0_BOOT_DISK)" ]; then \
		echo "Missing external stage0 boot disk: $(STAGE0_BOOT_DISK)" >&2; \
		echo "Build it first:  (cd $(STAGE0_DIR) && make build-$*)" >&2; \
		echo "or set STAGE0_BOOT_DISK=<path> to one unpacked from a stage0 release." >&2; \
		exit 1; \
	fi
	@D="build/$*/chain"; rm -rf "$$D"; mkdir -p "$$D"; H="http://$(SERVE_HOST)"; \
	cp tools/build-uki/$*/linux.efi "$$D/linux.efi"; \
	cp build/$*/stage2 "$$D/stage2"; \
	S2URL="\"$$H/stage2\""; \
	if [ -n "$(FALLBACK)" ]; then S2URL="[ \"http://127.0.0.1:9/stage2\", \"$$H/stage2\" ]"; echo "fallback: stage2 url = [dead 127.0.0.1:9, $$H/stage2]"; fi; \
	INLINE_ARGS=""; \
	if [ -n '$(ARGS)' ] && [ -z "$(SIGN_ARGS)" ]; then INLINE_ARGS=", \"args\": $$(printf '%s' '$(ARGS)')"; echo "inline payload args = $(ARGS)"; fi; \
	if [ -n "$(SIGN)" ]; then \
		cp build/$*/linux.efi.sig "$$D/linux.efi.sig"; \
		PUB=$$(cat build/keys/release.pub.b64); \
		S1="\"$*\": { \"payload\": { \"url\": \"$$H/linux.efi\", \"ed25519\": \"$$PUB\" } }"; \
		P2="\"url\": $$S2URL, \"ed25519\": \"$$PUB\""; \
		if [ -n "$(SIGN_ARGS)" ]; then \
			cp build/$*/args.json "$$D/args.json"; cp build/$*/args.json.sig "$$D/args.json.sig"; \
			P2="$$P2, \"args_url\": \"$$H/args.json\""; \
		fi; \
		if [ -n "$(MANIFEST)" ]; then \
			S2_SHA=$$(sha256sum "$$D/stage2" | cut -d' ' -f1); \
			printf '{ "_stage2": { "%s": { "payload": { "url": "%s/stage2", "sha256": "%s"%s } } } }\n' "$*" "$$H" "$$S2_SHA" "$$INLINE_ARGS" > "$$D/stage2.manifest.json"; \
			$(DOCKER_RUN) $(DOCKER_SAMEUSER) $(BUILD_IMAGE) bash -c \
				"$(DEPLOY) sign --domain stage2.manifest --key build/keys/release.pem --in $$D/stage2.manifest.json --out $$D/stage2.manifest.json.sig"; \
			S2="\"$*\": { \"manifest\": { \"url\": \"$$H/stage2.manifest.json\", \"ed25519\": \"$$PUB\" } }"; \
			echo "user-data: _stage2 via signed manifest (pubkey $$PUB)"; \
		else \
			cp build/$*/stage2.sig "$$D/stage2.sig"; \
			S2="\"$*\": { \"payload\": { $$P2$$INLINE_ARGS } }"; \
			echo "user-data: signed mode (pubkey $$PUB)"; \
		fi; \
	else \
		UKI_SHA=$$(sha256sum "$$D/linux.efi" | cut -d' ' -f1); \
		S2_SHA=$$(sha256sum "$$D/stage2" | cut -d' ' -f1); \
		S1="\"$*\": { \"payload\": { \"url\": \"$$H/linux.efi\", \"sha256\": \"$$UKI_SHA\" } }"; \
		S2="\"$*\": { \"payload\": { \"url\": $$S2URL, \"sha256\": \"$$S2_SHA\"$$INLINE_ARGS } }"; \
		echo "user-data: sha256 mode (UKI $$UKI_SHA, stage2 $$S2_SHA)"; \
	fi; \
	printf '{\n  "_stage1": { %s },\n  "_stage2": { %s }\n}\n' "$$S1" "$$S2" > user-data.stage0.json; \
	$(DOCKER_RUN) $(DOCKER_OPT_KVM) \
		-e YES_INSIDE_DOCKER_DO_DANGEROUS_IPTABLES=1 --cap-add=NET_ADMIN --device=/dev/net/tun \
		$(HARNESS_IMAGE) --kind stage0 --arch $* \
			--boot-disk "$(STAGE0_BOOT_DISK)" \
			--serve-dir "$$D" --user-data user-data.stage0.json $(if $(TRACE),--trace)

# ---- Smoke test: _stage2 args actually reach the payload's argv ----
# Boot the full chain with a known inline args array (one arg contains a space, to prove
# it is a real argv vector and not shell word-splitting) and assert the payload echoed it.
# The signed-remote-args path is covered separately by `test-chain-% SIGN=1 SIGN_ARGS=1`.
.PHONY: smoke-args-%
smoke-args-%:
	@log="build/$*/smoke-args.log"; mkdir -p "build/$*"; \
	$(MAKE) test-chain-$* ARGS='["--smoke","hello world"]' 2>&1 | tee "$$log"; \
	echo "=== smoke-args assertion ==="; \
	if grep -q 'arg\[1\]: --smoke' "$$log" && grep -q 'arg\[2\]: hello world' "$$log"; then \
		echo "PASS: inline _stage2.args reached the payload argv (spaces preserved)"; \
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
