# ---- Lock.Boot shared build harness ----------------------------------------------------------
# Runs every cargo/tool invocation inside the locally-built lockboot:build image, so builds are
# cc-free-by-design and byte-reproducible (rust-lld + musl, shared /src/.cargo + /src/.rustup).
#
# CANONICAL SOURCE: stage0/build.mk. This file is vendored byte-identically into each participating
# repo (stage1, vaportpm, ...) because CI checks out each repo ALONE (no workspace parent), so a
# shared harness cannot be a cross-repo include -- it must live in the repo. Do NOT hand-edit the
# copies: edit stage0/build.mk, then run `make sync-harness` from the workspace ($(CANON)=stage0),
# guarded by `make check-harness`.
#
# Each repo's Makefile does `include build.mk` and defines its own targets, invoking cargo as
#   $(DOCKER_RUN) $(DOCKER_SAMEUSER) $(BUILD_IMAGE) cargo ...
# with a `docker-build-base` prerequisite so the image is built on demand (incl. standalone CI).

# ---- Docker images (shared lockboot family; built locally, never published) ----
BUILD_IMAGE   = lockboot:build
HARNESS_IMAGE = lockboot:harness

.PHONY: docker-build-base
docker-build-base:
	docker build -f Dockerfile.build -t $(BUILD_IMAGE) .

# ---- Docker run plumbing (keep identical across repos) ----
# Own build artifacts by whoever owns the checkout, not the caller's euid. Under
# `gh act` the caller is root but the bind-mounted tree is still yours, so stat
# keeps output user-owned instead of trampling the project dir with root files.
# On a normal host/devcontainer run this equals `id -u`/`id -g`, so nothing changes.
USER_ID  := $(shell stat -c %u .)
GROUP_ID := $(shell stat -c %g .)

KVM_GID   := $(shell stat -c %g /dev/kvm 2>/dev/null || echo "")
KVM_MOUNT := $(shell test -e /dev/kvm && echo "-v /dev/kvm:/dev/kvm")
DOCKER_OPT_KVM := $(if $(KVM_GID),--group-add $(KVM_GID)) $(KVM_MOUNT)

# Recursive-docker passthrough: rules that shell out to the HOST docker daemon (e.g. stage1's UKI
# rootfs extraction / runtime-image buildx) forward the socket + its gid. Defined here for every
# repo; harmless (expands empty) when a repo has no such rule.
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
