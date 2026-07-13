#!/usr/bin/env python3
"""Regenerate fedora-deps.mk: the pinned kernel + systemd-boot-stub versions and SHA256s for the UKI.

Bump the deps with e.g.:

    make update-fedora-deps FCOS=44.20260621.3.1 SYSTEMD=259.6-1.fc44

The kernel NVR comes from the Fedora CoreOS build manifest (what FCOS actually ships); the
systemd-boot stub is pulled straight from Fedora (FCOS uses grub, not sd-boot), pinned either
explicitly via --systemd or to the latest stable in that Fedora release via Bodhi. Every RPM is
downloaded from Koji and its Fedora GPG signature verified (verify-rpm-gpg.sh) before its SHA256 is
recorded, so the pins provably correspond to genuinely Fedora-signed packages -- not just "whatever
bytes were at that URL when someone ran the bump".

Runs inside the build image (needs python3, rpm, gnupg, wget/urllib, the committed Fedora key).
"""
import argparse
import base64
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
KOJI = "https://kojipkgs.fedoraproject.org/packages"
FCOS_BASE = "https://builds.coreos.fedoraproject.org/prod/streams"
ARCHES = ("x86_64", "aarch64")

# (make-var stem, binary rpm name, koji source-package name)
PACKAGES = (
    ("FEDORA_KERNEL_CORE", "kernel-core", "kernel"),
    ("FEDORA_KERNEL_MODULES", "kernel-modules-core", "kernel"),
    ("SYSTEMD_BOOT", "systemd-boot-unsigned", "systemd"),
)


def fetch(url):
    with urllib.request.urlopen(url, timeout=60) as r:
        return r.read()


def key_short_id(keyfile):
    """Short (8-hex, lowercase) key id of an ASCII-armored v4 GPG key -- koji's signed/<id>/ subdir."""
    lines, body, inblock = open(keyfile).read().splitlines(), [], False
    for ln in lines:
        if ln.startswith("-----BEGIN"):
            inblock = True
            continue
        if ln.startswith("-----END"):
            break
        if inblock and ln.strip() and not ln.startswith("="):
            body.append(ln.strip())
    data = base64.b64decode("".join(body))
    b0 = data[0]
    if b0 & 0x40:  # new-format packet
        i = 1
        first = data[i]
        if first < 192:
            plen, i = first, i + 1
        elif first < 224:
            plen, i = ((first - 192) << 8) + data[i + 1] + 192, i + 2
        else:
            plen, i = struct.unpack(">I", data[i + 1:i + 5])[0], i + 5
    else:  # old-format packet
        lt, i = b0 & 0x03, 1
        sizes = {0: 1, 1: 2, 2: 4}
        n = sizes[lt]
        plen = int.from_bytes(data[i:i + n], "big")
        i += n
    pkt = data[i:i + plen]
    fpr = hashlib.sha1(b"\x99" + struct.pack(">H", len(pkt)) + pkt).hexdigest()
    return fpr[-8:].lower()


def kernel_nvr_from_fcos(version, stream):
    """Read the kernel-core NVR (version-release) from an FCOS build's meta.json pkgdiff."""
    url = f"{FCOS_BASE}/{stream}/builds/{version}/x86_64/meta.json"
    meta = json.loads(fetch(url))
    for entry in meta.get("pkgdiff", []):
        # entry = [name, changetype, {"NewPackage": [name, "ver-rel", arch], ...}] for a change,
        # or [name, changetype, [name, "ver-rel", arch]] for an add/remove.
        if entry and entry[0] == "kernel-core":
            info = entry[2]
            pkg = info["NewPackage"] if isinstance(info, dict) else info
            return pkg[1]
    raise SystemExit(
        f"kernel-core not found in {version} pkgdiff (kernel unchanged in this build?); "
        f"pass --kernel <nvr> explicitly."
    )


def systemd_nvr_from_bodhi(release):
    """Latest stable systemd build (version-release) for Fedora <release>, via Bodhi."""
    url = (f"https://bodhi.fedoraproject.org/updates/?packages=systemd"
           f"&releases=F{release}&status=stable&rows_per_page=10")
    data = json.loads(fetch(url))
    for upd in data.get("updates", []):
        for build in upd.get("builds", []):
            m = re.fullmatch(r"systemd-(.+)", build["nvr"])
            if m and f".fc{release}" in m.group(1):
                return m.group(1)
    raise SystemExit(f"could not find a stable systemd build for F{release} via Bodhi; pass --systemd.")


def split_nvr(nvr):
    """'7.0.12-201.fc44' -> ('7.0.12', '201.fc44')."""
    version, release = nvr.rsplit("-", 1)
    return version, release


def release_number(rel):
    m = re.search(r"\.fc(\d+)", rel)
    if not m:
        raise SystemExit(f"cannot derive Fedora release from '{rel}'")
    return m.group(1)


def signed_base(srcname, version, release, sigkey):
    # kojipkgs/packages/<src> serves the UNSIGNED build; the GPG-signed copies live under
    # data/signed/<short-key-id>/. That is the only path whose RPMs carry a Fedora signature.
    return f"{KOJI}/{srcname}/{version}/{release}/data/signed/{sigkey}"


def download_verify_sha256(binrpm, srcname, nvr, arch, keyfile, sigkey):
    """Download one signed RPM from Koji, GPG-verify it, return its sha256 hex."""
    version, release = split_nvr(nvr)
    fname = f"{binrpm}-{nvr}.{arch}.rpm"
    url = f"{signed_base(srcname, version, release, sigkey)}/{arch}/{fname}"
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, fname)
        print(f"  fetching {url}")
        with urllib.request.urlopen(url, timeout=120) as r, open(path, "wb") as f:
            h = hashlib.sha256()
            for chunk in iter(lambda: r.read(1 << 20), b""):
                f.write(chunk)
                h.update(chunk)
        subprocess.run([os.path.join(HERE, "verify-rpm-gpg.sh"), path, keyfile], check=True)
        return h.hexdigest()


def main():
    ap = argparse.ArgumentParser(description="Regenerate fedora-deps.mk (GPG-verified kernel + stub pins).")
    ap.add_argument("--fcos", help="Fedora CoreOS build version, e.g. 44.20260621.3.1")
    ap.add_argument("--stream", default="stable", help="FCOS stream (default: stable)")
    ap.add_argument("--kernel", help="kernel NVR override, e.g. 7.0.12-201.fc44 (else read from --fcos)")
    ap.add_argument("--systemd", help="systemd NVR, e.g. 259.6-1.fc44 (else latest stable via Bodhi)")
    args = ap.parse_args()

    if args.kernel:
        kernel_nvr = args.kernel
    elif args.fcos:
        kernel_nvr = kernel_nvr_from_fcos(args.fcos, args.stream)
    else:
        ap.error("need --fcos <version> or --kernel <nvr>")

    release = release_number(split_nvr(kernel_nvr)[1])
    systemd_nvr = args.systemd or systemd_nvr_from_bodhi(release)

    keyfile = os.path.join(HERE, "keys", f"RPM-GPG-KEY-fedora-{release}-primary")
    if not os.path.exists(keyfile):
        raise SystemExit(
            f"missing Fedora {release} signing key: {keyfile}\n"
            f"Fetch it from Fedora, verify its fingerprint against the value published at "
            f"https://fedoraproject.org/security/, and commit it (see keys/README.md)."
        )

    sigkey = key_short_id(keyfile)
    print(f"kernel  : {kernel_nvr}  (FCOS {args.fcos or 'n/a'})")
    print(f"systemd : {systemd_nvr}")
    print(f"key     : {keyfile}  (signed/{sigkey})")

    nvr_for = {"kernel": kernel_nvr, "systemd": systemd_nvr}
    shas = {}
    for stem, binrpm, srcname in PACKAGES:
        for arch in ARCHES:
            print(f"[{stem}_{arch}]")
            shas[f"{stem}_SHA256_{arch}"] = download_verify_sha256(
                binrpm, srcname, nvr_for[srcname], arch, keyfile, sigkey)

    kver, krel = split_nvr(kernel_nvr)
    sver, srel = split_nvr(systemd_nvr)
    out = os.path.join(HERE, "fedora-deps.mk")
    with open(out, "w") as f:
        f.write(
            "# GENERATED by update-fedora-deps.py -- do not hand-edit.\n"
            f"# Bump with: make update-fedora-deps FCOS=<version> [SYSTEMD=<nvr>]\n"
            f"# Kernel from Fedora CoreOS; systemd-boot stub from Fedora {release}. All RPMs are\n"
            f"# GPG-verified against keys/RPM-GPG-KEY-fedora-{release}-primary at bump time and every build.\n\n"
            f"FEDORA_RELEASE := {release}\n"
            f"FEDORA_KERNEL_VERSION := {kernel_nvr}\n"
            f"FEDORA_KERNEL_BASE_URL := {signed_base('kernel', kver, krel, sigkey)}\n"
            f"SYSTEMD_BOOT_VERSION := {systemd_nvr}\n"
            f"SYSTEMD_BOOT_BASE_URL := {signed_base('systemd', sver, srel, sigkey)}\n\n")
        for stem, _, _ in PACKAGES:
            for arch in ARCHES:
                f.write(f"{stem}_SHA256_{arch} := {shas[f'{stem}_SHA256_{arch}']}\n")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
