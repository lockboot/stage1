#!/usr/bin/env python3
# stage1's PCR replay file -- the stage1 link of the verification path.
#
# Given the stage1 UKI (linux.efi), write the events it adds between stage0's handoff and the
# stage2 handoff, as a pcr-replay/v1 file (format and verifier: workspace tools/pcr-replay). Each
# event carries a derivation from the UKI AND the digests computed here, independently, so a
# replay cross-checks both. Confirmed event-by-event against the Linux TCG event log of QEMU
# stage0 -> stage1 -> stage2 boots (x86_64, aarch64; sha1/256/384/512):
#
#   PCR11  systemd-stub, EV_IPL: for each UKI section in systemd's fixed order, H(name + NUL)
#          then H(section contents, VirtualSize bytes).
#   PCR9   Linux EFI stub, EV_EVENT_TAG: LOADED_IMAGE::LoadOptions = UTF-16LE(.cmdline) + NUL,
#          then "Linux initrd" = the initrd systemd-stub built (.initrd + a generated cpio
#          holding .osrel as /.extra/os-release; see stub_initrd()).
#   PCR5   firmware, EV_EFI_ACTION, at the kernel's ExitBootServices: "Exit Boot Services
#          Invocation", "Exit Boot Services Returned with Success".
#   PCR14  stage1's direct TPM2_PCR_Extend of stage2: H_bank(sha256(stage2)), not logged. An
#          input (stage2 is the deployment's choice).
#   PCR10  IMA: extended by the kernel from here on, its own log -- unpredictable.
#   others not extended. The kernel is NOT measured into PCR4: stage0 loads the UKI through its
#          own Security2 override (no firmware image measurement), so the UKI is covered by
#          PCR14 (whole file, stage0's event) and PCR11 (per section) instead.
#
# usage: predict-pcrs.py --uki linux.efi --replay stage1.replay.json [--banks sha256,sha384]
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from typing import Any

# systemd-stub's measured UKI sections, in the order it measures them (only those verified against
# a real event log; any other measured section is refused rather than guessed at).
MEASURED_ORDER = [".linux", ".osrel", ".cmdline", ".initrd", ".uname", ".sbat"]
# Sections systemd-stub also measures when present -- refused until their position is verified.
MEASURED_UNVERIFIED = [".ucode", ".splash", ".dtb", ".dtbauto", ".hwids", ".pcrpkey",
                       ".profile", ".efifw"]
UKI = "linux.efi"
EBS = ["Exit Boot Services Invocation", "Exit Boot Services Returned with Success"]
# systemd src/boot/cpio.c pack_cpio_trailer: a literal, with the name size in upper case ("B")
# unlike the generated entries' lower-case fields, then NUL padding.
CPIO_TRAILER = ("070701" + "00000000" * 4 + "00000001" + "00000000" * 6 + "0000000B" + "00000000"
                + "TRAILER!!!\0\0\0\0")


def pe_sections(pe: bytes) -> dict[str, bytes]:
    off = struct.unpack_from("<I", pe, 0x3C)[0]
    coff = off + 4
    nsec, = struct.unpack_from("<H", pe, coff + 2)
    opt_size, = struct.unpack_from("<H", pe, coff + 16)
    secs = {}
    for i in range(nsec):
        s = coff + 20 + opt_size + 40 * i
        name = pe[s:s + 8].rstrip(b"\0").decode()
        vsize, _vaddr, rsize, rptr = struct.unpack_from("<IIII", pe, s + 8)
        secs[name] = pe[rptr:rptr + min(vsize, rsize)]
    return secs


def _pad4(b: bytes) -> bytes:
    return b + b"\0" * ((-len(b)) % 4)


def _cpio_hdr(ino: int, mode: int, size: int, name: bytes) -> bytes:
    def w(v: int) -> bytes:
        return b"%08x" % v
    return _pad4(b"070701" + w(ino) + w(mode) + w(0) + w(0) + w(1) + w(0) + w(size)
                 + w(0) * 4 + w(len(name) + 1) + w(0) + name + b"\0")


def stub_initrd(secs: dict[str, bytes]) -> bytes:
    """The initrd systemd-stub (v259) hands the kernel, which the kernel measures into PCR9:
    the UKI .initrd, then the stub's generated cpio carrying .osrel as /.extra/os-release
    (systemd src/boot/cpio.c pack_cpio_literal: dir .extra 0555 inode 1, file 0444 inode 2,
    mtime 0, then the trailer), each padded to 4 bytes (stub.c combine_initrds). No .ucode,
    credentials, sysexts, confexts, .pcrsig, .pcrpkey or .profile -- the tool refuses UKIs
    with those sections, and stage0 loads the UKI from memory, so there is no ESP directory
    for the stub to pick credentials/sysexts up from."""
    osrel = secs[".osrel"]
    cpio = (_cpio_hdr(1, 0o040000 | 0o555, 0, b".extra")
            + _cpio_hdr(2, 0o100000 | 0o444, len(osrel), b".extra/os-release") + _pad4(osrel)
            + CPIO_TRAILER.encode())
    return _pad4(secs[".initrd"]) + cpio


def replay_file(uki: bytes, banks: list[str]) -> dict[str, Any]:
    secs = pe_sections(uki)
    bad = [s for s in MEASURED_UNVERIFIED + [".pcrsig"] if s in secs]
    if bad:
        raise SystemExit(f"UKI has section(s) {bad} whose PCR9/PCR11 effect is unverified")
    missing = [s for s in MEASURED_ORDER if s not in secs]
    if missing:
        raise SystemExit(f"UKI lacks expected section(s) {missing}")
    cmdline = secs[".cmdline"].rstrip(b"\0").decode()
    sec = lambda s: {"pe_section": s, "of": {"artifact": UKI}}  # noqa: E731

    # (pcr, type, by, about, derivation, bytes for the local computation)
    ev: list[tuple[int, str, str, str, dict[str, Any], bytes]] = []
    for s in MEASURED_ORDER:
        ev.append((11, "EV_IPL", "systemd-stub", f"section name {s}", {"utf8": s, "nul": True},
                   s.encode() + b"\0"))
        ev.append((11, "EV_IPL", "systemd-stub", f"section {s} ({len(secs[s])} bytes)", sec(s), secs[s]))
    ev.append((9, "EV_EVENT_TAG", "Linux EFI stub", "LOADED_IMAGE::LoadOptions (the .cmdline)",
               {"utf16le": cmdline, "nul": True}, cmdline.encode("utf-16-le") + b"\0\0"))
    ev.append((9, "EV_EVENT_TAG", "Linux EFI stub",
               "Linux initrd: .initrd + systemd-stub's cpio with .osrel as .extra/os-release",
               {"concat": [{"pad": 4, "of": sec(".initrd")},
                           {"cpio_newc": [{"ino": 1, "mode": "40555", "name": ".extra"},
                                          {"ino": 2, "mode": "100444", "name": ".extra/os-release",
                                           "data": sec(".osrel")}]},
                           {"utf8": CPIO_TRAILER}]},
               stub_initrd(secs)))
    for s in EBS:
        ev.append((5, "EV_EFI_ACTION", "firmware", "the kernel's ExitBootServices", {"utf8": s}, s.encode()))

    events: list[dict[str, Any]] = [
        {"pcr": pcr, "type": typ, "by": by, "about": about, "derive": expr,
         "digests": {b: getattr(hashlib, b)(data).hexdigest() for b in banks}}
        for pcr, typ, by, about, expr, data in ev]
    events.append({"pcr": 14, "type": "unlogged", "by": "stage1",
                   "about": "the stage2 stage1 verified and runs: H_bank(sha256(stage2))",
                   "derive": {"input": "stage2"}})
    return {
        "schema": "pcr-replay/v1",
        "name": "stage1 " + ("x86_64" if b"x86_64" in secs[".uname"] else "aarch64"),
        "about": "The stage1 UKI, from stage0's handoff to the stage2 handoff: systemd-stub, the "
                 "kernel's EFI stub and ExitBootServices, then stage1 measuring stage2.",
        "artifacts": {UKI: {"sha256": hashlib.sha256(uki).hexdigest()}},
        "entry": UKI,
        "inputs": {"stage2": {"about": "sha256 of the stage2 binary stage1 runs (the next stage)",
                              "next_entry": True}},
        "unextended": [0, 1, 2, 3, 4, 6, 7, 8, 12, 13] + list(range(15, 24)),
        "unpredictable": {"10": "IMA (the kernel's own measurement log)"},
        "events": events,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Write stage1's PCR replay file")
    ap.add_argument("--uki", required=True, help="the stage1 UKI (linux.efi)")
    ap.add_argument("--replay", required=True, help="write the pcr-replay/v1 file here")
    ap.add_argument("--banks", default="sha256,sha384", help="comma-separated (default sha256,sha384)")
    a = ap.parse_args()
    with open(a.uki, "rb") as f:
        uki = f.read()
    with open(a.replay, "w") as f:
        json.dump(replay_file(uki, a.banks.split(",")), f, indent=2)
        f.write("\n")


if __name__ == "__main__":
    main()
