#!/usr/bin/env python3
# Reproduce the PCRs stage1 leaves behind -- the stage1 link of the verification path.
#
# Input: stage0's predicted PCRs (its release `pcrs.json`, from stage0 tools/predict-pcrs.py),
# the stage1 UKI (`linux.efi`), and the stage2 payload's sha256. Output: the PCRs as they stand
# when stage2 starts, per bank, by appending the exact events this stage adds (confirmed
# event-by-event against the Linux TCG event log of a QEMU stage0 -> stage1 -> stage2 boot):
#
#   PCR3, PCR4, PCR6, PCR7   unchanged from stage0. The kernel is NOT measured into PCR4:
#                            stage0 loads the UKI through its own Security2 override (no firmware
#                            image measurement), so the UKI is covered by PCR14 (whole file) and
#                            PCR11 (per section) instead.
#   PCR5   stage0's value, then EV_EFI_ACTION "Exit Boot Services Invocation" and
#          "Exit Boot Services Returned with Success" (firmware, at the kernel's ExitBootServices).
#   PCR9   Linux EFI stub: EV_EVENT_TAG LOADED_IMAGE::LoadOptions = UTF-16LE(.cmdline) + NUL, then
#          EV_EVENT_TAG "Linux initrd" = the initrd systemd-stub built (.initrd + a generated
#          cpio holding .osrel as /.extra/os-release; see stub_initrd()).
#   PCR11  systemd-stub: for each UKI section in systemd's fixed order, H(name + NUL) then
#          H(section contents, VirtualSize bytes).
#   PCR8, PCR12, PCR13   nothing measured (no stub cmdline override, credentials or sysexts).
#   PCR14  stage0's value (which must be its measurement of THIS UKI -- checked), then stage1's
#          H(sha256(stage2)). Direct TPM2_PCR_Extend, not logged.
#
# Composable: every PCR in the stage0 input is carried through and only the events above are
# appended, so the output is the complete PCR state at the stage1 -> stage2 handoff. A different
# stage2 starts from this file; a different stage1 starts from stage0's.
#
# PCR0-2 are the provider's firmware (golden readings, see stage0's predictor); PCR10 is IMA (its
# own log; stage2 does not bind it); PCR15 is stage2's config (stage2's own step).
#
# usage: predict-pcrs.py --uki linux.efi --emit-measurements [--out measurements.json]
#          this stage's fixed extends only (shipped with each release, next to linux.efi)
#        predict-pcrs.py --uki linux.efi --stage0 pcrs.json --stage2-sha256 HEX [--out F]
#          the full state after stage1 (stage0's pcrs.json from its release, with or without its
#          PCR14 for this UKI -- added if absent, checked if present)
#        ... --check <serial.log>   (compare against "PCR <bank> <nn> <hex>" lines, e.g. from
#                                    example-stage2 --dump-tpm)
import argparse
import hashlib
import json
import re
import struct
import sys

# systemd-stub's measured UKI sections, in the order it measures them (only those verified against
# a real event log; any other measured section is refused rather than guessed at).
MEASURED_ORDER = [".linux", ".osrel", ".cmdline", ".initrd", ".uname", ".sbat"]
# Sections systemd-stub also measures when present -- refused until their position is verified.
MEASURED_UNVERIFIED = [".ucode", ".splash", ".dtb", ".dtbauto", ".hwids", ".pcrpkey",
                       ".profile", ".efifw"]


def pe_sections(pe):
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


def _pad4(b):
    return b + b"\0" * ((-len(b)) % 4)


def _cpio_hdr(ino, mode, size, name):
    w = lambda v: b"%08x" % v  # noqa: E731
    return _pad4(b"070701" + w(ino) + w(mode) + w(0) + w(0) + w(1) + w(0) + w(size)
                 + w(0) * 4 + w(len(name) + 1) + w(0) + name + b"\0")


def stub_initrd(secs):
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
            + b"070701" + b"00000000" * 4 + b"00000001" + b"00000000" * 6 + b"0000000B"
            + b"00000000" + b"TRAILER!!!\0\0\0\0")
    return _pad4(secs[".initrd"]) + cpio


def measurements(uki, banks):
    """This stage's fixed contribution, from the UKI alone: per bank, the digests it extends into
    each PCR, in order. (Its PCR14 extend depends on the deployed stage2, so it is an input.)"""
    secs = pe_sections(uki)
    bad = [s for s in MEASURED_UNVERIFIED + [".pcrsig"] if s in secs]
    if bad:
        raise SystemExit(f"UKI has section(s) {bad} whose PCR9/PCR11 effect is unverified")
    missing = [s for s in MEASURED_ORDER if s not in secs]
    if missing:
        raise SystemExit(f"UKI lacks expected section(s) {missing}")
    cmdline = secs[".cmdline"].rstrip(b"\0").decode()
    initrd = stub_initrd(secs)
    out = {}
    for bank in banks:
        H = getattr(hashlib, bank)
        out[bank] = {
            "5": [H(b"Exit Boot Services Invocation").digest().hex(),
                  H(b"Exit Boot Services Returned with Success").digest().hex()],
            "9": [H(cmdline.encode("utf-16-le") + b"\0\0").digest().hex(), H(initrd).digest().hex()],
            "11": [d.hex() for s in MEASURED_ORDER
                   for d in (H(s.encode() + b"\0").digest(), H(secs[s]).digest())],
        }
    return {"extends": out}


def apply(prev, measurements, uki_sha256, stage2_sha256):
    """Previous state (stage0's pcrs.json) + stage0's PCR14 measurement of the UKI + this stage's
    fixed extends + its PCR14 measurement of stage2 -> the state at the stage1 -> stage2 handoff."""
    out = {}
    for bank, ext in measurements["extends"].items():
        H = getattr(hashlib, bank)
        if bank not in prev["pcrs"]:
            raise SystemExit(f"previous pcrs.json has no {bank} bank")
        p = {int(k): v for k, v in prev["pcrs"][bank].items()}  # carry everything; extend only ours
        zero = "00" * H().digest_size

        def extend(pcr, digests):
            v = bytes.fromhex(p.get(pcr, zero))
            for e in digests:
                v = H(v + e).digest()
            p[pcr] = v.hex()

        if 14 not in p:      # stage0 predicted without a payload: add its measurement of this UKI
            extend(14, [H(bytes.fromhex(uki_sha256)).digest()])
        elif p[14] != H(b"\0" * H().digest_size + H(bytes.fromhex(uki_sha256)).digest()).hexdigest():
            raise SystemExit(f"previous pcrs.json PCR14 ({bank}) is not stage0's measurement of this UKI")
        for pcr, digests in ext.items():
            extend(int(pcr), [bytes.fromhex(d) for d in digests])
        for k in (8, 12, 13):   # nothing measured: explicit, so a verifier can bind them
            p.setdefault(k, zero)
        extend(14, [H(bytes.fromhex(stage2_sha256)).digest()])
        out[bank] = {str(k): v for k, v in sorted(p.items())}
    return {"pcrs": out}


def check(pred, log_path):
    with open(log_path, "rb") as f:
        txt = f.read().decode("latin1").replace("\r", "")
    seen = {(a, int(i)): v for a, i, v in
            re.findall(r"^(?:payload: )?PCR (\w+) (\d\d) ([0-9a-f]+)$", txt, re.M)}
    bad = 0
    for bank, pcrs in pred["pcrs"].items():
        for i, want in pcrs.items():
            got = seen.get((bank, int(i)))
            status = "ok" if got == want else ("MISSING" if got is None else "MISMATCH")
            bad += status != "ok"
            print(f"{bank:7} PCR{int(i):<2} {status:8} predicted {want[:16]}"
                  + ("" if status == "ok" or got is None else f"  read {got[:16]}"))
    print("ALL PREDICTED PCRS MATCH" if not bad else f"{bad} PREDICTED PCR(S) DO NOT MATCH")
    return bad == 0


def main():
    ap = argparse.ArgumentParser(description="stage1's PCR contribution, and the state after it")
    ap.add_argument("--uki", required=True, help="the stage1 UKI (linux.efi)")
    ap.add_argument("--emit-measurements", action="store_true",
                    help="write only this stage's fixed extends (the release artifact)")
    ap.add_argument("--stage0", help="previous state: stage0's pcrs.json")
    ap.add_argument("--stage2-sha256", help="sha256 of the stage2 binary stage1 runs")
    ap.add_argument("--banks", default="sha256,sha384", help="comma-separated (default sha256,sha384)")
    ap.add_argument("--out", help="write JSON here (default stdout)")
    ap.add_argument("--check", metavar="LOG", help="compare against a serial log's PCR dump")
    a = ap.parse_args()
    with open(a.uki, "rb") as f:
        uki = f.read()
    res = measurements(uki, a.banks.split(","))
    if not a.emit_measurements:
        if not (a.stage0 and a.stage2_sha256):
            ap.error("--stage0 and --stage2-sha256 are required unless --emit-measurements")
        with open(a.stage0) as f:
            res = apply(json.load(f), res, hashlib.sha256(uki).hexdigest(), a.stage2_sha256)
        if a.check:
            sys.exit(0 if check(res, a.check) else 1)
    js = json.dumps(res, indent=2) + "\n"
    if a.out:
        with open(a.out, "w") as f:
            f.write(js)
    else:
        sys.stdout.write(js)


if __name__ == "__main__":
    main()
