# Fedora package signing keys

The UKI's kernel and systemd-boot stub are Fedora RPMs, pulled from koji's **signed** path and
GPG-verified against the Fedora release signing key on every download (`../download-verify-rpm.sh` ->
`../verify-rpm-gpg.sh`) and at bump time (`../update-fedora-deps.py`). This directory holds the
trusted public keys, one per Fedora release, named `RPM-GPG-KEY-fedora-<N>-primary`.

These keys are the **trust anchor** for the kernel/stub supply chain: a SHA256 pin only says "these
exact bytes", but the GPG signature proves the bytes are genuinely Fedora's.

## Trusted keys

| File | Fedora | Fingerprint | koji `signed/` id |
|------|:------:|-------------|-------------------|
| `RPM-GPG-KEY-fedora-44-primary` | 44 | `36F6 12DC F27F 7D1A 48A8 35E4 DBFC F71C 6D9F 90A6` | `6d9f90a6` |

## Adding a new release's key (when bumping to fc45, etc.)

1. Fetch it, e.g. `curl -fsSLO https://src.fedoraproject.org/rpms/fedora-repos/raw/f45/f/RPM-GPG-KEY-fedora-45-primary`.
2. **Verify the fingerprint** against the value Fedora publishes at <https://fedoraproject.org/security/>
   before trusting it (`gpg --show-keys --with-fingerprint <file>`).
3. Commit it here and add a row above. `update-fedora-deps.py` derives the koji `signed/<id>` subdir
   from the key itself, and errors if the release's key is missing.
