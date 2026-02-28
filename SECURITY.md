# Security Advisories & Notes

This document tracks known security advisories affecting CryptoShift dependencies
and the project's mitigation status.

## Active Advisories

### RUSTSEC-2023-0071 — `rsa` crate (Marvin Attack)

- **Severity**: Medium (CVSS 5.9)
- **Affected versions**: All `rsa` versions ≤ 0.9.x
- **Issue**: Timing side-channel vulnerability in RSA decryption (PKCS#1 v1.5),
  known as the "Marvin Attack". Does **not** affect RSA **signature** operations,
  which is how CryptoShift uses the `rsa` crate.
- **Status**: No upstream fix available yet. CryptoShift only uses RSA for
  signing/verification (not decryption), so the practical impact is minimal.
- **Tracking**: <https://rustsec.org/advisories/RUSTSEC-2023-0071.html>

### RUSTSEC-2025-0141 — `bincode` 1.x (Unmaintained)

- **Severity**: Informational
- **Issue**: `bincode` 1.x is no longer maintained. The maintainers recommend
  migrating to `bincode` 2.x.
- **Status**: CryptoShift uses `bincode` 1.3 for binary serialization of
  signatures. A migration to `bincode` 2.x (or an alternative like `bitcode`)
  is planned for a future release.
- **Tracking**: <https://rustsec.org/advisories/RUSTSEC-2025-0141.html>

### RUSTSEC-2024-0380 — `pqcrypto-dilithium` (Unmaintained)

- **Severity**: Informational
- **Issue**: `pqcrypto-dilithium` is unmaintained. NIST finalized the Dilithium
  algorithm as **ML-DSA** (FIPS 204) in August 2024. The replacement crate is
  `pqcrypto-mldsa`.
- **Status**: Migration to `pqcrypto-mldsa` is planned. The algorithm names
  in CryptoShift will be updated to reflect the official NIST naming
  (Dilithium → ML-DSA, Kyber → ML-KEM) in a future release.
- **Tracking**: <https://rustsec.org/advisories/RUSTSEC-2024-0380.html>

## Resolved Advisories

### RUSTSEC-2026-0007 — `bytes` (Integer Overflow in `BytesMut::reserve`)

- **Resolved in**: `bytes` ≥ 1.11.1 (pulled in via `cargo update`)
- **Tracking**: <https://rustsec.org/advisories/RUSTSEC-2026-0007.html>

## Recommendations

1. **RSA usage**: If your application requires RSA decryption (not just
   signatures), consider using an alternative implementation until the Marvin
   Attack is patched upstream.
2. **Post-quantum migration**: Plan to move from Dilithium to ML-DSA when
   `pqcrypto-mldsa` stabilizes and CryptoShift adds support.
3. **Run `cargo audit` regularly** to check for new advisories.
