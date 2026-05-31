# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.3.x   | :white_check_mark: |
| 0.2.x   | :white_check_mark: |
| < 0.2   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in CryptoShift, please report it responsibly:

1. **Do not** open a public GitHub issue for security vulnerabilities.
2. Email details to the maintainers with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Suggested fix (if any)

We aim to acknowledge reports within 48 hours and provide a fix or mitigation within 30 days for confirmed critical issues.

## Security Audit Summary (v0.3.0)

This document summarizes the internal security review performed for CryptoShift v0.2.0.

### Cryptographic Design

| Area | Status | Notes |
|------|--------|-------|
| KEM-DEM encryption | Pass | Kyber/X25519 encapsulation + HKDF-SHA256 key derivation + AES-256-GCM |
| Digital signatures | Pass | Uses well-vetted libraries (ed25519-dalek, pqcrypto-dilithium, rsa, p256/p384) |
| Hybrid signatures | Pass | Dual signing with configurable verification strategies |
| Key zeroization | Pass | Private keys wrapped in `SecretKey` with `Zeroize` on drop |
| Random number generation | Pass | OS CSPRNG via `rand::rngs::OsRng` |

### Memory Safety

| Area | Status | Notes |
|------|--------|-------|
| Rust memory safety | Pass | No `unsafe` in core crypto modules |
| FFI boundary | Review | `src/ffi.rs` uses `unsafe` only for C pointer handling; callers must free buffers |
| Secret key handling | Pass | Keys zeroized on drop; not serialized in `KeyPair` |

### Dependency Audit Results (v0.3.0)

Run `cargo audit` regularly. Last audit findings:

| Advisory | Crate | Severity | Status |
|----------|-------|----------|--------|
| RUSTSEC-2023-0071 | rsa | Medium (5.9) | Known timing side-channel; no fixed version available. Document in deployment guides. |
| RUSTSEC-2024-0380 | pqcrypto-dilithium | Warning | Unmaintained; superseded by `pqcrypto-mldsa` (planned migration) |
| RUSTSEC-2024-0381 | pqcrypto-kyber | Warning | Unmaintained; superseded by `pqcrypto-mlkem` (planned migration) |
| RUSTSEC-2025-0141 | bincode | Warning | Unmaintained; evaluate migration to bincode 2.x |

### Known Limitations

1. **Inventory scanner is heuristic** — pattern matching only; false positives/negatives possible.
2. **Migration orchestrator is deterministic** — counter-based sampling, not cryptographically random.
3. **No FIPS validation** — library is not FIPS 140-3 certified.
4. **FALCON not implemented** — algorithm types defined but no implementation yet.
5. **FFI callers must free buffers** — memory leaks possible if `cryptoshift_buffer_free` is not called.

### Recommendations for Production Use

- Pin dependency versions and run `cargo audit` in CI.
- Use hybrid mode during migration rather than switching algorithms abruptly.
- Set minimum security level to 128 bits or higher in policies.
- Prefer Dilithium3 + Kyber768 as default post-quantum algorithms.
- Do not rely solely on the inventory scanner for compliance audits.
- Perform independent third-party cryptographic audit before high-assurance deployments.

### Audit Checklist

- [x] Input validation on all public API entry points
- [x] Policy enforcement before cryptographic operations
- [x] AEAD authentication tag verification (tamper detection)
- [x] Constant-time comparisons where applicable (via underlying libraries)
- [x] No hardcoded keys or test vectors in production code
- [x] Error messages do not leak key material
- [x] Integration tests cover tampered ciphertext rejection
- [x] Integration tests cover wrong-key decryption failure
- [ ] Independent third-party audit (recommended for production)
- [ ] Fuzz testing of FFI boundary (recommended)

## Secure Development Practices

- All cryptographic operations go through the policy engine.
- Private keys are never logged or included in error messages.
- The CLI stores keys in a self-describing binary format (algorithm tag + key bytes).
- Release builds use LTO and `opt-level = 3`.
