# CryptoShift

A comprehensive crypto-agility SDK for migrating from classical to post-quantum cryptography.

## Overview

CryptoShift enables organizations to safely transition from classical cryptographic algorithms (RSA, ECC, Ed25519) to post-quantum cryptography (Kyber, Dilithium) with minimal disruption.

## The Problem We Solve

Organizations face an urgent challenge: migrate to post-quantum cryptography before quantum computers become viable (estimated 5-10 years), but their systems have hardcoded cryptographic primitives that can't be easily swapped. CryptoShift provides the missing migration layer.

## Key Features

- **Hybrid Cryptography**: Support both classical and post-quantum algorithms simultaneously
- **Policy-Driven**: Define cryptographic policies centrally and enforce them across your system
- **Gradual Migration**: Roll out PQC gradually with percentage-based traffic splitting
- **KEM-DEM Encryption**: Kyber and X25519 key encapsulation with AES-256-GCM payload encryption
- **Migration Orchestrator**: Stage-based rollout plans with deterministic traffic splitting
- **Crypto Inventory**: Scan source code for quantum-vulnerable primitives
- **Security-First**: Built in Rust for memory safety and security guarantees
- **Language Bindings**: Python, Node.js, and C FFI for cross-language integration

## Project Status

**Current Phase**: Production-Ready — **v0.3.0**

### Completed Modules

| Module | Description |
|--------|-------------|
| `algorithms` | Algorithm type system (Classical + Post-Quantum) |
| `policy` | Policy engine (modes, migration stages, validation) |
| `keypair` | Key pair generation (Ed25519, X25519, RSA, ECDSA, Dilithium, Kyber) |
| `signature` | Digital signatures (classical + PQC) |
| `encryption` | KEM-DEM encryption (Kyber + X25519 with AES-256-GCM) |
| `hybrid` | Hybrid signatures (classical + PQC simultaneously) |
| `migration` | Migration orchestrator with staged rollout |
| `inventory` | Cryptographic discovery and quantum-risk scoring |
| `error` | Unified error handling |
| `ffi` | C-compatible FFI for language bindings |

### Test Coverage

- **61 unit tests** across all modules (including FFI)
- **14 integration tests** (end-to-end workflows)
- **75 total tests passing**
- Criterion benchmarks for keygen, sign, verify, and encryption

## Quick Start

### Command-Line Interface

```bash
# Build the CLI
cargo build --release --features cli

# List all supported algorithms
./target/release/cryptoshift list

# Generate a post-quantum key pair
./target/release/cryptoshift keygen --algorithm dilithium3 --output mykey

# Sign and verify
./target/release/cryptoshift sign --key mykey.key --input "Hello!" --output sig.bin
./target/release/cryptoshift verify --key mypub.pub --input "Hello!" --signature sig.bin

# Encrypt and decrypt (Kyber KEM + AES-256-GCM)
./target/release/cryptoshift keygen --algorithm kyber768 --output enckey
./target/release/cryptoshift encrypt --key enckey.pub --input "Secret data" --output ct.bin
./target/release/cryptoshift decrypt --key enckey.key --input ct.bin

# Simulate a migration rollout
./target/release/cryptoshift migrate --name auth-service --samples 1000

# Scan source code for quantum-vulnerable crypto
./target/release/cryptoshift scan ./src
```

### Running Examples

```bash
cargo run --example basic_usage          # Classical cryptography
cargo run --example post_quantum         # Post-quantum signatures
cargo run --example hybrid_mode          # Hybrid signatures
cargo run --example policy_management    # Policy configuration
cargo run --example encryption_demo      # Kyber + X25519 encryption
cargo run --example migration_demo       # Staged migration simulation
cargo run --example inventory_scan       # Crypto discovery scan
```

### Language Bindings

#### Python

```bash
cd bindings/python
pip install maturin
maturin develop --release

python -c "
import cryptoshift
pub, priv = cryptoshift.keygen('dilithium3')
sig = cryptoshift.sign('dilithium3', priv, b'Hello!')
print(cryptoshift.verify('dilithium3', pub, b'Hello!', sig))
"
```

#### Node.js

```bash
cd bindings/node
npm install
npm run build

node -e "
const cs = require('./index.js');
const { publicKey, privateKey } = cs.keygen('dilithium3');
const sig = cs.sign('dilithium3', privateKey, Buffer.from('Hello!'));
console.log(cs.verify('dilithium3', publicKey, Buffer.from('Hello!'), sig));
"
```

#### C FFI

Build the shared library and use the generated header:

```bash
cargo build --release --features ffi
# Header: include/cryptoshift.h
# Library: target/release/libcryptoshift.so
```

See [SECURITY.md](SECURITY.md) for the security audit summary and vulnerability reporting policy.

### Code Examples

#### Hybrid Signatures

```rust
use cryptoshift::{
    CryptoPolicy, CryptoMode, MigrationStage,
    HybridKeyPairGenerator, HybridSigner, HybridVerifier,
};

let policy = CryptoPolicy::new("my-policy")
    .set_mode(CryptoMode::Hybrid)
    .set_migration_stage(MigrationStage::Rollout(0.1))
    .set_min_security_level(128);

let generator = HybridKeyPairGenerator::with_defaults(policy.clone());
let keypair = generator.generate()?;

let signer = HybridSigner::new(policy.clone());
let signature = signer.sign(&keypair, b"Important message")?;

let verifier = HybridVerifier::with_defaults(policy);
verifier.verify(&keypair, b"Important message", &signature)?;
```

#### KEM-DEM Encryption

```rust
use cryptoshift::{
    AlgorithmType, PostQuantumAlgorithm, CryptoPolicy, CryptoMode,
    KeyPairGenerator, Encryptor, Decryptor,
};

let policy = CryptoPolicy::new("enc").set_mode(CryptoMode::Hybrid);
let algo = AlgorithmType::PostQuantum(PostQuantumAlgorithm::Kyber768);

let generator = KeyPairGenerator::new(policy.clone());
let keypair = generator.generate(algo)?;

let encryptor = Encryptor::new(policy.clone());
let message = encryptor.encrypt(algo, keypair.public_key(), b"Secret data")?;

let decryptor = Decryptor::new(policy);
let plaintext = decryptor.decrypt(&keypair, &message)?;
```

#### Migration Orchestration

```rust
use cryptoshift::{MigrationOrchestrator, MigrationPlan};

let plan = MigrationPlan::default_signature_plan("auth-service");
let mut orchestrator = MigrationOrchestrator::new(plan)?;

// Each call selects classical or PQC based on the current rollout stage
let algorithm = orchestrator.select_algorithm();
println!("{}", orchestrator.report());

// Advance to the next stage when ready
orchestrator.advance()?;
```

#### Crypto Inventory

```rust
use cryptoshift::CryptoInventory;

let inventory = CryptoInventory::new();
let report = inventory.scan_file("src/auth.rs")?;

println!("{}", report.summary());
for finding in &report.findings {
    println!("[{}] {}:{} — {}", finding.risk.label(), finding.source, finding.line, finding.primitive);
}
```

## Architecture

```
cryptoshift/
├── algorithms/   - Algorithm type system and definitions
├── error/        - Error types and handling
├── policy/       - Policy engine and validation
├── keypair/      - Key pair generation and management
├── signature/    - Digital signature operations
├── encryption/   - KEM-DEM encryption (Kyber + X25519)
├── hybrid/       - Hybrid cryptography (classical + PQC)
├── migration/    - Migration orchestration and rollout
└── inventory/    - Cryptographic discovery and risk scoring
```

## Supported Algorithms

### Classical Algorithms

| Algorithm | Category | Security Level |
|-----------|----------|----------------|
| Ed25519 | Signature | 128-bit |
| X25519 | Key Exchange | 128-bit |
| RSA-2048 | Signature | 112-bit |
| RSA-3072 | Signature | 128-bit |
| RSA-4096 | Signature | 152-bit |
| ECDSA P-256 | Signature | 128-bit |
| ECDSA P-384 | Signature | 192-bit |

### Post-Quantum Algorithms (NIST Selected)

| Algorithm | Category | Security Level |
|-----------|----------|----------------|
| Dilithium-2 (ML-DSA-44) | Signature | 128-bit |
| Dilithium-3 (ML-DSA-65) | Signature | 192-bit |
| Dilithium-5 (ML-DSA-87) | Signature | 256-bit |
| Kyber-512 (ML-KEM-512) | KEM | 128-bit |
| Kyber-768 (ML-KEM-768) | KEM | 192-bit |
| Kyber-1024 (ML-KEM-1024) | KEM | 256-bit |

## Development

```bash
# Build the project
cargo build

# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Build documentation
cargo doc --open

# Run benchmarks
cargo bench

# Build CLI
cargo build --release --features cli
```

## Roadmap

**Phase 1: Core Foundation** — Complete
- [x] Project setup and architecture
- [x] Algorithm type system
- [x] Policy engine
- [x] Key pair management
- [x] Signature operations

**Phase 2: Post-Quantum Integration** — Complete
- [x] Dilithium implementation
- [x] Kyber implementation
- [x] Hybrid mode implementation
- [x] Full test coverage

**Phase 3: Migration Tools** — Complete
- [x] Migration orchestrator
- [x] Code scanning and discovery
- [x] Staged rollout simulation

**Phase 4: Production Ready** — Complete
- [x] Performance benchmarks
- [x] CLI tools
- [x] Documentation and examples
- [x] Security audit (see [SECURITY.md](SECURITY.md))
- [x] Language bindings (Python, Node.js, C)
- [ ] Independent third-party audit

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Contributing

Contributions are welcome! This is an active development project focused on solving real-world crypto-agility challenges.

---

**Built to solve the quantum threat, one algorithm at a time.**
