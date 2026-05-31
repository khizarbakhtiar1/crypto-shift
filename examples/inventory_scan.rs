//! Scan source code for cryptographic usage and quantum risk.
//!
//! Run: `cargo run --example inventory_scan`

use cryptoshift::{CryptoInventory, RiskLevel};

fn main() {
    let inventory = CryptoInventory::new();

    let sources = [
        (
            "legacy_auth.rs",
            "use rsa::RsaPrivateKey;\nlet sig = ecdsa::SigningKey::random(&mut rng);",
        ),
        ("hash.go", "h := md5.New()"),
        ("pqc.rs", "use pqcrypto_kyber::kyber768;\nlet sig = dilithium3::detached_sign(msg, &sk);"),
        ("main.rs", "fn main() { println!(\"hello\"); }"),
    ];

    let report = inventory.scan_all(sources.iter().copied());

    println!("{}", report.summary());
    println!();

    for finding in &report.findings {
        println!(
            "  [{}] {}:{}  {}  -> {}",
            finding.risk.label(),
            finding.source,
            finding.line,
            finding.primitive,
            finding.recommendation
        );
    }

    if report.count(RiskLevel::QuantumVulnerable) > 0 {
        println!("\nAction required: quantum-vulnerable primitives detected.");
    }
}
