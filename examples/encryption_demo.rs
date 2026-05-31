//! KEM-DEM encryption with Kyber (post-quantum) and X25519 (classical).
//!
//! Run: `cargo run --example encryption_demo`

use cryptoshift::{
    AlgorithmType, CryptoMode, CryptoPolicy, Decryptor, Encryptor, KeyPairGenerator,
    PostQuantumAlgorithm, ClassicalAlgorithm,
};

fn main() -> cryptoshift::Result<()> {
    let policy = CryptoPolicy::new("encryption-demo")
        .set_mode(CryptoMode::Hybrid)
        .set_min_security_level(128);

    let plaintext = b"Sensitive data that must survive the quantum transition.";

    // Post-quantum: Kyber768 KEM + AES-256-GCM
    println!("=== Kyber768 encryption ===");
    let kyber = AlgorithmType::PostQuantum(PostQuantumAlgorithm::Kyber768);
    let generator = KeyPairGenerator::new(policy.clone());
    let keypair = generator.generate(kyber)?;

    let encryptor = Encryptor::new(policy.clone());
    let message = encryptor.encrypt(kyber, keypair.public_key(), plaintext)?;
    println!("   Encapsulated key: {} bytes", message.encapsulated_key().len());
    println!("   Ciphertext:       {} bytes", message.ciphertext().len());

    let decryptor = Decryptor::new(policy.clone());
    let recovered = decryptor.decrypt(&keypair, &message)?;
    assert_eq!(recovered, plaintext);
    println!("   Decryption: OK\n");

    // Classical: X25519 ECDH + AES-256-GCM
    println!("=== X25519 encryption ===");
    let x25519 = AlgorithmType::Classical(ClassicalAlgorithm::X25519);
    let keypair = generator.generate(x25519)?;
    let message = encryptor.encrypt(x25519, keypair.public_key(), plaintext)?;
    let recovered = decryptor.decrypt(&keypair, &message)?;
    assert_eq!(recovered, plaintext);
    println!("   Decryption: OK");

    Ok(())
}
