//! Post-quantum cryptography example
//!
//! This example demonstrates:
//! - Using post-quantum Dilithium signatures
//! - Different security levels (Dilithium2, 3, 5)
//! - Comparison with classical algorithms

use cryptoshift::{
    AlgorithmType, ClassicalAlgorithm, CryptoMode, CryptoPolicy, KeyPairGenerator,
    PostQuantumAlgorithm, Signer, Verifier,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔮 CryptoShift - Post-Quantum Cryptography Example\n");

    // Create post-quantum policies for different security tiers
    let pqc_policy_base = CryptoPolicy::new("quantum-resistant-app")
        .set_mode(CryptoMode::PostQuantum)
        .set_min_security_level(128);

    let pqc_policy_high = CryptoPolicy::new("quantum-resistant-app-high")
        .set_mode(CryptoMode::PostQuantum)
        .set_min_security_level(192);

    println!("📊 Comparing Classical vs Post-Quantum Signatures:\n");

    // Test Ed25519 (Classical)
    println!("1️⃣  Classical: Ed25519");
    let classical_policy = CryptoPolicy::new("classical")
        .set_mode(CryptoMode::Classical)
        .set_min_security_level(128);
    test_algorithm(
        classical_policy,
        AlgorithmType::Classical(ClassicalAlgorithm::Ed25519),
        "Ed25519",
    )?;

    // Test Dilithium2 (128-bit security → base policy)
    println!("\n2️⃣  Post-Quantum: Dilithium2 (NIST Level 2)");
    test_algorithm(
        pqc_policy_base,
        AlgorithmType::PostQuantum(PostQuantumAlgorithm::Dilithium2),
        "Dilithium2",
    )?;

    // Test Dilithium3 (192-bit security → high policy)
    println!("\n3️⃣  Post-Quantum: Dilithium3 (NIST Level 3)");
    test_algorithm(
        pqc_policy_high.clone(),
        AlgorithmType::PostQuantum(PostQuantumAlgorithm::Dilithium3),
        "Dilithium3",
    )?;

    // Test Dilithium5 (256-bit security → high policy)
    println!("\n4️⃣  Post-Quantum: Dilithium5 (NIST Level 5)");
    test_algorithm(
        pqc_policy_high,
        AlgorithmType::PostQuantum(PostQuantumAlgorithm::Dilithium5),
        "Dilithium5",
    )?;

    println!("\n✅ Post-quantum cryptography example completed!");
    println!("\nKey Takeaways:");
    println!("   - Post-quantum signatures are larger than classical ones");
    println!("   - Higher security levels = larger keys and signatures");
    println!("   - All are quantum-resistant and NIST-approved");

    Ok(())
}

fn test_algorithm(
    policy: CryptoPolicy,
    algorithm: AlgorithmType,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let generator = KeyPairGenerator::new(policy.clone());
    let keypair = generator.generate(algorithm)?;

    let message = b"Test message for post-quantum signatures";
    let signer = Signer::new(policy.clone());
    let signature = signer.sign(&keypair, message)?;

    let verifier = Verifier::new(policy);
    verifier.verify(keypair.public_key(), message, &signature)?;

    println!("   Algorithm: {}", name);
    println!("   Security Level: {} bits", algorithm.security_level());
    println!("   Public Key: {} bytes", keypair.public_key_size());
    println!("   Private Key: {} bytes", keypair.private_key_size());
    println!("   Signature: {} bytes", signature.len());
    println!("   Sign & Verify: SUCCESS");

    Ok(())
}

