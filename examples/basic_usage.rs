//! Basic usage example for CryptoShift SDK
//!
//! This example demonstrates:
//! - Creating cryptographic policies
//! - Generating key pairs
//! - Signing and verifying messages

use cryptoshift::{
    AlgorithmType, ClassicalAlgorithm, CryptoMode, CryptoPolicy, KeyPairGenerator, Signer,
    Verifier,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("CryptoShift - Basic Usage Example\n");

    // 1. Create a classical-only policy
    println!("[1] Creating a classical cryptography policy...");
    let classical_policy = CryptoPolicy::new("my-classical-app")
        .set_mode(CryptoMode::Classical)
        .set_min_security_level(128);
    println!("   Policy created: Classical mode, 128-bit minimum security\n");

    // 2. Generate an Ed25519 key pair
    println!("[2] Generating Ed25519 key pair...");
    let generator = KeyPairGenerator::new(classical_policy.clone());
    let keypair = generator.generate(AlgorithmType::Classical(ClassicalAlgorithm::Ed25519))?;
    println!("   Key pair generated:");
    println!("     Algorithm: {}", keypair.algorithm());
    println!("     Public key size: {} bytes", keypair.public_key_size());
    println!("     Private key size: {} bytes\n", keypair.private_key_size());

    // 3. Sign a message
    println!("[3] Signing a message...");
    let message = b"Hello, CryptoShift! This is a test message.";
    let signer = Signer::new(classical_policy.clone());
    let signature = signer.sign(&keypair, message)?;
    println!("   Message signed:");
    println!("     Signature size: {} bytes\n", signature.len());

    // 4. Verify the signature
    println!("[4] Verifying the signature...");
    let verifier = Verifier::new(classical_policy);
    verifier.verify(keypair.public_key(), message, &signature)?;
    println!("   Signature verified successfully!\n");

    // 5. Try to verify with wrong message (should fail)
    println!("[5] Testing with incorrect message...");
    let wrong_message = b"This is a different message";
    match verifier.verify(keypair.public_key(), wrong_message, &signature) {
        Ok(_) => println!("   ERROR: Verification should have failed!"),
        Err(e) => println!("   Verification correctly failed: {}\n", e),
    }

    println!("Basic usage example completed successfully!");

    Ok(())
}

