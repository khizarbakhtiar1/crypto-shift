//! Hybrid cryptography example
//!
//! This example demonstrates:
//! - Generating hybrid key pairs (classical + post-quantum)
//! - Creating hybrid signatures
//! - Different verification strategies
//! - Use case for migration period

use cryptoshift::{
    ClassicalAlgorithm, CryptoMode, CryptoPolicy, HybridKeyPairGenerator, HybridSigner,
    HybridVerifier, PostQuantumAlgorithm, VerificationStrategy,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("CryptoShift - Hybrid Cryptography Example\n");
    println!("Use Case: Transitioning from classical to post-quantum crypto\n");

    // Create a hybrid policy
    let policy = CryptoPolicy::new("hybrid-transition-app")
        .set_mode(CryptoMode::Hybrid)
        .set_min_security_level(128);

    // 1. Generate hybrid key pair with defaults (Ed25519 + Dilithium3)
    println!("[1] Generating hybrid key pair (Ed25519 + Dilithium3)...");
    let generator = HybridKeyPairGenerator::with_defaults(policy.clone());
    let keypair = generator.generate()?;
    println!("   Hybrid key pair generated:");
    println!(
        "     Classical: {}",
        keypair.classical_algorithm().name()
    );
    println!(
        "     Post-Quantum: {}",
        keypair.post_quantum_algorithm().name()
    );

    // 2. Sign a message with both algorithms
    println!("\n[2] Signing message with hybrid signature...");
    let message = b"Important document that needs both classical and PQC protection";
    let signer = HybridSigner::new(policy.clone());
    let signature = signer.sign(&keypair, message)?;
    println!("   Hybrid signature created:");
    println!(
        "     Classical signature: {} bytes",
        signature.classical().len()
    );
    println!(
        "     Post-quantum signature: {} bytes",
        signature.post_quantum().len()
    );
    println!("     Total size: {} bytes", signature.total_size());

    // 3. Test different verification strategies
    println!("\n[3] Testing verification strategies:\n");

    // Strategy 1: Require both (most secure)
    println!("   Strategy: RequireBoth (most secure)");
    let verifier = HybridVerifier::new(policy.clone(), VerificationStrategy::RequireBoth);
    verifier.verify(&keypair, message, &signature)?;
    println!("   Both signatures verified successfully\n");

    // Strategy 2: Require either (more lenient)
    println!("   Strategy: RequireEither (backward compatible)");
    let verifier = HybridVerifier::new(policy.clone(), VerificationStrategy::RequireEither);
    verifier.verify(&keypair, message, &signature)?;
    println!("   At least one signature verified\n");

    // Strategy 3: Classical only
    println!("   Strategy: RequireClassical (legacy systems)");
    let verifier = HybridVerifier::new(policy.clone(), VerificationStrategy::RequireClassical);
    verifier.verify(&keypair, message, &signature)?;
    println!("   Classical signature verified\n");

    // Strategy 4: Post-quantum only
    println!("   Strategy: RequirePostQuantum (quantum-safe only)");
    let verifier = HybridVerifier::new(policy.clone(), VerificationStrategy::RequirePostQuantum);
    verifier.verify(&keypair, message, &signature)?;
    println!("   Post-quantum signature verified\n");

    // 4. Test serialization
    println!("[4] Testing signature serialization...");
    let serialized = signature.to_bytes()?;
    println!("   Serialized to {} bytes", serialized.len());
    
    let deserialized = cryptoshift::HybridSignature::from_bytes(&serialized)?;
    let verifier = HybridVerifier::with_defaults(policy.clone());
    verifier.verify(&keypair, message, &deserialized)?;
    println!("   Deserialized and verified successfully\n");

    // 5. Custom algorithm combination
    println!("[5] Custom high-security combination (ECDSA-P384 + Dilithium5)...");
    let high_sec_policy = CryptoPolicy::new("high-security")
        .set_mode(CryptoMode::Hybrid)
        .set_min_security_level(192);
    
    let high_sec_gen = HybridKeyPairGenerator::new(
        high_sec_policy.clone(),
        ClassicalAlgorithm::EcdsaP384,
        PostQuantumAlgorithm::Dilithium5,
    );
    let high_sec_keypair = high_sec_gen.generate()?;
    
    let high_sec_signer = HybridSigner::new(high_sec_policy.clone());
    let high_sec_sig = high_sec_signer.sign(&high_sec_keypair, message)?;
    
    println!("   High-security hybrid signature:");
    println!("     Security: 192-bit classical, 256-bit post-quantum");
    println!("     Total size: {} bytes\n", high_sec_sig.total_size());

    println!("Hybrid cryptography example completed!\n");
    println!("Use Cases:");
    println!("   - Gradual migration from classical to post-quantum");
    println!("   - Defense in depth (if one algorithm breaks, other protects)");
    println!("   - Compatibility with legacy and future systems");
    println!("   - Compliance with evolving standards");

    Ok(())
}

