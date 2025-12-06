//! Policy-driven cryptography example
//!
//! This example demonstrates:
//! - Creating and managing cryptographic policies
//! - Policy validation and enforcement
//! - Different policy configurations for different use cases

use cryptoshift::{
    AlgorithmType, ClassicalAlgorithm, CryptoMode, CryptoPolicy, KeyPairGenerator,
    MigrationStage, PolicyBuilder, PostQuantumAlgorithm, Signer, Verifier,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("📋 CryptoShift - Policy-Driven Cryptography Example\n");

    // 1. Classical-only policy (current state for many systems)
    println!("1️⃣  Classical-Only Policy:");
    let classical_policy = PolicyBuilder::classical_only();
    demonstrate_policy(&classical_policy, "Classical")?;

    // 2. Post-quantum only policy (future state)
    println!("\n2️⃣  Post-Quantum Only Policy:");
    let pqc_policy = PolicyBuilder::post_quantum_only();
    demonstrate_policy(&pqc_policy, "PostQuantum")?;

    // 3. Hybrid policy with migration stage
    println!("\n3️⃣  Hybrid Policy with Gradual Rollout:");
    let hybrid_policy = PolicyBuilder::hybrid_migration(0.1); // 10% PQC
    demonstrate_policy(&hybrid_policy, "Hybrid")?;

    // 4. High-security policy (256-bit minimum)
    println!("\n4️⃣  High-Security Policy (256-bit minimum):");
    let high_sec_policy = PolicyBuilder::high_security();
    println!("   Policy: {}", high_sec_policy.name());
    println!("   Mode: {:?}", high_sec_policy.mode());
    println!("   Minimum Security: {} bits", high_sec_policy.min_security_level());
    
    // This should work (256-bit security)
    let dilithium5 = AlgorithmType::PostQuantum(PostQuantumAlgorithm::Dilithium5);
    match high_sec_policy.validate_algorithm(&dilithium5) {
        Ok(_) => println!("   Dilithium5 (256-bit): ALLOWED"),
        Err(e) => println!("   Dilithium5: {}", e),
    }
    
    // This should fail (128-bit security)
    let ed25519 = AlgorithmType::Classical(ClassicalAlgorithm::Ed25519);
    match high_sec_policy.validate_algorithm(&ed25519) {
        Ok(_) => println!("   Ed25519 (128-bit): ALLOWED"),
        Err(e) => println!("   Ed25519 (128-bit): REJECTED - {}", e),
    }

    // 5. Custom policy with specific algorithms
    println!("\n5️⃣  Custom Policy with Allowed Algorithms:");
    let custom_policy = CryptoPolicy::new("financial-institution")
        .set_mode(CryptoMode::Hybrid)
        .set_min_security_level(192)
        .allow_algorithm(AlgorithmType::Classical(ClassicalAlgorithm::EcdsaP384))
        .allow_algorithm(AlgorithmType::PostQuantum(PostQuantumAlgorithm::Dilithium5));
    
    println!("   Policy: {}", custom_policy.name());
    println!("   Mode: Hybrid (controlled allowlist)");
    println!("   Minimum Security: 192 bits");
    println!("   Allowed Algorithms:");
    
    // Test various algorithms
    let test_algos = vec![
        (AlgorithmType::Classical(ClassicalAlgorithm::Ed25519), "Ed25519"),
        (AlgorithmType::Classical(ClassicalAlgorithm::EcdsaP384), "ECDSA-P384"),
        (AlgorithmType::PostQuantum(PostQuantumAlgorithm::Dilithium3), "Dilithium3"),
        (AlgorithmType::PostQuantum(PostQuantumAlgorithm::Dilithium5), "Dilithium5"),
    ];
    
    for (algo, name) in test_algos {
        match custom_policy.validate_algorithm(&algo) {
            Ok(_) => println!("     {}: ALLOWED", name),
            Err(_) => println!("     {}: REJECTED", name),
        }
    }

    // 6. Migration stages
    println!("\n6️⃣  Migration Stage Examples:");
    test_migration_stages()?;

    println!("\n✅ Policy example completed!\n");
    println!("Key Benefits:");
    println!("   - Centralized security policy management");
    println!("   - Automatic validation and enforcement");
    println!("   - Flexible configuration for different use cases");
    println!("   - Support for gradual migration strategies");

    Ok(())
}

fn demonstrate_policy(
    policy: &CryptoPolicy,
    mode_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("   Policy: {}", policy.name());
    println!("   Mode: {}", mode_name);
    println!("   Minimum Security: {} bits", policy.min_security_level());
    
    // Generate and use a key pair
    let generator = KeyPairGenerator::new(policy.clone());
    let keypair = generator.generate_with_policy()?;
    
    let message = b"Test message for policy validation";
    let signer = Signer::new(policy.clone());
    let signature = signer.sign(&keypair, message)?;
    
    let verifier = Verifier::new(policy.clone());
    verifier.verify(keypair.public_key(), message, &signature)?;
    
    println!("   Generated key: {}", keypair.algorithm());
    println!("   Sign & Verify: SUCCESS");
    
    Ok(())
}

fn test_migration_stages() -> Result<(), Box<dyn std::error::Error>> {
    let stages = vec![
        (MigrationStage::NotStarted, "Not Started"),
        (MigrationStage::Testing(0.01), "Testing (1%)"),
        (MigrationStage::Rollout(0.25), "Rollout (25%)"),
        (MigrationStage::Rollout(0.75), "Rollout (75%)"),
        (MigrationStage::Complete, "Complete"),
    ];
    
    for (stage, name) in stages {
        let policy = CryptoPolicy::new("migration-test")
            .set_mode(CryptoMode::Hybrid)
            .set_migration_stage(stage);
        
        // Simulate some requests
        let mut pqc_count = 0;
        let samples = 100;
        
        for i in 0..samples {
            let sample = i as f32 / samples as f32;
            if policy.should_use_pqc(sample) {
                pqc_count += 1;
            }
        }
        
        println!("   {} → {}% PQC traffic", name, pqc_count);
    }
    
    Ok(())
}

