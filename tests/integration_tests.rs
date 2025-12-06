//! Integration tests for CryptoShift SDK
//!
//! These tests verify end-to-end workflows and cross-module functionality

use cryptoshift::*;

#[test]
fn test_full_classical_workflow() {
    // Create policy
    let policy = PolicyBuilder::classical_only();
    
    // Test multiple algorithms
    let algorithms = vec![
        AlgorithmType::Classical(ClassicalAlgorithm::Ed25519),
        AlgorithmType::Classical(ClassicalAlgorithm::EcdsaP256),
        AlgorithmType::Classical(ClassicalAlgorithm::EcdsaP384),
    ];
    
    for algo in algorithms {
        // Generate keypair
        let generator = KeyPairGenerator::new(policy.clone());
        let keypair = generator.generate(algo).unwrap();
        
        // Sign message
        let message = b"Integration test message";
        let signer = Signer::new(policy.clone());
        let signature = signer.sign(&keypair, message).unwrap();
        
        // Verify signature
        let verifier = Verifier::new(policy.clone());
        assert!(verifier.verify(keypair.public_key(), message, &signature).is_ok());
        
        // Wrong message should fail
        assert!(verifier.verify(keypair.public_key(), b"wrong", &signature).is_err());
    }
}

#[test]
fn test_full_post_quantum_workflow() {
    let policy = PolicyBuilder::post_quantum_only();
    
    let algorithms = vec![
        AlgorithmType::PostQuantum(PostQuantumAlgorithm::Dilithium2),
        AlgorithmType::PostQuantum(PostQuantumAlgorithm::Dilithium3),
        AlgorithmType::PostQuantum(PostQuantumAlgorithm::Dilithium5),
    ];
    
    for algo in algorithms {
        let generator = KeyPairGenerator::new(policy.clone());
        let keypair = generator.generate(algo).unwrap();
        
        let message = b"Post-quantum integration test";
        let signer = Signer::new(policy.clone());
        let signature = signer.sign(&keypair, message).unwrap();
        
        let verifier = Verifier::new(policy.clone());
        assert!(verifier.verify(keypair.public_key(), message, &signature).is_ok());
    }
}

#[test]
fn test_hybrid_workflow_end_to_end() {
    let policy = CryptoPolicy::new("integration-hybrid")
        .set_mode(CryptoMode::Hybrid);
    
    // Generate hybrid keypair
    let generator = HybridKeyPairGenerator::with_defaults(policy.clone());
    let keypair = generator.generate().unwrap();
    
    // Sign with hybrid
    let message = b"Hybrid integration test";
    let signer = HybridSigner::new(policy.clone());
    let signature = signer.sign(&keypair, message).unwrap();
    
    // Verify with all strategies
    for strategy in [
        VerificationStrategy::RequireBoth,
        VerificationStrategy::RequireEither,
        VerificationStrategy::RequireClassical,
        VerificationStrategy::RequirePostQuantum,
    ] {
        let verifier = HybridVerifier::new(policy.clone(), strategy);
        assert!(verifier.verify(&keypair, message, &signature).is_ok());
    }
    
    // Test serialization round-trip
    let bytes = signature.to_bytes().unwrap();
    let deserialized = HybridSignature::from_bytes(&bytes).unwrap();
    let verifier = HybridVerifier::with_defaults(policy);
    assert!(verifier.verify(&keypair, message, &deserialized).is_ok());
}

#[test]
fn test_policy_enforcement_across_modules() {
    // Create a policy that only allows high-security algorithms
    let policy = CryptoPolicy::new("high-security-only")
        .set_mode(CryptoMode::Hybrid)
        .set_min_security_level(256);
    
    // Dilithium5 should work (256-bit)
    let generator = KeyPairGenerator::new(policy.clone());
    let keypair = generator.generate(
        AlgorithmType::PostQuantum(PostQuantumAlgorithm::Dilithium5)
    ).unwrap();
    
    let message = b"High security test";
    let signer = Signer::new(policy.clone());
    let signature = signer.sign(&keypair, message).unwrap();
    
    let verifier = Verifier::new(policy.clone());
    assert!(verifier.verify(keypair.public_key(), message, &signature).is_ok());
    
    // Ed25519 should fail (128-bit)
    let result = generator.generate(
        AlgorithmType::Classical(ClassicalAlgorithm::Ed25519)
    );
    assert!(result.is_err());
}

#[test]
fn test_migration_simulation() {
    // Simulate a migration from 0% to 100% PQC
    let stages = vec![
        MigrationStage::NotStarted,
        MigrationStage::Testing(0.01),
        MigrationStage::Rollout(0.25),
        MigrationStage::Rollout(0.75),
        MigrationStage::Complete,
    ];
    
    for stage in stages {
        let policy = CryptoPolicy::new("migration-sim")
            .set_mode(CryptoMode::Hybrid)
            .set_migration_stage(stage);
        
        // Sample the policy
        let mut pqc_count = 0;
        let samples = 1000;
        
        for i in 0..samples {
            let sample = i as f32 / samples as f32;
            if policy.should_use_pqc(sample) {
                pqc_count += 1;
            }
        }
        
        // Verify the percentage is approximately correct
        let percentage = pqc_count as f32 / samples as f32;
        match stage {
            MigrationStage::NotStarted => assert!(percentage < 0.01),
            MigrationStage::Testing(p) | MigrationStage::Rollout(p) => {
                assert!((percentage - p).abs() < 0.05); // Allow 5% variance
            }
            MigrationStage::Complete => assert!(percentage > 0.99),
        }
    }
}

#[test]
fn test_cross_algorithm_compatibility() {
    // Ensure different algorithm combinations work together
    let policy = CryptoPolicy::new("compat-test").set_mode(CryptoMode::Hybrid);
    
    let combos = vec![
        (ClassicalAlgorithm::Ed25519, PostQuantumAlgorithm::Dilithium2),
        (ClassicalAlgorithm::EcdsaP256, PostQuantumAlgorithm::Dilithium3),
        (ClassicalAlgorithm::EcdsaP384, PostQuantumAlgorithm::Dilithium5),
    ];
    
    for (classical, pqc) in combos {
        let generator = HybridKeyPairGenerator::new(
            policy.clone(),
            classical,
            pqc,
        );
        let keypair = generator.generate().unwrap();
        
        let message = b"Compatibility test";
        let signer = HybridSigner::new(policy.clone());
        let signature = signer.sign(&keypair, message).unwrap();
        
        let verifier = HybridVerifier::with_defaults(policy.clone());
        assert!(verifier.verify(&keypair, message, &signature).is_ok());
    }
}

#[test]
fn test_large_message_handling() {
    let policy = PolicyBuilder::hybrid_migration(0.5);
    let generator = HybridKeyPairGenerator::with_defaults(policy.clone());
    let keypair = generator.generate().unwrap();
    
    // Test with different message sizes
    for size in [1, 100, 1000, 10000, 100000] {
        let message = vec![0x42u8; size];
        
        let signer = HybridSigner::new(policy.clone());
        let signature = signer.sign(&keypair, &message).unwrap();
        
        let verifier = HybridVerifier::with_defaults(policy.clone());
        assert!(verifier.verify(&keypair, &message, &signature).is_ok());
    }
}

#[test]
fn test_key_size_verification() {
    let policy = CryptoPolicy::new("key-size-test").set_mode(CryptoMode::Hybrid);
    
    // Verify key sizes match expected values
    let test_cases = vec![
        (AlgorithmType::Classical(ClassicalAlgorithm::Ed25519), 32, 32),
        (AlgorithmType::PostQuantum(PostQuantumAlgorithm::Dilithium2), 1312, 2560),
        (AlgorithmType::PostQuantum(PostQuantumAlgorithm::Dilithium3), 1952, 4032),
    ];
    
    for (algo, expected_pub, expected_priv) in test_cases {
        let generator = KeyPairGenerator::new(policy.clone());
        let keypair = generator.generate(algo).unwrap();
        
        assert_eq!(keypair.public_key_size(), expected_pub);
        assert_eq!(keypair.private_key_size(), expected_priv);
    }
}

#[test]
fn test_signature_size_verification() {
    let policy = PolicyBuilder::classical_only();
    
    // Ed25519 signatures should be exactly 64 bytes
    let generator = KeyPairGenerator::new(policy.clone());
    let keypair = generator.generate(
        AlgorithmType::Classical(ClassicalAlgorithm::Ed25519)
    ).unwrap();
    
    let message = b"Size test";
    let signer = Signer::new(policy);
    let signature = signer.sign(&keypair, message).unwrap();
    
    assert_eq!(signature.len(), 64);
}

#[test]
fn test_concurrent_operations() {
    use std::thread;
    
    let policy = PolicyBuilder::hybrid_migration(0.5);
    let policy_clone = policy.clone();
    
    // Spawn multiple threads doing crypto operations
    let handles: Vec<_> = (0..4).map(|i| {
        let p = policy_clone.clone();
        thread::spawn(move || {
            let generator = HybridKeyPairGenerator::with_defaults(p.clone());
            let keypair = generator.generate().unwrap();
            
            let message = format!("Thread {} message", i);
            let signer = HybridSigner::new(p.clone());
            let signature = signer.sign(&keypair, message.as_bytes()).unwrap();
            
            let verifier = HybridVerifier::with_defaults(p);
            verifier.verify(&keypair, message.as_bytes(), &signature).unwrap();
        })
    }).collect();
    
    for handle in handles {
        handle.join().unwrap();
    }
}

