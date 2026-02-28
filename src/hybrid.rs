//! Hybrid cryptography support for transition period
//!
//! This module enables systems to use both classical and post-quantum
//! cryptography simultaneously, allowing for safe gradual migration.
//!
//! ## Use Cases
//! - Backward compatibility during migration
//! - Defense in depth (if one algorithm is broken, the other still protects)
//! - Compliance with both legacy and future standards

use crate::algorithms::{AlgorithmType, ClassicalAlgorithm, PostQuantumAlgorithm};
use crate::error::{Error, Result};
use crate::keypair::{KeyPair, KeyPairGenerator};
use crate::policy::CryptoPolicy;
use crate::signature::{Signature, Signer, Verifier};
use serde::{Deserialize, Serialize};

/// Represents a hybrid key pair (classical + post-quantum)
#[derive(Clone)]
pub struct HybridKeyPair {
    classical: KeyPair,
    post_quantum: KeyPair,
}

impl HybridKeyPair {
    /// Create a new hybrid key pair
    pub fn new(classical: KeyPair, post_quantum: KeyPair) -> Self {
        Self {
            classical,
            post_quantum,
        }
    }

    /// Get the classical key pair
    pub fn classical(&self) -> &KeyPair {
        &self.classical
    }

    /// Get the post-quantum key pair
    pub fn post_quantum(&self) -> &KeyPair {
        &self.post_quantum
    }

    /// Get the classical algorithm type
    pub fn classical_algorithm(&self) -> AlgorithmType {
        self.classical.algorithm()
    }

    /// Get the post-quantum algorithm type
    pub fn post_quantum_algorithm(&self) -> AlgorithmType {
        self.post_quantum.algorithm()
    }
}

/// Represents a hybrid signature (contains both classical and post-quantum signatures)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HybridSignature {
    classical: Signature,
    post_quantum: Signature,
}

impl HybridSignature {
    /// Create a new hybrid signature
    pub fn new(classical: Signature, post_quantum: Signature) -> Self {
        Self {
            classical,
            post_quantum,
        }
    }

    /// Get the classical signature
    pub fn classical(&self) -> &Signature {
        &self.classical
    }

    /// Get the post-quantum signature
    pub fn post_quantum(&self) -> &Signature {
        &self.post_quantum
    }

    /// Get the total size of both signatures
    pub fn total_size(&self) -> usize {
        self.classical.len() + self.post_quantum.len()
    }

    /// Serialize to bytes (for storage/transmission)
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| Error::SerializationError(format!("Failed to serialize hybrid signature: {}", e)))
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes)
            .map_err(|e| Error::SerializationError(format!("Failed to deserialize hybrid signature: {}", e)))
    }
}

/// Generator for hybrid key pairs
pub struct HybridKeyPairGenerator {
    policy: CryptoPolicy,
    classical_algo: ClassicalAlgorithm,
    pqc_algo: PostQuantumAlgorithm,
}

impl HybridKeyPairGenerator {
    /// Create a new hybrid key pair generator
    pub fn new(
        policy: CryptoPolicy,
        classical_algo: ClassicalAlgorithm,
        pqc_algo: PostQuantumAlgorithm,
    ) -> Self {
        Self {
            policy,
            classical_algo,
            pqc_algo,
        }
    }

    /// Create with default algorithms (Ed25519 + Dilithium3)
    pub fn with_defaults(policy: CryptoPolicy) -> Self {
        Self {
            policy,
            classical_algo: ClassicalAlgorithm::Ed25519,
            pqc_algo: PostQuantumAlgorithm::Dilithium3,
        }
    }

    /// Generate a hybrid key pair
    pub fn generate(&self) -> Result<HybridKeyPair> {
        let generator = KeyPairGenerator::new(self.policy.clone());

        // Generate classical key pair
        let classical = generator.generate(AlgorithmType::Classical(self.classical_algo))?;

        // Generate post-quantum key pair
        let post_quantum = generator.generate(AlgorithmType::PostQuantum(self.pqc_algo))?;

        Ok(HybridKeyPair::new(classical, post_quantum))
    }
}

/// Signer for hybrid signatures
pub struct HybridSigner {
    policy: CryptoPolicy,
}

impl HybridSigner {
    /// Create a new hybrid signer
    pub fn new(policy: CryptoPolicy) -> Self {
        Self { policy }
    }

    /// Sign a message with both classical and post-quantum algorithms
    pub fn sign(&self, keypair: &HybridKeyPair, message: &[u8]) -> Result<HybridSignature> {
        let signer = Signer::new(self.policy.clone());

        // Sign with classical algorithm
        let classical_sig = signer.sign(keypair.classical(), message)?;

        // Sign with post-quantum algorithm
        let pqc_sig = signer.sign(keypair.post_quantum(), message)?;

        Ok(HybridSignature::new(classical_sig, pqc_sig))
    }
}

/// Verification strategy for hybrid signatures
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationStrategy {
    /// Both signatures must be valid (most secure)
    RequireBoth,
    /// Either signature can be valid (more lenient)
    RequireEither,
    /// Only classical must be valid (backward compatibility mode)
    RequireClassical,
    /// Only post-quantum must be valid (forward compatibility mode)
    RequirePostQuantum,
}

/// Verifier for hybrid signatures
pub struct HybridVerifier {
    policy: CryptoPolicy,
    strategy: VerificationStrategy,
}

impl HybridVerifier {
    /// Create a new hybrid verifier with a strategy
    pub fn new(policy: CryptoPolicy, strategy: VerificationStrategy) -> Self {
        Self { policy, strategy }
    }

    /// Create with default strategy (require both)
    pub fn with_defaults(policy: CryptoPolicy) -> Self {
        Self {
            policy,
            strategy: VerificationStrategy::RequireBoth,
        }
    }

    /// Verify a hybrid signature
    pub fn verify(
        &self,
        keypair: &HybridKeyPair,
        message: &[u8],
        signature: &HybridSignature,
    ) -> Result<()> {
        let verifier = Verifier::new(self.policy.clone());

        // Verify classical signature
        let classical_result = verifier.verify(
            keypair.classical().public_key(),
            message,
            signature.classical(),
        );

        // Verify post-quantum signature
        let pqc_result = verifier.verify(
            keypair.post_quantum().public_key(),
            message,
            signature.post_quantum(),
        );

        // Apply verification strategy
        match self.strategy {
            VerificationStrategy::RequireBoth => {
                classical_result?;
                pqc_result?;
                Ok(())
            }
            VerificationStrategy::RequireEither => {
                if classical_result.is_ok() || pqc_result.is_ok() {
                    Ok(())
                } else {
                    Err(Error::InvalidSignature(
                        "Both classical and post-quantum signature verification failed".into(),
                    ))
                }
            }
            VerificationStrategy::RequireClassical => classical_result,
            VerificationStrategy::RequirePostQuantum => pqc_result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::CryptoMode;

    #[test]
    fn test_hybrid_keypair_generation() {
        let policy = CryptoPolicy::new("hybrid-test").set_mode(CryptoMode::Hybrid);
        let generator = HybridKeyPairGenerator::with_defaults(policy);

        let keypair = generator.generate().unwrap();

        assert!(keypair.classical_algorithm().is_classical());
        assert!(keypair.post_quantum_algorithm().is_post_quantum());
    }

    #[test]
    fn test_hybrid_sign_and_verify_require_both() {
        let policy = CryptoPolicy::new("hybrid-test").set_mode(CryptoMode::Hybrid);
        let generator = HybridKeyPairGenerator::with_defaults(policy.clone());

        // Generate hybrid key pair
        let keypair = generator.generate().unwrap();

        // Sign with hybrid
        let signer = HybridSigner::new(policy.clone());
        let message = b"Hybrid cryptography test message";
        let signature = signer.sign(&keypair, message).unwrap();

        // Verify with "require both" strategy
        let verifier = HybridVerifier::new(policy, VerificationStrategy::RequireBoth);
        assert!(verifier.verify(&keypair, message, &signature).is_ok());

        // Verify with wrong message should fail
        let wrong_message = b"Wrong message";
        assert!(verifier.verify(&keypair, wrong_message, &signature).is_err());
    }

    #[test]
    fn test_hybrid_signature_size() {
        let policy = CryptoPolicy::new("hybrid-test").set_mode(CryptoMode::Hybrid);
        let generator = HybridKeyPairGenerator::with_defaults(policy.clone());
        let keypair = generator.generate().unwrap();

        let signer = HybridSigner::new(policy);
        let message = b"Size test";
        let signature = signer.sign(&keypair, message).unwrap();

        // Hybrid signature should be sum of both signatures
        let total = signature.total_size();
        assert!(total > 0);
        assert_eq!(
            total,
            signature.classical().len() + signature.post_quantum().len()
        );
    }

    #[test]
    fn test_hybrid_verification_strategies() {
        let policy = CryptoPolicy::new("hybrid-test").set_mode(CryptoMode::Hybrid);
        let generator = HybridKeyPairGenerator::with_defaults(policy.clone());
        let keypair = generator.generate().unwrap();

        let signer = HybridSigner::new(policy.clone());
        let message = b"Strategy test";
        let signature = signer.sign(&keypair, message).unwrap();

        // Test all strategies
        for strategy in [
            VerificationStrategy::RequireBoth,
            VerificationStrategy::RequireEither,
            VerificationStrategy::RequireClassical,
            VerificationStrategy::RequirePostQuantum,
        ] {
            let verifier = HybridVerifier::new(policy.clone(), strategy);
            assert!(verifier.verify(&keypair, message, &signature).is_ok());
        }
    }

    #[test]
    fn test_hybrid_signature_serialization() {
        let policy = CryptoPolicy::new("hybrid-test").set_mode(CryptoMode::Hybrid);
        let generator = HybridKeyPairGenerator::with_defaults(policy.clone());
        let keypair = generator.generate().unwrap();

        let signer = HybridSigner::new(policy);
        let message = b"Serialization test";
        let signature = signer.sign(&keypair, message).unwrap();

        // Serialize and deserialize
        let bytes = signature.to_bytes().unwrap();
        let deserialized = HybridSignature::from_bytes(&bytes).unwrap();

        // Verify deserialized signature
        let verifier = HybridVerifier::with_defaults(
            CryptoPolicy::new("hybrid-test").set_mode(CryptoMode::Hybrid),
        );
        assert!(verifier.verify(&keypair, message, &deserialized).is_ok());
    }

    #[test]
    fn test_custom_hybrid_algorithms() {
        let policy = CryptoPolicy::new("custom-hybrid")
            .set_mode(CryptoMode::Hybrid)
            .set_min_security_level(192);

        // Use P-384 (192-bit) + Dilithium5 (256-bit)
        let generator = HybridKeyPairGenerator::new(
            policy.clone(),
            ClassicalAlgorithm::EcdsaP384,
            PostQuantumAlgorithm::Dilithium5,
        );

        let keypair = generator.generate().unwrap();
        let signer = HybridSigner::new(policy.clone());
        let message = b"High security test";
        let signature = signer.sign(&keypair, message).unwrap();

        let verifier = HybridVerifier::with_defaults(policy);
        assert!(verifier.verify(&keypair, message, &signature).is_ok());
    }
}

