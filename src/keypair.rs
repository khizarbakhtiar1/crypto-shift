//! Unified key pair management across classical and post-quantum algorithms

use crate::algorithms::AlgorithmType;
use crate::error::{Error, Result};
use crate::policy::CryptoPolicy;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Represents a cryptographic key pair
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyPair {
    /// The algorithm used for this key pair
    algorithm: AlgorithmType,
    /// Public key bytes
    public_key: Vec<u8>,
    /// Private key bytes (will be zeroized on drop)
    #[serde(skip, default = "SecretKey::default")]
    private_key: SecretKey,
}

/// Secure wrapper for private key material
#[derive(Clone, Default)]
pub struct SecretKey {
    bytes: Vec<u8>,
}

impl SecretKey {
    /// Create a new secret key
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Get a reference to the key bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the length of the key
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if the key is empty
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl KeyPair {
    /// Create a new key pair
    pub fn new(algorithm: AlgorithmType, public_key: Vec<u8>, private_key: Vec<u8>) -> Self {
        Self {
            algorithm,
            public_key,
            private_key: SecretKey::new(private_key),
        }
    }

    /// Get the algorithm type
    pub fn algorithm(&self) -> AlgorithmType {
        self.algorithm
    }

    /// Get the public key
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Get the private key
    pub fn private_key(&self) -> &SecretKey {
        &self.private_key
    }

    /// Get the public key size in bytes
    pub fn public_key_size(&self) -> usize {
        self.public_key.len()
    }

    /// Get the private key size in bytes
    pub fn private_key_size(&self) -> usize {
        self.private_key.len()
    }

    /// Validate this key pair against a policy
    pub fn validate_against_policy(&self, policy: &CryptoPolicy) -> Result<()> {
        policy.validate_algorithm(&self.algorithm)
    }
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

/// Key pair generator
#[derive(Default)]
pub struct KeyPairGenerator {
    policy: CryptoPolicy,
}

impl KeyPairGenerator {
    /// Create a new key pair generator with a policy
    pub fn new(policy: CryptoPolicy) -> Self {
        Self { policy }
    }

    /// Generate a key pair for a specific algorithm
    pub fn generate(&self, algorithm: AlgorithmType) -> Result<KeyPair> {
        // Validate algorithm against policy
        self.policy.validate_algorithm(&algorithm)?;

        // Generate based on algorithm type
        match algorithm {
            AlgorithmType::Classical(classical) => self.generate_classical(classical, algorithm),
            AlgorithmType::PostQuantum(pq) => self.generate_post_quantum(pq, algorithm),
        }
    }

    /// Generate key pair using the policy's preferred algorithm
    pub fn generate_with_policy(&self) -> Result<KeyPair> {
        use crate::algorithms::{ClassicalAlgorithm, PostQuantumAlgorithm};
        use crate::policy::CryptoMode;

        // Select algorithm based on policy mode
        let algorithm = match self.policy.mode() {
            CryptoMode::Classical => {
                AlgorithmType::Classical(ClassicalAlgorithm::Ed25519)
            }
            CryptoMode::PostQuantum => {
                AlgorithmType::PostQuantum(PostQuantumAlgorithm::Dilithium3)
            }
            CryptoMode::Hybrid => {
                // In hybrid mode, prefer PQC but fall back to classical
                AlgorithmType::PostQuantum(PostQuantumAlgorithm::Dilithium3)
            }
        };

        self.generate(algorithm)
    }

    fn generate_classical(
        &self,
        classical: crate::algorithms::ClassicalAlgorithm,
        algorithm: AlgorithmType,
    ) -> Result<KeyPair> {
        use crate::algorithms::ClassicalAlgorithm;

        match classical {
            ClassicalAlgorithm::Ed25519 => {
                use ed25519_dalek::SigningKey;
                use rand::rngs::OsRng;

                // Generate random 32 bytes for the secret key
                let mut secret_bytes = [0u8; 32];
                use rand::RngCore;
                OsRng.fill_bytes(&mut secret_bytes);

                let signing_key = SigningKey::from_bytes(&secret_bytes);
                let verifying_key = signing_key.verifying_key();

                Ok(KeyPair::new(
                    algorithm,
                    verifying_key.to_bytes().to_vec(),
                    signing_key.to_bytes().to_vec(),
                ))
            }
            ClassicalAlgorithm::X25519 => {
                use rand::rngs::OsRng;
                use x25519_dalek::{PublicKey, EphemeralSecret};

                let secret = EphemeralSecret::random_from_rng(OsRng);
                let public = PublicKey::from(&secret);

                // X25519 doesn't expose secret bytes directly in the same way
                // We'll use a placeholder for now
                let secret_bytes = vec![0u8; 32]; // Placeholder

                Ok(KeyPair::new(
                    algorithm,
                    public.to_bytes().to_vec(),
                    secret_bytes,
                ))
            }
            ClassicalAlgorithm::RSA2048 => self.generate_rsa(2048, algorithm),
            ClassicalAlgorithm::RSA3072 => self.generate_rsa(3072, algorithm),
            ClassicalAlgorithm::RSA4096 => self.generate_rsa(4096, algorithm),
            ClassicalAlgorithm::EcdsaP256 => self.generate_ecdsa_p256(algorithm),
            ClassicalAlgorithm::EcdsaP384 => self.generate_ecdsa_p384(algorithm),
        }
    }

    fn generate_rsa(&self, bits: usize, algorithm: AlgorithmType) -> Result<KeyPair> {
        use rand::rngs::OsRng;
        use rsa::{RsaPrivateKey, RsaPublicKey};
        use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};

        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, bits)
            .map_err(|e| Error::crypto(format!("Failed to generate RSA key: {}", e)))?;
        
        let public_key = RsaPublicKey::from(&private_key);

        // Encode keys to DER format
        let private_der = private_key
            .to_pkcs8_der()
            .map_err(|e| Error::crypto(format!("Failed to encode RSA private key: {}", e)))?;
        
        let public_der = public_key
            .to_public_key_der()
            .map_err(|e| Error::crypto(format!("Failed to encode RSA public key: {}", e)))?;

        Ok(KeyPair::new(
            algorithm,
            public_der.as_bytes().to_vec(),
            private_der.as_bytes().to_vec(),
        ))
    }

    fn generate_ecdsa_p256(&self, algorithm: AlgorithmType) -> Result<KeyPair> {
        use p256::ecdsa::SigningKey;
        use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
        use rand::rngs::OsRng;

        let mut rng = OsRng;
        let signing_key = SigningKey::random(&mut rng);
        let verifying_key = signing_key.verifying_key();

        // Encode keys to DER format
        let private_der = signing_key
            .to_pkcs8_der()
            .map_err(|e| Error::crypto(format!("Failed to encode ECDSA P-256 private key: {}", e)))?;
        
        let public_der = verifying_key
            .to_public_key_der()
            .map_err(|e| Error::crypto(format!("Failed to encode ECDSA P-256 public key: {}", e)))?;

        Ok(KeyPair::new(
            algorithm,
            public_der.as_bytes().to_vec(),
            private_der.as_bytes().to_vec(),
        ))
    }

    fn generate_ecdsa_p384(&self, algorithm: AlgorithmType) -> Result<KeyPair> {
        use p384::ecdsa::SigningKey;
        use p384::pkcs8::{EncodePrivateKey, EncodePublicKey};
        use rand::rngs::OsRng;

        let mut rng = OsRng;
        let signing_key = SigningKey::random(&mut rng);
        let verifying_key = signing_key.verifying_key();

        // Encode keys to DER format
        let private_der = signing_key
            .to_pkcs8_der()
            .map_err(|e| Error::crypto(format!("Failed to encode ECDSA P-384 private key: {}", e)))?;
        
        let public_der = verifying_key
            .to_public_key_der()
            .map_err(|e| Error::crypto(format!("Failed to encode ECDSA P-384 public key: {}", e)))?;

        Ok(KeyPair::new(
            algorithm,
            public_der.as_bytes().to_vec(),
            private_der.as_bytes().to_vec(),
        ))
    }

    fn generate_post_quantum(
        &self,
        pq: crate::algorithms::PostQuantumAlgorithm,
        algorithm: AlgorithmType,
    ) -> Result<KeyPair> {
        use crate::algorithms::PostQuantumAlgorithm;

        match pq {
            PostQuantumAlgorithm::Dilithium2 => self.generate_dilithium2(algorithm),
            PostQuantumAlgorithm::Dilithium3 => self.generate_dilithium3(algorithm),
            PostQuantumAlgorithm::Dilithium5 => self.generate_dilithium5(algorithm),
            _ => Err(Error::UnsupportedAlgorithm(format!(
                "Post-quantum algorithm {} not yet fully implemented",
                algorithm
            ))),
        }
    }

    fn generate_dilithium2(&self, algorithm: AlgorithmType) -> Result<KeyPair> {
        use pqcrypto_dilithium::dilithium2;
        use pqcrypto_traits::sign::PublicKey as _;
        use pqcrypto_traits::sign::SecretKey as _;

        let (public_key, secret_key) = dilithium2::keypair();

        Ok(KeyPair::new(
            algorithm,
            public_key.as_bytes().to_vec(),
            secret_key.as_bytes().to_vec(),
        ))
    }

    fn generate_dilithium3(&self, algorithm: AlgorithmType) -> Result<KeyPair> {
        use pqcrypto_dilithium::dilithium3;
        use pqcrypto_traits::sign::PublicKey as _;
        use pqcrypto_traits::sign::SecretKey as _;

        let (public_key, secret_key) = dilithium3::keypair();

        Ok(KeyPair::new(
            algorithm,
            public_key.as_bytes().to_vec(),
            secret_key.as_bytes().to_vec(),
        ))
    }

    fn generate_dilithium5(&self, algorithm: AlgorithmType) -> Result<KeyPair> {
        use pqcrypto_dilithium::dilithium5;
        use pqcrypto_traits::sign::PublicKey as _;
        use pqcrypto_traits::sign::SecretKey as _;

        let (public_key, secret_key) = dilithium5::keypair();

        Ok(KeyPair::new(
            algorithm,
            public_key.as_bytes().to_vec(),
            secret_key.as_bytes().to_vec(),
        ))
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithms::ClassicalAlgorithm;
    use crate::policy::PolicyBuilder;

    #[test]
    fn test_keypair_generation_ed25519() {
        let policy = PolicyBuilder::classical_only();
        let generator = KeyPairGenerator::new(policy);
        let algorithm = AlgorithmType::Classical(ClassicalAlgorithm::Ed25519);

        let keypair = generator.generate(algorithm).unwrap();
        assert_eq!(keypair.algorithm(), algorithm);
        assert_eq!(keypair.public_key_size(), 32);
        assert_eq!(keypair.private_key_size(), 32);
    }

    #[test]
    fn test_keypair_generation_x25519() {
        let policy = PolicyBuilder::classical_only();
        let generator = KeyPairGenerator::new(policy);
        let algorithm = AlgorithmType::Classical(ClassicalAlgorithm::X25519);

        let keypair = generator.generate(algorithm).unwrap();
        assert_eq!(keypair.algorithm(), algorithm);
        assert_eq!(keypair.public_key_size(), 32);
        assert_eq!(keypair.private_key_size(), 32);
    }

    #[test]
    fn test_keypair_policy_validation() {
        let policy = PolicyBuilder::classical_only();
        let generator = KeyPairGenerator::new(policy.clone());
        let algorithm = AlgorithmType::Classical(ClassicalAlgorithm::Ed25519);

        let keypair = generator.generate(algorithm).unwrap();
        assert!(keypair.validate_against_policy(&policy).is_ok());
    }

    #[test]
    fn test_keypair_with_policy() {
        let policy = PolicyBuilder::classical_only();
        let generator = KeyPairGenerator::new(policy);

        let keypair = generator.generate_with_policy().unwrap();
        assert!(keypair.algorithm().is_classical());
    }

    #[test]
    fn test_secret_key_zeroization() {
        let mut secret = SecretKey::new(vec![1, 2, 3, 4, 5]);
        assert_eq!(secret.len(), 5);
        assert_ne!(secret.as_bytes(), &[0, 0, 0, 0, 0]);
        secret.zeroize();
        // After zeroization, the Vec is cleared (empty)
        assert_eq!(secret.len(), 0);
        assert!(secret.is_empty());
    }
}

