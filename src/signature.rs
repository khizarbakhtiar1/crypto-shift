//! Digital signature operations for classical and post-quantum algorithms
//!
//! This module provides a unified interface for signing and verification
//! operations across different cryptographic algorithms.

use crate::algorithms::{AlgorithmType, ClassicalAlgorithm};
use crate::error::{Error, Result};
use crate::keypair::KeyPair;
use crate::policy::CryptoPolicy;
use serde::{Deserialize, Serialize};

/// Represents a digital signature
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signature {
    /// The algorithm used to create this signature
    algorithm: AlgorithmType,
    /// The signature bytes
    bytes: Vec<u8>,
}

impl Signature {
    /// Create a new signature
    pub fn new(algorithm: AlgorithmType, bytes: Vec<u8>) -> Self {
        Self { algorithm, bytes }
    }

    /// Get the algorithm used for this signature
    pub fn algorithm(&self) -> AlgorithmType {
        self.algorithm
    }

    /// Get the signature bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the signature size in bytes
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if the signature is empty
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Convert to a byte vector
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Signer for creating digital signatures
pub struct Signer {
    policy: CryptoPolicy,
}

impl Signer {
    /// Create a new signer with a policy
    pub fn new(policy: CryptoPolicy) -> Self {
        Self { policy }
    }

    /// Sign a message with a key pair
    pub fn sign(&self, keypair: &KeyPair, message: &[u8]) -> Result<Signature> {
        // Validate the key pair against the policy
        keypair.validate_against_policy(&self.policy)?;

        // Sign based on algorithm type
        match keypair.algorithm() {
            AlgorithmType::Classical(classical) => self.sign_classical(classical, keypair, message),
            AlgorithmType::PostQuantum(pq) => self.sign_post_quantum(pq, keypair, message),
        }
    }

    fn sign_classical(
        &self,
        classical: ClassicalAlgorithm,
        keypair: &KeyPair,
        message: &[u8],
    ) -> Result<Signature> {
        match classical {
            ClassicalAlgorithm::Ed25519 => {
                use ed25519_dalek::{Signature as Ed25519Signature, Signer as Ed25519Signer, SigningKey};

                // Reconstruct the signing key from the stored bytes
                let secret_bytes = keypair.private_key().as_bytes();
                if secret_bytes.len() != 32 {
                    return Err(Error::invalid_key(format!(
                        "Invalid Ed25519 private key length: expected 32, got {}",
                        secret_bytes.len()
                    )));
                }

                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(secret_bytes);
                let signing_key = SigningKey::from_bytes(&key_bytes);

                // Sign the message
                let signature: Ed25519Signature = signing_key.sign(message);

                Ok(Signature::new(
                    keypair.algorithm(),
                    signature.to_bytes().to_vec(),
                ))
            }
            ClassicalAlgorithm::RSA2048 | ClassicalAlgorithm::RSA3072 | ClassicalAlgorithm::RSA4096 => {
                self.sign_rsa(keypair, message)
            }
            ClassicalAlgorithm::EcdsaP256 => self.sign_ecdsa_p256(keypair, message),
            ClassicalAlgorithm::EcdsaP384 => self.sign_ecdsa_p384(keypair, message),
            ClassicalAlgorithm::X25519 => Err(Error::UnsupportedAlgorithm(
                "X25519 is for key exchange, not signatures".into()
            )),
        }
    }

    fn sign_rsa(&self, keypair: &KeyPair, message: &[u8]) -> Result<Signature> {
        use rsa::{RsaPrivateKey, pkcs1v15::SigningKey};
        use rsa::pkcs8::DecodePrivateKey;
        use sha2::Sha256;
        use rsa::signature::{RandomizedSigner, SignatureEncoding};
        use rand::rngs::OsRng;

        // Decode the private key from DER format
        let private_key = RsaPrivateKey::from_pkcs8_der(keypair.private_key().as_bytes())
            .map_err(|e| Error::invalid_key(format!("Failed to decode RSA private key: {}", e)))?;

        let signing_key = SigningKey::<Sha256>::new_unprefixed(private_key);
        
        let mut rng = OsRng;
        // Sign the message
        let signature = signing_key.sign_with_rng(&mut rng, message);

        Ok(Signature::new(
            keypair.algorithm(),
            signature.to_vec(),
        ))
    }

    fn sign_ecdsa_p256(&self, keypair: &KeyPair, message: &[u8]) -> Result<Signature> {
        use p256::ecdsa::{SigningKey, signature::Signer as EcdsaSigner};
        use p256::pkcs8::DecodePrivateKey;

        // Decode the private key from DER format
        let signing_key = SigningKey::from_pkcs8_der(keypair.private_key().as_bytes())
            .map_err(|e| Error::invalid_key(format!("Failed to decode ECDSA P-256 private key: {}", e)))?;

        // Sign the message
        let signature: ecdsa::Signature<p256::NistP256> = signing_key.sign(message);

        Ok(Signature::new(
            keypair.algorithm(),
            signature.to_vec(),
        ))
    }

    fn sign_ecdsa_p384(&self, keypair: &KeyPair, message: &[u8]) -> Result<Signature> {
        use p384::ecdsa::{SigningKey, signature::Signer as EcdsaSigner};
        use p384::pkcs8::DecodePrivateKey;

        // Decode the private key from DER format
        let signing_key = SigningKey::from_pkcs8_der(keypair.private_key().as_bytes())
            .map_err(|e| Error::invalid_key(format!("Failed to decode ECDSA P-384 private key: {}", e)))?;

        // Sign the message
        let signature: ecdsa::Signature<p384::NistP384> = signing_key.sign(message);

        Ok(Signature::new(
            keypair.algorithm(),
            signature.to_vec(),
        ))
    }

    fn sign_post_quantum(
        &self,
        pq: crate::algorithms::PostQuantumAlgorithm,
        keypair: &KeyPair,
        message: &[u8],
    ) -> Result<Signature> {
        use crate::algorithms::PostQuantumAlgorithm;

        match pq {
            PostQuantumAlgorithm::Dilithium2 => self.sign_dilithium2(keypair, message),
            PostQuantumAlgorithm::Dilithium3 => self.sign_dilithium3(keypair, message),
            PostQuantumAlgorithm::Dilithium5 => self.sign_dilithium5(keypair, message),
            _ => Err(Error::UnsupportedAlgorithm(format!(
                "Post-quantum algorithm {} not yet fully implemented",
                keypair.algorithm()
            ))),
        }
    }

    fn sign_dilithium2(&self, keypair: &KeyPair, message: &[u8]) -> Result<Signature> {
        use pqcrypto_dilithium::dilithium2;
        use pqcrypto_traits::sign::{SecretKey, DetachedSignature};

        let secret_key = dilithium2::SecretKey::from_bytes(keypair.private_key().as_bytes())
            .map_err(|e| Error::invalid_key(format!("Invalid Dilithium2 secret key: {:?}", e)))?;

        let signature = dilithium2::detached_sign(message, &secret_key);

        Ok(Signature::new(
            keypair.algorithm(),
            signature.as_bytes().to_vec(),
        ))
    }

    fn sign_dilithium3(&self, keypair: &KeyPair, message: &[u8]) -> Result<Signature> {
        use pqcrypto_dilithium::dilithium3;
        use pqcrypto_traits::sign::{SecretKey, DetachedSignature};

        let secret_key = dilithium3::SecretKey::from_bytes(keypair.private_key().as_bytes())
            .map_err(|e| Error::invalid_key(format!("Invalid Dilithium3 secret key: {:?}", e)))?;

        let signature = dilithium3::detached_sign(message, &secret_key);

        Ok(Signature::new(
            keypair.algorithm(),
            signature.as_bytes().to_vec(),
        ))
    }

    fn sign_dilithium5(&self, keypair: &KeyPair, message: &[u8]) -> Result<Signature> {
        use pqcrypto_dilithium::dilithium5;
        use pqcrypto_traits::sign::{SecretKey, DetachedSignature};

        let secret_key = dilithium5::SecretKey::from_bytes(keypair.private_key().as_bytes())
            .map_err(|e| Error::invalid_key(format!("Invalid Dilithium5 secret key: {:?}", e)))?;

        let signature = dilithium5::detached_sign(message, &secret_key);

        Ok(Signature::new(
            keypair.algorithm(),
            signature.as_bytes().to_vec(),
        ))
    }
}

impl Default for Signer {
    fn default() -> Self {
        Self {
            policy: CryptoPolicy::default(),
        }
    }
}

/// Verifier for validating digital signatures
pub struct Verifier {
    policy: CryptoPolicy,
}

impl Verifier {
    /// Create a new verifier with a policy
    pub fn new(policy: CryptoPolicy) -> Self {
        Self { policy }
    }

    /// Verify a signature against a message and public key
    pub fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &Signature,
    ) -> Result<()> {
        // Validate the algorithm against the policy
        self.policy.validate_algorithm(&signature.algorithm())?;

        // Verify based on algorithm type
        match signature.algorithm() {
            AlgorithmType::Classical(classical) => {
                self.verify_classical(classical, public_key, message, signature)
            }
            AlgorithmType::PostQuantum(pq) => {
                self.verify_post_quantum(pq, public_key, message, signature)
            }
        }
    }

    fn verify_classical(
        &self,
        classical: ClassicalAlgorithm,
        public_key: &[u8],
        message: &[u8],
        signature: &Signature,
    ) -> Result<()> {
        match classical {
            ClassicalAlgorithm::Ed25519 => {
                use ed25519_dalek::{
                    Signature as Ed25519Signature, Verifier as Ed25519Verifier, VerifyingKey,
                };

                // Reconstruct the verifying key
                if public_key.len() != 32 {
                    return Err(Error::invalid_key(format!(
                        "Invalid Ed25519 public key length: expected 32, got {}",
                        public_key.len()
                    )));
                }

                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(public_key);

                let verifying_key = VerifyingKey::from_bytes(&key_bytes)
                    .map_err(|e| Error::invalid_key(format!("Invalid Ed25519 public key: {}", e)))?;

                // Reconstruct the signature
                if signature.as_bytes().len() != 64 {
                    return Err(Error::InvalidSignature(format!(
                        "Invalid Ed25519 signature length: expected 64, got {}",
                        signature.as_bytes().len()
                    )));
                }

                let mut sig_bytes = [0u8; 64];
                sig_bytes.copy_from_slice(signature.as_bytes());

                let sig = Ed25519Signature::from_bytes(&sig_bytes);

                // Verify the signature
                verifying_key
                    .verify(message, &sig)
                    .map_err(|e| Error::InvalidSignature(format!("Signature verification failed: {}", e)))?;

                Ok(())
            }
            ClassicalAlgorithm::RSA2048 | ClassicalAlgorithm::RSA3072 | ClassicalAlgorithm::RSA4096 => {
                self.verify_rsa(public_key, message, signature)
            }
            ClassicalAlgorithm::EcdsaP256 => self.verify_ecdsa_p256(public_key, message, signature),
            ClassicalAlgorithm::EcdsaP384 => self.verify_ecdsa_p384(public_key, message, signature),
            ClassicalAlgorithm::X25519 => Err(Error::UnsupportedAlgorithm(
                "X25519 is for key exchange, not signatures".into()
            )),
        }
    }

    fn verify_rsa(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &Signature,
    ) -> Result<()> {
        use rsa::{RsaPublicKey, pkcs1v15::VerifyingKey, signature::Verifier as RsaVerifier};
        use rsa::pkcs8::DecodePublicKey;
        use sha2::Sha256;

        // Decode the public key from DER format
        let public_key = RsaPublicKey::from_public_key_der(public_key)
            .map_err(|e| Error::invalid_key(format!("Failed to decode RSA public key: {}", e)))?;

        let verifying_key = VerifyingKey::<Sha256>::new_unprefixed(public_key);

        // Convert signature bytes to rsa::Signature
        let sig = rsa::pkcs1v15::Signature::try_from(signature.as_bytes())
            .map_err(|e| Error::InvalidSignature(format!("Invalid RSA signature format: {}", e)))?;

        // Verify the signature
        verifying_key
            .verify(message, &sig)
            .map_err(|e| Error::InvalidSignature(format!("RSA signature verification failed: {}", e)))?;

        Ok(())
    }

    fn verify_ecdsa_p256(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &Signature,
    ) -> Result<()> {
        use p256::ecdsa::{VerifyingKey, signature::Verifier as EcdsaVerifier};
        use p256::pkcs8::DecodePublicKey;

        // Decode the public key from DER format
        let verifying_key = VerifyingKey::from_public_key_der(public_key)
            .map_err(|e| Error::invalid_key(format!("Failed to decode ECDSA P-256 public key: {}", e)))?;

        // Parse the signature
        let sig = ecdsa::Signature::<p256::NistP256>::try_from(signature.as_bytes())
            .map_err(|e| Error::InvalidSignature(format!("Invalid ECDSA P-256 signature format: {}", e)))?;

        // Verify the signature
        verifying_key
            .verify(message, &sig)
            .map_err(|e| Error::InvalidSignature(format!("ECDSA P-256 signature verification failed: {}", e)))?;

        Ok(())
    }

    fn verify_ecdsa_p384(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &Signature,
    ) -> Result<()> {
        use p384::ecdsa::{VerifyingKey, signature::Verifier as EcdsaVerifier};
        use p384::pkcs8::DecodePublicKey;

        // Decode the public key from DER format
        let verifying_key = VerifyingKey::from_public_key_der(public_key)
            .map_err(|e| Error::invalid_key(format!("Failed to decode ECDSA P-384 public key: {}", e)))?;

        // Parse the signature
        let sig = ecdsa::Signature::<p384::NistP384>::try_from(signature.as_bytes())
            .map_err(|e| Error::InvalidSignature(format!("Invalid ECDSA P-384 signature format: {}", e)))?;

        // Verify the signature
        verifying_key
            .verify(message, &sig)
            .map_err(|e| Error::InvalidSignature(format!("ECDSA P-384 signature verification failed: {}", e)))?;

        Ok(())
    }

    fn verify_post_quantum(
        &self,
        pq: crate::algorithms::PostQuantumAlgorithm,
        public_key: &[u8],
        message: &[u8],
        signature: &Signature,
    ) -> Result<()> {
        use crate::algorithms::PostQuantumAlgorithm;

        match pq {
            PostQuantumAlgorithm::Dilithium2 => {
                self.verify_dilithium2(public_key, message, signature)
            }
            PostQuantumAlgorithm::Dilithium3 => {
                self.verify_dilithium3(public_key, message, signature)
            }
            PostQuantumAlgorithm::Dilithium5 => {
                self.verify_dilithium5(public_key, message, signature)
            }
            _ => Err(Error::UnsupportedAlgorithm(format!(
                "Post-quantum algorithm {} not yet fully implemented",
                signature.algorithm()
            ))),
        }
    }

    fn verify_dilithium2(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &Signature,
    ) -> Result<()> {
        use pqcrypto_dilithium::dilithium2;
        use pqcrypto_traits::sign::{PublicKey, DetachedSignature};

        let public_key = dilithium2::PublicKey::from_bytes(public_key)
            .map_err(|e| Error::invalid_key(format!("Invalid Dilithium2 public key: {:?}", e)))?;

        let sig = dilithium2::DetachedSignature::from_bytes(signature.as_bytes())
            .map_err(|e| Error::InvalidSignature(format!("Invalid Dilithium2 signature: {:?}", e)))?;

        dilithium2::verify_detached_signature(&sig, message, &public_key)
            .map_err(|e| Error::InvalidSignature(format!("Dilithium2 verification failed: {:?}", e)))?;

        Ok(())
    }

    fn verify_dilithium3(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &Signature,
    ) -> Result<()> {
        use pqcrypto_dilithium::dilithium3;
        use pqcrypto_traits::sign::{PublicKey, DetachedSignature};

        let public_key = dilithium3::PublicKey::from_bytes(public_key)
            .map_err(|e| Error::invalid_key(format!("Invalid Dilithium3 public key: {:?}", e)))?;

        let sig = dilithium3::DetachedSignature::from_bytes(signature.as_bytes())
            .map_err(|e| Error::InvalidSignature(format!("Invalid Dilithium3 signature: {:?}", e)))?;

        dilithium3::verify_detached_signature(&sig, message, &public_key)
            .map_err(|e| Error::InvalidSignature(format!("Dilithium3 verification failed: {:?}", e)))?;

        Ok(())
    }

    fn verify_dilithium5(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &Signature,
    ) -> Result<()> {
        use pqcrypto_dilithium::dilithium5;
        use pqcrypto_traits::sign::{PublicKey, DetachedSignature};

        let public_key = dilithium5::PublicKey::from_bytes(public_key)
            .map_err(|e| Error::invalid_key(format!("Invalid Dilithium5 public key: {:?}", e)))?;

        let sig = dilithium5::DetachedSignature::from_bytes(signature.as_bytes())
            .map_err(|e| Error::InvalidSignature(format!("Invalid Dilithium5 signature: {:?}", e)))?;

        dilithium5::verify_detached_signature(&sig, message, &public_key)
            .map_err(|e| Error::InvalidSignature(format!("Dilithium5 verification failed: {:?}", e)))?;

        Ok(())
    }
}

impl Default for Verifier {
    fn default() -> Self {
        Self {
            policy: CryptoPolicy::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keypair::KeyPairGenerator;
    use crate::policy::{PolicyBuilder, CryptoMode, CryptoPolicy};

    #[test]
    fn test_ed25519_sign_and_verify() {
        // Setup
        let policy = PolicyBuilder::classical_only();
        let generator = KeyPairGenerator::new(policy.clone());
        let algorithm = AlgorithmType::Classical(ClassicalAlgorithm::Ed25519);

        // Generate a key pair
        let keypair = generator.generate(algorithm).unwrap();

        // Sign a message
        let signer = Signer::new(policy.clone());
        let message = b"Hello, CryptoShift!";
        let signature = signer.sign(&keypair, message).unwrap();

        // Verify the signature
        let verifier = Verifier::new(policy);
        assert!(verifier
            .verify(keypair.public_key(), message, &signature)
            .is_ok());

        // Verify with wrong message should fail
        let wrong_message = b"Wrong message";
        assert!(verifier
            .verify(keypair.public_key(), wrong_message, &signature)
            .is_err());
    }

    #[test]
    fn test_signature_properties() {
        let policy = PolicyBuilder::classical_only();
        let generator = KeyPairGenerator::new(policy.clone());
        let algorithm = AlgorithmType::Classical(ClassicalAlgorithm::Ed25519);

        let keypair = generator.generate(algorithm).unwrap();
        let signer = Signer::new(policy);
        let message = b"Test message";
        let signature = signer.sign(&keypair, message).unwrap();

        assert_eq!(signature.algorithm(), algorithm);
        assert_eq!(signature.len(), 64); // Ed25519 signatures are 64 bytes
        assert!(!signature.is_empty());
    }

    #[test]
    fn test_invalid_signature() {
        let policy = PolicyBuilder::classical_only();
        let generator = KeyPairGenerator::new(policy.clone());
        let algorithm = AlgorithmType::Classical(ClassicalAlgorithm::Ed25519);

        let keypair = generator.generate(algorithm).unwrap();
        let message = b"Test message";

        // Create an invalid signature
        let invalid_sig = Signature::new(algorithm, vec![0u8; 64]);

        let verifier = Verifier::new(policy);
        assert!(verifier
            .verify(keypair.public_key(), message, &invalid_sig)
            .is_err());
    }

    #[test]
    fn test_policy_enforcement() {
        let policy = PolicyBuilder::classical_only();
        let generator = KeyPairGenerator::new(policy.clone());
        let algorithm = AlgorithmType::Classical(ClassicalAlgorithm::Ed25519);

        let keypair = generator.generate(algorithm).unwrap();
        let signer = Signer::new(policy);
        let message = b"Test message";

        // Should succeed with valid policy
        assert!(signer.sign(&keypair, message).is_ok());
    }

    #[test]
    fn test_rsa2048_sign_and_verify() {
        // RSA-2048 has 112-bit security, so we need to lower the minimum
        let policy = CryptoPolicy::new("rsa-test")
            .set_mode(CryptoMode::Classical)
            .set_min_security_level(112);
        let generator = KeyPairGenerator::new(policy.clone());
        let algorithm = AlgorithmType::Classical(ClassicalAlgorithm::RSA2048);

        // Generate RSA key pair
        let keypair = generator.generate(algorithm).unwrap();
        assert_eq!(keypair.algorithm(), algorithm);

        // Sign a message
        let signer = Signer::new(policy.clone());
        let message = b"RSA test message";
        let signature = signer.sign(&keypair, message).unwrap();

        // Verify the signature
        let verifier = Verifier::new(policy);
        assert!(verifier
            .verify(keypair.public_key(), message, &signature)
            .is_ok());

        // Verify with wrong message should fail
        let wrong_message = b"Wrong RSA message";
        assert!(verifier
            .verify(keypair.public_key(), wrong_message, &signature)
            .is_err());
    }

    #[test]
    fn test_rsa4096_sign_and_verify() {
        let policy = PolicyBuilder::classical_only();
        let generator = KeyPairGenerator::new(policy.clone());
        let algorithm = AlgorithmType::Classical(ClassicalAlgorithm::RSA4096);

        // Generate RSA key pair
        let keypair = generator.generate(algorithm).unwrap();

        // Sign and verify
        let signer = Signer::new(policy.clone());
        let message = b"RSA-4096 test";
        let signature = signer.sign(&keypair, message).unwrap();

        let verifier = Verifier::new(policy);
        assert!(verifier
            .verify(keypair.public_key(), message, &signature)
            .is_ok());
    }

    #[test]
    fn test_ecdsa_p256_sign_and_verify() {
        let policy = PolicyBuilder::classical_only();
        let generator = KeyPairGenerator::new(policy.clone());
        let algorithm = AlgorithmType::Classical(ClassicalAlgorithm::EcdsaP256);

        // Generate ECDSA P-256 key pair
        let keypair = generator.generate(algorithm).unwrap();
        assert_eq!(keypair.algorithm(), algorithm);

        // Sign a message
        let signer = Signer::new(policy.clone());
        let message = b"ECDSA P-256 test message";
        let signature = signer.sign(&keypair, message).unwrap();

        // Verify the signature
        let verifier = Verifier::new(policy);
        assert!(verifier
            .verify(keypair.public_key(), message, &signature)
            .is_ok());

        // Verify with wrong message should fail
        let wrong_message = b"Wrong ECDSA message";
        assert!(verifier
            .verify(keypair.public_key(), wrong_message, &signature)
            .is_err());
    }

    #[test]
    fn test_ecdsa_p384_sign_and_verify() {
        let policy = PolicyBuilder::classical_only();
        let generator = KeyPairGenerator::new(policy.clone());
        let algorithm = AlgorithmType::Classical(ClassicalAlgorithm::EcdsaP384);

        // Generate ECDSA P-384 key pair
        let keypair = generator.generate(algorithm).unwrap();

        // Sign and verify
        let signer = Signer::new(policy.clone());
        let message = b"ECDSA P-384 test";
        let signature = signer.sign(&keypair, message).unwrap();

        let verifier = Verifier::new(policy);
        assert!(verifier
            .verify(keypair.public_key(), message, &signature)
            .is_ok());
    }

    #[test]
    fn test_dilithium2_sign_and_verify() {
        let policy = PolicyBuilder::post_quantum_only();
        let generator = KeyPairGenerator::new(policy.clone());
        let algorithm = AlgorithmType::PostQuantum(crate::algorithms::PostQuantumAlgorithm::Dilithium2);

        // Generate Dilithium2 key pair
        let keypair = generator.generate(algorithm).unwrap();
        assert_eq!(keypair.algorithm(), algorithm);

        // Sign a message
        let signer = Signer::new(policy.clone());
        let message = b"Dilithium2 post-quantum test message";
        let signature = signer.sign(&keypair, message).unwrap();

        // Verify the signature
        let verifier = Verifier::new(policy);
        assert!(verifier
            .verify(keypair.public_key(), message, &signature)
            .is_ok());

        // Verify with wrong message should fail
        let wrong_message = b"Wrong PQC message";
        assert!(verifier
            .verify(keypair.public_key(), wrong_message, &signature)
            .is_err());
    }

    #[test]
    fn test_dilithium3_sign_and_verify() {
        let policy = PolicyBuilder::post_quantum_only();
        let generator = KeyPairGenerator::new(policy.clone());
        let algorithm = AlgorithmType::PostQuantum(crate::algorithms::PostQuantumAlgorithm::Dilithium3);

        // Generate Dilithium3 key pair
        let keypair = generator.generate(algorithm).unwrap();

        // Sign and verify
        let signer = Signer::new(policy.clone());
        let message = b"Dilithium3 test";
        let signature = signer.sign(&keypair, message).unwrap();

        let verifier = Verifier::new(policy);
        assert!(verifier
            .verify(keypair.public_key(), message, &signature)
            .is_ok());
    }

    #[test]
    fn test_dilithium5_sign_and_verify() {
        let policy = PolicyBuilder::post_quantum_only();
        let generator = KeyPairGenerator::new(policy.clone());
        let algorithm = AlgorithmType::PostQuantum(crate::algorithms::PostQuantumAlgorithm::Dilithium5);

        // Generate Dilithium5 key pair (highest security)
        let keypair = generator.generate(algorithm).unwrap();

        // Sign and verify
        let signer = Signer::new(policy.clone());
        let message = b"Dilithium5 256-bit security test";
        let signature = signer.sign(&keypair, message).unwrap();

        let verifier = Verifier::new(policy);
        assert!(verifier
            .verify(keypair.public_key(), message, &signature)
            .is_ok());
    }
}

