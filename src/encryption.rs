//! Encryption and decryption using a KEM-DEM hybrid scheme.
//!
//! CryptoShift uses the standard Key Encapsulation Mechanism / Data
//! Encapsulation Mechanism (KEM-DEM) construction:
//!
//! 1. A KEM (Kyber for post-quantum, or X25519 ECDH for classical) is used to
//!    establish a fresh shared secret between sender and recipient.
//! 2. The shared secret is expanded with HKDF-SHA256 into a symmetric key.
//! 3. The actual payload is sealed with AES-256-GCM (authenticated encryption).
//!
//! This means the public-key part only ever protects a small symmetric key,
//! while the bulk data is encrypted with fast, constant-overhead AEAD. The same
//! interface works for both classical and post-quantum algorithms, which is the
//! whole point of crypto-agility.

use crate::algorithms::{AlgorithmCategory, AlgorithmType, PostQuantumAlgorithm};
use crate::error::{Error, Result};
use crate::keypair::KeyPair;
use crate::policy::CryptoPolicy;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use serde::{Deserialize, Serialize};

/// Domain-separation string mixed into the HKDF expansion.
const HKDF_INFO: &[u8] = b"cryptoshift-kem-dem-v1";
/// Size of the derived AES-256 key, in bytes.
const AES_KEY_LEN: usize = 32;
/// Size of the AES-GCM nonce, in bytes.
const NONCE_LEN: usize = 12;

/// An encrypted message produced by [`Encryptor`].
///
/// It carries everything the recipient needs to decrypt, except their own
/// private key: the KEM encapsulation, the AEAD nonce and the sealed ciphertext.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedMessage {
    /// Algorithm used for the key-encapsulation step.
    algorithm: AlgorithmType,
    /// KEM ciphertext (Kyber) or ephemeral public key (X25519).
    encapsulated_key: Vec<u8>,
    /// AES-GCM nonce.
    nonce: Vec<u8>,
    /// AES-GCM ciphertext (includes the authentication tag).
    ciphertext: Vec<u8>,
}

impl EncryptedMessage {
    /// Algorithm used for the key-encapsulation step.
    pub fn algorithm(&self) -> AlgorithmType {
        self.algorithm
    }

    /// The KEM encapsulation bytes.
    pub fn encapsulated_key(&self) -> &[u8] {
        &self.encapsulated_key
    }

    /// The AEAD ciphertext bytes (including the tag).
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Total on-the-wire size of this message in bytes.
    pub fn total_size(&self) -> usize {
        self.encapsulated_key.len() + self.nonce.len() + self.ciphertext.len()
    }

    /// Serialize the message for storage or transmission.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| Error::SerializationError(format!("Failed to serialize message: {}", e)))
    }

    /// Deserialize a message produced by [`EncryptedMessage::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes)
            .map_err(|e| Error::SerializationError(format!("Failed to deserialize message: {}", e)))
    }
}

/// Encrypts data to a recipient's public key using a KEM-DEM scheme.
#[derive(Default)]
pub struct Encryptor {
    policy: CryptoPolicy,
}

impl Encryptor {
    /// Create a new encryptor bound to a policy.
    pub fn new(policy: CryptoPolicy) -> Self {
        Self { policy }
    }

    /// Encrypt `plaintext` for the holder of `recipient_public_key`.
    ///
    /// `algorithm` selects the KEM used to protect the symmetric key and must be
    /// a key-encapsulation or key-exchange algorithm (Kyber or X25519).
    pub fn encrypt(
        &self,
        algorithm: AlgorithmType,
        recipient_public_key: &[u8],
        plaintext: &[u8],
    ) -> Result<EncryptedMessage> {
        self.policy.validate_algorithm(&algorithm)?;
        ensure_kem_algorithm(algorithm)?;

        // Step 1: KEM — establish a fresh shared secret.
        let (shared_secret, encapsulated_key) = match algorithm {
            AlgorithmType::PostQuantum(pq) => encapsulate_kyber(pq, recipient_public_key)?,
            AlgorithmType::Classical(_) => encapsulate_x25519(recipient_public_key)?,
        };

        // Step 2: derive a symmetric key from the shared secret.
        let key = derive_key(&shared_secret)?;

        // Step 3: DEM — seal the payload with AES-256-GCM.
        let (nonce, ciphertext) = aead_seal(&key, plaintext)?;

        Ok(EncryptedMessage {
            algorithm,
            encapsulated_key,
            nonce,
            ciphertext,
        })
    }
}

/// Decrypts messages addressed to a key pair we control.
#[derive(Default)]
pub struct Decryptor {
    policy: CryptoPolicy,
}

impl Decryptor {
    /// Create a new decryptor bound to a policy.
    pub fn new(policy: CryptoPolicy) -> Self {
        Self { policy }
    }

    /// Decrypt `message` using our private `keypair`.
    pub fn decrypt(&self, keypair: &KeyPair, message: &EncryptedMessage) -> Result<Vec<u8>> {
        self.policy.validate_algorithm(&message.algorithm)?;
        ensure_kem_algorithm(message.algorithm)?;

        if keypair.algorithm() != message.algorithm {
            return Err(Error::crypto(format!(
                "Key pair algorithm {} does not match message algorithm {}",
                keypair.algorithm(),
                message.algorithm
            )));
        }

        // Step 1: KEM — recover the shared secret.
        let shared_secret = match message.algorithm {
            AlgorithmType::PostQuantum(pq) => {
                decapsulate_kyber(pq, keypair.private_key().as_bytes(), &message.encapsulated_key)?
            }
            AlgorithmType::Classical(_) => {
                decapsulate_x25519(keypair.private_key().as_bytes(), &message.encapsulated_key)?
            }
        };

        // Step 2: re-derive the symmetric key.
        let key = derive_key(&shared_secret)?;

        // Step 3: open the AEAD ciphertext.
        aead_open(&key, &message.nonce, &message.ciphertext)
    }
}

fn ensure_kem_algorithm(algorithm: AlgorithmType) -> Result<()> {
    match algorithm.category() {
        AlgorithmCategory::KEM | AlgorithmCategory::KeyExchange => Ok(()),
        AlgorithmCategory::Signature => Err(Error::UnsupportedAlgorithm(format!(
            "{} is a signature algorithm and cannot be used for encryption",
            algorithm
        ))),
    }
}

fn encapsulate_kyber(
    pq: PostQuantumAlgorithm,
    recipient_public_key: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SharedSecret as _};

    macro_rules! kyber_encap {
        ($module:ident) => {{
            use pqcrypto_kyber::$module;
            let pk = $module::PublicKey::from_bytes(recipient_public_key).map_err(|e| {
                Error::invalid_key(format!("Invalid {} public key: {:?}", stringify!($module), e))
            })?;
            let (shared, ct) = $module::encapsulate(&pk);
            (shared.as_bytes().to_vec(), ct.as_bytes().to_vec())
        }};
    }

    let result = match pq {
        PostQuantumAlgorithm::Kyber512 => kyber_encap!(kyber512),
        PostQuantumAlgorithm::Kyber768 => kyber_encap!(kyber768),
        PostQuantumAlgorithm::Kyber1024 => kyber_encap!(kyber1024),
        _ => {
            return Err(Error::UnsupportedAlgorithm(format!(
                "{:?} is not a KEM algorithm",
                pq
            )))
        }
    };
    Ok(result)
}

fn decapsulate_kyber(
    pq: PostQuantumAlgorithm,
    secret_key: &[u8],
    encapsulated_key: &[u8],
) -> Result<Vec<u8>> {
    use pqcrypto_traits::kem::{Ciphertext as _, SecretKey as _, SharedSecret as _};

    macro_rules! kyber_decap {
        ($module:ident) => {{
            use pqcrypto_kyber::$module;
            let sk = $module::SecretKey::from_bytes(secret_key).map_err(|e| {
                Error::invalid_key(format!("Invalid {} secret key: {:?}", stringify!($module), e))
            })?;
            let ct = $module::Ciphertext::from_bytes(encapsulated_key).map_err(|e| {
                Error::crypto(format!("Invalid {} ciphertext: {:?}", stringify!($module), e))
            })?;
            let shared = $module::decapsulate(&ct, &sk);
            shared.as_bytes().to_vec()
        }};
    }

    let shared = match pq {
        PostQuantumAlgorithm::Kyber512 => kyber_decap!(kyber512),
        PostQuantumAlgorithm::Kyber768 => kyber_decap!(kyber768),
        PostQuantumAlgorithm::Kyber1024 => kyber_decap!(kyber1024),
        _ => {
            return Err(Error::UnsupportedAlgorithm(format!(
                "{:?} is not a KEM algorithm",
                pq
            )))
        }
    };
    Ok(shared)
}

fn encapsulate_x25519(recipient_public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    use rand::rngs::OsRng;
    use x25519_dalek::{EphemeralSecret, PublicKey};

    let pk_bytes: [u8; 32] = recipient_public_key.try_into().map_err(|_| {
        Error::invalid_key(format!(
            "Invalid X25519 public key length: expected 32, got {}",
            recipient_public_key.len()
        ))
    })?;
    let recipient_pub = PublicKey::from(pk_bytes);

    // Ephemeral-static ECDH: the ephemeral public key is the "encapsulation".
    let eph_secret = EphemeralSecret::random_from_rng(OsRng);
    let eph_public = PublicKey::from(&eph_secret);
    let shared = eph_secret.diffie_hellman(&recipient_pub);

    Ok((shared.as_bytes().to_vec(), eph_public.to_bytes().to_vec()))
}

fn decapsulate_x25519(secret_key: &[u8], encapsulated_key: &[u8]) -> Result<Vec<u8>> {
    use x25519_dalek::{PublicKey, StaticSecret};

    let sk_bytes: [u8; 32] = secret_key.try_into().map_err(|_| {
        Error::invalid_key(format!(
            "Invalid X25519 secret key length: expected 32, got {}",
            secret_key.len()
        ))
    })?;
    let eph_bytes: [u8; 32] = encapsulated_key.try_into().map_err(|_| {
        Error::crypto(format!(
            "Invalid X25519 ephemeral key length: expected 32, got {}",
            encapsulated_key.len()
        ))
    })?;

    let secret = StaticSecret::from(sk_bytes);
    let eph_public = PublicKey::from(eph_bytes);
    let shared = secret.diffie_hellman(&eph_public);

    Ok(shared.as_bytes().to_vec())
}

fn derive_key(shared_secret: &[u8]) -> Result<[u8; AES_KEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key = [0u8; AES_KEY_LEN];
    hk.expand(HKDF_INFO, &mut key)
        .map_err(|e| Error::crypto(format!("HKDF key derivation failed: {}", e)))?;
    Ok(key)
}

fn aead_seal(key: &[u8; AES_KEY_LEN], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    use rand::rngs::OsRng;
    use rand::RngCore;

    let cipher = Aes256Gcm::new(key.into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| Error::crypto(format!("AES-GCM encryption failed: {}", e)))?;

    Ok((nonce_bytes.to_vec(), ciphertext))
}

fn aead_open(key: &[u8; AES_KEY_LEN], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let nonce_bytes: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| {
        Error::crypto(format!(
            "Invalid nonce length: expected {}, got {}",
            NONCE_LEN,
            nonce.len()
        ))
    })?;
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from(nonce_bytes);
    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| Error::InvalidSignature("AES-GCM authentication failed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithms::ClassicalAlgorithm;
    use crate::keypair::KeyPairGenerator;
    use crate::policy::{CryptoMode, CryptoPolicy};

    fn kem_policy() -> CryptoPolicy {
        // Hybrid mode allows both X25519 and Kyber; X25519 is only 128-bit.
        CryptoPolicy::new("kem-test")
            .set_mode(CryptoMode::Hybrid)
            .set_min_security_level(128)
    }

    fn roundtrip(algorithm: AlgorithmType) {
        let policy = kem_policy();
        let generator = KeyPairGenerator::new(policy.clone());
        let keypair = generator.generate(algorithm).unwrap();

        let plaintext = b"Attack at dawn -- but only with authenticated, agile crypto.";

        let encryptor = Encryptor::new(policy.clone());
        let message = encryptor
            .encrypt(algorithm, keypair.public_key(), plaintext)
            .unwrap();

        let decryptor = Decryptor::new(policy);
        let recovered = decryptor.decrypt(&keypair, &message).unwrap();

        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_kyber768_roundtrip() {
        roundtrip(AlgorithmType::PostQuantum(PostQuantumAlgorithm::Kyber768));
    }

    #[test]
    fn test_kyber512_roundtrip() {
        roundtrip(AlgorithmType::PostQuantum(PostQuantumAlgorithm::Kyber512));
    }

    #[test]
    fn test_kyber1024_roundtrip() {
        roundtrip(AlgorithmType::PostQuantum(PostQuantumAlgorithm::Kyber1024));
    }

    #[test]
    fn test_x25519_roundtrip() {
        roundtrip(AlgorithmType::Classical(ClassicalAlgorithm::X25519));
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let algorithm = AlgorithmType::PostQuantum(PostQuantumAlgorithm::Kyber768);
        let policy = kem_policy();
        let generator = KeyPairGenerator::new(policy.clone());
        let keypair = generator.generate(algorithm).unwrap();

        let encryptor = Encryptor::new(policy.clone());
        let mut message = encryptor
            .encrypt(algorithm, keypair.public_key(), b"secret payload")
            .unwrap();

        // Flip a bit in the ciphertext; AEAD must reject it.
        message.ciphertext[0] ^= 0x01;

        let decryptor = Decryptor::new(policy);
        assert!(decryptor.decrypt(&keypair, &message).is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let algorithm = AlgorithmType::PostQuantum(PostQuantumAlgorithm::Kyber768);
        let policy = kem_policy();
        let generator = KeyPairGenerator::new(policy.clone());
        let keypair = generator.generate(algorithm).unwrap();
        let other = generator.generate(algorithm).unwrap();

        let encryptor = Encryptor::new(policy.clone());
        let message = encryptor
            .encrypt(algorithm, keypair.public_key(), b"secret payload")
            .unwrap();

        let decryptor = Decryptor::new(policy);
        assert!(decryptor.decrypt(&other, &message).is_err());
    }

    #[test]
    fn test_message_serialization() {
        let algorithm = AlgorithmType::PostQuantum(PostQuantumAlgorithm::Kyber768);
        let policy = kem_policy();
        let generator = KeyPairGenerator::new(policy.clone());
        let keypair = generator.generate(algorithm).unwrap();

        let encryptor = Encryptor::new(policy.clone());
        let message = encryptor
            .encrypt(algorithm, keypair.public_key(), b"roundtrip via bytes")
            .unwrap();

        let bytes = message.to_bytes().unwrap();
        let restored = EncryptedMessage::from_bytes(&bytes).unwrap();

        let decryptor = Decryptor::new(policy);
        let recovered = decryptor.decrypt(&keypair, &restored).unwrap();
        assert_eq!(recovered, b"roundtrip via bytes");
    }

    #[test]
    fn test_signature_algorithm_rejected() {
        let policy = CryptoPolicy::new("kem-test").set_mode(CryptoMode::Hybrid);
        let encryptor = Encryptor::new(policy);
        let result = encryptor.encrypt(
            AlgorithmType::PostQuantum(PostQuantumAlgorithm::Dilithium3),
            &[0u8; 32],
            b"data",
        );
        assert!(result.is_err());
    }
}
