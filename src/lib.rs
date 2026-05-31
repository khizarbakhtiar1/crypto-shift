//! # CryptoShift
//!
//! A comprehensive crypto-agility SDK for migrating from classical to post-quantum cryptography.
//!
//! ## Overview
//!
//! CryptoShift enables organizations to:
//! - Discover and inventory cryptographic operations in their systems
//! - Gradually migrate from classical to post-quantum cryptography
//! - Support hybrid cryptography (classical + PQC simultaneously)
//! - Manage cryptographic policies centrally
//! - Monitor and audit cryptographic operations
//!
//! ## Module Structure
//!
//! - `policy`: Cryptographic policy management and enforcement
//! - `algorithms`: Core cryptographic algorithm abstractions
//! - `hybrid`: Hybrid cryptography implementations (classical + PQC)
//! - `migration`: Migration orchestration and state management
//! - `keypair`: Unified key pair management
//! - `signature`: Digital signature operations
//! - `encryption`: Encryption/decryption operations
//! - `error`: Error types and handling

#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod algorithms;
pub mod encryption;
pub mod error;
pub mod hybrid;
pub mod inventory;
pub mod keypair;
pub mod migration;
pub mod policy;
pub mod signature;

// Re-export commonly used types
pub use algorithms::{AlgorithmCategory, AlgorithmType, ClassicalAlgorithm, PostQuantumAlgorithm};
pub use encryption::{Decryptor, EncryptedMessage, Encryptor};
pub use error::{Error, Result};
pub use hybrid::{
    HybridKeyPair, HybridKeyPairGenerator, HybridSignature, HybridSigner, HybridVerifier,
    VerificationStrategy,
};
pub use inventory::{CryptoInventory, Finding, InventoryReport, RiskLevel};
pub use keypair::{KeyPair, KeyPairGenerator};
pub use migration::{MigrationOrchestrator, MigrationPlan, MigrationStats};
pub use policy::{CryptoMode, CryptoPolicy, MigrationStage, PolicyBuilder};
pub use signature::{Signature, Signer, Verifier};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::const_is_empty)]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }
}
