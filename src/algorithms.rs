//! Cryptographic algorithm abstractions and types

use serde::{Deserialize, Serialize};
use std::fmt;

/// Represents a cryptographic algorithm type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AlgorithmType {
    /// Classical algorithms (pre-quantum)
    Classical(ClassicalAlgorithm),
    /// Post-quantum algorithms
    PostQuantum(PostQuantumAlgorithm),
}

/// Classical cryptographic algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ClassicalAlgorithm {
    /// RSA with various key sizes
    RSA2048,
    /// RSA 3072-bit
    RSA3072,
    /// RSA 4096-bit
    RSA4096,
    /// Elliptic Curve Digital Signature Algorithm
    EcdsaP256,
    /// ECDSA with P-384 curve
    EcdsaP384,
    /// Ed25519 signature scheme
    Ed25519,
    /// X25519 key exchange
    X25519,
}

/// Post-quantum cryptographic algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PostQuantumAlgorithm {
    /// Kyber512 - NIST Level 1
    Kyber512,
    /// Kyber768 - NIST Level 3
    Kyber768,
    /// Kyber1024 - NIST Level 5
    Kyber1024,
    /// Dilithium2 - NIST Level 2
    Dilithium2,
    /// Dilithium3 - NIST Level 3
    Dilithium3,
    /// Dilithium5 - NIST Level 5
    Dilithium5,
    /// FALCON-512
    Falcon512,
    /// FALCON-1024
    Falcon1024,
}

/// Algorithm category for operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgorithmCategory {
    /// Digital signature algorithms
    Signature,
    /// Key encapsulation mechanisms
    KEM,
    /// Key exchange algorithms
    KeyExchange,
}

impl AlgorithmType {
    /// Check if this is a classical algorithm
    pub fn is_classical(&self) -> bool {
        matches!(self, AlgorithmType::Classical(_))
    }

    /// Check if this is a post-quantum algorithm
    pub fn is_post_quantum(&self) -> bool {
        matches!(self, AlgorithmType::PostQuantum(_))
    }

    /// Get the security level in bits (approximate)
    pub fn security_level(&self) -> u16 {
        match self {
            AlgorithmType::Classical(algo) => match algo {
                ClassicalAlgorithm::RSA2048 => 112,
                ClassicalAlgorithm::RSA3072 => 128,
                ClassicalAlgorithm::RSA4096 => 152,
                ClassicalAlgorithm::EcdsaP256 | ClassicalAlgorithm::Ed25519 => 128,
                ClassicalAlgorithm::EcdsaP384 => 192,
                ClassicalAlgorithm::X25519 => 128,
            },
            AlgorithmType::PostQuantum(algo) => match algo {
                PostQuantumAlgorithm::Kyber512 | PostQuantumAlgorithm::Dilithium2 => 128,
                PostQuantumAlgorithm::Kyber768
                | PostQuantumAlgorithm::Dilithium3
                | PostQuantumAlgorithm::Falcon512 => 192,
                PostQuantumAlgorithm::Kyber1024
                | PostQuantumAlgorithm::Dilithium5
                | PostQuantumAlgorithm::Falcon1024 => 256,
            },
        }
    }

    /// Get the algorithm category
    pub fn category(&self) -> AlgorithmCategory {
        match self {
            AlgorithmType::Classical(algo) => match algo {
                ClassicalAlgorithm::Ed25519
                | ClassicalAlgorithm::EcdsaP256
                | ClassicalAlgorithm::EcdsaP384
                | ClassicalAlgorithm::RSA2048
                | ClassicalAlgorithm::RSA3072
                | ClassicalAlgorithm::RSA4096 => AlgorithmCategory::Signature,
                ClassicalAlgorithm::X25519 => AlgorithmCategory::KeyExchange,
            },
            AlgorithmType::PostQuantum(algo) => match algo {
                PostQuantumAlgorithm::Dilithium2
                | PostQuantumAlgorithm::Dilithium3
                | PostQuantumAlgorithm::Dilithium5
                | PostQuantumAlgorithm::Falcon512
                | PostQuantumAlgorithm::Falcon1024 => AlgorithmCategory::Signature,
                PostQuantumAlgorithm::Kyber512
                | PostQuantumAlgorithm::Kyber768
                | PostQuantumAlgorithm::Kyber1024 => AlgorithmCategory::KEM,
            },
        }
    }

    /// Get algorithm name as string
    pub fn name(&self) -> &'static str {
        match self {
            AlgorithmType::Classical(algo) => match algo {
                ClassicalAlgorithm::RSA2048 => "RSA-2048",
                ClassicalAlgorithm::RSA3072 => "RSA-3072",
                ClassicalAlgorithm::RSA4096 => "RSA-4096",
                ClassicalAlgorithm::EcdsaP256 => "ECDSA-P256",
                ClassicalAlgorithm::EcdsaP384 => "ECDSA-P384",
                ClassicalAlgorithm::Ed25519 => "Ed25519",
                ClassicalAlgorithm::X25519 => "X25519",
            },
            AlgorithmType::PostQuantum(algo) => match algo {
                PostQuantumAlgorithm::Kyber512 => "Kyber-512",
                PostQuantumAlgorithm::Kyber768 => "Kyber-768",
                PostQuantumAlgorithm::Kyber1024 => "Kyber-1024",
                PostQuantumAlgorithm::Dilithium2 => "Dilithium-2",
                PostQuantumAlgorithm::Dilithium3 => "Dilithium-3",
                PostQuantumAlgorithm::Dilithium5 => "Dilithium-5",
                PostQuantumAlgorithm::Falcon512 => "FALCON-512",
                PostQuantumAlgorithm::Falcon1024 => "FALCON-1024",
            },
        }
    }
}

impl fmt::Display for AlgorithmType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_classification() {
        let ed25519 = AlgorithmType::Classical(ClassicalAlgorithm::Ed25519);
        assert!(ed25519.is_classical());
        assert!(!ed25519.is_post_quantum());

        let dilithium = AlgorithmType::PostQuantum(PostQuantumAlgorithm::Dilithium3);
        assert!(dilithium.is_post_quantum());
        assert!(!dilithium.is_classical());
    }

    #[test]
    fn test_security_levels() {
        let ed25519 = AlgorithmType::Classical(ClassicalAlgorithm::Ed25519);
        assert_eq!(ed25519.security_level(), 128);

        let dilithium5 = AlgorithmType::PostQuantum(PostQuantumAlgorithm::Dilithium5);
        assert_eq!(dilithium5.security_level(), 256);
    }

    #[test]
    fn test_algorithm_category() {
        let ed25519 = AlgorithmType::Classical(ClassicalAlgorithm::Ed25519);
        assert_eq!(ed25519.category(), AlgorithmCategory::Signature);

        let kyber = AlgorithmType::PostQuantum(PostQuantumAlgorithm::Kyber768);
        assert_eq!(kyber.category(), AlgorithmCategory::KEM);
    }

    #[test]
    fn test_algorithm_names() {
        let ed25519 = AlgorithmType::Classical(ClassicalAlgorithm::Ed25519);
        assert_eq!(ed25519.name(), "Ed25519");
        assert_eq!(ed25519.to_string(), "Ed25519");
    }
}

