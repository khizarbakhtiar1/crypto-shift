//! Error types for CryptoShift

use thiserror::Error;

/// Result type alias for CryptoShift operations
pub type Result<T> = std::result::Result<T, Error>;

/// Main error type for CryptoShift
#[derive(Error, Debug)]
pub enum Error {
    /// Cryptographic operation failed
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    /// Invalid key material
    #[error("Invalid key material: {0}")]
    InvalidKey(String),

    /// Invalid signature
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// Policy violation
    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    /// Algorithm not supported
    #[error("Algorithm not supported: {0}")]
    UnsupportedAlgorithm(String),

    /// Migration error
    #[error("Migration error: {0}")]
    MigrationError(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// IO error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Generic error
    #[error("{0}")]
    Other(String),
}

impl Error {
    /// Create a crypto error
    pub fn crypto<S: Into<String>>(msg: S) -> Self {
        Error::CryptoError(msg.into())
    }

    /// Create an invalid key error
    pub fn invalid_key<S: Into<String>>(msg: S) -> Self {
        Error::InvalidKey(msg.into())
    }

    /// Create a policy violation error
    pub fn policy_violation<S: Into<String>>(msg: S) -> Self {
        Error::PolicyViolation(msg.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let err = Error::crypto("test error");
        assert!(matches!(err, Error::CryptoError(_)));
    }

    #[test]
    fn test_error_display() {
        let err = Error::crypto("test");
        assert_eq!(err.to_string(), "Cryptographic operation failed: test");
    }
}

