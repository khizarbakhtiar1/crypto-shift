//! Cryptographic policy management and enforcement
//!
//! This module provides the core policy engine that controls:
//! - Which algorithms are allowed
//! - Migration stages and rollout strategies
//! - Hybrid mode configurations
//! - Security level requirements

use crate::algorithms::AlgorithmType;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Cryptographic operation mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CryptoMode {
    /// Use only classical algorithms
    Classical,
    /// Use only post-quantum algorithms
    PostQuantum,
    /// Use both classical and post-quantum (hybrid mode)
    Hybrid,
}

/// Migration stage configuration
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum MigrationStage {
    /// Not started - using classical only
    NotStarted,
    /// Testing phase - specific percentage of operations use PQC
    Testing(f32),
    /// Gradual rollout - specific percentage of operations use PQC
    Rollout(f32),
    /// Fully migrated to PQC
    Complete,
}

/// Cryptographic policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoPolicy {
    /// Operating mode (Classical, PostQuantum, or Hybrid)
    mode: CryptoMode,
    /// Migration stage
    migration_stage: MigrationStage,
    /// Allowed algorithms
    allowed_algorithms: HashSet<AlgorithmType>,
    /// Minimum security level in bits
    min_security_level: u16,
    /// Whether to enforce strict validation
    strict_validation: bool,
    /// Policy name/identifier
    name: String,
}

impl Default for CryptoPolicy {
    fn default() -> Self {
        Self {
            mode: CryptoMode::Classical,
            migration_stage: MigrationStage::NotStarted,
            allowed_algorithms: HashSet::new(),
            min_security_level: 128,
            strict_validation: true,
            name: "default".to_string(),
        }
    }
}

impl CryptoPolicy {
    /// Create a new policy with a name
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }

    /// Set the cryptographic mode
    pub fn set_mode(mut self, mode: CryptoMode) -> Self {
        self.mode = mode;
        self
    }

    /// Set the migration stage
    pub fn set_migration_stage(mut self, stage: MigrationStage) -> Self {
        self.migration_stage = stage;
        self
    }

    /// Set minimum security level
    pub fn set_min_security_level(mut self, level: u16) -> Self {
        self.min_security_level = level;
        self
    }

    /// Add an allowed algorithm
    pub fn allow_algorithm(mut self, algo: AlgorithmType) -> Self {
        self.allowed_algorithms.insert(algo);
        self
    }

    /// Set strict validation mode
    pub fn set_strict_validation(mut self, strict: bool) -> Self {
        self.strict_validation = strict;
        self
    }

    /// Get the current mode
    pub fn mode(&self) -> CryptoMode {
        self.mode
    }

    /// Get the migration stage
    pub fn migration_stage(&self) -> MigrationStage {
        self.migration_stage
    }

    /// Get minimum security level
    pub fn min_security_level(&self) -> u16 {
        self.min_security_level
    }

    /// Get policy name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Check if an algorithm is allowed by this policy
    pub fn is_algorithm_allowed(&self, algo: &AlgorithmType) -> bool {
        // If no algorithms specified, allow based on mode
        if self.allowed_algorithms.is_empty() {
            return match self.mode {
                CryptoMode::Classical => algo.is_classical(),
                CryptoMode::PostQuantum => algo.is_post_quantum(),
                CryptoMode::Hybrid => true,
            };
        }

        self.allowed_algorithms.contains(algo)
    }

    /// Validate an algorithm against this policy
    pub fn validate_algorithm(&self, algo: &AlgorithmType) -> Result<()> {
        // Check if algorithm is allowed
        if !self.is_algorithm_allowed(algo) {
            return Err(Error::policy_violation(format!(
                "Algorithm {} is not allowed by policy '{}'",
                algo, self.name
            )));
        }

        // Check security level
        if algo.security_level() < self.min_security_level {
            return Err(Error::policy_violation(format!(
                "Algorithm {} security level ({} bits) is below minimum required ({} bits)",
                algo,
                algo.security_level(),
                self.min_security_level
            )));
        }

        // Check mode compatibility
        match self.mode {
            CryptoMode::Classical if !algo.is_classical() => {
                return Err(Error::policy_violation(format!(
                    "Policy '{}' is in Classical mode but algorithm {} is post-quantum",
                    self.name, algo
                )));
            }
            CryptoMode::PostQuantum if !algo.is_post_quantum() => {
                return Err(Error::policy_violation(format!(
                    "Policy '{}' is in PostQuantum mode but algorithm {} is classical",
                    self.name, algo
                )));
            }
            _ => {}
        }

        Ok(())
    }

    /// Check if we should use PQC based on migration stage (for probabilistic rollout)
    pub fn should_use_pqc(&self, sample: f32) -> bool {
        match self.migration_stage {
            MigrationStage::NotStarted => false,
            MigrationStage::Testing(percentage) | MigrationStage::Rollout(percentage) => {
                sample < percentage
            }
            MigrationStage::Complete => true,
        }
    }
}

/// Builder for creating common policy configurations
pub struct PolicyBuilder;

impl PolicyBuilder {
    /// Create a classical-only policy
    pub fn classical_only() -> CryptoPolicy {
        CryptoPolicy::new("classical-only")
            .set_mode(CryptoMode::Classical)
            .set_min_security_level(128)
    }

    /// Create a post-quantum only policy
    pub fn post_quantum_only() -> CryptoPolicy {
        CryptoPolicy::new("post-quantum-only")
            .set_mode(CryptoMode::PostQuantum)
            .set_min_security_level(128)
    }

    /// Create a hybrid policy for gradual migration
    pub fn hybrid_migration(rollout_percentage: f32) -> CryptoPolicy {
        CryptoPolicy::new("hybrid-migration")
            .set_mode(CryptoMode::Hybrid)
            .set_migration_stage(MigrationStage::Rollout(rollout_percentage))
            .set_min_security_level(128)
    }

    /// Create a high-security policy (256-bit minimum)
    pub fn high_security() -> CryptoPolicy {
        CryptoPolicy::new("high-security")
            .set_mode(CryptoMode::Hybrid)
            .set_min_security_level(256)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithms::{ClassicalAlgorithm, PostQuantumAlgorithm};

    #[test]
    fn test_default_policy() {
        let policy = CryptoPolicy::default();
        assert_eq!(policy.mode(), CryptoMode::Classical);
        assert_eq!(policy.min_security_level(), 128);
    }

    #[test]
    fn test_policy_builder() {
        let policy = CryptoPolicy::new("test")
            .set_mode(CryptoMode::Hybrid)
            .set_min_security_level(192);

        assert_eq!(policy.mode(), CryptoMode::Hybrid);
        assert_eq!(policy.min_security_level(), 192);
    }

    #[test]
    fn test_algorithm_validation() {
        let policy = PolicyBuilder::classical_only();
        let ed25519 = AlgorithmType::Classical(ClassicalAlgorithm::Ed25519);
        let dilithium = AlgorithmType::PostQuantum(PostQuantumAlgorithm::Dilithium3);

        assert!(policy.validate_algorithm(&ed25519).is_ok());
        assert!(policy.validate_algorithm(&dilithium).is_err());
    }

    #[test]
    fn test_security_level_validation() {
        let policy = CryptoPolicy::new("high-sec")
            .set_mode(CryptoMode::Hybrid)  // Allow both classical and PQC
            .set_min_security_level(256);
        let ed25519 = AlgorithmType::Classical(ClassicalAlgorithm::Ed25519); // 128-bit
        let dilithium5 = AlgorithmType::PostQuantum(PostQuantumAlgorithm::Dilithium5); // 256-bit

        assert!(policy.validate_algorithm(&ed25519).is_err());
        assert!(policy.validate_algorithm(&dilithium5).is_ok());
    }

    #[test]
    fn test_migration_stage() {
        let policy = CryptoPolicy::new("test")
            .set_migration_stage(MigrationStage::Testing(0.1));

        assert!(policy.should_use_pqc(0.05)); // 5% < 10%
        assert!(!policy.should_use_pqc(0.15)); // 15% > 10%
    }

    #[test]
    fn test_hybrid_policy() {
        let policy = PolicyBuilder::hybrid_migration(0.5);
        let ed25519 = AlgorithmType::Classical(ClassicalAlgorithm::Ed25519);
        let dilithium = AlgorithmType::PostQuantum(PostQuantumAlgorithm::Dilithium3);

        // Both should be allowed in hybrid mode
        assert!(policy.validate_algorithm(&ed25519).is_ok());
        assert!(policy.validate_algorithm(&dilithium).is_ok());
    }
}

