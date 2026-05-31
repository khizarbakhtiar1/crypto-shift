//! Migration orchestration: driving a system from classical to post-quantum
//! cryptography in controlled, observable stages.
//!
//! A [`MigrationPlan`] describes *what* to migrate between (a classical and a
//! post-quantum algorithm) and *how* (an ordered list of [`MigrationStage`]s,
//! e.g. test on 5% of traffic, then 25%, then 100%).
//!
//! A [`MigrationOrchestrator`] executes a plan: it tracks the current stage,
//! decides which algorithm each operation should use so that the configured
//! rollout percentage is honored, advances through the stages, and records
//! statistics for observability.

use crate::algorithms::{AlgorithmType, ClassicalAlgorithm, PostQuantumAlgorithm};
use crate::error::{Error, Result};
use crate::policy::{CryptoMode, CryptoPolicy, MigrationStage};

/// Describes a migration between a classical and a post-quantum algorithm.
#[derive(Debug, Clone)]
pub struct MigrationPlan {
    name: String,
    classical_algorithm: ClassicalAlgorithm,
    pqc_algorithm: PostQuantumAlgorithm,
    stages: Vec<MigrationStage>,
}

impl MigrationPlan {
    /// Create a plan with explicit algorithms and stages.
    pub fn new(
        name: impl Into<String>,
        classical_algorithm: ClassicalAlgorithm,
        pqc_algorithm: PostQuantumAlgorithm,
        stages: Vec<MigrationStage>,
    ) -> Self {
        Self {
            name: name.into(),
            classical_algorithm,
            pqc_algorithm,
            stages,
        }
    }

    /// A sensible default plan: Ed25519 -> Dilithium3 over a 6-step rollout.
    pub fn default_signature_plan(name: impl Into<String>) -> Self {
        Self::new(
            name,
            ClassicalAlgorithm::Ed25519,
            PostQuantumAlgorithm::Dilithium3,
            vec![
                MigrationStage::NotStarted,
                MigrationStage::Testing(0.05),
                MigrationStage::Rollout(0.25),
                MigrationStage::Rollout(0.50),
                MigrationStage::Rollout(0.90),
                MigrationStage::Complete,
            ],
        )
    }

    /// Plan name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Classical algorithm being migrated away from.
    pub fn classical_algorithm(&self) -> ClassicalAlgorithm {
        self.classical_algorithm
    }

    /// Post-quantum algorithm being migrated to.
    pub fn pqc_algorithm(&self) -> PostQuantumAlgorithm {
        self.pqc_algorithm
    }

    /// The ordered stages of this plan.
    pub fn stages(&self) -> &[MigrationStage] {
        &self.stages
    }

    /// Number of stages in the plan.
    pub fn len(&self) -> usize {
        self.stages.len()
    }

    /// Whether the plan has no stages.
    pub fn is_empty(&self) -> bool {
        self.stages.is_empty()
    }
}

/// Counters describing how operations have been split during a migration.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MigrationStats {
    /// Operations performed with the classical algorithm.
    pub classical_ops: u64,
    /// Operations performed with the post-quantum algorithm.
    pub pqc_ops: u64,
}

impl MigrationStats {
    /// Total operations recorded.
    pub fn total(&self) -> u64 {
        self.classical_ops + self.pqc_ops
    }

    /// Fraction of operations that used the post-quantum algorithm (0.0..=1.0).
    pub fn pqc_ratio(&self) -> f32 {
        let total = self.total();
        if total == 0 {
            0.0
        } else {
            self.pqc_ops as f32 / total as f32
        }
    }
}

/// Executes a [`MigrationPlan`], tracking state and statistics.
pub struct MigrationOrchestrator {
    plan: MigrationPlan,
    current: usize,
    op_counter: u64,
    stats: MigrationStats,
}

impl MigrationOrchestrator {
    /// Start orchestrating the given plan at its first stage.
    pub fn new(plan: MigrationPlan) -> Result<Self> {
        if plan.is_empty() {
            return Err(Error::MigrationError(
                "Migration plan must contain at least one stage".into(),
            ));
        }
        Ok(Self {
            plan,
            current: 0,
            op_counter: 0,
            stats: MigrationStats::default(),
        })
    }

    /// Convenience constructor using [`MigrationPlan::default_signature_plan`].
    pub fn with_default_plan(name: impl Into<String>) -> Self {
        // The default plan is always non-empty, so this cannot fail.
        Self::new(MigrationPlan::default_signature_plan(name)).expect("default plan is non-empty")
    }

    /// The plan being executed.
    pub fn plan(&self) -> &MigrationPlan {
        &self.plan
    }

    /// The stage currently in effect.
    pub fn current_stage(&self) -> MigrationStage {
        self.plan.stages()[self.current]
    }

    /// Index of the current stage within the plan.
    pub fn current_index(&self) -> usize {
        self.current
    }

    /// Progress through the plan as a fraction (0.0 at the first stage, 1.0 at
    /// the last).
    pub fn progress(&self) -> f32 {
        let last = self.plan.len() - 1;
        if last == 0 {
            1.0
        } else {
            self.current as f32 / last as f32
        }
    }

    /// Whether the final stage has been reached.
    pub fn is_complete(&self) -> bool {
        matches!(self.current_stage(), MigrationStage::Complete)
            || self.current == self.plan.len() - 1
    }

    /// Advance to the next stage, returning the new stage.
    pub fn advance(&mut self) -> Result<MigrationStage> {
        if self.current + 1 >= self.plan.len() {
            return Err(Error::MigrationError(
                "Migration is already at its final stage".into(),
            ));
        }
        self.current += 1;
        Ok(self.current_stage())
    }

    /// A [`CryptoPolicy`] reflecting the current stage of the migration.
    pub fn current_policy(&self) -> CryptoPolicy {
        let stage = self.current_stage();
        let mode = match stage {
            MigrationStage::NotStarted => CryptoMode::Classical,
            MigrationStage::Complete => CryptoMode::PostQuantum,
            _ => CryptoMode::Hybrid,
        };
        CryptoPolicy::new(format!("{}-migration", self.plan.name()))
            .set_mode(mode)
            .set_migration_stage(stage)
            .set_min_security_level(0)
    }

    /// Decide which algorithm the *next* operation should use, honoring the
    /// current stage's rollout percentage, and record it in the statistics.
    ///
    /// Selection is deterministic (counter-based) so behavior is reproducible
    /// and the realized ratio converges to the configured percentage.
    pub fn select_algorithm(&mut self) -> AlgorithmType {
        let sample = (self.op_counter % 100) as f32 / 100.0;
        self.op_counter = self.op_counter.wrapping_add(1);

        let use_pqc = self.current_stage_should_use_pqc(sample);
        if use_pqc {
            self.stats.pqc_ops += 1;
            AlgorithmType::PostQuantum(self.plan.pqc_algorithm())
        } else {
            self.stats.classical_ops += 1;
            AlgorithmType::Classical(self.plan.classical_algorithm())
        }
    }

    fn current_stage_should_use_pqc(&self, sample: f32) -> bool {
        match self.current_stage() {
            MigrationStage::NotStarted => false,
            MigrationStage::Testing(p) | MigrationStage::Rollout(p) => sample < p,
            MigrationStage::Complete => true,
        }
    }

    /// Statistics gathered so far.
    pub fn stats(&self) -> MigrationStats {
        self.stats
    }

    /// Reset the operation counter and statistics (e.g. between stages).
    pub fn reset_stats(&mut self) {
        self.stats = MigrationStats::default();
        self.op_counter = 0;
    }

    /// A human-readable status summary.
    pub fn report(&self) -> String {
        format!(
            "Migration '{}': stage {}/{} ({:?}), {:.0}% complete | ops: {} classical, {} PQC ({:.1}% PQC)",
            self.plan.name(),
            self.current + 1,
            self.plan.len(),
            self.current_stage(),
            self.progress() * 100.0,
            self.stats.classical_ops,
            self.stats.pqc_ops,
            self.stats.pqc_ratio() * 100.0,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plan_construction() {
        let plan = MigrationPlan::default_signature_plan("svc");
        assert_eq!(plan.name(), "svc");
        assert_eq!(plan.classical_algorithm(), ClassicalAlgorithm::Ed25519);
        assert_eq!(plan.pqc_algorithm(), PostQuantumAlgorithm::Dilithium3);
        assert_eq!(plan.len(), 6);
    }

    #[test]
    fn test_empty_plan_rejected() {
        let plan = MigrationPlan::new(
            "empty",
            ClassicalAlgorithm::Ed25519,
            PostQuantumAlgorithm::Dilithium3,
            vec![],
        );
        assert!(MigrationOrchestrator::new(plan).is_err());
    }

    #[test]
    fn test_advance_through_stages() {
        let mut orch = MigrationOrchestrator::with_default_plan("svc");
        assert_eq!(orch.current_stage(), MigrationStage::NotStarted);
        assert!(!orch.is_complete());

        let mut steps = 0;
        while orch.advance().is_ok() {
            steps += 1;
        }
        assert_eq!(steps, 5);
        assert!(orch.is_complete());
        assert_eq!(orch.current_stage(), MigrationStage::Complete);
        // Advancing past the end is an error.
        assert!(orch.advance().is_err());
    }

    #[test]
    fn test_progress() {
        let mut orch = MigrationOrchestrator::with_default_plan("svc");
        assert_eq!(orch.progress(), 0.0);
        orch.advance().unwrap();
        assert!((orch.progress() - 0.2).abs() < 0.001);
    }

    #[test]
    fn test_not_started_uses_classical() {
        let mut orch = MigrationOrchestrator::with_default_plan("svc");
        for _ in 0..100 {
            assert!(orch.select_algorithm().is_classical());
        }
        assert_eq!(orch.stats().pqc_ops, 0);
        assert_eq!(orch.stats().classical_ops, 100);
    }

    #[test]
    fn test_complete_uses_pqc() {
        let mut orch = MigrationOrchestrator::with_default_plan("svc");
        while orch.advance().is_ok() {}
        for _ in 0..100 {
            assert!(orch.select_algorithm().is_post_quantum());
        }
        assert_eq!(orch.stats().classical_ops, 0);
        assert_eq!(orch.stats().pqc_ops, 100);
    }

    #[test]
    fn test_rollout_ratio_is_honored() {
        let mut orch = MigrationOrchestrator::with_default_plan("svc");
        // Advance to the Rollout(0.25) stage (index 2).
        orch.advance().unwrap();
        orch.advance().unwrap();
        assert_eq!(orch.current_stage(), MigrationStage::Rollout(0.25));

        for _ in 0..100 {
            orch.select_algorithm();
        }
        // Deterministic counter-based selection yields exactly 25%.
        assert_eq!(orch.stats().pqc_ops, 25);
        assert_eq!(orch.stats().classical_ops, 75);
        assert!((orch.stats().pqc_ratio() - 0.25).abs() < 0.001);
    }

    #[test]
    fn test_current_policy_modes() {
        let mut orch = MigrationOrchestrator::with_default_plan("svc");
        assert_eq!(orch.current_policy().mode(), CryptoMode::Classical);
        orch.advance().unwrap();
        assert_eq!(orch.current_policy().mode(), CryptoMode::Hybrid);
        while orch.advance().is_ok() {}
        assert_eq!(orch.current_policy().mode(), CryptoMode::PostQuantum);
    }

    #[test]
    fn test_reset_stats() {
        let mut orch = MigrationOrchestrator::with_default_plan("svc");
        for _ in 0..10 {
            orch.select_algorithm();
        }
        assert_eq!(orch.stats().total(), 10);
        orch.reset_stats();
        assert_eq!(orch.stats().total(), 0);
    }
}
