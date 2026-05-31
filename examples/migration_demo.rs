//! Simulate a staged migration from Ed25519 to Dilithium3.
//!
//! Run: `cargo run --example migration_demo`

use cryptoshift::{MigrationOrchestrator, MigrationPlan, MigrationStage};

fn main() -> cryptoshift::Result<()> {
    let plan = MigrationPlan::default_signature_plan("auth-service");
    println!("Migration plan: {} ({} stages)\n", plan.name(), plan.len());

    let mut orchestrator = MigrationOrchestrator::new(plan)?;
    let samples = 1000;

    loop {
        orchestrator.reset_stats();
        for _ in 0..samples {
            orchestrator.select_algorithm();
        }
        println!("{}", orchestrator.report());

        if orchestrator.advance().is_err() {
            break;
        }
    }

    println!("\nFinal stage: {:?}", MigrationStage::Complete);
    Ok(())
}
