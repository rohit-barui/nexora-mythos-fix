package nexora.safety

default allow = false

# Pre-patch safety checks that must always be satisfied
allow {
    count(violations) == 0
}

# Violation: patch jobs require a pre-patch snapshot for production assets
violations["Production patch jobs require a pre-patch snapshot"] {
    input.asset.environment == "production"
    input.patch_job.snapshot_metadata.status != "READY"
}

# Violation: patch jobs must define rollback availability
violations["Patch jobs must be rollback-capable"] {
    input.patch_job.rollback_available != true
}

# Violation: sandbox dry-run required for critical assets before production execution
violations["Critical assets require a sandbox dry-run before production execution"] {
    input.asset.criticality_score >= 8
    input.patch_job.execution_type != "SANDBOX_DRY_RUN"
}
