package nexora.remediation

default allow = false
default require_escalation = false

# 1. Main Policy Rule: Allow plan if no violation rules match
allow {
    count(violations) == 0
}

# 2. Violation: Block production patching during business hours (09:00 - 17:00 UTC)
violations["Production patching blocked during UTC business hours (09:00 - 17:00)"] {
    input.asset.environment == "production"
    input.current_hour_utc >= 9
    input.current_hour_utc <= 17
}

# 3. Violation: Reject plans that restart critical services without explicit approval
violations["Actions requiring restart on critical assets must undergo approval escalation"] {
    input.asset.criticality_score >= 8
    action := input.plan.actions[_]
    action.restart_required == true
    input.has_escalation_approval != true
}

# 4. Violation: Reject plans with missing target package or method
violations["Invalid action definition: missing target_package or method"] {
    action := input.plan.actions[_]
    not action.target_package
}

# 5. Require Escalation for Kernel / Core System Updates
require_escalation {
    action := input.plan.actions[_]
    action.target_package == "linux-image-generic"
}

require_escalation {
    input.asset.criticality_score >= 9
}
