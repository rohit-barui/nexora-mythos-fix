package nexora.virtual_patch

default allow = false

# Virtual patch rules control zero-day mitigations deployed via WAF / sysctl
allow {
    count(violations) == 0
}

# Violation: virtual patch must specify a target (URL path or sysctl key)
violations["Virtual patch missing target"] {
    action := input.plan.actions[_]
    action.action_type == "virtual_patch"
    not action.target_package
}

# Violation: virtual patch must declare a rollback template
violations["Virtual patch must define a rollback template"] {
    action := input.plan.actions[_]
    action.action_type == "virtual_patch"
    not action.rollback_command_template
}

# Violation: blocking WAF rules must be phase-2 (request body inspection is phase 1)
violations["Blocking WAF rules must not run in phase:1"] {
    action := input.plan.actions[_]
    action.method == "waf_rule"
    action.action_type == "virtual_patch"
    startswith(action.rollback_command_template, "phase:1")
}
