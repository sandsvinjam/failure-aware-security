# Define critical invariants
invariants = [
    PrivilegeBoundsInvariant(),
    TemporalFreshnessInvariant(),
    MonotonicRetryPrivilegesInvariant(),
]

invariant_checker = InvariantChecker(invariants)

# Check invariants without blocking (observation mode)
def check_permission_with_invariants(user, resource, operation, attempt=0, previous_auth=None):
    auth_result = check_permission(user, resource, operation)
    
    context = build_invariant_context(user, resource, operation, auth_result, attempt, previous_auth)
    
    try:
        invariant_checker.check_all(context)
    except SecurityInvariantViolation as e:
        # In observation mode: log but don't block
        security_log.critical(
            "Security invariant violated (observation mode)",
            error=str(e),
            context=context
        )
        
        # In production mode: would raise exception
        # raise
    
    return auth_result
