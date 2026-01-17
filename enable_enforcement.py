# Change from observation to enforcement
try:
    invariant_checker.check_all(context)
except SecurityInvariantViolation as e:
    # Now actually block the operation
    raise
