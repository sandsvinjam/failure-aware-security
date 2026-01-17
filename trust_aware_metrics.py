# Compare trust-aware vs. legacy authorization
metrics.increment(
    "auth.decision_comparison",
    tags={
        "trust_aware_result": str(trust_result.allowed),
        "legacy_result": str(legacy_result.allowed),
        "match": str(trust_result.allowed == legacy_result.allowed)
    }
)

# Alert on mismatches
if trust_result.allowed != legacy_result.allowed:
    security_log.warning(
        "Trust-aware authorization diverged from legacy",
        user=user.id,
        trust_result=trust_result,
        legacy_result=legacy_result
    )
