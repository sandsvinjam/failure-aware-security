# Sample 1% of authorization decisions for validation
import random

def check_permission_with_validation(user, resource, operation):
    result = check_permission(user, resource, operation)
    
    # Sample for validation
    if random.random() < 0.01:
        # Get ground truth from authoritative source
        # (slower, but accurate)
        ground_truth = authoritative_auth_check(user, resource, operation)
        
        metrics.increment(
            "auth.validation",
            tags={
                "correct": str(result == ground_truth),
                "cached": str(was_from_cache)
            }
        )
        
        if result != ground_truth:
            security_log.error(
                "Authorization mismatch detected",
                user=user.id,
                resource=resource.id,
                operation=operation,
                returned=result,
                ground_truth=ground_truth
            )
    
    return result
