def process_sensitive_operation(user, data):
    # Check authorization
    if not has_permission(user, "sensitive_data", "write"):
        raise PermissionDenied()
    
    # Process operation
    result = process_data(data)
    
    # Attempt to audit - but what if this fails?
    try:
        audit_service.log(user, "sensitive_write", data.id, result)
    except AuditServiceError:
        # Common pattern: log locally and continue
        logger.error("Audit service unavailable")
        # Operation proceeds anyway!
    
    return result
