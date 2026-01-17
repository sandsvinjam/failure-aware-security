class ResilientAuditService:
    def __init__(self, primary_audit, fallback_audit):
        self.primary = primary_audit
        self.fallback = fallback_audit
        self.audit_required_operations = {"admin", "delete", "share"}
    
    def log_operation(self, user, operation, resource, result, required=False):
        """
        Log operation with fallback and failure handling
        """
        audit_record = {
            "timestamp": datetime.utcnow().isoformat(),
            "user": user.id,
            "operation": operation,
            "resource": resource.id,
            "result": result,
            "required": required
        }
        
        try:
            # Try primary audit service
            self.primary.log(audit_record)
            
            metrics.increment(
                "audit.success",
                tags={"service": "primary"}
            )
            
            return True
            
        except AuditServiceError as e:
            metrics.increment(
                "audit.failure",
                tags={
                    "service": "primary",
                    "required": str(required)
                }
            )
            
            # Try fallback (e.g., local queue, S3, secondary database)
            try:
                self.fallback.log(audit_record)
                
                metrics.increment(
                    "audit.success",
                    tags={"service": "fallback"}
                )
                
                security_log.warning(
                    "Primary audit failed, used fallback",
                    error=str(e)
                )
                
                return True
                
            except Exception as fallback_error:
                metrics.increment(
                    "audit.failure",
                    tags={"service": "fallback"}
                )
                
                # If audit is required, block the operation
                if required or operation in self.audit_required_operations:
                    security_log.critical(
                        "Audit required but all audit services failed",
                        primary_error=str(e),
                        fallback_error=str(fallback_error)
                    )
                    
                    raise AuditFailureException(
                        "Operation blocked: audit service unavailable"
                    )
                
                # For non-required operations, log locally and continue
                security_log.error(
                    "Audit failed for non-required operation",
                    audit_record=audit_record,
                    primary_error=str(e),
                    fallback_error=str(fallback_error)
                )
                
                return False

# Usage
def process_sensitive_operation(user, data):
    if not has_permission(user, "sensitive_data", "write"):
        raise PermissionDenied()
    
    result = process_data(data)
    
    # Audit is REQUIRED for sensitive operations
    audit_service.log_operation(
        user,
        "sensitive_write",
        data,
        result,
        required=True  # Blocks if audit fails
    )
    
    return result
