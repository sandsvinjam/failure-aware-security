class TrustAwareAuthorizer:
    def __init__(self, auth_service, cache, trust_monitor):
        self.auth_service = auth_service
        self.cache = cache
        self.trust_monitor = trust_monitor
        self.enforcement_enabled = False  # Start in observation mode
    
    def check_permission(self, user, resource, operation):
        trust_level = self.trust_monitor.current_level
        
        # Only enforce for read operations initially
        if operation != "read" or not self.enforcement_enabled:
            # Fallback to existing logic
            return self._legacy_auth_check(user, resource, operation)
        
        # Trust-aware authorization for reads
        allowed_operations = self.trust_monitor.get_allowed_privileges(trust_level)
        
        if operation not in allowed_operations:
            metrics.increment(
                "auth.trust_blocked",
                tags={
                    "trust_level": trust_level.name,
                    "operation": operation
                }
            )
            
            return AuthResult(
                allowed=False,
                reason=f"Operation '{operation}' not permitted at trust level {trust_level.name}"
            )
        
        # Continue with trust-aware check...
        return self._trust_aware_check(user, resource, operation, trust_level)
