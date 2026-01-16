class TrustAwareAuthorizer:
    def __init__(self, auth_service, cache, trust_monitor):
        self.auth_service = auth_service
        self.cache = cache
        self.trust_monitor = trust_monitor
    
    def check_permission(self, user, resource, operation):
        """
        Check permission with awareness of current trust level
        """
        # Get current trust level
        trust_level = self.trust_monitor.current_level
        
        # Check if operation is allowed at current trust level
        allowed_operations = self.trust_monitor.get_allowed_privileges(trust_level)
        if operation not in allowed_operations:
            return AuthResult(
                allowed=False,
                reason=f"Operation '{operation}' not permitted at trust level {trust_level.name}"
            )
        
        # Attempt fresh authorization based on trust level
        if trust_level in [TrustLevel.NORMAL, TrustLevel.DEGRADED]:
            try:
                # Try fresh auth with shorter timeout at DEGRADED
                timeout = 1.0 if trust_level == TrustLevel.NORMAL else 0.5
                auth_result = self.auth_service.check(
                    user, resource, operation, 
                    timeout=timeout
                )
                
                # Cache the result for potential fallback
                self.cache.set(
                    f"auth:{user}:{resource}:{operation}",
                    auth_result,
                    ttl=300  # 5 minutes
                )
                
                return auth_result
                
            except TimeoutError:
                # At DEGRADED, fall back to cache for read operations only
                if trust_level == TrustLevel.DEGRADED and operation == "read":
                    cached = self.cache.get(f"auth:{user}:{resource}:{operation}")
                    if cached and cached.age_seconds < 300:
                        return cached
                
                # Otherwise, deny
                return AuthResult(
                    allowed=False,
                    reason="Authorization service timeout, no valid cache"
                )
        
        elif trust_level == TrustLevel.CONSTRAINED:
            # Only use recent cache for read-only operations
            if operation == "read":
                cached = self.cache.get(f"auth:{user}:{resource}:read")
                if cached and cached.age_seconds < 60:  # Only 1-minute old cache
                    return cached
            
            return AuthResult(
                allowed=False,
                reason="Insufficient trust level for authorization"
            )
        
        else:  # NO_TRUST
            # Only allow access to explicitly public resources
            if resource.is_public and operation == "read":
                return AuthResult(allowed=True, reason="Public resource")
            
            return AuthResult(
                allowed=False,
                reason="No trust - systems unavailable"
            )
