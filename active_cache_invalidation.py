class AuthorizationCache:
    def __init__(self, cache_backend):
        self.cache = cache_backend
        self.invalidation_service = InvalidationService()
    
    def set(self, key, value, ttl):
        # Store with TTL
        self.cache.set(key, value, ttl)
        
        # Register for invalidation
        self.invalidation_service.register(
            key,
            resource_id=value.resource_id,
            user_id=value.user_id
        )
    
    def invalidate_user(self, user_id):
        """Invalidate all cache entries for a user"""
        keys = self.invalidation_service.get_keys_for_user(user_id)
        for key in keys:
            self.cache.delete(key)
    
    def invalidate_resource(self, resource_id):
        """Invalidate all cache entries for a resource"""
        keys = self.invalidation_service.get_keys_for_resource(resource_id)
        for key in keys:
            self.cache.delete(key)

# Usage: invalidate on permission changes
def revoke_access(user, resource):
    # Revoke in authorization service
    auth_service.revoke(user, resource)
    
    # Immediately invalidate cache
    auth_cache.invalidate_user(user.id)
    auth_cache.invalidate_resource(resource.id)
    
    # Audit the revocation
    audit_service.log_operation(
        user,
        "revoke_access",
        resource,
        {"revoked_at": datetime.utcnow()}
    )
