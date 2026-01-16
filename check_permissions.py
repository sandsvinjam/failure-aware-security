def check_permission(user, resource):
    try:
        # Try fresh authorization
        return auth_service.check(user, resource, timeout=1.0)
    except TimeoutError:
        # Fallback to cache - DANGEROUS!
        cached_result = cache.get(f"auth:{user}:{resource}")
        if cached_result:
            return cached_result
        # Default to deny if no cache
        return False
