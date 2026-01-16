# Add metrics to existing authorization code
@instrument_authorization
def check_permission(user, resource, operation):
    start_time = time.time()
    
    try:
        result = existing_auth_check(user, resource, operation)
        
        metrics.histogram(
            "auth.latency_ms",
            (time.time() - start_time) * 1000
        )
        
        metrics.increment(
            "auth.decisions",
            tags={"result": "allowed" if result else "denied"}
        )
        
        return result
