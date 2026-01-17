# Detect privilege changes during retries (observation only)
def execute_with_retry_tracking(operation, max_attempts=3):
    initial_privileges = None
    
    for attempt in range(max_attempts):
        try:
            # Get current authorization
            auth = get_authorization(operation.user, operation.resource)
            
            if attempt == 0:
                initial_privileges = auth.privileges
            else:
                # Check for privilege changes
                if auth.privileges != initial_privileges:
                    metrics.increment(
                        "auth.retry.privilege_change",
                        tags={
                            "increased": str(auth.privileges > initial_privileges),
                            "decreased": str(auth.privileges < initial_privileges)
                        }
                    )
                    
                    security_log.warning(
                        "Privilege change detected during retry",
                        attempt=attempt,
                        initial=initial_privileges,
                        current=auth.privileges
                    )
            
            return operation.execute(privileges=auth.privileges)
            
        except TransientError:
            if attempt < max_attempts - 1:
                time.sleep(2 ** attempt)
                continue
            raise
