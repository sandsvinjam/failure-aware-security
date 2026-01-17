# Enable retry-safe authorization
def execute_with_retry_safe_auth(operation, max_attempts=3):
    auth_token = None
    
    for attempt in range(max_attempts):
        try:
            auth_result = retry_safe_authorizer.authorize_with_retry(
                operation.user,
                operation.resource,
                operation.operation,
                attempt=attempt,
                previous_token=auth_token
            )
            
            if not auth_result.allowed:
                raise PermissionDenied(auth_result.reason)
            
            auth_token = auth_result.token
            
            return operation.execute(privileges=auth_result.privileges)
            
        except TransientError:
            if attempt < max_attempts - 1:
                time.sleep(2 ** attempt)
                continue
            raise
