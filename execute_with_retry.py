def execute_with_retry(operation, max_attempts=3):
    for attempt in range(max_attempts):
        try:
            # Get fresh authorization
            auth = get_authorization(operation.user, operation.resource)
            
            # Execute operation with authorized privileges
            return operation.execute(privileges=auth.privileges)
            
        except TransientError:
            if attempt < max_attempts - 1:
                time.sleep(2 ** attempt)  # Exponential backoff
                continue
            raise
