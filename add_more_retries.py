# ❌ This makes security WORSE, not better
@retry(max_attempts=5, backoff=exponential)
def check_authorization(user, resource):
    return auth_service.check(user, resource)
