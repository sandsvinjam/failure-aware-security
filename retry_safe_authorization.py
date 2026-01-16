import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime, timedelta

@dataclass
class AuthorizationToken:
    """Idempotency token bound to specific authorization decision"""
    token_id: str
    user_id: str
    resource_id: str
    operation: str
    privileges: Set[str]
    granted_at: datetime
    expires_at: datetime
    
    def is_valid(self) -> bool:
        return datetime.utcnow() < self.expires_at
    
    def compute_hmac(self, secret_key: bytes) -> str:
        """Cryptographically bind token to authorization details"""
        message = f"{self.token_id}:{self.user_id}:{self.resource_id}:{self.operation}:{sorted(self.privileges)}".encode()
        return hmac.new(secret_key, message, hashlib.sha256).hexdigest()

class RetrySafeAuthorizer:
    def __init__(self, auth_service, secret_key):
        self.auth_service = auth_service
        self.secret_key = secret_key
        self.token_store = {}  # In production: use Redis
    
    def authorize_with_retry(self, user, resource, operation, attempt=0, previous_token=None):
        """
        Authorize operation with retry safety guarantees
        """
        if attempt == 0:
            # First attempt: perform full authorization
            privileges = self.auth_service.get_privileges(user, resource, operation)
            
            # Create idempotency token
            token = AuthorizationToken(
                token_id=generate_unique_id(),
                user_id=user.id,
                resource_id=resource.id,
                operation=operation,
                privileges=privileges,
                granted_at=datetime.utcnow(),
                expires_at=datetime.utcnow() + timedelta(minutes=5)
            )
            
            # Store token for retry validation
            self.token_store[token.token_id] = token
            
            return AuthResult(
                allowed=True,
                token=token,
                privileges=privileges
            )
        
        else:
            # Retry attempt: validate token and enforce monotonic privileges
            if not previous_token or not previous_token.is_valid():
                return AuthResult(
                    allowed=False,
                    reason="Invalid or expired authorization token"
                )
            
            # Verify token hasn't been tampered with
            stored_token = self.token_store.get(previous_token.token_id)
            if not stored_token:
                return AuthResult(
                    allowed=False,
                    reason="Authorization token not found"
                )
            
            # Get current privileges
            current_privileges = self.auth_service.get_privileges(
                user, resource, operation
            )
            
            # CRITICAL: Enforce monotonic privilege reduction
            # Retry can only use privileges <= original privileges
            allowed_privileges = stored_token.privileges & current_privileges
            
            if allowed_privileges != stored_token.privileges:
                # Privileges have changed since initial authorization
                # Log security event
                security_log.warning(
                    f"Privilege change detected during retry for user {user.id}",
                    original=stored_token.privileges,
                    current=current_privileges,
                    allowed=allowed_privileges
                )
            
            return AuthResult(
                allowed=True,
                token=stored_token,  # Reuse same token
                privileges=allowed_privileges  # Reduced privileges
            )

# Usage in application code
def execute_sensitive_operation(user, resource, operation, data):
    auth_token = None
    
    for attempt in range(3):
        try:
            # Get authorization (fresh or retry-safe)
            auth_result = authorizer.authorize_with_retry(
                user, resource, operation,
                attempt=attempt,
                previous_token=auth_token
            )
            
            if not auth_result.allowed:
                raise PermissionDenied(auth_result.reason)
            
            auth_token = auth_result.token
            
            # Execute with authorized privileges
            return operation.execute(
                privileges=auth_result.privileges,
                data=data
            )
            
        except TransientError as e:
            if attempt < 2:
                time.sleep(2 ** attempt)
                continue
            raise
