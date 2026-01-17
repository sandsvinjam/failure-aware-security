class OperationRisk(Enum):
    PUBLIC = 1      # No authentication required
    LOW = 2         # Read-only, user's own data
    MEDIUM = 3      # Write to user's own data
    HIGH = 4        # Write to shared data
    CRITICAL = 5    # Admin, delete, share, security changes

# Map trust levels to allowed risk levels
TRUST_TO_RISK = {
    TrustLevel.NORMAL: {OperationRisk.PUBLIC, OperationRisk.LOW, OperationRisk.MEDIUM, OperationRisk.HIGH, OperationRisk.CRITICAL},
    TrustLevel.DEGRADED: {OperationRisk.PUBLIC, OperationRisk.LOW, OperationRisk.MEDIUM, OperationRisk.HIGH},
    TrustLevel.CONSTRAINED: {OperationRisk.PUBLIC, OperationRisk.LOW, OperationRisk.MEDIUM},
    TrustLevel.NO_TRUST: {OperationRisk.PUBLIC},
}

def check_permission(user, resource, operation):
    trust_level = trust_monitor.current_level
    operation_risk = get_operation_risk(operation, resource)
    allowed_risks = TRUST_TO_RISK[trust_level]
    
    if operation_risk not in allowed_risks:
        return AuthResult(
            allowed=False,
            reason=f"Operation risk {operation_risk.name} exceeds trust level {trust_level.name}"
        )
    
    # Continue with authorization check...
