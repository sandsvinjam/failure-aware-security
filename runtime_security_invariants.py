from abc import ABC, abstractmethod
from enum import Enum

class InvariantSeverity(Enum):
    CRITICAL = 1  # Block operation if violated
    HIGH = 2      # Alert but allow operation
    MEDIUM = 3    # Log violation
    LOW = 4       # Metrics only

class SecurityInvariant(ABC):
    def __init__(self, severity: InvariantSeverity):
        self.severity = severity
    
    @abstractmethod
    def check(self, context: Dict) -> bool:
        """Return True if invariant holds, False if violated"""
        pass
    
    @abstractmethod
    def violation_message(self, context: Dict) -> str:
        """Describe the violation"""
        pass

class PrivilegeBoundsInvariant(SecurityInvariant):
    """Granted privileges must not exceed maximum for trust level"""
    
    def __init__(self):
        super().__init__(InvariantSeverity.CRITICAL)
    
    def check(self, context: Dict) -> bool:
        granted = context['granted_privileges']
        trust_level = context['trust_level']
        max_allowed = context['trust_monitor'].get_allowed_privileges(trust_level)
        
        # Invariant: granted ⊆ max_allowed
        return granted.issubset(max_allowed)
    
    def violation_message(self, context: Dict) -> str:
        granted = context['granted_privileges']
        max_allowed = context['trust_monitor'].get_allowed_privileges(context['trust_level'])
        excess = granted - max_allowed
        
        return f"Granted privileges {excess} exceed maximum for trust level {context['trust_level'].name}"

class TemporalFreshnessInvariant(SecurityInvariant):
    """Authorization must be fresh relative to trust level"""
    
    def __init__(self):
        super().__init__(InvariantSeverity.HIGH)
    
    def check(self, context: Dict) -> bool:
        auth_age = context['auth_age_seconds']
        trust_level = context['trust_level']
        
        # Maximum auth age by trust level
        max_age = {
            TrustLevel.NORMAL: 3600,      # 1 hour
            TrustLevel.DEGRADED: 1800,    # 30 minutes
            TrustLevel.CONSTRAINED: 300,  # 5 minutes
            TrustLevel.NO_TRUST: 0        # Must be fresh
        }
        
        return auth_age <= max_age[trust_level]
    
    def violation_message(self, context: Dict) -> str:
        return f"Authorization age {context['auth_age_seconds']}s exceeds maximum for {context['trust_level'].name}"

class MonotonicRetryPrivilegesInvariant(SecurityInvariant):
    """Retry attempts must have <= privileges of original attempt"""
    
    def __init__(self):
        super().__init__(InvariantSeverity.CRITICAL)
    
    def check(self, context: Dict) -> bool:
        if context.get('attempt', 0) == 0:
            return True  # First attempt, no constraint
        
        current_privileges = context['current_privileges']
        original_privileges = context['original_privileges']
        
        # Invariant: current ⊆ original (monotonic reduction)
        return current_privileges.issubset(original_privileges)
    
    def violation_message(self, context: Dict) -> str:
        escalated = context['current_privileges'] - context['original_privileges']
        return f"Retry attempt escalated privileges: {escalated}"

class InvariantChecker:
    def __init__(self, invariants: List[SecurityInvariant]):
        self.invariants = invariants
        self.metrics = MetricsService()
    
    def check_all(self, context: Dict) -> bool:
        """
        Check all invariants, return True if all pass
        Block operation if any CRITICAL invariant fails
        """
        all_passed = True
        
        for invariant in self.invariants:
            passed = invariant.check(context)
            
            # Record metric
            self.metrics.increment(
                "security.invariant.checks",
                tags={
                    "invariant": invariant.__class__.__name__,
                    "passed": str(passed),
                    "severity": invariant.severity.name
                }
            )
            
            if not passed:
                all_passed = False
                message = invariant.violation_message(context)
                
                # Handle based on severity
                if invariant.severity == InvariantSeverity.CRITICAL:
                    security_log.critical(f"CRITICAL invariant violation: {message}")
                    raise SecurityInvariantViolation(message)
                
                elif invariant.severity == InvariantSeverity.HIGH:
                    security_log.error(f"HIGH severity invariant violation: {message}")
                    alert_security_team(message)
                
                elif invariant.severity == InvariantSeverity.MEDIUM:
                    security_log.warning(f"Invariant violation: {message}")
                
                else:  # LOW
                    security_log.info(f"Invariant violation: {message}")
        
        return all_passed

# Usage in authorization flow
def authorize_operation(user, resource, operation, attempt=0, previous_auth=None):
    # ... authorization logic ...
    
    # Build context for invariant checking
    context = {
        'user': user,
        'resource': resource,
        'operation': operation,
        'granted_privileges': auth_result.privileges,
        'trust_level': trust_monitor.current_level,
        'trust_monitor': trust_monitor,
        'auth_age_seconds': (datetime.utcnow() - auth_result.granted_at).total_seconds(),
        'attempt': attempt,
        'current_privileges': auth_result.privileges,
        'original_privileges': previous_auth.privileges if previous_auth else auth_result.privileges,
    }
    
    # Check invariants
    invariant_checker.check_all(context)  # Raises exception if CRITICAL invariant fails
    
    return auth_result
