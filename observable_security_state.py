from dataclasses import dataclass
from typing import Dict, List
import time

@dataclass
class SecurityMetrics:
    """Observable security state for monitoring"""
    trust_level: TrustLevel
    trust_level_duration_seconds: float
    authorization_correctness_rate: float
    privilege_escalations_blocked: int
    security_violations_detected: int
    cache_staleness_p95_seconds: float
    auth_service_error_rate: float

class SecurityObservabilityService:
    def __init__(self, metrics_backend):
        self.metrics = metrics_backend
        self.trust_level_start_time = time.time()
        self.current_trust_level = TrustLevel.NORMAL
    
    def record_trust_transition(self, old_level: TrustLevel, new_level: TrustLevel):
        """Record trust level transitions"""
        duration = time.time() - self.trust_level_start_time
        
        # Record duration at previous level
        self.metrics.histogram(
            "security.trust_level.duration_seconds",
            duration,
            tags={"level": old_level.name}
        )
        
        # Record transition
        self.metrics.increment(
            "security.trust_transitions",
            tags={
                "from": old_level.name,
                "to": new_level.name
            }
        )
        
        # Alert on degradation
        if new_level.value < old_level.value:
            self.alert_trust_degradation(old_level, new_level)
        
        self.current_trust_level = new_level
        self.trust_level_start_time = time.time()
    
    def record_authorization_decision(self, result: AuthResult, ground_truth: bool):
        """Track authorization correctness"""
        correct = (result.allowed == ground_truth)
        
        self.metrics.increment(
            "security.authorization.decisions",
            tags={
                "trust_level": self.current_trust_level.name,
                "correct": str(correct)
            }
        )
        
        if not correct:
            self.metrics.increment("security.authorization.violations")
            self.alert_authorization_violation(result)
    
    def record_privilege_escalation_attempt(self, blocked: bool, details: Dict):
        """Track privilege escalation attempts"""
        self.metrics.increment(
            "security.privilege_escalation.attempts",
            tags={"blocked": str(blocked)}
        )
        
        if blocked:
            security_log.warning(
                "Privilege escalation attempt blocked",
                **details
            )
        else:
            security_log.critical(
                "Privilege escalation NOT blocked",
                **details
            )
            self.alert_privilege_escalation(details)
    
    def alert_trust_degradation(self, old_level, new_level):
        """Alert when trust degrades"""
        if new_level == TrustLevel.NO_TRUST:
            self.send_alert(
                severity="CRITICAL",
                title="Security systems unreachable",
                message=f"Trust level degraded to NO_TRUST from {old_level.name}"
            )
        elif new_level == TrustLevel.CONSTRAINED:
            self.send_alert(
                severity="HIGH",
                title="Significant security degradation",
                message=f"Trust level degraded to CONSTRAINED from {old_level.name}"
            )
    
    def get_security_health_dashboard(self) -> Dict:
        """Generate security health metrics for dashboards"""
        return {
            "current_trust_level": self.current_trust_level.name,
            "time_at_current_level_minutes": (time.time() - self.trust_level_start_time) / 60,
            "authorization_correctness_24h": self.metrics.get("security.authorization.correctness_rate", window="24h"),
            "privilege_escalations_blocked_24h": self.metrics.get("security.privilege_escalation.blocked", window="24h"),
            "security_violations_24h": self.metrics.get("security.authorization.violations", window="24h"),
        }
