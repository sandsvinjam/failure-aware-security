from enum import Enum
from dataclasses import dataclass
from typing import Set

class TrustLevel(Enum):
    NORMAL = 4      # All systems healthy
    DEGRADED = 3    # Some degradation, but functional
    CONSTRAINED = 2 # Significant degradation
    NO_TRUST = 1    # Systems unreachable or severely degraded

@dataclass
class TrustMetrics:
    auth_latency_p99: float  # milliseconds
    error_rate: float         # percentage
    cache_staleness: float    # seconds

class TrustMonitor:
    def __init__(self):
        self.current_level = TrustLevel.NORMAL
        
    def evaluate_trust_level(self, metrics: TrustMetrics) -> TrustLevel:
        """Determine trust level based on observable metrics"""
        
        # NO_TRUST: Systems are effectively down
        if (metrics.error_rate > 50 or 
            metrics.auth_latency_p99 > 10000 or
            metrics.cache_staleness > 1800):
            return TrustLevel.NO_TRUST
        
        # CONSTRAINED: Significant degradation
        if (metrics.error_rate > 20 or 
            metrics.auth_latency_p99 > 2000 or
            metrics.cache_staleness > 300):
            return TrustLevel.CONSTRAINED
        
        # DEGRADED: Noticeable issues but functional
        if (metrics.error_rate > 1 or 
            metrics.auth_latency_p99 > 200):
            return TrustLevel.DEGRADED
        
        # NORMAL: Healthy operation
        return TrustLevel.NORMAL
    
    def get_allowed_privileges(self, trust_level: TrustLevel) -> Set[str]:
        """Define which privileges are allowed at each trust level"""
        
        if trust_level == TrustLevel.NORMAL:
            return {"read", "write", "delete", "admin", "share"}
        
        elif trust_level == TrustLevel.DEGRADED:
            # Restrict high-risk operations
            return {"read", "write", "share"}
        
        elif trust_level == TrustLevel.CONSTRAINED:
            # Only safe, read-only operations
            return {"read"}
        
        else:  # NO_TRUST
            # Only public access, no authenticated operations
            return set()
