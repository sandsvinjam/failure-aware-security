# Run trust monitor in observation-only mode
class TrustMonitor:
    def __init__(self, metrics_service):
        self.metrics = metrics_service
        self.current_level = TrustLevel.NORMAL
        self.observation_mode = True  # Don't enforce yet
    
    def update_trust_level(self):
        # Collect current metrics
        metrics = TrustMetrics(
            auth_latency_p99=self.get_auth_latency_p99(),
            error_rate=self.get_auth_error_rate(),
            cache_staleness=self.get_cache_staleness_p95()
        )
        
        # Evaluate what trust level WOULD be
        new_level = self.evaluate_trust_level(metrics)
        
        if new_level != self.current_level:
            # Log transition but don't enforce
            security_log.info(
                "Trust level transition (observation only)",
                from_level=self.current_level.name,
                to_level=new_level.name,
                metrics=metrics
            )
            
            self.metrics.increment(
                "security.trust_transitions.observed",
                tags={
                    "from": self.current_level.name,
                    "to": new_level.name
                }
            )
            
            self.current_level = new_level
        
        # Record current state
        self.metrics.gauge(
            "security.trust_level",
            new_level.value,
            tags={"level": new_level.name}
        )

# Run monitor every 10 seconds
scheduler.add_job(
    trust_monitor.update_trust_level,
    trigger='interval',
    seconds=10
)
