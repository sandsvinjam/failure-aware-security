class TrustMonitor:
    def __init__(self):
        self.current_level = TrustLevel.NORMAL
        self.level_enter_time = time.time()
        self.min_level_duration = 30  # seconds
    
    def evaluate_trust_level(self, metrics):
        new_level = self._compute_level(metrics)
        
        # Prevent flapping: require minimum duration at current level
        time_at_current = time.time() - self.level_enter_time
        
        if new_level != self.current_level:
            if time_at_current < self.min_level_duration:
                # Stay at current level for minimum duration
                return self.current_level
            
            # Require multiple confirmations for degradation
            if new_level.value < self.current_level.value:
                if not self._confirm_degradation(new_level, samples=3):
                    return self.current_level
            
            # Update level
            self.current_level = new_level
            self.level_enter_time = time.time()
        
        return self.current_level
