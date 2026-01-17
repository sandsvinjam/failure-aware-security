# Failure-Aware Security for Distributed Systems

**Production-ready patterns for maintaining security guarantees during partial failures**

This repository contains reference implementations of the patterns described in the InfoQ article ["Why Your Distributed System's Security Breaks During Failures (And How to Fix It)"](https://www.infoq.com/) by Sandhya Vinjam.

## Overview

Distributed systems experience partial failures that compromise security without any attacker involvement. Traditional security models assume binary states (working or failed), but production systems exist in intermediate degraded states where security mechanisms become unreliable.

This repository provides **production-tested code** for handling authorization, retries, and audit during failures. 

Deploying these patterns achieved:

- **Authorization correctness**: 73% → 99.7% during failures (+26.7%)
- **Privilege escalations**: 47/month → 0/month
- **Audit gaps**: 4 hours/month → 0 minutes/month
- **Latency overhead**: Only 8-10% additional latency
- **Availability trade-off**: -0.4% overall (only high-risk operations affected)

## Patterns Included

### 1. Graduated Trust Levels

Define explicit trust levels with different security guarantees instead of binary trust.

**Trust Levels:**
- `NORMAL`: All systems healthy, all operations allowed
- `DEGRADED`: Some degradation, high-risk operations restricted
- `CONSTRAINED`: Significant degradation, only read operations allowed
- `NO_TRUST`: Systems unreachable, only public access allowed

**Files:**
- `graduated_trust_levels.py` - Core implementation
- `trust_monitor.py` - Usage example

**Key Benefits:**
- Explicit degradation policy
- Graceful security reduction
- Observable state for monitoring
- Prevents catastrophic failures

### 2. Retry-Safe Authorization

Prevent privilege escalation during retries using idempotency tokens and monotonic privilege reduction.

**Files:**
- `retry_safe_authorization.py` - Core implementation

**Key Benefits:**
- Prevents privilege escalation (97% blocked in production)
- Cryptographically bound tokens
- Time-limited authorization
- Fully auditable

### 3. Observable Security State

Make security degradation visible through metrics and monitoring.

**Files:**
- `trust_aware_metrics.py` - Core implementation

**Metrics Tracked:**
- Trust level distribution
- Authorization correctness rate
- Privilege escalation attempts
- Cache staleness
- Security violation rate

### 4. Runtime Security Invariants

Define and enforce security properties that must hold even during failures.

**Files:**
- `runtime_security_invariants.py` - Core implementation

**Invariants Included:**
- `PrivilegeBoundsInvariant`: Granted privileges ≤ max for trust level
- `TemporalFreshnessInvariant`: Authorization freshness relative to trust level
- `MonotonicRetryPrivilegesInvariant`: Retry privileges ≤ original privileges

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/sandsvinjam/failure-aware-security.git
cd failure-aware-security

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage

```python
from graduated_trust_levels import TrustMonitor, TrustAwareAuthorizer
from retry_safe_authorization import RetrySafeAuthorizer
from runtime_security_invariants import InvariantChecker, PrivilegeBoundsInvariant

# Initialize trust monitor
trust_monitor = TrustMonitor()

# Create trust-aware authorizer
authorizer = TrustAwareAuthorizer(
    auth_service=your_auth_service,
    cache=your_cache,
    trust_monitor=trust_monitor
)

# Check permission with trust awareness
result = authorizer.check_permission(user, resource, operation)

if result.allowed:
    # Execute operation
    perform_action(user, resource, result.privileges)
else:
    # Handle denial
    log_denial(result.reason)
```

### Running Examples

```bash
# Run graduated trust example
python examples/trust_monitor_example.py

# Run retry-safe authorization example
python examples/retry_safe_example.py

# Run observability example
python examples/observability_example.py

# Run invariants example
python examples/invariants_example.py
```

## Implementation Guide

### Week 1: Measure Current State

Instrument your existing authorization system to establish baseline metrics.

```python
from patterns.instrumentation import instrument_authorization

@instrument_authorization
def check_permission(user, resource, operation):
    # Your existing authorization logic
    return existing_auth_check(user, resource, operation)
```

**Metrics to collect:**
- Authorization latency (p50, p95, p99)
- Error rate
- Cache hit rate and staleness
- Decision correctness

### Week 2-3: Deploy Trust Monitoring (Observation Mode)

Deploy the trust monitor without changing authorization behavior.

```python
from graduated_trust_levels import TrustMonitor

# Initialize in observation mode
trust_monitor = TrustMonitor(observation_mode=True)

# Schedule periodic updates (every 10 seconds)
trust_monitor.start_monitoring(interval_seconds=10)
```

### Week 4-5: Enable Graduated Trust (Read Operations)

Start with read operations only, gradually rolling out to more traffic.

```python
from graduated_trust_levels import TrustAwareAuthorizer

authorizer = TrustAwareAuthorizer(
    auth_service=auth_service,
    cache=cache,
    trust_monitor=trust_monitor,
    enforcement_enabled=False  # Start in observation mode
)

# After validation, enable enforcement
authorizer.enable_enforcement(operations=["read"])
```

### Week 6: Deploy Retry-Safe Authorization

Add idempotency tokens to prevent privilege escalation.

```python
from retry_safe_auth import RetrySafeAuthorizer

retry_safe_authorizer = RetrySafeAuthorizer(
    auth_service=auth_service,
    secret_key=your_secret_key
)

# Use in retry loops
auth_result = retry_safe_authorizer.authorize_with_retry(
    user, resource, operation,
    attempt=attempt_number,
    previous_token=auth_token
)
```

### Week 7: Enable Security Invariants

Deploy invariant checking, starting with observation mode.

```python
from runtime_security_invariants import (
    InvariantChecker,
    PrivilegeBoundsInvariant,
    TemporalFreshnessInvariant,
    MonotonicRetryPrivilegesInvariant
)

invariants = [
    PrivilegeBoundsInvariant(),
    TemporalFreshnessInvariant(),
    MonotonicRetryPrivilegesInvariant(),
]

checker = InvariantChecker(invariants)

# Check before executing operations
checker.check_all(context)  # Raises exception if CRITICAL invariant fails
```

### Week 8: Deploy Audit Resilience

Add fallback strategies for audit failures.

```python
from audit_resilience import ResilientAuditService

audit_service = ResilientAuditService(
    primary_audit=primary_audit_service,
    fallback_audit=fallback_audit_service
)

# Require audit for sensitive operations
audit_service.log_operation(
    user, operation, resource, result,
    required=True  # Blocks if audit fails
)
```

## Configuration

### Trust Level Thresholds

Customize trust level thresholds in `config/trust_levels.yaml`:

```yaml
trust_levels:
  normal:
    max_error_rate: 1.0  # 1%
    max_latency_p99: 200  # milliseconds
    max_cache_staleness: 3600  # seconds
    
  degraded:
    max_error_rate: 20.0  # 20%
    max_latency_p99: 2000  # milliseconds
    max_cache_staleness: 300  # seconds
    
  constrained:
    max_error_rate: 50.0  # 50%
    max_latency_p99: 10000  # milliseconds
    max_cache_staleness: 1800  # seconds
```

### Operation Risk Levels

Define operation risk levels in `config/operation_risks.yaml`:

```yaml
operation_risks:
  read_own_data: LOW
  read_shared_data: MEDIUM
  write_own_data: MEDIUM
  write_shared_data: HIGH
  delete: CRITICAL
  admin: CRITICAL
  share: CRITICAL
```

### Monitoring & Alerting

Configure alerts in `config/alerts.yaml`:

```yaml
alerts:
  - name: trust_degraded_to_constrained
    condition: trust_level == CONSTRAINED
    severity: HIGH
    message: "Security in constrained mode - only read operations allowed"
    
  - name: authorization_correctness_low
    condition: authorization_correctness_rate < 0.95
    window: 5min
    severity: HIGH
    message: "Authorization correctness below 95%"
    
  - name: privilege_escalation_detected
    condition: privilege_escalation.successful > 0
    severity: CRITICAL
    message: "Privilege escalation not blocked"
```

## Testing

### Unit Tests

```bash
# Run all tests
pytest tests/

# Run specific pattern tests
pytest tests/test_graduated_trust.py
pytest tests/test_retry_safe_auth.py
pytest tests/test_security_invariants.py

# Run with coverage
pytest --cov=patterns tests/
```

### Integration Tests

```bash
# Run integration tests
pytest tests/integration/

# Test failure scenarios
pytest tests/integration/test_failure_scenarios.py
```

### Chaos Testing

Use the provided chaos testing tools to validate behavior under failures:

```bash
# Inject latency into auth service
python tools/chaos/inject_latency.py --service auth --latency 2000

# Inject errors into auth service
python tools/chaos/inject_errors.py --service auth --error_rate 0.25

# Simulate network partition
python tools/chaos/partition.py --duration 60
```

## Monitoring & Dashboards

### Grafana Dashboards

Import the provided Grafana dashboards:

1. **Security Health Dashboard** (`dashboards/security_dashboard.json`)
   - Trust level distribution
   - Authorization correctness
   - Privilege escalation attempts
   - Cache staleness

2. **Trust Level Timeline** (`dashboards/trust_timeline.json`)
   - Trust level transitions over time
   - Degradation triggers
   - Recovery patterns

### Metrics Exported

The patterns export the following metrics (Prometheus format):

```
# Trust level
security_trust_level{level="NORMAL|DEGRADED|CONSTRAINED|NO_TRUST"}

# Authorization decisions
security_authorization_decisions_total{trust_level="...", correct="true|false"}

# Privilege escalations
security_privilege_escalation_attempts_total{blocked="true|false"}

# Invariant violations
security_invariant_checks_total{invariant="...", passed="true|false", severity="..."}

# Audit operations
audit_operations_total{service="primary|fallback", success="true|false"}
```

## Production Deployment

### Prerequisites

- Python 3.8+
- Redis (for token storage)
- Metrics backend (Prometheus/Datadog/etc.)
- Audit storage (database, S3, etc.)

### Deployment Checklist

- [ ] Configure trust level thresholds for your environment
- [ ] Set up metrics collection and dashboards
- [ ] Configure alerting rules
- [ ] Test in staging with chaos engineering
- [ ] Deploy trust monitoring in observation mode (Week 2-3)
- [ ] Enable graduated trust for reads (Week 4-5)
- [ ] Deploy retry-safe authorization (Week 6)
- [ ] Enable security invariants (Week 7)
- [ ] Deploy audit resilience (Week 8)
- [ ] Monitor and tune thresholds based on production data

### Performance Considerations

**Latency Overhead:**
- Trust level evaluation: ~0.5ms
- Invariant checking: ~0.8ms
- Token generation/validation: ~0.5ms
- **Total overhead: 8-10%**

**Memory Requirements:**
- Token store: ~1KB per active token
- Trust metrics: ~10KB per service
- **Total: Minimal (<100MB for large deployments)**

**Throughput:**
- Tested at 50,000+ requests/second
- Scales linearly with number of instances
- No centralized bottlenecks

## Common Pitfalls

### 1. Over-Aggressive Trust Degradation

**Problem:** Trust level degrades too quickly, blocking legitimate operations.

**Solution:** Add hysteresis and require multiple confirmations for degradation.

```python
trust_monitor = TrustMonitor(
    min_level_duration=30,  # seconds
    degradation_confirmations=3
)
```

### 2. Insufficient Privilege Granularity

**Problem:** Trust levels allow too many or too few operations.

**Solution:** Define fine-grained operation risk levels (see `config/operation_risks.yaml`).

### 3. Ignoring Cache Invalidation

**Problem:** Cached authorization doesn't invalidate when permissions change.

**Solution:** Implement active cache invalidation on permission changes.

```python
# Invalidate cache on permission changes
auth_cache.invalidate_user(user_id)
auth_cache.invalidate_resource(resource_id)
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Application Layer                       │
│  ┌────────────┐  ┌─────────────┐  ┌────────────────────┐   │
│  │  Service A  │  │  Service B  │  │     Service C      │   │
│  └─────┬──────┘  └──────┬──────┘  └──────────┬─────────┘   │
└────────┼─────────────────┼──────────────────────┼───────────┘
         │                 │                      │
         └─────────────────┼──────────────────────┘
                           │
         ┌─────────────────▼──────────────────────┐
         │     Trust-Aware Authorizer             │
         │  ┌──────────────────────────────────┐  │
         │  │      Trust Monitor               │  │
         │  │  (Graduated Trust Levels)        │  │
         │  └──────────────────────────────────┘  │
         │  ┌──────────────────────────────────┐  │
         │  │  Retry-Safe Authorizer           │  │
         │  │  (Idempotency Tokens)            │  │
         │  └──────────────────────────────────┘  │
         │  ┌──────────────────────────────────┐  │
         │  │  Invariant Checker               │  │
         │  │  (Runtime Guarantees)            │  │
         │  └──────────────────────────────────┘  │
         └─────────────────┬──────────────────────┘
                           │
         ┌─────────────────▼──────────────────────┐
         │      Infrastructure Layer              │
         │  ┌───────────┐  ┌──────────┐  ┌──────┐│
         │  │ Auth      │  │  Cache   │  │Audit ││
         │  │ Service   │  │  (Redis) │  │Store ││
         │  └───────────┘  └──────────┘  └──────┘│
         └────────────────────────────────────────┘
```


### Areas for Contribution

- Additional security invariants
- Support for more metrics backends
- Integration examples for popular frameworks
- Performance optimizations
- Additional chaos testing scenarios

## Support

- **Issues**: [GitHub Issues](https://github.com/sandsvinjam/failure-aware-security/issues)
- **Discussions**: [GitHub Discussions](https://github.com/sandsvinjam/failure-aware-security/discussions)
- **Article**: [InfoQ Article](https://www.infoq.com/) (full context and explanation)

## License

MIT License - see [LICENSE](LICENSE) for details.

## Citation

If you use these patterns in your research or production systems, please cite:

```bibtex
@article{vinjam2025failure,
  title={Why Your Distributed System's Security Breaks During Failures (And How to Fix It)},
  author={Vinjam, Sandhya},
  journal={InfoQ},
  year={2025},
  url={https://github.com/sandsvinjam/failure-aware-security}
}
```

## Acknowledgments

These patterns were developed and validated through production deployments, protecting systems handling 50,000+ authorization requests.


## Related Work

- [Hystrix](https://github.com/Netflix/Hystrix) - Circuit breaker pattern
- [Resilience4j](https://github.com/resilience4j/resilience4j) - Fault tolerance library
- [Open Policy Agent](https://www.openpolicyagent.org/) - Policy-based authorization

This work extends traditional fault tolerance patterns to specifically address security concerns during partial failures.

---

**Author:** Sandhya Vinjam, Principal Software Engineer 
https://www.linkedin.com/in/sandhyavinjam/
