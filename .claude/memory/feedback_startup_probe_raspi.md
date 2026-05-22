---
name: startupProbe for slow Spring Boot on Raspberry Pi
description: Spring Boot takes 70s+ to start on raspi hardware; use startupProbe not initialDelaySeconds
type: feedback
---

Always use `startupProbe` for Spring Boot services on this cluster. Spring Boot takes ~70s to start on Raspberry Pi hardware. Using `initialDelaySeconds` on liveness is fragile — the probe fires before startup completes and Kubernetes kills the pod.

**Why:** auth-service and device-service both crashed in CrashLoopBackOff on 2026-04-14 because liveness fired at 60s (initialDelaySeconds=30 + 3×10s) before the 70s startup finished.

**How to apply:** Use this pattern for every Spring Boot service:
```yaml
startupProbe:
  httpGet:
    path: /actuator/health
    port: <port>
  failureThreshold: 30
  periodSeconds: 5        # allows up to 150s for startup
livenessProbe:
  httpGet:
    path: /actuator/health
    port: <port>
  periodSeconds: 10
  failureThreshold: 3
readinessProbe:
  httpGet:
    path: /actuator/health
    port: <port>
  periodSeconds: 5
  failureThreshold: 3
```
