# NexusEdge Python SDK (`nexusedge`)

Official, zero-dependency Python client library for the **NexusEdge Global Infrastructure & Multi-Objective AI Orchestration Platform**.

## Installation

```bash
pip install nexusedge
```

## Quick Start

### 1. Multi-Objective AI Inference

```python
from nexusedge import NexusEdgeClient

client = NexusEdgeClient(api_key="nke_live_your_api_key_here")

# Direct inference with sovereign routing and cost telemetry
response = client.inference.create_completion(
    model="meta-llama/Llama-3.3-70B-Instruct",
    messages=[
        {"role": "system", "content": "You are a helpful AI assistant."},
        {"role": "user", "content": "What is the capital of Bangladesh?"}
    ],
    routing_strategy="LATENCY_OPTIMAL",
    jurisdiction="BD",
    temperature=0.7,
    max_tokens=512
)

print(response.choices[0].message.content)
print(f"Provider: {response.telemetry.provider}")
print(f"Cost: ${response.telemetry.cost:.6f}")
print(f"TTFT: {response.telemetry.ttft_ms} ms")
```

### 2. Edge Custom Domain Management

```python
# Onboard a custom domain with anycast edge routing
domain = client.domains.onboard(
    hostname="api.mycompany.com",
    origin_address="203.0.113.10",
    origin_port=443,
    origin_protocol="https",
    allowed_pops=["dhaka", "singapore"]
)
print(f"CNAME Target: {domain.cname_target}")
print(f"Verification Token: {domain.verification_token}")

# Verify domain DNS propagation
status = client.domains.verify(domain.domain_id)
print(f"Verification status: {status.state}")
```

### 3. Real-Time Telemetry & Health

```python
# Query sliding-window analytics and rate limit status
telemetry = client.telemetry.get_summary()
print(f"P50 Latency: {telemetry.p50_latency_ms} ms")
print(f"P99 Latency: {telemetry.p99_latency_ms} ms")
print(f"Cache Hit Ratio: {telemetry.cache_hit_ratio * 100:.1f}%")

# Query global PoP health and BGP announcement states
health = client.telemetry.get_pop_health()
for pop in health:
    print(f"{pop.name} ({pop.region}): {pop.status} | BGP: {pop.anycast_announced}")
```
