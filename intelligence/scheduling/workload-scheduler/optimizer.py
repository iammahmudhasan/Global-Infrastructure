"""
NexusEdge Intelligence Plane: Multi-Objective Workload Placement Optimizer
Calculates: WHERE should every application, AI inference request, and compute workload run right now?

Objectives:
  1. Minimize Network Latency (RTT to user/agent)
  2. Minimize Operational Cost ($ per token / compute hour)
  3. Minimize Carbon & Grid Power Constraints (gCO2eq/kWh)
  4. Maximize KV-Cache Warmth & GPU Memory Locality
  5. Enforce Strict Data Sovereignty (e.g. Bangladesh NDMA 2026, EU GDPR)
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
import json
import math
import os
import urllib.request
import urllib.error

@dataclass
class ComputeNode:
    node_id: str
    provider: str         # "baremetal-bd", "coreweave", "aws", "gcp", "iceland-green-dc"
    region: str           # "ap-south-2", "us-east-1", "eu-central-1", "is-north-1"
    jurisdiction: str     # "BD", "US", "EU", "IS"
    gpu_type: str         # "H100", "B200", "L40S"
    available_gpus: int
    cost_per_gpu_hour: float
    carbon_intensity: float  # gCO2/kWh (Grid power metric)
    rtt_ms_from_dhaka: int
    rtt_ms_from_frankfurt: int
    rtt_ms_from_virginia: int
    rtt_ms_from_singapore: int = 100
    kv_cache_warmth: float = 0.0  # 0.0 to 1.0 (is model/prefix already loaded)
    live_latency_overrides: Dict[str, float] = field(default_factory=dict)

@dataclass
class WorkloadRequirement:
    workload_id: str
    workload_type: str       # "GPU_INFERENCE", "BANKING_API", "REASONING_AGENT"
    client_origin: str       # "dhaka", "frankfurt", "virginia", "singapore"
    required_jurisdiction: Optional[str] # e.g. "BD" for Bangladesh National Data Act
    strict_sovereignty: bool
    max_latency_p95_ms: int
    max_cost_per_hour: float
    gpus_requested: int = 1
    prioritize_green_energy: bool = False
    tenant_id: str = "tenant-default"
    project_id: str = "proj-default"

class GlobalScheduler:
    def __init__(self, nodes: List[ComputeNode]):
        self.nodes = nodes
        self.active_workloads: Dict[str, str] = {} # workload_id -> node_id
        self.idempotency_cache: Dict[str, Dict] = {} # tenant:proj:key -> decision
        self.live_pop_health: Dict[str, Dict[str, Any]] = {}

    def update_live_telemetry(self, pop_health: Dict[str, Dict[str, Any]]) -> None:
        """
        Updates live PoP health states and measured EWMA latencies.
        If a PoP is marked unhealthy or draining, origin routes may experience failover transit penalty.
        """
        self.live_pop_health = pop_health

    def fetch_live_telemetry(self, control_plane_url: Optional[str] = None, auth_token: Optional[str] = None) -> bool:
        """
        Pulls live telemetry from Config Controller REST API (/v1/edge/pops/health).
        Fails safely with deterministic fallback if the control plane is offline (Rules 28-30).
        """
        url = control_plane_url or os.getenv("NEXUSEDGE_CONFIG_CONTROLLER_ENDPOINT") or os.getenv("NEXUSEDGE_CP_ENDPOINT") or "http://127.0.0.1:9091"
        token = auth_token or os.getenv("NEXUSEDGE_CP_AUTH_TOKEN") or "dev-fixture-key-01"
        endpoint = f"{url.rstrip('/')}/v1/edge/pops/health"

        try:
            req = urllib.request.Request(endpoint, headers={
                "Authorization": f"Bearer {token}",
                "User-Agent": "NexusEdge-Optimizer/1.0"
            })
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    pops_list = data.get("pops", [])
                    health_map = {p["pop_id"]: p for p in pops_list}
                    self.update_live_telemetry(health_map)
                    return True
        except Exception:
            # Deterministic offline fallback
            pass
        return False

    def find_optimal_placement(self, req: WorkloadRequirement) -> Dict:
        # 0. Scoped Idempotency Check (Finding 16)
        idempotency_key = f"{req.tenant_id}:{req.project_id}:{req.workload_id}"
        if idempotency_key in self.idempotency_cache:
            return self.idempotency_cache[idempotency_key]

        candidates = []

        client_origin = req.client_origin.lower()
        live_pop = self.live_pop_health.get(client_origin)

        for node in self.nodes:
            # 1. Capacity check with requested GPUs (Finding 16)
            if node.available_gpus < req.gpus_requested:
                continue

            # 2. Strict Sovereignty Constraint (Hard Legal Boundary)
            if req.strict_sovereignty and req.required_jurisdiction:
                if node.jurisdiction != req.required_jurisdiction:
                    continue

            # 3. Latency Upper Bound Check (Hard SLA Constraint with Live Telemetry)
            if live_pop and not live_pop.get("healthy", True):
                # Origin PoP is degraded/cut - apply subsea failover transit penalty (TAT-14 / SMW6)
                base_rtt = getattr(node, f"rtt_ms_from_{client_origin}", 100)
                rtt = base_rtt + 78
            elif client_origin in node.live_latency_overrides:
                rtt = node.live_latency_overrides[client_origin]
            else:
                rtt = getattr(node, f"rtt_ms_from_{client_origin}", 100)

            if req.max_latency_p95_ms > 0 and rtt > req.max_latency_p95_ms:
                continue

            # 4. Budget Constraint Check
            if req.max_cost_per_hour > 0 and node.cost_per_gpu_hour > req.max_cost_per_hour:
                continue

            candidates.append((node, rtt))

        if not candidates:
            return {
                "error": "No available node satisfies constraints or capacity exhausted",
                "workload_id": req.workload_id,
                "status": "UNSCHEDULABLE"
            }

        # Multi-Objective Optimization Scoring Function (Lower Score is Better)
        best_node = None
        best_score = float("inf")
        best_rtt = 0

        w_lat = 1.0
        w_cost = 10.0
        w_carbon = 0.5 if req.prioritize_green_energy else 0.05
        w_kv = 30.0

        for node, rtt in candidates:
            score = (w_lat * rtt) + (w_cost * node.cost_per_gpu_hour) + (w_carbon * node.carbon_intensity) - (w_kv * node.kv_cache_warmth)
            
            # Sovereign locality bonus
            if req.required_jurisdiction and node.jurisdiction == req.required_jurisdiction:
                score -= 50.0

            if score < best_score:
                best_score = score
                best_node = node
                best_rtt = rtt

        # Real Capacity Accounting: decrement available GPUs upon placement (Finding 16)
        best_node.available_gpus -= req.gpus_requested
        self.active_workloads[req.workload_id] = best_node.node_id

        carbon_label = "LOW_CARBON_RENEWABLE_POWER" if best_node.carbon_intensity < 50.0 else "STANDARD_GRID"

        decision = {
            "workload_id": req.workload_id,
            "status": "SCHEDULED",
            "assigned_node": best_node.node_id,
            "provider": best_node.provider,
            "region": best_node.region,
            "jurisdiction": best_node.jurisdiction,
            "measured_rtt_ms": best_rtt,
            "hourly_cost": best_node.cost_per_gpu_hour,
            "carbon_gco2_kwh": best_node.carbon_intensity,
            "carbon_classification": carbon_label,
            "remaining_node_gpus": best_node.available_gpus,
            "optimization_score": round(best_score, 2),
            "reason": f"Optimized via Intelligence Plane (RTT: {best_rtt}ms, Cost: ${best_node.cost_per_gpu_hour}/h, Sovereignty: {best_node.jurisdiction}, Power: {carbon_label})"
        }

        self.idempotency_cache[idempotency_key] = decision
        return decision

if __name__ == "__main__":
    # Testbed topology across 4 strategic regions
    nodes = [
        ComputeNode("bd-dhaka-dgx01", "baremetal-bd", "ap-south-2", "BD", "H100", 8, 2.10, 480.0, 4, 130, 210, 32, 0.9),
        ComputeNode("sg-aws-gpu01", "aws", "ap-southeast-1", "SG", "H100", 16, 3.20, 390.0, 32, 115, 180, 8, 0.5),
        ComputeNode("is-green-gpu01", "iceland-green-dc", "is-north-1", "IS", "H100", 32, 1.45, 12.0, 160, 35, 75, 145, 0.2),
        ComputeNode("us-cw-h100-iad", "coreweave", "us-east-1", "US", "H100", 64, 1.85, 340.0, 210, 85, 8, 180, 0.8),
    ]

    scheduler = GlobalScheduler(nodes)

    print("=== TEST 1: Bangladesh Banking Workload (NDMA 2026 Strict Sovereignty) ===")
    banking_job = WorkloadRequirement(
        workload_id="fintech-cbr-01",
        workload_type="BANKING_API",
        client_origin="dhaka",
        required_jurisdiction="BD",
        strict_sovereignty=True,
        max_latency_p95_ms=20,
        max_cost_per_hour=5.0
    )
    print(scheduler.find_optimal_placement(banking_job))

    print("\n=== TEST 2: Global Batch Reasoning LLM (Green Power & Low Cost Prioritized) ===")
    global_ai_batch = WorkloadRequirement(
        workload_id="reasoning-batch-99",
        workload_type="GPU_INFERENCE",
        client_origin="frankfurt",
        required_jurisdiction=None,
        strict_sovereignty=False,
        max_latency_p95_ms=200,
        max_cost_per_hour=2.0,
        prioritize_green_energy=True
    )
    print(scheduler.find_optimal_placement(global_ai_batch))

    print("\n=== TEST 3: Impossible Latency Budget Rejection (Hard SLA) ===")
    impossible_latency_job = WorkloadRequirement(
        workload_id="impossible-lat-01",
        workload_type="LOW_LATENCY_API",
        client_origin="frankfurt",
        required_jurisdiction=None,
        strict_sovereignty=False,
        max_latency_p95_ms=5,
        max_cost_per_hour=10.0
    )
    res_lat = scheduler.find_optimal_placement(impossible_latency_job)
    print(res_lat)
    assert res_lat["status"] == "UNSCHEDULABLE", f"Expected UNSCHEDULABLE, got {res_lat['status']}"

    print("\n=== TEST 4: Strict Sovereignty with Latency Bound Exceeded ===")
    sovereign_violating_job = WorkloadRequirement(
        workload_id="fintech-latency-violation",
        workload_type="BANKING_API",
        client_origin="dhaka",
        required_jurisdiction="BD",
        strict_sovereignty=True,
        max_latency_p95_ms=2,  # Node has 4ms RTT from dhaka
        max_cost_per_hour=5.0
    )
    res_sov = scheduler.find_optimal_placement(sovereign_violating_job)
    print(res_sov)
    assert res_sov["status"] == "UNSCHEDULABLE", f"Expected UNSCHEDULABLE, got {res_sov['status']}"

    print("\n=== TEST 5: Live Telemetry Subsea Failover Rerouting ===")
    # Simulate Frankfurt DE-CIX fiber cut in live telemetry
    scheduler.update_live_telemetry({
        "frankfurt": {
            "pop_id": "frankfurt",
            "healthy": False,
            "status": "POP_DRAINING",
            "failover_pop_id": "virginia",
            "ewma_latency_ms": 140.0
        }
    })
    # Client with tight 50ms SLA in Frankfurt must failover or reject based on subsea penalty
    frankfurt_tight_sla = WorkloadRequirement(
        workload_id="fra-ai-failover-01",
        workload_type="GPU_INFERENCE",
        client_origin="frankfurt",
        required_jurisdiction=None,
        strict_sovereignty=False,
        max_latency_p95_ms=50, # Normally 35ms from is-green-gpu01, but +78ms TAT-14 penalty = 113ms > 50ms
        max_cost_per_hour=5.0
    )
    res_failover = scheduler.find_optimal_placement(frankfurt_tight_sla)
    print(res_failover)
    assert res_failover["status"] == "UNSCHEDULABLE", "Expected SLA violation due to subsea cable failure"

    print("\n=== TEST 6: Singapore Origin Workload Placement ===")
    sg_job = WorkloadRequirement(
        workload_id="sg-inference-01",
        workload_type="GPU_INFERENCE",
        client_origin="singapore",
        required_jurisdiction=None,
        strict_sovereignty=False,
        max_latency_p95_ms=50,
        max_cost_per_hour=5.0
    )
    res_sg = scheduler.find_optimal_placement(sg_job)
    print(res_sg)
    assert res_sg["status"] == "SCHEDULED" and res_sg["assigned_node"] == "sg-aws-gpu01"

    print("All Python scheduler constraint tests passed.")

