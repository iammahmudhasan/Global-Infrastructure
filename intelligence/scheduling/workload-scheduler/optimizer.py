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

from dataclasses import dataclass
from typing import List, Optional, Dict
import math

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
    kv_cache_warmth: float   # 0.0 to 1.0 (is model/prefix already loaded)

@dataclass
class WorkloadRequirement:
    workload_id: str
    workload_type: str       # "GPU_INFERENCE", "BANKING_API", "REASONING_AGENT"
    client_origin: str       # "dhaka", "frankfurt", "virginia"
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

    def find_optimal_placement(self, req: WorkloadRequirement) -> Dict:
        # 0. Scoped Idempotency Check (Finding 16)
        idempotency_key = f"{req.tenant_id}:{req.project_id}:{req.workload_id}"
        if idempotency_key in self.idempotency_cache:
            return self.idempotency_cache[idempotency_key]

        candidates = []

        for node in self.nodes:
            # 1. Capacity check with requested GPUs (Finding 16)
            if node.available_gpus < req.gpus_requested:
                continue

            # 2. Strict Sovereignty Constraint (Hard Legal Boundary)
            if req.strict_sovereignty and req.required_jurisdiction:
                if node.jurisdiction != req.required_jurisdiction:
                    continue

            # 3. Latency Upper Bound Check
            rtt = getattr(node, f"rtt_ms_from_{req.client_origin}", 100)
            if req.max_latency_p95_ms > 0 and rtt > req.max_latency_p95_ms:
                if not req.strict_sovereignty:
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
    # Testbed topology
    nodes = [
        ComputeNode("bd-dhaka-dgx01", "baremetal-bd", "ap-south-2", "BD", "H100", 8, 2.10, 480.0, 4, 130, 210, 0.9),
        ComputeNode("sg-aws-gpu01", "aws", "ap-southeast-1", "SG", "H100", 16, 3.20, 390.0, 32, 115, 180, 0.5),
        ComputeNode("is-green-gpu01", "iceland-green-dc", "is-north-1", "IS", "H100", 32, 1.45, 12.0, 160, 35, 75, 0.2),
        ComputeNode("us-cw-h100-iad", "coreweave", "us-east-1", "US", "H100", 64, 1.85, 340.0, 210, 85, 8, 0.8),
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
