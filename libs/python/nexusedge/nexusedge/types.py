"""
NexusEdge Python SDK - Data Models & Types
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional

RoutingStrategy = Literal[
    "LATENCY_OPTIMAL",
    "COST_MINIMAL",
    "CARBON_NEUTRAL",
    "SOVEREIGN_PINNED"
]

Jurisdiction = Literal["BD", "EU", "US", "GLOBAL"]


@dataclass
class ChatMessage:
    role: str
    content: str


@dataclass
class CompletionTelemetry:
    provider: Optional[str] = None
    cost: Optional[float] = None
    ttft_ms: Optional[int] = None
    region: Optional[str] = None


@dataclass
class CompletionChoice:
    index: int
    message: ChatMessage
    finish_reason: Optional[str] = None


@dataclass
class CompletionUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


@dataclass
class CompletionResponse:
    model: str
    choices: List[CompletionChoice]
    telemetry: CompletionTelemetry
    id: Optional[str] = None
    object: str = "chat.completion"
    created: int = 0
    usage: Optional[CompletionUsage] = None


@dataclass
class DomainRecord:
    id: str
    project_id: str
    hostname: str
    status: str
    cname_target: Optional[str] = None
    origin_address: Optional[str] = None
    origin_port: Optional[int] = None
    origin_protocol: Optional[str] = None
    allowed_pops: List[str] = field(default_factory=list)
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


@dataclass
class OnboardDomainResult:
    domain_id: str
    hostname: str
    cname_target: str
    verification_token: str
    status: str
    allowed_pops: List[str] = field(default_factory=list)


@dataclass
class VerifyDomainResult:
    status: str
    domain_id: str
    hostname: str
    state: str
    message: Optional[str] = None


@dataclass
class TelemetryRateLimit:
    limit: int
    remaining: int


@dataclass
class TelemetrySummary:
    project_id: str
    total_requests: int
    p50_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    cache_hit_ratio: float
    threat_blocks: int
    success_rate: float
    status_distribution: Dict[str, int] = field(default_factory=dict)
    pop_distribution: Dict[str, int] = field(default_factory=dict)
    rate_limit: Optional[TelemetryRateLimit] = None


@dataclass
class PoPHealthRecord:
    id: str
    name: str
    region: str
    status: str
    latency_p50_ms: float
    capacity_used_pct: float
    anycast_announced: bool


@dataclass
class LatencyMatrixRoute:
    from_pop: str
    latency_ms: float
    to_pop: Optional[str] = None
    to_target: Optional[str] = None
    status: Optional[str] = None


@dataclass
class LatencyMatrixResult:
    routes: List[LatencyMatrixRoute] = field(default_factory=list)
    timestamp: Optional[str] = None


@dataclass
class SovereignEvaluationResult:
    allowed: bool
    decision_code: str
    reason: str
    source_jurisdiction: str
    target_jurisdiction: str
    data_classification: str
    enforced_law: Optional[str] = None
    evaluated_at: Optional[str] = None


@dataclass
class SchedulingDecision:
    workload_id: str
    status: str
    reason: str
    assigned_node: Optional[str] = None
    provider: Optional[str] = None
    region: Optional[str] = None
    jurisdiction: Optional[str] = None
    measured_rtt_ms: Optional[int] = None
    hourly_cost: Optional[float] = None
    carbon_gco2_kwh: Optional[float] = None
    carbon_classification: Optional[str] = None
    remaining_node_gpus: Optional[int] = None
    optimization_score: Optional[float] = None
    evaluated_at: Optional[str] = None


@dataclass
class ComputeNodeRecord:
    node_id: str
    provider: str
    region: str
    jurisdiction: str
    gpu_type: str
    total_gpus: int
    available_gpus: int
    cost_per_gpu_hour: float
    carbon_intensity: float
    rtt_from_dhaka: int = 0
    rtt_from_frankfurt: int = 0
    rtt_from_virginia: int = 0
    rtt_from_singapore: int = 0
    kv_cache_warmth: float = 0.0

