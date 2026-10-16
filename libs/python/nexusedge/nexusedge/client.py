"""
NexusEdge Python SDK - Client Implementation
Zero-dependency, strictly-typed client for Global Infrastructure,
Multi-Objective AI Orchestration, Custom Domains, and Telemetry.
"""

from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple, Union

from .exceptions import NexusEdgeError
from .types import (
    ChatMessage,
    CompletionChoice,
    CompletionResponse,
    CompletionTelemetry,
    CompletionUsage,
    DomainRecord,
    Jurisdiction,
    LatencyMatrixResult,
    LatencyMatrixRoute,
    OnboardDomainResult,
    PoPHealthRecord,
    RoutingStrategy,
    TelemetryRateLimit,
    TelemetrySummary,
    VerifyDomainResult,
    SovereignEvaluationResult,
    SchedulingDecision,
    ComputeNodeRecord,
)


class NexusEdgeClient:
    """Official NexusEdge API Client."""

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://dashboard.aeitron.com",
        timeout_seconds: float = 30.0,
    ) -> None:
        if not api_key or not isinstance(api_key, str) or not api_key.strip():
            raise NexusEdgeError(400, "NexusEdgeClient requires a valid API key (e.g., nke_live_...)", "INVALID_API_KEY")

        self.api_key: str = api_key.strip()
        self.base_url: str = base_url.rstrip("/")
        self.timeout_seconds: float = max(0.1, float(timeout_seconds))

        self.inference = InferenceNamespace(self)
        self.domains = DomainsNamespace(self)
        self.telemetry = TelemetryNamespace(self)
        self.scheduler = SchedulerNamespace(self)
        self.policies = PoliciesNamespace(self)

    def request(
        self,
        endpoint: str,
        method: str = "GET",
        body: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[Any, Dict[str, str]]:
        """Executes an authenticated HTTP request against NexusEdge APIs."""
        endpoint = endpoint if endpoint.startswith("/") else f"/{endpoint}"
        full_url = f"{self.base_url}{endpoint}"

        req_headers: Dict[str, str] = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.api_key}",
            "X-API-Key": self.api_key,
            "User-Agent": "NexusEdge-Python-SDK/0.1.0",
        }
        if headers:
            req_headers.update(headers)

        req_data: Optional[bytes] = None
        if body is not None:
            req_headers["Content-Type"] = "application/json"
            req_data = json.dumps(body).encode("utf-8")

        req = urllib.request.Request(full_url, data=req_data, headers=req_headers, method=method.upper())

        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                resp_bytes = resp.read()
                raw_headers = dict(resp.headers.items())
                norm_headers = {k.lower(): v for k, v in raw_headers.items()}

                if not resp_bytes:
                    return None, norm_headers

                try:
                    parsed_json = json.loads(resp_bytes.decode("utf-8"))
                except Exception:
                    parsed_json = {"raw": resp_bytes.decode("utf-8", errors="replace")}

                return parsed_json, norm_headers

        except urllib.error.HTTPError as e:
            err_bytes = e.read()
            err_json: Any = None
            if err_bytes:
                try:
                    err_json = json.loads(err_bytes.decode("utf-8"))
                except Exception:
                    err_json = {"raw": err_bytes.decode("utf-8", errors="replace")}

            msg = f"HTTP {e.code}: {e.reason}"
            code: Union[str, int] = e.code
            if isinstance(err_json, dict):
                msg = err_json.get("error") or err_json.get("message") or msg
                code = err_json.get("code") or err_json.get("error_code") or code

            raise NexusEdgeError(e.code, str(msg), code=code, details=err_json) from e

        except (socket.timeout, TimeoutError) as e:
            raise NexusEdgeError(504, f"Request timed out after {self.timeout_seconds}s", "TIMEOUT") from e

        except urllib.error.URLError as e:
            if isinstance(e.reason, (socket.timeout, TimeoutError)):
                raise NexusEdgeError(504, f"Request timed out after {self.timeout_seconds}s", "TIMEOUT") from e
            raise NexusEdgeError(500, f"Network request failed: {e.reason}", "NETWORK_ERROR") from e

        except Exception as e:
            raise NexusEdgeError(500, str(e), "CLIENT_ERROR") from e


class InferenceNamespace:
    """Namespace for Multi-Objective AI Inference routing."""

    def __init__(self, client: NexusEdgeClient) -> None:
        self._client = client

    def create_completion(
        self,
        messages: List[Union[ChatMessage, Dict[str, str]]],
        model: str = "meta-llama/Llama-3.3-70B-Instruct",
        routing_strategy: Optional[RoutingStrategy] = None,
        jurisdiction: Optional[Jurisdiction] = None,
        temperature: float = 0.7,
        max_tokens: int = 1024,
    ) -> CompletionResponse:
        """Executes multi-objective LLM inference through NexusEdge Edge Gateway."""
        if not messages or not isinstance(messages, list):
            raise NexusEdgeError(400, "create_completion requires a non-empty messages list", "INVALID_PARAMS")

        formatted_messages = []
        for msg in messages:
            if isinstance(msg, ChatMessage):
                formatted_messages.append({"role": msg.role, "content": msg.content})
            elif isinstance(msg, dict):
                formatted_messages.append({"role": msg.get("role", "user"), "content": msg.get("content", "")})
            else:
                raise NexusEdgeError(400, "Invalid message item; must be ChatMessage or dict", "INVALID_PARAMS")

        extra_headers: Dict[str, str] = {}
        if routing_strategy:
            extra_headers["X-NexusEdge-Routing-Strategy"] = routing_strategy
        if jurisdiction:
            extra_headers["X-NexusEdge-Jurisdiction"] = jurisdiction

        payload = {
            "model": model,
            "messages": formatted_messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        data, headers = self._client.request(
            "/api/proxy/inference",
            method="POST",
            body=payload,
            headers=extra_headers,
        )

        cost_hdr = headers.get("x-nexusedge-cost")
        ttft_hdr = headers.get("x-nexusedge-ttft-ms")

        telemetry = CompletionTelemetry(
            provider=headers.get("x-nexusedge-provider"),
            cost=float(cost_hdr) if cost_hdr is not None else None,
            ttft_ms=int(ttft_hdr) if ttft_hdr is not None else None,
            region=headers.get("x-nexusedge-region"),
        )

        choices_raw = data.get("choices", []) if isinstance(data, dict) else []
        choices: List[CompletionChoice] = []
        for item in choices_raw:
            msg_raw = item.get("message", {})
            choice = CompletionChoice(
                index=item.get("index", 0),
                message=ChatMessage(
                    role=msg_raw.get("role", "assistant"),
                    content=msg_raw.get("content", ""),
                ),
                finish_reason=item.get("finish_reason"),
            )
            choices.append(choice)

        usage_raw = data.get("usage") if isinstance(data, dict) else None
        usage = None
        if isinstance(usage_raw, dict):
            usage = CompletionUsage(
                prompt_tokens=usage_raw.get("prompt_tokens", 0),
                completion_tokens=usage_raw.get("completion_tokens", 0),
                total_tokens=usage_raw.get("total_tokens", 0),
            )

        return CompletionResponse(
            id=data.get("id") if isinstance(data, dict) else None,
            object=data.get("object", "chat.completion") if isinstance(data, dict) else "chat.completion",
            created=data.get("created", int(time.time())) if isinstance(data, dict) else int(time.time()),
            model=data.get("model", model) if isinstance(data, dict) else model,
            choices=choices,
            usage=usage,
            telemetry=telemetry,
        )


class DomainsNamespace:
    """Namespace for Custom Edge Domain Onboarding & Verification."""

    def __init__(self, client: NexusEdgeClient) -> None:
        self._client = client

    def list(self) -> List[DomainRecord]:
        """Lists all registered edge domains for the active project."""
        data, _ = self._client.request("/api/proxy/domains", method="GET")
        domains_list = data.get("domains", []) if isinstance(data, dict) else []
        results: List[DomainRecord] = []
        for d in domains_list:
            results.append(
                DomainRecord(
                    id=d.get("id", ""),
                    project_id=d.get("project_id", ""),
                    hostname=d.get("hostname", ""),
                    status=d.get("status", "PENDING"),
                    cname_target=d.get("cname_target"),
                    origin_address=d.get("origin_address"),
                    origin_port=d.get("origin_port"),
                    origin_protocol=d.get("origin_protocol"),
                    allowed_pops=d.get("allowed_pops", []),
                    created_at=d.get("created_at"),
                    updated_at=d.get("updated_at"),
                )
            )
        return results

    def onboard(
        self,
        hostname: str,
        origin_address: str,
        origin_port: int = 443,
        origin_protocol: str = "https",
        allowed_pops: Optional[List[str]] = None,
    ) -> OnboardDomainResult:
        """Onboards a custom hostname onto the NexusEdge Anycast Network."""
        if not hostname or not origin_address:
            raise NexusEdgeError(400, "onboard requires hostname and origin_address", "INVALID_PARAMS")

        payload = {
            "hostname": hostname.strip().lower(),
            "origin_address": origin_address.strip(),
            "origin_port": origin_port,
            "origin_protocol": origin_protocol,
            "allowed_pops": allowed_pops or ["dhaka", "singapore", "frankfurt", "virginia"],
        }

        data, _ = self._client.request("/api/proxy/domains", method="POST", body=payload)
        return OnboardDomainResult(
            domain_id=data.get("domain_id", ""),
            hostname=data.get("hostname", hostname),
            cname_target=data.get("cname_target", ""),
            verification_token=data.get("verification_token", ""),
            status=data.get("status", "PENDING_VERIFICATION"),
            allowed_pops=data.get("allowed_pops", []),
        )

    def get(self, domain_id: str) -> DomainRecord:
        """Retrieves details of a specific edge domain."""
        if not domain_id:
            raise NexusEdgeError(400, "domain_id is required", "INVALID_PARAMS")

        escaped = urllib.parse.quote(domain_id)
        d, _ = self._client.request(f"/api/proxy/domains/{escaped}", method="GET")
        return DomainRecord(
            id=d.get("id", domain_id),
            project_id=d.get("project_id", ""),
            hostname=d.get("hostname", ""),
            status=d.get("status", ""),
            cname_target=d.get("cname_target"),
            origin_address=d.get("origin_address"),
            origin_port=d.get("origin_port"),
            origin_protocol=d.get("origin_protocol"),
            allowed_pops=d.get("allowed_pops", []),
            created_at=d.get("created_at"),
            updated_at=d.get("updated_at"),
        )

    def verify(self, domain_id: str, force: bool = False) -> VerifyDomainResult:
        """Triggers DNS CNAME and TLS verification for an edge domain."""
        if not domain_id:
            raise NexusEdgeError(400, "domain_id is required", "INVALID_PARAMS")

        escaped = urllib.parse.quote(domain_id)
        query = "?force=true" if force else ""
        data, _ = self._client.request(f"/api/proxy/domains/{escaped}/verify{query}", method="POST")
        return VerifyDomainResult(
            status=data.get("status", "ok"),
            domain_id=data.get("domain_id", domain_id),
            hostname=data.get("hostname", ""),
            state=data.get("state", ""),
            message=data.get("message"),
        )

    def delete(self, domain_id: str) -> Dict[str, Any]:
        """Deletes an onboarded domain from the edge network."""
        if not domain_id:
            raise NexusEdgeError(400, "domain_id is required", "INVALID_PARAMS")

        escaped = urllib.parse.quote(domain_id)
        data, _ = self._client.request(f"/api/proxy/domains/{escaped}", method="DELETE")
        return data if isinstance(data, dict) else {"status": "deleted", "domain_id": domain_id}


class TelemetryNamespace:
    """Namespace for Telemetry, Sliding-Window Analytics, and PoP Health."""

    def __init__(self, client: NexusEdgeClient) -> None:
        self._client = client

    def get_summary(self, project_id: Optional[str] = None) -> TelemetrySummary:
        """Retrieves aggregated sliding-window metrics and rate limit status."""
        query = f"?project_id={urllib.parse.quote(project_id)}" if project_id else ""
        data, _ = self._client.request(f"/api/proxy/analytics/summary{query}", method="GET")

        rl_raw = data.get("rate_limit") if isinstance(data, dict) else None
        rate_limit = None
        if isinstance(rl_raw, dict):
            rate_limit = TelemetryRateLimit(
                limit=int(rl_raw.get("limit", 60)),
                remaining=int(rl_raw.get("remaining", 60)),
            )

        return TelemetrySummary(
            project_id=data.get("project_id", ""),
            total_requests=int(data.get("total_requests", 0)),
            p50_latency_ms=float(data.get("p50_latency_ms", 0.0)),
            p95_latency_ms=float(data.get("p95_latency_ms", 0.0)),
            p99_latency_ms=float(data.get("p99_latency_ms", 0.0)),
            cache_hit_ratio=float(data.get("cache_hit_ratio", 0.0)),
            threat_blocks=int(data.get("threat_blocks", 0)),
            success_rate=float(data.get("success_rate", 1.0)),
            status_distribution=data.get("status_distribution", {}),
            pop_distribution=data.get("pop_distribution", {}),
            rate_limit=rate_limit,
        )

    def get_latency_matrix(self) -> LatencyMatrixResult:
        """Retrieves edge-to-edge latency matrix between global PoPs."""
        data, _ = self._client.request("/api/proxy/pops/matrix", method="GET")
        raw_routes = data.get("routes", []) if isinstance(data, dict) else []
        routes: List[LatencyMatrixRoute] = []
        for r in raw_routes:
            routes.append(
                LatencyMatrixRoute(
                    from_pop=r.get("from_pop", ""),
                    latency_ms=float(r.get("latency_ms", 0.0)),
                    to_pop=r.get("to_pop"),
                    to_target=r.get("to_target"),
                    status=r.get("status"),
                )
            )
        return LatencyMatrixResult(
            routes=routes,
            timestamp=data.get("timestamp") if isinstance(data, dict) else None,
        )

    def get_pop_health(self) -> List[PoPHealthRecord]:
        """Retrieves live synthetic probe and BGP announcement status across all PoPs."""
        data, _ = self._client.request("/api/proxy/pops/health", method="GET")
        raw_pops = data.get("pops", []) if isinstance(data, dict) else []
        records: List[PoPHealthRecord] = []
        for p in raw_pops:
            records.append(
                PoPHealthRecord(
                    id=p.get("id") or p.get("pop_id", ""),
                    name=p.get("name", ""),
                    region=p.get("region", ""),
                    status=p.get("status", "ACTIVE"),
                    latency_p50_ms=float(p.get("latency_p50_ms") or p.get("ewma_latency_ms", 0.0)),
                    capacity_used_pct=float(p.get("capacity_used_pct", 0.0)),
                    anycast_announced=bool(p.get("anycast_announced", True)),
                )
            )
        return records


class PoliciesNamespace:
    """Methods for evaluating data residency, sovereignty, and legal compliance."""

    def __init__(self, client: NexusEdgeClient) -> None:
        self._client = client

    def evaluate_sovereignty(
        self,
        tenant_id: str,
        project_id: str,
        workload_id: str,
        source_jurisdiction: str,
        target_jurisdiction: str,
        data_classification: str = "CONFIDENTIAL",
        strict_sovereignty: bool = True,
        target_node_id: Optional[str] = None,
        target_region: Optional[str] = None,
        export_permit_hash: Optional[str] = None,
    ) -> SovereignEvaluationResult:
        """Evaluates whether data flow complies with Bangladesh NDMA 2026, EU GDPR, or local sovereignty laws."""
        payload: Dict[str, Any] = {
            "tenant_id": tenant_id,
            "project_id": project_id,
            "workload_id": workload_id,
            "data_classification": data_classification,
            "source_jurisdiction": source_jurisdiction,
            "target_jurisdiction": target_jurisdiction,
            "strict_sovereignty": strict_sovereignty,
        }
        if target_node_id:
            payload["target_node_id"] = target_node_id
        if target_region:
            payload["target_region"] = target_region
        if export_permit_hash:
            payload["export_permit_hash"] = export_permit_hash

        endpoint = "/api/proxy/policies/sovereignty/evaluate"
        data, _ = self._client.request(endpoint, method="POST", body=payload)
        return SovereignEvaluationResult(
            allowed=bool(data.get("allowed", False)),
            decision_code=str(data.get("decision_code", "")),
            reason=str(data.get("reason", "")),
            source_jurisdiction=str(data.get("source_jurisdiction", source_jurisdiction)),
            target_jurisdiction=str(data.get("target_jurisdiction", target_jurisdiction)),
            data_classification=str(data.get("data_classification", data_classification)),
            enforced_law=data.get("enforced_law"),
            evaluated_at=data.get("evaluated_at"),
        )


class SchedulerNamespace:
    """Methods for multi-objective universal workload scheduling and compute capacity."""

    def __init__(self, client: NexusEdgeClient) -> None:
        self._client = client

    def find_optimal_placement(
        self,
        workload_type: str = "GPU_INFERENCE",
        client_origin: str = "dhaka",
        required_jurisdiction: Optional[str] = None,
        strict_sovereignty: bool = False,
        data_classification: str = "INTERNAL",
        max_latency_p95_ms: int = 150,
        max_cost_per_hour: float = 10.0,
        gpus_requested: int = 1,
        prioritize_green_energy: bool = False,
        tenant_id: str = "tenant-default",
        project_id: str = "proj-default",
        workload_id: Optional[str] = None,
    ) -> SchedulingDecision:
        """Calculates optimal global placement balancing RTT latency, hourly compute cost, carbon, and sovereignty."""
        payload: Dict[str, Any] = {
            "tenant_id": tenant_id,
            "project_id": project_id,
            "workload_id": workload_id or f"wl-sdk-{int(time.time() * 1000)}",
            "workload_type": workload_type,
            "client_origin": client_origin,
            "required_jurisdiction": required_jurisdiction,
            "strict_sovereignty": strict_sovereignty,
            "data_classification": data_classification,
            "max_latency_p95_ms": max_latency_p95_ms,
            "max_cost_per_hour": max_cost_per_hour,
            "gpus_requested": gpus_requested,
            "prioritize_green_energy": prioritize_green_energy,
        }

        endpoint = "/api/proxy/workloads/schedule"
        data, _ = self._client.request(endpoint, method="POST", body=payload)
        return SchedulingDecision(
            workload_id=str(data.get("workload_id", "")),
            status=str(data.get("status", "UNSCHEDULABLE")),
            reason=str(data.get("reason", "")),
            assigned_node=data.get("assigned_node"),
            provider=data.get("provider"),
            region=data.get("region"),
            jurisdiction=data.get("jurisdiction"),
            measured_rtt_ms=data.get("measured_rtt_ms"),
            hourly_cost=float(data["hourly_cost"]) if data.get("hourly_cost") is not None else None,
            carbon_gco2_kwh=float(data["carbon_gco2_kwh"]) if data.get("carbon_gco2_kwh") is not None else None,
            carbon_classification=data.get("carbon_classification"),
            remaining_node_gpus=data.get("remaining_node_gpus"),
            optimization_score=float(data["optimization_score"]) if data.get("optimization_score") is not None else None,
            evaluated_at=data.get("evaluated_at"),
        )

    def list_nodes(self) -> List[ComputeNodeRecord]:
        """Lists active global compute nodes and current GPU capacity."""
        endpoint = "/api/proxy/workloads/nodes"
        data, _ = self._client.request(endpoint, method="GET")
        raw_nodes = data.get("nodes", []) if isinstance(data, dict) else []
        nodes: List[ComputeNodeRecord] = []
        for n in raw_nodes:
            nodes.append(
                ComputeNodeRecord(
                    node_id=str(n.get("node_id", "")),
                    provider=str(n.get("provider", "")),
                    region=str(n.get("region", "")),
                    jurisdiction=str(n.get("jurisdiction", "")),
                    gpu_type=str(n.get("gpu_type", "")),
                    total_gpus=int(n.get("total_gpus", 0)),
                    available_gpus=int(n.get("available_gpus", 0)),
                    cost_per_gpu_hour=float(n.get("cost_per_gpu_hour", 0.0)),
                    carbon_intensity=float(n.get("carbon_intensity", 0.0)),
                    rtt_from_dhaka=int(n.get("rtt_from_dhaka", 0)),
                    rtt_from_frankfurt=int(n.get("rtt_from_frankfurt", 0)),
                    rtt_from_virginia=int(n.get("rtt_from_virginia", 0)),
                    rtt_from_singapore=int(n.get("rtt_from_singapore", 0)),
                    kv_cache_warmth=float(n.get("kv_cache_warmth", 0.0)),
                )
            )
        return nodes

