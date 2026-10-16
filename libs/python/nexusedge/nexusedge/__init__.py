"""
NexusEdge Official Python SDK
"""

from .client import NexusEdgeClient
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
)

__version__ = "0.1.0"
__all__ = [
    "NexusEdgeClient",
    "NexusEdgeError",
    "ChatMessage",
    "CompletionChoice",
    "CompletionResponse",
    "CompletionTelemetry",
    "CompletionUsage",
    "DomainRecord",
    "Jurisdiction",
    "LatencyMatrixResult",
    "LatencyMatrixRoute",
    "OnboardDomainResult",
    "PoPHealthRecord",
    "RoutingStrategy",
    "TelemetryRateLimit",
    "TelemetrySummary",
    "VerifyDomainResult",
]
