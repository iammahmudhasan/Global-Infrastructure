"""
NexusEdge Python SDK - Exceptions
"""

from typing import Any, Optional, Union


class NexusEdgeError(Exception):
    """Base exception for all NexusEdge client errors."""

    def __init__(
        self,
        status: int,
        message: str,
        code: Optional[Union[str, int]] = None,
        details: Any = None
    ) -> None:
        super().__init__(message)
        self.status = status
        self.message = message
        self.code = code if code is not None else status
        self.details = details

    def __str__(self) -> str:
        if self.code != self.status:
            return f"[{self.status}:{self.code}] {self.message}"
        return f"[{self.status}] {self.message}"

    def __repr__(self) -> str:
        return f"NexusEdgeError(status={self.status}, code={self.code!r}, message={self.message!r})"
