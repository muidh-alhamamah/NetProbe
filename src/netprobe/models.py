"""Shared result type returned by every diagnostic."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class CheckResult:
    check: str
    target: str
    ok: bool
    details: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    duration_ms: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
