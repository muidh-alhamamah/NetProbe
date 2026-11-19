"""Exception hierarchy. Everything NetProbe raises on purpose derives from NetProbeError."""


class NetProbeError(Exception):
    """Base class for expected, user-facing errors."""


class InvalidTargetError(NetProbeError, ValueError):
    """A host, port or numeric option failed validation."""


class CommandNotFoundError(NetProbeError):
    """A required system tool (ping, tracert, ...) is not installed or not on PATH."""


class CommandTimeoutError(NetProbeError):
    """A system tool did not finish within its timeout."""
