"""Domain exceptions with stable CLI exit-code mapping."""


class FinGuardError(Exception):
    """Base exception for expected, user-actionable failures."""


class ConfigurationError(FinGuardError):
    """Raised when policy or change-control input is invalid."""


class ReportParseError(FinGuardError):
    """Raised when a scanner report cannot be interpreted safely."""


class EvidenceVerificationError(FinGuardError):
    """Raised when evidence integrity verification fails."""


class DeploymentError(FinGuardError):
    """Raised when a controlled deployment cannot complete or roll back safely."""
