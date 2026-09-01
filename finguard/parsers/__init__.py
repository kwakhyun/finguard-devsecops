"""Scanner report parser registry."""

from .registry import discover_reports, parse_report
from .sarif import parse_sarif

__all__ = ["discover_reports", "parse_report", "parse_sarif"]
