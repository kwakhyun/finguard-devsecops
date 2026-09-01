"""Dependency-free sample service for repeatable DAST smoke tests."""

from __future__ import annotations

import json
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


class SecureHandler(BaseHTTPRequestHandler):
    server_version = "FinGuardSample"
    sys_version = ""

    def end_headers(self) -> None:
        self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._json(HTTPStatus.OK, {"status": "healthy"})
            return
        if self.path == "/api/v1/version":
            self._json(HTTPStatus.OK, {"service": "finguard-sample", "version": "1.0"})
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def _json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        # Avoid leaking request data in the portfolio service's default logs.
        return


def run(host: str = "0.0.0.0", port: int = 8080) -> None:  # noqa: S104 - container listener
    server = ThreadingHTTPServer((host, port), SecureHandler)
    server.serve_forever()


if __name__ == "__main__":
    run(port=int(os.environ.get("PORT", "8080")))
