"""Container-local health probe."""

from __future__ import annotations

import urllib.request


def main() -> int:
    with urllib.request.urlopen("http://127.0.0.1:8080/health", timeout=2) as response:  # noqa: S310
        return 0 if response.status == 200 else 1


if __name__ == "__main__":
    raise SystemExit(main())
