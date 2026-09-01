#!/usr/bin/env python3
"""Wait for an HTTP endpoint without curl or third-party dependencies."""

from __future__ import annotations

import argparse
import sys
import time
import urllib.error
import urllib.request


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("url")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--interval", type=float, default=0.5)
    args = parser.parse_args()
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(args.url, timeout=2) as response:  # noqa: S310
                if 200 <= response.status < 400:
                    return 0
        except (urllib.error.URLError, TimeoutError):
            pass
        time.sleep(args.interval)
    print(f"Timed out waiting for {args.url}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
