"""Canonical HTTP URL handling shared by DAST and deployment controls."""

from __future__ import annotations

import urllib.parse


def canonical_http_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value.strip())
    scheme = parsed.scheme.casefold()
    if scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("URL must use http or https and include a host")
    if parsed.username or parsed.password:
        raise ValueError("URL credentials are not allowed")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("URL port is invalid") from exc
    host = parsed.hostname.casefold().rstrip(".")
    if not host:
        raise ValueError("URL host is empty")
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    authority = host if port is None or default_port else f"{host}:{port}"
    path = parsed.path or "/"
    return urllib.parse.urlunsplit((scheme, authority, path, parsed.query, ""))


def canonical_dast_location(value: str, *, base_url: str) -> tuple[str, str]:
    canonical_base = canonical_http_url(base_url)
    absolute = urllib.parse.urljoin(canonical_base, value)
    canonical = canonical_http_url(absolute)
    parsed = urllib.parse.urlsplit(canonical)
    base = urllib.parse.urlsplit(canonical_base)
    if (parsed.scheme, parsed.netloc) != (base.scheme, base.netloc):
        raise ValueError("DAST instance URI must remain on the scanned target origin")
    query_keys = sorted({key.casefold() for key, _ in urllib.parse.parse_qsl(parsed.query)})
    location = parsed.path or "/"
    if query_keys:
        location = f"{location}?{'&'.join(query_keys)}"
    return location, canonical
