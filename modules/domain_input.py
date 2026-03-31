#!/usr/bin/env python3
"""
Domain input normalization helpers.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import unquote, urlsplit

import idna


class DomainInputError(ValueError):
    """Raised when a domain-like input cannot be normalized."""


_DOT_TRANSLATION = str.maketrans({
    "。": ".",
    "．": ".",
    "｡": ".",
})


def _extract_host(value: str) -> str:
    """Extract host from raw input that can be domain/URL/email-like text."""
    raw = (value or "").strip().strip("'\"")
    raw = unquote(raw).translate(_DOT_TRANSLATION).replace("\\", "/")
    if not raw:
        raise DomainInputError("域名为空")

    if raw.lower().startswith("mailto:"):
        raw = raw[7:]

    # Email-like input: user@example.com -> example.com
    if "@" in raw and "://" not in raw and raw.count("@") == 1:
        raw = raw.split("@", 1)[1]

    candidate = raw if "://" in raw else f"//{raw}"
    parsed = urlsplit(candidate)
    host = (parsed.hostname or "").strip()
    if host:
        return host

    # Fallback for malformed URLs.
    head = raw.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in head:
        head = head.rsplit("@", 1)[1]
    if head.startswith("[") and "]" in head:
        return head[1:head.index("]")]
    if ":" in head and head.count(":") == 1:
        return head.rsplit(":", 1)[0]
    return head


def normalize_domain_input(value: str) -> str:
    """
    Normalize domain input to a stable lowercase host.

    Accepted examples:
    - example.com
    - HTTPS://WWW.Example.COM/login?a=1
    - user:pass@sub.example.com:8443/path
    - 测试.中国
    - *.example.com
    - user@example.com
    """
    host = _extract_host(value).strip().lower()
    host = host.strip(".")
    if host.startswith("*."):
        host = host[2:]
    host = host.lstrip(".")
    if not host:
        raise DomainInputError("未解析到有效域名")

    # If host is a valid IPv4 or IPv6 address, return it unchanged.
    try:
        ip = ipaddress.ip_address(host)
        # Return the canonical textual representation (e.g., compress IPv6)
        return ip.compressed if hasattr(ip, 'compressed') else str(ip)
    except ValueError:
        # Not an IP address — continue with domain normalization
        pass

    labels = [part for part in host.split(".") if part]
    if not labels:
        raise DomainInputError("未解析到有效域名")

    normalized_labels = []
    for label in labels:
        token = label.strip()
        if not token:
            continue
        try:
            ascii_label = idna.encode(token, uts46=True, std3_rules=False).decode("ascii")
        except idna.IDNAError:
            # Fallback for non-standard labels. Keep common host chars only.
            ascii_label = re.sub(r"[^0-9A-Za-z_-]", "", token).lower()
            if not ascii_label:
                raise DomainInputError(f"域名片段无效: {label}")
        normalized_labels.append(ascii_label.lower())

    if not normalized_labels:
        raise DomainInputError("未解析到有效域名")

    normalized = ".".join(normalized_labels)
    if len(normalized) > 253:
        raise DomainInputError("域名长度超出限制")
    return normalized
