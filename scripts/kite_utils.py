#!/usr/bin/env python3
# Copyright (c) 2026 KiteSurf Contributors — MIT License
# See LICENSE file for details.
"""
kite_utils.py — Shared utility functions for all KiteSurf modules.
"""

import re


def mask_ip(addr: str) -> str:
    """Mask the last two octets of any IPv4 address embedded in a string for privacy.

    Supports bare IP, IP:port, and URL formats (ws://, wss://, http://, etc.).

    Examples:
        "14.22.11.161:17845"              → "14.22.*.*:17845"
        "192.168.1.100:9000"              → "192.168.*.*:9000"
        "14.22.11.161"                    → "14.22.*.*"
        "ws://192.168.1.5:17851"          → "ws://192.168.*.*:17851"
        "wss://10.0.0.3:17851"            → "wss://10.*.*.*:17851"
        "http://127.0.0.1:8080"           → "http://127.0.*.*:8080"
        ""                                → ""
        "localhost:8080"                   → "localhost:8080"  (non-IPv4 — unchanged)
    """
    if not addr:
        return ""
    return _IPV4_RE.sub(_mask_match, addr)


# Regex: matches an IPv4 address (4 dotted decimal groups, each 1-3 digits)
# Uses word boundaries and lookahead/lookbehind to avoid partial matches inside other numbers.
_IPV4_RE = re.compile(
    r"(?<![.\d])"               # not preceded by a dot or digit
    r"(\d{1,3}\.\d{1,3})\."    # first two octets (captured)
    r"\d{1,3}\.\d{1,3}"        # last two octets (will be replaced)
    r"(?![.\d])"                # not followed by a dot or digit
)


def _mask_match(m: re.Match) -> str:
    """Replace the last two octets with *.*"""
    return f"{m.group(1)}.*.*"
