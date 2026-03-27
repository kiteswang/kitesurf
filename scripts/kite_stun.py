#!/usr/bin/env python3
# Copyright (c) 2026 KiteSurf Contributors — MIT License
# See LICENSE file for details.
"""
kite_stun.py — Lightweight STUN client for NAT address discovery (RFC 5389)

Probes multiple STUN servers in parallel, returns the first successful (public IP, public port) mapping.

Usage:
  from kite_stun import discover_public_addr
  ip, port = await discover_public_addr(local_port=17850)
"""

import asyncio
import logging
import os
import socket
import struct
from typing import Optional, Tuple

from kite_utils import mask_ip as _mask_ip

log = logging.getLogger("kite-stun")

# ── STUN Server Pool (public servers, no authentication required) ──

STUN_SERVERS_CN = [
    ("stun.miwifi.com",              3478),
    ("stun.chat.bilibili.com",       3478),
    ("stun.cdnbye.com",              3478),
    ("stun.hitv.com",                3478),
    ("stun.voipbuster.com",          3478),
    ("stun.voipstunt.com",           3478),
]

STUN_SERVERS_INTL = [
    ("stun.l.google.com",            19302),
    ("stun1.l.google.com",           19302),
    ("stun2.l.google.com",           19302),
    ("stun3.l.google.com",           19302),
    ("stun4.l.google.com",           19302),
    ("stun.cloudflare.com",          3478),
    ("stun.sipgate.net",             3478),
    ("stun.nextcloud.com",           3478),
]

# Merged pool: domestic servers first, international as fallback
STUN_SERVERS = STUN_SERVERS_CN + STUN_SERVERS_INTL

# ── STUN Message Constants ────────────────────────────────────────────────────
STUN_BINDING_REQUEST  = 0x0001
STUN_BINDING_RESPONSE = 0x0101
STUN_MAGIC_COOKIE     = 0x2112A442
ATTR_MAPPED_ADDRESS   = 0x0001
ATTR_XOR_MAPPED_ADDRESS = 0x0020

# ── STUN Protocol Helper Functions ─────────────────────────────────────────────────────

def _build_binding_request(transaction_id: bytes) -> bytes:
    """Build a minimal STUN Binding Request (20-byte header, no attributes)."""
    msg_type   = STUN_BINDING_REQUEST
    msg_length = 0
    magic      = STUN_MAGIC_COOKIE
    return struct.pack("!HHI12s", msg_type, msg_length, magic, transaction_id)


def _parse_binding_response(data: bytes, transaction_id: bytes) -> Optional[Tuple[str, int]]:
    """Parse a STUN Binding Response; return (ip, port) or None."""
    if len(data) < 20:
        return None
    msg_type, msg_length, magic = struct.unpack("!HHI", data[:8])
    if msg_type != STUN_BINDING_RESPONSE:
        return None
    if magic != STUN_MAGIC_COOKIE:
        return None
    resp_tid = data[8:20]
    if resp_tid != transaction_id:
        return None

    # parse attributes
    offset = 20
    while offset + 4 <= len(data):
        attr_type, attr_len = struct.unpack("!HH", data[offset:offset + 4])
        attr_val = data[offset + 4: offset + 4 + attr_len]
        offset += 4 + attr_len
        # align to 4-byte boundary
        if attr_len % 4:
            offset += 4 - (attr_len % 4)

        if attr_type == ATTR_XOR_MAPPED_ADDRESS and len(attr_val) >= 8:
            # XOR-MAPPED-ADDRESS: family=IPv4, port XORed with magic high 16 bits, IP XORed with magic
            family = attr_val[1]
            if family == 0x01:  # IPv4
                xport = struct.unpack("!H", attr_val[2:4])[0]
                xip   = struct.unpack("!I", attr_val[4:8])[0]
                port  = xport ^ (STUN_MAGIC_COOKIE >> 16)
                ip    = socket.inet_ntoa(struct.pack("!I", xip ^ STUN_MAGIC_COOKIE))
                return ip, port

        elif attr_type == ATTR_MAPPED_ADDRESS and len(attr_val) >= 8:
            family = attr_val[1]
            if family == 0x01:  # IPv4
                port = struct.unpack("!H", attr_val[2:4])[0]
                ip   = socket.inet_ntoa(attr_val[4:8])
                return ip, port

    return None


# ── Async UDP STUN Probing ──────────────────────────────────────────────────────

class _StunProtocol(asyncio.DatagramProtocol):
    def __init__(self, transaction_id: bytes, future: asyncio.Future):
        self._tid = transaction_id
        self._future = future

    def datagram_received(self, data: bytes, addr):
        if self._future.done():
            return
        result = _parse_binding_response(data, self._tid)
        if result:
            self._future.set_result(result)

    def error_received(self, exc):
        if not self._future.done():
            self._future.set_exception(exc)

    def connection_lost(self, exc):
        if not self._future.done():
            self._future.cancel()


async def _probe_one(
    stun_host: str,
    stun_port: int,
    local_port: int,
    timeout: float = 3.0,
) -> Optional[Tuple[str, int]]:
    """Send a single STUN probe; return (public IP, public port) or None."""
    loop = asyncio.get_running_loop()
    tid = os.urandom(12)  # 96-bit random transaction ID
    request = _build_binding_request(tid)
    future: asyncio.Future = loop.create_future()

    try:
        stun_addr = await loop.run_in_executor(
            None, lambda: socket.getaddrinfo(stun_host, stun_port, socket.AF_INET)[0][4]
        )
    except Exception:
        return None

    try:
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _StunProtocol(tid, future),
            local_addr=("0.0.0.0", local_port),
        )
    except OSError:
        # port occupied; use ephemeral port
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _StunProtocol(tid, future),
                local_addr=("0.0.0.0", 0),
            )
        except Exception:
            return None

    try:
        transport.sendto(request, stun_addr)
        return await asyncio.wait_for(future, timeout=timeout)
    except Exception:
        return None
    finally:
        transport.close()


async def discover_public_addr(
    local_port: int = 0,
    timeout_per_server: float = 3.0,
    max_parallel: int = 4,
) -> Optional[Tuple[str, int]]:
    """
    Probe STUN servers in parallel batches.
    Returns (public IP, public port) from the first successful response, or None.
    """
    servers = list(STUN_SERVERS)
    for i in range(0, len(servers), max_parallel):
        batch = servers[i:i + max_parallel]
        tasks = [
            asyncio.create_task(_probe_one(h, p, local_port, timeout_per_server))
            for h, p in batch
        ]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        for task in done:
            result = task.result()
            if result:
                log.info(f"[stun] public address: {_mask_ip(result[0])}:{result[1]}")
                return result
        log.debug(f"[stun] batch {i//max_parallel + 1} failed, trying next batch...")

    log.warning("[stun] all STUN servers failed")
    return None
