#!/usr/bin/env python3
# Copyright (c) 2026 KiteSurf Contributors — MIT License
# See LICENSE file for details.
"""
kite_punch.py — UDP hole punching + relay fallback for KiteSurf

Flow:
  1. Both sides discover public addresses via STUN (kite_stun.py)
  2. Exchange public addresses through Rendezvous (punch_ready / punch_start)
  3. Simultaneously send UDP probe packets (hole punching)
  4. Success → direct P2P UDP channel (AES-256-GCM encrypted)
  5. Failure (3s timeout) → Rendezvous Relay fallback (encrypted)

Public API:
  puncher = KitePuncher(rendezvous_ws, node_id, kitp_port)
  channel = await puncher.punch(pair_id, peer_node_id, pair_secret="...")
  # channel.send(data) / channel.recv() / channel.close()
  # channel.mode == "direct" | "relay"
"""

import asyncio
import logging
import os
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger("kite-punch")

from kite_utils import mask_ip as _mask_ip

PUNCH_TIMEOUT   = 4.0    # seconds to wait for hole punch success
PUNCH_INTERVAL  = 0.2    # probe packet send interval (seconds)
PROBE_MAGIC     = b"KITE_PUNCH_v1"
RELAY_MAGIC     = b"KITE_RELAY_v1"


# ─────────────────────────── Channel Abstraction ─────────────────────────────

_SENTINEL = object()   # poison pill pushed on close

@dataclass
class KiteChannel:
    """Unified send/receive interface regardless of transport (direct UDP or relay).

    When a cipher is attached, sending transparently encrypts and receiving transparently decrypts.
    Callers only see plaintext.
    Probe/relay frame protocol packets bypass encryption (handled at protocol layer).
    """
    mode: str              # "direct" | "relay"
    pair_id: str
    peer_node_id: str
    _send_fn: object       # async callable (data: bytes)
    _recv_queue: asyncio.Queue = field(default=None, repr=False)
    _closed: bool = False
    _cipher: object = field(default=None, repr=False)   # optional KiteChannelCipher

    def __post_init__(self):
        if self._recv_queue is None:
            self._recv_queue = asyncio.Queue()

    async def send(self, data: bytes):
        """Send data, encrypting first if a cipher is attached."""
        if self._closed:
            raise RuntimeError("channel is closed")
        if self._cipher:
            data = self._cipher.encrypt(data)
        await self._send_fn(data)

    async def recv(self, timeout: float = None) -> bytes:
        """Receive data. Decrypts if a cipher is attached.
        Raises RuntimeError if the channel is closed."""
        if self._closed:
            raise RuntimeError("channel is closed")
        if timeout:
            item = await asyncio.wait_for(self._recv_queue.get(), timeout=timeout)
        else:
            item = await self._recv_queue.get()
        if item is _SENTINEL:
            raise RuntimeError("channel is closed")
        if self._cipher:
            plaintext = self._cipher.decrypt(item)
            if plaintext is None:
                log.warning(f"[channel] ⚠️ decryption failed on {self.mode} channel "
                            f"(pair={self.pair_id}), dropping packet")
                # return empty bytes instead of crashing — caller can handle accordingly
                return b""
            return plaintext
        return item

    def push(self, data: bytes):
        """Internal call when encrypted data arrives on this channel.
        Data is enqueued as-is; decryption happens in recv()."""
        if not self._closed:
            self._recv_queue.put_nowait(data)

    def close(self):
        if not self._closed:
            self._closed = True
            # wake up coroutines blocked on recv()
            self._recv_queue.put_nowait(_SENTINEL)


# ─────────────────────────── UDP Hole Punch Engine ────────────────────────────────

class _UdpPunchProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        self.transport = None
        self._listeners: dict[str, asyncio.Future] = {}
        self._channels: dict[str, KiteChannel] = {}

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        if data.startswith(PROBE_MAGIC):
            pair_id = data[len(PROBE_MAGIC):].decode(errors="ignore").strip()
            fut = self._listeners.get(f"probe:{pair_id}")
            if fut and not fut.done():
                fut.set_result(addr)

        elif data.startswith(RELAY_MAGIC):
            # relay forwarded payload: RELAY_MAGIC + pair_id(36) + payload
            header_len = len(RELAY_MAGIC) + 36
            if len(data) > header_len:
                pair_id = data[len(RELAY_MAGIC):len(RELAY_MAGIC)+36].decode(errors="ignore")
                payload = data[header_len:]
                ch = self._channels.get(pair_id)
                if ch:
                    ch.push(payload)
        else:
            # raw channel data
            for ch in self._channels.values():
                if not ch._closed:
                    ch.push(data)

    def error_received(self, exc):
        log.warning(f"[punch] UDP error: {exc}")

    def connection_lost(self, exc):
        pass

    def register_probe_listener(self, pair_id: str) -> asyncio.Future:
        fut = asyncio.get_running_loop().create_future()
        self._listeners[f"probe:{pair_id}"] = fut
        return fut

    def register_channel(self, pair_id: str, channel: KiteChannel):
        self._channels[pair_id] = channel


# ─────────────────────────── KitePuncher ─────────────────────────────────────

class KitePuncher:
    """
    Manages UDP hole punching for KiteNode.

    Args:
        rendezvous_ws: active websockets connection to Rendezvous server
        node_id: local node ID
        kitp_port: KITP listen port (used as local UDP port hint)
        stun_local_port: UDP port for STUN probing (0 = ephemeral port)
    """

    def __init__(self, rendezvous_ws, node_id: str, kitp_port: int = 17850,
                 stun_local_port: int = 0):
        self._ws = rendezvous_ws
        self.node_id = node_id
        self.kitp_port = kitp_port
        self.stun_local_port = stun_local_port or kitp_port + 1

        self._public_addr: Optional[tuple] = None   # (ip, port) from STUN
        self._udp_proto: Optional[_UdpPunchProtocol] = None
        self._udp_transport = None
        self._punch_futures: dict[str, asyncio.Future] = {}

    async def setup(self):
        """Discover public address via STUN and bind UDP socket."""
        from kite_stun import discover_public_addr
        self._public_addr = await discover_public_addr(local_port=self.stun_local_port)
        if self._public_addr:
            log.info(f"[punch] public address: {self._public_addr[0]}:{self._public_addr[1]}")
        else:
            log.warning("[punch] STUN failed — relay-only mode")

        # bind UDP socket for hole punching
        loop = asyncio.get_running_loop()
        try:
            self._udp_transport, self._udp_proto = await loop.create_datagram_endpoint(
                _UdpPunchProtocol,
                local_addr=("0.0.0.0", self.stun_local_port),
            )
        except OSError:
            self._udp_transport, self._udp_proto = await loop.create_datagram_endpoint(
                _UdpPunchProtocol,
                local_addr=("0.0.0.0", 0),
            )

    async def punch(self, pair_id: str, peer_node_id: str,
                    pair_secret: str = "") -> KiteChannel:
        """
        Attempt UDP hole punching with the peer.
        Returns a KiteChannel with mode="direct" or mode="relay".

        If pair_secret is provided, the channel uses AES-256-GCM encryption.
        Both sides must use the same pair_secret for it to work.
        """
        if not self._udp_proto:
            await self.setup()

        # build cipher for this channel (if secret provided)
        cipher = self._make_cipher(pair_secret, pair_id, "kite-udp",
                                   local_node_id=self.node_id,
                                   peer_node_id=peer_node_id)

        # announce readiness + public address to Rendezvous
        pub = f"{self._public_addr[0]}:{self._public_addr[1]}" if self._public_addr else ""
        await self._ws_send({
            "type": "punch_ready",
            "pair_id": pair_id,
            "public_addr": pub,
        })

        # wait for punch_start from Rendezvous (contains peer's public address)
        peer_public_addr = await self._wait_punch_start(pair_id, timeout=10.0)
        if not peer_public_addr or not self._public_addr:
            log.info(f"[punch] {pair_id}: no public address — using relay")
            return self._make_relay_channel(pair_id, peer_node_id, cipher)

        # parse peer address
        try:
            peer_ip, peer_port_str = peer_public_addr.rsplit(":", 1)
            peer_port = int(peer_port_str)
        except ValueError:
            return self._make_relay_channel(pair_id, peer_node_id, cipher)

        # register probe listener before sending
        probe_future = self._udp_proto.register_probe_listener(pair_id)

        # send probes concurrently
        probe_task = asyncio.create_task(
            self._send_probes(peer_ip, peer_port, pair_id)
        )

        try:
            peer_addr = await asyncio.wait_for(probe_future, timeout=PUNCH_TIMEOUT)
            probe_task.cancel()
            log.info(f"[punch] ✅ direct P2P established with {peer_node_id} at {_mask_ip(str(peer_addr))}")
            return self._make_direct_channel(pair_id, peer_node_id, peer_addr, cipher)
        except asyncio.TimeoutError:
            probe_task.cancel()
            log.info(f"[punch] ⚡ hole punch timed out — falling back to relay")
            return self._make_relay_channel(pair_id, peer_node_id, cipher)

    # ── Channel Factory ──

    def _make_direct_channel(self, pair_id: str, peer_node_id: str,
                              peer_addr: tuple,
                              cipher=None) -> KiteChannel:
        transport = self._udp_transport

        async def send_fn(data: bytes):
            transport.sendto(data, peer_addr)

        ch = KiteChannel(
            mode="direct",
            pair_id=pair_id,
            peer_node_id=peer_node_id,
            _send_fn=send_fn,
            _cipher=cipher,
        )
        self._udp_proto.register_channel(pair_id, ch)
        if cipher and cipher.enabled:
            log.info(f"[punch] 🔒 direct UDP channel encrypted (AES-256-GCM)")
        return ch

    def _make_relay_channel(self, pair_id: str, peer_node_id: str,
                             cipher=None) -> KiteChannel:
        puncher_ref = self  # capture self so send_fn always uses current _ws

        async def send_fn(data: bytes):
            import json
            import base64
            ws = puncher_ref._ws
            if ws is None:
                raise RuntimeError("relay channel: WebSocket is not connected")
            await ws.send(json.dumps({
                "type": "relay",
                "pair_id": pair_id,
                "data": base64.b64encode(data).decode(),
            }))

        ch = KiteChannel(
            mode="relay",
            pair_id=pair_id,
            peer_node_id=peer_node_id,
            _send_fn=send_fn,
            _cipher=cipher,
        )
        if self._udp_proto:
            self._udp_proto.register_channel(pair_id, ch)
        if cipher and cipher.enabled:
            log.info(f"[punch] 🔒 relay channel encrypted (AES-256-GCM)")
        return ch

    # ── Helper Methods ──

    async def _send_probes(self, peer_ip: str, peer_port: int, pair_id: str):
        """Continuously send hole punch probe packets until cancelled."""
        probe = PROBE_MAGIC + pair_id.encode()
        while True:
            try:
                self._udp_transport.sendto(probe, (peer_ip, peer_port))
            except Exception:
                pass
            await asyncio.sleep(PUNCH_INTERVAL)

    async def _wait_punch_start(self, pair_id: str, timeout: float) -> Optional[str]:
        """Wait for punch_start message from Rendezvous; return peer's public address."""
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        self._punch_futures[pair_id] = fut
        try:
            result = await asyncio.wait_for(fut, timeout=timeout)
            return result
        except asyncio.TimeoutError:
            return None
        finally:
            self._punch_futures.pop(pair_id, None)

    def on_rendezvous_message(self, msg: dict):
        """Feed messages from the Rendezvous server into the puncher (called from pairing loop)."""
        t = msg.get("type")
        if t == "punch_start":
            pair_id = msg.get("pair_id", "")
            fut = self._punch_futures.get(pair_id)
            if fut and not fut.done():
                fut.set_result(msg.get("peer_public_addr", ""))

        elif t == "relay_data":
            import base64  # decoding binary KITP frames from JSON WebSocket transport
            pair_id = msg.get("pair_id", "")
            if self._udp_proto:
                ch = self._udp_proto._channels.get(pair_id)
                if ch:
                    try:
                        data = base64.b64decode(msg.get("data", ""))
                        ch.push(data)
                    except Exception:
                        pass

    async def _ws_send(self, data: dict):
        import json
        try:
            await self._ws.send(json.dumps(data))
        except Exception as e:
            log.error(f"[punch] WS send failed: {e}")

    @staticmethod
    def _make_cipher(pair_secret: str, pair_id: str, purpose: str,
                     local_node_id: str = "", peer_node_id: str = ""):
        """Create a KiteChannelCipher if pair_secret is provided."""
        if not pair_secret:
            return None
        try:
            from kite_crypto import KiteChannelCipher
            return KiteChannelCipher(pair_secret, pair_id, purpose,
                                     local_node_id=local_node_id,
                                     peer_node_id=peer_node_id)
        except ImportError:
            log.warning("[punch] kite_crypto unavailable — channel unencrypted")
            return None

    def close(self):
        """Clean up all channels and close UDP transport."""
        if self._udp_proto:
            # close all active channels
            for ch in list(self._udp_proto._channels.values()):
                ch.close()
            self._udp_proto._channels.clear()
        if self._udp_transport:
            self._udp_transport.close()
        # cancel all pending punch futures
        for fut in self._punch_futures.values():
            if not fut.done():
                fut.cancel()
        self._punch_futures.clear()
