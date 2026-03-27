#!/usr/bin/env python3
# Copyright (c) 2026 KiteSurf Contributors — MIT License
# See LICENSE file for details.
"""
kite_rendezvous.py — KiteSurf Rendezvous Server

Lightweight signaling server for KiteSurf node discovery and optional relay.
Does not proxy task content — only handles presence, search, metadata, and
fallback relay when P2P direct connect fails.

Nodes discover each other via this server, then connect P2P directly.
Invite/accept pairing happens over the P2P connection, NOT through this server.

Protocol messages (JSON over WebSocket):
  Client → Server:
    register           — Announce online with profile (includes public_addr from STUN)
    unregister         — Go offline
    list               — Browse online nodes (returns addr_hint + public_addr)
    punch_ready        — Signal readiness for UDP hole punch (pair_id + STUN public_addr)
    relay              — Fallback data relay for paired nodes (when P2P fails)
    update_metadata    — Update node metadata (e.g. leader announce)
    update_public_addr — Push STUN-discovered public address after registration
    ping               — Heartbeat keepalive

  Server → Client:
    registered      — Registration confirmation (assigns peer_token)
    listed          — Online node list with addresses for P2P direct connect
    punch_start     — Sent to both sides when a punch pair matches (contains peer's public_addr)
    relay_data      — Relayed data from a paired peer
    node_joined     — Push notification when a same-group node registers
    metadata_updated — Metadata update confirmation
    error           — Error response
    pong            — Heartbeat reply

Admin HTTP API (--admin-port, default 17852, localhost only):
    GET /status                — Server overview (uptime, online count, stats)
    GET /overview              — Node list dashboard (status classification, pagination, sorting, search)
    GET /list                  — Lightweight node listing (only compact core fields)
    GET /nodes                 — List all online nodes with full details
    GET /nodes/<node_id>       — Single node details
    GET /pairs                 — Active relay pairs
    GET /events                — Recent event log (within 24 hours)
    GET /events?type=<type>    — Filter events by type

  Security: Admin API binds to 127.0.0.1 only, rejects non-local requests.

Usage:
  python3 kite_rendezvous.py [--host 0.0.0.0] [--port 17851] [--admin-port 17852]

  Enable TLS (wss://):
  python3 kite_rendezvous.py --ssl-cert /path/to/cert.pem --ssl-key /path/to/key.pem
"""

import argparse
import asyncio
import collections
import datetime
import json
import logging
import re
import ssl
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from websockets.asyncio.server import serve as ws_serve
from websockets.asyncio.client import connect as ws_connect
from websockets.exceptions import ConnectionClosed as WsConnectionClosed

from kite_utils import mask_ip as _mask_ip

log = logging.getLogger("kite-rendezvous")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


# ─────────────────────────── Event log ───────────────────────────────────

EVENT_LOG_MAX = 10000           # max events kept in ring buffer
EVENT_TTL = 86400               # 24 hours in seconds
NODE_STALE_TIMEOUT = 120        # seconds without ping → node considered dead (4× keepalive interval)


@dataclass
class EventRecord:
    ts: float                   # unix timestamp
    event: str                  # event type: register, unregister, relay_registered, disconnect, ...
    node_id: str                # primary actor
    detail: dict                # extra info (peer_id, pair_id, etc.)

    def to_dict(self) -> dict:
        # Mask IP-bearing fields in detail for privacy
        masked_detail = {}
        _IP_KEYS = {"remote_ip", "addr_a", "addr_b", "addr_hint", "public_addr"}
        for k, v in self.detail.items():
            if k in _IP_KEYS and isinstance(v, str):
                masked_detail[k] = _mask_ip(v)
            else:
                masked_detail[k] = v
        return {
            "ts": self.ts,
            "time": datetime.datetime.fromtimestamp(self.ts).strftime("%Y-%m-%d %H:%M:%S"),
            "event": self.event,
            "node_id": self.node_id,
            "detail": masked_detail,
        }


class EventLog:
    """Ring-buffer event log that auto-evicts entries older than EVENT_TTL."""

    def __init__(self, maxlen: int = EVENT_LOG_MAX):
        self._buf: collections.deque[EventRecord] = collections.deque(maxlen=maxlen)

    def append(self, event: str, node_id: str, **detail):
        self._buf.append(EventRecord(ts=time.time(), event=event, node_id=node_id, detail=detail))

    def query(self, event_type: str = None, node_id: str = None, limit: int = 200) -> List[dict]:
        cutoff = time.time() - EVENT_TTL
        results = []
        for rec in reversed(self._buf):
            if rec.ts < cutoff:
                break  # older than 24h — stop (deque is chronological)
            if event_type and rec.event != event_type:
                continue
            if node_id and rec.node_id != node_id:
                continue
            results.append(rec.to_dict())
            if len(results) >= limit:
                break
        return results

# ─────────────────────────── Node profile ───────────────────────────────

@dataclass
class KiteProfile:
    node_id: str          # unique per session, machine-fingerprint or user-chosen
    nickname: str         # fun human-readable name e.g. "WaveChaser-Shark", "WindBreaker-Eagle"
    emoji: str            # e.g. "🌊"
    tags: list            # capability / topic tags e.g. ["AI", "research", "translator"]
    group: str            # group name: same-group nodes see each other; "" or "*" = default (smart match)
    hidden: bool          # if True, won't appear in list (invite-only)
    peer_token: str       # server-assigned one-time token for this session
    version: str          # protocol version e.g. "kitp/1"
    joined_at: float = field(default_factory=time.time)
    last_active_at: float = field(default_factory=time.time)  # updated on every ping/message
    remote_ip: str = ""   # client IP from websocket
    addr_hint: str = ""   # listen_addr declared by client
    public_addr: str = "" # STUN-discovered public address (ip:port) declared by client
    # ── KiteChain v2 — Blockchain identity & capabilities (§7, §9, §10 of Whitepaper) ──
    chain_enabled: bool = False           # node has KiteChain enabled
    wallet_address: str = ""              # Ed25519 public key hex (chain identity / account address)
    scp_version: str = ""                 # Skill Call Protocol version e.g. "scp/1" (§10)
    chain_capabilities: list = field(default_factory=list)  # chain-callable Skill IDs (§9)
    # ── Gossip protocol — port advertised so peers can resolve correct UDP target ──
    gossip_port: int = 0                  # 0 = not advertised / gossip not enabled
    # ── Metadata (v2.1) — arbitrary key-value pairs for leader announce etc. ──
    metadata: dict = field(default_factory=dict)

    @property
    def display_name(self) -> str:
        """Human-friendly display: nickname (node_id) or just node_id."""
        if self.nickname:
            return f"{self.nickname}  ({self.node_id})"
        return self.node_id

    def public_view(self) -> dict:
        """Safe fields to expose to other nodes (no private skills, no wallet details).
        Chain fields: only chain_enabled (bool) — indicates blockchain readiness."""
        view = {
            "node_id": self.node_id,
            "nickname": self.nickname,
            "emoji": self.emoji,
            "tags": self.tags,
            "group": self.group,
            "hidden": self.hidden,
            "version": self.version,
            "joined_at": self.joined_at,
        }
        if self.addr_hint:
            view["addr_hint"] = self.addr_hint
        if self.remote_ip:
            view["remote_ip"] = self.remote_ip
        if self.public_addr:
            view["public_addr"] = self.public_addr
        if self.gossip_port:
            view["gossip_port"] = self.gossip_port
        # ── KiteChain v2: public layer — minimal chain presence flag ──
        if self.chain_enabled:
            view["chain_enabled"] = True
            view["scp_version"] = self.scp_version
        if self.metadata:
            view["metadata"] = self.metadata
        return view

    def brief_view(self) -> dict:
        """Minimal fields for lightweight node listing."""
        now = time.time()
        idle = now - self.last_active_at
        view = {
            "node_id": self.node_id,
            "nickname": self.nickname,
            "emoji": self.emoji,
            "group": self.group if self.group and self.group != "*" else "(default)",
            "tags": self.tags,
            "idle_seconds": round(idle),
            "idle_human": _fmt_duration(idle),
        }
        # ── KiteChain v2: brief layer — chain-enabled indicator ──
        if self.chain_enabled:
            view["chain_enabled"] = True
        return view

    def capabilities_view(self) -> dict:
        """Chain-relevant fields disclosed after pairing / capability exchange.
        Includes wallet_address and chain_capabilities for SCP negotiation (§10)."""
        view = self.public_view()
        if self.chain_enabled:
            view["wallet_address"] = self.wallet_address
            view["chain_capabilities"] = self.chain_capabilities
        return view

    def admin_view(self) -> dict:
        """Full detail for admin API — no session tokens exposed.
        Chain fields: all chain state visible (localhost only)."""
        now = time.time()
        uptime = now - self.joined_at
        idle = now - self.last_active_at
        view = {
            "node_id": self.node_id,
            "nickname": self.nickname,
            "emoji": self.emoji,
            "tags": self.tags,
            "group": self.group,
            "hidden": self.hidden,
            "version": self.version,
            "joined_at": self.joined_at,
            "joined_at_str": datetime.datetime.fromtimestamp(self.joined_at).strftime("%Y-%m-%d %H:%M:%S"),
            "uptime_seconds": round(uptime),
            "uptime_human": _fmt_duration(uptime),
            "last_active_at": self.last_active_at,
            "last_active_seconds_ago": round(idle),
            "remote_ip": _mask_ip(self.remote_ip),
            "addr_hint": _mask_ip(self.addr_hint),
        }
        # ── KiteChain v2: admin layer — full chain state ──
        if self.chain_enabled:
            view["chain"] = {
                "enabled": True,
                "wallet_address": self.wallet_address,
                "scp_version": self.scp_version,
                "chain_capabilities": self.chain_capabilities,
            }
        return view


def _fmt_duration(seconds: float) -> str:
    """Format seconds into human-readable duration like '2h 15m 30s'."""
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m {s % 60}s"
    h = s // 3600
    m = (s % 3600) // 60
    return f"{h}h {m}m"


# ─────────────────────────── Rendezvous server ──────────────────────────

class KiteRendezvousServer:
    def __init__(self, host: str = "0.0.0.0", port: int = 17851, admin_port: int = 17852,
                 ssl_cert: Optional[str] = None, ssl_key: Optional[str] = None):
        self.host = host
        self.port = port
        self.admin_port = admin_port
        self._ssl_context = self._build_ssl_context(ssl_cert, ssl_key)
        self._start_time = time.time()
        # peer_token → (profile, websocket)
        self._nodes: Dict[str, tuple] = {}
        # node_id → peer_token (for lookup by nickname)
        self._id_index: Dict[str, str] = {}
        # relay authorization: pair_id → set of node_ids allowed to relay
        self._relay_pairs: Dict[str, set] = {}
        # UDP hole-punch coordination: pair_id → (peer_token, public_addr)
        # Buffers the first punch_ready; when the second arrives, send punch_start to both
        self._punch_pending: Dict[str, tuple] = {}
        # event log (24h ring buffer)
        self._events = EventLog()
        # stats counters
        self._stats = {
            "total_registers": 0,
            "total_relays": 0,
            "total_disconnects": 0,
        }

    # ── TLS support ──

    @staticmethod
    def _build_ssl_context(cert_path: Optional[str], key_path: Optional[str]) -> Optional[ssl.SSLContext]:
        """Build SSL context from cert/key files. Returns None when TLS is not configured."""
        if not cert_path or not key_path:
            return None
        cert = Path(cert_path)
        key = Path(key_path)
        if not cert.exists():
            raise FileNotFoundError(f"SSL cert not found: {cert}")
        if not key.exists():
            raise FileNotFoundError(f"SSL key not found: {key}")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(cert), str(key))
        # Modern TLS settings
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        log.info(f"[rendezvous] TLS enabled: cert={cert}, key={key}")
        return ctx

    # ── Server lifecycle ──

    async def start(self):
        proto = "wss" if self._ssl_context else "ws"
        serve_kwargs = {}
        if self._ssl_context:
            serve_kwargs["ssl"] = self._ssl_context
        async with ws_serve(self._handle, self.host, self.port,
                           max_size=1024 * 1024,  # 1MB max frame
                           open_timeout=10,
                           **serve_kwargs) as server:
            log.info("")
            log.info("  ╔═══════════════════════════════════════════════════╗")
            log.info("  ║  🏖️  KiteSurf Rendezvous                        ║")
            log.info("  ║  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━                 ║")
            log.info("  ║  Where surfers meet, pair up, and set sail        ║")
            log.info("  ╚═══════════════════════════════════════════════════╝")
            log.info("")
            log.info(f"  🌊 Signaling   : {proto}://{self.host}:{self.port}")
            # Admin API always binds to localhost — not exposed to public
            admin_bind = "127.0.0.1"
            log.info(f"  🔧 Admin       : http://{admin_bind}:{self.admin_port} (localhost only)")
            if self._ssl_context:
                log.info(f"  🔒 TLS         : enabled")
            log.info(f"  🟢 Ready — waiting for surfers to join!")
            log.info("")
            admin_server = await asyncio.start_server(
                self._admin_handle, admin_bind, self.admin_port
            )
            # Background task: evict nodes that stopped sending heartbeats
            stale_cleanup = asyncio.create_task(self._stale_node_cleanup_loop())
            async with admin_server:
                await server.wait_closed()
            stale_cleanup.cancel()

    # ── Connection handler ──

    async def _handle(self, ws):
        peer_token = None
        # Capture remote IP for admin visibility
        remote_ip = ""
        try:
            remote = ws.remote_address
            if remote:
                remote_ip = f"{remote[0]}:{remote[1]}" if len(remote) >= 2 else str(remote)
        except Exception:
            pass
        try:
            async for raw in ws:
                try:
                    msg = json.loads(raw)
                    peer_token = await self._dispatch(msg, ws, peer_token, remote_ip)
                except json.JSONDecodeError:
                    await self._send(ws, {"type": "error", "reason": "invalid_json"})
                except Exception as e:
                    log.error(f"[rendezvous] Internal error: {e}")
                    await self._send(ws, {"type": "error", "reason": "internal_error"})
        except WsConnectionClosed:
            pass
        except Exception as e:
            # Catch invalid WebSocket handshakes (port scans, health checks, non-WS HTTP, etc.)
            # These are harmless — log at debug level instead of letting traceback propagate
            log.debug(f"[rendezvous] WebSocket handshake failed from {_mask_ip(remote_ip) or '?'}: "
                      f"{type(e).__name__}: {e}")
        finally:
            if peer_token:
                await self._remove_node(peer_token)

    async def _dispatch(self, msg: dict, ws, peer_token: Optional[str], remote_ip: str = "") -> Optional[str]:
        t = msg.get("type")

        if t == "register":
            return await self._on_register(msg, ws, remote_ip)

        if t == "ping":
            # Update last active timestamp for timeout detection
            if peer_token and peer_token in self._nodes:
                self._nodes[peer_token][0].last_active_at = time.time()
            await self._send(ws, {"type": "pong"})
            return peer_token

        # All other operations require registration first
        if not peer_token or peer_token not in self._nodes:
            await self._send(ws, {"type": "error", "reason": "not_registered"})
            return peer_token

        if t == "unregister":
            await self._remove_node(peer_token)
            return None

        elif t == "list":
            await self._on_list(msg, ws, peer_token)

        elif t == "relay":
            await self._on_relay(msg, ws, peer_token)

        elif t == "register_relay":
            await self._on_register_relay(msg, ws, peer_token)

        elif t == "punch_ready":
            await self._on_punch_ready(msg, ws, peer_token)

        elif t == "update_metadata":
            await self._on_update_metadata(msg, ws, peer_token)

        elif t == "update_public_addr":
            await self._on_update_public_addr(msg, ws, peer_token)

        else:
            await self._send(ws, {"type": "error", "reason": "unknown_type"})

        return peer_token

    # ── Handlers ──

    async def _on_register(self, msg: dict, ws, remote_ip: str = "") -> str:
        node_id = str(msg.get("node_id", "")).strip()[:64]
        if not node_id:
            await self._send(ws, {"type": "error", "reason": "node_id_required"})
            return None

        # Sanitize node_id: only allow safe characters (alphanumeric, hyphens, underscores, dots)
        if not re.match(r'^[a-zA-Z0-9_.\-]+$', node_id):
            await self._send(ws, {"type": "error", "reason": "node_id_invalid_chars"})
            return None

        # Evict old session with the same node_id
        if node_id in self._id_index:
            old_token = self._id_index[node_id]
            await self._remove_node(old_token)

        peer_token = str(uuid.uuid4())
        profile = KiteProfile(
            node_id=node_id,
            nickname=str(msg.get("nickname", ""))[:32],
            emoji=str(msg.get("emoji", "🪁"))[:8],
            tags=[str(t)[:32] for t in msg.get("tags", [])[:20]],
            group=str(msg.get("group", ""))[:32].strip(),
            hidden=bool(msg.get("hidden", False)),
            peer_token=peer_token,
            version=str(msg.get("version", "kitp/1"))[:16],
            remote_ip=remote_ip,
            addr_hint=str(msg.get("addr_hint", ""))[:64],
            public_addr=str(msg.get("public_addr", ""))[:64],
            # ── Gossip port — so peers can resolve the correct UDP target ──
            gossip_port=max(0, min(65535, int(msg.get("gossip_port", 0) or 0))),
            # ── KiteChain v2 — accept chain fields from registration ──
            chain_enabled=bool(msg.get("chain_enabled", False)),
            wallet_address=str(msg.get("wallet_address", ""))[:128],
            scp_version=str(msg.get("scp_version", ""))[:16],
            chain_capabilities=[str(s)[:64] for s in msg.get("chain_capabilities", [])[:50]],
            metadata=({str(k)[:32]: str(v)[:256] for k, v in msg["metadata"].items()}
                      if isinstance(msg.get("metadata"), dict) else {}),
        )
        self._nodes[peer_token] = (profile, ws)
        self._id_index[node_id] = peer_token
        self._stats["total_registers"] += 1
        self._events.append("register", node_id, remote_ip=remote_ip,
                            tags=profile.tags, group=profile.group, hidden=profile.hidden)

        tags_str = " · ".join(profile.tags) if profile.tags else "(no tags)"
        group_str = f"📦 {profile.group}" if profile.group else "🌐 default"
        log.info(f"[rendezvous] 🏄 {profile.emoji} {profile.display_name} joined "
                 f"[{tags_str}] [{group_str}] "
                 f"({'👻 hidden' if profile.hidden else '🌐 public'})")
        await self._send(ws, {
            "type": "registered",
            "peer_token": peer_token,
            "node_id": node_id,
        })

        # ── Notify same-group nodes about new member (election protocol) ──
        # This enables instant peer discovery: existing nodes can trigger an
        # immediate election round instead of waiting for the next polling cycle.
        await self._broadcast_node_joined(peer_token, profile)

        return peer_token

    async def _broadcast_node_joined(self, new_token: str, new_profile: KiteProfile):
        """Broadcast a 'node_joined' event to same-group online nodes.

        This is a lightweight push notification so existing nodes can trigger
        an immediate discovery/election cycle rather than waiting for the next
        30-second polling interval.  Only non-hidden, same-group peers receive
        the notification.  The payload is minimal (just node_id + group) to
        avoid leaking registration details.
        """
        new_group = new_profile.group
        if not new_group or new_group == "*":
            return  # default group: no election, skip broadcast

        notified = 0
        for pt, (prof, ws) in list(self._nodes.items()):
            if pt == new_token:
                continue  # don't notify the new node itself
            # Only notify same-group nodes
            if prof.group != new_group:
                continue
            try:
                await self._send(ws, {
                    "type": "node_joined",
                    "node_id": new_profile.node_id,
                    "group": new_group,
                })
                notified += 1
            except Exception:
                pass  # best effort — node may have disconnected

        if notified:
            log.info(f"[rendezvous] 📢 node_joined broadcast: {new_profile.node_id} → "
                     f"{notified} same-group peer(s) (group={new_group})")

    async def _on_list(self, msg: dict, ws, peer_token: str):
        query_tags = msg.get("tags", [])           # filter by tags (OR match)
        query_text = str(msg.get("q", "")).lower() # full-text: node_id + nickname + tags

        # Resolve requester's profile for group filtering and affinity scoring
        requester_prof = self._nodes[peer_token][0] if peer_token in self._nodes else None
        requester_group = requester_prof.group if requester_prof else ""
        # Normalize: "" and "*" both mean "default group" (smart match mode)
        is_default_group = (not requester_group) or requester_group == "*"

        # Smart match limit for default group — avoid broadcast storm
        DEFAULT_GROUP_MAX = 5

        results = []
        for pt, (prof, _) in self._nodes.items():
            if pt == peer_token:
                continue  # don't list self
            if prof.hidden:
                continue

            # ── Group filtering ──
            peer_group = prof.group
            peer_is_default = (not peer_group) or peer_group == "*"

            if not is_default_group:
                # Requester is in a named group → only show same-group nodes
                if peer_group != requester_group:
                    continue
            else:
                # Requester is in default group → only show other default-group nodes
                if not peer_is_default:
                    continue

            # ── Tag / text filters (applied on top of group filter) ──
            if query_tags and not any(t in prof.tags for t in query_tags):
                continue
            if query_text and (
                query_text not in prof.node_id.lower() and
                query_text not in prof.nickname.lower() and
                not any(query_text in t.lower() for t in prof.tags)
            ):
                continue
            results.append(prof.public_view())

        # ── Default group: rank by affinity and cap at DEFAULT_GROUP_MAX ──
        if is_default_group and requester_prof and len(results) > DEFAULT_GROUP_MAX:
            results = self._rank_by_affinity(requester_prof, results, DEFAULT_GROUP_MAX)

        await self._send(ws, {"type": "listed", "nodes": results, "total": len(results)})

    @staticmethod
    def _rank_by_affinity(requester: "KiteProfile", candidates: list, top_n: int) -> list:
        """Rank candidate nodes by affinity with the requester, return top N.

        Affinity score = shared tags count (nodes with overlapping capabilities rank higher).
        """
        my_tags = set(t.lower() for t in requester.tags)

        scored = []
        for node in candidates:
            score = 0.0
            # Tag overlap (capability matching)
            node_tags = set(t.lower() for t in node.get("tags", []))
            score += len(my_tags & node_tags) * 3.0
            scored.append((score, node))

        # Sort by score descending, then by joined_at descending (newest first for ties)
        scored.sort(key=lambda x: (x[0], x[1].get("joined_at", 0)), reverse=True)
        return [node for _, node in scored[:top_n]]

    async def _on_register_relay(self, msg: dict, ws, from_token: str):
        """Register a relay pair between two nodes.

        Called by nodes after they have established a P2P connection and want
        to set up a fallback relay path through the Rendezvous server.

        Protocol:
          → {"type": "register_relay", "pair_id": "...", "peer_node_id": "..."}
          ← {"type": "relay_registered", "pair_id": "..."}
        """
        pair_id = str(msg.get("pair_id", "")).strip()
        peer_node_id = str(msg.get("peer_node_id", "")).strip()
        if not pair_id or not peer_node_id:
            await self._send(ws, {"type": "error", "reason": "pair_id_and_peer_required"})
            return

        from_prof, _ = self._nodes[from_token]

        # Deduplicate: if these two nodes already have an active pair, remove the old one
        pair_members = {from_prof.node_id, peer_node_id}
        stale_pairs = [pid for pid, members in self._relay_pairs.items() if members == pair_members]
        for pid in stale_pairs:
            self._relay_pairs.pop(pid, None)
            log.info(f"[rendezvous] ♻️ Removed stale relay pair {pid} "
                     f"(re-registering {from_prof.node_id} ↔ {peer_node_id})")

        self._relay_pairs[pair_id] = pair_members
        log.info(f"[rendezvous] 📡 Relay pair registered: {from_prof.node_id} ↔ {peer_node_id} "
                 f"(pair_id={pair_id})")
        self._events.append("relay_registered", from_prof.node_id,
                            peer=peer_node_id, pair_id=pair_id)
        await self._send(ws, {"type": "relay_registered", "pair_id": pair_id})

    async def _on_punch_ready(self, msg: dict, ws, peer_token: str):
        """Coordinate UDP hole-punch between two nodes.

        When a node sends punch_ready, it declares its STUN-discovered public
        address and the pair_id it is trying to connect for.  The Rendezvous
        server buffers the first arrival; when the second node with the same
        pair_id sends punch_ready, both sides receive a punch_start message
        containing the other's public address so they can begin UDP probing.

        If only one side sends punch_ready (e.g. single-sided invite), the
        client-side puncher will time out and fall back to TCP or relay
        automatically — no harm done.

        Protocol:
          → {"type": "punch_ready", "pair_id": "...", "public_addr": "ip:port"}
          ← {"type": "punch_start", "pair_id": "...", "peer_public_addr": "ip:port"}
             (sent to BOTH sides once the pair is matched)
        """
        pair_id = str(msg.get("pair_id", "")).strip()
        public_addr = str(msg.get("public_addr", "")).strip()
        if not pair_id:
            await self._send(ws, {"type": "error", "reason": "pair_id_required"})
            return

        from_prof, _ = self._nodes[peer_token]

        pending = self._punch_pending.get(pair_id)
        if pending is None:
            # First node to signal readiness — buffer it
            self._punch_pending[pair_id] = (peer_token, public_addr)
            log.info(f"[rendezvous] 🥊 punch_ready buffered: {from_prof.display_name} "
                     f"pair={pair_id[:12]} addr={_mask_ip(public_addr) if public_addr else '(none)'}")
        else:
            # Second node arrived — match them
            first_token, first_addr = pending
            self._punch_pending.pop(pair_id, None)

            if first_token not in self._nodes:
                # First node went offline before second arrived
                log.warning(f"[rendezvous] 🥊 punch_ready: first peer left before match "
                            f"(pair={pair_id[:12]})")
                # Buffer this one instead
                self._punch_pending[pair_id] = (peer_token, public_addr)
                return

            first_prof, first_ws = self._nodes[first_token]
            log.info(f"[rendezvous] 🥊 punch_start! {first_prof.display_name} ↔ "
                     f"{from_prof.display_name} (pair={pair_id[:12]})")

            # Send punch_start to both sides with the other's public address
            await self._send(first_ws, {
                "type": "punch_start",
                "pair_id": pair_id,
                "peer_public_addr": public_addr,       # second node's addr → first node
            })
            await self._send(ws, {
                "type": "punch_start",
                "pair_id": pair_id,
                "peer_public_addr": first_addr,         # first node's addr → second node
            })

    async def _on_update_metadata(self, msg: dict, ws, peer_token: str):
        """Update metadata for the registered node.

        Used for arbitrary key-value metadata updates (e.g. leader election announce).

        Protocol:
          → {"type": "update_metadata", "metadata": {"key": "value"}}
          ← {"type": "metadata_updated"}
        """
        raw_meta = msg.get("metadata")
        if not isinstance(raw_meta, dict):
            await self._send(ws, {"type": "error", "reason": "metadata_must_be_dict"})
            return

        # Sanitize: max 16 keys, key max 32 chars, value max 256 chars
        sanitized = {}
        for k, v in list(raw_meta.items())[:16]:
            sanitized[str(k)[:32]] = str(v)[:256]

        profile, _ = self._nodes[peer_token]
        profile.metadata.update(sanitized)
        log.info(f"[rendezvous] 📝 {profile.display_name} updated metadata: "
                 f"{list(sanitized.keys())}")
        await self._send(ws, {"type": "metadata_updated"})

    async def _on_update_public_addr(self, msg: dict, ws, peer_token: str):
        """Update the STUN-discovered public address for the registered node.

        Called by nodes after startup STUN discovery completes (which happens
        after the initial registration, so public_addr is empty at register time).

        Protocol:
          → {"type": "update_public_addr", "public_addr": "ip:port"}
          ← {"type": "public_addr_updated"}
        """
        public_addr = str(msg.get("public_addr", "")).strip()[:64]
        if not public_addr:
            await self._send(ws, {"type": "error", "reason": "public_addr_required"})
            return

        profile, _ = self._nodes[peer_token]
        old_addr = profile.public_addr
        profile.public_addr = public_addr
        log.info(f"[rendezvous] 🌐 {profile.display_name} public_addr updated: "
                 f"{_mask_ip(old_addr) if old_addr else '(none)'} → {_mask_ip(public_addr)}")
        await self._send(ws, {"type": "public_addr_updated"})

    async def _on_relay(self, msg: dict, ws, from_token: str):
        """
        Relay raw data between paired nodes (fallback when hole punch fails).
        Only forwards to nodes that share a known pair — no open relay.
        """
        import base64
        pair_id = str(msg.get("pair_id", "")).strip()
        raw_data = msg.get("data", "")
        if not pair_id or not raw_data:
            return

        # ── Size limit: reject oversized relay payloads (max 1 MB base64 ≈ 750 KB raw) ──
        MAX_RELAY_SIZE = 1_048_576
        if len(raw_data) > MAX_RELAY_SIZE:
            await self._send(ws, {"type": "error", "reason": "relay_payload_too_large"})
            return

        from_prof, _ = self._nodes[from_token]

        # ── Verify SENDER belongs to this pair (not just receiver) ──
        pair_members = self._relay_pairs.get(pair_id, set())
        if from_prof.node_id not in pair_members:
            await self._send(ws, {"type": "error", "reason": "relay_unauthorized"})
            return

        # Find the other side of this pair
        target_token = None
        for token, (prof, _) in self._nodes.items():
            if token == from_token:
                continue
            if prof.node_id in pair_members:
                target_token = token
                break

        if not target_token:
            await self._send(ws, {"type": "error", "reason": "relay_pair_not_found"})
            return

        _, target_ws = self._nodes[target_token]
        relay_msg = {
            "type": "relay_data",
            "pair_id": pair_id,
            "from": from_prof.node_id,
            "data": raw_data,
        }
        # Forward 'kind' tag if present (e.g. "kitp" for direct KITP JSON relay)
        msg_kind = msg.get("kind", "")
        if msg_kind:
            relay_msg["kind"] = msg_kind
        await self._send(target_ws, relay_msg)
        # Lookup target node_id for logging (never log peer_token)
        target_nid = self._nodes[target_token][0].node_id if target_token in self._nodes else "?"
        log.debug(f"[rendezvous] relay pair={pair_id} {from_prof.node_id} → {target_nid}")
        self._stats["total_relays"] += 1

    # ── Helper Functions ──

    async def _stale_node_cleanup_loop(self):
        """Periodically evict nodes that have stopped sending heartbeats.

        If a node's ``last_active_at`` exceeds ``NODE_STALE_TIMEOUT`` seconds,
        it is considered dead (process alive but connection lost). Close its WebSocket
        and remove it, so the client reconnect loop can re-register with a new connection.
        """
        while True:
            await asyncio.sleep(60)  # check every 60s
            now = time.time()
            stale_tokens = []
            for pt, (prof, ws) in list(self._nodes.items()):
                idle = now - prof.last_active_at
                if idle > NODE_STALE_TIMEOUT:
                    stale_tokens.append((pt, prof, ws, idle))

            for pt, prof, ws, idle in stale_tokens:
                log.warning(
                    f"[rendezvous] 💀 {prof.emoji} {prof.display_name} no heartbeat "
                    f"{int(idle)}s (>{NODE_STALE_TIMEOUT}s) — stale, force removing"
                )
                await self._remove_node(pt)
                # Force-close the zombie WebSocket so TCP resources are freed
                try:
                    await ws.close(1001, "stale: no keepalive")
                except Exception:
                    pass

    async def _remove_node(self, peer_token: str):
        entry = self._nodes.pop(peer_token, None)
        if entry:
            prof, _ = entry
            self._id_index.pop(prof.node_id, None)
            self._stats["total_disconnects"] += 1
            self._events.append("disconnect", prof.node_id, remote_ip=prof.remote_ip)
            remaining = len(self._nodes)
            log.info(f"[rendezvous] 👋 {prof.emoji} {prof.display_name} left the beach")

            # Clean up relay pairs where this node was a member
            stale_pairs = [
                pid for pid, members in self._relay_pairs.items()
                if prof.node_id in members
            ]
            for pid in stale_pairs:
                self._relay_pairs.pop(pid, None)
            if stale_pairs:
                log.info(f"[rendezvous]   cleaned {len(stale_pairs)} relay pair(s) for {prof.node_id}")

            # Clean up pending punch_ready entries for this node
            stale_punches = [
                pid for pid, (pt, _) in self._punch_pending.items()
                if pt == peer_token
            ]
            for pid in stale_punches:
                self._punch_pending.pop(pid, None)

    @staticmethod
    async def _send(ws, data: dict):
        try:
            await ws.send(json.dumps(data))
        except Exception as e:
            log.debug(f"[send] Failed to send message: {e}")

    # ── Admin HTTP API ──

    # Allowed source IPs for Admin API (localhost only)
    _ADMIN_ALLOWED_IPS = {"127.0.0.1", "::1"}

    async def _admin_handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Minimal HTTP/1.1 handler for admin queries (localhost only, no framework dependency)."""
        try:
            # ── Access control: reject non-localhost clients ──
            peer = writer.get_extra_info("peername")
            client_ip = peer[0] if peer else ""
            if client_ip not in self._ADMIN_ALLOWED_IPS:
                log.warning(f"[admin] BLOCKED request from {_mask_ip(client_ip)} — only localhost allowed")
                resp = (
                    "HTTP/1.1 403 Forbidden\r\n"
                    "Content-Type: application/json; charset=utf-8\r\n"
                    "Content-Length: 52\r\n"
                    "Connection: close\r\n\r\n"
                    '{"error":"forbidden","detail":"localhost access only"}'
                )
                writer.write(resp.encode("utf-8"))
                await writer.drain()
                writer.close()
                return

            request_line = await asyncio.wait_for(reader.readline(), timeout=5.0)
            if not request_line:
                writer.close()
                return

            parts = request_line.decode("utf-8", errors="replace").strip().split()
            method = parts[0] if parts else "GET"
            raw_path = parts[1] if len(parts) > 1 else "/"

            # Consume remaining headers
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=5.0)
                if line in (b"\r\n", b"\n", b""):
                    break

            # Parse path and query string
            path = raw_path.split("?")[0].rstrip("/") or "/"
            query = {}
            if "?" in raw_path:
                for kv in raw_path.split("?", 1)[1].split("&"):
                    if "=" in kv:
                        k, v = kv.split("=", 1)
                        query[k] = v

            # Route
            if path == "/status":
                body = self._admin_status()
            elif path == "/overview":
                body = self._admin_overview(query)
            elif path == "/list":
                body = self._admin_list(query)
            elif path == "/nodes":
                body = self._admin_nodes(query)
            elif path.startswith("/nodes/"):
                node_id = path[len("/nodes/"):]
                body = self._admin_node_detail(node_id)
            elif path == "/groups":
                body = self._admin_groups()
            elif path.startswith("/groups/"):
                group_name = path[len("/groups/"):]
                body = self._admin_group_detail(group_name)
            elif path == "/pairs":
                body = self._admin_pairs()
            elif path == "/events":
                body = self._admin_events(query)
            else:
                body = self._admin_help()

            payload = json.dumps(body, ensure_ascii=False, indent=2).encode("utf-8")
            header = (
                f"HTTP/1.1 200 OK\r\n"
                f"Content-Type: application/json; charset=utf-8\r\n"
                f"Content-Length: {len(payload)}\r\n"
                f"Connection: close\r\n\r\n"
            )
            writer.write(header.encode("utf-8") + payload)
            await writer.drain()
        except Exception as e:
            log.debug(f"[admin] request error: {e}")
        finally:
            writer.close()

    def _admin_help(self) -> dict:
        return {
            "service": "KiteSurf Rendezvous Admin API",
            "security": "Localhost only (127.0.0.1 / ::1)",
            "endpoints": {
                "GET /status": "Server overview (uptime, online count, group stats)",
                "GET /overview": "Node list dashboard (status categories, pagination, sorting and search)",
                "GET /overview?page=1&size=20": "Paginated node list (default page=1, size=50, max size=200)",
                "GET /overview?sort=idle|joined|name": "Sort by idle time/join time/name (default: idle)",
                "GET /overview?order=asc|desc": "Sort direction (default: idle asc, joined desc)",
                "GET /overview?q=<keyword>": "Search by node_id, nickname or tags",
                "GET /overview?group=<name>": "Filter by group (empty string = default group)",
                "GET /overview?status=active|idle|stale": "Filter by health status",
                "GET /list": "Lightweight node inventory (node_id, nickname, emoji, group, tags, idle time only)",
                "GET /list?group=<name>": "Filter by group",
                "GET /list?q=<keyword>": "Search by node_id, nickname or tags",
                "GET /nodes": "List all online nodes with full details",
                "GET /nodes?group=<name>": "Filter nodes by group (empty string = default group)",
                "GET /nodes/<node_id>": "Single node details",
                "GET /groups": "List all groups with member counts and details",
                "GET /groups/<group_name>": "Single group details with member list",
                "GET /pairs": "Active relay pairs",
                "GET /events": "Recent event log (last 24 hours)",
                "GET /events?type=<type>": "Filter events by type (register, disconnect, relay_registered, ...)",
                "GET /events?node_id=<id>": "Filter events by node_id",
                "GET /events?limit=<n>": "Limit number of returned events (default 200)",
            },
        }

    def _admin_status(self) -> dict:
        uptime = time.time() - self._start_time
        # Compute group stats
        group_counts: Dict[str, int] = {}
        for pt, (prof, _) in self._nodes.items():
            g = prof.group if prof.group and prof.group != "*" else ""
            group_counts[g] = group_counts.get(g, 0) + 1
        return {
            "status": "running",
            "uptime_seconds": round(uptime),
            "uptime_human": _fmt_duration(uptime),
            "started_at": datetime.datetime.fromtimestamp(self._start_time).strftime("%Y-%m-%d %H:%M:%S"),
            "online_nodes": len(self._nodes),
            "groups": {
                "count": len(group_counts),
                "breakdown": {(k or "(default)"): v for k, v in sorted(group_counts.items(), key=lambda x: -x[1])},
            },
            "active_relay_pairs": len(self._relay_pairs),
            "stats": dict(self._stats),
        }

    def _admin_list(self, query: dict) -> dict:
        """GET /list — Lightweight node list with only essential fields.

        Returns a compact table-friendly list: node_id, nickname, emoji,
        group, tags, and idle time. No IP, no uptime.

        Query parameters:
          group — filter by group name ("" for default group)
          q     — keyword search (node_id, nickname, tags)
        """
        filter_group = query.get("group", None)
        q = query.get("q", "").lower().strip()

        items = []
        for pt, (prof, _) in self._nodes.items():
            # Group filter
            if filter_group is not None:
                node_group = prof.group if prof.group and prof.group != "*" else ""
                if node_group != filter_group:
                    continue
            # Keyword search
            if q:
                haystack = (
                    prof.node_id.lower() + " " +
                    prof.nickname.lower() + " " +
                    " ".join(t.lower() for t in prof.tags)
                )
                if q not in haystack:
                    continue
            items.append(prof.brief_view())

        # Sort by idle ascending (most active first)
        items.sort(key=lambda x: x["idle_seconds"])

        result = {"online_count": len(items), "nodes": items}
        if filter_group is not None:
            result["filter_group"] = filter_group or "(default)"
        if q:
            result["filter_q"] = q
        return result

    # ── Health thresholds for overview classification ──
    _ACTIVE_THRESHOLD = 30     # last active within 30s → "active"
    _IDLE_THRESHOLD = 90       # 30s ~ 90s → "idle"
    # > 90s → "stale" (approaching NODE_STALE_TIMEOUT=120s eviction)

    def _admin_overview(self, query: dict) -> dict:
        """GET /overview — Node list dashboard with health classification,
        group breakdown, pagination, sorting and keyword search.

        Query parameters:
          page   — page number, starting from 1 (default: 1)
          size   — items per page (default: 50, max: 200)
          sort   — "idle" (default) | "joined" | "name"
          order  — "asc" (default for idle) | "desc" (default for joined/name)
          q      — keyword search (node_id, nickname, tags)
          group  — filter by group name ("" for default group)
          status — filter by health status: "active" | "idle" | "stale"
        """
        now = time.time()

        # ── Parse query params ──
        try:
            page = max(1, int(query.get("page", "1")))
        except (ValueError, TypeError):
            page = 1
        try:
            size = min(200, max(1, int(query.get("size", "50"))))
        except (ValueError, TypeError):
            size = 50
        sort_by = query.get("sort", "idle")
        if sort_by not in ("idle", "joined", "name"):
            sort_by = "idle"
        order = query.get("order", "")
        q = query.get("q", "").lower().strip()
        filter_group = query.get("group", None)
        filter_status = query.get("status", "").lower().strip()
        if filter_status and filter_status not in ("active", "idle", "stale"):
            filter_status = ""

        # ── Classify all nodes ──
        all_items = []
        status_counts = {"active": 0, "idle": 0, "stale": 0}
        group_counts: Dict[str, int] = {}

        for pt, (prof, _) in self._nodes.items():
            idle_sec = now - prof.last_active_at
            # Health classification
            if idle_sec <= self._ACTIVE_THRESHOLD:
                health = "active"
            elif idle_sec <= self._IDLE_THRESHOLD:
                health = "idle"
            else:
                health = "stale"

            status_counts[health] += 1
            g = prof.group if prof.group and prof.group != "*" else ""
            group_counts[g] = group_counts.get(g, 0) + 1

            # ── Filters ──
            # Group filter
            if filter_group is not None:
                node_group = prof.group if prof.group and prof.group != "*" else ""
                if node_group != filter_group:
                    continue

            # Status filter
            if filter_status and health != filter_status:
                continue

            # Keyword search
            if q:
                haystack = (
                    prof.node_id.lower() + " " +
                    prof.nickname.lower() + " " +
                    " ".join(t.lower() for t in prof.tags)
                )
                if q not in haystack:
                    continue

            # Count active relay pairs for this node
            pair_count = sum(
                1 for members in self._relay_pairs.values()
                if prof.node_id in members
            )

            item = {
                "node_id": prof.node_id,
                "nickname": prof.nickname,
                "emoji": prof.emoji,
                "group": g or "(default)",
                "tags": prof.tags,
                "status": health,
                "idle_seconds": round(idle_sec),
                "idle_human": _fmt_duration(idle_sec),
                "uptime_seconds": round(now - prof.joined_at),
                "uptime_human": _fmt_duration(now - prof.joined_at),
                "joined_at": datetime.datetime.fromtimestamp(prof.joined_at).strftime("%Y-%m-%d %H:%M:%S"),
                "version": prof.version,
                "remote_ip": _mask_ip(prof.remote_ip),
                "active_pairs": pair_count,
                "hidden": prof.hidden,
            }
            all_items.append(item)

        # ── Sort ──
        if sort_by == "idle":
            default_order = "asc"   # least idle first (most active)
            all_items.sort(key=lambda x: x["idle_seconds"], reverse=(order or default_order) == "desc")
        elif sort_by == "joined":
            default_order = "desc"  # newest first
            all_items.sort(key=lambda x: x["uptime_seconds"], reverse=(order or default_order) == "asc")
        elif sort_by == "name":
            default_order = "asc"
            all_items.sort(key=lambda x: (x["nickname"] or x["node_id"]).lower(),
                           reverse=(order or default_order) == "desc")

        # ── Paginate ──
        total_filtered = len(all_items)
        total_pages = max(1, (total_filtered + size - 1) // size)
        page = min(page, total_pages)
        start = (page - 1) * size
        page_items = all_items[start:start + size]

        return {
            "summary": {
                "total_online": len(self._nodes),
                "active": status_counts["active"],
                "idle": status_counts["idle"],
                "stale": status_counts["stale"],
                "groups": {(k or "(default)"): v for k, v in
                           sorted(group_counts.items(), key=lambda x: -x[1])},
                "active_relay_pairs": len(self._relay_pairs),
            },
            "pagination": {
                "page": page,
                "size": size,
                "total_items": total_filtered,
                "total_pages": total_pages,
            },
            "filters": {
                "q": q or None,
                "group": filter_group,
                "status": filter_status or None,
                "sort": sort_by,
                "order": order or default_order,
            },
            "nodes": page_items,
        }

    def _admin_nodes(self, query: dict) -> dict:
        filter_group = query.get("group", None)  # None = no filter, "" = default group
        nodes = []
        for pt, (prof, ws) in self._nodes.items():
            if filter_group is not None:
                node_group = prof.group if prof.group and prof.group != "*" else ""
                if node_group != filter_group:
                    continue
            nodes.append(prof.admin_view())
        # Sort by joined_at descending (newest first)
        nodes.sort(key=lambda n: n["joined_at"], reverse=True)
        result = {"online_count": len(nodes), "nodes": nodes}
        if filter_group is not None:
            result["filter_group"] = filter_group or "(default)"
        return result

    def _admin_node_detail(self, node_id: str) -> dict:
        if node_id not in self._id_index:
            return {"error": "node_not_found", "node_id": node_id}
        token = self._id_index[node_id]
        if token not in self._nodes:
            return {"error": "node_offline", "node_id": node_id}
        prof, _ = self._nodes[token]
        # Also gather this node's relay pairs
        pairs = []
        for pair_id, members in self._relay_pairs.items():
            if node_id in members:
                pairs.append({"pair_id": pair_id, "members": list(members)})
        # Recent events for this node
        recent_events = self._events.query(node_id=node_id, limit=50)
        return {
            "node": prof.admin_view(),
            "relay_pairs": pairs,
            "recent_events": recent_events,
        }

    def _admin_pairs(self) -> dict:
        pairs = []
        for pair_id, members in self._relay_pairs.items():
            member_list = list(members)
            pair_info = {"pair_id": pair_id, "members": member_list}
            # Check if members are still online
            for m in member_list:
                pair_info[f"{m}_online"] = m in self._id_index
            pairs.append(pair_info)
        return {"active_pairs": len(pairs), "pairs": pairs}

    def _admin_groups(self) -> dict:
        """List all groups with member counts and node details."""
        groups: Dict[str, list] = {}
        for pt, (prof, _) in self._nodes.items():
            g = prof.group if prof.group and prof.group != "*" else ""
            groups.setdefault(g, []).append(prof.admin_view())
        result = []
        for g_name, members in sorted(groups.items(), key=lambda x: -len(x[1])):
            result.append({
                "group": g_name or "(default)",
                "member_count": len(members),
                "members": [m["node_id"] for m in members],
            })
        return {"group_count": len(result), "groups": result}

    def _admin_group_detail(self, group_name: str) -> dict:
        """Detail for a single group — list all members with full admin_view."""
        # Normalize: "(default)" or empty → match default group
        is_default_query = group_name in ("(default)", "default", "")
        members = []
        for pt, (prof, _) in self._nodes.items():
            node_group = prof.group if prof.group and prof.group != "*" else ""
            if is_default_query:
                if node_group != "":
                    continue
            else:
                if node_group != group_name:
                    continue
            members.append(prof.admin_view())
        members.sort(key=lambda n: n["joined_at"], reverse=True)
        display_name = group_name if not is_default_query else "(default)"
        return {
            "group": display_name,
            "member_count": len(members),
            "nodes": members,
        }

    def _admin_events(self, query: dict) -> dict:
        event_type = query.get("type", None)
        node_id = query.get("node_id", None)
        try:
            limit = min(int(query.get("limit", "200")), 1000)
        except (ValueError, TypeError):
            limit = 200
        events = self._events.query(event_type=event_type, node_id=node_id, limit=limit)
        return {
            "count": len(events),
            "filter": {"type": event_type, "node_id": node_id, "limit": limit},
            "events": events,
        }


# ──────────────────────────── CLI ────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="KiteSurf Rendezvous Server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=17851)
    parser.add_argument("--admin-port", type=int, default=17852, help="Admin HTTP API port")
    parser.add_argument("--ssl-cert", default=None,
                        help="SSL certificate path (.pem) for wss:// support")
    parser.add_argument("--ssl-key", default=None,
                        help="SSL private key path (.pem) for wss:// support")
    args = parser.parse_args()
    server = KiteRendezvousServer(
        host=args.host, port=args.port, admin_port=args.admin_port,
        ssl_cert=args.ssl_cert, ssl_key=args.ssl_key,
    )
    asyncio.run(server.start())


if __name__ == "__main__":
    main()
