#!/usr/bin/env python3
# Copyright (c) 2026 KiteSurf Contributors — MIT License
# See LICENSE file for details.
"""
kitesurf: WebSocket-based inter-Agent communication node
Protocol: KITP (KiteSurf Inter-node Transport Protocol) v1

Pairing extension: optional Rendezvous-based node discovery.
Enable by setting rendezvous_url + config file fields in KiteNode.
"""

import asyncio
import hashlib
import json
import logging
import socket
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

# Optional: notification system (may not be available in standalone mode)
try:
    import kite_notify as _kn
except ImportError:
    _kn = None
from typing import Any, Callable, Dict, List, Optional


def _generate_node_id() -> str:
    """Generate a stable, machine-unique node_id based on MAC address + hostname.
    Format: node-<12 hex digits>  e.g. node-a3f9c201b84e
    The same machine always produces the same ID across restarts.
    """
    mac = uuid.getnode()          # 48-bit MAC address as int
    hostname = socket.gethostname()
    raw = f"{mac}-{hostname}"
    digest = hashlib.sha256(raw.encode()).hexdigest()
    return f"node-{digest[:12]}"

from websockets.asyncio.server import serve as ws_serve
from websockets.asyncio.client import connect as ws_connect
from websockets.exceptions import ConnectionClosed as WsConnectionClosed

from kite_utils import mask_ip as _mask_ip

# ── Ed25519 public-key authentication ──────────────────────────────
# Used for signing and verifying all KITP messages.
# Replaces the old shared-secret HMAC model — private key never leaves the node.
try:
    from nacl.signing import SigningKey as _Ed25519SigningKey, VerifyKey as _Ed25519VerifyKey
    from nacl.exceptions import BadSignatureError as _BadSigError
    HAS_NACL = True
except ImportError:
    HAS_NACL = False
    _Ed25519SigningKey = None
    _Ed25519VerifyKey = None
    _BadSigError = Exception

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("kitesurf")

# ─────────────────────────── Protocol Types ────────────────────────────

KITE_HELLO    = "hello"      # handshake initiation
KITE_WELCOME  = "welcome"    # handshake accepted
KITE_REJECT   = "reject"     # handshake rejected
KITE_PING     = "ping"
KITE_PONG     = "pong"
KITE_TASK     = "task"       # submit task to remote Agent
KITE_RESULT   = "result"     # task completion callback
KITE_ERROR    = "error"      # task error callback
KITE_FORWARD  = "forward"    # forward message to another node

# ── KiteChain v2 — Blockchain message types (§5.2 of KiteChain Whitepaper) ──
KITE_CHAIN_TX       = "chain_tx"        # broadcast new transaction to Mempool
KITE_CHAIN_BLOCK    = "chain_block"     # broadcast new block from producer
KITE_CHAIN_CONFIRM  = "chain_confirm"   # BFT confirmation signature
KITE_CHAIN_SYNC_REQ = "chain_sync_req"  # request block sync (height range)
KITE_CHAIN_SYNC_RESP = "chain_sync_resp" # return block data
KITE_CHAIN_STATE_REQ = "chain_state_req" # request ledger state snapshot

# ───────────────────────────── Data Models ─────────────────────────────

@dataclass
class KiteMessage:
    type: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    ts: float = field(default_factory=time.time)
    from_node: str = ""
    to_node: str = ""
    payload: Dict[str, Any] = field(default_factory=dict)
    sig: str = ""
    # ── KiteChain v2 — On-chain transaction metadata (§8.2 of Whitepaper) ──
    # Populated only for chain_tx / chain_block / chain_confirm messages.
    # For regular KITP messages (task/result/ping/etc.), this remains None.
    chain_meta: Optional[Dict[str, Any]] = field(default=None)
    # chain_meta schema (when present):
    #   tx_type:    str   — "transfer"|"skill_register"|"skill_call"|"skill_settle"|"stake"|...
    #   tx_id:      str   — SHA-256 hash of canonical transaction
    #   nonce:      int   — sender account nonce (anti-replay)
    #   amount:     int   — value in smallest unit (1 KITE = 10^8)
    #   fee:        int   — transaction fee in smallest unit
    #   wallet_address: str — sender's Ed25519 public key (hex)

    def sign(self, signing_key: "_Ed25519SigningKey") -> "KiteMessage":
        """Sign this message with the sender's Ed25519 private key.

        The signature is stored as a hex string in self.sig.
        The private key never leaves the node — only the public key is shared.
        """
        self.sig = _sign_ed25519(self._signable(), signing_key)
        return self

    def verify(self, verify_key: "_Ed25519VerifyKey", max_age: float = 300.0) -> bool:
        """Verify Ed25519 signature and optional timestamp freshness.

        Args:
            verify_key: peer's Ed25519 public (verify) key
            max_age: maximum allowed message age (seconds), 0 = skip check.
                     Default 300s (5 minutes) to prevent replay attacks.
        """
        if not _verify_ed25519(self._signable(), self.sig, verify_key):
            return False
        # Timestamp freshness check — reject replayed or far-future messages
        if max_age > 0:
            drift = abs(time.time() - self.ts)
            if drift > max_age:
                return False
        return True

    def _signable(self) -> str:
        """Build the canonical string for signing.

        Includes all mutable fields to prevent any field from being tampered with:
          type:id:ts:from_node:to_node:compact_json(payload):compact_json(chain_meta)
        """
        payload_str = json.dumps(self.payload, sort_keys=True, separators=(",", ":")) if self.payload else ""
        chain_str = json.dumps(self.chain_meta, sort_keys=True, separators=(",", ":")) if self.chain_meta else ""
        return f"{self.type}:{self.id}:{self.ts:.3f}:{self.from_node}:{self.to_node}:{payload_str}:{chain_str}"

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, raw: str) -> "KiteMessage":
        d = json.loads(raw)
        return cls(**d)


def _sign_ed25519(data: str, signing_key: "_Ed25519SigningKey") -> str:
    """Sign data with Ed25519 private key, return hex signature."""
    if not HAS_NACL or signing_key is None:
        return ""
    signed = signing_key.sign(data.encode("utf-8"))
    return signed.signature.hex()


def _verify_ed25519(data: str, sig_hex: str, verify_key: "_Ed25519VerifyKey") -> bool:
    """Verify Ed25519 signature. Returns True if valid, False otherwise."""
    if not HAS_NACL or verify_key is None or not sig_hex:
        return False
    try:
        verify_key.verify(data.encode("utf-8"), bytes.fromhex(sig_hex))
        return True
    except (_BadSigError, ValueError):
        return False
    except Exception:
        return False


def _load_or_create_wallet(wallet_path: str) -> tuple:
    """Load or auto-generate an Ed25519 wallet (keypair).

    Returns:
        (signing_key, verify_key, wallet_address_hex, wallet_pubkey_hex)
    """
    if not HAS_NACL:
        log.error("[wallet] ❌ 'PyNaCl' package not installed — Ed25519 auth unavailable. "
                  "Install with: pip install pynacl")
        return None, None, "", ""

    p = Path(wallet_path)
    if p.exists():
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            sk_hex = data.get("private_key", "")
            if sk_hex:
                sk = _Ed25519SigningKey(bytes.fromhex(sk_hex))
                vk = sk.verify_key
                addr = data.get("address", vk.encode().hex())
                log.info(f"[wallet] 🔑 Loaded wallet from {wallet_path}  addr={addr[:16]}...")
                return sk, vk, addr, vk.encode().hex()
        except Exception as e:
            log.warning(f"[wallet] ⚠️  Failed to load wallet from {wallet_path}: {e} — regenerating")

    # Auto-generate a new wallet
    sk = _Ed25519SigningKey.generate()
    vk = sk.verify_key
    addr = vk.encode().hex()
    wallet_data = {
        "private_key": sk.encode().hex(),
        "public_key": vk.encode().hex(),
        "address": addr,
    }
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(wallet_data, indent=2), encoding="utf-8")
        # Restrict wallet file permissions to owner-only (best-effort on Windows)
        try:
            p.chmod(0o600)
        except (OSError, NotImplementedError):
            pass  # chmod may not work on all platforms (e.g. Windows)
        log.info(f"[wallet] 🆕 Generated new Ed25519 wallet → {wallet_path}  addr={addr[:16]}...")
    except Exception as e:
        log.warning(f"[wallet] ⚠️  Could not persist wallet to {wallet_path}: {e}")
    return sk, vk, addr, vk.encode().hex()


# ──────────────────────────── Kite Node ────────────────────────────────

class _RelayBridge:
    """Wraps a KiteChannel (relay) as a WebSocket-like interface for KITP dispatch.

    KiteChannel.send(bytes) / recv() → bytes
    WebSocket .send(str)   / recv() → str
    This bridge adapts between the two, so _handle_messages / _dispatch need no changes.
    """

    def __init__(self, channel, node_id: str):
        self._ch = channel
        self._node_id = node_id
        self._closed = False

    async def send(self, data: str):
        """Send a JSON string via relay (encoded as bytes)."""
        if self._closed:
            raise RuntimeError("RelayBridge closed")
        await self._ch.send(data.encode("utf-8"))

    async def recv(self) -> str:
        """Receive a JSON string from relay (decoded from bytes)."""
        raw = await self._ch.recv()
        return raw.decode("utf-8")

    async def close(self):
        self._closed = True
        self._ch.close()

    def __aiter__(self):
        return self

    async def __anext__(self) -> str:
        try:
            return await self.recv()
        except RuntimeError:
            raise StopAsyncIteration


class _RendezvousRelayBridge:
    """KITP transport bridge via Rendezvous relay (WebSocket-based).

    An "always available" fallback: when both UDP hole punching and TCP direct
    connection fail, KITP messages are forwarded through the Rendezvous server.
    """

    def __init__(self, pairing_client, pair_id: str, peer_node_id: str,
                 node_id: str):
        self._pairing = pairing_client
        self._pair_id = pair_id
        self._peer_node_id = peer_node_id
        self._node_id = node_id
        self._recv_queue: asyncio.Queue = asyncio.Queue()
        self._closed = False

    async def send(self, data: str):
        """Send a KITP JSON string via Rendezvous relay."""
        if self._closed:
            raise RuntimeError("RendezvousRelayBridge closed")
        # Log relay send for debugging
        try:
            preview = json.loads(data)
            msg_type = preview.get("type", "?")
            msg_id = preview.get("id", "")[:8]
            log.debug(f"[relay-bridge] 📤 {self._node_id} → relay → {self._peer_node_id}: "
                      f"type={msg_type}, id={msg_id}, pair={self._pair_id[:12]}, {len(data)} bytes")
        except Exception:
            pass
        await self._pairing._send({
            "type": "relay",
            "pair_id": self._pair_id,
            "data": data,
            "kind": "kitp",  # tag so receiver knows this is raw KITP, not base64
        })

    async def recv(self) -> str:
        """Receive a KITP JSON string from Rendezvous relay."""
        if self._closed:
            raise RuntimeError("RendezvousRelayBridge closed")
        item = await self._recv_queue.get()
        if item is None:
            raise RuntimeError("RendezvousRelayBridge closed")
        return item

    def push(self, data: str):
        """Called when a relay_data (kind=kitp) message for this pair_id is received."""
        if not self._closed:
            self._recv_queue.put_nowait(data)

    async def close(self):
        self._closed = True
        self._recv_queue.put_nowait(None)  # wake up recv()

    def __aiter__(self):
        return self

    async def __anext__(self) -> str:
        try:
            return await self.recv()
        except RuntimeError:
            raise StopAsyncIteration


class KiteNode:
    def __init__(
        self,
        node_id: str,                            # REQUIRED: auto-generated machine-unique identity
        wallet_path: str = "./wallet.json",      # Ed25519 wallet file (auto-created if missing)
        host: str = "0.0.0.0",
        port: int = 17850,
        peers: Optional[list] = None,
        # ── Pairing / Rendezvous options ──
        rendezvous_url: Optional[str] = None,   # e.g. "wss://rendezvous.example.com:17851"
        nickname: str = "",
        emoji: str = "🪁",
        tags: Optional[List[str]] = None,
        group: str = "",                         # group name: "" or "*" = default (smart match)
        hidden: bool = False,
        auto_accept: bool = False,               # auto-accept all incoming invites
        invite_timeout: float = 120,             # seconds before auto-declining unanswered invites (0=disable)
        invite_handler: Optional[Callable] = None,  # async fn(invite_token, from_profile, message)
        private_skills: Optional[List[str]] = None,  # disclosed only after pairing
        ssl_verify: bool = True,                 # set False to skip TLS cert verification
        allow_insecure: bool = False,            # MUST be True to allow wss→ws downgrade
        keepalive_config: Optional[Dict[str, Any]] = None,  # override smart keepalive params
        # ── KiteChain v2 — Blockchain integration (§7, §12.4 of Whitepaper) ──
        chain_enabled: bool = False,             # enable KiteChain blockchain features
        wallet_address: str = "",                # Ed25519 public key hex (chain identity)
        wallet_pubkey: str = "",                 # full Ed25519 public key hex (for signature verification)
        scp_version: str = "scp/1",              # Skill Call Protocol version (§10)
        chain_capabilities: Optional[List[str]] = None,  # chain-callable Skill IDs
        chain_config: Optional[Dict[str, Any]] = None,   # chain parameters (§14.2)
    ):
        if not node_id or not node_id.strip():
            raise ValueError("node_id is required and cannot be empty (must be auto-generated)")
        self.node_id = node_id

        # ── Ed25519 identity keypair (replaces shared-secret HMAC) ──
        # Private key signs outgoing messages; public key verifies incoming ones.
        # The private key NEVER leaves this node.
        self._signing_key, self._verify_key, self._wallet_addr, self._wallet_pubkey_hex = \
            _load_or_create_wallet(wallet_path)
        # Override wallet_address/pubkey from wallet file if not explicitly provided
        if not wallet_address and self._wallet_addr:
            wallet_address = self._wallet_addr
        if not wallet_pubkey and self._wallet_pubkey_hex:
            wallet_pubkey = self._wallet_pubkey_hex

        self.host = host
        self.port = port
        self.peers: list[str] = peers or []
        self.connections: Dict[str, object] = {}
        self._task_callbacks: Dict[str, Callable] = {}
        self._task_handler: Optional[Callable] = None

        # Per-peer verify keys: peer_node_id → Ed25519VerifyKey
        # Populated during HELLO/WELCOME handshake (peer sends their public key)
        self._peer_verify_keys: Dict[str, "_Ed25519VerifyKey"] = {}

        # Connection-ready futures: peer_node_id → Future
        # Set when KITP handshake completes (connection fully usable)
        self._connect_futures: Dict[str, asyncio.Future] = {}

        # Guard against concurrent connection attempts to the same peer.
        # peer_node_id is added when _on_paired fires, removed on success or failure.
        self._connecting_peers: set = set()

        # ── P2P Smart Keepalive (inspired by WeChat Mars / QQ) ──
        # Per-peer health tracking
        self._peer_last_recv: Dict[str, float] = {}       # last msg received (any type)
        self._peer_rtt: Dict[str, float] = {}             # smoothed RTT in seconds (EWMA)
        self._peer_ping_sent: Dict[str, float] = {}       # ts of last PING sent (for RTT calc)
        self._peer_miss_count: Dict[str, int] = {}        # consecutive ping misses
        self._peer_ping_seq: Dict[str, int] = {}          # monotonic ping counter (nonce)
        # Smart heartbeat parameters (overridable via keepalive_config)
        kc = keepalive_config or {}
        self._P2P_KEEPALIVE_MIN = float(kc.get("min_interval", 20))
        self._P2P_KEEPALIVE_MAX = float(kc.get("max_interval", 55))
        self._P2P_KEEPALIVE_STEP = 5.0
        self._P2P_KEEPALIVE_INTERVAL = float(kc.get("interval", 30))
        self._P2P_MISS_TOLERANCE = int(kc.get("miss_tolerance", 3))
        self._P2P_RTT_ALPHA = 0.3
        self._P2P_ADAPTIVE = bool(kc.get("adaptive", True))
        # Active keepalive tasks per peer (so we can cancel on disconnect)
        self._keepalive_tasks: Dict[str, asyncio.Task] = {}
        # Per-peer adaptive interval (overrides default when smart heartbeat kicks in)
        self._peer_ka_interval: Dict[str, float] = {}

        # Pairing state
        self._rendezvous_url = rendezvous_url
        self._nickname = nickname
        self._emoji = emoji
        self._tags = tags or []
        self._group = group
        self._hidden = hidden
        self._auto_accept = auto_accept
        self._invite_timeout = invite_timeout
        self._invite_handler = invite_handler
        self._private_skills = private_skills or []
        self._ssl_verify = ssl_verify
        self._allow_insecure = allow_insecure
        self._pairing: Optional[Any] = None   # KitePairingClient instance

        # ── Connection approval gate ──
        # When auto_accept=False, inbound connections from non-trusted peers
        # are parked until a human approves via Admin API POST /connect-approve.
        self._pending_connect_approvals: Dict[str, dict] = {}
        self._PENDING_CONNECT_MAX = 20          # max queued connection requests
        self._PENDING_CONNECT_TTL = 300.0       # 5 minutes before auto-decline
        # Active rendezvous relay bridges: pair_id → _RendezvousRelayBridge
        self._relay_bridges: Dict[str, "_RendezvousRelayBridge"] = {}
        # Buffer for relay messages that arrive before bridge is created
        self._relay_early_msgs: Dict[str, list] = {}

        # ── KiteChain v2 state (§7, §12.4 of Whitepaper) ──
        self._chain_enabled = chain_enabled
        self._wallet_address = wallet_address
        self._wallet_pubkey = wallet_pubkey
        self._scp_version = scp_version
        self._chain_capabilities = chain_capabilities or []
        self._chain_config = chain_config or {}

        # ── Gossip Protocol state ──
        self._gossip_enabled = False        # set True via enable_gossip()
        self._gossip = None                 # KiteGossip instance
        self._gossip_port = 17586           # UDP gossip port

        # ── Control-Plane Discovery state ──
        # Discovery loop queries Rendezvous for same-group peers and seeds
        # the gossip protocol.  Once seeded, gossip maintains membership
        # autonomously even if Rendezvous goes offline.
        self._auto_mesh_enabled = False     # set True via enable_gossip(auto_mesh=True)
        self._auto_mesh_task: Optional[asyncio.Task] = None
        # Cluster membership list maintained by gossip protocol
        self._cluster_members: List[str] = []   # other node_ids in the group

        # ── RDV detach state (instance variables — NOT class variables) ──
        # When gossip is healthy, we disconnect from RDV to become autonomous.
        # If gossip empties, we reconnect to RDV for re-seeding.
        self._rdv_detached: bool = False    # True when we intentionally disconnected from RDV
        self._RDV_DETACH_GRACE: int = 60   # seconds — wait for gossip to stabilize before detaching
        self._rdv_connect_task: Optional[asyncio.Task] = None  # tracks reconnect tasks to avoid duplicates
        # Discovery loop parameters (instance-level to avoid cross-instance class-var issues)
        self._RDV_BOOTSTRAP_INTERVAL: int = 30    # seconds — aggressive RDV polling before first seed
        self._RDV_STEADY_INTERVAL: int = 300      # seconds — lazy RDV reseed after gossip is healthy
        self._RDV_SEEDED: bool = False             # has gossip ever been successfully seeded?
        self._RDV_STEADY_KEEPALIVE: int = 120      # seconds — RDV ping interval when gossip is healthy

        # ── Connection strategy timeouts (instance variables) ──
        self._INBOUND_WAIT_TIMEOUT: float = 45.0   # passive side wait for peer inbound connect
        self._RELAY_HANDSHAKE_TIMEOUT: float = 45.0 # relay fallback handshake timeout

        # ── Background task tracking ──
        # All fire-and-forget create_task() calls are tracked here so they can
        # be cancelled in shutdown().  Tasks remove themselves on completion.
        self._background_tasks: set = set()

    # ── Task lifecycle helpers ──

    def _track_task(self, coro, *, name: str = "") -> asyncio.Task:
        """Create an asyncio task and track it in _background_tasks.

        The task automatically removes itself from the set when done.
        This ensures all fire-and-forget tasks can be cancelled in shutdown().
        """
        task = asyncio.create_task(coro, name=name or None)
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)
        return task

    async def shutdown(self):
        """Gracefully shut down this KiteNode and release all resources.

        Cancels all background tasks, disconnects from Rendezvous, stops gossip,
        closes all peer connections, and cleans up the puncher.
        """
        log.info(f"[{self.node_id}] 🛑 Shutdown initiated...")

        # 1. Cancel RDV connect task
        if self._rdv_connect_task and not self._rdv_connect_task.done():
            self._rdv_connect_task.cancel()

        # 2. Cancel auto-mesh discovery loop
        if self._auto_mesh_task and not self._auto_mesh_task.done():
            self._auto_mesh_task.cancel()

        # 3. Cancel all keepalive tasks
        for peer_id, task in list(self._keepalive_tasks.items()):
            if not task.done():
                task.cancel()
        self._keepalive_tasks.clear()

        # 4. Cancel all tracked background tasks
        for task in list(self._background_tasks):
            if not task.done():
                task.cancel()

        # 5. Disconnect from Rendezvous
        if self._pairing:
            try:
                await self._pairing.disconnect()
            except Exception as e:
                log.debug(f"[{self.node_id}] pairing disconnect error: {e}")

        # 6. Stop gossip protocol
        if self._gossip:
            try:
                await self._gossip.stop()
            except Exception as e:
                log.debug(f"[{self.node_id}] gossip stop error: {e}")

        # 7. Close all peer connections
        for peer_id, ws in list(self.connections.items()):
            try:
                if hasattr(ws, 'close'):
                    await ws.close()
            except Exception:
                pass
        self.connections.clear()
        self._connecting_peers.clear()

        # 8. Close relay bridges
        for pair_id, bridge in list(self._relay_bridges.items()):
            try:
                bridge._closed = True
                bridge._recv_queue.put_nowait(None)
            except Exception:
                pass
        self._relay_bridges.clear()

        # 9. Wait briefly for tasks to finish
        if self._background_tasks:
            await asyncio.gather(*self._background_tasks, return_exceptions=True)

        log.info(f"[{self.node_id}] 🛑 Shutdown complete")

    def sign_message(self, msg: "KiteMessage") -> "KiteMessage":
        """Sign a KiteMessage with this node's Ed25519 private key.

        Public API for sub-modules (gossip, pairing) that need to send signed messages
        without directly accessing _signing_key.
        """
        return msg.sign(self._signing_key)

    # ── Public API ──

    @property
    def pairing_client(self):
        """Access the KitePairingClient instance (None if no rendezvous_url configured)."""
        return self._pairing

    def on_task(self, handler: Callable):
        """Register async handler(task_id, message, from_node) -> str"""
        self._task_handler = handler
        return handler

    async def send_task(self, target_node: str, message: str, timeout: float = 300) -> str:
        """Send a task to a peer node. Returns result string.

        Args:
            target_node: peer's node_id (must be connected)
            message: task description / prompt
            timeout: max seconds to wait for result (default 300)

        Raises:
            ConnectionError: peer not connected
            TimeoutError: no result within timeout
        """
        if target_node not in self.connections:
            connected_peers = list(self.connections.keys())
            raise ConnectionError(
                f"Node {target_node!r} not connected. "
                f"Connected peers: {connected_peers if connected_peers else '(none)'}"
            )
        task_id = str(uuid.uuid4())
        task_short = task_id[:8]
        future: asyncio.Future = asyncio.get_running_loop().create_future()
        self._task_callbacks[task_id] = future
        msg = KiteMessage(
            type=KITE_TASK,
            id=task_id,
            from_node=self.node_id,
            to_node=target_node,
            payload={"message": message},
        ).sign(self._signing_key)
        try:
            await self.connections[target_node].send(msg.to_json())
            log.info(f"[{self.node_id}] 📤 KITP task [{task_short}] sent to {target_node} "
                     f"({len(message)} chars, timeout={timeout}s), waiting for result...")
        except Exception as e:
            self._task_callbacks.pop(task_id, None)
            log.error(f"[{self.node_id}] 🔌 KITP task [{task_short}] send FAILED to {target_node}: {e}")
            raise ConnectionError(f"Failed to send task to {target_node}: {e}")
        t0 = time.time()
        try:
            result = await asyncio.wait_for(asyncio.shield(future), timeout=timeout)
            elapsed = time.time() - t0
            log.info(f"[{self.node_id}] 📥 KITP task [{task_short}] result received from "
                     f"{target_node} in {elapsed:.1f}s ({len(result)} chars)")
            return result
        except asyncio.TimeoutError:
            elapsed = time.time() - t0
            self._task_callbacks.pop(task_id, None)
            log.error(f"[{self.node_id}] ⏱️ KITP task [{task_short}] TIMEOUT after {elapsed:.1f}s "
                      f"— no KITE_RESULT received from {target_node}. "
                      f"Remote node may be stuck executing the task.")
            raise TimeoutError(f"Task {task_id} timed out after {timeout}s waiting for {target_node}")
        except asyncio.CancelledError:
            self._task_callbacks.pop(task_id, None)
            raise

    def enable_gossip(self, seed_peers: Optional[List[str]] = None,
                      gossip_port: int = 17586,
                      auto_mesh: bool = True):
        """Enable UDP gossip protocol for group membership management.

        The gossip protocol provides decentralized node discovery, liveness
        tracking, and member eviction without needing a leader or central server.
        Once the member table is seeded (via RDV or seed_peers), the group
        operates autonomously even if the Rendezvous server goes offline.

        Args:
            seed_peers: Optional list of seed peer addresses (host:port) for
                        initial gossip bootstrap. These should be gossip UDP
                        addresses (default port 17586).
            gossip_port: UDP port for gossip protocol (default 17586).
            auto_mesh: If True, enable RDV discovery loop that seeds the gossip
                       protocol with newly discovered peers. Default True.
        """
        if not self._group or self._group == "*":
            log.warning(f"[{self.node_id}] gossip requires a named group (not empty/'*') — skipped")
            return

        # Validate gossip port does not overlap with KITP port
        if gossip_port == self.port:
            log.error(f"[{self.node_id}] gossip port {gossip_port} conflicts with KITP port — skipped")
            return

        self._gossip_enabled = True
        self._gossip_port = gossip_port
        self._auto_mesh_enabled = auto_mesh
        self._gossip_seed_peers = seed_peers or []
        log.info(f"[{self.node_id}] 📡 Gossip enabled: group='{self._group}', "
                 f"port={gossip_port}, seed_peers={self._gossip_seed_peers}, "
                 f"auto_mesh={self._auto_mesh_enabled}")

    async def start(self):
        """Start KITP server, connect to static peers, and optionally join rendezvous."""
        async with ws_serve(self._handle_incoming, self.host, self.port) as server:
            log.info(f"[{self.node_id}] 🟢 KITP server started — {_mask_ip(self.host)}:{self.port} 🏄 Ready to surf!")
            tasks = [self._connect_peers()]
            if self._rendezvous_url:
                tasks.append(self._start_pairing())
            elif self._gossip_enabled:
                # No Rendezvous configured, but gossip is enabled —
                # start gossip protocol standalone (purely UDP-based)
                tasks.append(self._setup_gossip())
            # Periodic connection status logger
            tasks.append(self._connection_status_loop())
            tasks.append(server.wait_closed())
            await asyncio.gather(*tasks)

    async def _connection_status_loop(self):
        """Periodically log a rich connection status summary with quality indicators."""
        await asyncio.sleep(30)  # initial delay
        while True:
            if self.connections:
                import random
                status_emoji = random.choice(["🏄", "🪁", "🌊", "💨", "⚡", "🎯", "🐬", "🦈"])
                now = time.time()
                peer_info = []
                for pid in self.connections:
                    last = self._peer_last_recv.get(pid, 0)
                    idle = int(now - last) if last > 0 else -1
                    conn = self.connections[pid]
                    transport = "relay" if isinstance(conn, _RendezvousRelayBridge) else "tcp"
                    # RTT quality indicator
                    rtt = self._peer_rtt.get(pid)
                    rtt_str = f"{self._rtt_quality(rtt)}{rtt*1000:.0f}ms" if rtt else "?"
                    # Adaptive interval
                    iv = self._peer_ka_interval.get(pid, self._P2P_KEEPALIVE_INTERVAL)
                    # Miss count
                    misses = self._peer_miss_count.get(pid, 0)
                    miss_str = f",miss={misses}" if misses > 0 else ""
                    peer_info.append(
                        f"{pid}({transport},rtt={rtt_str},idle={idle}s,iv={iv:.0f}s{miss_str})"
                    )
                summary = ", ".join(peer_info)
                log.info(f"[{self.node_id}] {status_emoji} Surf status: "
                         f"{len(self.connections)} active — [{summary}]")
                # Optimization: log current Rendezvous info for observability
                if self._pairing:
                    rdv_url = self._pairing.rendezvous_url or "(none)"
                    rdv_connected = getattr(self._pairing, '_rendezvous_connected', False)
                    if self._rdv_detached:
                        gossip_count = self._gossip.member_count() if self._gossip else 0
                        log.info(f"[{self.node_id}] 📡 RDV: detached (autonomous mode) | "
                                 f"gossip: {gossip_count} member(s)")
                    else:
                        log.info(f"[{self.node_id}] 📡 RDV: {_mask_ip(rdv_url)} "
                                 f"(connected={rdv_connected})")
            await asyncio.sleep(60)

    def get_peer_quality(self, peer_id: str = "") -> Dict[str, Any]:
        """Public API: get connection quality metrics for a peer (or all peers).

        Returns per-peer dict with:
          - transport: "tcp" | "relay"
          - rtt_ms: smoothed RTT in milliseconds (None if not yet measured)
          - quality: emoji indicator (⚡🟢🟡🔴)
          - idle_s: seconds since last received message
          - interval_s: current adaptive keepalive interval
          - misses: consecutive ping misses
          - connected: True if in connections dict

        Usage examples:
          node.get_peer_quality("node-abc")  → single peer
          node.get_peer_quality()            → all peers
        """
        def _info(pid: str) -> Dict[str, Any]:
            conn = self.connections.get(pid)
            rtt = self._peer_rtt.get(pid)
            last = self._peer_last_recv.get(pid, 0)
            return {
                "peer_id": pid,
                "connected": conn is not None,
                "transport": "relay" if isinstance(conn, _RendezvousRelayBridge) else "tcp" if conn else None,
                "rtt_ms": round(rtt * 1000, 1) if rtt else None,
                "quality": self._rtt_quality(rtt) if rtt else "❓",
                "idle_s": round(time.time() - last, 1) if last > 0 else None,
                "interval_s": self._peer_ka_interval.get(pid, self._P2P_KEEPALIVE_INTERVAL),
                "misses": self._peer_miss_count.get(pid, 0),
            }
        if peer_id:
            return _info(peer_id)
        return {pid: _info(pid) for pid in self.connections}

    # ── Pairing Integration ──

    async def _start_pairing(self):
        """Startup flow (strict serial):

        ① STUN — discover our public IP (before connecting to anything)
        ② Connect & register RDV — registration message carries public_addr
        ③ RDV pushes same-group peers → seed gossip
        ④ Start gossip — UDP heartbeat-based autonomous membership
        ⑤ Once gossip is healthy → disconnect from RDV (no longer needed)

        This ensures every other node learns our *public* address from the
        very first RDV registration, and gossip becomes the sole discovery
        mechanism after bootstrap.
        """
        from kite_pairing import KitePairingClient
        from kite_punch import KitePuncher

        # Build listen_addr: prefer LAN IP over 127.0.0.1 so peers on the same LAN can reach us
        if self.host != "0.0.0.0":
            listen_addr = f"{self.host}:{self.port}"
        else:
            lan_ip = self._detect_lan_ip()
            listen_addr = f"{lan_ip}:{self.port}"
        self._listen_addr = listen_addr  # stored for gossip addr_hint propagation

        # ── Step ①: STUN — discover public address BEFORE RDV registration ──
        # This is done synchronously so that when we register with RDV in step ②,
        # the registration message already contains our public_addr.  Other nodes
        # will see our public address immediately, without needing a second
        # update_public_addr round-trip.
        stun_pub_str = ""
        stun_pub_tuple = None
        try:
            from kite_stun import discover_public_addr
            log.info(f"[{self.node_id}] 🌐 Step ① STUN: discovering public address...")
            stun_pub_tuple = await discover_public_addr(local_port=self.port + 1)
            if stun_pub_tuple:
                pub_ip, pub_port = stun_pub_tuple
                stun_pub_str = f"{pub_ip}:{pub_port}"
                log.info(f"[{self.node_id}] 🌐 Step ① STUN OK: public_addr={_mask_ip(stun_pub_str)}")
            else:
                log.warning(f"[{self.node_id}] 🌐 Step ① STUN failed — public_addr unavailable, "
                            f"continuing with LAN address only")
        except Exception as e:
            log.warning(f"[{self.node_id}] 🌐 Step ① STUN error: {e} — continuing without public_addr")

        # ── Step ②: Create pairing client (with public_addr already set) ──
        log.info(f"[{self.node_id}] 📡 Step ② Creating RDV client and registering...")
        self._pairing = KitePairingClient(
            node_id=self.node_id,
            nickname=self._nickname,
            emoji=self._emoji,
            tags=self._tags,
            group=self._group,
            hidden=self._hidden,
            rendezvous_url=self._rendezvous_url,
            listen_addr=listen_addr,
            private_skills=self._private_skills,
            ssl_verify=self._ssl_verify,
            allow_insecure=self._allow_insecure,
            # ── KiteChain v2 — chain profile for Rendezvous registration ──
            chain_enabled=self._chain_enabled,
            wallet_address=self._wallet_address,
            scp_version=self._scp_version,
            chain_capabilities=self._chain_capabilities,
        )
        # ★ Set public_addr BEFORE connect() so the first register message carries it
        if stun_pub_str:
            self._pairing.public_addr = stun_pub_str
        # Advertise gossip port via RDV so peers can resolve correct UDP target
        if self._gossip_enabled:
            self._pairing.gossip_port = self._gossip_port

        # KitePuncher is lazily initialized after the WebSocket connection is established
        # Attach it to the pairing client to receive punch_start/relay_data
        self._puncher: Optional[KitePuncher] = None

        # Pre-warm puncher with the STUN result (avoids redundant STUN on first punch)
        if stun_pub_tuple:
            async def _prewarm_puncher():
                """Pre-warm the KitePuncher with the STUN result from Step ①."""
                try:
                    for _ in range(30):
                        if self._pairing and self._pairing._ws:
                            break
                        await asyncio.sleep(0.5)
                    else:
                        return
                    if not self._puncher and self._pairing and self._pairing._ws:
                        from kite_punch import KitePuncher as _KP, _UdpPunchProtocol
                        self._puncher = _KP(
                            rendezvous_ws=self._pairing._ws,
                            node_id=self.node_id,
                            kitp_port=self.port,
                        )
                        self._puncher._public_addr = stun_pub_tuple
                        loop = asyncio.get_running_loop()
                        try:
                            self._puncher._udp_transport, self._puncher._udp_proto = \
                                await loop.create_datagram_endpoint(
                                    _UdpPunchProtocol,
                                    local_addr=("0.0.0.0", self.port + 1),
                                )
                        except OSError:
                            self._puncher._udp_transport, self._puncher._udp_proto = \
                                await loop.create_datagram_endpoint(
                                    _UdpPunchProtocol,
                                    local_addr=("0.0.0.0", 0),
                                )
                        if self._pairing:
                            self._pairing._puncher_ref = self._puncher
                        log.info(f"[{self.node_id}] 🥊 Puncher pre-warmed (STUN addr={_mask_ip(stun_pub_str)})")
                except Exception as e:
                    log.debug(f"[{self.node_id}] puncher pre-warm error: {e}")
            self._track_task(_prewarm_puncher(), name="prewarm_puncher")

        # Register KITP relay handler to route relay_data(kind=kitp) messages
        # to the correct _RendezvousRelayBridge instance
        def _on_kitp_relay(pair_id: str, data: str):
            bridge = self._relay_bridges.get(pair_id)
            if bridge:
                bridge.push(data)
            else:
                # Bridge not yet created — buffer the message to avoid losing it.
                # This happens when the peer sends HELLO before our side finishes
                # hole-punch/TCP attempts and creates the relay bridge.
                log.info(f"[{self.node_id}] relay_data(kitp) buffered for pair_id={pair_id} (bridge not ready)")
                self._relay_early_msgs.setdefault(pair_id, []).append(data)

        self._pairing._kitp_relay_handler = _on_kitp_relay

        # When Rendezvous connection drops, immediately close all relay bridges
        # so _handle_messages loops exit promptly, rather than waiting for
        # keepalive to detect the silent failure.
        def _on_rendezvous_disconnect():
            if self._relay_bridges:
                log.warning(f"[{self.node_id}] 🔌 Rendezvous disconnected — "
                            f"closing {len(self._relay_bridges)} relay bridge(s)")
                for pair_id, bridge in list(self._relay_bridges.items()):
                    try:
                        bridge._closed = True
                        bridge._recv_queue.put_nowait(None)  # wake recv() → StopAsyncIteration
                    except Exception:
                        pass

        self._pairing.on_disconnect(_on_rendezvous_disconnect)

        # ── Step ③④: Gossip Protocol Integration ──
        # Start the UDP gossip protocol for group membership management.
        # Gossip runs independently of Rendezvous — once seeded, the group
        # operates autonomously even if RDV goes offline.
        if self._gossip_enabled:
            # Start gossip protocol
            self._track_task(self._setup_gossip(), name="setup_gossip")
            log.info(f"[{self.node_id}] 📡 Step ③ Gossip protocol starting (UDP port {self._gossip_port})")

            # Sync STUN result to gossip protocol
            if stun_pub_str:
                async def _sync_stun_to_gossip():
                    """Wait for gossip to start, then inject STUN address."""
                    for _ in range(20):
                        if self._gossip and self._gossip._running:
                            break
                        await asyncio.sleep(0.5)
                    if self._gossip:
                        self._gossip.update_self_public_addr(stun_pub_str)
                        log.info(f"[{self.node_id}] 🌐 STUN public_addr → gossip: {_mask_ip(stun_pub_str)}")
                self._track_task(_sync_stun_to_gossip(), name="sync_stun_to_gossip")

            # Start RDV discovery loop to seed gossip with peer addresses
            if self._auto_mesh_enabled:
                self._auto_mesh_task = self._track_task(self._discovery_loop(), name="discovery_loop")
                log.info(f"[{self.node_id}] 🔗 Step ④ RDV discovery loop started — "
                         f"bootstrap every {self._RDV_BOOTSTRAP_INTERVAL}s, "
                         f"steady every {self._RDV_STEADY_INTERVAL}s (seeds gossip)")

            # ── Instant discovery on node_joined push from Rendezvous ──
            # When a new same-group node registers, the RDV pushes a notification.
            # We immediately run a discovery cycle to seed gossip with the new peer.
            _node_joined_debounce: float = 0.0

            async def _on_node_joined(joined_id: str, joined_group: str):
                nonlocal _node_joined_debounce
                now = time.time()
                # Debounce: skip if another node_joined was handled < 3s ago
                if now - _node_joined_debounce < 3.0:
                    return
                _node_joined_debounce = now
                log.info(f"[{self.node_id}] ⚡ node_joined push: {joined_id} — "
                         f"triggering instant RDV discovery → gossip seed")
                try:
                    await self._discovery_once()
                except Exception as e:
                    log.debug(f"[{self.node_id}] instant discovery error: {e}")

            self._pairing._node_joined_handler = _on_node_joined

            # ── Step ⑤: RDV detach monitor ──
            # Once gossip is healthy (has members), we no longer need RDV.
            # Disconnect to reduce central dependency.  If gossip becomes
            # empty later, reconnect to RDV for re-seeding.
            self._track_task(self._rdv_detach_monitor(), name="rdv_detach_monitor")

        await self._pairing.connect()

    async def _rdv_detach_monitor(self):
        """Background task: disconnect from RDV once gossip is self-sufficient.

        ⑤ After gossip has been healthy for _RDV_DETACH_GRACE seconds,
        disconnect from RDV.  If gossip member table empties, reconnect
        to RDV for re-seeding (temporary).

        This implements "后续不再依赖 RDV" — the node becomes fully
        autonomous once gossip membership is stable.
        """
        gossip_healthy_since: float = 0.0

        # Wait for initial RDV registration + gossip startup
        await asyncio.sleep(5)

        while True:
            try:
                # 改动一: only consider gossip healthy when UDP is bidirectionally
                # confirmed (not just RDV-seeded member_count > 0)
                gossip_has_members = (
                    self._gossip and self._gossip.udp_alive_count() > 0
                )

                if gossip_has_members and not self._rdv_detached:
                    # Track how long gossip has been healthy
                    if gossip_healthy_since == 0:
                        gossip_healthy_since = time.time()

                    # Wait for grace period before detaching
                    healthy_duration = time.time() - gossip_healthy_since
                    if healthy_duration >= self._RDV_DETACH_GRACE:
                        # ── Detach from RDV ──
                        log.info(f"[{self.node_id}] 🔌 Step ⑤ Gossip healthy for "
                                 f"{int(healthy_duration)}s — detaching from RDV "
                                 f"(gossip members: {self._gossip.member_count()})")
                        self._rdv_detached = True
                        if self._pairing:
                            try:
                                await self._pairing.disconnect()
                                log.info(f"[{self.node_id}] ✅ RDV disconnected — "
                                         f"now running fully autonomous via gossip")
                            except Exception as e:
                                log.warning(f"[{self.node_id}] RDV disconnect error: {e}")

                elif not gossip_has_members and self._rdv_detached:
                    # ── Gossip emptied — reconnect to RDV for re-seeding ──
                    gossip_healthy_since = 0
                    log.warning(f"[{self.node_id}] ⚠️ Gossip member table empty — "
                                f"reconnecting to RDV for re-seeding")
                    self._rdv_detached = False
                    if self._pairing:
                        try:
                            # ── Fix #1: Cancel any previous orphaned connect task ──
                            if self._rdv_connect_task and not self._rdv_connect_task.done():
                                self._rdv_connect_task.cancel()
                                log.debug(f"[{self.node_id}] Cancelled previous RDV connect task")

                            # ── Fix #2: Re-STUN to refresh NAT mapping ──
                            # NAT mappings may have expired during the detach period.
                            try:
                                from kite_stun import discover_public_addr
                                log.info(f"[{self.node_id}] 🌐 Re-STUN: refreshing public address before RDV reconnect...")
                                new_pub = await discover_public_addr(local_port=self.port + 1)
                                if new_pub:
                                    pub_ip, pub_port = new_pub
                                    new_pub_str = f"{pub_ip}:{pub_port}"
                                    self._pairing.public_addr = new_pub_str
                                    log.info(f"[{self.node_id}] 🌐 Re-STUN OK: {_mask_ip(new_pub_str)}")
                                    # Sync to gossip
                                    if self._gossip:
                                        self._gossip.update_self_public_addr(new_pub_str)
                                    # ── Fix #6: Update puncher's STUN result + ws reference ──
                                    if self._puncher:
                                        self._puncher._public_addr = new_pub
                                else:
                                    log.warning(f"[{self.node_id}] 🌐 Re-STUN failed — "
                                                f"using stale public_addr")
                            except Exception as stun_e:
                                log.warning(f"[{self.node_id}] 🌐 Re-STUN error: {stun_e}")

                            # Re-start the pairing connect loop
                            self._pairing._running = True
                            self._rdv_connect_task = self._track_task(
                                self._rdv_reconnect_wrapper(),
                                name="rdv_reconnect"
                            )
                            log.info(f"[{self.node_id}] 📡 RDV reconnect initiated "
                                     f"(gossip re-seeding mode)")
                        except Exception as e:
                            log.warning(f"[{self.node_id}] RDV reconnect error: {e}")

                elif not gossip_has_members:
                    gossip_healthy_since = 0

            except asyncio.CancelledError:
                break
            except Exception as e:
                log.debug(f"[{self.node_id}] rdv_detach_monitor error: {e}")

            await asyncio.sleep(15)  # check every 15 seconds

    async def _rdv_reconnect_wrapper(self):
        """Wrapper around self._pairing.connect() for RDV reconnection.

        After the connection is re-established, this refreshes stale
        references that were captured from the previous WebSocket:

          - Fix #6: KitePuncher._ws → update to the new WebSocket instance
          - Relay bridge references are naturally re-created on next pairing

        This also ensures the task has proper exception handling so it
        doesn't become an unhandled task exception.
        """
        try:
            await self._pairing.connect()
        except asyncio.CancelledError:
            log.debug(f"[{self.node_id}] RDV reconnect task cancelled")
            return
        except Exception as e:
            log.warning(f"[{self.node_id}] RDV reconnect wrapper error: {e}")
            return
        finally:
            # ── Fix #6: Update Puncher's WebSocket reference ──
            # After reconnection, self._pairing._ws is a new WebSocket.
            # The puncher was initialized with the OLD ws, so update it.
            if self._puncher and self._pairing and self._pairing._ws:
                old_ws = self._puncher._ws
                self._puncher._ws = self._pairing._ws
                if old_ws is not self._pairing._ws:
                    log.info(f"[{self.node_id}] 🥊 Puncher WebSocket reference refreshed after RDV reconnect")

    # ── Discovery Loop: feed Rendezvous discoveries to gossip protocol ──
    #
    # Design principle: RDV is used ONLY for initial bootstrapping.
    # Once gossip has a non-empty member table, it self-maintains via UDP
    # heartbeats. The discovery loop adapts accordingly:
    #   - Phase 1 (bootstrap): query RDV every 30s until gossip has members
    #   - Phase 2 (steady):    query RDV every 5min as a low-frequency reseed
    #     (catches nodes that joined while all existing peers were unreachable)
    #   - If gossip member count drops to 0: fall back to Phase 1
    # (constants now live in __init__ as instance variables)

    async def _discovery_loop(self):
        """Background loop: bootstrap gossip via Rendezvous, then step back.

        After the first successful seed, RDV polling interval increases from
        30s to 300s.  Gossip handles all liveness detection independently.
        If gossip's member table empties, we re-enter aggressive bootstrap mode.

        When RDV is detached (Step ⑤), this loop pauses — gossip is fully
        autonomous.  If gossip empties and RDV is reconnected, the loop resumes.
        """
        await asyncio.sleep(2)  # let RDV registration finish

        log.info(f"[{self.node_id}] 🔍 Discovery loop started "
                 f"(group='{self._group}', bootstrap_interval="
                 f"{self._RDV_BOOTSTRAP_INTERVAL}s, steady_interval="
                 f"{self._RDV_STEADY_INTERVAL}s)")

        while self._gossip_enabled:
            # Skip RDV queries when detached — gossip is autonomous
            if self._rdv_detached:
                try:
                    await asyncio.sleep(30)
                except asyncio.CancelledError:
                    break
                continue

            # Only query RDV if connected
            if not self._pairing or not self._pairing._running:
                try:
                    await asyncio.sleep(5)
                except asyncio.CancelledError:
                    break
                continue

            try:
                await self._discovery_once()
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.debug(f"[{self.node_id}] discovery cycle error: {e}")

            # Adaptive interval: aggressive while gossip is empty, lazy once healthy
            gossip_has_members = (
                self._gossip and self._gossip.member_count() > 0
            )
            if gossip_has_members:
                if not self._RDV_SEEDED:
                    self._RDV_SEEDED = True
                    log.info(f"[{self.node_id}] 🔍 Gossip seeded — switching RDV "
                             f"discovery to steady mode ({self._RDV_STEADY_INTERVAL}s)")
                    # Reduce RDV keepalive frequency to save resources
                    if self._pairing and not self._rdv_detached:
                        self._pairing.adjust_keepalive(self._RDV_STEADY_KEEPALIVE)
                interval = self._RDV_STEADY_INTERVAL
            else:
                if self._RDV_SEEDED:
                    log.info(f"[{self.node_id}] 🔍 Gossip member table empty — "
                             f"switching RDV discovery back to bootstrap mode "
                             f"({self._RDV_BOOTSTRAP_INTERVAL}s)")
                    self._RDV_SEEDED = False
                    # Restore RDV keepalive to normal frequency
                    if self._pairing and not self._rdv_detached:
                        self._pairing.restore_keepalive()
                interval = self._RDV_BOOTSTRAP_INTERVAL

            try:
                await asyncio.sleep(interval)
            except asyncio.CancelledError:
                break

        log.info(f"[{self.node_id}] 🔍 Discovery loop stopped")

    async def _discovery_once(self):
        """Execute one discovery cycle: query Rendezvous → seed gossip protocol.

        This is a lightweight supplement to gossip — it only runs to bootstrap
        or reseed the gossip member table. Gossip itself handles all ongoing
        liveness detection and member eviction via UDP.

        Steps:
          1. Query Rendezvous for online same-group peers
          2. Feed discovered nodes (with addresses) to gossip protocol
          3. Gossip protocol maintains membership from there via UDP
        """
        if not self._pairing or not self._pairing._rendezvous_connected:
            return  # Rendezvous not ready yet — skip this cycle
        if self._rdv_detached:
            return  # RDV intentionally disconnected — gossip is autonomous

        # 1. Discover online peers (central RDV)
        try:
            all_nodes = await self._pairing.list_nodes()
        except Exception as e:
            log.debug(f"[{self.node_id}] discovery: list_nodes failed: {e}")
            return

        # 2. Filter to same-group peers
        same_group_nodes = []
        for node_info in all_nodes:
            nid = node_info.get("node_id", "")
            if not nid or nid == self.node_id:
                continue
            if node_info.get("group", "") != self._group:
                continue
            same_group_nodes.append(node_info)

        # 3. Seed gossip protocol with discovered peers
        if self._gossip and same_group_nodes:
            self._gossip.seed_from_rdv(same_group_nodes)

        if same_group_nodes:
            log.debug(f"[{self.node_id}] 🔍 Discovered {len(same_group_nodes)} "
                      f"same-group peer(s) via RDV → seeded gossip")

    # ── Gossip Protocol Methods ──

    async def _setup_gossip(self):
        """Initialize and start the UDP gossip protocol.

        Gossip runs independently on UDP port 17586 and manages group membership
        via periodic heartbeats and member table exchange. Once seeded with peer
        addresses (from RDV or config), it operates autonomously.
        """
        from kite_gossip import KiteGossip

        def _on_member_join(node_id: str, addr: str):
            """Callback: new member discovered via gossip."""
            log.info(f"[{self.node_id}] 📡 Gossip: member joined: {node_id} ({addr})")
            self._cluster_members = self._gossip.alive_member_ids() if self._gossip else []

        def _on_member_leave(node_id: str):
            """Callback: member evicted (dead timeout)."""
            log.warning(f"[{self.node_id}] 📡 Gossip: member left: {node_id}")
            self._cluster_members = self._gossip.alive_member_ids() if self._gossip else []

        def _on_members_changed(alive_members: list):
            """Callback: member table changed."""
            self._cluster_members = list(alive_members)
            log.debug(f"[{self.node_id}] 📡 Gossip: members updated: {alive_members}")

        seed_peers = getattr(self, '_gossip_seed_peers', [])

        # Persist gossip member table next to the script (for cold-start recovery)
        _persist_dir = str(Path(__file__).resolve().parent)

        self._gossip = KiteGossip(
            node_id=self.node_id,
            group=self._group,
            host=self.host,
            port=self._gossip_port,
            seed_peers=seed_peers,
            on_member_join=_on_member_join,
            on_member_leave=_on_member_leave,
            on_members_changed=_on_members_changed,
            # Profile metadata — propagated to all peers via gossip
            nickname=self._nickname,
            emoji=self._emoji,
            tags=self._tags,
            hidden=self._hidden,
            # Persistence — cold-start recovery without RDV
            persist_dir=_persist_dir,
            # TCP/KITP listen address — propagated to all peers for direct connect
            addr_hint=getattr(self, '_listen_addr', ''),
        )
        await self._gossip.start()

    def gossip_status(self) -> Dict[str, Any]:
        """Return gossip state for admin API / monitoring."""
        if not self._gossip:
            if self._gossip_enabled:
                return {
                    "enabled": True,
                    "status": "starting",
                    "message": "Gossip protocol initializing",
                    "auto_mesh": self._auto_mesh_enabled,
                }
            return {"enabled": False}
        status = self._gossip.gossip_status()
        status["enabled"] = True
        # Add cluster membership info and discovery mode
        gossip_has_members = self._gossip.member_count() > 0
        rdv_keepalive = self._pairing._KEEPALIVE_INTERVAL if (self._pairing and not self._rdv_detached) else 0
        rdv_connected = (self._pairing._rendezvous_connected if self._pairing else False) and not self._rdv_detached
        status["auto_mesh"] = {
            "enabled": self._auto_mesh_enabled,
            "cluster_members": list(self._cluster_members),
            "discovery_mode": "autonomous" if self._rdv_detached else ("steady" if self._RDV_SEEDED else "bootstrap"),
            "rdv_detached": self._rdv_detached,
            "rdv_connected": rdv_connected,
            "rdv_interval": 0 if self._rdv_detached else (self._RDV_STEADY_INTERVAL if self._RDV_SEEDED else self._RDV_BOOTSTRAP_INTERVAL),
            "rdv_keepalive": rdv_keepalive,
            "gossip_has_members": gossip_has_members,
        }
        return status

    @staticmethod
    def _group_addrs_by_phase(tcp_addrs: List[str]) -> List[tuple]:
        """Group candidate addresses into connection phases by network type.

        Returns a list of (phase_name, emoji, [addresses]) tuples, sorted:
          Phase 1: LAN        (RFC 1918 private networks)
          Phase 2: Cloud-LAN  (Cloud VPC / CGNAT)
          Phase 3: WAN        (Public internet)

        Addresses that don't match any known category are placed in the WAN phase.
        """
        lan_addrs = []
        cloud_addrs = []
        wan_addrs = []
        for a in tcp_addrs:
            tag = KiteNode._classify_addr(a)
            if "LAN" in tag and "Cloud" not in tag:
                lan_addrs.append(a)
            elif "Cloud" in tag:
                cloud_addrs.append(a)
            else:
                wan_addrs.append(a)
        phases = []
        if lan_addrs:
            phases.append(("LAN", "🏠", lan_addrs))
        if cloud_addrs:
            phases.append(("Cloud-LAN", "☁️", cloud_addrs))
        if wan_addrs:
            phases.append(("WAN", "🌐", wan_addrs))
        return phases

    async def _try_tcp_phases(self, peer_id: str, tcp_addrs: List[str]) -> bool:
        """Try TCP direct connect in phases: LAN → Cloud-LAN → WAN.

        Each phase tries all addresses of that network type before moving to the next.
        Returns True on the first successful connection.
        """
        phases = self._group_addrs_by_phase(tcp_addrs)
        total_phases = len(phases)

        for idx, (phase_name, emoji, addrs) in enumerate(phases, 1):
            log.info(f"[{self.node_id}] 🔌 Phase {idx}/{total_phases}: "
                     f"trying {emoji} {phase_name} direct connect → {peer_id} "
                     f"({len(addrs)} candidate(s): {[_mask_ip(a) for a in addrs]})")

            for addr in addrs:
                log.info(f"[{self.node_id}]   → TCP dial {emoji} {phase_name} {_mask_ip(addr)}")
                tcp_ok = await self._try_dial_once(addr, timeout=5.0, peer_id=peer_id)
                if tcp_ok:
                    summary = self._transport_summary("tcp-direct", addr)
                    log.info(f"[{self.node_id}] ✅ Connected: {peer_id} "
                             f"[{summary}] via {emoji} {phase_name}")
                    return True

            log.info(f"[{self.node_id}] ❌ Phase {idx}/{total_phases}: "
                     f"{emoji} {phase_name} direct connect failed → {peer_id}")

        return False

    async def _punch_and_connect(self, pair_id: str, peer_id: str, tcp_addrs: List[str]):
        """Connect to a peer with progressive fallback.

        Connection priority (fast & cheap first, slow & expensive last):
          1. TCP direct — phased by network type:
             a. LAN        (RFC 1918 private networks, <1ms)
             b. Cloud-LAN  (Cloud VPC / CGNAT, 1-5ms)
             c. WAN        (Public internet, 10-200ms)
          2. UDP P2P direct  (hole punch — requires RDV signaling)
          3. Relay bridge    (KITP via Rendezvous relay — always available)

        Rationale: TCP direct needs no RDV signaling or STUN, and succeeds
        instantly when peers are reachable. UDP punch has a 10s signaling
        wait, so it's tried only after TCP fails. Relay is the last resort.

        Args:
            tcp_addrs: ordered list of candidate addresses [lan_addr, cloud_addr, public_addr, ...]
        """
        try:
            # ── Phase 1: TCP direct connect (LAN → Cloud-LAN → WAN) ──
            if tcp_addrs:
                log.info(f"[{self.node_id}] 🔌 Trying TCP direct connect phases → {peer_id}")
                tcp_ok = await self._try_tcp_phases(peer_id, tcp_addrs)
                if tcp_ok:
                    return

            # ── Phase 2: UDP hole punch ──
            log.info(f"[{self.node_id}] 🥊 TCP direct failed, trying UDP hole punch → {peer_id}")

            # Lazy-init KitePuncher on first use
            if not self._puncher:
                from kite_punch import KitePuncher
                self._puncher = KitePuncher(
                    rendezvous_ws=self._pairing._ws,
                    node_id=self.node_id,
                    kitp_port=self.port,
                )
                await self._puncher.setup()
                # After STUN discovery, sync public address to gossip + pairing + RDV
                if self._puncher._public_addr:
                    pub_ip, pub_port = self._puncher._public_addr
                    pub_str = f"{pub_ip}:{pub_port}"
                    if self._gossip:
                        self._gossip.update_self_public_addr(pub_str)
                    if self._pairing:
                        await self._pairing.update_public_addr(pub_str)
                    log.info(f"[{self.node_id}] 🌐 STUN public addr → gossip + pairing + RDV: {pub_str}")

            channel = await self._puncher.punch(pair_id, peer_id,
                                                pair_secret="")
            log.info(f"[{self.node_id}] Channel to {peer_id}: mode={channel.mode}")

            if channel.mode == "direct":
                # UDP P2P established; still try TCP in background for a proper
                # KITP WebSocket (more reliable than raw UDP for long-lived sessions)
                log.info(f"[{self.node_id}] ✅ UDP P2P hole punch succeeded → {peer_id}, upgrading to TCP KITP")
                self.connections[peer_id] = channel
                if tcp_addrs:
                    self._track_task(self._dial(tcp_addrs[0], retry_delay=5.0, max_retries=3), name="dial_tcp")
                return

            # ── Phase 3: Rendezvous relay (last resort) ──
            log.info(f"[{self.node_id}] 📡 UDP hole punch also failed, "
                     f"falling back to Rendezvous relay → {peer_id}")
            await self._setup_rendezvous_relay(pair_id, peer_id)

        except Exception as e:
            log.warning(f"[{self.node_id}] punch_and_connect failed: {e}")
            if peer_id not in self.connections:
                # Last resort: try rendezvous relay (cleanup happens inside if relay also fails)
                await self._setup_rendezvous_relay(pair_id, peer_id)

    async def _dial_or_relay(self, pair_id: str, peer_id: str, tcp_addrs: List[str]):
        """Try phased TCP direct connect (LAN → Cloud-LAN → WAN); fall back to Rendezvous relay on failure."""
        log.info(f"[{self.node_id}] No STUN result — trying TCP direct connect phases → {peer_id}")

        tcp_ok = await self._try_tcp_phases(peer_id, tcp_addrs)
        if tcp_ok:
            return

        log.info(f"[{self.node_id}] 📡 All TCP direct connect phases failed ({tcp_addrs}), "
                 f"falling back to Rendezvous relay → {peer_id}")
        await self._setup_rendezvous_relay(pair_id, peer_id)

    async def _setup_rendezvous_relay(self, pair_id: str, peer_id: str):
        """Set up a KITP message relay bridge via Rendezvous WebSocket.

        Creates a _RendezvousRelayBridge that sends/receives KITP JSON messages
        through the Rendezvous server's relay mechanism, without needing UDP or
        TCP direct connection. Always available as long as both sides are
        connected to the Rendezvous server.

        Note: The bridge is immediately registered in self._relay_bridges
        (for routing incoming relay messages), but self.connections[peer_id]
        is not set until the KITP handshake succeeds.
        Cleans up all state on failure.
        """
        if peer_id in self.connections:
            log.debug(f"[{self.node_id}] Already connected to {peer_id}, skip relay setup")
            return

        summary = self._transport_summary("rendezvous-relay")
        rdv_url = self._pairing.rendezvous_url if self._pairing else "?"
        log.info(f"[{self.node_id}] 📡 Setting up Rendezvous relay → {peer_id} "
                 f"[{summary}] via {rdv_url}")

        bridge = _RendezvousRelayBridge(
            pairing_client=self._pairing,
            pair_id=pair_id,
            peer_node_id=peer_id,
            node_id=self.node_id,
        )
        # Register bridge for message routing (but NOT in self.connections yet)
        self._relay_bridges[pair_id] = bridge

        # Replay any messages that arrived before the bridge was created
        # (e.g. peer sent HELLO while we were still attempting hole-punch/TCP)
        early = self._relay_early_msgs.pop(pair_id, [])
        if early:
            log.info(f"[{self.node_id}] 📬 Replaying {len(early)} buffered relay message(s) for pair={pair_id}")
            for data in early:
                bridge.push(data)

        # Perform KITP handshake: smaller node_id initiates
        if self.node_id < peer_id:
            self._track_task(self._relay_handshake(bridge, peer_id, pair_id), name="relay_handshake")
        else:
            self._track_task(self._relay_accept(bridge, peer_id, pair_id), name="relay_accept")

    async def _try_dial_once(self, addr: str, timeout: float = 5.0, peer_id: str = "") -> bool:
        """Attempt a single TCP WebSocket dial. Returns True on successful KITP handshake.
        Connection uses AES-256-GCM encryption after handshake.

        Note: `timeout` applies only to the TCP connection + KITP handshake phase.
        After a successful handshake, _handle_messages runs indefinitely (no timeout).
        """
        uri = f"ws://{addr}"
        net_tag = self._classify_addr(addr)
        log.info(f"[{self.node_id}] 🔌 TCP connecting {net_tag} {_mask_ip(addr)} (timeout={timeout}s)...")
        t0 = time.time()
        ws = None
        try:
            # Phase 1: TCP connect + KITP handshake — bounded by timeout
            try:
                async with asyncio.timeout(timeout):
                    ws = await ws_connect(uri).__aenter__()
                    elapsed_ms = (time.time() - t0) * 1000
                    log.info(f"[{self.node_id}] 🔌 TCP socket established {net_tag} {_mask_ip(addr)} "
                             f"({elapsed_ms:.0f}ms), starting KITP handshake...")
                    handshake_ok = await self._do_hello(ws, addr, peer_id_hint=peer_id)
            except asyncio.TimeoutError:
                elapsed_ms = (time.time() - t0) * 1000
                log.info(f"[{self.node_id}] ❌ TCP connect timeout {net_tag} {_mask_ip(addr)} "
                         f"({elapsed_ms:.0f}ms, limit={timeout}s)")
                if ws:
                    await ws.close()
                return False

            if not handshake_ok:
                elapsed_ms = (time.time() - t0) * 1000
                log.warning(f"[{self.node_id}] ❌ TCP connected but KITP handshake rejected by "
                            f"{net_tag} {_mask_ip(addr)} ({elapsed_ms:.0f}ms)")
                await ws.close()
                return False

            # Phase 2: Handshake succeeded — run message loop WITHOUT timeout
            actual_peer = peer_id or addr
            ews = self.connections.get(actual_peer)
            if ews is None:
                # _do_hello returned True but tie-breaking dropped this outbound
                # connection — the inbound connection is being used instead.
                log.info(f"[{self.node_id}] ⏩ Outbound handshake OK but connection "
                         f"dropped by tie-break — {actual_peer} handled by inbound path")
                await ws.close()
                return True
            total_ms = (time.time() - t0) * 1000
            log.info(f"[{self.node_id}] ✅ TCP+KITP handshake OK {net_tag} {addr} → "
                     f"{actual_peer} ({total_ms:.0f}ms)")
            try:
                await self._handle_messages(ews, actual_peer)
            finally:
                # Message loop exited — clean up.
                # Only remove if WE are still the active connection handler.
                if self.connections.get(actual_peer) is ews:
                    del self.connections[actual_peer]
                    self._connecting_peers.discard(actual_peer)
                    log.info(f"[{self.node_id}] 🔴 {actual_peer} disconnected "
                             f"[{len(self.connections)} active]")
                    if _kn:
                        _kn.get().notify_connect(actual_peer, connected=False,
                                                 info=f"remaining connections: {len(self.connections)}")
            return True
        except ConnectionRefusedError:
            elapsed_ms = (time.time() - t0) * 1000
            log.info(f"[{self.node_id}] ❌ TCP connect refused {net_tag} {addr} "
                     f"({elapsed_ms:.0f}ms) — port not listening or firewall reject")
        except OSError as e:
            elapsed_ms = (time.time() - t0) * 1000
            # OSError covers: network unreachable, host unreachable, no route to host, etc.
            log.info(f"[{self.node_id}] ❌ TCP connect failed {net_tag} {_mask_ip(addr)} "
                     f"({elapsed_ms:.0f}ms) — {type(e).__name__}: {e}")
        except Exception as e:
            elapsed_ms = (time.time() - t0) * 1000
            log.info(f"[{self.node_id}] ❌ TCP dial failed {net_tag} {addr} "
                     f"({elapsed_ms:.0f}ms) — {type(e).__name__}: {e}")
        finally:
            # Ensure WebSocket is closed if still open and not handed off to _handle_messages.
            # NOTE: websockets 12+ asyncio ClientConnection has no `.closed` attribute;
            # `.close()` is idempotent, so we just call it and swallow errors.
            if ws is not None:
                try:
                    await ws.close()
                except Exception:
                    pass
        return False

    def _cleanup_failed_pair(self, peer_id: str, pair_id: str = ""):
        """Clean up all state left by a failed pairing/connection attempt.

        Called when a relay handshake times out, is rejected, or errors.
        Ensures no zombie entries remain in connections, relay bridges, secrets, etc.
        """
        cleaned = []
        # Remove from in-progress connecting set
        if peer_id in self._connecting_peers:
            self._connecting_peers.discard(peer_id)
            cleaned.append("connecting_peers")
        if peer_id in self.connections:
            del self.connections[peer_id]
            cleaned.append("connections")
        if pair_id and pair_id in self._relay_bridges:
            del self._relay_bridges[pair_id]
            cleaned.append("relay_bridges")
        if pair_id and pair_id in self._relay_early_msgs:
            del self._relay_early_msgs[pair_id]
            cleaned.append("relay_early_msgs")
        if peer_id in self._peer_verify_keys:
            del self._peer_verify_keys[peer_id]
            cleaned.append("peer_verify_keys")
        # Cancel keepalive task if running
        ka = self._keepalive_tasks.pop(peer_id, None)
        if ka:
            ka.cancel()
            cleaned.append("keepalive_task")
        self._peer_last_recv.pop(peer_id, None)
        self._peer_rtt.pop(peer_id, None)
        self._peer_ping_sent.pop(peer_id, None)
        self._peer_miss_count.pop(peer_id, None)
        self._peer_ping_seq.pop(peer_id, None)
        self._peer_ka_interval.pop(peer_id, None)
        # Resolve (reject) any pending connect future so callers don't hang forever
        fut = self._connect_futures.pop(peer_id, None)
        if fut and not fut.done():
            fut.set_exception(ConnectionError(
                f"All connection attempts to {peer_id} failed (pair_id={pair_id})"
            ))
            cleaned.append("connect_future")
        if cleaned:
            log.info(f"[{self.node_id}] 🧹 Cleaned up failed pair state for {peer_id} "
                     f"(pair={pair_id[:12] if pair_id else '?'}): {', '.join(cleaned)}")

    async def _relay_handshake(self, bridge: "_RelayBridge", peer_id: str, pair_id: str = ""):
        """Initiator: send HELLO via relay bridge, wait for WELCOME, then dispatch.

        Retries HELLO up to 3 times, because the peer's relay bridge may not be ready
        yet (the peer may still be attempting TCP/UDP phases).

        ECDH: Each HELLO carries an ephemeral X25519 public key. Upon receiving
        a WELCOME containing the peer's public key, a shared ECDH secret is derived
        for forward-secret channel encryption over the relay.
        """
        timeout = self._RELAY_HANDSHAKE_TIMEOUT
        # ── Ed25519 public-key auth: sign with our private key ──
        max_hello_attempts = 3
        hello_interval = timeout / (max_hello_attempts + 1)  # spread attempts across timeout window

        # ── Generate ephemeral ECDH keypair (reused across retries) ──
        ecdh_priv = b""
        ecdh_pub_hex = ""
        try:
            from kite_crypto import generate_ecdh_keypair
            ecdh_priv, ecdh_pub = generate_ecdh_keypair()
            if ecdh_pub:
                ecdh_pub_hex = ecdh_pub.hex()
        except ImportError:
            pass

        try:
            deadline = asyncio.get_running_loop().time() + timeout
            attempt = 0

            while asyncio.get_running_loop().time() < deadline:
                attempt += 1
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    break

                # Send (or re-send) HELLO with ECDH public key + Ed25519 verify key
                hello_payload = {"version": "1"}
                if ecdh_pub_hex:
                    hello_payload["ecdh_pub"] = ecdh_pub_hex
                if self._wallet_pubkey_hex:
                    hello_payload["ed25519_pub"] = self._wallet_pubkey_hex
                hello = KiteMessage(
                    type=KITE_HELLO,
                    from_node=self.node_id,
                    payload=hello_payload,
                ).sign(self._signing_key)
                log.info(f"[{self.node_id}] 📡 Relay HELLO #{attempt} → {peer_id} "
                         f"(pair={pair_id[:12]}, remaining={remaining:.0f}s)")
                await bridge.send(hello.to_json())

                # Wait for WELCOME (or timeout then retry HELLO)
                wait_time = min(hello_interval, remaining)
                try:
                    raw = await asyncio.wait_for(bridge.recv(), timeout=wait_time)
                    resp = KiteMessage.from_json(raw)
                    if resp.type == KITE_WELCOME:
                        # ── Store peer's Ed25519 verify key ──
                        peer_ed_pub = resp.payload.get("ed25519_pub", "")
                        if peer_ed_pub and HAS_NACL:
                            try:
                                self._peer_verify_keys[peer_id] = _Ed25519VerifyKey(bytes.fromhex(peer_ed_pub))
                            except Exception as e:
                                log.warning(f"[{self.node_id}] ⚠️ Failed to parse peer Ed25519 key: {e}")

                        # ── ECDH: derive shared secret from peer's public key ──
                        peer_ecdh_pub_hex = resp.payload.get("ecdh_pub", "")
                        channel_secret = ""
                        if ecdh_priv and peer_ecdh_pub_hex:
                            try:
                                from kite_crypto import ecdh_derive_secret
                                canonical_pair = ":".join(sorted([self.node_id, peer_id]))
                                ecdh_secret = ecdh_derive_secret(
                                    ecdh_priv, bytes.fromhex(peer_ecdh_pub_hex), canonical_pair
                                )
                                if ecdh_secret:
                                    channel_secret = ecdh_secret
                                    log.info(f"[{self.node_id}] 🔐 ECDH key exchange completed "
                                             f"(relay initiator → {peer_id})")
                            except Exception as e:
                                log.warning(f"[{self.node_id}] ⚠️ ECDH failed in relay_handshake: {e}")

                        # Wrap relay bridge with encryption if we have a channel secret
                        ews = self._wrap_encrypted_ws(bridge, channel_secret, peer_id)
                        summary = self._transport_summary("rendezvous-relay")
                        log.info(
                            f"[{self.node_id}] ✅ Connected: {peer_id} [{summary}] "
                            f"(relay handshake initiator, attempt #{attempt}) "
                            f"[{len(self.connections)} active]"
                        )
                        self.connections[peer_id] = ews
                        self._notify_connected(peer_id)
                        await self._handle_messages(ews, peer_id)
                        # Message loop exited (bridge closed / keepalive timeout / peer gone)
                        if peer_id in self.connections:
                            del self.connections[peer_id]
                            self._connecting_peers.discard(peer_id)
                            log.info(f"[{self.node_id}] 🔴 {peer_id} relay disconnected "
                                     f"[{len(self.connections)} active]")
                            if _kn:
                                _kn.get().notify_connect(peer_id, connected=False,
                                                         info=f"remaining connections: {len(self.connections)}")
                        return
                    elif resp.type == KITE_REJECT:
                        log.warning(f"[{self.node_id}] ❌ Relay handshake rejected by {peer_id}")
                        self._cleanup_failed_pair(peer_id, pair_id)
                        return
                    else:
                        log.debug(f"[{self.node_id}] relay_handshake: unexpected msg type={resp.type}, retrying")
                except asyncio.TimeoutError:
                    if attempt < max_hello_attempts:
                        log.info(f"[{self.node_id}] ⏳ No WELCOME yet from {peer_id}, re-sending HELLO...")
                    continue

            # Exhausted all attempts
            log.warning(f"[{self.node_id}] ❌ Relay handshake timed out after {timeout}s "
                        f"({max_hello_attempts} HELLO attempts) → {peer_id}")
            self._cleanup_failed_pair(peer_id, pair_id)
        except Exception as e:
            log.warning(f"[{self.node_id}] ❌ Relay handshake failed: {e}")
            self._cleanup_failed_pair(peer_id, pair_id)

    async def _relay_accept(self, bridge: "_RelayBridge", peer_id: str, pair_id: str = ""):
        """Acceptor: wait for HELLO via relay bridge, send WELCOME, then dispatch.

        Loops until a valid HELLO is received (the initiator may resend HELLO
        multiple times while waiting for our side to be ready). Non-HELLO messages
        are silently discarded to tolerate out-of-order or duplicate messages.

        ECDH: Extracts the peer's X25519 public key from HELLO, generates our keypair,
        includes our public key in WELCOME, and derives the shared ECDH secret for
        forward-secret channel encryption.
        """
        timeout = self._RELAY_HANDSHAKE_TIMEOUT
        try:
            # ── Ed25519 public-key auth ──
            deadline = asyncio.get_running_loop().time() + timeout
            log.info(f"[{self.node_id}] 📡 Relay acceptor waiting for HELLO ← {peer_id} "
                     f"(pair={pair_id[:12]}, timeout={timeout}s)")

            while asyncio.get_running_loop().time() < deadline:
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    break
                try:
                    raw = await asyncio.wait_for(bridge.recv(), timeout=remaining)
                except asyncio.TimeoutError:
                    break  # overall deadline reached
                msg = KiteMessage.from_json(raw)

                if msg.type != KITE_HELLO:
                    # Might be a duplicate WELCOME or other noise — skip and keep waiting
                    log.debug(f"[{self.node_id}] relay_accept: got {msg.type} instead of HELLO, ignoring")
                    continue

                # ── Extract peer's Ed25519 public key from HELLO and verify ──
                peer_ed_pub = msg.payload.get("ed25519_pub", "")
                if not peer_ed_pub or not HAS_NACL:
                    log.warning(f"[{self.node_id}] ❌ HELLO missing ed25519_pub from {peer_id}, rejecting")
                    await bridge.send(KiteMessage(type=KITE_REJECT, from_node=self.node_id,
                                                  payload={"reason": "missing_pubkey"}).sign(self._signing_key).to_json())
                    self._cleanup_failed_pair(peer_id, pair_id)
                    return
                try:
                    peer_vk = _Ed25519VerifyKey(bytes.fromhex(peer_ed_pub))
                except Exception:
                    log.warning(f"[{self.node_id}] ❌ Invalid Ed25519 key from {peer_id}, rejecting")
                    await bridge.send(KiteMessage(type=KITE_REJECT, from_node=self.node_id,
                                                  payload={"reason": "invalid_pubkey"}).sign(self._signing_key).to_json())
                    self._cleanup_failed_pair(peer_id, pair_id)
                    return

                if not msg.verify(peer_vk, max_age=300.0):
                    log.warning(f"[{self.node_id}] ❌ HELLO verification failed from {peer_id}, rejecting")
                    await bridge.send(KiteMessage(type=KITE_REJECT, from_node=self.node_id,
                                                  payload={"reason": "auth_failed"}).sign(self._signing_key).to_json())
                    self._cleanup_failed_pair(peer_id, pair_id)
                    return

                # Store peer's verify key
                self._peer_verify_keys[peer_id] = peer_vk

                # ── Connection approval gate (relay path) ──
                if not self._auto_accept:
                    _trusted = getattr(self, '_trusted_connect_nodes', set())
                    if peer_id not in _trusted:
                        approval_id = str(uuid.uuid4())[:12]
                        evt = asyncio.Event()
                        entry = {
                            "approval_id": approval_id,
                            "peer_id": peer_id,
                            "remote_addr": "(relay)",
                            "ed25519_pub": peer_ed_pub[:16] + "...",
                            "timestamp": time.time(),
                            "event": evt,
                            "approved": None,
                        }
                        if len(self._pending_connect_approvals) >= self._PENDING_CONNECT_MAX:
                            oldest_key = next(iter(self._pending_connect_approvals))
                            old = self._pending_connect_approvals.pop(oldest_key)
                            old["approved"] = False
                            old["event"].set()
                        self._pending_connect_approvals[approval_id] = entry
                        log.info(f"[{self.node_id}] ⏳ Relay connection from {peer_id} pending approval "
                                 f"[{approval_id}] (auto_accept=false)")
                        cb = getattr(self, '_on_connect_approval_needed', None)
                        if cb:
                            try:
                                cb(approval_id, peer_id, "(relay)")
                            except Exception:
                                pass
                        try:
                            await asyncio.wait_for(evt.wait(), timeout=self._invite_timeout)
                        except asyncio.TimeoutError:
                            self._pending_connect_approvals.pop(approval_id, None)
                            await bridge.send(KiteMessage(type=KITE_REJECT, from_node=self.node_id,
                                                          payload={"reason": "approval_timeout"}).sign(self._signing_key).to_json())
                            log.warning(f"[{self.node_id}] ⏰ Relay connection from {peer_id} timed out "
                                        f"waiting for approval [{approval_id}]")
                            self._cleanup_failed_pair(peer_id, pair_id)
                            return
                        self._pending_connect_approvals.pop(approval_id, None)
                        if not entry["approved"]:
                            await bridge.send(KiteMessage(type=KITE_REJECT, from_node=self.node_id,
                                                          payload={"reason": "rejected_by_user"}).sign(self._signing_key).to_json())
                            log.info(f"[{self.node_id}] 🚫 Relay connection from {peer_id} rejected by user [{approval_id}]")
                            self._cleanup_failed_pair(peer_id, pair_id)
                            return
                        log.info(f"[{self.node_id}] ✅ Relay connection from {peer_id} approved [{approval_id}]")

                # ── ECDH: extract peer's public key and generate ours ──
                peer_ecdh_pub_hex = msg.payload.get("ecdh_pub", "")
                ecdh_priv = b""
                ecdh_pub_hex = ""
                try:
                    from kite_crypto import generate_ecdh_keypair
                    ecdh_priv, ecdh_pub = generate_ecdh_keypair()
                    if ecdh_pub:
                        ecdh_pub_hex = ecdh_pub.hex()
                except ImportError:
                    pass

                # Valid HELLO received — send WELCOME with our ECDH + Ed25519 public keys
                welcome_payload = {}
                if ecdh_pub_hex:
                    welcome_payload["ecdh_pub"] = ecdh_pub_hex
                if self._wallet_pubkey_hex:
                    welcome_payload["ed25519_pub"] = self._wallet_pubkey_hex
                welcome = KiteMessage(type=KITE_WELCOME, from_node=self.node_id,
                                      to_node=peer_id, payload=welcome_payload).sign(self._signing_key)
                await bridge.send(welcome.to_json())

                # ── ECDH: derive shared secret ──
                channel_secret = ""
                if ecdh_priv and peer_ecdh_pub_hex:
                    try:
                        from kite_crypto import ecdh_derive_secret
                        canonical_pair = ":".join(sorted([self.node_id, peer_id]))
                        ecdh_secret = ecdh_derive_secret(
                            ecdh_priv, bytes.fromhex(peer_ecdh_pub_hex), canonical_pair
                        )
                        if ecdh_secret:
                            channel_secret = ecdh_secret
                            log.info(f"[{self.node_id}] 🔐 ECDH key exchange completed "
                                     f"(relay acceptor ← {peer_id})")
                    except Exception as e:
                        log.warning(f"[{self.node_id}] ⚠️ ECDH failed in relay_accept: {e}")

                # Wrap relay bridge with encryption
                ews = self._wrap_encrypted_ws(bridge, channel_secret, peer_id)
                summary = self._transport_summary("rendezvous-relay")
                log.info(
                    f"[{self.node_id}] ✅ Connected: {peer_id} [{summary}] "
                    f"(relay handshake acceptor) [{len(self.connections)} active]"
                )
                self.connections[peer_id] = ews
                self._notify_connected(peer_id)
                await self._handle_messages(ews, peer_id)
                # Message loop exited (bridge closed / keepalive timeout / peer gone)
                if peer_id in self.connections:
                    del self.connections[peer_id]
                    self._connecting_peers.discard(peer_id)
                    log.info(f"[{self.node_id}] 🔴 {peer_id} relay disconnected "
                             f"[{len(self.connections)} active]")
                    if _kn:
                        _kn.get().notify_connect(peer_id, connected=False,
                                                 info=f"remaining connections: {len(self.connections)}")
                return

            # Timeout with no valid HELLO
            log.warning(f"[{self.node_id}] ❌ Relay accept timed out ({timeout}s) — "
                        f"no HELLO from {peer_id}")
            self._cleanup_failed_pair(peer_id, pair_id)
        except Exception as e:
            log.warning(f"[{self.node_id}] ❌ Relay accept failed: {e}")
            self._cleanup_failed_pair(peer_id, pair_id)

    async def discover(self, tags: Optional[List[str]] = None, q: str = "",
                       source: str = "auto") -> list:
        """Discover online same-group nodes.

        改动二: RDV is the authoritative member source (who exists).
        Gossip only supplements with status fields (udp_ok, udp_rtt_ms, state).
        The two are merged: RDV provides the canonical list, gossip enriches it.

        Data source priority (when source='auto'):
          1. Try RDV first (authoritative, who is registered)
          2. Merge gossip status fields into RDV results
          3. If RDV unavailable, fall back to gossip-only

        Args:
            tags: Optional tag filter (OR match).
            q: Optional full-text search on nickname/node_id.
            source: 'auto' (default), 'gossip', or 'rdv'.
        """
        # ── Build gossip lookup for merge (all states including dead) ──
        gossip_map: Dict[str, dict] = {}
        if self._gossip:
            # include_dead=True so we can show dead nodes' status too
            for m in self._gossip.members(include_suspect=True, include_dead=True):
                nid = m.get("id", m.get("node_id", ""))
                if nid:
                    gossip_map[nid] = m

        # ── Gossip-only mode ──
        if source == "gossip":
            result = []
            for nid, m in gossip_map.items():
                m["source"] = "gossip"
                m["node_id"] = m.pop("id", m.get("node_id", ""))
                if "hint" in m:
                    m["addr_hint"] = m.pop("hint")
                if "pub" in m:
                    m["public_addr"] = m.pop("pub")
                result.append(m)
            if tags:
                result = [m for m in result
                          if any(t in m.get("tags", []) for t in tags)]
            if q:
                q_lower = q.lower()
                result = [m for m in result
                          if q_lower in m.get("nick", "").lower()
                          or q_lower in m.get("node_id", "").lower()]
            return result

        # ── RDV source (authoritative) ──
        rdv_nodes = []
        if self._pairing and not self._rdv_detached:
            try:
                rdv_nodes = await self._pairing.list_nodes(tags=tags, q=q)
            except Exception as e:
                log.debug(f"[{self.node_id}] RDV list_nodes failed: {e}")

        if rdv_nodes:
            # 改动二: merge gossip status into RDV results
            for n in rdv_nodes:
                n["source"] = "rdv+gossip"
                nid = n.get("node_id", "")
                gm = gossip_map.pop(nid, None)
                if gm:
                    # Supplement with gossip status fields
                    n["gossip_state"] = gm.get("state", "unknown")
                    n["udp_ok"] = gm.get("udp_ok")
                    n["udp_rtt_ms"] = gm.get("udp_rtt_ms")
                else:
                    n["gossip_state"] = "unknown"
                    n["udp_ok"] = None
                    n["udp_rtt_ms"] = None

            # 改动二: also append gossip-only members not in RDV (dead/suspect)
            for nid, gm in gossip_map.items():
                extra = {
                    "node_id": gm.get("id", nid),
                    "source": "gossip",
                    "gossip_state": gm.get("state", "unknown"),
                    "udp_ok": gm.get("udp_ok"),
                    "udp_rtt_ms": gm.get("udp_rtt_ms"),
                }
                if "nick" in gm:
                    extra["nickname"] = gm["nick"]
                if "hint" in gm:
                    extra["addr_hint"] = gm["hint"]
                if "pub" in gm:
                    extra["public_addr"] = gm["pub"]
                if "tags" in gm:
                    extra["tags"] = gm["tags"]
                rdv_nodes.append(extra)

            return rdv_nodes

        # ── RDV unavailable — fall back to gossip ──
        if gossip_map:
            result = []
            for nid, m in gossip_map.items():
                m["source"] = "gossip"
                m["node_id"] = m.pop("id", m.get("node_id", ""))
                if "hint" in m:
                    m["addr_hint"] = m.pop("hint")
                if "pub" in m:
                    m["public_addr"] = m.pop("pub")
                result.append(m)
            if tags:
                result = [m for m in result
                          if any(t in m.get("tags", []) for t in tags)]
            if q:
                q_lower = q.lower()
                result = [m for m in result
                          if q_lower in m.get("nick", "").lower()
                          or q_lower in m.get("node_id", "").lower()]
            return result

        # ── Neither source available ──
        if not self._pairing:
            if self._gossip:
                return []
            raise RuntimeError("Neither gossip nor Rendezvous is available for discovery.")

        # RDV configured but returned empty
        return []

    async def invite_peer(self, target_node_id: str, message: str = "") -> str:
        """Invite a node to pair by discovering its address and directly connecting P2P.

        Invite does NOT go through the Rendezvous server.  The flow is:
          1. Query RDV ``list_nodes`` to resolve the target's network addresses
          2. Collect candidate TCP addresses (addr_hint, public_addr)
          3. Initiate ``_punch_and_connect`` (UDP punch → TCP phases → relay fallback)

        The resulting KITP handshake triggers ``_notify_connected`` which resolves
        the ``_connect_futures`` entry that ``invite_and_connect`` is awaiting.

        Returns:
            A pair_id string for tracking (informational only).

        Raises:
            RuntimeError: if Rendezvous is not configured.
            LookupError: if the target node is not found on Rendezvous.
        """
        if not self._pairing:
            raise RuntimeError("Rendezvous not configured. Set rendezvous_url in KiteNode.")

        # ── 1. Discover target node to obtain its addresses ──
        nodes = await self._pairing.list_nodes()
        target_info = None
        for n in nodes:
            if n.get("node_id") == target_node_id:
                target_info = n
                break
        if not target_info:
            raise LookupError(
                f"Node {target_node_id!r} not found on Rendezvous. "
                f"Is it online and in the same group?"
            )

        # ── 2. Collect candidate TCP addresses ──
        tcp_addrs: List[str] = []
        addr_hint = target_info.get("addr_hint", "")
        public_addr = target_info.get("public_addr", "")
        if addr_hint:
            tcp_addrs.append(addr_hint)
        if public_addr and public_addr != addr_hint:
            tcp_addrs.append(public_addr)

        log.info(f"[{self.node_id}] 📨 invite_peer → {target_node_id} "
                 f"(addrs={[_mask_ip(a) for a in tcp_addrs]}, msg={message!r})")

        # ── 3. Guard against duplicate concurrent connects ──
        if target_node_id in self._connecting_peers:
            log.info(f"[{self.node_id}] Already connecting to {target_node_id}, skipping duplicate invite")
            return f"dup-{target_node_id}"
        self._connecting_peers.add(target_node_id)

        # ── 4. Generate pair_id and initiate P2P connection ──
        pair_id = str(uuid.uuid4())

        if tcp_addrs:
            self._track_task(self._punch_and_connect(pair_id, target_node_id, tcp_addrs), name="punch_and_connect")
        else:
            # No addresses at all — go straight to relay
            log.warning(f"[{self.node_id}] No TCP addresses for {target_node_id}, "
                        f"falling back to relay")
            self._track_task(self._setup_rendezvous_relay(pair_id, target_node_id), name="relay_fallback")

        return pair_id

    async def invite_and_connect(self, target_node_id: str, message: str = "",
                                  timeout: float = 30) -> str:
        """Invite a peer and wait for the KITP connection to be fully established.

        Recommended high-level programmatic API:
          peer_id = await node.invite_and_connect("target-B", timeout=30)
          result  = await node.send_task(peer_id, "hello")

        Returns the peer's node_id when the connection is ready.
        Raises TimeoutError if the peer does not accept or connect within the given time.

        If a connection attempt is already in progress (from a previous call),
        joins the existing wait instead of sending a duplicate invite.

        After handshake completion, a brief stability check verifies the connection is still
        alive before returning (prevents returning "connected" for connections that drop
        immediately after handshake).
        """
        # If already connected, return immediately
        if target_node_id in self.connections:
            return target_node_id

        # If a connect attempt is already in progress, join the existing future
        # rather than sending a duplicate invite and overwriting the future
        existing_fut = self._connect_futures.get(target_node_id)
        if existing_fut and not existing_fut.done():
            log.info(f"[{self.node_id}] ⏳ invite_and_connect: already connecting to "
                     f"{target_node_id}, joining existing wait")
            try:
                peer_id = await asyncio.wait_for(asyncio.shield(existing_fut), timeout=timeout)
            except asyncio.TimeoutError:
                raise TimeoutError(
                    f"invite_and_connect to {target_node_id!r} timed out after {timeout}s "
                    f"(joined existing attempt). Peer may be offline, or didn't accept the invite."
                )
            # Stability check after join
            return await self._verify_connection_stable(peer_id)

        # Create a future that will be resolved when KITP handshake completes
        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        self._connect_futures[target_node_id] = fut

        try:
            # Send the invite
            await self.invite_peer(target_node_id, message=message)
            # Wait for the full chain: accept → paired → punch/relay → KITP handshake
            peer_id = await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            self._connect_futures.pop(target_node_id, None)
            raise TimeoutError(
                f"invite_and_connect to {target_node_id!r} timed out after {timeout}s. "
                f"Peer may be offline, or didn't accept the invite."
            )
        except Exception:
            self._connect_futures.pop(target_node_id, None)
            raise

        # ── Stability check: verify connection survived the first moments ──
        return await self._verify_connection_stable(peer_id)

    async def _verify_connection_stable(self, peer_id: str,
                                         grace: float = 1.5,
                                         checks: int = 3) -> str:
        """Wait briefly and verify the connection is still alive.

        After handshake completes, relay/TCP connections sometimes die within
        the first second (e.g., Rendezvous relay channel closes, WebSocket
        context exits). This method catches those "flash disconnects" and
        raises ConnectionError instead of silently returning a stale peer_id.

        Args:
            peer_id: The connected peer to verify.
            grace: Total grace period in seconds.
            checks: Number of checks to perform during the grace period.
        """
        interval = grace / checks
        for i in range(checks):
            await asyncio.sleep(interval)
            if peer_id not in self.connections:
                log.warning(f"[{self.node_id}] ⚠️ Connection to {peer_id} died during "
                            f"stability check (check {i + 1}/{checks}, {interval * (i + 1):.1f}s "
                            f"after handshake)")
                raise ConnectionError(
                    f"Connection to {peer_id} was established but dropped within "
                    f"{interval * (i + 1):.1f}s. The peer may have disconnected, "
                    f"or the relay channel was interrupted."
                )
        log.info(f"[{self.node_id}] ✅ Connection to {peer_id} stable "
                 f"(survived {grace}s grace period)")
        return peer_id

    async def wait_for_peer(self, peer_node_id: str, timeout: float = 60) -> str:
        """Wait until a specific peer connects (from any direction — invite or incoming).

        Useful for the receiving side (Agent/worker) that wants to block until
        a specific requester establishes a connection:
          peer = await node.wait_for_peer("requester-A", timeout=60)
          # connection is ready, incoming tasks will be dispatched

        Also useful for waiting on a peer that was invited separately.
        Returns the peer's node_id. Raises TimeoutError if not connected in time.
        """
        if peer_node_id in self.connections:
            return peer_node_id

        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        self._connect_futures[peer_node_id] = fut

        try:
            return await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            self._connect_futures.pop(peer_node_id, None)
            raise TimeoutError(
                f"wait_for_peer({peer_node_id!r}) timed out after {timeout}s"
            )

    async def wait_for_any_peer(self, timeout: float = 60) -> str:
        """Wait until ANY new peer connects.

        Useful for agents that don't know who will connect in advance:
          peer = await node.wait_for_any_peer(timeout=120)
          print(f"Someone connected: {peer}")

        Returns the peer's node_id. Raises TimeoutError if nobody connects.
        """
        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        # Use a special sentinel key
        self._connect_futures["*"] = fut
        try:
            return await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            self._connect_futures.pop("*", None)
            raise TimeoutError(
                f"wait_for_any_peer timed out after {timeout}s — no peer connected"
            )

    # ── Internal Helpers ──

    @staticmethod
    def _is_cloud_private(ip) -> bool:
        """Check if an IP is in common cloud provider VPC / CGNAT ranges.
        These ranges are private but not within RFC 1918 (ipaddress.is_private misses them).

        Known ranges:
          - 100.64.0.0/10  (CGNAT / Tailscale / some cloud VPCs)
          - 11.0.0.0/8     (Alibaba Cloud classic network)
          - 30.0.0.0/8     (Alibaba Cloud internal)
          - 9.0.0.0/8      (Tencent internal / some enterprises)
          - 100.0.0.0/8    (various cloud internals)
        """
        import ipaddress as _ipa
        _cloud_nets = (
            _ipa.ip_network("100.64.0.0/10"),   # CGNAT
            _ipa.ip_network("11.0.0.0/8"),       # Alibaba classic
            _ipa.ip_network("30.0.0.0/8"),       # Alibaba internal
            _ipa.ip_network("9.0.0.0/8"),        # Tencent / enterprise
            _ipa.ip_network("14.0.0.0/8"),       # Tencent Cloud / some ISP internal
        )
        for net in _cloud_nets:
            if ip in net:
                return True
        return False

    @staticmethod
    def _classify_addr(addr: str) -> str:
        """Classify an address as LAN/loopback/WAN for logging.

        Returns a human-readable tag like '🏠 LAN', '☁️ Cloud-LAN', '🌐 WAN', or '🔁 loopback'.
        Recognises RFC 1918 private ranges AND common cloud-provider VPC ranges.
        """
        try:
            host = addr.rsplit(":", 1)[0]
            import ipaddress
            ip = ipaddress.ip_address(host)
            if ip.is_loopback:
                return "🔁 loopback"
            if ip.is_private:
                return "🏠 LAN"
            if KiteNode._is_cloud_private(ip):
                return "☁️ Cloud-LAN"
            return "🌐 WAN"
        except Exception:
            return "❓ unknown"

    @staticmethod
    def _transport_summary(method: str, addr: str = "", encrypted: bool = True) -> str:
        """Build a one-line transport summary string for connection logs.

        Args:
            method: 'tcp-direct', 'udp-p2p', 'rendezvous-relay'
            addr: the address connected to (for tcp-direct / udp-p2p)
            encrypted: whether AES-256-GCM is active
        """
        labels = {
            "tcp-direct": "TCP Direct",
            "udp-p2p": "UDP P2P",
            "rendezvous-relay": "Rendezvous Relay",
        }
        parts = [labels.get(method, method)]
        if addr:
            net = KiteNode._classify_addr(addr)
            parts.append(f"{net} {addr}")
        if encrypted:
            parts.append("🔒 AES-256-GCM")
        else:
            parts.append("⚠️ unencrypted")
        return " | ".join(parts)

    def _get_verify_key(self, peer_id: str = "") -> "_Ed25519VerifyKey":
        """Get the Ed25519 verify key for a given peer.

        Priority:
          1. Per-peer verify key (received during HELLO/WELCOME handshake)
          2. None (unknown peer — verification will fail)
        """
        if peer_id and peer_id in self._peer_verify_keys:
            return self._peer_verify_keys[peer_id]
        return None

    def _wrap_encrypted_ws(self, ws, channel_secret: str, peer_id: str):
        """Wrap a plain WebSocket with application-layer AES-256-GCM encryption.

        Uses the ECDH-derived channel secret to derive an encryption key.
        Falls back to plain ws if crypto is unavailable or no secret was derived.

        IMPORTANT: The pair_id used for key derivation MUST be identical on both
        sides. We use sorted(node_id, peer_id) to guarantee a canonical value
        regardless of which side initiates the connection.
        """
        if not channel_secret:
            return ws
        try:
            from kite_crypto import KiteChannelCipher, EncryptedWebSocket
            # Canonical pair_id: sorted concatenation ensures both sides derive the same key
            canonical_pair = ":".join(sorted([self.node_id, peer_id]))
            cipher = KiteChannelCipher(channel_secret, canonical_pair, purpose="kite-tcp",
                                       local_node_id=self.node_id, peer_node_id=peer_id)
            if cipher.enabled:
                log.info(f"[{self.node_id}] 🔒 TCP connection to {peer_id} encrypted (AES-256-GCM)")
                return EncryptedWebSocket(ws, cipher)
            return ws
        except ImportError:
            log.warning(f"[{self.node_id}] kite_crypto not available — TCP connection unencrypted")
            return ws

    def _notify_connected(self, peer_id: str):
        """Resolve any pending connect future for this peer (used by invite_and_connect)."""
        # Connection attempt completed — remove from in-progress set
        self._connecting_peers.discard(peer_id)
        # 🔔 Desktop notification for peer connect
        if _kn:
            _kn.get().notify_connect(peer_id, connected=True,
                                     info=f"Active connections: {len(self.connections)}")

        # Specific peer future
        fut = self._connect_futures.pop(peer_id, None)
        if fut and not fut.done():
            fut.set_result(peer_id)
        # Wildcard future (wait_for_any_peer)
        any_fut = self._connect_futures.pop("*", None)
        if any_fut and not any_fut.done():
            any_fut.set_result(peer_id)

    @staticmethod
    def _detect_lan_ip() -> str:
        """Best-effort LAN IP detection. Returns 127.0.0.1 if all methods fail."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(1)
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
            if ip and not ip.startswith("127."):
                return ip
        except Exception:
            pass
        return "127.0.0.1"

    @staticmethod
    def _detect_local_ips() -> List[str]:
        """Detect ALL local non-loopback IPs across all interfaces.

        Returns a list sorted by preference:
          1. RFC 1918 private IPs (192.168.x, 10.x, 172.16-31.x)  — "real" LAN
          2. Cloud-private IPs (11.x, 9.x, 100.64.x, 30.x)       — cloud VPC
          3. Other non-loopback IPs
        """
        import ipaddress as _ipa
        ips = set()
        # Method 1: default route interface
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(1)
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
                if ip and not ip.startswith("127."):
                    ips.add(ip)
        except Exception:
            pass
        # Method 2: enumerate all interfaces
        try:
            import netifaces  # type: ignore
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
                for a in addrs:
                    ip = a.get("addr", "")
                    if ip and not ip.startswith("127."):
                        ips.add(ip)
        except ImportError:
            # netifaces not available — try socket fallback
            try:
                hostname = socket.gethostname()
                for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
                    ip = info[4][0]
                    if ip and not ip.startswith("127."):
                        ips.add(ip)
            except Exception:
                pass

        if not ips:
            return ["127.0.0.1"]

        # Sort: RFC 1918 first, then cloud-private, then others
        def _sort_key(ip_str: str):
            ip = _ipa.ip_address(ip_str)
            if ip.is_private:
                return (0, ip_str)
            if KiteNode._is_cloud_private(ip):
                return (1, ip_str)
            return (2, ip_str)

        return sorted(ips, key=_sort_key)

    async def _connect_peers(self):
        for addr in self.peers:
            self._track_task(self._dial(addr), name=f"dial_{addr}")

    async def _dial(self, addr: str, retry_delay: float = 5.0, max_retries: int = 0):
        """Dial a peer via TCP WebSocket with exponential backoff.

        After KITP handshake succeeds, all messages are encrypted with AES-256-GCM
        via EncryptedWebSocket wrapping.

        Args:
            addr: host:port to connect to
            retry_delay: initial seconds between retries (doubles each attempt, capped at 60s)
            max_retries: 0 = infinite retries (for static peers), >0 = give up after N failures
        """
        uri = f"ws://{addr}"
        net_tag = self._classify_addr(addr)
        attempts = 0
        current_delay = retry_delay
        max_delay = 60.0  # cap exponential backoff
        while True:
            t0 = time.time()
            log.info(f"[{self.node_id}] 🔌 TCP connecting {net_tag} {_mask_ip(addr)} (attempt #{attempts + 1})...")
            try:
                async with ws_connect(uri) as ws:
                    elapsed_ms = (time.time() - t0) * 1000
                    log.info(f"[{self.node_id}] 🔌 TCP socket established {net_tag} {_mask_ip(addr)} "
                             f"({elapsed_ms:.0f}ms), starting KITP handshake...")
                    if not await self._do_hello(ws, addr):
                        total_ms = (time.time() - t0) * 1000
                        log.warning(f"[{self.node_id}] ❌ TCP connected but KITP handshake "
                                    f"rejected by {net_tag} {_mask_ip(addr)} ({total_ms:.0f}ms)")
                        return
                    # _do_hello already wrapped ws → EncryptedWebSocket in self.connections
                    # Find the actual peer_id from connections (it might differ from addr)
                    ews = None
                    peer_id = addr
                    for pid, conn in self.connections.items():
                        if hasattr(conn, '_ws') and conn._ws is ws:
                            ews = conn
                            peer_id = pid
                            break
                    if ews is None:
                        ews = self.connections.get(addr)
                    if ews is None:
                        # _do_hello returned True but tie-breaking dropped this
                        # outbound — the inbound path handles this peer instead.
                        log.info(f"[{self.node_id}] ⏩ Outbound dial to {_mask_ip(addr)} handshake OK "
                                 f"but tie-break dropped — peer handled by inbound path")
                        return
                    total_ms = (time.time() - t0) * 1000
                    summary = self._transport_summary("tcp-direct", addr)
                    log.info(
                        f"[{self.node_id}] ✅ Connected: {peer_id} [{summary}] "
                        f"(outgoing, {total_ms:.0f}ms) [{len(self.connections)} active]"
                    )
                    await self._handle_messages(ews, peer_id)
                    # Message loop exited — clean up before ws_connect context closes the socket.
                    # Only remove if WE are still the active connection handler.
                    if self.connections.get(peer_id) is ews:
                        del self.connections[peer_id]
                        self._connecting_peers.discard(peer_id)
                        log.info(f"[{self.node_id}] 🔴 {peer_id} disconnected (outgoing) "
                                 f"[{len(self.connections)} active]")
                        if _kn:
                            _kn.get().notify_connect(peer_id, connected=False,
                                                     info=f"remaining connections: {len(self.connections)}")
            except asyncio.TimeoutError:
                elapsed_ms = (time.time() - t0) * 1000
                err_detail = f"timeout ({elapsed_ms:.0f}ms)"
            except ConnectionRefusedError:
                elapsed_ms = (time.time() - t0) * 1000
                err_detail = f"connection refused ({elapsed_ms:.0f}ms) — port not listening or firewall reject"
            except OSError as e:
                elapsed_ms = (time.time() - t0) * 1000
                err_detail = f"{type(e).__name__}: {e} ({elapsed_ms:.0f}ms)"
            except Exception as e:
                elapsed_ms = (time.time() - t0) * 1000
                err_detail = f"{type(e).__name__}: {e} ({elapsed_ms:.0f}ms)"
            else:
                # ws_connect context exited normally (connection closed cleanly)
                continue

            attempts += 1
            if max_retries > 0 and attempts >= max_retries:
                log.info(f"[{self.node_id}] ❌ {net_tag} {_mask_ip(addr)} gave up after {attempts} attempts — {err_detail}")
                return
            log.warning(f"[{self.node_id}] ⏳ {net_tag} {_mask_ip(addr)} — {err_detail}. "
                        f"Retry #{attempts} (in {current_delay:.0f}s)")
            await asyncio.sleep(current_delay)
            # Exponential backoff with cap
            current_delay = min(current_delay * 1.5, max_delay)

    async def _do_hello(self, ws, addr: str, peer_id_hint: str = "") -> bool:
        """Send HELLO, wait for WELCOME. On success, wrap ws with encryption.

        Ed25519 public-key authentication:
          HELLO carries our Ed25519 public key. The peer verifies our signature
          using that key and responds with WELCOME carrying their public key.
          No shared secret is needed — each side's private key never leaves the node.

        ECDH key exchange:
          An ephemeral X25519 keypair is generated and the public key is
          included in the HELLO payload. The server responds with its own
          public key in WELCOME. Both sides then derive a shared ECDH secret
          for channel encryption — providing forward secrecy.
        """
        # ── Ed25519 public-key auth: sign with our private key ──
        pub_hex = self._wallet_pubkey_hex or ""
        log.info(f"[{self.node_id}] 🔑 _do_hello to {_mask_ip(addr)} (hint={peer_id_hint}): "
                 f"auth=Ed25519, pubkey={pub_hex[:16]}...")

        # ── Generate ephemeral ECDH keypair for forward secrecy ──
        ecdh_priv = b""
        ecdh_pub_hex = ""
        try:
            from kite_crypto import generate_ecdh_keypair
            ecdh_priv, ecdh_pub = generate_ecdh_keypair()
            if ecdh_pub:
                ecdh_pub_hex = ecdh_pub.hex()
        except ImportError:
            pass

        payload = {"version": "1"}
        if ecdh_pub_hex:
            payload["ecdh_pub"] = ecdh_pub_hex
        if pub_hex:
            payload["ed25519_pub"] = pub_hex

        msg = KiteMessage(
            type=KITE_HELLO,
            from_node=self.node_id,
            payload=payload,
        ).sign(self._signing_key)
        await ws.send(msg.to_json())
        raw = await ws.recv()
        resp = KiteMessage.from_json(raw)
        if resp.type == KITE_WELCOME:
            actual_peer_id = resp.from_node

            # ── Verify peer_id matches expected hint (if known) ──
            if peer_id_hint and actual_peer_id != peer_id_hint:
                log.warning(f"[{self.node_id}] ❌ WELCOME from_node mismatch: "
                            f"expected={peer_id_hint}, got={actual_peer_id} — possible MITM")
                return False

            # ── Store peer's Ed25519 verify key from WELCOME ──
            peer_ed_pub = resp.payload.get("ed25519_pub", "")
            if peer_ed_pub and HAS_NACL:
                try:
                    peer_vk = _Ed25519VerifyKey(bytes.fromhex(peer_ed_pub))
                    # Verify WELCOME signature with peer's public key
                    if not resp.verify(peer_vk, max_age=300.0):
                        log.warning(f"[{self.node_id}] ❌ WELCOME signature verification failed "
                                    f"from {actual_peer_id} — rejecting")
                        return False
                    self._peer_verify_keys[actual_peer_id] = peer_vk
                except Exception as e:
                    log.warning(f"[{self.node_id}] ⚠️ Failed to parse/verify peer Ed25519 key: {e}")
                    return False
            else:
                log.warning(f"[{self.node_id}] ⚠️ WELCOME missing ed25519_pub from {actual_peer_id}")

            # ── ECDH: derive shared secret from peer's public key ──
            peer_ecdh_pub_hex = resp.payload.get("ecdh_pub", "")
            channel_secret = ""
            if ecdh_priv and peer_ecdh_pub_hex:
                try:
                    from kite_crypto import ecdh_derive_secret
                    canonical_pair = ":".join(sorted([self.node_id, actual_peer_id]))
                    ecdh_secret = ecdh_derive_secret(
                        ecdh_priv, bytes.fromhex(peer_ecdh_pub_hex), canonical_pair
                    )
                    if ecdh_secret:
                        channel_secret = ecdh_secret
                        log.info(f"[{self.node_id}] 🔐 ECDH key exchange completed "
                                 f"(direct TCP → {actual_peer_id})")
                except Exception as e:
                    log.warning(f"[{self.node_id}] ⚠️ ECDH failed in _do_hello: {e}")
            # ── Simultaneous-open tie-break (outbound side) ──
            if actual_peer_id in self.connections:
                if self.node_id < actual_peer_id:
                    old_conn = self.connections.pop(actual_peer_id, None)
                    log.info(f"[{self.node_id}] 🔀 Simultaneous TCP: replacing inbound from {actual_peer_id} "
                             f"with our outbound (tie-break: {self.node_id} < {actual_peer_id})")
                    if old_conn:
                        try:
                            await old_conn.close()
                        except Exception:
                            pass
                else:
                    # We are the "acceptor-wins" side — keep the existing inbound, drop this outbound
                    log.info(f"[{self.node_id}] 🔀 Simultaneous TCP: keeping inbound from {actual_peer_id}, "
                             f"dropping our outbound (tie-break: {self.node_id} > {actual_peer_id})")
                    return True  # handshake succeeded, but we won't use this connection

            # Wrap with application-layer encryption
            ews = self._wrap_encrypted_ws(ws, channel_secret, actual_peer_id)
            self.connections[actual_peer_id] = ews
            self._notify_connected(actual_peer_id)
            return True
        return False

    async def _handle_incoming(self, ws):
        peer_id = None
        ews = None  # Will be set after successful handshake; used by finally for cleanup guard
        # Log inbound TCP connection with remote address
        remote_addr = ""
        if hasattr(ws, 'remote_address') and ws.remote_address:
            remote_addr = f"{ws.remote_address[0]}:{ws.remote_address[1]}"
        net_tag = self._classify_addr(remote_addr) if remote_addr else "❓ unknown"
        log.info(f"[{self.node_id}] 🔌 TCP inbound connection from {net_tag} {_mask_ip(remote_addr) or '(unknown)'}")
        try:
            # Expect HELLO first (plaintext — handshake not yet complete)
            raw = await ws.recv()
            msg = KiteMessage.from_json(raw)
            peer_id = msg.from_node

            # ── Ed25519 public-key auth ──
            log.info(f"[{self.node_id}] 🔑 Incoming connection from {peer_id}: auth=Ed25519")
            if msg.type != KITE_HELLO:
                await ws.send(KiteMessage(type=KITE_REJECT, from_node=self.node_id,
                                          payload={"reason": "expected_hello"}).sign(self._signing_key).to_json())
                log.warning(f"[{self.node_id}] ❌ First inbound message is not HELLO (got={msg.type}), peer={peer_id}")
                return

            # ── Extract peer's Ed25519 public key from HELLO and verify ──
            peer_ed_pub = msg.payload.get("ed25519_pub", "")
            if not peer_ed_pub or not HAS_NACL:
                log.warning(f"[{self.node_id}] ❌ HELLO missing ed25519_pub from {peer_id}, rejecting")
                await ws.send(KiteMessage(type=KITE_REJECT, from_node=self.node_id,
                                          payload={"reason": "missing_pubkey"}).sign(self._signing_key).to_json())
                return
            try:
                peer_vk = _Ed25519VerifyKey(bytes.fromhex(peer_ed_pub))
            except Exception:
                log.warning(f"[{self.node_id}] ❌ Invalid Ed25519 key from {peer_id}, rejecting")
                await ws.send(KiteMessage(type=KITE_REJECT, from_node=self.node_id,
                                          payload={"reason": "invalid_pubkey"}).sign(self._signing_key).to_json())
                return

            if not msg.verify(peer_vk, max_age=300.0):
                ts_drift = abs(time.time() - msg.ts)
                await ws.send(KiteMessage(type=KITE_REJECT, from_node=self.node_id,
                                          payload={"reason": "auth_failed"}).sign(self._signing_key).to_json())
                log.warning(f"[{self.node_id}] ❌ HELLO verification failed, peer={peer_id}: "
                            f"ts_drift={ts_drift:.1f}s, auth=Ed25519")
                return

            # Store peer's verify key for subsequent message verification
            self._peer_verify_keys[peer_id] = peer_vk

            # ── Connection approval gate ──
            # When auto_accept is False, non-trusted peers must be approved
            # by a human via Admin API before the connection proceeds.
            if not self._auto_accept:
                # Check if peer is in trusted_nodes (trusted = auto-pass)
                _trusted = getattr(self, '_trusted_connect_nodes', set())
                if peer_id not in _trusted:
                    approval_id = str(uuid.uuid4())[:12]
                    evt = asyncio.Event()
                    entry = {
                        "approval_id": approval_id,
                        "peer_id": peer_id,
                        "remote_addr": remote_addr,
                        "ed25519_pub": peer_ed_pub[:16] + "...",
                        "timestamp": time.time(),
                        "event": evt,
                        "approved": None,  # None=pending, True=approved, False=rejected
                    }
                    # Evict oldest if queue full
                    if len(self._pending_connect_approvals) >= self._PENDING_CONNECT_MAX:
                        oldest_key = next(iter(self._pending_connect_approvals))
                        old = self._pending_connect_approvals.pop(oldest_key)
                        old["approved"] = False
                        old["event"].set()
                    self._pending_connect_approvals[approval_id] = entry
                    log.info(f"[{self.node_id}] ⏳ Connection from {peer_id} pending approval "
                             f"[{approval_id}] (auto_accept=false)")
                    # Notify via callback (Agent layer hooks this for push notifications)
                    cb = getattr(self, '_on_connect_approval_needed', None)
                    if cb:
                        try:
                            cb(approval_id, peer_id, remote_addr)
                        except Exception:
                            pass
                    # Wait for human decision (up to invite_timeout)
                    try:
                        await asyncio.wait_for(evt.wait(), timeout=self._invite_timeout)
                    except asyncio.TimeoutError:
                        self._pending_connect_approvals.pop(approval_id, None)
                        await ws.send(KiteMessage(type=KITE_REJECT, from_node=self.node_id,
                                                  payload={"reason": "approval_timeout"}).sign(self._signing_key).to_json())
                        log.warning(f"[{self.node_id}] ⏰ Connection from {peer_id} timed out "
                                    f"waiting for approval [{approval_id}]")
                        return
                    # Check decision
                    self._pending_connect_approvals.pop(approval_id, None)
                    if not entry["approved"]:
                        await ws.send(KiteMessage(type=KITE_REJECT, from_node=self.node_id,
                                                  payload={"reason": "rejected_by_user"}).sign(self._signing_key).to_json())
                        log.info(f"[{self.node_id}] 🚫 Connection from {peer_id} rejected by user [{approval_id}]")
                        return
                    log.info(f"[{self.node_id}] ✅ Connection from {peer_id} approved [{approval_id}]")

            # ── ECDH: generate our keypair and extract peer's public key ──
            peer_ecdh_pub_hex = msg.payload.get("ecdh_pub", "")
            ecdh_priv = b""
            ecdh_pub_hex = ""
            try:
                from kite_crypto import generate_ecdh_keypair
                ecdh_priv, ecdh_pub = generate_ecdh_keypair()
                if ecdh_pub:
                    ecdh_pub_hex = ecdh_pub.hex()
            except ImportError:
                pass

            # Send WELCOME on plain ws (peer expects plaintext for handshake)
            welcome_payload = {}
            if ecdh_pub_hex:
                welcome_payload["ecdh_pub"] = ecdh_pub_hex
            if self._wallet_pubkey_hex:
                welcome_payload["ed25519_pub"] = self._wallet_pubkey_hex
            welcome = KiteMessage(type=KITE_WELCOME, from_node=self.node_id,
                                  to_node=peer_id, payload=welcome_payload).sign(self._signing_key)
            await ws.send(welcome.to_json())

            # ── ECDH: derive shared secret ──
            channel_secret = ""
            if ecdh_priv and peer_ecdh_pub_hex:
                try:
                    from kite_crypto import ecdh_derive_secret
                    canonical_pair = ":".join(sorted([self.node_id, peer_id]))
                    ecdh_secret = ecdh_derive_secret(
                        ecdh_priv, bytes.fromhex(peer_ecdh_pub_hex), canonical_pair
                    )
                    if ecdh_secret:
                        channel_secret = ecdh_secret
                        log.info(f"[{self.node_id}] 🔐 ECDH key exchange completed "
                                 f"(incoming TCP ← {peer_id})")
                except Exception as e:
                    log.warning(f"[{self.node_id}] ⚠️ ECDH failed in _handle_incoming: {e}")

            # ── Simultaneous-open tie-break ──
            if peer_id in self.connections:
                if self.node_id < peer_id:
                    log.info(f"[{self.node_id}] 🔀 Simultaneous TCP: already connected to {peer_id} "
                             f"via outbound — dropping duplicate inbound (tie-break: {self.node_id} < {peer_id})")
                    return
                else:
                    old_conn = self.connections.pop(peer_id, None)
                    log.info(f"[{self.node_id}] 🔀 Simultaneous TCP: replacing outbound connection to {peer_id} "
                             f"with inbound (tie-break: {self.node_id} > {peer_id})")
                    if old_conn:
                        try:
                            await old_conn.close()
                        except Exception:
                            pass

            # NOW switch to encrypted channel for all subsequent messages
            ews = self._wrap_encrypted_ws(ws, channel_secret, peer_id)
            self.connections[peer_id] = ews
            # Determine remote address for transport summary
            remote_addr = ""
            if hasattr(ws, 'remote_address') and ws.remote_address:
                remote_addr = f"{ws.remote_address[0]}:{ws.remote_address[1]}"
            ecdh_tag = "ECDH " if (ecdh_priv and peer_ecdh_pub_hex) else ""
            summary = self._transport_summary("tcp-direct", remote_addr) if remote_addr else f"TCP Direct | 🔒 {ecdh_tag}AES-256-GCM"
            log.info(
                f"[{self.node_id}] ✅ Connected: {peer_id} [{summary}] "
                f"(incoming) [{len(self.connections)} active]"
            )
            self._notify_connected(peer_id)
            await self._handle_messages(ews, peer_id)
        except WsConnectionClosed:
            if peer_id:
                log.info(f"[{self.node_id}] 🔌 {peer_id} WebSocket closed")
        except Exception as e:
            if peer_id:
                log.warning(f"[{self.node_id}] ⚠️ Error handling {peer_id} connection: {e}")
        finally:
            if peer_id:
                self._connecting_peers.discard(peer_id)
                # Only remove from connections if WE are still the active handler.
                # During simultaneous-open, tie-breaking may have replaced our ews
                # with a different connection — we must NOT remove that one.
                # ews is None if handshake failed before wrapping.
                if ews is not None and self.connections.get(peer_id) is ews:
                    del self.connections[peer_id]
                    log.info(f"[{self.node_id}] 🔴 {peer_id} disconnected [{len(self.connections)} active]")
                    # 🔔 Desktop notification for peer disconnect
                    if _kn:
                        _kn.get().notify_connect(peer_id, connected=False,
                                                 info=f"Remaining connections: {len(self.connections)}")

    async def _handle_messages(self, ws, peer_id: str):
        # NOTE: Peer's Ed25519 verify key is stored in _peer_verify_keys[peer_id]
        # after the HELLO/WELCOME handshake. Fetch it dynamically in case of reconnect.
        # Start keepalive probe for this peer
        t0 = time.time()
        self._peer_last_recv[peer_id] = t0
        ka_task = self._track_task(self._peer_keepalive(ws, peer_id), name=f"keepalive_{peer_id}")
        self._keepalive_tasks[peer_id] = ka_task
        msg_count = 0
        exit_reason = "unknown"
        try:
            async for raw in ws:
                # Update liveness on every received message (data or pong)
                self._peer_last_recv[peer_id] = time.time()
                msg_count += 1
                try:
                    msg = KiteMessage.from_json(raw)
                    # Verify with peer's Ed25519 public key
                    vk = self._get_verify_key(peer_id)
                    if not vk or not msg.verify(vk, max_age=300.0):
                        log.warning(f"[{self.node_id}] ⚠️ Signature verification failed (peer={peer_id}, type={msg.type}), "
                                    f"possible key mismatch or expired message — dropped")
                        continue
                    await self._dispatch(msg, ws, peer_id)
                except json.JSONDecodeError:
                    log.warning(f"[{self.node_id}] Invalid JSON data received (peer={peer_id}) — dropped")
                except Exception as e:
                    log.error(f"[{self.node_id}] Message dispatch error: {e}")
            exit_reason = "ws_iter_end"  # async for completed normally (peer closed / EOF)
        except WsConnectionClosed as e:
            exit_reason = f"ws_closed(code={e.code}, reason={e.reason!r})"
        except RuntimeError as e:
            # _RendezvousRelayBridge raises RuntimeError("...closed") on close/push(None)
            exit_reason = f"bridge_closed({e})"
        except Exception as e:
            exit_reason = f"exception({type(e).__name__}: {e})"
        finally:
            duration = time.time() - t0
            log.info(f"[{self.node_id}] 📊 _handle_messages exited for {peer_id}: "
                     f"reason={exit_reason}, duration={duration:.1f}s, msgs={msg_count}")
            # Stop keepalive when message loop exits (connection closed).
            # Only clean up if OUR ka_task is still the active one for this peer.
            # During simultaneous-open, a replacement connection may have already
            # started its own keepalive — we must not cancel that one.
            ka_task.cancel()
            if self._keepalive_tasks.get(peer_id) is ka_task:
                self._keepalive_tasks.pop(peer_id, None)
                # Clean up all per-peer keepalive state only if we're the active handler
                self._peer_last_recv.pop(peer_id, None)
                self._peer_rtt.pop(peer_id, None)
                self._peer_ping_sent.pop(peer_id, None)
                self._peer_miss_count.pop(peer_id, None)
                self._peer_ping_seq.pop(peer_id, None)
                self._peer_ka_interval.pop(peer_id, None)

    async def _peer_keepalive(self, ws, peer_id: str):
        """Smart P2P keepalive — inspired by WeChat Mars & QQ practices.

        Key improvements over a naive fixed-interval ping:

        1. **Adaptive interval** (WeChat Mars "smart heartbeat"):
           Starts at 30s, probes upward in 5s steps toward 55s ceiling.
           If a probe fails (miss), back off to last known-good interval.
           This finds the maximum interval that keeps NAT mappings alive,
           minimizing traffic while ensuring liveness.

        2. **Lightweight ping with monotonic seq** (QQ-style):
           Each ping carries an incrementing ``seq`` nonce in the payload
           instead of relying on UUIDs. The pong echoes the same seq,
           enabling precise RTT measurement and duplicate/replay detection.

        3. **RTT measurement** (EWMA smoothed):
           On every pong, compute RTT = now - ping_sent_ts.
           Smoothed via exponential weighted moving average (α=0.3).
           Exposed as ``_peer_rtt[peer_id]`` for quality-of-service decisions
           (e.g., prefer TCP-direct over relay when RTT is lower).

        4. **Consecutive-miss tolerance** (QQ practice):
           Don't kill the connection on a single missed pong — networks
           are bursty. Only declare dead after 3 consecutive misses
           (configurable via ``_P2P_MISS_TOLERANCE``).

        5. **Connection quality emoji** (fun):
           Status log shows signal-bar style quality based on RTT:
           ⚡ <50ms | 🟢 <150ms | 🟡 <300ms | 🔴 ≥300ms
        """
        # NOTE: Messages are signed with our Ed25519 private key (self._signing_key).
        interval = self._peer_ka_interval.get(peer_id, self._P2P_KEEPALIVE_INTERVAL)
        miss_tolerance = self._P2P_MISS_TOLERANCE
        min_iv = self._P2P_KEEPALIVE_MIN
        max_iv = self._P2P_KEEPALIVE_MAX
        step = self._P2P_KEEPALIVE_STEP
        alpha = self._P2P_RTT_ALPHA
        adaptive = self._P2P_ADAPTIVE
        # Track the last-known-good interval for adaptive fallback
        good_interval = interval
        # Track whether we're in "probing up" phase
        probing = False

        self._peer_miss_count[peer_id] = 0
        self._peer_ping_seq[peer_id] = 0

        log.debug(f"[{self.node_id}] 💓 Smart keepalive started for {peer_id} "
                  f"(interval={interval}s, miss_tol={miss_tolerance})")
        try:
            while True:
                await asyncio.sleep(interval)
                now = time.time()
                last = self._peer_last_recv.get(peer_id, 0)
                silence = now - last

                # ── Check if previous ping was answered ──
                ping_sent_at = self._peer_ping_sent.get(peer_id, 0)
                if ping_sent_at > 0 and last < ping_sent_at:
                    # Pong not received since our last ping → miss
                    misses = self._peer_miss_count.get(peer_id, 0) + 1
                    self._peer_miss_count[peer_id] = misses

                    if misses >= miss_tolerance:
                        # ── Dead: N consecutive misses ──
                        log.warning(
                            f"[{self.node_id}] 💀 {peer_id} unresponsive "
                            f"({misses}/{miss_tolerance} misses, silent {int(silence)}s) "
                            f"— closing connection"
                        )
                        try:
                            await ws.close()
                        except Exception:
                            pass
                        return

                    # ── Adaptive: failed probe → shrink interval back ──
                    if adaptive and probing:
                        interval = max(good_interval, min_iv)
                        self._peer_ka_interval[peer_id] = interval
                        probing = False
                        log.debug(f"[{self.node_id}] 💓 {peer_id} probe miss "
                                  f"({misses}/{miss_tolerance}), interval ← {interval}s")
                else:
                    # Pong received → reset miss counter
                    if self._peer_miss_count.get(peer_id, 0) > 0:
                        self._peer_miss_count[peer_id] = 0

                    # ── Adaptive: success → try probing a longer interval ──
                    if adaptive and not probing and interval < max_iv:
                        probing = True
                        good_interval = interval
                        interval = min(interval + step, max_iv)
                        self._peer_ka_interval[peer_id] = interval
                        log.debug(f"[{self.node_id}] 💓 {peer_id} probing ↑ "
                                  f"interval={interval}s (good={good_interval}s)")
                    elif adaptive and probing:
                        # Probe succeeded → this interval is safe
                        good_interval = interval
                        probing = False
                        log.debug(f"[{self.node_id}] 💓 {peer_id} probe OK, "
                                  f"good_interval ← {interval}s")

                # ── Send ping if idle > 80% of interval (save bandwidth if busy) ──
                if silence > interval * 0.8:
                    seq = self._peer_ping_seq.get(peer_id, 0) + 1
                    self._peer_ping_seq[peer_id] = seq
                    # Sign with our Ed25519 private key
                    ping = KiteMessage(
                        type=KITE_PING,
                        from_node=self.node_id,
                        to_node=peer_id,
                        payload={"seq": seq},
                    ).sign(self._signing_key)
                    try:
                        self._peer_ping_sent[peer_id] = time.time()
                        await ws.send(ping.to_json())
                        log.debug(f"[{self.node_id}] 💓 ping #{seq} → {peer_id} "
                                  f"(idle {silence:.0f}s, iv={interval}s)")
                    except Exception as e:
                        log.warning(f"[{self.node_id}] 💀 ping send failed → {peer_id}: "
                                    f"{e} — connection broken")
                        try:
                            await ws.close()
                        except Exception:
                            pass
                        return
        except asyncio.CancelledError:
            log.debug(f"[{self.node_id}] 💓 Smart keepalive stopped for {peer_id}")
            return

    @staticmethod
    def _rtt_quality(rtt_s: float) -> str:
        """Signal-bar style quality emoji based on RTT (fun diagnostic)."""
        ms = rtt_s * 1000
        if ms < 50:
            return "⚡"     # blazing
        elif ms < 150:
            return "🟢"    # good
        elif ms < 300:
            return "🟡"    # ok
        else:
            return "🔴"    # poor

    async def _dispatch(self, msg: KiteMessage, ws, peer_id: str = ""):
        if msg.type == KITE_PING:
            # Echo back the seq nonce for RTT measurement on the sender side
            pong = KiteMessage(type=KITE_PONG, from_node=self.node_id,
                               to_node=msg.from_node, id=msg.id,
                               payload={"seq": msg.payload.get("seq", 0)}).sign(self._signing_key)
            await ws.send(pong.to_json())

        elif msg.type == KITE_PONG:
            # ── RTT measurement + seq validation (WeChat Mars style) ──
            sender = msg.from_node
            pong_seq = msg.payload.get("seq", 0)
            expected_seq = self._peer_ping_seq.get(sender, 0)

            # Security: validate seq nonce — must match our latest ping's seq.
            # This prevents replayed or fabricated pongs from keeping a dead
            # connection artificially alive (anti-spoof).
            if pong_seq != expected_seq:
                log.debug(f"[{self.node_id}] ⚠️ pong seq mismatch from {sender}: "
                          f"got={pong_seq} expected={expected_seq} — ignoring stale pong")
                return  # don't update RTT or liveness for stale pongs

            ping_ts = self._peer_ping_sent.get(sender, 0)
            if ping_ts > 0:
                rtt = time.time() - ping_ts
                prev = self._peer_rtt.get(sender)
                if prev is not None:
                    # EWMA (exponential weighted moving average), α=0.3
                    smoothed = self._P2P_RTT_ALPHA * rtt + (1 - self._P2P_RTT_ALPHA) * prev
                else:
                    smoothed = rtt
                self._peer_rtt[sender] = smoothed
                q = self._rtt_quality(smoothed)
                log.debug(f"[{self.node_id}] {q} pong ← {sender} "
                          f"rtt={rtt*1000:.0f}ms smooth={smoothed*1000:.0f}ms "
                          f"seq={pong_seq}")
            # (liveness already updated in _handle_messages)
            return  # pong fully handled here, no further dispatch

        elif msg.type == KITE_TASK:
            if self._task_handler:
                self._track_task(self._run_task(msg, ws), name=f"run_task_{msg.id[:8]}")
            else:
                err = KiteMessage(type=KITE_ERROR, from_node=self.node_id,
                                  to_node=msg.from_node, id=msg.id,
                                  payload={"error": "no_handler"}).sign(self._signing_key)
                await ws.send(err.to_json())

        elif msg.type in (KITE_RESULT, KITE_ERROR):
            future = self._task_callbacks.pop(msg.id, None)
            if future and not future.done():
                if msg.type == KITE_RESULT:
                    future.set_result(msg.payload.get("result", ""))
                else:
                    # Preserve both error code and detail from remote node
                    err_code = msg.payload.get("error", "unknown")
                    err_detail = msg.payload.get("detail", "")
                    err_msg = f"{err_code}: {err_detail}" if err_detail else err_code
                    future.set_exception(RuntimeError(err_msg))

        elif msg.type == KITE_FORWARD:
            target = msg.payload.get("target")
            # Only allow forwarding to nodes that the sender is also connected to
            if target and target in self.connections and msg.from_node in self.connections:
                await self.connections[target].send(msg.payload.get("data", ""))
            else:
                log.warning(f"[{self.node_id}] Forward denied: {msg.from_node} → {target!r}")

    async def _run_task(self, msg: KiteMessage, ws):
        task_id_short = msg.id[:8]
        task_message = msg.payload.get('message', '')
        log.info(f"[{self.node_id}] 📥 Task received [{task_id_short}] ← {msg.from_node}")
        log.info(f"[{self.node_id}]    📋 {task_message[:120]}")
        t0 = time.time()
        try:
            log.info(f"[{self.node_id}] 🔄 Task [{task_id_short}] executing via handler...")
            result = await self._task_handler(msg.id, task_message, msg.from_node)
            elapsed = time.time() - t0
            log.info(f"[{self.node_id}] ✅ Task completed [{task_id_short}] in {elapsed:.1f}s → {len(result)} chars")
            resp = KiteMessage(type=KITE_RESULT, from_node=self.node_id,
                               to_node=msg.from_node, id=msg.id,
                               payload={"result": result}).sign(self._signing_key)
        except Exception as e:
            elapsed = time.time() - t0
            log.error(f"[{self.node_id}] 💥 Task failed [{task_id_short}] after {elapsed:.1f}s: {e}")
            resp = KiteMessage(type=KITE_ERROR, from_node=self.node_id,
                               to_node=msg.from_node, id=msg.id,
                               payload={"error": "task_execution_failed",
                                        "detail": str(e)[:500]}).sign(self._signing_key)
        try:
            await ws.send(resp.to_json())
            log.info(f"[{self.node_id}] 📤 Task [{task_id_short}] {resp.type} sent back to {msg.from_node}")
        except Exception as e:
            log.error(f"[{self.node_id}] 🔌 Task [{task_id_short}] failed to send {resp.type} "
                      f"back to {msg.from_node}: {e} — connection may be broken")

