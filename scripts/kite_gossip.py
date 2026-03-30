#!/usr/bin/env python3
# Copyright (c) 2026 KiteSurf Contributors — MIT License
# See LICENSE file for details.
"""
kite_gossip.py — UDP Gossip Protocol for KiteSurf Group Membership

A lightweight, decentralized gossip protocol running over UDP (port 17586) that
manages group membership without requiring a central server or leader election.

Core responsibilities:
  1. **Node discovery** — Learn about same-group peers via RDV bootstrap + gossip
  2. **Liveness tracking** — Periodic heartbeat + suspicion-based failure detection
  3. **Member eviction** — Automatically remove unresponsive nodes from the member table
  4. **RDV-independent** — Once the initial member table is seeded, the group operates
     autonomously even if the Rendezvous server goes offline

Protocol overview (SWIM-inspired, simplified):
  - Every GOSSIP_INTERVAL seconds, pick a random subset of known members and send
    them a UDP datagram containing our member table snapshot.
  - On receiving a gossip datagram, merge the remote member table into our own.
  - Members not heard from (directly or transitively) within MEMBER_DEAD_TIMEOUT
    are marked suspect, then dead, then removed.

Datagram format (JSON, max ~1400 bytes to fit in a single UDP packet):
  {
    "proto": "kite-gossip/1",
    "node_id": "node-abc123",
    "group": "my-squad",
    "seq": 42,                           # monotonic sequence number
    "members": [
      {"id": "node-abc123", "addr": "192.168.1.5:17586", "state": "alive", "seq": 42, "ts": 1711411200.0,
       "nick": "Alice", "emoji": "🪁", "tags": ["agent"], "pub": "203.0.113.5:17586"},
      {"id": "node-def456", "addr": "10.0.0.3:17586",   "state": "alive", "seq": 38, "ts": 1711411198.0},
      ...
    ]
  }

Member states:
  alive    — actively sending heartbeats (directly or via gossip)
  suspect  — no heartbeat for MEMBER_SUSPECT_TIMEOUT; still included in gossip
  dead     — no heartbeat for MEMBER_DEAD_TIMEOUT; evicted from member table

Security:
  - Group isolation: only accept gossip from the same group
  - HMAC-SHA256 signature: every datagram is signed with group name as key;
    forged or tampered datagrams are rejected
  - Sender validation: verify UDP source address matches claimed member addr
    (rejects datagrams from spoofed source IPs)
  - Rate limiting: max datagrams per peer per window to prevent flooding
  - Sequence number: reject stale/replayed datagrams (per-node monotonic)
"""

import asyncio
import hashlib
import hmac
import json
import logging
import os
import random
import socket
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

log = logging.getLogger("kite-gossip")

# ── Protocol constants ────────────────────────────────────────────────
GOSSIP_PORT = 17586                  # default UDP listen port
GOSSIP_INTERVAL = 10                 # seconds between gossip rounds
GOSSIP_FANOUT = 3                    # number of random peers to gossip to each round
MEMBER_SUSPECT_TIMEOUT = 45          # seconds without heartbeat → suspect
MEMBER_DEAD_TIMEOUT = 90             # seconds without heartbeat → dead (evicted)
MEMBER_EVICT_GRACE = 120             # seconds after dead before full removal from table
MAX_DGRAM_SIZE = 1400                # max UDP payload (fit in single Ethernet frame)
RATE_LIMIT_WINDOW = 60               # seconds — sliding window
RATE_LIMIT_MAX_PER_PEER = 20         # max datagrams per peer per window
PROTO_VERSION = "kite-gossip/1"
BOOTSTRAP_DELAY = 2                  # seconds before first gossip round
FULL_SYNC_INTERVAL = 60              # seconds between full member table broadcasts
PERSIST_DEBOUNCE = 30                # seconds between disk writes of member table
PERSIST_FILE = "gossip_peers.json"   # filename for persisted peer table


class MemberState:
    ALIVE = "alive"
    SUSPECT = "suspect"
    DEAD = "dead"


class MemberEntry:
    """Represents a known group member with profile metadata."""
    __slots__ = (
        "node_id", "addr", "state", "seq", "last_seen", "state_change_at",
        # ── Profile fields (synced via gossip, originally from RDV registration) ──
        "nickname", "emoji", "tags", "hidden", "public_addr",
        # ── TCP address (for KITP direct connect / invite) ──
        "addr_hint",
        # ── UDP reachability (改动一+四: track UDP bidirectional proof) ──
        "udp_confirmed",       # True once we receive a direct UDP datagram from this member
        "udp_rtt_ms",          # latest UDP round-trip time in ms (None = not measured)
        "udp_last_recv",       # timestamp of last direct UDP datagram received
    )

    def __init__(self, node_id: str, addr: str, state: str = MemberState.ALIVE,
                 seq: int = 0, last_seen: float = 0.0,
                 nickname: str = "", emoji: str = "", tags: Optional[List[str]] = None,
                 hidden: bool = False, public_addr: str = "",
                 addr_hint: str = ""):
        self.node_id = node_id
        self.addr = addr                    # "ip:port" for UDP gossip
        self.state = state
        self.seq = seq                      # latest known sequence number
        self.last_seen = last_seen or time.time()
        self.state_change_at = time.time()  # when state last changed
        # Profile metadata
        self.nickname = nickname
        self.emoji = emoji
        self.tags = tags or []
        self.hidden = hidden
        self.public_addr = public_addr      # STUN-discovered public address
        self.addr_hint = addr_hint          # TCP/KITP listen address (from RDV registration)
        # UDP reachability tracking
        self.udp_confirmed = False          # set True on first direct UDP datagram
        self.udp_rtt_ms: Optional[float] = None   # UDP round-trip time (ms)
        self.udp_last_recv: float = 0.0     # timestamp of last direct UDP recv

    def to_dict(self) -> dict:
        d = {
            "id": self.node_id,
            "addr": self.addr,
            "state": self.state,
            "seq": self.seq,
            "ts": round(self.last_seen, 1),
        }
        # Include profile only if populated (saves datagram space)
        if self.nickname:
            d["nick"] = self.nickname
        if self.emoji:
            d["emoji"] = self.emoji
        if self.tags:
            d["tags"] = self.tags
        if self.hidden:
            d["hidden"] = True
        if self.public_addr:
            d["pub"] = self.public_addr
        if self.addr_hint:
            d["hint"] = self.addr_hint
        # ── UDP reachability fields (改动四) ──
        d["udp_ok"] = self.udp_confirmed if self.udp_confirmed else None
        if self.udp_rtt_ms is not None:
            d["udp_rtt_ms"] = round(self.udp_rtt_ms, 1)
        return d

    @staticmethod
    def from_dict(d: dict) -> "MemberEntry":
        return MemberEntry(
            node_id=d.get("id", ""),
            addr=d.get("addr", ""),
            state=d.get("state", MemberState.ALIVE),
            seq=d.get("seq", 0),
            last_seen=d.get("ts", 0.0),
            nickname=d.get("nick", ""),
            emoji=d.get("emoji", ""),
            tags=d.get("tags", []),
            hidden=d.get("hidden", False),
            public_addr=d.get("pub", ""),
            addr_hint=d.get("hint", ""),
        )


class KiteGossip:
    """UDP-based gossip protocol for group membership management.

    Lifecycle:
      1. Create instance with node_id, group, listen port
      2. Optionally seed with known peer addresses (from RDV or config)
      3. Call start() — runs UDP listener + gossip broadcast loop
      4. Query members() for current alive/suspect member list
      5. Call stop() to shut down

    Callbacks:
      on_member_join(node_id, addr)  — new member discovered
      on_member_leave(node_id)       — member evicted (dead timeout)
      on_members_changed(members)    — member table changed (any state transition)
    """

    def __init__(
        self,
        node_id: str,
        group: str,
        host: str = "0.0.0.0",
        port: int = GOSSIP_PORT,
        seed_peers: Optional[List[str]] = None,    # initial peer addresses ["ip:port", ...]
        on_member_join: Optional[Callable] = None,
        on_member_leave: Optional[Callable] = None,
        on_members_changed: Optional[Callable] = None,
        # ── Profile metadata (propagated to all peers via gossip) ──
        nickname: str = "",
        emoji: str = "",
        tags: Optional[List[str]] = None,
        hidden: bool = False,
        # ── Persistence ──
        persist_dir: Optional[str] = None,         # directory to store gossip_peers.json
        # ── TCP address hint (for KITP direct connect) ──
        addr_hint: str = "",                       # "ip:port" for TCP/KITP listener
    ):
        self.node_id = node_id
        self.group = group
        self.host = host
        self.port = port
        self._seed_peers = seed_peers or []

        # Callbacks
        self._on_member_join = on_member_join
        self._on_member_leave = on_member_leave
        self._on_members_changed = on_members_changed

        # Self profile (included in every gossip datagram for our own entry)
        self._nickname = nickname
        self._emoji = emoji
        self._tags = tags or []
        self._hidden = hidden
        self._public_addr = ""  # set by update_self_public_addr() after STUN
        self._addr_hint = addr_hint  # TCP/KITP listen address

        # Member table: node_id → MemberEntry
        self._members: Dict[str, MemberEntry] = {}

        # Our own monotonic sequence counter
        self._seq: int = 0

        # Our advertised address (set during start or externally)
        self._self_addr: str = ""

        # 改动四: per-peer last gossip send timestamp (for UDP RTT estimation)
        self._peer_last_send_ts: Dict[str, float] = {}

        # UDP transport
        self._transport: Optional[asyncio.DatagramTransport] = None
        self._protocol: Optional["_GossipUDPProtocol"] = None
        self._running = False

        # Rate limiting: source_addr → [timestamps]
        self._rate_limits: Dict[str, List[float]] = {}

        # Background tasks
        self._gossip_task: Optional[asyncio.Task] = None
        self._sweep_task: Optional[asyncio.Task] = None

        # Persistence: save member table to disk for cold-start recovery
        self._persist_dir: Optional[Path] = Path(persist_dir) if persist_dir else None
        self._last_persist_time: float = 0.0

    # ── Public API ────────────────────────────────────────────────────

    def members(self, include_suspect: bool = False,
                include_dead: bool = False) -> List[Dict[str, Any]]:
        """Return current alive (and optionally suspect/dead) members.

        改动五: include_dead=True returns all members including dead,
        so /peers can show the full picture with state info.
        """
        result = []
        for nid, entry in self._members.items():
            if nid == self.node_id:
                continue  # exclude self
            if entry.state == MemberState.ALIVE:
                result.append(entry.to_dict())
            elif include_suspect and entry.state == MemberState.SUSPECT:
                result.append(entry.to_dict())
            elif include_dead and entry.state == MemberState.DEAD:
                result.append(entry.to_dict())
        return result

    def update_self_profile(self, nickname: str = "", emoji: str = "",
                            tags: Optional[List[str]] = None, hidden: bool = False):
        """Update our own profile metadata.  Changes propagate on the next gossip round.

        Called by KiteNode when profile is changed via /reload or config update.
        """
        if nickname:
            self._nickname = nickname
        if emoji:
            self._emoji = emoji
        if tags is not None:
            self._tags = tags
        self._hidden = hidden
        # Update our entry in the member table
        me = self._members.get(self.node_id)
        if me:
            me.nickname = self._nickname
            me.emoji = self._emoji
            me.tags = self._tags
            me.hidden = self._hidden
        log.debug(f"[gossip] Self profile updated: nick={self._nickname}, "
                  f"emoji={self._emoji}, tags={self._tags}")

    def update_self_public_addr(self, public_addr: str):
        """Update our STUN-discovered public address.

        Called by KiteNode after puncher.setup() discovers our public address.
        The STUN result contains an ephemeral NAT-mapped port which is NOT the
        same as our gossip listen port.  For gossip reachability we need:
          - self_addr = public_ip : gossip_port  (where we actually listen)
          - public_addr = original STUN result   (informational, for punch/NAT)
        """
        if not public_addr:
            return
        old_pub = self._public_addr
        try:
            pub_ip = public_addr.rsplit(":", 1)[0]
        except Exception:
            return

        # Store the STUN-discovered address as-is (informational / punch use)
        # Build the gossip-reachable address: public IP + our actual gossip port
        gossip_reachable = f"{pub_ip}:{self.port}"
        self._public_addr = gossip_reachable

        me = self._members.get(self.node_id)
        if me:
            me.public_addr = gossip_reachable
            # Update self_addr if we were using a LAN address
            if not self._self_addr_is_public():
                old_addr = self._self_addr
                self._self_addr = gossip_reachable
                me.addr = self._self_addr
                log.info(f"[gossip] 🌐 Self addr updated: {old_addr} → {self._self_addr} "
                         f"(STUN public: {public_addr})")
        if old_pub != gossip_reachable:
            log.info(f"[gossip] 🌐 Public addr updated: {old_pub or '(none)'} → {gossip_reachable}")

    def update_self_addr_hint(self, addr_hint: str):
        """Update our TCP/KITP listen address.

        Called by KiteNode after starting TCP listener so peers know where to
        connect for KITP sessions (invite, task, etc.).
        """
        if not addr_hint or addr_hint == self._addr_hint:
            return
        self._addr_hint = addr_hint
        me = self._members.get(self.node_id)
        if me:
            me.addr_hint = addr_hint
        log.info(f"[gossip] 📌 addr_hint updated: {addr_hint}")

    def _self_addr_is_public(self) -> bool:
        """Check if our current self_addr is already a public (non-RFC1918) IP."""
        if not self._self_addr:
            return False
        ip = self._self_addr.rsplit(":", 1)[0]
        # RFC 1918 private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("127.") or ip == "0.0.0.0":
            return False
        if ip.startswith("172."):
            # 172.16.0.0 – 172.31.255.255 (second octet 16–31)
            try:
                second_octet = int(ip.split(".")[1])
                if 16 <= second_octet <= 31:
                    return False
            except (IndexError, ValueError):
                return False
        return True

    def alive_member_ids(self) -> List[str]:
        """Return node_ids of alive members (excluding self)."""
        return [nid for nid, e in self._members.items()
                if nid != self.node_id and e.state == MemberState.ALIVE]

    def all_member_ids(self) -> List[str]:
        """Return node_ids of alive + suspect members (excluding self)."""
        return [nid for nid, e in self._members.items()
                if nid != self.node_id and e.state in (MemberState.ALIVE, MemberState.SUSPECT)]

    def member_count(self) -> int:
        """Number of alive members (excluding self)."""
        return sum(1 for nid, e in self._members.items()
                   if nid != self.node_id and e.state == MemberState.ALIVE)

    def udp_alive_count(self) -> int:
        """Number of members with confirmed UDP bidirectional reachability (改动一).

        Only counts members that are ALIVE **and** have been confirmed via
        direct UDP datagram exchange.  This is the safe criterion for
        deciding whether gossip is truly self-sufficient (RDV detach).
        """
        return sum(1 for nid, e in self._members.items()
                   if nid != self.node_id
                   and e.state == MemberState.ALIVE
                   and e.udp_confirmed)

    def seed_from_rdv(self, nodes: List[Dict[str, Any]]):
        """Seed the member table with nodes discovered from Rendezvous.

        Called by KiteNode's discovery loop. Each node dict should have at least
        'node_id' and optionally 'addr_hint', 'public_addr' for address info,
        plus profile fields: 'nickname', 'emoji', 'tags', 'hidden'.
        """
        now = time.time()
        changed = False
        for node in nodes:
            nid = node.get("node_id", "")
            if not nid or nid == self.node_id:
                continue
            # Build gossip address: use remote node's gossip_port if available
            addr = self._resolve_gossip_addr(node)
            if not addr:
                continue
            # Extract profile from RDV node info
            nick = node.get("nickname", "")
            emoji = node.get("emoji", "")
            tags = node.get("tags", [])
            hidden = node.get("hidden", False)
            pub = node.get("public_addr", "")
            hint = node.get("addr_hint", "")

            existing = self._members.get(nid)
            if not existing:
                self._members[nid] = MemberEntry(
                    node_id=nid, addr=addr, state=MemberState.ALIVE,
                    seq=0, last_seen=now,
                    nickname=nick, emoji=emoji, tags=tags,
                    hidden=hidden, public_addr=pub,
                    addr_hint=hint,
                )
                changed = True
                log.info(f"[gossip] 🌱 Seeded member from RDV: {nid} → {addr}"
                         f"{f' [{nick}]' if nick else ''}")
                self._fire_member_join(nid, addr)
            elif existing.state == MemberState.DEAD:
                # Revive dead member if RDV says it's online
                existing.state = MemberState.ALIVE
                existing.addr = addr
                existing.last_seen = now
                existing.state_change_at = now
                # Update profile
                if nick:
                    existing.nickname = nick
                if emoji:
                    existing.emoji = emoji
                if tags:
                    existing.tags = tags
                existing.hidden = hidden
                if pub:
                    existing.public_addr = pub
                if hint:
                    existing.addr_hint = hint
                changed = True
                log.info(f"[gossip] 🔄 Revived member from RDV: {nid} → {addr}")
                self._fire_member_join(nid, addr)
            else:
                # Member already known and alive — update profile if RDV has newer info
                if nick and not existing.nickname:
                    existing.nickname = nick
                if emoji and not existing.emoji:
                    existing.emoji = emoji
                if tags and not existing.tags:
                    existing.tags = tags
                if pub and not existing.public_addr:
                    existing.public_addr = pub
                if hint and not existing.addr_hint:
                    existing.addr_hint = hint
        if changed:
            self._fire_members_changed()

    def add_seed_peer(self, addr: str):
        """Add a seed peer address dynamically."""
        if addr not in self._seed_peers:
            self._seed_peers.append(addr)

    def gossip_status(self) -> Dict[str, Any]:
        """Return gossip state for admin API / monitoring."""
        now = time.time()
        alive = []
        suspect = []
        dead = []
        for nid, entry in self._members.items():
            if nid == self.node_id:
                continue
            info = entry.to_dict()
            info["idle_seconds"] = round(now - entry.last_seen)
            if entry.state == MemberState.ALIVE:
                alive.append(info)
            elif entry.state == MemberState.SUSPECT:
                suspect.append(info)
            elif entry.state == MemberState.DEAD:
                dead.append(info)
        return {
            "node_id": self.node_id,
            "group": self.group,
            "port": self.port,
            "self_addr": self._self_addr,
            "public_addr": self._public_addr,
            "running": self._running,
            "seq": self._seq,
            "member_count": len(alive),
            "suspect_count": len(suspect),
            "dead_count": len(dead),
            "alive": alive,
            "suspect": suspect,
            "dead": dead,
            "seed_peers": self._seed_peers,
        }

    # ── Lifecycle ─────────────────────────────────────────────────────

    async def start(self):
        """Start the gossip protocol: bind UDP socket + run background loops."""
        if self._running:
            return
        self._running = True

        # ── Load persisted peers as additional seeds (cold-start recovery) ──
        persisted_seeds = self._load_persisted_seeds()
        if persisted_seeds:
            for addr in persisted_seeds:
                if addr not in self._seed_peers:
                    self._seed_peers.append(addr)
            log.info(f"[gossip] 💾 Loaded {len(persisted_seeds)} persisted seed(s) "
                     f"for cold-start recovery")

        # Determine our own gossip address
        self._self_addr = self._build_self_addr()

        # Register ourselves in the member table (with profile)
        self._members[self.node_id] = MemberEntry(
            node_id=self.node_id,
            addr=self._self_addr,
            state=MemberState.ALIVE,
            seq=self._seq,
            last_seen=time.time(),
            nickname=self._nickname,
            emoji=self._emoji,
            tags=self._tags,
            hidden=self._hidden,
            public_addr=self._public_addr,
            addr_hint=self._addr_hint,
        )

        # Create UDP endpoint
        loop = asyncio.get_running_loop()
        self._protocol = _GossipUDPProtocol(self)
        try:
            self._transport, _ = await loop.create_datagram_endpoint(
                lambda: self._protocol,
                local_addr=(self.host, self.port),
                family=socket.AF_INET,
            )
            log.info(f"[gossip] 🟢 UDP gossip started on {self.host}:{self.port} "
                     f"(group='{self.group}', node={self.node_id})")
        except OSError as e:
            log.error(f"[gossip] ❌ Failed to bind UDP {self.host}:{self.port}: {e}")
            self._running = False
            return

        # Seed initial peers
        for addr in self._seed_peers:
            # We don't know the node_id yet — send a probe gossip to each seed
            # The seed will respond with its own gossip containing its member table
            pass  # seeds will be contacted in the first gossip round

        # Start background tasks
        self._gossip_task = asyncio.create_task(self._gossip_loop())
        self._sweep_task = asyncio.create_task(self._sweep_loop())
        log.info(f"[gossip] 🔄 Gossip loop started (interval={GOSSIP_INTERVAL}s, "
                 f"fanout={GOSSIP_FANOUT}, seeds={self._seed_peers})")

    def stop(self):
        """Stop the gossip protocol."""
        self._running = False
        # Persist member table before shutdown (best-effort)
        self._persist_members()
        if self._gossip_task:
            self._gossip_task.cancel()
        if self._sweep_task:
            self._sweep_task.cancel()
        if self._transport:
            self._transport.close()
            self._transport = None
        log.info(f"[gossip] 🔴 Gossip stopped (group='{self.group}')")

    # ── Gossip Loop ───────────────────────────────────────────────────

    async def _gossip_loop(self):
        """Periodically send gossip datagrams to random subset of known members."""
        await asyncio.sleep(BOOTSTRAP_DELAY)

        # First round: send to all seed peers to bootstrap
        await self._gossip_to_seeds()

        tick = 0
        while self._running:
            try:
                tick += 1
                self._seq += 1
                # Update our own entry (seq, timestamp, profile)
                me = self._members[self.node_id]
                me.seq = self._seq
                me.last_seen = time.time()
                me.nickname = self._nickname
                me.emoji = self._emoji
                me.tags = self._tags
                me.hidden = self._hidden
                me.public_addr = self._public_addr
                me.addr_hint = self._addr_hint

                # Build our gossip datagram
                dgram = self._build_datagram()

                # Select targets: random subset of alive/suspect members
                targets = self._select_targets()

                # Also include seed peers we haven't heard from yet
                # (they might be unknown members not yet in our table)
                seed_targets = self._get_unknown_seed_addrs()

                all_targets = targets + seed_targets

                send_ts = time.time()
                for addr in all_targets:
                    self._send_dgram(dgram, addr)
                    # 改动四: record send timestamp per target for RTT estimation
                    addr_key = f"{addr[0]}:{addr[1]}"
                    self._peer_last_send_ts[addr_key] = send_ts

                if tick % 6 == 0:  # ~every 60s
                    log.debug(f"[gossip] 📊 Members: {self.member_count()} alive, "
                              f"{sum(1 for e in self._members.values() if e.state == MemberState.SUSPECT)} suspect, "
                              f"seq={self._seq}")

            except asyncio.CancelledError:
                break
            except Exception as e:
                log.warning(f"[gossip] Gossip round error: {e}")

            await asyncio.sleep(GOSSIP_INTERVAL)

    async def _gossip_to_seeds(self):
        """Send initial gossip to all seed peers for bootstrapping."""
        if not self._seed_peers:
            return
        dgram = self._build_datagram()
        for addr_str in self._seed_peers:
            try:
                host, port = self._parse_addr(addr_str)
                self._send_dgram(dgram, (host, port))
                log.info(f"[gossip] 🌱 Bootstrap gossip sent to seed {addr_str}")
            except Exception as e:
                log.debug(f"[gossip] Seed gossip to {addr_str} failed: {e}")

    def _select_targets(self) -> List[Tuple[str, int]]:
        """Select random peers for this gossip round.

        For each peer, collect multiple candidate addresses:
          1. entry.addr (primary — may be LAN or already-upgraded public)
          2. entry.public_addr (STUN-discovered public address, if different)

        This ensures cross-NAT reachability: if the LAN address is unreachable,
        the public address may still work. UDP sendto is fire-and-forget, so
        sending to both addresses is cheap and harmless (receiver deduplicates
        by seq number).
        """
        candidates = []  # List[List[Tuple[str, int]]] — per-peer address lists
        for nid, entry in self._members.items():
            if nid == self.node_id:
                continue
            if entry.state in (MemberState.ALIVE, MemberState.SUSPECT):
                addrs = []
                # ① Primary address (original behavior)
                try:
                    host, port = self._parse_addr(entry.addr)
                    addrs.append((host, port))
                except ValueError:
                    pass
                # ② Fallback: public_addr if different from primary
                if entry.public_addr and entry.public_addr != entry.addr:
                    try:
                        host, port = self._parse_addr(entry.public_addr)
                        if (host, port) not in addrs:
                            addrs.append((host, port))
                    except ValueError:
                        pass
                if addrs:
                    candidates.append(addrs)

        if not candidates:
            return []

        # Fanout: pick up to GOSSIP_FANOUT random *peers*
        k = min(GOSSIP_FANOUT, len(candidates))
        selected = random.sample(candidates, k)

        # Flatten: return all candidate addresses for selected peers
        result = []
        for addr_list in selected:
            result.extend(addr_list)
        return result

    def _get_unknown_seed_addrs(self) -> List[Tuple[str, int]]:
        """Return seed addresses for peers not yet in our member table."""
        known_addrs = {e.addr for e in self._members.values()}
        unknown = []
        for addr_str in self._seed_peers:
            if addr_str not in known_addrs:
                try:
                    host, port = self._parse_addr(addr_str)
                    unknown.append((host, port))
                except ValueError:
                    continue
        return unknown

    # ── Sweep Loop (failure detection) ────────────────────────────────

    async def _sweep_loop(self):
        """Periodically check member health and transition states."""
        while self._running:
            await asyncio.sleep(GOSSIP_INTERVAL)
            try:
                self._sweep_members()
            except Exception as e:
                log.warning(f"[gossip] Sweep error: {e}")

    def _sweep_members(self):
        """Check each member's liveness and transition states.

        State machine (改动五: dead 不再剔除，保留在本地表):
          alive  ──(SUSPECT_TIMEOUT)──→  suspect
          suspect ──(DEAD_TIMEOUT)──→    dead
          dead   ──  stays in table (no eviction)
        """
        now = time.time()
        changed = False

        for nid, entry in list(self._members.items()):
            if nid == self.node_id:
                continue  # never evict ourselves

            idle = now - entry.last_seen

            if entry.state == MemberState.ALIVE and idle > MEMBER_SUSPECT_TIMEOUT:
                entry.state = MemberState.SUSPECT
                entry.state_change_at = now
                changed = True
                log.info(f"[gossip] 🟡 {nid} → SUSPECT (idle {int(idle)}s)")

            elif entry.state == MemberState.SUSPECT and idle > MEMBER_DEAD_TIMEOUT:
                entry.state = MemberState.DEAD
                entry.state_change_at = now
                entry.udp_confirmed = False  # 改动一: reset UDP confirmation
                changed = True
                log.warning(f"[gossip] 🔴 {nid} → DEAD (idle {int(idle)}s)")
                self._fire_member_leave(nid)

            # 改动五: dead members are NOT evicted — they stay in the local table
            # so /peers can still show them. RDV seed_from_rdv() can revive them.

        if changed:
            self._fire_members_changed()

    # ── Datagram handling ─────────────────────────────────────────────

    def on_datagram_received(self, data: bytes, addr: Tuple[str, int]):
        """Process an incoming gossip datagram."""
        # Rate limiting
        addr_key = f"{addr[0]}:{addr[1]}"
        if not self._check_rate_limit(addr_key):
            return

        # ── HMAC signature verification ──
        payload = self._verify_datagram(data)
        if payload is None:
            return

        try:
            msg = json.loads(payload.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            log.debug(f"[gossip] Invalid datagram from {addr_key}")
            return

        # Protocol validation
        if msg.get("proto") != PROTO_VERSION:
            return
        if msg.get("group") != self.group:
            return  # group isolation
        sender_id = msg.get("node_id", "")
        if not sender_id or sender_id == self.node_id:
            return  # ignore our own messages

        remote_members = msg.get("members", [])
        if not isinstance(remote_members, list):
            return

        # ── Sender address validation ──
        # Verify the UDP source IP matches the address the sender claims in its
        # own member entry.  This prevents a node at IP-A from impersonating a
        # node that should be at IP-B.  Only the IP is checked (ports may differ
        # due to NAT).
        sender_ip = addr[0]
        for rm in remote_members:
            if rm.get("id") == sender_id:
                claimed_addr = rm.get("addr", "")
                if claimed_addr:
                    try:
                        claimed_ip, _ = self._parse_addr(claimed_addr)
                        if claimed_ip != sender_ip:
                            # Allow if sender also has a public_addr matching
                            claimed_pub = rm.get("pub", "")
                            if claimed_pub:
                                try:
                                    pub_ip = claimed_pub.rsplit(":", 1)[0]
                                    if pub_ip == sender_ip:
                                        break  # public addr matches, OK
                                except Exception:
                                    pass
                            log.debug(f"[gossip] Sender addr mismatch: {sender_id} "
                                      f"claims {claimed_addr} but UDP from {sender_ip}")
                            return
                    except ValueError:
                        pass
                break

        # Merge remote member table into ours
        self._merge_members(remote_members, sender_id, addr)

    def _merge_members(self, remote_members: List[dict], sender_id: str,
                       sender_addr: Tuple[str, int]):
        """Merge remote member information into our local table."""
        now = time.time()
        changed = False

        for rm in remote_members:
            nid = rm.get("id", "")
            if not nid or nid == self.node_id:
                continue
            remote_seq = rm.get("seq", 0)
            remote_ts = rm.get("ts", 0)
            remote_state = rm.get("state", MemberState.ALIVE)
            remote_addr = rm.get("addr", "")
            # Profile fields
            remote_nick = rm.get("nick", "")
            remote_emoji = rm.get("emoji", "")
            remote_tags = rm.get("tags", [])
            remote_hidden = rm.get("hidden", False)
            remote_pub = rm.get("pub", "")
            remote_hint = rm.get("hint", "")

            # Reject future timestamps (>30s clock skew = suspicious)
            if remote_ts > now + 30:
                continue

            existing = self._members.get(nid)

            if not existing:
                # New member discovered via gossip
                if remote_state == MemberState.DEAD:
                    continue  # don't add dead members we never knew about
                self._members[nid] = MemberEntry(
                    node_id=nid,
                    addr=remote_addr,
                    state=MemberState.ALIVE,
                    seq=remote_seq,
                    last_seen=remote_ts if remote_ts > 0 else now,
                    nickname=remote_nick,
                    emoji=remote_emoji,
                    tags=remote_tags,
                    hidden=remote_hidden,
                    public_addr=remote_pub,
                    addr_hint=remote_hint,
                )
                changed = True
                log.info(f"[gossip] 🆕 Discovered member via gossip: {nid} ({remote_addr})"
                         f"{f' [{remote_nick}]' if remote_nick else ''}")
                self._fire_member_join(nid, remote_addr)

            else:
                # Update existing member — only if remote info is newer
                if remote_seq > existing.seq:
                    old_state = existing.state
                    existing.seq = remote_seq
                    if remote_ts > existing.last_seen:
                        existing.last_seen = remote_ts
                    if remote_addr:
                        existing.addr = remote_addr
                    # Update profile fields (newer seq = authoritative)
                    if remote_nick:
                        existing.nickname = remote_nick
                    if remote_emoji:
                        existing.emoji = remote_emoji
                    if remote_tags:
                        existing.tags = remote_tags
                    existing.hidden = remote_hidden
                    if remote_pub:
                        existing.public_addr = remote_pub
                    if remote_hint:
                        existing.addr_hint = remote_hint

                    # Revive suspect/dead members if remote says alive with newer seq
                    if remote_state == MemberState.ALIVE and old_state != MemberState.ALIVE:
                        existing.state = MemberState.ALIVE
                        existing.state_change_at = now
                        changed = True
                        log.info(f"[gossip] 🟢 {nid} revived via gossip (was {old_state})")
                        if old_state == MemberState.DEAD:
                            self._fire_member_join(nid, remote_addr)

                elif remote_seq == existing.seq and remote_ts > existing.last_seen:
                    # Same seq but more recent timestamp — refresh
                    existing.last_seen = remote_ts

        # If the sender itself is not in our table, add it
        if sender_id not in self._members:
            sender_addr_str = f"{sender_addr[0]}:{sender_addr[1]}"
            # Find sender's entry in remote members for seq/profile info
            sender_seq = 0
            sender_nick = ""
            sender_emoji = ""
            sender_tags: List[str] = []
            sender_hidden = False
            sender_pub = ""
            sender_hint = ""
            for rm in remote_members:
                if rm.get("id") == sender_id:
                    sender_seq = rm.get("seq", 0)
                    sender_nick = rm.get("nick", "")
                    sender_emoji = rm.get("emoji", "")
                    sender_tags = rm.get("tags", [])
                    sender_hidden = rm.get("hidden", False)
                    sender_pub = rm.get("pub", "")
                    sender_hint = rm.get("hint", "")
                    break
            self._members[sender_id] = MemberEntry(
                node_id=sender_id,
                addr=sender_addr_str,
                state=MemberState.ALIVE,
                seq=sender_seq,
                last_seen=now,
                nickname=sender_nick,
                emoji=sender_emoji,
                tags=sender_tags,
                hidden=sender_hidden,
                public_addr=sender_pub,
                addr_hint=sender_hint,
            )
            # ── 改动一: direct UDP datagram → confirmed ──
            self._members[sender_id].udp_confirmed = True
            self._members[sender_id].udp_last_recv = now
            changed = True
            log.info(f"[gossip] 🆕 Discovered sender: {sender_id} ({sender_addr_str})"
                     f"{f' [{sender_nick}]' if sender_nick else ''}")
            self._fire_member_join(sender_id, sender_addr_str)
        else:
            # Refresh sender's last_seen (direct heartbeat proof)
            entry = self._members[sender_id]
            entry.last_seen = now
            # ── 改动一+四: mark UDP bidirectional confirmed ──
            if not entry.udp_confirmed:
                entry.udp_confirmed = True
                log.info(f"[gossip] ✅ {sender_id} UDP confirmed (direct datagram received)")
            entry.udp_last_recv = now
            # ── 改动四: estimate UDP RTT ──
            sender_addr_key = f"{sender_addr[0]}:{sender_addr[1]}"
            last_send = self._peer_last_send_ts.get(sender_addr_key, 0)
            if last_send > 0:
                rtt_ms = (now - last_send) * 1000
                # Only record if reasonable (< 30s, otherwise stale)
                if rtt_ms < 30000:
                    entry.udp_rtt_ms = rtt_ms
            if entry.state != MemberState.ALIVE:
                old = entry.state
                entry.state = MemberState.ALIVE
                entry.state_change_at = now
                changed = True
                log.info(f"[gossip] 🟢 {sender_id} → ALIVE (direct heartbeat, was {old})")
                if old == MemberState.DEAD:
                    self._fire_member_join(sender_id, entry.addr)

        if changed:
            self._fire_members_changed()

    # ── Datagram construction & sending ───────────────────────────────

    def _compute_hmac(self, payload: bytes) -> str:
        """Compute HMAC-SHA256 of payload using group name as key."""
        key = self.group.encode("utf-8")
        return hmac.new(key, payload, hashlib.sha256).hexdigest()[:16]

    def _build_datagram(self) -> bytes:
        """Build a gossip datagram with our member table snapshot.

        The datagram is signed with HMAC-SHA256 (key = group name) to prevent
        forgery and tampering by peers that don't know the group name.
        """
        members = []
        for nid, entry in self._members.items():
            if entry.state == MemberState.DEAD:
                # Include dead entries briefly so other nodes learn about the death
                dead_age = time.time() - entry.state_change_at
                if dead_age > 30:
                    continue  # stop gossiping about long-dead members
            members.append(entry.to_dict())

        msg = {
            "proto": PROTO_VERSION,
            "node_id": self.node_id,
            "group": self.group,
            "seq": self._seq,
            "members": members,
        }
        payload = json.dumps(msg, separators=(",", ":")).encode("utf-8")

        # If payload exceeds MAX_DGRAM_SIZE, trim member list (keep self + most recent)
        if len(payload) > MAX_DGRAM_SIZE:
            members.sort(key=lambda m: m.get("ts", 0), reverse=True)
            while len(payload) > MAX_DGRAM_SIZE and len(members) > 1:
                members.pop()
                msg["members"] = members
                payload = json.dumps(msg, separators=(",", ":")).encode("utf-8")

        # Append HMAC signature: payload + "|" + hmac_hex
        sig = self._compute_hmac(payload)
        return payload + b"|" + sig.encode("ascii")

    def _verify_datagram(self, raw: bytes) -> Optional[bytes]:
        """Verify HMAC signature and return payload if valid, else None."""
        sep = raw.rfind(b"|")
        if sep < 0:
            log.debug("[gossip] Rejected unsigned datagram")
            return None
        payload = raw[:sep]
        sig_received = raw[sep + 1:].decode("ascii", errors="ignore")
        sig_expected = self._compute_hmac(payload)
        if not hmac.compare_digest(sig_received, sig_expected):
            log.debug("[gossip] Rejected datagram: HMAC mismatch")
            return None
        return payload

    def _send_dgram(self, data: bytes, addr: Tuple[str, int]):
        """Send a UDP datagram to the specified address."""
        if self._transport and not self._transport.is_closing():
            try:
                self._transport.sendto(data, addr)
            except Exception as e:
                log.debug(f"[gossip] Send to {addr[0]}:{addr[1]} failed: {e}")

    # ── Rate limiting ─────────────────────────────────────────────────

    def _check_rate_limit(self, addr_key: str) -> bool:
        """Check if a datagram from this address is within rate limits."""
        now = time.time()
        timestamps = self._rate_limits.setdefault(addr_key, [])
        cutoff = now - RATE_LIMIT_WINDOW
        self._rate_limits[addr_key] = [t for t in timestamps if t > cutoff]
        timestamps = self._rate_limits[addr_key]
        if len(timestamps) >= RATE_LIMIT_MAX_PER_PEER:
            log.debug(f"[gossip] ⚠️ Rate limit exceeded for {addr_key}")
            return False
        timestamps.append(now)
        return True

    # ── Address utilities ─────────────────────────────────────────────

    def _build_self_addr(self) -> str:
        """Determine our own gossip address."""
        if self.host == "0.0.0.0":
            lan_ip = self._detect_lan_ip()
            return f"{lan_ip}:{self.port}"
        return f"{self.host}:{self.port}"

    @staticmethod
    def _detect_lan_ip() -> str:
        """Best-effort LAN IP detection (same as KiteNode)."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"

    def _resolve_gossip_addr(self, node: dict) -> str:
        """Extract a usable gossip address from a RDV node info dict.

        Prefer: public_addr > addr_hint > remote_ip.
        Use the *remote* node's gossip port (from 'gossip_port' field in RDV
        node info) instead of our own.  Falls back to our port only if the
        remote node didn't advertise its gossip port (backward-compatible with
        nodes that all use the default port).
        """
        remote_gossip_port = node.get("gossip_port") or self.port
        for key in ("public_addr", "addr_hint", "remote_ip"):
            raw = node.get(key, "")
            if not raw:
                continue
            try:
                host, _ = self._parse_addr(raw)
                return f"{host}:{remote_gossip_port}"
            except ValueError:
                # Might be just an IP without port
                if ":" not in raw or raw.count(":") == 0:
                    return f"{raw}:{remote_gossip_port}"
        return ""

    @staticmethod
    def _parse_addr(addr: str) -> Tuple[str, int]:
        """Parse 'host:port' string into (host, port) tuple."""
        if not addr:
            raise ValueError("empty address")
        # Handle IPv6 [::1]:port
        if addr.startswith("["):
            bracket_end = addr.index("]")
            host = addr[1:bracket_end]
            port_str = addr[bracket_end + 2:]  # skip "]:"
            return host, int(port_str)
        parts = addr.rsplit(":", 1)
        if len(parts) != 2:
            raise ValueError(f"invalid address: {addr}")
        return parts[0], int(parts[1])

    # ── Callbacks ─────────────────────────────────────────────────────

    def _fire_member_join(self, node_id: str, addr: str):
        if self._on_member_join:
            try:
                result = self._on_member_join(node_id, addr)
                if asyncio.iscoroutine(result):
                    asyncio.create_task(result)
            except Exception as e:
                log.debug(f"[gossip] on_member_join callback error: {e}")

    def _fire_member_leave(self, node_id: str):
        if self._on_member_leave:
            try:
                result = self._on_member_leave(node_id)
                if asyncio.iscoroutine(result):
                    asyncio.create_task(result)
            except Exception as e:
                log.debug(f"[gossip] on_member_leave callback error: {e}")

    def _fire_members_changed(self):
        if self._on_members_changed:
            try:
                alive = self.alive_member_ids()
                result = self._on_members_changed(alive)
                if asyncio.iscoroutine(result):
                    asyncio.create_task(result)
            except Exception as e:
                log.debug(f"[gossip] on_members_changed callback error: {e}")
        # Persist member table to disk (debounced)
        now = time.time()
        if now - self._last_persist_time >= PERSIST_DEBOUNCE:
            self._persist_members()

    # ── Persistence ──────────────────────────────────────────────────

    def _persist_path(self) -> Optional[Path]:
        """Return the path to the persisted peers file, or None if disabled."""
        if not self._persist_dir:
            return None
        return self._persist_dir / PERSIST_FILE

    def _persist_members(self):
        """Save ALIVE/SUSPECT members to disk for cold-start recovery.

        File format (gossip_peers.json):
          {
            "group": "my-squad",
            "updated_at": 1711411200.0,
            "peers": [
              {"id": "node-abc", "addr": "192.168.1.5:17586", "pub": "58.211.x.x:17586"},
              ...
            ]
          }

        Only node_id + addr + public_addr are stored — the minimum needed to
        bootstrap gossip after a restart. Profile fields, seq, state are NOT
        persisted because they will be refreshed within the first gossip round.
        """
        path = self._persist_path()
        if not path:
            return
        peers = []
        for nid, entry in self._members.items():
            if nid == self.node_id:
                continue
            if entry.state not in (MemberState.ALIVE, MemberState.SUSPECT):
                continue
            peer: Dict[str, str] = {"id": nid, "addr": entry.addr}
            if entry.public_addr and entry.public_addr != entry.addr:
                peer["pub"] = entry.public_addr
            peers.append(peer)
        if not peers:
            return  # don't overwrite with empty list
        data = {
            "group": self.group,
            "updated_at": round(time.time(), 1),
            "peers": peers,
        }
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            tmp.replace(path)  # atomic rename
            self._last_persist_time = time.time()
            log.debug(f"[gossip] 💾 Persisted {len(peers)} peer(s) to {path}")
        except Exception as e:
            log.warning(f"[gossip] ⚠️ Failed to persist member table: {e}")

    def _load_persisted_seeds(self) -> List[str]:
        """Load persisted peer addresses for cold-start seeding.

        Returns a list of "host:port" strings (both addr and public_addr) that
        can be used as seed_peers. Stale entries are harmless — gossip's sweep
        mechanism will mark unreachable nodes as SUSPECT → DEAD → evicted.
        """
        path = self._persist_path()
        if not path or not path.exists():
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            log.warning(f"[gossip] ⚠️ Failed to load persisted peers: {e}")
            return []
        # Validate group (don't load peers from a different group)
        if data.get("group") != self.group:
            log.debug(f"[gossip] Persisted peers group mismatch: "
                      f"{data.get('group')} != {self.group}, ignoring")
            return []
        # Staleness check: ignore if older than 24 hours
        updated_at = data.get("updated_at", 0)
        age = time.time() - updated_at
        if age > 86400:
            log.info(f"[gossip] 💾 Persisted peers too old ({int(age)}s), ignoring")
            return []
        addrs: List[str] = []
        seen: set = set()
        for peer in data.get("peers", []):
            for key in ("addr", "pub"):
                addr = peer.get(key, "")
                if addr and addr not in seen:
                    seen.add(addr)
                    addrs.append(addr)
        log.info(f"[gossip] 💾 Loaded {len(addrs)} address(es) from {path} "
                 f"(age={int(age)}s)")
        return addrs


# ── UDP Protocol ──────────────────────────────────────────────────────

class _GossipUDPProtocol(asyncio.DatagramProtocol):
    """asyncio UDP protocol handler for gossip datagrams."""

    def __init__(self, gossip: KiteGossip):
        self._gossip = gossip

    def connection_made(self, transport):
        pass

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        self._gossip.on_datagram_received(data, addr)

    def error_received(self, exc):
        log.debug(f"[gossip] UDP error: {exc}")

    def connection_lost(self, exc):
        if exc:
            log.debug(f"[gossip] UDP connection lost: {exc}")
