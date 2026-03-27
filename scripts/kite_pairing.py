#!/usr/bin/env python3
# Copyright (c) 2026 KiteSurf Contributors — MIT License
# See LICENSE file for details.
"""
kite_pairing.py — KiteSurf client-side pairing via Rendezvous server.
Handles: registration, listing/search, relay registration, and metadata updates.

Invite/accept pairing happens over P2P direct connections, NOT through this module.
This module manages the RDV WebSocket lifecycle, keepalive, and node discovery.
"""

import asyncio
import datetime
import json
import logging
import ssl
import time
from typing import Any, Callable, Dict, List, Optional

from websockets.asyncio.client import connect as ws_connect

from kite_utils import mask_ip as _mask_ip

log = logging.getLogger("kite-pairing")


class KitePairingClient:
    def __init__(
        self,
        node_id: str,                # required: auto-generated machine-unique identifier
        nickname: str = "",
        emoji: str = "🪁",
        tags: Optional[List[str]] = None,
        group: str = "",
        hidden: bool = False,
        rendezvous_url: str = "wss://localhost:17851",
        listen_addr: str = "",      # hint: shared with peer for direct KITP connection
        private_skills: Optional[List[str]] = None,  # disclosed only after pairing
        ssl_verify: bool = True,     # set to False to skip TLS cert verification (self-signed certs)
        allow_insecure: bool = False,  # must be True to allow wss→ws downgrade & auto-disable cert verification
        # ── KiteChain v2 — Blockchain integration (§7, §12.4 of Whitepaper) ──
        chain_enabled: bool = False,             # enable KiteChain blockchain features
        wallet_address: str = "",                # Ed25519 public key hex (chain identity)
        scp_version: str = "scp/1",              # Skill Call Protocol version (§10)
        chain_capabilities: Optional[List[str]] = None,  # chain-callable Skill IDs
    ):
        if not node_id or not node_id.strip():
            raise ValueError("node_id is required and cannot be empty (must be auto-generated)")
        self.node_id = node_id
        self.nickname = nickname
        self.emoji = emoji
        self.tags = tags or []
        self.group = group
        self.hidden = hidden
        self.rendezvous_url = rendezvous_url
        self.listen_addr = listen_addr
        self.private_skills = private_skills or []  # sent during capability handshake
        self._ssl_verify = ssl_verify
        self._ssl_verify_original = ssl_verify  # preserved for restore after session downgrade
        self._ssl_downgraded = False
        self._allow_insecure = allow_insecure
        # ── KiteChain v2 state ──
        self._chain_enabled = chain_enabled
        self._wallet_address = wallet_address
        self._scp_version = scp_version
        self._chain_capabilities = chain_capabilities or []
        # Public address discovered via STUN (set by KiteNode after puncher.setup())
        # Always included in registration messages
        self.public_addr: str = ""
        # Gossip UDP port (set by KiteNode if gossip is enabled)
        self.gossip_port: int = 0

        self._ws = None
        self._peer_token: Optional[str] = None
        self._pending: Dict[str, asyncio.Future[Any]] = {}   # request correlation
        self._capabilities_handler: Optional[Callable[..., Any]] = None
        self._puncher_ref = None    # set by KiteNode to receive punch_start/relay_data
        self._kitp_relay_handler = None  # set by KiteNode to route KITP relay messages
        self._disconnect_callbacks: list[Any] = []  # called when rendezvous ws disconnects
        self._node_joined_handler: Optional[Callable[..., Any]] = None  # called on node_joined push
        self._running = False
        self._request_reconnect = False  # set True to force disconnect & reconnect to new URL
        self._last_pong_at: float = 0.0          # unix timestamp of last pong received
        self._rendezvous_connected: bool = False  # True after successful registration
        self._rendezvous_connected_since: float = 0.0
        self._KEEPALIVE_INTERVAL = 30             # ping interval (seconds)
        self._KEEPALIVE_INTERVAL_ORIGINAL = 30    # preserved for restore when gossip drains
        self._PONG_TIMEOUT = 90                   # 3 consecutive missed pongs → force reconnect

        # ── Consecutive connection failure tracking ──
        # Track reconnect failures. After N failures, fire the
        # fallback callback so KiteNode can handle the situation.
        self._consecutive_connect_failures: int = 0
        self._MAX_CONSECUTIVE_FAILURES: int = 3       # after 3 failures → trigger fallback
        self._fallback_to_central_cb: Optional[Callable] = None  # set by KiteNode

    # ── Decorators ──

    def on_capabilities(self, fn: Callable[..., Any]):
        """async fn(pair_id, peer_node_id, skills: list)
        Triggered when a paired peer discloses its private skills."""
        self._capabilities_handler = fn
        return fn

    # ── Lifecycle ──

    async def connect(self):
        """Connect to Rendezvous, register, and start the listen loop.

        Security policy (controlled by ``allow_insecure``):
        - **allow_insecure=False** (default): SSL errors are logged and retried
          with the *original* URL/settings. No protocol downgrade (wss→ws) occurs,
          and certificate verification is never auto-disabled.
          The user must manually fix the configuration.
        - **allow_insecure=True**: The client may downgrade wss→ws when
          WRONG_VERSION_NUMBER is detected, and may disable certificate
          verification when CERTIFICATE_VERIFY_FAILED is detected.
          A security warning is emitted on every reconnect in degraded mode.
        """
        self._running = True
        url = self.rendezvous_url
        _downgraded = False  # track whether we've fallen back to ws://

        while self._running:
            # ── Hot-switch: detect if rendezvous_url was changed externally ──
            # (e.g. by gossip fallback or /reload API)
            if not _downgraded and self.rendezvous_url != url:
                old_url = url
                url = self.rendezvous_url
                log.info(f"[pairing] 🔄 Rendezvous URL hot-switched: {old_url} → {url}")

            # ── Handle reconnect request (from election callback or fallback) ──
            if self._request_reconnect:
                self._request_reconnect = False
                old_url = url
                url = self.rendezvous_url  # always pick up latest URL
                _downgraded = False         # reset downgrade state for new target
                log.info(f"[pairing] 🔄 Reconnect requested → {old_url} → {url}")

            # ── Persistent security warning while running in degraded mode ──
            if _downgraded or (url.startswith("wss://") and not self._ssl_verify):
                log.warning("[pairing] ⚠️  Running in INSECURE mode (allow_insecure=true), "
                            "data may be eavesdropped or tampered! Configure proper TLS certificates.")

            # Build SSL context for wss:// connections
            ssl_ctx = None
            if url.startswith("wss://"):
                if self._ssl_verify:
                    ssl_ctx = ssl.create_default_context()
                else:
                    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ssl_ctx.check_hostname = False
                    ssl_ctx.verify_mode = ssl.CERT_NONE
                    log.warning("[pairing] TLS certificate verification DISABLED (ssl_verify=False)")

            try:
                connect_kwargs = {}
                if ssl_ctx is not None:
                    connect_kwargs["ssl"] = ssl_ctx
                async with ws_connect(url, **connect_kwargs) as ws:
                    self._ws = ws
                    self._last_pong_at = time.time()  # treat connect as implicit pong
                    # ── Connection succeeded → reset consecutive failure counter ──
                    if self._consecutive_connect_failures > 0:
                        log.info(f"[pairing] ✅ Reconnected after "
                                 f"{self._consecutive_connect_failures} failure(s) — counter reset")
                    self._consecutive_connect_failures = 0
                    if _downgraded:
                        log.info(f"[pairing] ✅ Downgraded to {url} — connected (insecure mode)")
                    asyncio.create_task(self._keepalive())
                    # Run register concurrently with listen loop to avoid deadlock
                    await asyncio.gather(
                        self._register(),
                        self._listen_loop(ws),
                    )
            except ssl.SSLError as e:
                err_str = str(e)
                if "WRONG_VERSION_NUMBER" in err_str or "PROTOCOL_IS_SHUTDOWN" in err_str:
                    if url.startswith("wss://") and self._allow_insecure:
                        # allow_insecure=True → downgrade wss→ws
                        alt_url = "ws://" + url[6:]
                        log.warning(f"[pairing] 🔒 SSL version mismatch — server may not have TLS enabled")
                        log.warning(f"[pairing]    ⚠️  allow_insecure=true → downgrading: {url} → {alt_url}")
                        log.warning(f"[pairing]    🚨 Communication is now plaintext — risk of eavesdropping/tampering!")
                        url = alt_url
                        _downgraded = True
                        await asyncio.sleep(1)
                        continue
                    elif url.startswith("wss://"):
                        # allow_insecure=False → refuse to downgrade
                        log.error(f"[pairing] ❌ SSL version mismatch — server may not have TLS enabled")
                        log.error(f"[pairing]    Refusing to downgrade to ws:// (security policy: allow_insecure=false)")
                        log.error(f"[pairing]    Fix options:")
                        log.error(f"[pairing]      1. Enable TLS on the server")
                        log.error(f"[pairing]      2. Or change rendezvous_url to ws:// (if encryption is not needed)")
                        log.error(f"[pairing]      3. Or set \"allow_insecure\": true in config (not recommended)")
                    else:
                        log.error(f"[pairing] ❌ SSL error: {e}")
                elif "CERTIFICATE_VERIFY_FAILED" in err_str:
                    if self._ssl_verify and self._allow_insecure:
                        # allow_insecure=True → disable cert verify and retry (session-only)
                        log.warning(f"[pairing] 🔒 Certificate verification failed — allow_insecure=true → disabling verification for this session")
                        log.warning(f"[pairing]    🚨 Without cert verification, MITM attacks cannot be prevented!")
                        self._ssl_verify = False
                        self._ssl_downgraded = True  # track that we downgraded for this session
                        await asyncio.sleep(1)
                        continue
                    elif self._ssl_verify:
                        # allow_insecure=False → refuse to disable cert verify
                        log.error(f"[pairing] ❌ Certificate verification failed — refusing to disable (security policy: allow_insecure=false)")
                        log.error(f"[pairing]    Fix options:")
                        log.error(f"[pairing]      1. Use a valid TLS certificate (Let's Encrypt recommended)")
                        log.error(f"[pairing]      2. Or set \"ssl_verify\": false (for self-signed certs)")
                        log.error(f"[pairing]      3. Or set \"allow_insecure\": true (not recommended)")
                    else:
                        log.error(f"[pairing] ❌ SSL cert verification failed (already disabled): {e}")
                else:
                    log.error(f"[pairing] ❌ SSL error: {e}")
                self._ws = None
                self._peer_token = None
                self._rendezvous_connected = False
                self._fire_disconnect()
                if await self._check_leader_fallback(url):
                    continue  # fallback triggered → reconnect to central immediately
                await asyncio.sleep(5)
            except ConnectionRefusedError:
                log.warning(f"[pairing] 🌊 Rendezvous connection refused ({url}). Retrying in 5s...")
                self._ws = None
                self._peer_token = None
                self._rendezvous_connected = False
                self._fire_disconnect()
                if await self._check_leader_fallback(url):
                    continue  # fallback triggered → reconnect to central immediately
                await asyncio.sleep(5)
            except Exception as e:
                err_str = str(e)
                # Some SSL errors come wrapped in other exceptions
                if "WRONG_VERSION_NUMBER" in err_str and url.startswith("wss://"):
                    if self._allow_insecure:
                        alt_url = "ws://" + url[6:]
                        log.warning(f"[pairing] 🔒 SSL version mismatch (wrapped) — allow_insecure=true → downgrading: {url} → {alt_url}")
                        log.warning(f"[pairing]    🚨 Communication is now plaintext — risk of eavesdropping/tampering!")
                        url = alt_url
                        _downgraded = True
                        await asyncio.sleep(1)
                        continue
                    else:
                        log.error(f"[pairing] ❌ SSL version mismatch — refusing to downgrade (allow_insecure=false)")
                        log.error(f"[pairing]    Check rendezvous_url protocol or set \"allow_insecure\": true")
                log.warning(f"[pairing] 🌊 Disconnected from Rendezvous: {e}. Reconnecting in 5s...")
                self._ws = None
                self._peer_token = None
                self._rendezvous_connected = False
                self._fire_disconnect()
                if await self._check_leader_fallback(url):
                    continue  # fallback triggered → reconnect to central immediately
                await asyncio.sleep(5)

    async def disconnect(self):
        self._running = False
        self._rendezvous_connected = False
        self._fire_disconnect()
        if self._ws:
            try:
                await self._send({"type": "unregister"})
            except Exception:
                pass
            try:
                await self._ws.close()
            except Exception:
                pass

    async def request_reconnect(self):
        """Force disconnect and reconnect to the current rendezvous_url.

        Called by KiteNode when the election engine switches RDV URL.
        The connect() loop will pick up the new self.rendezvous_url on next iteration.
        """
        self._request_reconnect = True
        ws = self._ws
        if ws:
            log.info(f"[pairing] 🔌 Closing current Rendezvous connection for hot-switch...")
            try:
                await ws.close()
            except Exception:
                pass

    def on_disconnect(self, callback):
        """Register a callback to be called when Rendezvous connection drops.

        The callback receives no arguments. Used by KiteNode to close
        relay bridges whose underlying transport just vanished.
        """
        self._disconnect_callbacks.append(callback)

    def set_fallback_callback(self, callback: Optional[Callable]):
        """Set callback for automatic fallback when connection fails repeatedly.

        The callback is an async function called when consecutive reconnect
        failures exceed the threshold, indicating the current Rendezvous
        target is likely down.
        """
        self._fallback_to_central_cb = callback

    def reset_failure_counter(self):
        """Reset the consecutive failure counter.

        Called by KiteNode when the rendezvous URL is intentionally changed
        (e.g., following a new leader or falling back to central). This ensures
        the counter starts fresh for the new target.
        """
        self._consecutive_connect_failures = 0
        # Restore SSL verification if it was downgraded for a previous session
        if self._ssl_downgraded:
            self._ssl_verify = self._ssl_verify_original
            self._ssl_downgraded = False
            log.info("[pairing] 🔒 SSL verification restored after session reset")

    async def _check_leader_fallback(self, current_url: str) -> bool:
        """Track consecutive connection failures and trigger fallback if threshold reached.

        This method implements two scenarios:
          - Scenario A (first connect): URL was just switched to leader, never connected.
            Failures accumulate until threshold → fallback.
          - Scenario B (reconnect after drop): Was connected, then lost connection.
            Failures accumulate from the disconnect point → fallback.

        In both cases, the counter is reset to 0 on successful connection
        (handled in the connect() try block above).

        Returns:
            True if fallback was triggered (caller should skip sleep and reconnect
            immediately to central), False otherwise.
        """
        self._consecutive_connect_failures += 1
        count = self._consecutive_connect_failures
        limit = self._MAX_CONSECUTIVE_FAILURES

        log.info(f"[pairing] 📊 Consecutive connect failure #{count}/{limit} "
                 f"(url={current_url})")

        if count >= limit and self._fallback_to_central_cb:
            log.warning(f"[pairing] ⚠️  {count} consecutive failures — "
                        f"triggering fallback to central Rendezvous")
            self._consecutive_connect_failures = 0  # reset to avoid re-triggering
            try:
                await self._fallback_to_central_cb()
                return True
            except Exception as e:
                log.error(f"[pairing] Fallback callback error: {e}")
        return False

    def _fire_disconnect(self):
        """Notify all registered disconnect callbacks."""
        for cb in self._disconnect_callbacks:
            try:
                cb()
            except Exception as e:
                log.warning(f"[pairing] disconnect callback error: {e}")

    def adjust_keepalive(self, interval: int, pong_timeout: Optional[int] = None):
        """Dynamically adjust the Rendezvous keepalive interval.

        Called by KiteNode when gossip health changes:
          - Gossip healthy (has members): increase interval to 120s (reduce RDV load)
          - Gossip empty: restore to original 30s (need RDV for re-seeding)

        Args:
            interval: new ping interval in seconds.
            pong_timeout: new pong timeout in seconds (auto-calculated as 3×interval if None).
        """
        if self._KEEPALIVE_INTERVAL == interval:
            return  # already at requested interval — skip redundant log
        old_iv = self._KEEPALIVE_INTERVAL
        self._KEEPALIVE_INTERVAL = interval
        if pong_timeout is not None:
            self._PONG_TIMEOUT = pong_timeout
        else:
            self._PONG_TIMEOUT = interval * 3
        log.info(f"[pairing] ⏱️ Keepalive interval adjusted: {old_iv}s → {interval}s "
                 f"(pong_timeout={self._PONG_TIMEOUT}s)")

    def restore_keepalive(self):
        """Restore the original keepalive interval (30s).

        Called when gossip member table empties and RDV becomes the primary
        discovery mechanism again.
        """
        self.adjust_keepalive(
            self._KEEPALIVE_INTERVAL_ORIGINAL,
            self._KEEPALIVE_INTERVAL_ORIGINAL * 3,
        )

    def rendezvous_health(self) -> Dict[str, Any]:
        """Return Rendezvous connection health info (for Admin API / monitoring).

        Returns a dict with:
          connected (bool): True if registered and ws alive
          connected_since (str|None): ISO timestamp of successful registration
          last_pong_seconds_ago (float|None): seconds since last pong (None if never)
          ws_open (bool): whether the underlying WebSocket is open
        """
        now = time.time()
        ws_open = self._ws is not None and not getattr(self._ws, 'close_code', None)
        connected = self._rendezvous_connected and ws_open
        return {
            "connected": connected,
            "connected_since": (
                datetime.datetime.fromtimestamp(self._rendezvous_connected_since)
                .strftime("%Y-%m-%d %H:%M:%S")
                if self._rendezvous_connected_since > 0 else None
            ),
            "last_pong_seconds_ago": (
                round(now - self._last_pong_at) if self._last_pong_at > 0 else None
            ),
            "ws_open": ws_open,
        }

    # ── Public API ──

    async def list_nodes(
        self,
        tags: Optional[List[str]] = None,
        q: str = "",
    ) -> List[Dict[str, Any]]:
        """List online nodes. Filter by tags (OR) or free text search."""
        fut = self._make_future("listed")
        await self._send({
            "type": "list",
            "tags": tags or [],
            "q": q,
        })
        resp = await asyncio.wait_for(fut, timeout=10)
        return resp.get("nodes", [])

    async def update_metadata(self, metadata: Dict[str, str]):
        """Update this node's metadata on the Rendezvous server.

        Used for arbitrary key-value metadata updates (e.g. leader election announce).
        Other nodes will see this metadata in list_nodes results.

        Args:
            metadata: key-value pairs to merge into the node's metadata.
        """
        fut = self._make_future("metadata_updated")
        await self._send({
            "type": "update_metadata",
            "metadata": metadata,
        })
        await asyncio.wait_for(fut, timeout=10)
        log.info(f"[pairing] 📝 Metadata updated on Rendezvous: {list(metadata.keys())}")

    async def update_public_addr(self, public_addr: str):
        """Push STUN-discovered public address to the Rendezvous server.

        Called after STUN discovery completes (which happens after initial
        registration, so public_addr is empty at register time). This ensures
        other nodes can see our public address in list_nodes results for
        TCP WAN direct connect and UDP hole punch coordination.

        Args:
            public_addr: STUN-discovered public address in "ip:port" format.
        """
        if not public_addr:
            return
        self.public_addr = public_addr
        if not self._ws or not self._rendezvous_connected:
            return  # not connected, will be included in next registration
        try:
            fut = self._make_future("public_addr_updated")
            await self._send({
                "type": "update_public_addr",
                "public_addr": public_addr,
            })
            await asyncio.wait_for(fut, timeout=10)
            log.info(f"[pairing] 🌐 Public address updated on Rendezvous: {_mask_ip(public_addr)}")
        except Exception as e:
            # Non-fatal: older RDV servers may not support this message.
            # The address is still stored locally and will be included in
            # the next registration (on reconnect).
            log.debug(f"[pairing] update_public_addr failed (server may be older): {e}")

    async def register_relay(self, pair_id: str, peer_node_id: str):
        """Register a relay pair with the Rendezvous server.

        Called after P2P connection is established to set up a fallback relay path.
        Both sides of a pair should call this so the RDV knows about the pair.

        Args:
            pair_id: unique identifier for this peer pair
            peer_node_id: the node_id of the other peer
        """
        fut = self._make_future("relay_registered")
        await self._send({
            "type": "register_relay",
            "pair_id": pair_id,
            "peer_node_id": peer_node_id,
        })
        resp = await asyncio.wait_for(fut, timeout=10)
        log.info(f"[pairing] 📡 Relay pair registered: pair_id={pair_id[:8]} "
                 f"peer={peer_node_id}")
        return resp

    async def relay(self, pair_id: str, data: str, kind: str = ""):
        """Send data through the Rendezvous relay (fallback when P2P fails).

        Args:
            pair_id: the relay pair ID
            data: payload to relay (string or base64-encoded)
            kind: optional message kind tag (e.g. "kitp" for KITP relay)
        """
        msg = {
            "type": "relay",
            "pair_id": pair_id,
            "data": data,
        }
        if kind:
            msg["kind"] = kind
        await self._send(msg)

    async def disclose_capabilities(self, pair_id: str):
        """Send private skills to a paired peer over rendezvous relay."""
        if not self.private_skills:
            return
        await self.relay(
            pair_id,
            json.dumps({
                "kind": "capabilities",
                "node_id": self.node_id,
                "skills": self.private_skills,
            }),
        )

    # ── Internals ──

    async def _register(self):
        fut = self._make_future("registered")
        reg_msg = {
            "type": "register",
            "node_id": self.node_id,
            "nickname": self.nickname,
            "emoji": self.emoji,
            "tags": self.tags,
            "group": self.group,
            "hidden": self.hidden,
            "version": "kitp/1",
            "addr_hint": self.listen_addr,
        }
        # Include STUN-discovered public address for P2P direct connect
        if self.public_addr:
            reg_msg["public_addr"] = self.public_addr
        # Include gossip port so peers can resolve correct UDP target
        if self.gossip_port:
            reg_msg["gossip_port"] = self.gossip_port
        # ── KiteChain v2 — include chain profile if enabled ──
        if self._chain_enabled:
            reg_msg["chain_enabled"] = True
            reg_msg["wallet_address"] = self._wallet_address
            reg_msg["scp_version"] = self._scp_version
            if self._chain_capabilities:
                reg_msg["chain_capabilities"] = self._chain_capabilities
        await self._send(reg_msg)
        resp = await asyncio.wait_for(fut, timeout=10)
        self._peer_token = resp.get("peer_token")
        self._rendezvous_connected = True
        self._rendezvous_connected_since = time.time()
        self._last_pong_at = time.time()  # registration reply counts as liveness proof
        display_name = f"{self.nickname}  ({self.node_id})" if self.nickname else self.node_id
        group_str = f"📦 {self.group}" if self.group and self.group != "*" else "🌐 default"
        log.info(f"[pairing] 🏄 Joined Rendezvous: {self.emoji} {display_name} [{group_str}]")
        log.info(f"[pairing] 📡 Connected to: {_mask_ip(self.rendezvous_url)} "
                 f"(token={self._peer_token[:8] if self._peer_token else '?'})")

    async def _listen_loop(self, ws):
        async for raw in ws:
            try:
                msg = json.loads(raw)
                await self._on_message(msg)
            except json.JSONDecodeError:
                log.warning(f"[pairing] Invalid JSON data received — ignored")
            except Exception as e:
                log.error(f"[pairing] Message handling error: {e}")

    async def _on_message(self, msg: Dict[str, Any]):
        t = msg.get("type")

        # Resolve pending futures
        if t in self._pending:
            fut = self._pending.pop(t)
            if not fut.done():
                fut.set_result(msg)
            return

        # Push events
        if t == "relay_data":
            pair_id = msg.get("pair_id", "")
            raw_data = msg.get("data", "")
            msg_kind = msg.get("kind", "")

            # Route KITP messages to _RendezvousRelayBridge (if registered by KiteNode)
            if msg_kind == "kitp" and hasattr(self, '_kitp_relay_handler') and self._kitp_relay_handler:
                self._kitp_relay_handler(pair_id, raw_data)
                return

            # Try puncher first (hole punch relay fallback)
            if self._puncher_ref:
                self._puncher_ref.on_rendezvous_message(msg)
            # Also check if it's a capabilities disclosure
            try:
                inner = json.loads(raw_data)
                if inner.get("kind") == "capabilities" and self._capabilities_handler:
                    asyncio.create_task(self._capabilities_handler(
                        pair_id,
                        inner.get("node_id", ""),
                        inner.get("skills", []),
                    ))
            except Exception:
                pass  # not JSON or not capabilities — handled by puncher above

        elif t == "pong":
            self._last_pong_at = time.time()  # liveness proof from Rendezvous

        elif t == "error":
            reason = msg.get("reason", "unknown")
            if reason == "unknown_type":
                # RDV server doesn't recognise a message we sent (e.g. punch_ready
                # on an older server).  This is harmless — the caller has its own
                # timeout fallback.  Log at debug to avoid noise.
                log.debug(f"[pairing] Rendezvous: unknown_type (server may be older version)")
            else:
                log.warning(f"[pairing] Rendezvous returned error: {reason}")

        elif t == "node_joined":
            # A new node registered on the same group — trigger instant discovery
            joined_id = msg.get("node_id", "")
            joined_group = msg.get("group", "")
            log.info(f"[pairing] 📢 Peer joined: {joined_id} (group={joined_group})")
            if self._node_joined_handler:
                try:
                    asyncio.create_task(self._node_joined_handler(joined_id, joined_group))
                except Exception as e:
                    log.debug(f"[pairing] node_joined handler error: {e}")

        elif t == "punch_start":
            # Route punch_start from RDV to the puncher (contains peer's public_addr)
            if self._puncher_ref:
                self._puncher_ref.on_rendezvous_message(msg)

    async def _keepalive(self):
        """Send periodic pings and verify pong replies.

        If no pong is received within ``_PONG_TIMEOUT`` seconds (default 90s,
        i.e. 3 consecutive 30s intervals without a pong), the connection is
        considered dead and forcibly closed so the outer ``connect()`` loop
        triggers a reconnect. This prevents the zombie state where the process
        is alive but Rendezvous has been lost.
        """
        while self._running and self._ws:
            await asyncio.sleep(self._KEEPALIVE_INTERVAL)
            # Check if the last pong is too old
            silence = time.time() - self._last_pong_at
            if silence > self._PONG_TIMEOUT:
                log.warning(
                    f"[pairing] 💀 Rendezvous unresponsive for {int(silence)}s "
                    f"(>{self._PONG_TIMEOUT}s) — declaring lost, forcing reconnect"
                )
                self._rendezvous_connected = False
                self._fire_disconnect()
                try:
                    await self._ws.close()
                except Exception:
                    pass
                break
            try:
                await self._send({"type": "ping"})
            except Exception:
                break

    async def _send(self, data: Dict[str, Any]):
        ws = self._ws
        if ws:
            await ws.send(json.dumps(data))
        else:
            raise ConnectionError("Rendezvous WebSocket not connected")

    def _make_future(self, response_type: str) -> asyncio.Future[Any]:
        fut = asyncio.get_running_loop().create_future()
        self._pending[response_type] = fut
        return fut
