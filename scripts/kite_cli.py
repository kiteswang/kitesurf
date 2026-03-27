#!/usr/bin/env python3
# Copyright (c) 2026 KiteSurf Contributors — MIT License
# See LICENSE file for details.
"""
kite_cli.py — KiteSurf CLI tool (zero-intrusion Rendezvous client).
Query nodes, send invites, check status. Run -h for usage.
"""

import argparse
import asyncio
import json
import sys
import time
from urllib.request import urlopen, Request
from urllib.error import URLError

# ── Dependency check (no auto-install) ──
try:
    from websockets.asyncio.client import connect as ws_connect
except ImportError:
    print("[kite-cli] Missing dependency: websockets")
    print("[kite-cli] Please install it manually:")
    print("  pip install websockets")
    sys.exit(1)


# ─────────────────────── WebSocket helpers ───────────────────────────

async def _ws_roundtrip(url: str, node_id: str, request: dict,
                        expect_type: str, timeout: float = 10.0,
                        group: str = "") -> dict:
    """Connect to Rendezvous, register, send one request, return response, disconnect."""
    async with ws_connect(url) as ws:
        # Step 1: Register (must complete before any other operation)
        reg_msg = {
            "type": "register",
            "node_id": node_id,
            "emoji": "🔧",
            "tags": [],
            "group": group,
            "hidden": True,  # Don't show CLI tool in node list
            "version": "kitp/1",
        }
        await ws.send(json.dumps(reg_msg))

        # Wait for registration confirmation
        while True:
            raw = await asyncio.wait_for(ws.recv(), timeout=timeout)
            msg = json.loads(raw)
            if msg.get("type") == "registered":
                break
            if msg.get("type") == "error":
                raise RuntimeError(f"Registration failed: {msg.get('reason')}")

        # Step 2: Send the actual request
        await ws.send(json.dumps(request))

        # Step 3: Wait for expected response
        while True:
            raw = await asyncio.wait_for(ws.recv(), timeout=timeout)
            msg = json.loads(raw)
            if msg.get("type") == expect_type:
                return msg
            if msg.get("type") == "error":
                raise RuntimeError(f"Server error: {msg.get('reason')}")

        # Step 4: Unregister (best effort, connection is about to close)
        await ws.send(json.dumps({"type": "unregister"}))


async def _ws_invite_and_wait(url: str, node_id: str, target: str,
                               message: str, wait_accept: bool,
                               timeout: float = 30.0) -> dict:
    """Connect, register, invite target node, optionally wait for pairing/decline."""
    async with ws_connect(url) as ws:
        # Register (hidden mode)
        reg_msg = {
            "type": "register",
            "node_id": node_id,
            "emoji": "🔧",
            "tags": [],
            "group": "",
            "hidden": True,
            "version": "kitp/1",
        }
        await ws.send(json.dumps(reg_msg))

        # Wait for registration to complete
        while True:
            raw = await asyncio.wait_for(ws.recv(), timeout=10)
            msg = json.loads(raw)
            if msg.get("type") == "registered":
                break
            if msg.get("type") == "error":
                raise RuntimeError(f"Registration failed: {msg.get('reason')}")

        # Send invite
        await ws.send(json.dumps({
            "type": "invite",
            "target_node_id": target,
            "message": message,
        }))

        # Wait for invite sent confirmation
        invite_token = None
        while True:
            raw = await asyncio.wait_for(ws.recv(), timeout=10)
            msg = json.loads(raw)
            if msg.get("type") == "invite_sent":
                invite_token = msg.get("invite_token", "")
                break
            if msg.get("type") == "error":
                raise RuntimeError(f"Invite failed: {msg.get('reason')}")

        result = {"invite_token": invite_token, "status": "sent"}

        if not wait_accept:
            return result

        # Wait for pairing/decline/expiry
        print(f"  ⏳ Waiting for response (timeout={timeout}s)...")
        start = time.time()
        while time.time() - start < timeout:
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=min(5, timeout - (time.time() - start)))
                msg = json.loads(raw)
                if msg.get("type") == "paired":
                    result["status"] = "paired"
                    result["pair_id"] = msg.get("pair_id")
                    result["peer"] = msg.get("peer", {})
                    result["peer_addr"] = msg.get("peer_addr", "")
                    return result
                elif msg.get("type") == "declined":
                    result["status"] = "declined"
                    result["by"] = msg.get("by", {})
                    return result
                elif msg.get("type") == "invite_expired":
                    result["status"] = "expired"
                    return result
            except asyncio.TimeoutError:
                continue

        result["status"] = "timeout"
        return result


# ─────────────────────── HTTP helpers ─────────────────────────────────

def _http_get(url: str) -> dict:
    """Simple HTTP GET → JSON (no external dependencies)."""
    try:
        req = Request(url, method="GET")
        with urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except URLError as e:
        raise RuntimeError(f"HTTP request failed: {e}")


# ─────────────────────── Pretty print ────────────────────────────────

def _print_nodes(nodes: list):
    if not nodes:
        print("  🏖️  Calm waters — no nodes online")
        return
    for i, n in enumerate(nodes, 1):
        emoji = n.get("emoji", "🪁")
        nid = n.get("node_id", "?")
        nick = n.get("nickname", "")
        tags = n.get("tags", [])
        group = n.get("group", "")
        hidden = n.get("hidden", False)
        prefix = "├" if i < len(nodes) else "└"
        branch = "│" if i < len(nodes) else " "
        display_name = f"{nick}  ({nid})" if nick else nid
        print(f"  {prefix}── {emoji} {display_name}" + (" 👻" if hidden else ""))
        if group:
            print(f"  {branch}   📦 Group: {group}")
        if tags:
            print(f"  {branch}   🏷️  {' · '.join(tags)}")


def _print_json(data: dict, indent: int = 2):
    print(json.dumps(data, ensure_ascii=False, indent=indent))


# ─────────────────────── Commands ────────────────────────────────────

async def cmd_nodes(args):
    """List online nodes from Rendezvous."""
    request = {
        "type": "list",
        "tags": args.tags.split(",") if args.tags else [],
        "q": args.query or "",
    }
    group = getattr(args, "group", "") or ""
    resp = await _ws_roundtrip(args.url, args.node_id, request, "listed", group=group)
    nodes = resp.get("nodes", [])
    total = resp.get("total", len(nodes))

    group_label = f"📦 {group}" if group else "🌐 default group"
    print("")
    print("  ╔═══════════════════════════════════════════╗")
    print(f"  ║  {group_label}  ·  {total} online{' ' * max(1, 26 - len(group_label))}║")
    print("  ╚═══════════════════════════════════════════╝")
    print("  │")
    _print_nodes(nodes)
    print("")

    if args.json:
        _print_json(resp)


async def cmd_invite(args):
    """Send an invite to a target node."""
    print(f"\n  🪁 Sending surf invite to {args.target}...")

    result = await _ws_invite_and_wait(
        url=args.url,
        node_id=args.node_id,
        target=args.target,
        message=args.message or "",
        wait_accept=args.wait,
        timeout=args.timeout,
    )

    status = result.get("status")
    if status == "sent":
        print(f"  ✅ Invite sent (token={result['invite_token'][:8]}...)")
        if not args.wait:
            print(f"  💡 Tip: use --wait to wait for the other side's response")
    elif status == "paired":
        peer = result.get("peer", {})
        peer_emoji = peer.get('emoji', '🪁')
        peer_nick = peer.get('nickname', '')
        peer_id = peer.get('node_id', '?')
        peer_name = f"{peer_nick}  ({peer_id})" if peer_nick else peer_id
        print(f"  🤝 Paired successfully! Let's surf together!")
        print(f"     Node: {peer_emoji} {peer_name}")
        print(f"     Pair: {result.get('pair_id', '?')}")
        if result.get("peer_addr"):
            print(f"     Address: {result['peer_addr']}")
    elif status == "declined":
        by = result.get("by", {})
        by_nick = by.get('nickname', '')
        by_id = by.get('node_id', '?')
        by_name = f"{by_nick}  ({by_id})" if by_nick else by_id
        print(f"  😔 {by.get('emoji', '🪁')} {by_name} declined the invite")
    elif status == "expired":
        print(f"  ⏰ Invite expired — the other side may be offline")
    elif status == "timeout":
        print(f"  ⏳ Wait timed out — the other side is still thinking...")

    if args.json:
        _print_json(result)


def cmd_admin(args):
    """Query Rendezvous admin HTTP API."""
    try:
        data = _http_get(args.url)
        print(f"\n  🔧 Rendezvous Admin — {args.url}")
        print("  " + "─" * 50)
        _print_json(data)
    except RuntimeError as e:
        print(f"\n  ❌ {e}")
        print(f"  Please confirm the Rendezvous server is running and the admin port is accessible")
        sys.exit(1)


def cmd_groups(args):
    """Query Rendezvous admin API for group information."""
    base = args.admin_url.rstrip("/")
    try:
        if args.name:
            data = _http_get(f"{base}/groups/{args.name}")
            group_name = data.get("group", args.name)
            members = data.get("nodes", [])
            print(f"\n  📦 Group Details — {group_name} ({data.get('member_count', len(members))} members)")
            print("  " + "─" * 50)
            if members:
                print("  │")
                _print_nodes(members)
            else:
                print("  │  🏖️  No members in this group")
            print("")
        else:
            data = _http_get(f"{base}/groups")
            groups = data.get("groups", [])
            total_groups = data.get("group_count", len(groups))
            print(f"\n  📦 Groups — {total_groups} groups online")
            print("  " + "═" * 50)
            if not groups:
                print("  │  🏖️  No groups")
            for i, g in enumerate(groups, 1):
                g_name = g.get("group", "(default)")
                count = g.get("member_count", 0)
                members = g.get("members", [])
                prefix = "├" if i < len(groups) else "└"
                branch = "│" if i < len(groups) else " "
                print(f"  {prefix}── 📦 {g_name}  ·  {count} members")
                for j, m in enumerate(members):
                    mp = "├" if j < len(members) - 1 else "└"
                    print(f"  {branch}   {mp}── {m}")
            print("")

        if args.json:
            _print_json(data)
    except RuntimeError as e:
        print(f"\n  ❌ {e}")
        print(f"  Please confirm the Rendezvous admin API is accessible (default http://127.0.0.1:17852)")
        sys.exit(1)


def cmd_agent(args):
    """Query Agent admin HTTP API."""
    try:
        data = _http_get(args.url)
        print(f"\n  🪁 Agent Status — {args.url}")
        print("  " + "─" * 50)
        _print_json(data)
    except RuntimeError as e:
        print(f"\n  ❌ {e}")
        print(f"  Please confirm the Agent is running and admin_port is accessible (default http://127.0.0.1:17853)")
        sys.exit(1)


def cmd_gossip(args):
    """Query gossip protocol state from Agent admin API."""
    base = args.admin_url.rstrip("/")
    url = f"{base}/gossip"
    try:
        data = _http_get(url)
    except RuntimeError as e:
        print(f"\n  ❌ {e}")
        print(f"  Please confirm the Agent is running (default http://127.0.0.1:17853)")
        sys.exit(1)

    enabled = data.get("enabled", False)
    print("")
    if not enabled:
        print("  📡 Gossip protocol is not enabled on this node.")
        print("  💡 Set \"gossip.enabled\": true in config to enable.")
        print("")
        if args.json:
            _print_json(data)
        return

    # Pending state: enabled but waiting to start
    if data.get("status") == "starting":
        print("  📡 Gossip protocol is enabled but starting up.")
        print(f"  💡 {data.get('message', 'Gossip protocol initializing...')}")
        print("")
        if args.json:
            _print_json(data)
        return

    group = data.get("group", "")
    seq = data.get("seq", 0)
    member_count = data.get("member_count", 0)
    suspect_count = data.get("suspect_count", 0)
    dead_count = data.get("dead_count", 0)
    self_addr = data.get("self_addr", "")
    public_addr = data.get("public_addr", "")
    port = data.get("port", 17586)
    alive = data.get("alive", [])
    suspect = data.get("suspect", [])
    auto_mesh = data.get("auto_mesh", {})
    discovery_mode = auto_mesh.get("discovery_mode", "?")
    rdv_interval = auto_mesh.get("rdv_interval", "?")
    rdv_keepalive = auto_mesh.get("rdv_keepalive", "?")

    print("  ╔═══════════════════════════════════════════════╗")
    print(f"  ║  📡 Gossip Status  ·  {member_count} member(s) online     ║")
    print("  ╚═══════════════════════════════════════════════╝")
    print(f"  │  📦 Group          : {group or '(default)'}")
    print(f"  │  🔌 UDP Port       : {port}")
    print(f"  │  📍 Self Address   : {self_addr}")
    if public_addr:
        print(f"  │  🌐 Public Address : {public_addr}")
    print(f"  │  🔢 Sequence       : {seq}")
    print(f"  │  🔍 Discovery      : {discovery_mode} (RDV poll {rdv_interval}s, keepalive {rdv_keepalive}s)")
    print(f"  │  🟢 Alive members  : {member_count}")
    if alive:
        for i, m in enumerate(alive):
            prefix = "├" if i < len(alive) - 1 else "└"
            idle = m.get("idle_seconds", 0)
            nick = m.get("nick", "")
            emoji = m.get("emoji", "")
            pub = m.get("pub", "")
            label = f"{emoji} {nick}" if nick else m.get('id', '?')
            addr_info = m.get('addr', '?')
            if pub:
                addr_info += f" (pub: {pub})"
            print(f"  │     {prefix}── {label} ({addr_info}) idle={idle}s")
    if suspect_count > 0:
        print(f"  │  🟡 Suspect        : {suspect_count}")
        for i, m in enumerate(suspect):
            prefix = "├" if i < len(suspect) - 1 else "└"
            idle = m.get("idle_seconds", 0)
            nick = m.get("nick", "")
            label = nick if nick else m.get('id', '?')
            print(f"  │     {prefix}── {label} idle={idle}s")
    if dead_count > 0:
        print(f"  │  🔴 Dead           : {dead_count}")

    print("")

    if args.json:
        _print_json(data)


# ─────────────────────── CLI entry ───────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="KiteSurf CLI — Query Rendezvous and Agent without disturbing running services",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List online nodes
  python kite_cli.py nodes ws://server:17851 --node-id my-kite

  # List nodes in a specific group
  python kite_cli.py nodes ws://server:17851 --node-id my-kite --group my-squad

  # Send an invite and wait for response
  python kite_cli.py invite ws://server:17851 --node-id my-kite --target surfer-B --wait

  # List all groups (via admin API)
  python kite_cli.py groups --admin-url http://127.0.0.1:17852

  # View members of a specific group
  python kite_cli.py groups --admin-url http://127.0.0.1:17852 --name my-squad

  # Query Rendezvous admin
  python kite_cli.py admin http://127.0.0.1:17852/status
  python kite_cli.py admin http://127.0.0.1:17852/nodes?group=my-squad
  python kite_cli.py admin http://127.0.0.1:17852/groups

  # Query Agent admin
  python kite_cli.py agent http://127.0.0.1:17853/status

  # View gossip state
  python kite_cli.py gossip
  python kite_cli.py gossip --admin-url http://127.0.0.1:17853 --json
""",
    )

    sub = parser.add_subparsers(dest="command", help="Available commands")

    # ── nodes ──
    p_nodes = sub.add_parser("nodes", help="List online nodes from Rendezvous")
    p_nodes.add_argument("url", help="Rendezvous WebSocket URL (ws:// or wss://)")
    p_nodes.add_argument("--node-id", required=True, help="Your node ID (for registration)")
    p_nodes.add_argument("--tags", default="", help="Filter by tags (comma-separated)")
    p_nodes.add_argument("--group", default="", help="Group name (only show same-group nodes; empty = smart match)")
    p_nodes.add_argument("--query", "-q", default="", help="Full-text search (node_id + nickname + tags)")
    p_nodes.add_argument("--json", action="store_true", help="Also print raw JSON response")

    # ── invite ──
    p_invite = sub.add_parser("invite", help="Send a pairing invite")
    p_invite.add_argument("url", help="Rendezvous WebSocket URL (ws:// or wss://)")
    p_invite.add_argument("--node-id", required=True, help="Your node ID (for registration)")
    p_invite.add_argument("--target", required=True, help="Target node_id")
    p_invite.add_argument("--message", "-m", default="", help="Invite message")
    p_invite.add_argument("--wait", action="store_true", help="Wait for accept/decline (up to --timeout)")
    p_invite.add_argument("--timeout", type=float, default=30, help="Timeout in seconds for --wait (default 30)")
    p_invite.add_argument("--json", action="store_true", help="Also print raw JSON response")

    # ── groups ──
    p_groups = sub.add_parser("groups", help="List groups or view group details (via admin API)")
    p_groups.add_argument("--admin-url", default="http://127.0.0.1:17852",
                          help="Rendezvous admin base URL (default: http://127.0.0.1:17852)")
    p_groups.add_argument("--name", default="", help="Group name to query (omit to view all groups)")
    p_groups.add_argument("--json", action="store_true", help="Also print raw JSON response")

    # ── admin ──
    p_admin = sub.add_parser("admin", help="Query Rendezvous admin HTTP API")
    p_admin.add_argument("url", help="Admin endpoint URL (e.g. http://127.0.0.1:17852/status)")

    # ── agent ──
    p_agent = sub.add_parser("agent", help="Query Agent admin HTTP API")
    p_agent.add_argument("url", help="Agent admin endpoint URL (e.g. http://127.0.0.1:17853/status)")

    # ── gossip ──
    p_gossip = sub.add_parser("gossip", help="View gossip protocol state")
    p_gossip.add_argument("--admin-url", default="http://127.0.0.1:17853",
                           help="Agent admin base URL (default: http://127.0.0.1:17853)")
    p_gossip.add_argument("--json", action="store_true", help="Also print raw JSON response")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "nodes":
        asyncio.run(cmd_nodes(args))
    elif args.command == "invite":
        asyncio.run(cmd_invite(args))
    elif args.command == "groups":
        cmd_groups(args)
    elif args.command == "admin":
        cmd_admin(args)
    elif args.command == "agent":
        cmd_agent(args)
    elif args.command == "gossip":
        cmd_gossip(args)


if __name__ == "__main__":
    main()
