#!/usr/bin/env python3
# Copyright (c) 2026 KiteSurf Contributors — MIT License
"""
kite_notify: KiteSurf Notification System.

Push channels (by priority):
  1. OpenClaw push-back — automatically leverages the running OpenClaw Gateway / CLI
     to send notifications back to the user/session that initiated the task, zero config.
  2. Webhook — WeChat Work/DingTalk/Feishu/Slack/Bark/ServerChan (requires manual URL config)
  3. Console banner — colored terminal banner (useful when viewing via SSH)

Configuration (in kitesurf.config.json):
  "notifications": {
      "enabled": true,
      "openclaw_push": true,          // Push notifications via OpenClaw (auto, recommended)
      "webhook_url": "",              // Manual webhook (optional)
      "webhook_urls": [],             // Multiple webhooks (optional)
      "bark_key": "",                 // Bark push (optional)
      "serverchan_key": "",           // ServerChan (optional)
      "console_banner": true,         // Colored terminal banner
      "on_task": true,
      "on_invite": true,
      "on_connect": true,
      "on_error": true
  }
"""

import json
import logging
import os
import socket
import subprocess
import sys
import threading
import time
import traceback
from urllib.request import Request, urlopen
from urllib.error import URLError

log = logging.getLogger("kite-notify")

# ── ANSI color helpers ────────────────────────────────────────────────────

_COLORS = {
    "reset":   "\033[0m",
    "bold":    "\033[1m",
    "red":     "\033[91m",
    "green":   "\033[92m",
    "yellow":  "\033[93m",
    "blue":    "\033[94m",
    "magenta": "\033[95m",
    "cyan":    "\033[96m",
    "white":   "\033[97m",
    "bg_red":    "\033[41m",
    "bg_green":  "\033[42m",
    "bg_yellow": "\033[43m",
    "bg_blue":   "\033[44m",
    "bg_magenta": "\033[45m",
    "bg_cyan":   "\033[46m",
}


def _c(text: str, *styles: str) -> str:
    """Apply ANSI styles to text."""
    prefix = "".join(_COLORS.get(s, "") for s in styles)
    return f"{prefix}{text}{_COLORS['reset']}" if prefix else text


# ── Default config ────────────────────────────────────────────────────────

_DEFAULT_NOTIFY_CFG = {
    "enabled": True,
    "openclaw_push": True,
    "webhook_url": "",
    "webhook_urls": [],
    "bark_key": "",
    "serverchan_key": "",
    "console_banner": True,
    "on_task": True,
    "on_invite": True,
    "on_connect": True,
    "on_error": True,
}


# ══════════════════════════════════════════════════════════════════════════
#  OpenClaw Push-back — auto-discover and leverage local OpenClaw to send messages
# ══════════════════════════════════════════════════════════════════════════

def _detect_openclaw_gateway() -> str:
    """Auto-detect local OpenClaw Gateway URL (same logic as kite_agent)."""
    cfg_paths = [
        os.path.expanduser("~/.openclaw/openclaw.json"),
        "/projects/.openclaw/openclaw.json",
    ]
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA", "")
        localappdata = os.environ.get("LOCALAPPDATA", "")
        if appdata:
            cfg_paths.insert(0, os.path.join(appdata, "openclaw", "openclaw.json"))
        if localappdata:
            cfg_paths.insert(0, os.path.join(localappdata, "openclaw", "openclaw.json"))

    for p in cfg_paths:
        try:
            with open(p) as f:
                oc = json.load(f)
            port = (
                oc.get("gateway", {}).get("port")
                or oc.get("apiPort")
                or oc.get("gatewayPort")
                or oc.get("port")
            )
            if port and isinstance(port, int):
                return f"http://localhost:{port}"
        except (FileNotFoundError, json.JSONDecodeError, TypeError, KeyError):
            continue

    # Port scan fallback (same order as kite_agent)
    for port in (18789, 23003, 23004, 23001, 3000, 3001, 3007, 8080, 8000):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                s.close()
                return f"http://localhost:{port}"
            s.close()
        except Exception:
            pass
    return ""


def _detect_openclaw_token() -> str:
    """Auto-detect OpenClaw Gateway auth token (same logic as kite_agent)."""
    env_token = os.environ.get("OPENCLAW_GATEWAY_TOKEN", "")
    if env_token:
        return env_token

    cfg_paths = [
        os.path.expanduser("~/.openclaw/openclaw.json"),
        "/projects/.openclaw/openclaw.json",
    ]
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA", "")
        localappdata = os.environ.get("LOCALAPPDATA", "")
        if appdata:
            cfg_paths.insert(0, os.path.join(appdata, "openclaw", "openclaw.json"))
        if localappdata:
            cfg_paths.insert(0, os.path.join(localappdata, "openclaw", "openclaw.json"))

    for p in cfg_paths:
        try:
            with open(p) as f:
                oc = json.load(f)
            token = oc.get("gateway", {}).get("auth", {}).get("token", "")
            if token:
                return token
        except (FileNotFoundError, json.JSONDecodeError, TypeError, KeyError):
            continue
    return ""


def _push_via_openclaw_gateway(gateway_url: str, session_id: str,
                                user_id: str, message: str, timeout: int = 15,
                                agent_name: str = "", gateway_token: str = ""):
    """Send a notification message through OpenClaw Gateway API.

    Tries OpenClaw native endpoints first (most likely to work on current
    versions), then falls back to OpenAI-compatible endpoints.
      Native:  POST /api/agent/turn, /api/sendMessage
      OpenAI:  POST /v1/chat/completions  (fallback: /api/v1/chat/completions)
      Authorization: Bearer <token>
    """
    base = gateway_url.rstrip("/")
    agent_id = agent_name or "main"

    # OpenAI-compatible payload
    openai_payload = {
        "model": f"openclaw:{agent_id}",
        "messages": [{"role": "user", "content": message}],
    }
    # OpenClaw native payload
    native_payload = {
        "agentId": agent_id,
        "message": message,
        "sessionKey": session_id or "kite-notify",
        "user": user_id or "kitesurf",
    }

    headers = {"Content-Type": "application/json"}
    if gateway_token:
        headers["Authorization"] = f"Bearer {gateway_token}"
    headers["x-openclaw-agent-id"] = agent_id
    if session_id:
        headers["x-openclaw-session-key"] = session_id

    # Native endpoints first, then OpenAI-compatible
    endpoints = [
        (f"{base}/api/agent/turn",          native_payload),
        (f"{base}/api/sendMessage",          native_payload),
        (f"{base}/v1/chat/completions",      openai_payload),
        (f"{base}/api/v1/chat/completions",  openai_payload),
    ]
    for url, payload in endpoints:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = Request(url, data=data, headers=headers)
        try:
            resp = urlopen(req, timeout=timeout)
            log.debug(f"[kite-notify] OpenClaw push OK via {url} (status={resp.getcode()})")
            return True
        except Exception as e:
            err_str = str(e)
            # 404 = endpoint not found, try next; other errors = stop
            if "404" in err_str:
                log.debug(f"[kite-notify] {url} -> 404, trying next endpoint")
                continue
            log.debug(f"[kite-notify] OpenClaw push failed via {url}: {e}")
            # 401 = auth error, no point trying other endpoints
            if "401" in err_str:
                return False
            continue
    log.debug("[kite-notify] OpenClaw push failed on all endpoints")
    return False


def _push_via_openclaw_cli(session_to: str, session_id: str,
                            agent_name: str, message: str, timeout: int = 30):
    """Send a notification message through `openclaw agent` CLI.

    Falls back to CLI when Gateway API is not available.
    """
    cmd = ["openclaw", "agent", "--message", message, "--timeout", str(timeout)]
    if session_to:
        cmd.extend(["--to", session_to])

    # session_id must be UUID format for --session-id.
    # If it looks like a session key (contains colons like
    # "agent:main:wecom:direct:t55000018a"), extract agent_name and skip --session-id.
    if session_id and ":" in session_id:
        parts = session_id.split(":")
        if not agent_name and len(parts) >= 2 and parts[0] == "agent":
            agent_name = parts[1]
        session_id = ""  # don't pass key-format to --session-id

    if session_id:
        cmd.extend(["--session-id", session_id])
    if agent_name:
        cmd.extend(["--agent", agent_name])

    if not any([session_to, session_id, agent_name]):
        log.debug("[kite-notify] OpenClaw CLI push skipped: no session params")
        return False

    try:
        kwargs = {}
        if sys.platform == "win32":
            kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
        result = subprocess.run(
            cmd, capture_output=True, timeout=timeout, **kwargs
        )
        if result.returncode == 0:
            log.debug("[kite-notify] OpenClaw CLI push OK")
            return True
        else:
            log.debug(f"[kite-notify] OpenClaw CLI push failed (exit {result.returncode})")
            return False
    except FileNotFoundError:
        log.debug("[kite-notify] openclaw command not found")
        return False
    except subprocess.TimeoutExpired:
        log.debug("[kite-notify] OpenClaw CLI push timed out")
        return False
    except Exception as e:
        log.debug(f"[kite-notify] OpenClaw CLI push error: {e}")
        return False


# ══════════════════════════════════════════════════════════════════════════
#  Webhook payload builders — auto-detect platform by URL
# ══════════════════════════════════════════════════════════════════════════

def _build_wechat_work(title: str, body: str) -> dict:
    """WeChat Work group bot (markdown)."""
    content = f"### {title}\n{body}"
    return {"msgtype": "markdown", "markdown": {"content": content}}


def _build_dingtalk(title: str, body: str) -> dict:
    """DingTalk group bot (markdown)."""
    content = f"### {title}\n\n{body}"
    return {"msgtype": "markdown", "markdown": {"title": title, "text": content}}


def _build_feishu(title: str, body: str) -> dict:
    """Feishu/Lark group bot (rich_text)."""
    return {
        "msg_type": "interactive",
        "card": {
            "header": {
                "title": {"tag": "plain_text", "content": title},
                "template": "blue",
            },
            "elements": [
                {"tag": "markdown", "content": body},
            ],
        },
    }


def _build_slack(title: str, body: str) -> dict:
    """Slack Incoming Webhook."""
    return {"text": f"*{title}*\n{body}"}


def _build_generic(title: str, body: str) -> dict:
    """Generic JSON webhook."""
    return {
        "title": title,
        "body": body,
        "source": "kitesurf",
        "timestamp": int(time.time()),
    }


def _detect_platform(url: str) -> str:
    """Detect webhook platform from URL pattern."""
    u = url.lower()
    if "qyapi.weixin.qq.com" in u:
        return "wechat_work"
    elif "oapi.dingtalk.com" in u:
        return "dingtalk"
    elif "open.feishu.cn" in u or "open.larksuite.com" in u:
        return "feishu"
    elif "hooks.slack.com" in u:
        return "slack"
    return "generic"


_BUILDERS = {
    "wechat_work": _build_wechat_work,
    "dingtalk": _build_dingtalk,
    "feishu": _build_feishu,
    "slack": _build_slack,
    "generic": _build_generic,
}


def _send_webhook(url: str, title: str, body: str, timeout: int = 10):
    """Send notification to a webhook URL (blocking)."""
    platform = _detect_platform(url)
    builder = _BUILDERS.get(platform, _build_generic)
    payload = builder(title, body)
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        resp = urlopen(req, timeout=timeout)
        status = resp.getcode()
        if status and status >= 300:
            log.warning(f"[kite-notify] Webhook returned {status}: {url[:60]}")
        else:
            log.debug(f"[kite-notify] Webhook OK ({platform}): {url[:60]}")
    except URLError as e:
        log.warning(f"[kite-notify] Webhook failed ({platform}): {e}")
    except Exception as e:
        log.warning(f"[kite-notify] Webhook error ({platform}): {e}")


def _send_bark(bark_key: str, title: str, body: str, timeout: int = 10):
    """Send push via Bark (iOS)."""
    from urllib.parse import quote
    url = f"https://api.day.app/{bark_key}/{quote(title)}/{quote(body)}"
    req = Request(url)
    try:
        urlopen(req, timeout=timeout)
        log.debug("[kite-notify] Bark push OK")
    except Exception as e:
        log.warning(f"[kite-notify] Bark push failed: {e}")


def _send_serverchan(key: str, title: str, body: str, timeout: int = 10):
    """Send push via ServerChan (WeChat)."""
    url = f"https://sctapi.ftqq.com/{key}.send"
    data = json.dumps({"title": title, "desp": body}, ensure_ascii=False).encode("utf-8")
    req = Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        urlopen(req, timeout=timeout)
        log.debug("[kite-notify] ServerChan push OK")
    except Exception as e:
        log.warning(f"[kite-notify] ServerChan push failed: {e}")


# ══════════════════════════════════════════════════════════════════════════
#  KiteNotifier
# ══════════════════════════════════════════════════════════════════════════

class KiteNotifier:
    """Notification manager for KiteSurf — OpenClaw push + Webhook + Console."""

    def __init__(self, config: dict = None):
        self._full_config = config or {}
        raw = self._full_config.get("notifications", {})
        self.cfg = {**_DEFAULT_NOTIFY_CFG, **raw}

        # ── OpenClaw push channel (auto-discovered, zero config) ──
        self._openclaw_push = self.cfg.get("openclaw_push", True)
        self._openclaw_gateway_url = ""
        self._openclaw_gateway_token = ""
        self._openclaw_cli_available = None  # lazy detect
        if self._openclaw_push:
            # Gateway URL: prefer agent's already-detected URL, else discover ourselves
            self._openclaw_gateway_url = (
                self._full_config.get("gateway_url")
                or _detect_openclaw_gateway()
            )
            # Gateway token: prefer explicit config, else auto-detect
            self._openclaw_gateway_token = (
                self._full_config.get("gateway_token", "")
                or _detect_openclaw_token()
            )
        # Session params from the same config that kite_agent uses
        self._session_to = self._full_config.get("session_to", "")
        self._session_id = self._full_config.get("session_id", "")
        self._agent_name = self._full_config.get("agent_name", "")
        self._gateway_user = self._full_config.get("gateway_user", "kitesurf")

        # ── Webhook channels (manual config) ──
        self._webhook_urls: list[str] = []
        main_url = self.cfg.get("webhook_url", "")
        if main_url:
            self._webhook_urls.append(main_url)
        extra_urls = self.cfg.get("webhook_urls", [])
        if isinstance(extra_urls, list):
            for u in extra_urls:
                if u and u not in self._webhook_urls:
                    self._webhook_urls.append(u)

        self._bark_key = self.cfg.get("bark_key", "")
        self._serverchan_key = self.cfg.get("serverchan_key", "")

        # ── Rate limiting ──
        self._last_push_time: dict[str, float] = {}
        self._min_interval = 3.0  # seconds between same-type pushes

        # ── Track OpenClaw push failures to avoid repeated slow timeouts ──
        self._openclaw_push_failures = 0
        self._openclaw_push_disabled_until = 0.0

    def _is_enabled(self, event_type: str) -> bool:
        return self.cfg.get("enabled", True) and self.cfg.get(event_type, True)

    def _has_push_channel(self) -> bool:
        return bool(
            (self._openclaw_push and self._openclaw_gateway_url)
            or self._webhook_urls
            or self._bark_key
            or self._serverchan_key
        )

    def _rate_ok(self, key: str) -> bool:
        """Simple rate limiter."""
        now = time.time()
        last = self._last_push_time.get(key, 0)
        if now - last < self._min_interval:
            return False
        self._last_push_time[key] = now
        return True

    # ══════════════════════════════════════════════════════════════════════
    #  Public API — called by KiteSurfAgent / KiteNode
    # ══════════════════════════════════════════════════════════════════════

    def notify_task(self, task_id: str, message: str, from_node: str):
        """Notification for incoming task."""
        if not self._is_enabled("on_task"):
            return
        short_id = task_id[:8]
        title = "📥 KiteSurf — New Task"
        body = f"From: {from_node}\nTask ID: {short_id}\nContent: {message[:200]}"
        self._fire(title, body, "task")

    def notify_task_success(self, task_id: str, elapsed: float):
        """Notification for task success."""
        if not self._is_enabled("on_task"):
            return
        title = "✅ KiteSurf — Task Completed"
        body = f"Task {task_id[:8]} succeeded ({elapsed:.1f}s)"
        self._fire(title, body, "success")

    def notify_task_failed(self, task_id: str, error: str):
        """Notification for task failure."""
        if not self._is_enabled("on_error"):
            return
        title = "❌ KiteSurf — Task Failed"
        body = f"Task {task_id[:8]}: {error[:200]}"
        self._fire(title, body, "error")

    def notify_task_approval(self, task_id: str, message: str, from_node: str,
                              reason: str = "", admin_port: int = 17853):
        """Push task-approval notification directly to human, bypassing AI.

        Called when a task requires human approval (either by keyword trigger
        or by task_approval_mode="notify"). The human receives the notification
        via webhook/Bark/ServerChan with instructions to approve or reject.
        """
        if not self._is_enabled("on_task"):
            return
        short_id = task_id[:8]
        title = "⏳ KiteSurf — Task Pending Approval"
        body_lines = [
            f"From: {from_node}",
            f"Task ID: {short_id}",
            f"Content: {message[:200]}",
        ]
        if reason:
            body_lines.append(f"Reason: {reason}")
        body_lines.append(f"")
        body_lines.append(f"✅ Approve: POST http://127.0.0.1:{admin_port}/approve?task_id={short_id}")
        body_lines.append(f"📋 View:    GET  http://127.0.0.1:{admin_port}/approve")
        body = "\n".join(body_lines)

        if self.cfg.get("console_banner", True):
            self._console_banner(title, body, "task", extra_tag=f"[{short_id}]")
        if self._rate_ok(f"approval-{short_id}"):
            threading.Thread(
                target=self._push_human_only,
                args=(title, body),
                daemon=True,
            ).start()

    def notify_invite(self, from_profile: dict, message: str = ""):
        """Notification for incoming invite."""
        if not self._is_enabled("on_invite"):
            return
        from_id = from_profile.get("node_id", "?")
        from_nick = from_profile.get("nickname", "")
        from_emoji = from_profile.get("emoji", "🪁")
        from_name = f"{from_emoji} {from_nick}" if from_nick else f"{from_emoji} {from_id}"
        title = "📨 KiteSurf — Connection Invite"
        body = f"From: {from_name}"
        if message:
            body += f"\nMessage: {message[:120]}"
        self._fire(title, body, "invite")

    def notify_invite_human_only(self, from_profile: dict, message: str = "",
                                  invite_token: str = ""):
        """Push invite notification DIRECTLY to the human user, bypassing AI.

        Unlike ``notify_invite`` → ``_fire`` → ``_push_all`` which includes the
        OpenClaw Gateway/CLI channel (triggering an AI agentTurn that may
        autonomously accept/decline the invite), this method ONLY uses channels
        that deliver the message to the human without AI intermediation:

          ✅ Webhook (WeChat Work / DingTalk / Feishu / Slack)
          ✅ Bark (iOS push)
          ✅ ServerChan (WeChat)
          ✅ Console banner

          ❌ OpenClaw Gateway/CLI  ← deliberately skipped
        """
        if not self._is_enabled("on_invite"):
            return
        from_id = from_profile.get("node_id", "?")
        from_nick = from_profile.get("nickname", "")
        from_emoji = from_profile.get("emoji", "🪁")
        from_name = f"{from_emoji} {from_nick}" if from_nick else f"{from_emoji} {from_id}"
        title = "📨 KiteSurf — Connection Invite"
        body = f"From: {from_name}"
        if message:
            body += f"\nMessage: {message[:120]}"
        if invite_token:
            body += f"\nToken: {invite_token[:16]}..."
            body += f"\nTo accept: accept_invite('{invite_token[:8]}...')"

        # Console banner (synchronous, immediate)
        if self.cfg.get("console_banner", True):
            self._console_banner(title, body, "invite")

        # All NON-AI push channels (background thread)
        if self._rate_ok("invite_human"):
            threading.Thread(
                target=self._push_human_only,
                args=(title, body),
                daemon=True,
            ).start()

    def _push_human_only(self, title: str, body: str):
        """Send to webhook/Bark/ServerChan only. NO OpenClaw push.

        This ensures the notification reaches the human user directly,
        not an AI agent that might act on it autonomously.
        """
        body_oneline = body.replace("\n", " | ")

        # ── Webhook URLs ──
        for url in self._webhook_urls:
            try:
                _send_webhook(url, title, body)
            except Exception:
                log.debug(f"[kite-notify] Webhook exception:\n{traceback.format_exc()}")

        # ── Bark ──
        if self._bark_key:
            try:
                _send_bark(self._bark_key, title, body_oneline)
            except Exception:
                log.debug(f"[kite-notify] Bark exception:\n{traceback.format_exc()}")

        # ── ServerChan ──
        if self._serverchan_key:
            try:
                _send_serverchan(self._serverchan_key, title, body)
            except Exception:
                log.debug(f"[kite-notify] ServerChan exception:\n{traceback.format_exc()}")

        has_any = bool(self._webhook_urls or self._bark_key or self._serverchan_key)
        if not has_any:
            log.warning(
                "[kite-notify] ⚠️ No human-direct push channel configured! "
                "Invite notification was only shown in console. "
                "Configure webhook_url, bark_key, or serverchan_key in "
                "kitesurf.config.json → notifications to receive invite "
                "alerts on your phone/IM."
            )

    def notify_connect_approval(self, approval_id: str, peer_id: str,
                                 remote_addr: str = "", admin_port: int = 17853):
        """Push connection-approval notification directly to human.

        Called when auto_accept=false and an inbound connection from a
        non-trusted peer needs manual approval. The human receives the
        notification via webhook/Bark/ServerChan with instructions to approve.
        """
        if not self._is_enabled("on_connect"):
            return
        title = "⏳ KiteSurf — Connection Pending Approval"
        body_lines = [
            f"Peer: {peer_id}",
            f"From: {remote_addr or '(unknown)'}",
            f"Approval ID: {approval_id}",
            f"",
            f"✅ Approve: POST http://127.0.0.1:{admin_port}/connect-approve?id={approval_id}",
            f"🚫 Reject:  POST http://127.0.0.1:{admin_port}/connect-reject?id={approval_id}",
            f"📋 View:    GET  http://127.0.0.1:{admin_port}/connect-requests",
        ]
        body = "\n".join(body_lines)

        if self.cfg.get("console_banner", True):
            self._console_banner(title, body, "connect", extra_tag=f"[{approval_id[:8]}]")
        if self._rate_ok(f"connect-approval-{approval_id}"):
            threading.Thread(
                target=self._push_human_only,
                args=(title, body),
                daemon=True,
            ).start()

    def notify_connect(self, peer_id: str, connected: bool, info: str = ""):
        """Notification for peer connect/disconnect."""
        if not self._is_enabled("on_connect"):
            return
        if connected:
            title = "🟢 KiteSurf — Node Connected"
            body = f"Node {peer_id} is online"
        else:
            title = "🔴 KiteSurf — Node Disconnected"
            body = f"Node {peer_id} is offline"
        if info:
            body += f"\n{info}"
        self._fire(title, body, "connect" if connected else "disconnect")

    # ══════════════════════════════════════════════════════════════════════
    #  Core: fire notification across all enabled channels
    # ══════════════════════════════════════════════════════════════════════

    def _fire(self, title: str, body: str, event_type: str, extra_tag: str = ""):
        """Fire notification on all enabled channels (non-blocking)."""
        # 1. Console banner (synchronous, immediate)
        if self.cfg.get("console_banner", True):
            self._console_banner(title, body, event_type, extra_tag)

        # 2. All push channels (background thread)
        if self._has_push_channel() and self._rate_ok(event_type):
            threading.Thread(
                target=self._push_all,
                args=(title, body),
                daemon=True,
            ).start()

    def _push_all(self, title: str, body: str):
        """Send to all configured push channels. Runs in background thread."""
        body_oneline = body.replace("\n", " | ")
        combined = f"{title}\n{body}"

        # ── Channel 1: OpenClaw push-back (auto, zero config) ──
        if self._openclaw_push and time.time() > self._openclaw_push_disabled_until:
            pushed = self._push_via_openclaw(combined)
            if pushed:
                self._openclaw_push_failures = 0
            else:
                self._openclaw_push_failures += 1
                # After 3 consecutive failures, back off for 5 minutes
                if self._openclaw_push_failures >= 3:
                    self._openclaw_push_disabled_until = time.time() + 300
                    log.warning("[kite-notify] OpenClaw push failed 3x, backing off 5min")

        # ── Channel 2: Webhook URLs ──
        for url in self._webhook_urls:
            try:
                _send_webhook(url, title, body)
            except Exception:
                log.debug(f"[kite-notify] Webhook exception:\n{traceback.format_exc()}")

        # ── Channel 3: Bark ──
        if self._bark_key:
            try:
                _send_bark(self._bark_key, title, body_oneline)
            except Exception:
                log.debug(f"[kite-notify] Bark exception:\n{traceback.format_exc()}")

        # ── Channel 4: ServerChan ──
        if self._serverchan_key:
            try:
                _send_serverchan(self._serverchan_key, title, body)
            except Exception:
                log.debug(f"[kite-notify] ServerChan exception:\n{traceback.format_exc()}")

    def _push_via_openclaw(self, message: str) -> bool:
        """Try pushing notification via OpenClaw (Gateway first, CLI fallback)."""
        # Strategy 1: Gateway API (faster, non-blocking)
        if self._openclaw_gateway_url:
            session_id = self._session_id or "kite-notify"
            ok = _push_via_openclaw_gateway(
                self._openclaw_gateway_url, session_id,
                self._gateway_user, message, timeout=10,
                agent_name=self._agent_name,
                gateway_token=self._openclaw_gateway_token,
            )
            if ok:
                return True

        # Strategy 2: CLI fallback
        ok = _push_via_openclaw_cli(
            self._session_to, self._session_id,
            self._agent_name, message, timeout=15,
        )
        return ok

    # ── Channel: Console Banner ───────────────────────────────────────────

    def _console_banner(self, title: str, body: str, event_type: str, extra_tag: str = ""):
        """Print a highly visible colored banner to the terminal."""
        style_map = {
            "task":       ("bg_cyan", "bold", "white"),
            "success":    ("bg_green", "bold", "white"),
            "error":      ("bg_red", "bold", "white"),
            "invite":     ("bg_magenta", "bold", "white"),
            "connect":    ("bg_green", "bold", "white"),
            "disconnect": ("bg_yellow", "bold", "red"),
        }
        styles = style_map.get(event_type, ("bold", "cyan"))

        separator = "═" * 60
        tag = f" {extra_tag}" if extra_tag else ""

        lines = [
            "",
            _c(f"╔{separator}╗", *styles),
            _c(f"║  {title}{tag:<{57 - len(title) - len(tag)}}║", *styles),
            _c(f"╟{'─' * 60}╢", *styles),
        ]
        for line in body.split("\n"):
            while len(line) > 56:
                lines.append(_c(f"║  {line[:56]}  ║", *styles))
                line = line[56:]
            lines.append(_c(f"║  {line:<56}  ║", *styles))
        lines.append(_c(f"╚{separator}╝", *styles))
        lines.append("")

        output = "\n".join(lines)
        try:
            print(output, flush=True)
        except UnicodeEncodeError:
            print(output.encode("utf-8", errors="replace").decode("ascii", errors="replace"),
                  flush=True)


# ══════════════════════════════════════════════════════════════════════════
#  Module-level singleton (lazy init)
# ══════════════════════════════════════════════════════════════════════════

_notifier: KiteNotifier = None


def init(config: dict = None):
    """Initialize the global notifier. Call once at startup."""
    global _notifier
    _notifier = KiteNotifier(config or {})

    channels = []
    if _notifier._openclaw_push:
        if _notifier._openclaw_gateway_url:
            channels.append(f"openclaw-gateway({_notifier._openclaw_gateway_url})")
        elif any([_notifier._session_to, _notifier._session_id, _notifier._agent_name]):
            channels.append("openclaw-cli")
        else:
            channels.append("openclaw(no session params — will try at push time)")
    if _notifier._webhook_urls:
        platforms = [_detect_platform(u) for u in _notifier._webhook_urls]
        channels.append(f"webhook({','.join(platforms)})")
    if _notifier._bark_key:
        channels.append("bark")
    if _notifier._serverchan_key:
        channels.append("serverchan")
    if _notifier.cfg.get("console_banner"):
        channels.append("console")

    if _notifier.cfg.get("enabled"):
        if channels:
            log.info(f"[kite-notify] 🔔 Notifications enabled: {', '.join(channels)}")
        else:
            log.info("[kite-notify] 🔔 Notifications enabled (console only)")
    else:
        log.info("[kite-notify] 🔕 Notifications disabled")
    return _notifier


def get() -> KiteNotifier:
    """Get the global notifier (auto-initialize if needed)."""
    global _notifier
    if _notifier is None:
        _notifier = KiteNotifier()
    return _notifier
