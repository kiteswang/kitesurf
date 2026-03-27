# KiteSurf 🪁

> *"If you can't make it useful, make it playful. Play is power."*

**Cross-machine AI Agent communication framework** — enables multiple OpenClaw / CodeBuddy nodes to auto-discover, pair, encrypt interconnections, and collaborate on tasks.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://python.org)
[![Protocol: KITP v1](https://img.shields.io/badge/Protocol-KITP%20v1-green.svg)](docs/protocol.md)

---

## ✨ Features

| Capability | Description |
|------------|-------------|
| 🔍 **Auto-Discovery** | Automatically discover online nodes via Rendezvous server, supports tag filtering and smart recommendations |
| 🤝 **One-Click Pairing** | Invite → Accept → Auto-establish encrypted connection, no manual IP configuration needed |
| 🔐 **End-to-End Encryption** | HMAC-SHA256 signature authentication + AES-256-GCM encrypted transport |
| 🕳️ **NAT Traversal** | STUN discovers public address → UDP hole punching → Direct P2P channel (falls back to Relay on failure) |
| 📡 **Task Distribution** | Send tasks to remote Agents, wait for execution results |
| 🛡️ **6-Layer Security** | Privacy probe protection · Node whitelist · Rate limiting · Message inspection · Keyword filtering · Manual approval |
| 💓 **Smart Keepalive** | Adaptive heartbeat detection (inspired by WeChat Mars / QQ), auto-adjusting intervals, fast recovery on network fluctuations |
| 📢 **Multi-Channel Notifications** | OpenClaw push-back · Webhook (WeChat Work/DingTalk/Feishu/Slack) · Bark · ServerChan · Console banner |
| 🔄 **Session Auto-Discovery** | Auto-detect OpenClaw active sessions, 5-minute cache, auto-refresh on expiry |

## 🏗️ Architecture

```
┌──────────┐     wss://     ┌─────────────────┐     wss://     ┌──────────┐
│  Node A  │◄──────────────►│   Rendezvous    │◄──────────────►│  Node B  │
│ (Agent)  │   discovery    │   Server 🌐     │   discovery    │ (Agent)  │
│          │   + pairing    │                 │   + pairing    │          │
└────┬─────┘                └─────────────────┘                └────┬─────┘
     │                                                              │
     │              Direct P2P (KITP over WebSocket)                │
     │◄────────────────────────────────────────────────────────────►│
     │           HMAC-SHA256 signed + AES-256-GCM encrypted         │
```

## 🚀 Quick Start

### Installation

```bash
pip install websockets aiohttp

# Optional: enable AES-256-GCM encryption (strongly recommended)
pip install cryptography
```

### Configuration

Create `config.json` (**change `secret` to your own key**):

```json
{
  "secret": "my-team-secret-2026",
  "port": 17850,
  "rendezvous_url": "wss://www.kitesurf.chat:17851",
  "auto_accept": false,
  "admin_port": 17853,
  "public_profile": {
    "nickname": "my-node",
    "emoji": "🪁",
    "tags": ["coding", "research"]
  }
}
```

### Start

```bash
# Start in background (recommended)
python3 scripts/kite_agent.py --config config.json --daemon

# Check running status
python3 scripts/kite_agent.py --config config.json --check

# Stop
python3 scripts/kite_agent.py --config config.json --stop
```

### Usage

```bash
# Check node status
curl http://127.0.0.1:17853/status

# Discover online nodes
curl http://127.0.0.1:17853/peers

# Invite a node
curl -X POST http://127.0.0.1:17853/invite \
  -d '{"target":"<node_id>", "message":"Let us collaborate"}'

# Send a task
curl -X POST http://127.0.0.1:17853/task \
  -d '{"peer":"<node_id>", "message":"Help me analyze this code", "timeout":300}'
```

## 📖 Configuration Reference

| Field | Default | Description |
|-------|---------|-------------|
| `secret` | — | **Required**, all collaborating nodes use the same key |
| `port` | `17850` | KITP communication port |
| `rendezvous_url` | `wss://...` | Rendezvous discovery service address |
| `auto_accept` | `false` | Auto-accept all pairing invites |
| `admin_port` | `17853` | Admin API port (localhost only) |
| `ssl_verify` | `true` | TLS certificate verification (`false` for self-signed certificates) |
| `allow_insecure` | `false` | Allow wss→ws downgrade (**not recommended**, dev environments only) |
| `task_timeout` | `300` | Task timeout in seconds |

## 🛡️ Security Model

### 6-Layer Defense-in-Depth

```
Remote task received → [0.Privacy Probe Protection] → [1.Policy Mode] → [2.Rate Limiting] → [3.Message Length] → [4.Keyword Blacklist] → [5.Manual Approval] → Execute
```

| Layer | Description | Configurable |
|-------|-------------|--------------|
| **Layer 0: Privacy Probe Protection** | Hardcoded 140+ patterns, blocks capability sniffing/OS probing/network probing/filesystem/identity/processes/containers/databases/security config/code/command injection | ❌ Always enforced, cannot be disabled |
| **Layer 1: Task Policy** | `open` (allow all) / `trusted_only` (whitelist only) / `disabled` (reject all) | ✅ `task_policy` |
| **Layer 2: Rate Limiting** | Cooldown interval + per-minute/per-hour limits, counted per node | ✅ `rate_limit` |
| **Layer 3: Message Length** | Maximum characters per message | ✅ `max_message_length` |
| **Layer 4: Keyword Blacklist** | Rejected on match (case-insensitive) | ✅ `blocked_keywords` |
| **Layer 5: Manual Approval** | Matched keywords enter approval queue, execute after `POST /approve` | ✅ `require_approval_keywords` |

### Traditional Security

- **Authentication**: HMAC-SHA256 signatures, all messages require shared secret signature verification
- **Encryption**: AES-256-GCM end-to-end encryption (requires `cryptography` package)
- **Transport**: Default wss:// (TLS), refuses automatic downgrade
- **Replay Protection**: Message timestamp window ±5 minutes
- **Access Control**: Admin API binds to 127.0.0.1 only

### Dynamic Management

All security policies can be dynamically adjusted at runtime via the `GET/POST /security` endpoint, no restart required.

## 🔌 Admin API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/status` | GET | Node status (uptime, connection count, task stats, security policy summary) |
| `/connections` | GET | Connected peer list |
| `/peers` | GET | Discover online nodes via Rendezvous |
| `/invites` | GET | Pending pairing invites |
| `/tasks` | GET | Task send/receive history (last 50) |
| `/invite` | POST | Send pairing invite |
| `/accept` | POST | Accept pairing invite |
| `/task` | POST | Send task and wait for result |
| `/reconnect` | POST | Force reconnect peer |
| `/disconnect` | GET | Disconnect peer |
| `/security` | GET/POST | View/update security policies |
| `/approve` | GET/POST | View/approve pending tasks |
| `/shutdown` | POST | Graceful shutdown |

## 🔌 Use as a Skill

KiteSurf is a [CodeBuddy](https://www.codebuddy.ai) Skill that can be installed directly into the CodeBuddy IDE:

1. Download `kitesurf.zip` (or run `python pack_skill.py` to package it yourself)
2. CodeBuddy → Settings → Skills → Import
3. Say "kitesurf" or "connect two OpenClaws" in the conversation to trigger it

## 📂 Project Structure

```
kitesurf/
├── SKILL.md                     # Skill manual (LLM reads this file)
├── LICENSE                      # MIT License
├── README.md                    # This file
├── requirements.txt             # Python dependencies
├── pack_skill.py                # Packaging script → kitesurf.zip
├── scripts/
│   ├── kite_agent.py            # Agent main program (daemon + Admin API + security engine)
│   ├── kite_node.py             # KITP communication node core (with smart keepalive)
│   ├── kite_pairing.py          # Rendezvous pairing client
│   ├── kite_notify.py           # Multi-channel notification system
│   ├── kite_cli.py              # CLI tool
│   ├── kite_crypto.py           # AES-256-GCM encryption module
│   ├── kite_punch.py            # UDP hole punching + Relay
│   ├── kite_stun.py             # STUN NAT traversal
│   ├── kite_rendezvous.py       # Rendezvous server (standalone deployment)
│   └── kitesurf.config.json     # Configuration template
└── docs/
    └── protocol.md              # KITP v1 protocol specification
```

## 🤝 Contributing

PRs and Issues are welcome! Please ensure:

1. Code passes existing tests: `python -m pytest scripts/test_*.py`
2. New features include tests
3. Follow existing code style

## 📄 License

[MIT License](LICENSE) — free to use, modify, and distribute.
