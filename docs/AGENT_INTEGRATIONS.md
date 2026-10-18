# Agent Integration Guide: GrokBot, Meta Muse, Dots, Claude & ChatGPT

Because modern AI assistants run either **locally on your desktop** or **natively hosted in a provider's cloud**, `ai-assistant-voice` ships with a **dual-transport Model Context Protocol (MCP) server**:

1. **Desktop / Local CLI Transport (`--transport stdio`)**:
   - The desktop client spawns `ai-assistant-voice` as a local child process and communicates over `stdin`/`stdout` JSON-RPC 2.0.
   - Zero network ports are opened on your machine for MCP.
2. **Provider-Hosted Remote MCP Transport (`--transport http`)**:
   - When your primary agent is hosted by the provider (**xAI GrokBot**, **Meta Muse Cloud**, **Dots (`getdot.ai`)**, **Claude.ai Custom Connectors**, **ChatGPT Developer Mode Connectors**), you cannot run a local `stdio` subprocess beside their cloud container.
   - Instead, `ai-assistant-voice` runs on a small VPS or home server (where your SIP-TLS/SRTP trunk terminates) and exposes a hardened **Streamable HTTP** endpoint (`POST /mcp`) + **RFC 9728 OAuth 2.1 Protected Resource Metadata** (`GET /.well-known/oauth-protected-resource`).

---

## Architectural Comparison: Desktop vs. Provider-Hosted

| Deployment Model | Where the Main Agent Runs | Where `ai-assistant-voice` Runs | MCP Transport | Auth Mechanism |
| :--- | :--- | :--- | :--- | :--- |
| **Desktop / CLI** (Muse Code, Grok CLI, Claude Desktop, Cursor, Antigravity) | Local Workstation | Local Workstation (or over SSH `stdio`) | `stdio` | OS process isolation (no network port) |
| **Provider-Hosted Cloud** (xAI GrokBot / Grok API, Hosted Meta Muse, Dots, Claude.ai / ChatGPT Web) | Provider Cloud | Your VPS / Home Lab (via Cloudflare Tunnel or Reverse Proxy) | Streamable HTTP (`https://<your-domain>/mcp`) | `Authorization: Bearer <256-bit-token>` or OAuth 2.1 + Origin Validation |

---

## 1. xAI GrokBot & Grok API / CLI

xAI supports MCP both natively in the **xAI Cloud API (Remote MCP Tools)**—ideal for provider-hosted GrokBot deployments—and locally via the **Grok CLI (`~/.grok/config.toml`)**.

### A. Provider-Hosted GrokBot (xAI Remote MCP API)
When GrokBot runs in xAI's cloud, pass your `ai-assistant-voice` Streamable HTTP endpoint directly in the `tools` array of `chat.completions` / `responses`. xAI's servers connect outbound over HTTPS to your `/mcp` endpoint using your Bearer token:

```python
import os
from openai import OpenAI

client = OpenAI(
    api_key=os.environ["XAI_API_KEY"],
    base_url="https://api.x.ai/v1",
)

response = client.responses.create(
    model="grok-4",
    input="Call Bistro L'avenir at +12025550188 and confirm a table for 4 at 7:30 PM Friday under Dan.",
    tools=[
        {
            "type": "mcp",
            "server_label": "voice",
            "server_description": "Autonomous SIP/SRTP outbound/inbound phone calls and SMS/2FA",
            "server_url": "https://voice-mcp.example.com/mcp",
            "authorization": f"Bearer {os.environ['AI_VOICE_MCP_TOKEN']}",
            "allowed_tools": [
                "voice_call_outbound",
                "voice_get_call",
                "voice_list_calls",
                "voice_send_dtmf",
                "voice_hangup_call",
                "voice_send_sms",
                "voice_list_sms",
                "voice_system_status",
            ],
        }
    ],
)
print(response.output_text)
```

> **Bonus — Using xAI Grok Voice Realtime as the Voice Engine:**
> In addition to calling `ai-assistant-voice` *from* GrokBot via MCP, `ai-assistant-voice` can also use xAI's `wss://api.x.ai/v1/realtime` (`AI_VOICE_PROVIDER=xai_realtime`) as the underlying audio-to-audio voice model, which supports native 8kHz G.711 $\mu$-law (`audio/pcmu`) frames with zero resampling.

### B. Desktop / Local Grok CLI (`~/.grok/config.toml`)
For local desktop or terminal Grok agents, add `ai-assistant-voice` to `~/.grok/config.toml` (or run `grok mcp add`):

```toml
# Option 1: Local stdio subprocess
[mcp_servers.voice]
command = "ai-assistant-voice"
args = ["--transport", "stdio"]
env = { AI_VOICE_SIP_SERVER = "washington2.voip.ms", AI_VOICE_SIP_USERNAME = "123456_voiceagent" }

# Option 2: Remote Streamable HTTP server
[mcp_servers.voice_remote]
url = "https://voice-mcp.example.com/mcp"
headers = { Authorization = "Bearer REPLACE_WITH_AI_VOICE_MCP_TOKEN" }
```

---

## 2. Meta Muse & Muse Code

Meta's **Muse** agent ecosystem supports MCP connections via `"type": "remote"` HTTP connectors (for provider-hosted Muse environments and enterprise gateways) and local `stdio` servers (for **Muse Code** desktop).

### A. Provider-Hosted Muse / Remote MCP Connector
Configure Muse to connect to your HTTPS `/mcp` endpoint with Bearer authentication:

```json
{
  "schema_version": 1,
  "mcp_servers": {
    "ai-assistant-voice": {
      "type": "remote",
      "url": "https://voice-mcp.example.com/mcp",
      "headers": {
        "Authorization": "Bearer REPLACE_WITH_AI_VOICE_MCP_TOKEN"
      },
      "timeout_ms": 60000
    }
  }
}
```

### B. Desktop Muse Code (`~/.config/muse/settings.json`)
For local desktop usage in Muse Code, configure `stdio` transport in `~/.config/muse/settings.json` (note that `"schema_version": 1` is required by Muse):

```json
{
  "schema_version": 1,
  "mcp_servers": {
    "ai-assistant-voice": {
      "command": "ai-assistant-voice",
      "args": ["--transport", "stdio"],
      "env": {
        "AI_VOICE_SIP_SERVER": "washington2.voip.ms",
        "AI_VOICE_SIP_USERNAME": "123456_voiceagent",
        "AI_VOICE_SIP_PASSWORD": "REPLACE_WITH_VOIPMS_PASSWORD",
        "GEMINI_API_KEY": "REPLACE_WITH_GEMINI_API_KEY"
      }
    }
  }
}
```

---

## 3. Dots, Claude (Desktop & Web Connectors), and ChatGPT

### A. Provider-Hosted Connectors (Dots `getdot.ai`, Claude.ai Custom Connectors, ChatGPT Developer Mode)
Cloud-hosted assistants such as **Dots**, **Claude.ai ("Connectors")**, and **ChatGPT Custom MCP Connectors** connect over HTTPS **Streamable HTTP** (`POST /mcp`) and discover authentication requirements via **RFC 9728 OAuth 2.1 Protected Resource Metadata** (`GET /.well-known/oauth-protected-resource`).

`ai-assistant-voice` serves both endpoints out of the box when started with `--transport http`:
- **MCP Endpoint**: `https://voice-mcp.example.com/mcp`
- **OAuth 2.1 Protected Resource Metadata**: `https://voice-mcp.example.com/.well-known/oauth-protected-resource`
- **Health Check**: `https://voice-mcp.example.com/healthz`

To register `ai-assistant-voice` in **Dots**, **Claude.ai**, or **ChatGPT**:
1. Set `AI_VOICE_MCP_PUBLIC_URL=https://voice-mcp.example.com` and `AI_VOICE_ALLOWED_ORIGINS=https://claude.ai,https://chatgpt.com,https://app.getdot.ai` in `.env`.
2. In your connector settings:
   - **Server URL**: `https://voice-mcp.example.com/mcp`
   - **Authentication**: Select **Bearer Token / API Key** (pass `AI_VOICE_MCP_TOKEN`) or **OAuth 2.1** (if fronted by Cloudflare Access / Auth0 / Pocket-ID with `AI_VOICE_OAUTH_ISSUER_URL` set).

### B. Desktop (`stdio` or SSH-Tunneled `stdio`)
For **Claude Desktop** (`claude_desktop_config.json`), **Cursor**, or **Antigravity**:

**Local `stdio` (when SIP/RTP runs on the same desktop):**
```json
{
  "mcpServers": {
    "ai-assistant-voice": {
      "command": "ai-assistant-voice",
      "args": ["--transport", "stdio"]
    }
  }
}
```

**SSH-Tunneled `stdio` (Recommended hybrid when `ai-assistant-voice` runs on a remote Linux host with a static public IP for SIP/SRTP, while your agent runs on your laptop):**
```json
{
  "mcpServers": {
    "ai-assistant-voice": {
      "command": "ssh",
      "args": [
        "-q",
        "voice-operator@voice-host.example.com",
        "docker", "exec", "-i", "ai-assistant-voice",
        "ai-assistant-voice", "--transport", "stdio"
      ]
    }
  }
}
```
This hybrid pattern gives you a **zero-exposed-HTTP-port** MCP connection authenticated by your SSH Ed25519 key while keeping the SIP-TLS and SRTP UDP ports anchored on your server.
