# VoIP Provider Requirements & VoIP.ms Configuration Guide

`ai-assistant-voice` speaks standard **SIP/2.0 (RFC 3261)** and **RTP/SRTP (RFC 3550 / RFC 3711)** directly to your SIP trunk—meaning you do not need proprietary WebRTC gateways, Asterisk/FreeSWITCH PBXs, or high-markup voice middleware.

---

## 1. What Is Required from a VoIP Provider

To support the full feature set (encrypted inbound/outbound voice, IVR DTMF navigation, blind call transfer, and SMS/2FA reception), your VoIP trunk provider should support the following standards:

| Requirement | Standard / Protocol | Required vs. Optional | Why It Matters |
| :--- | :--- | :--- | :--- |
| **SIP Registration & Digest Auth** | RFC 3261 / RFC 2617 (`MD5` / `qop=auth`) | **Required** | Authenticates inbound and outbound `REGISTER`, `INVITE`, and `MESSAGE` requests without static IP lock-in. |
| **SIP over TLS (`sips` / port `5061`)** | TLS 1.2 / 1.3 over TCP `5061` | **Strongly Recommended** (Default) | Encrypts SIP signaling headers, phone numbers, SMS bodies (`SIP MESSAGE`), and SDES SRTP master keys in transit. |
| **SDES SRTP Media Encryption** | RFC 4568 (`AES_CM_128_HMAC_SHA1_80`) | **Strongly Recommended** (Default) | Encrypts and authenticates every 20ms UDP audio packet so voice traffic cannot be eavesdropped or tampered with. |
| **G.711 $\mu$-law Codec (`PCMU`)** | ITU-T G.711 (`PT 0`, 8000 Hz, 20ms `ptime`) | **Required** | Uncompressed toll-quality narrowband audio supported universally by all North American and global carriers. |
| **Out-of-Band DTMF Events** | RFC 4733 / RFC 2833 (`telephone-event/8000`, `PT 101`) | **Required** | Reliably navigates remote IVR menus and extensions (`send_dtmf`). `ai-assistant-voice` also transmits in-band dual-tone audio for legacy PBXs. |
| **Inbound & Outbound SMS** | RFC 3428 (`SIP MESSAGE`) or HTTPS Webhook/REST | **Optional** (Required for SMS/2FA) | Delivers inbound SMS (including 2FA/OTP codes) directly over the existing SIP-TLS socket without polling. |
| **Blind Call Transfer** | RFC 3515 (`SIP REFER`) | **Optional** (Required for VIP Transfer) | Allows the inbound AI receptionist to transfer VIP callers directly to your mobile or internal extension. |
| **International / Premium Call Blocking** | Provider-side spending cap & international lock | **Strongly Recommended** | Defense-in-depth backup to `ai-assistant-voice`'s local toll-fraud firewall (`AI_VOICE_ALLOW_INTERNATIONAL=false`). |

### Compatible Providers
- **VoIP.ms** *(Recommended — supports SIP-TLS 5061, SDES SRTP, G.711u, RFC 4733 DTMF, SIP REFER, and native bidirectional `SIP MESSAGE` SMS on the same subaccount)*
- **Telnyx** *(Supports SIP-TLS, SRTP, G.711u, RFC 4733 DTMF, and webhook/REST SMS)*
- **Twilio Elastic SIP Trunking** *(Supports SIP-TLS + SRTP)*
- **Flowroute / Bandwidth** *(Supports SIP-TLS + SRTP)*

---

## 2. Step-by-Step Setup for VoIP.ms

### Step 1: Create a Dedicated SIP Subaccount
1. Log in to the **VoIP.ms Portal** and navigate to **Sub Accounts → Create Sub Account**.
2. Configure the following settings:
   - **Authentication Type**: `User/Password Authentication`
   - **Username**: e.g., `123456_voiceagent` (your 6-digit account ID + underscore + subaccount suffix)
   - **Password**: Generate a strong 24+ character password
   - **Device Type**: `Asterisk, IP PBX, Gateway or VoIP Switch` (so Caller ID and `SIP MESSAGE` pass through cleanly)
   - **CallerID Number**: Choose **"I will use a system default CallerID number"** (and select your DID) or **"I use a system capable of passing its own CallerID"**
   - **Allowed Codecs**: Check **`G.711u (ulaw)`** (you may uncheck `G.729` and `GSM` to force clean `PCMU/8000` negotiation)
   - **DTMF Mode**: **`RFC2833`** (or `Auto`)
   - **NAT**: **`yes`**
   - **Encrypted SIP Traffic (TLS)**: **`Yes`**
   - **Encrypted Audio (SRTP)**: **`Yes`**
   - **International Calls**: **`Disable`** (recommended unless you explicitly need international calling)
   - **Max Channels**: `2` (matches `AI_VOICE_MAX_CONCURRENT_CALLS=2`)

### Step 2: Configure Your DID & Point It to the Subaccount
1. Navigate to **DID Numbers → Manage DID(s)** and edit your DID number:
   - **Routing**: Select **SIP/IAX Sub Account** and pick `123456_voiceagent`.
   - **DID Point of Presence (POP) Server**: Pick the POP closest to your server (e.g., `washington2.voip.ms`, `newyork1.voip.ms`, `chicago1.voip.ms`).
     > **Important:** Your `AI_VOICE_SIP_SERVER` in `.env` **must match** the exact POP server selected on your DID so inbound calls and `SIP MESSAGE` texts route down the registered TLS socket.

### Step 3: Enable SMS via `SIP MESSAGE` on the DID
1. Still in **DID Numbers → Manage DID(s)**, scroll to the **SMS / MMS (Message Service)** section:
   - **Enable SMS/MMS**: Checked (`Yes`)
   - **SMS SIP Account**: Enable and select your subaccount (`123456_voiceagent`).
2. Save the DID settings. Both inbound and outbound SMS messages will now flow over your encrypted `SIP/TLS 5061` connection using standard `SIP MESSAGE` packets.

### Step 4: Network / Firewall Requirements on Your Host
- **Outbound TCP `5061`**: Must be allowed to `<pop>.voip.ms:5061` (for SIP-TLS registration and signaling).
- **Inbound/Outbound UDP `10000–10050`**: Must be forwarded/allowed on your host firewall so symmetric SRTP media packets from the VoIP.ms POP can reach `CallRTPSession`.
- **Public IP (`AI_VOICE_PUBLIC_IP`)**: Set to your host's public IPv4 address so the SDP `c=IN IP4 <ip>` line tells VoIP.ms where to send encrypted SRTP audio.

---

## 3. Complete VoIP.ms Example Configuration (`.env`)

```dotenv
# ============================================================================
# VoIP.ms SIP over TLS + SDES SRTP Configuration
# ============================================================================
AI_VOICE_SIP_SERVER=washington2.voip.ms
AI_VOICE_SIP_PORT=5061
AI_VOICE_SIP_TRANSPORT=tls
AI_VOICE_SRTP_ENABLED=true

# Subaccount credentials (from VoIP.ms -> Sub Accounts)
AI_VOICE_SIP_USERNAME=123456_voiceagent
AI_VOICE_SIP_PASSWORD=REPLACE_WITH_VOIPMS_SUBACCOUNT_PASSWORD
AI_VOICE_SIP_DISPLAY_NAME=Lexie Assistant

# Your 10-digit or E.164 VoIP.ms DID number
AI_VOICE_CALLER_ID=+12025550199

# Operator extension or number for VIP blind transfers (SIP REFER)
AI_VOICE_TRANSFER_TARGET=100

# Host network settings for SDP negotiation & SRTP UDP ports
AI_VOICE_PUBLIC_IP=203.0.113.10
AI_VOICE_RTP_PORT_START=10000
AI_VOICE_RTP_PORT_END=10050

# ============================================================================
# Realtime Audio-to-Audio LLM Configuration
# ============================================================================
AI_VOICE_PROVIDER=gemini_live
AI_VOICE_MODEL=models/gemini-3.8-live
AI_VOICE_NAME=Aoede
GEMINI_API_KEY=REPLACE_WITH_GEMINI_API_KEY

# ============================================================================
# Security & Rate-Limiting Guardrails (Safe Defaults)
# ============================================================================
AI_VOICE_ALLOW_INTERNATIONAL=false
AI_VOICE_ALLOWED_PREFIXES=+1
AI_VOICE_MAX_CALLS_PER_HOUR=20
AI_VOICE_MAX_SMS_PER_HOUR=40
AI_VOICE_MAX_CALL_DURATION=900
AI_VOICE_MAX_CONCURRENT_CALLS=2

# ============================================================================
# MCP Transport Configuration
# ============================================================================
# Use 'stdio' for Desktop agents or 'http' for Provider-Hosted cloud agents
AI_VOICE_MCP_TRANSPORT=stdio
AI_VOICE_MCP_HOST=127.0.0.1
AI_VOICE_MCP_PORT=8400
AI_VOICE_MCP_TOKEN=REPLACE_WITH_32_BYTE_HIGH_ENTROPY_BEARER_SECRET
```
