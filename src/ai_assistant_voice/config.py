"""Configuration loader using environment variables and platform conventions.

Never hardcodes user paths or secrets; redacts sensitive fields in string representations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path


def _read_secret(name: str, env_var: str, default: str = "") -> str:
    """Read a secret from SECRETS_DIR/<name> if mounted, falling back to environment variable."""
    secrets_dir = Path(os.environ.get("SECRETS_DIR", "/run/secrets"))
    secret_file = secrets_dir / name
    try:
        if secret_file.is_file():
            return secret_file.read_text(encoding="utf-8").strip()
    except OSError:
        pass
    return os.environ.get(env_var, default).strip()


def _default_data_dir() -> Path:
    env_dir = os.environ.get("AI_VOICE_DATA_DIR", "").strip()
    if env_dir:
        return Path(env_dir).expanduser().resolve()
    xdg = os.environ.get("XDG_DATA_HOME", "").strip()
    base = Path(xdg).expanduser() if xdg else (Path.home() / ".local" / "share")
    return (base / "ai-assistant-voice").resolve()


@dataclass
class VoiceSettings:
    data_dir: Path = field(default_factory=_default_data_dir)
    db_path: Path | None = None
    enabled: bool = True
    sip_server: str = "washington2.voip.ms"
    sip_port: int = 5061
    sip_transport: str = "tls"
    srtp_enabled: bool = True
    sip_username: str = ""
    sip_password: str = field(default="", repr=False)
    sip_display_name: str = "Lexie"
    did_number: str = ""
    rtp_port_start: int = 10000
    rtp_port_end: int = 10050

    voice_provider: str = "gemini_live"
    voice_model: str = "models/gemini-3.8-live"
    voice_name: str = "Aoede"
    gemini_api_key: str = field(default="", repr=False)
    xai_api_key: str = field(default="", repr=False)
    openai_api_key: str = field(default="", repr=False)

    assistant_name: str = "Lexie"
    company_name: str = "Our Office"
    company_brief: str = ""
    owner_transfer_number: str = ""
    dead_air_timeout_seconds: float = 4.5

    mcp_transport: str = "stdio"
    mcp_host: str = "127.0.0.1"
    mcp_port: int = 8400
    mcp_auth_token: str = field(default="", repr=False)
    mcp_public_url: str = ""
    oauth_issuer_url: str = ""
    allowed_origins: tuple[str, ...] = ()

    allow_international: bool = False
    allowed_country_prefixes: tuple[str, ...] = ("+1",)
    outbound_allowlist: tuple[str, ...] = ()
    max_calls_per_hour: int = 20
    max_sms_per_hour: int = 40
    max_call_duration_seconds: int = 900
    max_concurrent_calls: int = 2

    def __post_init__(self) -> None:
        self.data_dir = Path(self.data_dir)
        if self.db_path is None:
            self.db_path = self.data_dir / "voice_state.db"
        else:
            self.db_path = Path(self.db_path)

    def validate_security_posture(self) -> None:
        """Fail-closed startup check when exposing HTTP MCP on a non-loopback address."""
        if self.mcp_transport == "http":
            loopback_hosts = {"127.0.0.1", "localhost", "::1"}
            if self.mcp_host not in loopback_hosts and len(self.mcp_auth_token) < 32:
                raise RuntimeError(
                    f"Refusing to bind HTTP MCP server to non-loopback address ({self.mcp_host}) "
                    "without a high-entropy AI_VOICE_MCP_TOKEN (>= 32 characters)."
                )

    @classmethod
    def from_env(cls) -> VoiceSettings:
        raw_origins = os.environ.get("AI_VOICE_ALLOWED_ORIGINS", "")
        origins = tuple(o.strip().rstrip("/") for o in raw_origins.split(",") if o.strip())
        raw_allowlist = os.environ.get("AI_VOICE_OUTBOUND_ALLOWLIST", "")
        allowlist = tuple(a.strip() for a in raw_allowlist.split(",") if a.strip())
        raw_prefixes = os.environ.get("AI_VOICE_ALLOWED_PREFIXES", "+1")
        prefixes = tuple(p.strip() for p in raw_prefixes.split(",") if p.strip()) or ("+1",)

        data_dir = _default_data_dir()
        raw_db = os.environ.get("AI_VOICE_DB_PATH", "").strip()
        db_path = Path(raw_db).expanduser().resolve() if raw_db else (data_dir / "voice_state.db")

        return cls(
            data_dir=data_dir,
            db_path=db_path,
            enabled=os.environ.get("AI_VOICE_ENABLED", "true").lower() in ("1", "true", "yes"),
            sip_server=(
                os.environ.get("AI_VOICE_SIP_SERVER")
                or os.environ.get("VOIPMS_SIP_SERVER")
                or "washington2.voip.ms"
            ).strip(),
            sip_port=int(
                os.environ.get("AI_VOICE_SIP_PORT")
                or os.environ.get("VOIPMS_SIP_PORT")
                or "5061"
            ),
            sip_transport=(
                os.environ.get("AI_VOICE_SIP_TRANSPORT")
                or os.environ.get("VOIPMS_SIP_TRANSPORT")
                or "tls"
            ).strip().lower(),
            srtp_enabled=os.environ.get("AI_VOICE_SRTP_ENABLED", "true").lower() in ("1", "true", "yes"),
            sip_username=_read_secret("voipms_sip_username", "AI_VOICE_SIP_USERNAME")
            or _read_secret("voipms_sip_username", "VOIPMS_SIP_USERNAME"),
            sip_password=_read_secret("voipms_sip_password", "AI_VOICE_SIP_PASSWORD")
            or _read_secret("voipms_sip_password", "VOIPMS_SIP_PASSWORD"),
            sip_display_name=os.environ.get("AI_VOICE_SIP_DISPLAY_NAME", "Lexie").strip(),
            did_number=(
                os.environ.get("AI_VOICE_CALLER_ID")
                or os.environ.get("VOIPMS_DID")
                or ""
            ).strip(),
            rtp_port_start=int(os.environ.get("AI_VOICE_RTP_PORT_START", "10000")),
            rtp_port_end=int(os.environ.get("AI_VOICE_RTP_PORT_END", "10050")),
            voice_provider=os.environ.get("AI_VOICE_PROVIDER", "gemini_live").strip().lower(),
            voice_model=os.environ.get("AI_VOICE_MODEL", "models/gemini-3.8-live").strip(),
            voice_name=os.environ.get("AI_VOICE_NAME", "Aoede").strip(),
            gemini_api_key=_read_secret("gemini_api_key", "GEMINI_API_KEY"),
            xai_api_key=_read_secret("xai_api_key", "XAI_API_KEY"),
            openai_api_key=_read_secret("openai_api_key", "OPENAI_API_KEY"),
            assistant_name=os.environ.get("AI_VOICE_ASSISTANT_NAME", "Lexie").strip(),
            company_name=os.environ.get("AI_VOICE_COMPANY_NAME", "Our Office").strip(),
            company_brief=os.environ.get("AI_VOICE_COMPANY_BRIEF", "").strip(),
            owner_transfer_number=os.environ.get("AI_VOICE_TRANSFER_TARGET", "").strip(),
            dead_air_timeout_seconds=float(os.environ.get("AI_VOICE_DEAD_AIR_SECONDS", "4.5")),
            mcp_transport=(
                os.environ.get("AI_VOICE_MCP_TRANSPORT")
                or os.environ.get("AI_VOICE_TRANSPORT")
                or "stdio"
            ).strip().lower(),
            mcp_host=(
                os.environ.get("AI_VOICE_MCP_HOST")
                or os.environ.get("AI_VOICE_BIND_HOST")
                or "127.0.0.1"
            ).strip(),
            mcp_port=int(
                os.environ.get("AI_VOICE_MCP_PORT")
                or os.environ.get("AI_VOICE_BIND_PORT")
                or "8400"
            ),
            mcp_auth_token=_read_secret("ai_voice_mcp_token", "AI_VOICE_MCP_TOKEN"),
            mcp_public_url=(
                os.environ.get("AI_VOICE_MCP_PUBLIC_URL")
                or os.environ.get("AI_VOICE_PUBLIC_ORIGIN")
                or ""
            ).strip().rstrip("/"),
            oauth_issuer_url=(
                os.environ.get("AI_VOICE_OAUTH_ISSUER_URL")
                or os.environ.get("AI_VOICE_OAUTH_ISSUER")
                or ""
            ).strip().rstrip("/"),
            allowed_origins=origins,
            allow_international=os.environ.get("AI_VOICE_ALLOW_INTERNATIONAL", "false").lower() in ("1", "true", "yes"),
            allowed_country_prefixes=prefixes,
            outbound_allowlist=allowlist,
            max_calls_per_hour=max(1, int(os.environ.get("AI_VOICE_MAX_CALLS_PER_HOUR", "20"))),
            max_sms_per_hour=max(1, int(os.environ.get("AI_VOICE_MAX_SMS_PER_HOUR", "40"))),
            max_call_duration_seconds=max(30, int(os.environ.get("AI_VOICE_MAX_CALL_DURATION", "900"))),
            max_concurrent_calls=max(1, int(os.environ.get("AI_VOICE_MAX_CONCURRENT_CALLS", "2"))),
        )
