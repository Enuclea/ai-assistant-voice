"""Security controls: PSTN toll-fraud protection, SIP header sanitization,
Context Firewall untrusted wrapping, prompt-injection detection, rate limiting,
and constant-time Bearer/Origin authentication.
"""

from __future__ import annotations

from collections import deque
import hmac
import ipaddress
import re
import time

# Emergency numbers that an AI agent must NEVER dial autonomously
EMERGENCY_NUMBERS = frozenset({
    "911", "112", "999", "988", "933", "000", "119",
    "+1911", "+1988", "+1933", "+1112", "+1999",
})

# NANPA premium-rate / high-fraud area codes (1-900, 1-976, and pay-per-call Caribbean NPAs)
PREMIUM_OR_HIGH_RISK_NPAS = frozenset({
    "900",
    "976",
    "809",
    "829",
    "849",
    "876",
    "658",
    "473",
    "284",
    "649",
    "664",
    "268",
    "242",
    "246",
    "345",
    "767",
    "758",
    "784",
    "868",
    "869",
})

_INJECTION_PATTERNS = (
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)", re.I),
    re.compile(r"system\s*prompt|developer\s*mode|jailbreak|do\s+anything\s+now", re.I),
    re.compile(r"disregard\s+(your|all)\s+(instructions|guardrails|constraints)", re.I),
    re.compile(r"(reveal|read\s+out|text\s+me|send\s+me)\s+(all\s+)?(passwords|api\s*keys|secrets|tokens|ssn)", re.I),
    re.compile(r"<\s*/?\s*untrusted_pstn_content\s*>", re.I),
)


class SecurityPolicyError(ValueError):
    """Raised when an action violates PSTN security, rate-limit, or auth policies."""


def sanitize_sip_token(value: str, *, max_len: int = 128, max_length: int | None = None) -> str:
    """Strip CR/LF, control characters, and header-splitting characters from SIP fields."""
    limit = max_length if max_length is not None else max_len
    cleaned = re.sub(r"[\r\n\x00-\x1f\x7f<>\\]", "", str(value or "")).strip()
    return cleaned[:limit]


def normalize_phone(raw: str) -> str:
    """Normalize a phone string or SIP URI into strict E.164 format (+1XXXXXXXXXX)."""
    if not raw:
        return ""
    s = str(raw).strip()
    if s.lower().startswith("sip:"):
        s = s[4:].split("@", 1)[0].split(";", 1)[0]
    digits = re.sub(r"\D", "", s)
    if digits in ("911", "112", "999", "988", "933", "000", "119"):
        return digits
    if not digits:
        return ""
    if len(digits) == 10:
        return f"+1{digits}"
    if len(digits) == 11 and digits.startswith("1"):
        return f"+{digits}"
    if 7 <= len(digits) <= 15:
        return f"+{digits}"
    return ""


def validate_outbound_destination(
    raw_number: str,
    *,
    allow_international: bool = False,
    allowed_country_prefixes: tuple[str, ...] = ("+1",),
    allowlist: tuple[str, ...] = (),
) -> str:
    """Validate an outbound phone destination against emergency, toll-fraud, and allowlist rules."""
    clean_raw = re.sub(r"\D", "", str(raw_number or ""))
    if clean_raw in EMERGENCY_NUMBERS or raw_number.strip() in EMERGENCY_NUMBERS:
        raise SecurityPolicyError(
            "Emergency numbers (911/112/999/988) are strictly prohibited."
        )

    norm = normalize_phone(raw_number)
    if not norm or norm in EMERGENCY_NUMBERS:
        raise SecurityPolicyError(f"Invalid or Emergency phone number: {raw_number!r}")

    digits = norm.lstrip("+")
    if digits.startswith("1") and len(digits) == 11:
        npa = digits[1:4]
        nxx = digits[4:7]
        if (
            npa in PREMIUM_OR_HIGH_RISK_NPAS
            or nxx == "976"
            or digits[1:4] == "911"
            or digits[4:7] == "911"
        ):
            raise SecurityPolicyError(
                f"Premium-rate or high-fraud NPA ({npa}/{nxx}) is blocked."
            )
    elif not allow_international:
        raise SecurityPolicyError(
            f"International outbound dialing ({norm}) is disabled by default. "
            "Set AI_VOICE_ALLOW_INTERNATIONAL=true to permit non-NANPA (+1) destinations."
        )
    elif allowed_country_prefixes:
        if not any(norm.startswith(p) for p in allowed_country_prefixes):
            raise SecurityPolicyError(
                f"International destination {norm} does not match allowed prefixes {allowed_country_prefixes}."
            )

    if allowlist:
        normalized_allow = [normalize_phone(a) or a.strip() for a in allowlist if a.strip()]
        if not any(norm == allowed or norm.startswith(allowed) for allowed in normalized_allow):
            raise SecurityPolicyError(f"Destination {norm} is not in AI_VOICE_OUTBOUND_ALLOWLIST.")

    return norm


def detect_prompt_injection(text: str) -> list[str]:
    """Scan untrusted PSTN speech or SMS text for prompt-injection attempts."""
    if not text:
        return []
    flags: list[str] = []
    for pat in _INJECTION_PATTERNS:
        if pat.search(text):
            flags.append("prompt_injection_pattern")
            break
    return flags


def wrap_untrusted_pstn(source_or_text: str, text: str | None = None) -> str:
    """Wrap untrusted caller audio transcripts or SMS bodies so the outer LLM treats them strictly as data."""
    if text is None:
        raw_text = source_or_text
        safe_body = re.sub(
            r"<\s*/?\s*untrusted_pstn_(?:speech|content)\s*>",
            "[redacted-tag]",
            raw_text or "",
            flags=re.I,
        ).strip()
        return f"<untrusted_pstn_speech>{safe_body}</untrusted_pstn_speech>"
    safe_source = re.sub(r"[^a-zA-Z0-9:+._-]", "", source_or_text or "pstn")[:64]
    safe_body = re.sub(
        r"<\s*/?\s*untrusted_pstn_(?:speech|content)\s*>",
        "[redacted-tag]",
        text or "",
        flags=re.I,
    ).strip()
    return f'<untrusted_pstn_content source="{safe_source}">\n{safe_body}\n</untrusted_pstn_content>'


def sanitize_call_brief_facts(allowed_facts: dict[str, str] | None) -> dict[str, str]:
    """Sanitize key/value facts passed into the Context Firewall for an outbound call."""
    if not allowed_facts or not isinstance(allowed_facts, dict):
        return {}
    out: dict[str, str] = {}
    for idx, (k, v) in enumerate(allowed_facts.items()):
        if idx >= 20:
            break
        clean_k = re.sub(r"[^a-zA-Z0-9_ -]", "", str(k or "")).strip()[:64]
        clean_v = re.sub(r"[\r\n\x00-\x1f]", " ", str(v or "")).strip()[:300]
        if clean_k and clean_v:
            out[clean_k] = clean_v
    return out


def verify_bearer_token(auth_header: str | None, expected_token: str) -> bool:
    """Constant-time verification of a Bearer token."""
    if not expected_token or len(expected_token) < 16:
        return False
    supplied = (auth_header or "").strip()
    if not supplied.lower().startswith("bearer "):
        return False
    token = supplied[7:].strip()
    return hmac.compare_digest(token.encode("utf-8"), expected_token.encode("utf-8"))


def verify_origin(origin_header: str | None, allowed_origins: tuple[str, ...]) -> bool:
    """Validate HTTP Origin header when present to prevent browser-based DNS rebinding / CSRF against MCP."""
    if not origin_header:
        return True
    clean_origin = origin_header.strip().rstrip("/").lower()
    if not allowed_origins:
        return clean_origin in ("http://localhost", "http://127.0.0.1", "https://localhost")
    return clean_origin in {o.lower().rstrip("/") for o in allowed_origins}


def is_trusted_rtp_peer(candidate_ip: str, negotiated_ip: str) -> bool:
    """Verify Symmetric RTP peer IP matches the SDP-negotiated IP or shares its carrier /24 subnet."""
    if not candidate_ip or not negotiated_ip:
        return False
    if candidate_ip == negotiated_ip:
        return True
    try:
        cand = ipaddress.ip_address(candidate_ip)
        neg = ipaddress.ip_address(negotiated_ip)
        if cand.version == 4 and neg.version == 4:
            net = ipaddress.ip_network(f"{negotiated_ip}/24", strict=False)
            return cand in net
    except ValueError:
        return False
    return False


class SlidingWindowRateLimiter:
    """In-memory sliding-window rate limiter for outbound PSTN calls and SMS messages."""

    def __init__(self, max_events: int, window_seconds: float = 3600.0) -> None:
        self.max_events = max(1, int(max_events))
        self.window_seconds = float(window_seconds)
        self._timestamps: deque[float] = deque()

    def _prune(self) -> None:
        cutoff = time.monotonic() - self.window_seconds
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.popleft()

    def allow(self, _action_label: str = "outbound") -> bool:
        self._prune()
        if len(self._timestamps) >= self.max_events:
            return False
        self._timestamps.append(time.monotonic())
        return True

    def remaining(self, _action_label: str = "outbound") -> int:
        self._prune()
        return max(0, self.max_events - len(self._timestamps))

    def check_and_record(self, action_label: str = "outbound") -> None:
        if not self.allow(action_label):
            raise SecurityPolicyError(
                f"Rate limit exceeded for {action_label}: max {self.max_events} per {int(self.window_seconds)}s."
            )
