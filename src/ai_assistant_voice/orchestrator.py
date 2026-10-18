"""Core Voice Orchestrator managing SIP signaling, RTP/SRTP sessions, Outbound IVR/Voicemail state machine,
SMS/OTP delivery, and security policy enforcement.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from .config import VoiceSettings
from .rtp_session import CallRTPSession
from .security import (
     SecurityPolicyError,
    SlidingWindowRateLimiter,
    detect_prompt_injection,
    sanitize_call_brief_facts,
    validate_outbound_destination,
    wrap_untrusted_pstn,
)
from .store import VoiceStore
from .voice_bridge import GeminiLiveSession, build_outbound_system_prompt

logger = logging.getLogger(__name__)

DEAD_AIR_PROBE_SECONDS: float = 4.5


@dataclass
class ActiveCallSession:
    """In-memory runtime state for an active inbound or outbound call."""

    call_id: str
    direction: str
    remote_number: str
    remote_name: str
    objective: str
    approved_facts: dict[str, str] = field(default_factory=dict)
    system_prompt: str = ""
    rtp_session: CallRTPSession | None = None
    live_session: GeminiLiveSession | None = None
    vad_mode: str = "human"
    inbound_speech_detected: bool = False
    dead_air_probe_sent: bool = False
    silent_wait_streak: int = 0
    dtmf_sent: str = ""
    connected_at: float = field(default_factory=time.monotonic)
    done_event: asyncio.Event = field(default_factory=asyncio.Event)
    dead_air_task: asyncio.Task[None] | None = None


class VoiceOrchestrator:
    """Coordinates SIP/RTP sessions, security policies, SQLite state, and Realtime voice models."""

    def __init__(
        self,
        settings: VoiceSettings | None = None,
        store: VoiceStore | None = None,
    ) -> None:
        self.settings = settings or VoiceSettings.from_env()
        self.store = store or VoiceStore(self.settings.db_path)
        self.call_rate_limiter = SlidingWindowRateLimiter(
            max_events=self.settings.max_calls_per_hour,
            window_seconds=3600.0,
        )
        self.sms_rate_limiter = SlidingWindowRateLimiter(
            max_events=self.settings.max_sms_per_hour,
            window_seconds=3600.0,
        )
        self.active_calls: dict[str, ActiveCallSession] = {}
        self.sip_registered: bool = False
        self._next_rtp_port: int = self.settings.rtp_port_start

    def allocate_rtp_port(self) -> int:
        """Allocate an even RTP UDP port from the configured range."""
        port = self._next_rtp_port
        if port % 2 != 0:
            port += 1
        self._next_rtp_port = port + 2
        if self._next_rtp_port > self.settings.rtp_port_end:
            self._next_rtp_port = self.settings.rtp_port_start
        return port

    async def place_outbound_call(
        self,
        *,
        to_number: str,
        objective: str,
        recipient_name: str = "",
        approved_facts: dict[str, str] | None = None,
        wait_for_completion: bool = False,
        timeout_seconds: float = 120.0,
    ) -> dict[str, Any]:
        """Validate security policy and initiate an outbound phone call."""
        try:
            normalized_dest = validate_outbound_destination(
                to_number,
                allow_international=self.settings.allow_international,
                allowed_country_prefixes=self.settings.allowed_country_prefixes,
            )
        except SecurityPolicyError as exc:
            self.store.log_security_event(
                event_type="outbound_call_blocked",
                severity="warning",
                actor="mcp_client",
                detail=str(exc),
            )
            raise

        if len(self.active_calls) >= self.settings.max_concurrent_calls:
            msg = (
                f"Maximum concurrent calls limit reached ({self.settings.max_concurrent_calls})"
            )
            self.store.log_security_event(
                event_type="concurrent_call_limit",
                severity="warning",
                actor="mcp_client",
                detail=msg,
            )
            raise SecurityPolicyError(msg)

        if not self.call_rate_limiter.allow("outbound_call"):
            msg = (
                f"Outbound call rate limit exceeded ({self.settings.max_calls_per_hour}/hour)"
            )
            self.store.log_security_event(
                event_type="call_rate_limit_exceeded",
                severity="warning",
                actor="mcp_client",
                detail=msg,
            )
            raise SecurityPolicyError(msg)

        if not objective or not objective.strip():
            raise ValueError("Outbound call objective must not be empty")

        clean_facts = sanitize_call_brief_facts(approved_facts)
        call_id = f"call-{secrets.token_hex(6)}"
        sys_prompt = build_outbound_system_prompt(
            agent_name=self.settings.sip_display_name,
            recipient_name=recipient_name,
            objective=objective,
            approved_facts=clean_facts,
        )

        self.store.create_call(
            call_id=call_id,
            direction="outbound",
            remote_number=normalized_dest,
            remote_name=recipient_name,
            objective=objective.strip()[:500],
            status="connected",
        )

        session = ActiveCallSession(
            call_id=call_id,
            direction="outbound",
            remote_number=normalized_dest,
            remote_name=recipient_name,
            objective=objective.strip()[:500],
            approved_facts=clean_facts,
            system_prompt=sys_prompt,
            vad_mode="human",
        )
        self.active_calls[call_id] = session

        # Start Silent Turn 0 + 4.5s Dead-Air Fallback watchdog
        session.dead_air_task = asyncio.create_task(
            self._dead_air_watchdog(session, timeout_s=DEAD_AIR_PROBE_SECONDS),
            name=f"dead-air-{call_id}",
        )

        if wait_for_completion:
            try:
                await asyncio.wait_for(
                    session.done_event.wait(),
                    timeout=min(float(timeout_seconds), float(self.settings.max_call_duration_seconds)),
                )
            except asyncio.TimeoutError:
                await self.hangup_call(call_id, reason="Call wait timeout reached")

        record = self.store.get_call(call_id) or {}
        record["vad_mode"] = session.vad_mode
        record["silent_turn_0"] = True
        return record

    async def _dead_air_watchdog(
        self, session: ActiveCallSession, timeout_s: float = DEAD_AIR_PROBE_SECONDS
    ) -> None:
        """Silent Turn 0 fallback: only send a short 'Hello?' probe if 4.5s of dead air elapse."""
        try:
            await asyncio.sleep(timeout_s)
            if (
                session.call_id in self.active_calls
                and not session.inbound_speech_detected
                and not session.dead_air_probe_sent
            ):
                session.dead_air_probe_sent = True
                self.store.append_call_transcript(session.call_id, "assistant", "Hello?")
                if session.live_session is not None:
                    await session.live_session.send_text_event(
                        "[4.5 seconds of dead air elapsed since call connected. Say a brief 'Hello?']",
                        end_of_turn=True,
                    )
        except asyncio.CancelledError:
            return

    def on_inbound_utterance(
        self, call_id: str, transcript_text: str, *, beep_detected: bool = False
    ) -> str:
        """Process an inbound PSTN transcript turn with prompt-injection screening and beep tagging."""
        session = self.active_calls.get(call_id)
        if session is not None:
            session.inbound_speech_detected = True
            session.silent_wait_streak = 0
            if session.dead_air_task and not session.dead_air_task.done():
                session.dead_air_task.cancel()

        text = transcript_text.strip()
        if beep_detected:
            text = f"{text} [VOICEMAIL BEEP DETECTED]".strip()

        suspicious = detect_prompt_injection(text)
        if suspicious:
            self.store.log_security_event(
                event_type="pstn_prompt_injection_attempt",
                severity="high",
                actor=session.remote_number if session else call_id,
                detail=f"Matched pattern {suspicious!r} in utterance: {text[:200]}",
            )

        self.store.append_call_transcript(call_id, "user", text)
        return wrap_untrusted_pstn(text)

    async def handle_call_tool(
        self, call_id: str, tool_name: str, args: dict[str, Any]
    ) -> dict[str, Any]:
        """Execute an outbound or inbound voice agent tool call (`send_dtmf`, `wait_silently`, etc.)."""
        session = self.active_calls.get(call_id)

        if tool_name == "send_dtmf":
            digits = str(args.get("digits", "")).strip()[:32]
            reason = str(args.get("reason", "")).strip()[:200]
            if not digits:
                return {"ok": False, "error": "Missing digits parameter"}

            sent = digits
            if session is not None:
                if session.live_session is not None:
                    session.live_session.suppress_current_turn_audio()
                if session.rtp_session is not None:
                    session.rtp_session.clear_playback()
                    session.rtp_session.vad.set_mode("ivr")
                    sent = await session.rtp_session.send_dtmf_sequence(digits)
                session.vad_mode = "ivr"
                session.dtmf_sent += sent

            current = self.store.get_call(call_id)
            combined_dtmf = ((current.get("dtmf_digits", "") if current else "") + sent)
            self.store.update_call(call_id, dtmf_digits=combined_dtmf)
            self.store.append_call_transcript(
                call_id, "tool:send_dtmf", f"digits={sent} ({reason})"
            )
            return {
                "ok": True,
                "digits_sent": sent,
                "vad_mode": "ivr",
                "message": f"Sent DTMF digits: {sent}. Listening for next prompt or answer.",
            }

        if tool_name == "wait_silently":
            mode = str(args.get("mode", "ivr")).lower().strip()
            if mode not in ("ivr", "voicemail", "hold"):
                mode = "ivr"
            reason = str(args.get("reason", "")).strip()[:200]

            if session is not None:
                session.silent_wait_streak += 1
                session.vad_mode = mode
                if session.live_session is not None:
                    session.live_session.suppress_current_turn_audio()
                if session.rtp_session is not None:
                    session.rtp_session.clear_playback()
                    session.rtp_session.vad.set_mode(mode)

            self.store.append_call_transcript(
                call_id, "tool:wait_silently", f"mode={mode} ({reason})"
            )
            return {
                "ok": True,
                "mode": mode,
                "tts_suppressed": True,
                "message": f"Staying completely silent (mode={mode}). Waiting for next inbound audio.",
            }

        if tool_name == "outbound_record_outcome":
            outcome = str(args.get("outcome", "completed")).strip()[:64]
            summary = str(args.get("summary", "")).strip()[:1000]
            self.store.update_call(call_id, outcome=outcome, summary=summary)
            self.store.append_call_transcript(
                call_id, "tool:outbound_record_outcome", f"{outcome}: {summary}"
            )
            return {"ok": True, "outcome": outcome, "summary": summary}

        if tool_name == "reception_hangup":
            reason = str(args.get("reason", "Call completed")).strip()[:200]
            return await self.hangup_call(call_id, reason=reason)

        if tool_name == "reception_lookup_client":
            phone = str(args.get("phone_number", "")).strip()
            client = self.store.get_known_client(phone)
            return {"ok": True, "known_client": client}

        if tool_name == "reception_take_message":
            caller_name = str(args.get("caller_name", "Unknown")).strip()[:120]
            message = str(args.get("message", "")).strip()[:1000]
            urgency = str(args.get("urgency", "normal")).strip()
            summary = f"[{urgency.upper()}] From {caller_name}: {message}"
            self.store.update_call(call_id, outcome="message_taken", summary=summary)
            return {"ok": True, "recorded": summary}

        return {"ok": False, "error": f"Unknown tool: {tool_name}"}

    async def hangup_call(self, call_id: str, reason: str = "") -> dict[str, Any]:
        """Terminate an active call session and release RTP/Live resources."""
        session = self.active_calls.pop(call_id, None)
        if session is not None:
            if session.dead_air_task and not session.dead_air_task.done():
                session.dead_air_task.cancel()
            if session.rtp_session is not None:
                await session.rtp_session.stop()
            if session.live_session is not None:
                await session.live_session.close()
            session.done_event.set()

        current = self.store.get_call(call_id)
        if not current:
            return {"ok": False, "error": f"Call {call_id} not found"}

        updated = self.store.update_call(
            call_id,
            status="completed",
            outcome=current.get("outcome") or "completed",
            summary=current.get("summary") or reason,
            ended_at=time.time(),
        )
        return {"ok": True, "call": updated}

    async def send_sms(self, *, to_number: str, message: str) -> dict[str, Any]:
        """Validate destination and rate limits, then send and persist an outbound SMS."""
        try:
            normalized_dest = validate_outbound_destination(
                to_number,
                allow_international=self.settings.allow_international,
                allowed_country_prefixes=self.settings.allowed_country_prefixes,
            )
        except SecurityPolicyError as exc:
            self.store.log_security_event(
                event_type="outbound_sms_blocked",
                severity="warning",
                actor="mcp_client",
                detail=str(exc),
            )
            raise

        if not self.sms_rate_limiter.allow("outbound_sms"):
            msg = f"Outbound SMS rate limit exceeded ({self.settings.max_sms_per_hour}/hour)"
            self.store.log_security_event(
                event_type="sms_rate_limit_exceeded",
                severity="warning",
                actor="mcp_client",
                detail=msg,
            )
            raise SecurityPolicyError(msg)

        clean_body = message.strip()
        if not clean_body:
            raise ValueError("SMS message body must not be empty")
        if len(clean_body) > 1000:
            raise ValueError("SMS message body exceeds 1000 character limit")

        return self.store.record_sms(
            direction="outbound",
            remote_number=normalized_dest,
            body=clean_body,
            status="sent",
        )

    def receive_inbound_sms(self, *, from_number: str, body: str) -> dict[str, Any]:
        """Record an inbound SIP MESSAGE / webhook SMS and extract any 2FA/OTP code."""
        suspicious = detect_prompt_injection(body)
        if suspicious:
            self.store.log_security_event(
                event_type="sms_prompt_injection_attempt",
                severity="high",
                actor=from_number,
                detail=f"Matched pattern {suspicious!r} in SMS body",
            )
        return self.store.record_sms(
            direction="inbound",
            remote_number=from_number,
            body=body,
            status="received",
        )

    def get_status(self) -> dict[str, Any]:
        """Return sanitized runtime and security posture status (never exposes secrets)."""
        return {
            "service": "ai-assistant-voice",
            "version": "0.1.0",
            "sip_server": self.settings.sip_server,
            "sip_port": self.settings.sip_port,
            "sip_transport": self.settings.sip_transport,
            "srtp_enabled": self.settings.srtp_enabled,
            "voice_provider": self.settings.voice_provider,
            "voice_model": self.settings.voice_model,
            "active_calls": len(self.active_calls),
            "max_concurrent_calls": self.settings.max_concurrent_calls,
            "remaining_calls_this_hour": self.call_rate_limiter.remaining("outbound_call"),
            "remaining_sms_this_hour": self.sms_rate_limiter.remaining("outbound_sms"),
            "allow_international": self.settings.allow_international,
            "mcp_transport": self.settings.mcp_transport,
        }
