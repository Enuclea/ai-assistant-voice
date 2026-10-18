"""End-to-end unit tests for the `ai-assistant-voice` pipeline and MCP server.

Covers:
- G.711 PCMU codec & 8k/16k/24k resampling (`codec.py`)
- RFC 4733 DTMF packet builder, parser, and in-band dual-tone synthesis (`dtmf.py`)
- Adaptive VAD modes (`human`, `ivr`, `voicemail`, `hold`) and Narrowband Voicemail Beep detection (`vad.py`)
- Outbound Call State Machine: Silent Turn 0, 4.5s dead-air fallback, `send_dtmf`, `wait_silently`, `outbound_record_outcome` (`orchestrator.py`)
- SMS 2FA/OTP extraction and VIP client allowlist (`store.py`)
- MCP JSON-RPC 2.0 server (`initialize`, `tools/list`, `tools/call`) and Streamable HTTP + RFC 9728 OAuth metadata (`mcp_server.py`)
"""

from __future__ import annotations

import asyncio
import json
import math
from pathlib import Path
import struct

import httpx
import pytest

from ai_assistant_voice.codec import (
    downsample_24k_to_8k_ulaw,
    frame_rms,
    pcm16_to_ulaw,
    ulaw_to_pcm16,
    upsample_8k_to_16k,
)
from ai_assistant_voice.config import VoiceSettings
from ai_assistant_voice.dtmf import (
    build_rfc4733_dtmf_frames,
    parse_rfc4733_dtmf,
    synthesize_dtmf_ulaw,
)
from ai_assistant_voice.mcp_server import VoiceMCPServer
from ai_assistant_voice.orchestrator import VoiceOrchestrator
from ai_assistant_voice.store import VoiceStore, extract_otp_code
from ai_assistant_voice.vad import ENDPOINTING_MODES, VoiceActivityDetector, detect_voicemail_beep


def _generate_sine_pcm16(freq_hz: float, duration_ms: int, sample_rate: int = 8000, amplitude: int = 12000) -> bytes:
    num_samples = int(sample_rate * duration_ms / 1000)
    samples = [
        int(amplitude * math.sin(2.0 * math.pi * freq_hz * i / sample_rate))
        for i in range(num_samples)
    ]
    return struct.pack(f"<{num_samples}h", *samples)


def test_g711_ulaw_codec_and_resampling() -> None:
    pcm_8k = _generate_sine_pcm16(440.0, 20, sample_rate=8000)
    ulaw = pcm16_to_ulaw(pcm_8k)
    assert len(ulaw) == 160
    decoded_pcm = ulaw_to_pcm16(ulaw)
    assert len(decoded_pcm) == 320
    assert frame_rms(decoded_pcm) > 5000.0

    pcm_16k = upsample_8k_to_16k(pcm_8k)
    assert len(pcm_16k) == 640

    pcm_24k = _generate_sine_pcm16(440.0, 20, sample_rate=24000)
    ulaw_from_24k = downsample_24k_to_8k_ulaw(pcm_24k)
    assert len(ulaw_from_24k) == 160


def test_rfc4733_and_inband_dtmf() -> None:
    frames = build_rfc4733_dtmf_frames("1", tone_frames=8, gap_frames=0)
    assert len(frames) == 8
    first = parse_rfc4733_dtmf(frames[0]["payload"])
    assert first is not None
    assert first["digit"] == "1" and first["end"] is False

    last = parse_rfc4733_dtmf(frames[-1]["payload"])
    assert last is not None
    assert last["digit"] == "1" and last["end"] is True

    inband = synthesize_dtmf_ulaw("5", duration_ms=160, gap_ms=100)
    assert len(inband) == int(8000 * 0.260)


def test_adaptive_vad_and_voicemail_beep_detection() -> None:
    vad = VoiceActivityDetector(mode="human")
    assert vad.config.silence_ms == 700

    vad.set_mode("ivr")
    assert vad.config.silence_ms == ENDPOINTING_MODES["ivr"].silence_ms == 1800

    vad.set_mode("voicemail")
    assert vad.config.silence_ms == ENDPOINTING_MODES["voicemail"].silence_ms == 2200

    vad.set_mode("hold")
    assert vad.config.silence_ms == ENDPOINTING_MODES["hold"].silence_ms == 2500

    # 1000 Hz pure voicemail beep for 500 ms should be detected in voicemail mode
    beep_pcm = _generate_sine_pcm16(1000.0, 500, sample_rate=8000, amplitude=14000)
    assert detect_voicemail_beep(beep_pcm) is True

    # Short 80 ms blip should not trigger voicemail beep
    blip_pcm = _generate_sine_pcm16(1000.0, 80, sample_rate=8000, amplitude=14000)
    assert detect_voicemail_beep(blip_pcm) is False


@pytest.mark.asyncio
async def test_outbound_call_silent_turn_0_and_ivr_tools(tmp_path: Path) -> None:
    settings = VoiceSettings(
        data_dir=tmp_path,
        db_path=tmp_path / "voice.db",
    )
    orch = VoiceOrchestrator(settings=settings)

    call_info = await orch.place_outbound_call(
        to_number="+12025550144",
        recipient_name="Bistro L'avenir",
        objective="Press 1 for reservations and book a table for 4 at 7 PM.",
        approved_facts={"callback_number": "+12025550199"},
    )
    call_id = call_info["call_id"]
    assert call_info["silent_turn_0"] is True
    assert call_info["transcript"] == []  # Silent Turn 0: does NOT speak immediately on connect!

    # Simulate IVR greeting arriving before 4.5s dead-air timer fires
    wrapped = orch.on_inbound_utterance(
        call_id,
        "Thank you for calling Bistro L'avenir. For reservations, press 1.",
    )
    assert "<untrusted_pstn_speech>" in wrapped

    # Voice agent calls `send_dtmf(digits="1")`
    dtmf_res = await orch.handle_call_tool(
        call_id,
        "send_dtmf",
        {"digits": "1", "reason": "Press 1 for reservations"},
    )
    assert dtmf_res["ok"] is True
    assert dtmf_res["digits_sent"] == "1"
    assert dtmf_res["vad_mode"] == "ivr"

    # Next turn is a voicemail greeting in progress -> agent calls `wait_silently(mode="voicemail")`
    wait_res = await orch.handle_call_tool(
        call_id,
        "wait_silently",
        {"mode": "voicemail", "reason": "Voicemail greeting still playing"},
    )
    assert wait_res["ok"] is True
    assert wait_res["mode"] == "voicemail"
    assert wait_res["tts_suppressed"] is True

    # Beep detected on next inbound utterance
    orch.on_inbound_utterance(
        call_id,
        "Please leave your message after the tone.",
        beep_detected=True,
    )
    updated_call = orch.store.get_call(call_id)
    assert updated_call is not None
    assert "[VOICEMAIL BEEP DETECTED]" in updated_call["transcript"][-1]["text"]

    # Record outcome and hang up
    await orch.handle_call_tool(
        call_id,
        "outbound_record_outcome",
        {"outcome": "voicemail_left", "summary": "Left reservation request on voicemail."},
    )
    hangup_res = await orch.handle_call_tool(
        call_id,
        "reception_hangup",
        {"reason": "Voicemail finished"},
    )
    assert hangup_res["ok"] is True
    final_call = orch.store.get_call(call_id)
    assert final_call is not None
    assert final_call["status"] == "completed"
    assert final_call["outcome"] == "voicemail_left"
    assert final_call["dtmf_digits"] == "1"


@pytest.mark.asyncio
async def test_dead_air_watchdog_triggers_hello_probe(tmp_path: Path) -> None:
    settings = VoiceSettings(data_dir=tmp_path, db_path=tmp_path / "voice.db")
    orch = VoiceOrchestrator(settings=settings)
    call_info = await orch.place_outbound_call(
        to_number="+12025550188",
        objective="Check store hours",
    )
    call_id = call_info["call_id"]
    session = orch.active_calls[call_id]

    # Directly run dead-air watchdog with a fast 0.05s timeout
    if session.dead_air_task:
        session.dead_air_task.cancel()
    await orch._dead_air_watchdog(session, timeout_s=0.05)

    assert session.dead_air_probe_sent is True
    stored = orch.store.get_call(call_id)
    assert stored is not None
    assert any(t["text"] == "Hello?" for t in stored["transcript"])
    await orch.hangup_call(call_id)


def test_sms_otp_extraction_and_vip_store(tmp_path: Path) -> None:
    assert extract_otp_code("Your verification code is 849201. Do not share it.") == "849201"
    assert extract_otp_code("G-492817 is your Google verification code.") == "492817"
    assert extract_otp_code("739104 is your login passcode.") == "739104"

    store = VoiceStore(tmp_path / "voice.db")
    msg = store.record_sms(
        direction="inbound",
        remote_number="+12025550177",
        body="Your security code: 554321",
    )
    assert msg["otp_code"] == "554321"

    otp_list = store.list_sms(only_otp=True)
    assert len(otp_list) == 1
    assert otp_list[0]["otp_code"] == "554321"

    vip = store.upsert_known_client(
        phone_number="202-555-0155",
        name="Alice Vance",
        company="Enuclea",
        auto_transfer=True,
    )
    assert vip["phone_number"] == "+12025550155"
    assert store.get_known_client("+12025550155") is not None


@pytest.mark.asyncio
async def test_mcp_server_jsonrpc_and_streamable_http(tmp_path: Path) -> None:
    token = "mcp-secret-token-" + ("x" * 24)
    settings = VoiceSettings(
        data_dir=tmp_path,
        db_path=tmp_path / "voice.db",
        mcp_transport="http",
        mcp_host="127.0.0.1",
        mcp_port=8400,
        mcp_auth_token=token,
        allowed_origins=("https://claude.ai",),
    )
    mcp = VoiceMCPServer(VoiceOrchestrator(settings=settings))
    app = mcp.create_http_app()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. Health check works without auth
        health = await client.get("/healthz")
        assert health.status_code == 200

        # 2. RFC 9728 OAuth Protected Resource Metadata endpoint works
        meta = await client.get("/.well-known/oauth-protected-resource")
        assert meta.status_code == 200
        meta_json = meta.json()
        assert meta_json["resource"].endswith("/mcp")

        # 3. Unauthenticated request to /mcp is rejected with 401 + WWW-Authenticate
        unauth = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
        assert unauth.status_code == 401
        assert "resource_metadata=" in unauth.headers.get("WWW-Authenticate", "")

        # 4. Unauthorized browser Origin is rejected with 403
        bad_origin = await client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {token}", "Origin": "https://evil.example"},
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        )
        assert bad_origin.status_code == 403

        # 5. Authenticated tools/list succeeds
        tools_resp = await client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {token}", "Origin": "https://claude.ai"},
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        )
        assert tools_resp.status_code == 200
        tools_data = tools_resp.json()
        tool_names = {t["name"] for t in tools_data["result"]["tools"]}
        assert "voice_call_outbound" in tool_names
        assert "voice_send_dtmf" in tool_names
        assert "voice_send_sms" in tool_names

        # 6. Authenticated tools/call to voice_call_outbound succeeds
        call_resp = await client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "voice_call_outbound",
                    "arguments": {
                        "to_number": "+12025550122",
                        "objective": "Confirm dental appointment",
                    },
                },
            },
        )
        assert call_resp.status_code == 200
        call_result = call_resp.json()
        assert call_result["result"]["isError"] is False
        parsed_payload = json.loads(call_result["result"]["content"][0]["text"])
        assert parsed_payload["remote_number"] == "+12025550122"
        await mcp.orchestrator.hangup_call(parsed_payload["call_id"])
