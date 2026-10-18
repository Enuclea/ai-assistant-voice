"""RFC 4733 / RFC 2833 telephone-event DTMF builder/parser and in-band dual-tone synthesizer."""

from __future__ import annotations

import math
import struct
from typing import Any

from .codec import pcm16_to_ulaw

DTMF_EVENT_TO_DIGIT: dict[int, str] = {
    0: "0",
    1: "1",
    2: "2",
    3: "3",
    4: "4",
    5: "5",
    6: "6",
    7: "7",
    8: "8",
    9: "9",
    10: "*",
    11: "#",
    12: "A",
    13: "B",
    14: "C",
    15: "D",
}
DIGIT_TO_DTMF_EVENT: dict[str, int] = {v: k for k, v in DTMF_EVENT_TO_DIGIT.items()}
DTMF_CHAR_MAP: dict[str, int] = DIGIT_TO_DTMF_EVENT

DTMF_FREQS: dict[str, tuple[float, float]] = {
    "1": (697.0, 1209.0),
    "2": (697.0, 1336.0),
    "3": (697.0, 1477.0),
    "A": (697.0, 1633.0),
    "4": (770.0, 1209.0),
    "5": (770.0, 1336.0),
    "6": (770.0, 1477.0),
    "B": (770.0, 1633.0),
    "7": (852.0, 1209.0),
    "8": (852.0, 1336.0),
    "9": (852.0, 1477.0),
    "C": (852.0, 1633.0),
    "*": (941.0, 1209.0),
    "0": (941.0, 1336.0),
    "#": (941.0, 1477.0),
    "D": (941.0, 1633.0),
}


def parse_rfc4733_dtmf(payload: bytes) -> dict[str, Any] | None:
    """Parse an RFC 4733 telephone-event 4-byte RTP payload."""
    if len(payload) < 4:
        return None
    event, flags, duration = struct.unpack("!BBH", payload[:4])
    digit = DTMF_EVENT_TO_DIGIT.get(event)
    if digit is None:
        return None
    end_bit = bool(flags & 0x80)
    volume = flags & 0x3F
    return {
        "digit": digit,
        "event": event,
        "end": end_bit,
        "volume": volume,
        "duration": duration,
    }


def build_rfc4733_dtmf(digit: str, *, end: bool = True, volume: int = 10, duration: int = 160) -> bytes:
    """Build an RFC 4733 telephone-event 4-byte RTP payload."""
    ev = DIGIT_TO_DTMF_EVENT.get(digit.upper())
    if ev is None:
        raise ValueError(f"Unsupported DTMF digit: {digit!r}")
    flags = (0x80 if end else 0x00) | (volume & 0x3F)
    return struct.pack("!BBH", ev, flags, duration & 0xFFFF)


def synthesize_dtmf_ulaw(
    digits: str,
    *,
    sample_rate: int = 8000,
    tone_ms: int = 160,
    duration_ms: int | None = None,
    gap_ms: int = 100,
    pause_ms: int = 500,
) -> bytes:
    """Synthesize in-band dual-tone G.711 u-law audio for a DTMF digit sequence ('0-9', '*', '#', 'w')."""
    out = bytearray()
    effective_tone_ms = duration_ms if duration_ms is not None else tone_ms
    tone_samples = max(1, int(sample_rate * effective_tone_ms / 1000))
    gap_samples = max(1, int(sample_rate * gap_ms / 1000))
    pause_samples = max(1, int(sample_rate * pause_ms / 1000))
    for ch in (digits or "").upper():
        if ch == "W":
            out.extend(b"\xff" * pause_samples)
            continue
        freqs = DTMF_FREQS.get(ch)
        if not freqs:
            continue
        f_low, f_high = freqs
        pcm_samples = [
            int(
                7000.0
                * (
                    math.sin(2.0 * math.pi * f_low * i / sample_rate)
                    + math.sin(2.0 * math.pi * f_high * i / sample_rate)
                )
            )
            for i in range(tone_samples)
        ]
        pcm_bytes = struct.pack(f"<{len(pcm_samples)}h", *pcm_samples)
        out.extend(pcm16_to_ulaw(pcm_bytes))
        out.extend(b"\xff" * gap_samples)
    return bytes(out)


def build_rfc4733_dtmf_frames(
    digits: str,
    *,
    tone_frames: int = 8,
    gap_frames: int = 5,
    pause_frames: int = 25,
) -> list[dict[str, Any]]:
    """Build 20ms RTP step descriptors for RFC 4733 telephone-event transmission."""
    frames: list[dict[str, Any]] = []
    for ch in (digits or "").upper():
        if ch == "W":
            for _ in range(pause_frames):
                frames.append({"kind": "silence"})
            continue
        if ch not in DTMF_FREQS:
            continue
        for step in range(tone_frames):
            dur = (step + 1) * 160
            is_end = step == (tone_frames - 1)
            payload = build_rfc4733_dtmf(ch, end=is_end, volume=10, duration=dur)
            frames.append({
                "kind": "dtmf",
                "digit": ch,
                "marker": step == 0,
                "end": is_end,
                "duration": dur,
                "new_event": step == 0,
                "payload": payload,
            })
        for _ in range(gap_frames):
            frames.append({"kind": "silence"})
    return frames
