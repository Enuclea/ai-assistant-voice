"""Adaptive Voice Activity Detector (human, ivr, voicemail, hold) and Goertzel narrowband beep detector."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import math
import struct
from typing import Any, NamedTuple

from .codec import frame_rms


class EndpointingConfig(NamedTuple):
    silence_ms: int
    max_utterance_ms: int


# Adaptive VAD endpointing table: mode -> EndpointingConfig(silence_ms, max_utterance_ms)
ENDPOINTING_MODES: dict[str, EndpointingConfig] = {
    "human": EndpointingConfig(700, 8000),
    "ivr": EndpointingConfig(1800, 15000),
    "voicemail": EndpointingConfig(2200, 20000),
    "hold": EndpointingConfig(2500, 60000),
}


def is_narrowband_beep_frame(pcm_frame: bytes, *, sample_rate: int = 8000, min_rms: float = 300.0) -> bool:
    """Detect whether a 20ms PCM16 frame is a narrowband single-frequency tone in 800-1200 Hz."""
    count = len(pcm_frame) // 2
    if count < 32:
        return False
    samples = struct.unpack(f"<{count}h", pcm_frame[: count * 2])
    mean = sum(samples) / count
    ac = [s - mean for s in samples]
    total_energy = sum(s * s for s in ac)
    if total_energy <= 0.0 or math.sqrt(total_energy / count) < min_rms:
        return False

    best_power = 0.0
    for freq in (800.0, 850.0, 900.0, 950.0, 1000.0, 1050.0, 1100.0, 1150.0, 1200.0):
        omega = 2.0 * math.pi * freq / sample_rate
        coeff = 2.0 * math.cos(omega)
        s_prev = 0.0
        s_prev2 = 0.0
        for x in ac:
            s = x + coeff * s_prev - s_prev2
            s_prev2 = s_prev
            s_prev = s
        power = s_prev * s_prev + s_prev2 * s_prev2 - coeff * s_prev * s_prev2
        if power > best_power:
            best_power = power

    concentration = (2.0 * best_power) / (count * total_energy)
    return concentration >= 0.65


def detect_voicemail_beep(pcm_bytes: bytes, *, sample_rate: int = 8000, frame_ms: int = 20) -> bool:
    """Return True if `pcm_bytes` contains a narrowband 800-1200 Hz tone lasting 300-1200 ms."""
    frame_bytes = max(2, int(sample_rate * frame_ms / 1000) * 2)
    run_ms = 0
    max_run_ms = 0
    for offset in range(0, len(pcm_bytes) - frame_bytes + 1, frame_bytes):
        frame = pcm_bytes[offset : offset + frame_bytes]
        if is_narrowband_beep_frame(frame, sample_rate=sample_rate):
            run_ms += frame_ms
            if 300 <= run_ms <= 1400 and run_ms > max_run_ms:
                max_run_ms = run_ms
        else:
            if 300 <= run_ms <= 1400:
                return True
            run_ms = 0
    return 300 <= max_run_ms <= 1400


@dataclass
class VoiceActivityDetector:
    """Energy-based VAD with pre-roll buffer, barge-in trigger, adaptive endpointing modes, and beep detection."""

    sample_rate: int = 8000
    frame_ms: int = 20
    energy_threshold: float = 350.0
    barge_in_ms: int = 160
    silence_flush_ms: int = 700
    min_speech_ms: int = 60
    preroll_frames: int = 0
    max_utterance_ms: int = 7500
    mode: str = "human"
    _speech_ms: int = 0
    _utterance_ms: int = 0
    _silence_ms: int = 0
    _resume_speech_ms: int = 0
    _barge_dip_ms: int = 0
    _tone_ms: int = 0
    _noise_rms: float = 120.0
    _beep_detected: bool = False
    _in_utterance: bool = False
    _buffer: bytearray = field(default_factory=bytearray)
    _preroll: deque[bytes] = field(default_factory=deque)

    def set_mode(self, mode: str) -> str:
        clean = (mode or "human").strip().lower()
        if clean not in ENDPOINTING_MODES:
            clean = "human"
        self.mode = clean
        self.silence_flush_ms, self.max_utterance_ms = ENDPOINTING_MODES[clean]
        return self.mode

    @property
    def config(self) -> EndpointingConfig:
        return ENDPOINTING_MODES.get(self.mode, ENDPOINTING_MODES["human"])

    @property
    def is_currently_speaking(self) -> bool:
        return self._in_utterance

    @property
    def barge_in_streak(self) -> int:
        return self._speech_ms // max(1, self.frame_ms)

    def process_frame(self, pcm_frame: bytes, *, is_playing: bool = False) -> tuple[bytes | None, bool]:
        res = self.feed_frame(pcm_frame, playback_active=is_playing)
        return res["utterance_pcm"], bool(res["beep_detected"])

    def feed_frame(self, pcm_frame: bytes, *, playback_active: bool = False) -> dict[str, Any]:
        rms = frame_rms(pcm_frame)
        if not playback_active and rms < max(self.energy_threshold * 1.4, self._noise_rms * 2.0):
            self._noise_rms = 0.96 * self._noise_rms + 0.04 * rms
        adaptive_floor = min(850.0, self._noise_rms * 2.4) if self._in_utterance else 0.0
        thresh = (
            max(self.energy_threshold * 2.0, 850.0)
            if playback_active
            else max(self.energy_threshold, adaptive_floor)
        )
        is_speech = rms >= thresh
        barge_in = False
        flushed: bytes | None = None
        flushed_beep = False

        if is_speech and not playback_active:
            if is_narrowband_beep_frame(pcm_frame, sample_rate=self.sample_rate):
                self._tone_ms += self.frame_ms
                if 300 <= self._tone_ms <= 1400:
                    self._beep_detected = True
            else:
                if self._tone_ms > 1400:
                    self._beep_detected = False
                self._tone_ms = 0

        if is_speech:
            if not self._in_utterance and self._speech_ms == 0 and self._preroll:
                for pf in self._preroll:
                    self._buffer.extend(pf)
                self._preroll.clear()
            self._speech_ms += self.frame_ms
            if self._in_utterance and self._silence_ms >= 80:
                self._resume_speech_ms += self.frame_ms
                if self._resume_speech_ms >= 40:
                    self._silence_ms = 0
                    self._resume_speech_ms = 0
            else:
                self._silence_ms = 0
                self._resume_speech_ms = 0
            self._barge_dip_ms = 0
            self._buffer.extend(pcm_frame)
            if not self._in_utterance and self._speech_ms >= self.min_speech_ms:
                self._in_utterance = True
                self._utterance_ms = self._speech_ms
            elif self._in_utterance:
                self._utterance_ms += self.frame_ms
            if playback_active and self._speech_ms >= self.barge_in_ms:
                barge_in = True
                self._in_utterance = True
            if self._in_utterance and self._utterance_ms >= self.max_utterance_ms:
                flushed = bytes(self._buffer)
                flushed_beep = self._beep_detected
                self.reset()
        else:
            self._tone_ms = 0
            self._resume_speech_ms = 0
            if playback_active:
                if self._speech_ms > 0:
                    self._barge_dip_ms += self.frame_ms
                    self._buffer.extend(pcm_frame)
                    if self._barge_dip_ms > 80:
                        self._speech_ms = 0
                        self._utterance_ms = 0
                        self._barge_dip_ms = 0
                        self._in_utterance = False
                        self._buffer.clear()
                elif self.preroll_frames > 0:
                    self._preroll.append(pcm_frame)
                    while len(self._preroll) > self.preroll_frames:
                        self._preroll.popleft()
            elif self._in_utterance:
                self._silence_ms += self.frame_ms
                self._utterance_ms += self.frame_ms
                self._buffer.extend(pcm_frame)
                effective_flush_ms = min(self.silence_flush_ms, 360) if self._beep_detected else self.silence_flush_ms
                if self._silence_ms >= effective_flush_ms or self._utterance_ms >= self.max_utterance_ms:
                    if self._speech_ms >= self.min_speech_ms:
                        flushed = bytes(self._buffer)
                        flushed_beep = self._beep_detected
                    self.reset()
            else:
                if self._speech_ms > 0 and self._barge_dip_ms < 40:
                    self._barge_dip_ms += self.frame_ms
                    self._buffer.extend(pcm_frame)
                else:
                    self._speech_ms = 0
                    self._utterance_ms = 0
                    self._barge_dip_ms = 0
                    self._beep_detected = False
                    self._buffer.clear()
                    if self.preroll_frames > 0:
                        self._preroll.append(pcm_frame)
                        while len(self._preroll) > self.preroll_frames:
                            self._preroll.popleft()

        return {
            "is_speech": is_speech,
            "barge_in": barge_in,
            "utterance_pcm": flushed,
            "rms": rms,
            "beep_detected": flushed_beep,
            "mode": self.mode,
        }

    def reset(self) -> None:
        self._speech_ms = 0
        self._utterance_ms = 0
        self._silence_ms = 0
        self._resume_speech_ms = 0
        self._barge_dip_ms = 0
        self._tone_ms = 0
        self._beep_detected = False
        self._in_utterance = False
        self._buffer.clear()
        self._preroll.clear()
