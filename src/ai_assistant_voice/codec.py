"""Pure-Python G.711 u-law <-> 16-bit PCM codec, WAV wrapper, and audio resamplers."""

from __future__ import annotations

import io
import math
import struct
import wave

_ULAW_BIAS = 0x84
_ULAW_CLIP = 32635
FRAME_SAMPLES_8K = 160
ULAW_SILENCE_BYTE = b"\xff"


def _linear_to_ulaw_sample(sample: int) -> int:
    sign = 0x80 if sample < 0 else 0
    if sample < 0:
        sample = -sample
    if sample > _ULAW_CLIP:
        sample = _ULAW_CLIP
    sample += _ULAW_BIAS
    exponent = 7
    mask = 0x4000
    while exponent > 0 and (sample & mask) == 0:
        exponent -= 1
        mask >>= 1
    mantissa = (sample >> (exponent + 3)) & 0x0F
    return (~(sign | (exponent << 4) | mantissa)) & 0xFF


def _ulaw_to_linear_sample(u_val: int) -> int:
    u_val = (~u_val) & 0xFF
    t = (((u_val & 0x0F) << 3) + _ULAW_BIAS) << ((u_val & 0x70) >> 4)
    return (_ULAW_BIAS - t) if (u_val & 0x80) else (t - _ULAW_BIAS)


_ULAW_DECODE_TABLE: tuple[int, ...] = tuple(_ulaw_to_linear_sample(i) for i in range(256))
_ULAW_ENCODE_TABLE: bytes = bytes(_linear_to_ulaw_sample(s - 32768) for s in range(65536))


def pcm16_to_ulaw(pcm_bytes: bytes) -> bytes:
    """Encode 16-bit signed little-endian PCM (8 kHz mono) to G.711 u-law bytes."""
    count = len(pcm_bytes) // 2
    if count == 0:
        return b""
    samples = struct.unpack(f"<{count}h", pcm_bytes[: count * 2])
    return bytes(_ULAW_ENCODE_TABLE[s + 32768] for s in samples)


def ulaw_to_pcm16(ulaw_bytes: bytes) -> bytes:
    """Decode G.711 u-law bytes to 16-bit signed little-endian PCM (8 kHz mono)."""
    if not ulaw_bytes:
        return b""
    decoded = [_ULAW_DECODE_TABLE[b] for b in ulaw_bytes]
    return struct.pack(f"<{len(decoded)}h", *decoded)


def frame_rms(pcm_bytes: bytes) -> float:
    """Compute root-mean-square energy of a 16-bit signed little-endian PCM frame."""
    count = len(pcm_bytes) // 2
    if count == 0:
        return 0.0
    samples = struct.unpack(f"<{count}h", pcm_bytes[: count * 2])
    return math.sqrt(sum(s * s for s in samples) / count)


def wrap_pcm16_wav(pcm_bytes: bytes, *, sample_rate: int = 8000) -> bytes:
    """Wrap raw 16-bit mono PCM bytes in a RIFF WAV container."""
    buf = io.BytesIO()
    with wave.open(buf, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sample_rate)
        wf.writeframes(pcm_bytes)
    return buf.getvalue()


def extract_pcm16_16k(audio_bytes: bytes) -> bytes:
    """Convert an 8 kHz WAV or raw PCM16 buffer into 16 kHz mono 16-bit little-endian PCM."""
    if not audio_bytes:
        return b""
    pcm_bytes = audio_bytes
    sample_rate = 8000
    n_channels = 1
    if audio_bytes[:4] == b"RIFF":
        try:
            with wave.open(io.BytesIO(audio_bytes), "rb") as wf:
                sample_rate = wf.getframerate()
                n_channels = wf.getnchannels()
                pcm_bytes = wf.readframes(wf.getnframes())
        except Exception:
            pcm_bytes = audio_bytes[44:] if len(audio_bytes) > 44 else b""

    count = len(pcm_bytes) // 2
    if count == 0:
        return b""
    samples = list(struct.unpack(f"<{count}h", pcm_bytes[: count * 2]))
    if n_channels > 1:
        samples = samples[::n_channels]
    if not samples:
        return b""

    if sample_rate == 16000:
        return struct.pack(f"<{len(samples)}h", *samples)
    if sample_rate == 8000:
        out: list[int] = []
        n = len(samples)
        for i in range(n - 1):
            s0 = samples[i]
            s1 = samples[i + 1]
            out.append(s0)
            out.append((s0 + s1) // 2)
        out.append(samples[-1])
        out.append(samples[-1])
        return struct.pack(f"<{len(out)}h", *out)

    ratio = sample_rate / 16000.0
    out_len = max(1, int(len(samples) / ratio))
    resampled = [samples[min(len(samples) - 1, int(i * ratio))] for i in range(out_len)]
    return struct.pack(f"<{len(resampled)}h", *resampled)


def wav_to_8k_ulaw(wav_bytes: bytes) -> bytes:
    """Convert any mono/stereo 16-bit WAV (e.g. 24 kHz from Gemini Live) into 8 kHz G.711 u-law."""
    with wave.open(io.BytesIO(wav_bytes), "rb") as wf:
        channels = wf.getnchannels()
        sampwidth = wf.getsampwidth()
        framerate = wf.getframerate()
        raw = wf.readframes(wf.getnframes())
    if sampwidth != 2 or not raw:
        return b""
    total_samples = len(raw) // 2
    samples = struct.unpack(f"<{total_samples}h", raw[: total_samples * 2])
    if channels > 1:
        samples = samples[::channels]
    if framerate != 8000 and len(samples) > 1:
        ratio = framerate / 8000.0
        out_len = int(len(samples) / ratio)
        samples = tuple(samples[min(len(samples) - 1, int(i * ratio))] for i in range(out_len))
    pcm_8k = struct.pack(f"<{len(samples)}h", *samples)
    return pcm16_to_ulaw(pcm_8k)


def upsample_8k_to_16k(pcm16_8k: bytes) -> bytes:
    """Linearly interpolate 8 kHz 16-bit mono PCM to 16 kHz 16-bit mono PCM."""
    return extract_pcm16_16k(pcm16_8k)


def downsample_24k_to_8k_ulaw(pcm16_24k: bytes) -> bytes:
    """Decimate 24 kHz 16-bit mono PCM (3:1) to 8 kHz G.711 u-law."""
    count = len(pcm16_24k) // 2
    if count == 0:
        return b""
    samples = struct.unpack(f"<{count}h", pcm16_24k[: count * 2])
    decimated = samples[::3]
    return bytes(_ULAW_ENCODE_TABLE[s + 32768] for s in decimated)

