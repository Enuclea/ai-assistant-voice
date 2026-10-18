"""20ms RTP/SRTP media session with Symmetric RTP subnet validation, DTX silence flushing, and RFC 4733 DTMF."""

from __future__ import annotations

import asyncio
import logging
import secrets
import struct
import time
from typing import Callable

from .codec import FRAME_SAMPLES_8K, ULAW_SILENCE_BYTE, ulaw_to_pcm16
from .dtmf import DTMF_CHAR_MAP, build_rfc4733_dtmf_frames, parse_rfc4733_dtmf, synthesize_dtmf_ulaw
from .security import is_trusted_rtp_peer
from .srtp import SRTPContext
from .vad import VoiceActivityDetector

logger = logging.getLogger(__name__)


class _RTPDatagramProtocol(asyncio.DatagramProtocol):
    def __init__(self, session: CallRTPSession) -> None:
        self._session = session

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self._session.on_rtp_packet(data, addr)

    def error_received(self, exc: Exception) -> None:
        logger.debug("RTP socket error on call %s: %s", self._session.call_id, exc)


class CallRTPSession:
    """Manages bidirectional 20ms G.711 PCMU RTP/SRTP audio and RFC 4733 DTMF for a call."""

    def __init__(
        self,
        *,
        call_id: str,
        local_port: int,
        remote_ip: str,
        remote_port: int,
        dtmf_payload_type: int = 101,
        tx_srtp: SRTPContext | None = None,
        rx_srtp: SRTPContext | None = None,
        on_utterance: Callable[[bytes, bool], None] | None = None,
        on_dtmf_received: Callable[[str], None] | None = None,
        on_barge_in: Callable[[], None] | None = None,
        on_raw_pcm16_8k: Callable[[bytes], None] | None = None,
    ) -> None:
        self.call_id = call_id
        self.local_port = local_port
        self.sdp_Negotiated_ip = remote_ip
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.dtmf_payload_type = dtmf_payload_type
        self.tx_srtp = tx_srtp
        self.rx_srtp = rx_srtp

        self._on_utterance = on_utterance
        self._on_dtmf_received = on_dtmf_received
        self._on_barge_in = on_barge_in
        self._on_raw_pcm16_8k = on_raw_pcm16_8k

        self.vad = VoiceActivityDetector(mode="human")
        self._tx_queue: bytearray = bytearray()
        self._seq: int = secrets.randbelow(32768)
        self._timestamp: int = secrets.randbelow(100000)
        self._ssrc: int = secrets.randbits(32)
        self._transport: asyncio.DatagramTransport | None = None
        self._tx_task: asyncio.Task[None] | None = None
        self._dtx_task: asyncio.Task[None] | None = None
        self._closed: bool = False
        self._last_rx_monotonic: float = time.monotonic()
        self._last_dtmf_ts: int | None = None
        self.packets_sent: int = 0
        self.packets_received: int = 0
        self.srtp_auth_failures: int = 0
        self.untrusted_peer_drops: int = 0

    @property
    def is_playing(self) -> bool:
        return len(self._tx_queue) >= FRAME_SAMPLES_8K

    async def start(self, bind_host: str = "0.0.0.0") -> None:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _RTPDatagramProtocol(self),
            local_addr=(bind_host, self.local_port),
        )
        self._transport = transport
        self._tx_task = asyncio.create_task(self._tx_loop(), name=f"rtp-tx-{self.call_id}")
        self._dtx_task = asyncio.create_task(self._dtx_watchdog_loop(), name=f"rtp-dtx-{self.call_id}")

    async def stop(self) -> None:
        self._closed = True
        for task in (self._tx_task, self._dtx_task):
            if task and not task.done():
                task.cancel()
        if self._transport is not None:
            self._transport.close()
            self._transport = None

    def enqueue_ulaw(self, ulaw_bytes: bytes) -> None:
        """Append 8kHz G.711 mu-law audio bytes to the outbound playback buffer."""
        self._tx_queue.extend(ulaw_bytes)

    def clear_playback(self) -> int:
        """Clear queued outbound audio (barge-in or wait_silently) and return dropped bytes."""
        dropped = len(self._tx_queue)
        self._tx_queue.clear()
        return dropped

    def _send_rtp_packet(
        self,
        *,
        payload_type: int,
        marker: bool,
        timestamp: int,
        payload: bytes,
    ) -> None:
        if self._closed or self._transport is None or not self.remote_ip or self.remote_port <= 0:
            return
        self._seq = (self._seq + 1) & 0xFFFF
        b1 = (0x80 if marker else 0x00) | (payload_type & 0x7F)
        header = struct.pack("!BBHII", 0x80, b1, self._seq, timestamp & 0xFFFFFFFF, self._ssrc)
        packet = header + payload
        if self.tx_srtp is not None:
            packet = self.tx_srtp.protect(packet)
        self._transport.sendto(packet, (self.remote_ip, self.remote_port))
        self.packets_sent += 1

    async def send_dtmf_sequence(self, digits: str) -> str:
        """Transmit a sequence of DTMF digits using both RFC 4733 telephone-event and in-band audio."""
        self.clear_playback()
        sent_chars: list[str] = []
        for ch in digits.strip():
            upper = ch.upper()
            if upper == "W" or ch == ",":
                await asyncio.sleep(0.5)
                sent_chars.append("w")
                continue
            if upper not in DTMF_CHAR_MAP:
                continue
            event_ts = self._timestamp
            frames = build_rfc4733_dtmf_frames(upper, tone_frames=8, gap_frames=0)
            for step in frames:
                if step.get("kind") != "dtmf":
                    continue
                self._send_rtp_packet(
                    payload_type=self.dtmf_payload_type,
                    marker=bool(step.get("marker", False)),
                    timestamp=event_ts,
                    payload=step["payload"],
                )
                if not step.get("end"):
                    await asyncio.sleep(0.02)
            # Also queue in-band dual-tone audio for PBXs that decode in-band after auto-attendant transfer
            self.enqueue_ulaw(synthesize_dtmf_ulaw(upper, duration_ms=160, gap_ms=100))
            sent_chars.append(upper)
            await asyncio.sleep(0.10)
        return "".join(sent_chars)

    def on_rtp_packet(self, packet: bytes, addr: tuple[str, int]) -> None:
        """Handle an inbound UDP RTP/SRTP datagram."""
        if self._closed or len(packet) < 12:
            return

        source_ip, source_port = addr
        if (source_ip != self.remote_ip or source_port != self.remote_port):
            if is_trusted_rtp_peer(source_ip, self.sdp_Negotiated_ip):
                self.remote_ip = source_ip
                self.remote_port = source_port
            else:
                self.untrusted_peer_drops += 1
                return

        if self.rx_srtp is not None:
            unprotected = self.rx_srtp.unprotect(packet)
            if unprotected is None:
                self.srtp_auth_failures += 1
                return
            packet = unprotected

        b0, b1, _seq, ts, _ssrc = struct.unpack("!BBHII", packet[:12])
        csrc_count = b0 & 0x0F
        header_len = 12 + (4 * csrc_count)
        if b0 & 0x10:  # RTP extension header present
            if len(packet) < header_len + 4:
                return
            _, ext_words = struct.unpack("!HH", packet[header_len : header_len + 4])
            header_len += 4 + (4 * ext_words)
        if len(packet) <= header_len:
            return

        payload_type = b1 & 0x7F
        payload = packet[header_len:]
        self.packets_received += 1
        self._last_rx_monotonic = time.monotonic()

        # Check for RFC 4733 DTMF event
        if payload_type == self.dtmf_payload_type:
            parsed = parse_rfc4733_dtmf(payload)
            if parsed is not None:
                if parsed.get("end") and self._last_dtmf_ts != ts:
                    self._last_dtmf_ts = ts
                    if self._on_dtmf_received is not None:
                        self._on_dtmf_received(str(parsed["digit"]))
            return

        if payload_type != 0:  # Only G.711 PCMU (PT 0)
            return

        pcm16 = ulaw_to_pcm16(payload)
        if self._on_raw_pcm16_8k is not None:
            self._on_raw_pcm16_8k(pcm16)

        self._feed_vad_frame(pcm16)

    def _feed_vad_frame(self, pcm16: bytes) -> None:
        utterance, beep_detected = self.vad.process_frame(pcm16, is_playing=self.is_playing)
        if self.is_playing and self.vad.barge_in_streak >= 8:
            self.clear_playback()
            if self._on_barge_in is not None:
                self._on_barge_in()
        if utterance is not None and self._on_utterance is not None:
            self._on_utterance(utterance, beep_detected)

    async def _tx_loop(self) -> None:
        """Transmit one 160-byte (20ms) G.711 PCMU RTP packet every 20ms."""
        silence_frame = ULAW_SILENCE_BYTE * FRAME_SAMPLES_8K
        next_tick = time.monotonic()
        while not self._closed:
            now = time.monotonic()
            if now < next_tick:
                await asyncio.sleep(next_tick - now)
            next_tick += 0.020

            if len(self._tx_queue) >= FRAME_SAMPLES_8K:
                frame = bytes(self._tx_queue[:FRAME_SAMPLES_8K])
                del self._tx_queue[:FRAME_SAMPLES_8K]
            elif self._tx_queue:
                frame = bytes(self._tx_queue) + (
                    ULAW_SILENCE_BYTE * (FRAME_SAMPLES_8K - len(self._tx_queue))
                )
                self._tx_queue.clear()
            else:
                frame = silence_frame

            self._timestamp = (self._timestamp + FRAME_SAMPLES_8K) & 0xFFFFFFFF
            self._send_rtp_packet(
                payload_type=0,
                marker=False,
                timestamp=self._timestamp,
                payload=frame,
            )

    async def _dtx_watchdog_loop(self) -> None:
        """Synthesize silence frames into the VAD when the remote PBX stops RTP during silence (DTX)."""
        zero_pcm = b"\x00\x00" * FRAME_SAMPLES_8K
        while not self._closed:
            await asyncio.sleep(0.020)
            if (
                self.vad.is_currently_speaking
                and (time.monotonic() - self._last_rx_monotonic) > 0.060
            ):
                self._feed_vad_frame(zero_pcm)
                if self._on_raw_pcm16_8k is not None:
                    self._on_raw_pcm16_8k(zero_pcm)
