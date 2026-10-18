"""RFC 3711 AES_CM_128_HMAC_SHA1_80 SRTP encryption/decryption with 64-packet anti-replay window."""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b, strict=True))


class SRTPContext:
    """RFC 3711 SRTP context (AES_CM_128_HMAC_SHA1_80 or AES_CM_128_HMAC_SHA1_32) with replay protection."""

    def __init__(self, master_key: bytes, master_salt: bytes, *, suite: str = "AES_CM_128_HMAC_SHA1_80") -> None:
        if len(master_key) != 16 or len(master_salt) != 14:
            raise ValueError("SRTP requires 16-byte master key and 14-byte master salt")
        self.master_key = master_key
        self.master_salt = master_salt
        self.tag_len = 4 if suite.endswith("_32") else 10
        self.roc = 0
        self._last_seq: int | None = None
        self._replay_Base: int | None = None
        self._replay_window: int = 0
        self.enc_key = self._derive_key(0x00, 16)
        self.auth_key = self._derive_key(0x01, 20)
        self.salt_key = self._derive_key(0x02, 14)

    @classmethod
    def generate(cls, *, suite: str = "AES_CM_128_HMAC_SHA1_80") -> SRTPContext:
        import secrets
        return cls(secrets.token_bytes(16), secrets.token_bytes(14), suite=suite)

    @classmethod
    def from_inline(cls, inline_b64: str, *, suite: str = "AES_CM_128_HMAC_SHA1_80") -> SRTPContext:
        raw = base64.b64decode(inline_b64.split("|")[0].strip())
        if len(raw) < 30:
            raise ValueError("SDES inline key+salt must be at least 30 bytes")
        return cls(raw[:16], raw[16:30], suite=suite)

    @classmethod
    def from_sdp_inline(cls, inline_b64: str, *, suite: str = "AES_CM_128_HMAC_SHA1_80") -> SRTPContext:
        return cls.from_inline(inline_b64, suite=suite)

    def to_sdp_inline(self) -> str:
        return base64.b64encode(self.master_key + self.master_salt).decode("ascii")

    def _derive_key(self, label: int, out_len: int) -> bytes:
        key_id = bytes([label]) + b"\x00" * 6
        padded_salt = self.master_salt[:7] + _xor_bytes(self.master_salt[7:14], key_id) + b"\x00\x00"
        cipher = Cipher(algorithms.AES(self.master_key), modes.CTR(padded_salt))
        encryptor = cipher.encryptor()
        return (encryptor.update(b"\x00" * 32) + encryptor.finalize())[:out_len]

    def _packet_iv(self, ssrc: int, index: int) -> bytes:
        buf = bytearray(16)
        buf[0:14] = self.salt_key
        ssrc_bytes = struct.pack("!I", ssrc & 0xFFFFFFFF)
        idx_bytes = index.to_bytes(6, "big")
        for i in range(4):
            buf[4 + i] ^= ssrc_bytes[i]
        for i in range(6):
            buf[8 + i] ^= idx_bytes[i]
        return bytes(buf)

    @staticmethod
    def rtp_header_len(pkt: bytes) -> int:
        if len(pkt) < 12:
            return 0
        v_p_x_cc = pkt[0]
        if (v_p_x_cc >> 6) != 2:
            return 0
        cc = v_p_x_cc & 0x0F
        has_ext = bool(v_p_x_cc & 0x10)
        hdr_len = 12 + 4 * cc
        if len(pkt) < hdr_len:
            return 0
        if has_ext:
            if len(pkt) < hdr_len + 4:
                return 0
            ext_words = struct.unpack("!H", pkt[hdr_len + 2 : hdr_len + 4])[0]
            hdr_len += 4 + 4 * ext_words
        return hdr_len if len(pkt) >= hdr_len else 0

    def protect(self, rtp_pkt: bytes) -> bytes:
        hdr_len = self.rtp_header_len(rtp_pkt)
        if hdr_len == 0:
            return rtp_pkt
        seq = struct.unpack("!H", rtp_pkt[2:4])[0]
        ssrc = struct.unpack("!I", rtp_pkt[8:12])[0]
        if self._last_seq is not None and seq < self._last_seq and (self._last_seq - seq) > 0x8000:
            self.roc = (self.roc + 1) & 0xFFFFFFFF
        self._last_seq = seq
        index = ((self.roc & 0xFFFFFFFF) << 16) | seq
        iv = self._packet_iv(ssrc, index)
        cipher = Cipher(algorithms.AES(self.enc_key), modes.CTR(iv))
        enc = cipher.encryptor()
        ciphertext = enc.update(rtp_pkt[hdr_len:]) + enc.finalize()
        authenticated = rtp_pkt[:hdr_len] + ciphertext
        roc_bytes = struct.pack("!I", self.roc & 0xFFFFFFFF)
        tag = hmac.new(self.auth_key, authenticated + roc_bytes, hashlib.sha1).digest()[: self.tag_len]
        return authenticated + tag

    def unprotect(self, srtp_pkt: bytes) -> bytes | None:
        if len(srtp_pkt) < 12 + self.tag_len:
            return None
        authenticated = srtp_pkt[: -self.tag_len]
        rx_tag = srtp_pkt[-self.tag_len :]
        hdr_len = self.rtp_header_len(authenticated)
        if hdr_len == 0:
            return None
        seq = struct.unpack("!H", authenticated[2:4])[0]
        ssrc = struct.unpack("!I", authenticated[8:12])[0]
        est_roc = self.roc
        if self._last_seq is not None:
            if seq < self._last_seq and (self._last_seq - seq) > 0x8000:
                est_roc = (self.roc + 1) & 0xFFFFFFFF
            elif seq > self._last_seq and (seq - self._last_seq) > 0x8000 and self.roc > 0:
                est_roc = self.roc - 1

        index = ((est_roc & 0xFFFFFFFF) << 16) | seq

        # RFC 3711 Section 3.3.2: 64-packet sliding window replay check prior to decryption
        if self._replay_Base is not None:
            delta = index - self._replay_Base
            if delta <= 0:
                offset = -delta
                if offset >= 64 or (self._replay_window & (1 << offset)):
                    return None

        roc_bytes = struct.pack("!I", est_roc & 0xFFFFFFFF)
        expected_tag = hmac.new(self.auth_key, authenticated + roc_bytes, hashlib.sha1).digest()[: self.tag_len]
        if not hmac.compare_digest(rx_tag, expected_tag):
            return None

        # Update anti-replay window after MAC verification succeeds
        if self._replay_Base is None:
            self._replay_Base = index
            self._replay_window = 1
        else:
            delta = index - self._replay_Base
            if delta > 0:
                if delta >= 64:
                    self._replay_window = 1
                else:
                    self._replay_window = ((self._replay_window << delta) | 1) & ((1 << 64) - 1)
                self._replay_Base = index
            else:
                offset = -delta
                self._replay_window |= 1 << offset

        self.roc = est_roc
        self._last_seq = seq
        iv = self._packet_iv(ssrc, index)
        cipher = Cipher(algorithms.AES(self.enc_key), modes.CTR(iv))
        dec = cipher.decryptor()
        plaintext = dec.update(authenticated[hdr_len:]) + dec.finalize()
        return authenticated[:hdr_len] + plaintext
