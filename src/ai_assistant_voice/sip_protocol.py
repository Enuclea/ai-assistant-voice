"""SIP/2.0 signaling parser, Digest Auth (RFC 3261/2617), and SDP/SRTP builders.

All header fields and URI tokens pass through `sanitize_sip_token` to eliminate
CRLF / SIP header injection vectors.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass, field

from .security import sanitize_sip_token
from .srtp import SRTPContext


@dataclass(slots=True)
class SIPMessage:
    """Parsed SIP request or response."""

    start_line: str
    headers: dict[str, str]
    body: str
    raw: str
    all_vias: list[str] = field(default_factory=list)
    all_record_routes: list[str] = field(default_factory=list)

    @property
    def is_response(self) -> bool:
        return self.start_line.upper().startswith("SIP/2.0 ")

    @property
    def status_code(self) -> int | None:
        if not self.is_response:
            return None
        parts = self.start_line.split(" ", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            return int(parts[1])
        return None

    @property
    def method(self) -> str | None:
        if self.is_response:
            return None
        return self.start_line.split(" ", 1)[0].upper()

    @property
    def call_id(self) -> str:
        return self.headers.get("call-id", self.headers.get("i", ""))

    @property
    def cseq(self) -> str:
        return self.headers.get("cseq", "")

    @property
    def from_header(self) -> str:
        return self.headers.get("from", self.headers.get("f", ""))

    @property
    def to_header(self) -> str:
        return self.headers.get("to", self.headers.get("t", ""))

    @property
    def via_header(self) -> str:
        return self.headers.get("via", self.headers.get("v", ""))


@dataclass(slots=True)
class SDPOffer:
    """Parsed SDP media offer including SRTP SDES crypto attributes."""

    media_ip: str
    media_port: int
    payload_types: list[int]
    dtmf_payload_type: int = 101
    crypto_tag: int | None = None
    crypto_suite: str | None = None
    crypto_inline_b64: str | None = None


def parse_sip_packet(data: bytes | str) -> SIPMessage | None:
    """Parse raw SIP packet bytes or text into a `SIPMessage`."""
    text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
    text = text.lstrip("\r\n")
    if not text:
        return None

    if "\r\n\r\n" in text:
        head, body = text.split("\r\n\r\n", 1)
        lines = head.split("\r\n")
    elif "\n\n" in text:
        head, body = text.split("\n\n", 1)
        lines = head.split("\n")
    else:
        lines = text.splitlines()
        body = ""

    if not lines:
        return None

    start_line = lines[0].strip()
    headers: dict[str, str] = {}
    all_vias: list[str] = []
    all_record_routes: list[str] = []

    for line in lines[1:]:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        key = k.strip().lower()
        val = v.strip()
        if key in ("via", "v"):
            all_vias.append(val)
        elif key == "record-route":
            all_record_routes.append(val)
        if key not in headers:
            headers[key] = val

    return SIPMessage(
        start_line=start_line,
        headers=headers,
        body=body,
        raw=text,
        all_vias=all_vias,
        all_record_routes=all_record_routes,
    )


def parse_www_authenticate(header_val: str) -> dict[str, str]:
    """Parse Digest challenge attributes from WWW-Authenticate or Proxy-Authenticate."""
    params: dict[str, str] = {}
    for match in re.finditer(r'(\w+)\s*=\s*(?:"([^"]*)"|([^\s,]+))', header_val):
        key = match.group(1).lower()
        val = match.group(2) if match.group(2) is not None else match.group(3)
        params[key] = val
    return params


def compute_digest_authorization(
    *,
    username: str,
    password: str,
    realm: str,
    nonce: str,
    method: str,
    uri: str,
    qop: str | None = None,
    nc: str = "00000001",
    cnonce: str | None = None,
    opaque: str | None = None,
    header_name: str = "Authorization",
) -> str:
    """Compute RFC 2617 / RFC 3261 Digest Authorization header line."""
    safe_user = sanitize_sip_token(username)
    safe_realm = sanitize_sip_token(realm)
    safe_nonce = sanitize_sip_token(nonce)
    safe_uri = sanitize_sip_token(uri)
    safe_method = sanitize_sip_token(method)

    ha1 = hashlib.md5(f"{safe_user}:{safe_realm}:{password}".encode("utf-8")).hexdigest()
    ha2 = hashlib.md5(f"{safe_method}:{safe_uri}".encode("utf-8")).hexdigest()

    qop_options = [q.strip() for q in (qop or "").split(",") if q.strip()]
    use_auth_qop = "auth" in qop_options or (qop and qop.strip() == "auth")

    if use_auth_qop:
        cnonce_val = sanitize_sip_token(cnonce or secrets.token_hex(8))
        nc_val = sanitize_sip_token(nc)
        resp = hashlib.md5(
            f"{ha1}:{safe_nonce}:{nc_val}:{cnonce_val}:auth:{ha2}".encode("utf-8")
        ).hexdigest()
        parts = [
            f'username="{safe_user}"',
            f'realm="{safe_realm}"',
            f'nonce="{safe_nonce}"',
            f'uri="{safe_uri}"',
            f'response="{resp}"',
            "algorithm=MD5",
            "qop=auth",
            f"nc={nc_val}",
            f'cnonce="{cnonce_val}"',
        ]
    else:
        resp = hashlib.md5(f"{ha1}:{safe_nonce}:{ha2}".encode("utf-8")).hexdigest()
        parts = [
            f'username="{safe_user}"',
            f'realm="{safe_realm}"',
            f'nonce="{safe_nonce}"',
            f'uri="{safe_uri}"',
            f'response="{resp}"',
            "algorithm=MD5",
        ]

    if opaque:
        parts.append(f'opaque="{sanitize_sip_token(opaque)}"')

    return f"{sanitize_sip_token(header_name)}: Digest " + ", ".join(parts)


def parse_sdp_offer(sdp_body: str) -> SDPOffer | None:
    """Extract media IP, port, payload types, and optional SDES SRTP crypto from SDP."""
    if not sdp_body:
        return None
    media_ip = ""
    media_port = 0
    payload_types: list[int] = []
    dtmf_pt = 101
    crypto_tag: int | None = None
    crypto_suite: str | None = None
    crypto_inline_b64: str | None = None

    for raw_line in sdp_body.splitlines():
        line = raw_line.strip()
        if line.startswith("c=IN IP4 "):
            media_ip = line.split("c=IN IP4 ", 1)[1].split("/")[0].strip()
        elif line.startswith("m=audio "):
            parts = line.split()
            if len(parts) >= 4 and parts[1].isdigit():
                media_port = int(parts[1])
                for pt in parts[3:]:
                    if pt.isdigit():
                        payload_types.append(int(pt))
        elif line.startswith("a=rtpmap:"):
            # e.g. a=rtpmap:101 telephone-event/8000
            m = re.match(r"a=rtpmap:(\d+)\s+([^\s/]+)", line, re.IGNORECASE)
            if m and m.group(2).lower() == "telephone-event":
                dtmf_pt = int(m.group(1))
        elif line.startswith("a=crypto:") and crypto_inline_b64 is None:
            # e.g. a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj|2^31
            m = re.match(
                r"a=crypto:(\d+)\s+(AES_CM_128_HMAC_SHA1_(?:80|32))\s+inline:([A-Za-z0-9+/=]+)",
                line,
            )
            if m:
                crypto_tag = int(m.group(1))
                crypto_suite = m.group(2)
                crypto_inline_b64 = m.group(3)

    if not media_ip or media_port <= 0:
        return None

    return SDPOffer(
        media_ip=media_ip,
        media_port=media_port,
        payload_types=payload_types,
        dtmf_payload_type=dtmf_pt,
        crypto_tag=crypto_tag,
        crypto_suite=crypto_suite,
        crypto_inline_b64=crypto_inline_b64,
    )


def build_sdp_body(
    *,
    public_ip: str,
    rtp_port: int,
    srtp_ctx: SRTPContext | None = None,
    crypto_tag: int = 1,
    crypto_suite: str = "AES_CM_128_HMAC_SHA1_80",
    dtmf_payload_type: int = 101,
) -> str:
    """Build SDP body for G.711 PCMU (PT 0) + RFC 4733 telephone-event + optional SDES SRTP."""
    safe_ip = sanitize_sip_token(public_ip, max_length=64)
    proto = "RTP/SAVP" if srtp_ctx is not None else "RTP/AVP"
    lines = [
        "v=0",
        f"o=ai-assistant-voice 1000 1000 IN IP4 {safe_ip}",
        "s=AI Assistant Voice Engine",
        f"c=IN IP4 {safe_ip}",
        "t=0 0",
        f"m=audio {int(rtp_port)} {proto} 0 {int(dtmf_payload_type)}",
        "a=rtpmap:0 PCMU/8000",
        f"a=rtpmap:{int(dtmf_payload_type)} telephone-event/8000",
        f"a=fmtp:{int(dtmf_payload_type)} 0-16",
        "a=ptime:20",
        "a=sendrecv",
    ]
    if srtp_ctx is not None:
        lines.append(
            f"a=crypto:{int(crypto_tag)} {sanitize_sip_token(crypto_suite)} inline:{srtp_ctx.to_sdp_inline()}"
        )
    return "\r\n".join(lines) + "\r\n"


def build_register_request(
    *,
    server: str,
    username: str,
    display_name: str,
    contact_host: str,
    contact_port: int,
    transport: str,
    call_id: str,
    cseq: int,
    from_tag: str,
    expires: int = 180,
    auth_header: str | None = None,
) -> str:
    """Construct a sanitized SIP REGISTER request."""
    srv = sanitize_sip_token(server)
    user = sanitize_sip_token(username)
    disp = sanitize_sip_token(display_name)
    chost = sanitize_sip_token(contact_host)
    trans = sanitize_sip_token(transport).upper()
    cid = sanitize_sip_token(call_id)
    ftag = sanitize_sip_token(from_tag)
    branch = f"z9hG4bK-{secrets.token_hex(8)}"

    headers = [
        f"REGISTER sip:{srv} SIP/2.0",
        f"Via: SIP/2.0/{trans} {chost}:{int(contact_port)};rport;branch={branch}",
        "Max-Forwards: 70",
        f'From: "{disp}" <sip:{user}@{srv}>;tag={ftag}',
        f"To: <sip:{user}@{srv}>",
        f"Call-ID: {cid}",
        f"CSeq: {int(cseq)} REGISTER",
        f"Contact: <sip:{user}@{chost}:{int(contact_port)};transport={trans.lower()}>",
        f"Expires: {int(expires)}",
        "Allow: INVITE, ACK, CANCEL, BYE, OPTIONS, MESSAGE, REFER, NOTIFY",
        "User-Agent: ai-assistant-voice/0.1.0",
    ]
    if auth_header:
        headers.append(sanitize_sip_token(auth_header, max_length=1024))
    headers.append("Content-Length: 0")
    return "\r\n".join(headers) + "\r\n\r\n"


def build_invite_request(
    *,
    target_number: str,
    server: str,
    username: str,
    caller_id_number: str,
    display_name: str,
    contact_host: str,
    contact_port: int,
    transport: str,
    call_id: str,
    cseq: int,
    from_tag: str,
    sdp_body: str,
    auth_header: str | None = None,
) -> str:
    """Construct a sanitized outbound SIP INVITE request."""
    target = sanitize_sip_token(target_number).lstrip("+")
    srv = sanitize_sip_token(server)
    user = sanitize_sip_token(username)
    cid_num = sanitize_sip_token(caller_id_number or username).lstrip("+")
    disp = sanitize_sip_token(display_name)
    chost = sanitize_sip_token(contact_host)
    trans = sanitize_sip_token(transport).upper()
    cid = sanitize_sip_token(call_id)
    ftag = sanitize_sip_token(from_tag)
    branch = f"z9hG4bK-{secrets.token_hex(8)}"
    body_bytes = sdp_body.encode("utf-8")

    headers = [
        f"INVITE sip:{target}@{srv} SIP/2.0",
        f"Via: SIP/2.0/{trans} {chost}:{int(contact_port)};rport;branch={branch}",
        "Max-Forwards: 70",
        f'From: "{disp}" <sip:{user}@{srv}>;tag={ftag}',
        f"To: <sip:{target}@{srv}>",
        f"Call-ID: {cid}",
        f"CSeq: {int(cseq)} INVITE",
        f"Contact: <sip:{user}@{chost}:{int(contact_port)};transport={trans.lower()}>",
        f'P-Asserted-Identity: "{disp}" <sip:{cid_num}@{srv}>',
        "Allow: INVITE, ACK, CANCEL, BYE, OPTIONS, MESSAGE, REFER, NOTIFY",
        "User-Agent: ai-assistant-voice/0.1.0",
        "Content-Type: application/sdp",
    ]
    if auth_header:
        headers.append(sanitize_sip_token(auth_header, max_length=1024))
    headers.append(f"Content-Length: {len(body_bytes)}")
    return "\r\n".join(headers) + "\r\n\r\n" + sdp_body


def build_sip_message_request(
    *,
    target_number: str,
    server: str,
    username: str,
    caller_id_number: str,
    display_name: str,
    contact_host: str,
    contact_port: int,
    transport: str,
    call_id: str,
    cseq: int,
    from_tag: str,
    text_body: str,
    auth_header: str | None = None,
) -> str:
    """Construct a sanitized SIP MESSAGE request for SMS delivery."""
    target = sanitize_sip_token(target_number).lstrip("+")
    srv = sanitize_sip_token(server)
    user = sanitize_sip_token(caller_id_number or username).lstrip("+")
    disp = sanitize_sip_token(display_name)
    chost = sanitize_sip_token(contact_host)
    trans = sanitize_sip_token(transport).upper()
    cid = sanitize_sip_token(call_id)
    ftag = sanitize_sip_token(from_tag)
    branch = f"z9hG4bK-{secrets.token_hex(8)}"
    body_bytes = text_body.encode("utf-8")

    headers = [
        f"MESSAGE sip:{target}@{srv} SIP/2.0",
        f"Via: SIP/2.0/{trans} {chost}:{int(contact_port)};rport;branch={branch}",
        "Max-Forwards: 70",
        f'From: "{disp}" <sip:{user}@{srv}>;tag={ftag}',
        f"To: <sip:{target}@{srv}>",
        f"Call-ID: {cid}",
        f"CSeq: {int(cseq)} MESSAGE",
        "User-Agent: ai-assistant-voice/0.1.0",
        "Content-Type: text/plain; charset=utf-8",
    ]
    if auth_header:
        headers.append(sanitize_sip_token(auth_header, max_length=1024))
    headers.append(f"Content-Length: {len(body_bytes)}")
    return "\r\n".join(headers) + "\r\n\r\n" + text_body


def build_refer_request(
    *,
    request_uri: str,
    refer_to_number: str,
    server: str,
    username: str,
    contact_host: str,
    contact_port: int,
    transport: str,
    call_id: str,
    cseq: int,
    from_header: str,
    to_header: str,
) -> str:
    """Construct a sanitized blind-transfer SIP REFER request."""
    req_uri = sanitize_sip_token(request_uri)
    refer_target = sanitize_sip_token(refer_to_number).lstrip("+")
    srv = sanitize_sip_token(server)
    user = sanitize_sip_token(username)
    chost = sanitize_sip_token(contact_host)
    trans = sanitize_sip_token(transport).upper()
    cid = sanitize_sip_token(call_id)
    f_hdr = sanitize_sip_token(from_header, max_length=512)
    t_hdr = sanitize_sip_token(to_header, max_length=512)
    branch = f"z9hG4bK-{secrets.token_hex(8)}"

    headers = [
        f"REFER {req_uri} SIP/2.0",
        f"Via: SIP/2.0/{trans} {chost}:{int(contact_port)};rport;branch={branch}",
        "Max-Forwards: 70",
        f"From: {f_hdr}",
        f"To: {t_hdr}",
        f"Call-ID: {cid}",
        f"CSeq: {int(cseq)} REFER",
        f"Contact: <sip:{user}@{chost}:{int(contact_port)};transport={trans.lower()}>",
        f"Refer-To: <sip:{refer_target}@{srv}>",
        f"Referred-By: <sip:{user}@{srv}>",
        "User-Agent: ai-assistant-voice/0.1.0",
        "Content-Length: 0",
    ]
    return "\r\n".join(headers) + "\r\n\r\n"
