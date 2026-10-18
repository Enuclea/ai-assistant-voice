"""Dual-Transport Model Context Protocol (MCP) Server for `ai-assistant-voice`.

Supports:
1. `stdio` JSON-RPC 2.0 transport for Desktop agents (Claude Desktop, Muse Code, Grok CLI, Antigravity).
2. `http` Streamable HTTP (`/mcp`) + RFC 9728 OAuth 2.1 Protected Resource Metadata
   (`/.well-known/oauth-protected-resource`) for Provider-Hosted cloud agents
   (xAI GrokBot Remote MCP, Meta Muse Hosted Connectors, Claude/ChatGPT Custom Connectors, Dots).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
import uvicorn

from .config import VoiceSettings
from .orchestrator import VoiceOrchestrator
from .security import SecurityPolicyError, verify_bearer_token, verify_origin

logger = logging.getLogger(__name__)

MCP_PROTOCOL_VERSION = "2025-03-26"
MAX_MCP_BODY_BYTES = 256 * 1024

MCP_TOOLS: list[dict[str, Any]] = [
    {
        "name": "voice_call_outbound",
        "description": (
            "Place an autonomous outbound phone call via SIP/SRTP. Starts in Silent Turn 0 listening mode, "
            "automatically navigates keypad IVR menus via RFC 4733 DTMF, waits silently during voicemail greetings "
            "until the beep, and enforces a strict Context Firewall so only `approved_facts` can be shared."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "to_number": {
                    "type": "string",
                    "description": "Destination phone number in E.164 or 10-digit NANP format (e.g. '+18005550199').",
                },
                "recipient_name": {
                    "type": "string",
                    "description": "Name of the person or business being called.",
                },
                "objective": {
                    "type": "string",
                    "description": "Clear goal for the call (e.g. 'Confirm dinner reservation for 4 at 7 PM Friday').",
                },
                "approved_facts": {
                    "type": "object",
                    "description": (
                        "Explicit key-value facts the voice agent is allowed to share if asked "
                        "(e.g. {'callback_number': '+12025550144', 'party_size': '4'})."
                    ),
                    "additionalProperties": {"type": "string"},
                },
                "wait_for_completion": {
                    "type": "boolean",
                    "description": "If true, wait for the call to finish before returning; if false, return call_id immediately.",
                    "default": False,
                },
            },
            "required": ["to_number", "objective"],
        },
    },
    {
        "name": "voice_get_call",
        "description": "Get the status, structured outcome, DTMF history, and turn-by-turn transcript of a phone call.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "call_id": {
                    "type": "string",
                    "description": "Unique call identifier returned by `voice_call_outbound` or `voice_list_calls`.",
                },
            },
            "required": ["call_id"],
        },
    },
    {
        "name": "voice_list_calls",
        "description": "List recent inbound and outbound phone calls with outcomes and summaries.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of calls to return (1-200).",
                    "default": 20,
                },
                "direction": {
                    "type": "string",
                    "enum": ["inbound", "outbound"],
                    "description": "Optional filter by call direction.",
                },
            },
        },
    },
    {
        "name": "voice_send_dtmf",
        "description": "Transmit RFC 4733 + in-band DTMF keypad digits ('0-9', '*', '#', 'w' pause) on an active call.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "call_id": {"type": "string"},
                "digits": {
                    "type": "string",
                    "description": "Keypad digits to press (e.g. '1', 'w104#').",
                },
                "reason": {
                    "type": "string",
                    "description": "Menu option or extension being dialed.",
                },
            },
            "required": ["call_id", "digits"],
        },
    },
    {
        "name": "voice_hangup_call",
        "description": "Disconnect an active phone call immediately.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "call_id": {"type": "string"},
                "reason": {"type": "string"},
            },
            "required": ["call_id"],
        },
    },
    {
        "name": "voice_send_sms",
        "description": "Send an outbound SMS text message via the configured VoIP DID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "to_number": {
                    "type": "string",
                    "description": "Destination phone number in E.164 format.",
                },
                "message": {
                    "type": "string",
                    "description": "Text message body (max 1000 chars).",
                },
            },
            "required": ["to_number", "message"],
        },
    },
    {
        "name": "voice_list_sms",
        "description": (
            "List recent SMS messages or retrieve extracted 2FA/OTP verification codes (`only_otp=true`)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "default": 20},
                "remote_number": {
                    "type": "string",
                    "description": "Optional phone number filter.",
                },
                "only_otp": {
                    "type": "boolean",
                    "description": "If true, return only inbound messages containing a parsed 2FA/OTP code.",
                    "default": False,
                },
            },
        },
    },
    {
        "name": "voice_manage_vip_client",
        "description": "Add, update, or list VIP clients on the inbound receptionist allowlist.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["upsert", "list"],
                    "default": "list",
                },
                "phone_number": {"type": "string"},
                "name": {"type": "string"},
                "company": {"type": "string"},
                "notes": {"type": "string"},
                "auto_transfer": {"type": "boolean", "default": True},
            },
            "required": ["action"],
        },
    },
    {
        "name": "voice_system_status",
        "description": "Return SIP/SRTP configuration status, active calls count, and remaining hourly rate-limit budgets.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
]


class VoiceMCPServer:
    """JSON-RPC 2.0 MCP dispatcher and Streamable HTTP / stdio transport handler."""

    def __init__(self, orchestrator: VoiceOrchestrator | None = None) -> None:
        self.orchestrator = orchestrator or VoiceOrchestrator()

    async def execute_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Dispatch an MCP `tools/call` invocation to `VoiceOrchestrator`."""
        args = arguments or {}
        if name == "voice_call_outbound":
            return await self.orchestrator.place_outbound_call(
                to_number=str(args.get("to_number", "")),
                recipient_name=str(args.get("recipient_name", "")),
                objective=str(args.get("objective", "")),
                approved_facts=args.get("approved_facts") if isinstance(args.get("approved_facts"), dict) else None,
                wait_for_completion=bool(args.get("wait_for_completion", False)),
            )

        if name == "voice_get_call":
            call_id = str(args.get("call_id", "")).strip()
            call = self.orchestrator.store.get_call(call_id)
            if not call:
                return {"ok": False, "error": f"Call {call_id!r} not found"}
            return {"ok": True, "call": call}

        if name == "voice_list_calls":
            calls = self.orchestrator.store.list_calls(
                limit=int(args.get("limit", 20)),
                direction=args.get("direction"),
            )
            return {"ok": True, "calls": calls}

        if name == "voice_send_dtmf":
            return await self.orchestrator.handle_call_tool(
                str(args.get("call_id", "")),
                "send_dtmf",
                {
                    "digits": str(args.get("digits", "")),
                    "reason": str(args.get("reason", "")),
                },
            )

        if name == "voice_hangup_call":
            return await self.orchestrator.hangup_call(
                str(args.get("call_id", "")),
                reason=str(args.get("reason", "Hung up via MCP")),
            )

        if name == "voice_send_sms":
            sms = await self.orchestrator.send_sms(
                to_number=str(args.get("to_number", "")),
                message=str(args.get("message", "")),
            )
            return {"ok": True, "sms": sms}

        if name == "voice_list_sms":
            messages = self.orchestrator.store.list_sms(
                limit=int(args.get("limit", 20)),
                remote_number=args.get("remote_number"),
                only_otp=bool(args.get("only_otp", False)),
            )
            return {"ok": True, "messages": messages}

        if name == "voice_manage_vip_client":
            action = str(args.get("action", "list")).lower()
            if action == "upsert":
                client = self.orchestrator.store.upsert_known_client(
                    phone_number=str(args.get("phone_number", "")),
                    name=str(args.get("name", "")),
                    company=str(args.get("company", "")),
                    notes=str(args.get("notes", "")),
                    auto_transfer=bool(args.get("auto_transfer", True)),
                )
                return {"ok": True, "client": client}
            return {"ok": True, "clients": self.orchestrator.store.list_known_clients()}

        if name == "voice_system_status":
            return {"ok": True, "status": self.orchestrator.get_status()}

        raise ValueError(f"Unknown MCP tool: {name!r}")

    async def handle_jsonrpc(self, request_obj: dict[str, Any]) -> dict[str, Any] | None:
        """Process a single JSON-RPC 2.0 MCP message and return a response dict (or None for notifications)."""
        req_id = request_obj.get("id")
        method = request_obj.get("method", "")
        params = request_obj.get("params") or {}

        # Notifications (no id) do not return a response object
        if req_id is None and method.startswith("notifications/"):
            return None

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "serverInfo": {
                        "name": "ai-assistant-voice",
                        "version": "0.1.0",
                    },
                    "capabilities": {
                        "tools": {"listChanged": False},
                    },
                },
            }

        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": MCP_TOOLS},
            }

        if method == "tools/call":
            tool_name = str(params.get("name", ""))
            tool_args = params.get("arguments") or {}
            try:
                output = await self.execute_tool(tool_name, tool_args)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(output, ensure_ascii=False, indent=2),
                            }
                        ],
                        "isError": False,
                    },
                }
            except (SecurityPolicyError, ValueError) as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(
                                    {"ok": False, "error": str(exc)},
                                    ensure_ascii=False,
                                ),
                            }
                        ],
                        "isError": True,
                    },
                }
            except Exception as exc:
                logger.exception("Unhandled error in MCP tool %s", tool_name)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(
                                    {"ok": False, "error": f"Internal tool error: {type(exc).__name__}"},
                                    ensure_ascii=False,
                                ),
                            }
                        ],
                        "isError": True,
                    },
                }

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32601,
                "message": f"Method not found: {method}",
            },
        }

    def create_http_app(self) -> FastAPI:
        """Create the FastAPI Streamable HTTP + RFC 9728 OAuth Metadata web application."""
        settings = self.orchestrator.settings
        settings.validate_security_posture()

        app = FastAPI(title="ai-assistant-voice MCP Server", version="0.1.0")
        app.add_api_route("/healthz", self._handle_healthz, methods=["GET"])
        app.add_api_route(
            "/.well-known/oauth-protected-resource",
            self._handle_oauth_protected_resource,
            methods=["GET"],
        )
        app.add_api_route("/mcp", self._handle_http_mcp, methods=["POST"])
        return app

    async def _handle_healthz(self, _request: Request) -> JSONResponse:
        return JSONResponse({"ok": True, "service": "ai-assistant-voice"})

    async def _handle_oauth_protected_resource(self, request: Request) -> JSONResponse:
        """RFC 9728 OAuth 2.1 Protected Resource Metadata for Claude/ChatGPT/Muse/Dots connectors."""
        settings = self.orchestrator.settings
        host = request.headers.get("host", f"{settings.mcp_host}:{settings.mcp_port}")
        base_url = settings.mcp_public_url or f"{request.url.scheme}://{host}"
        metadata: dict[str, Any] = {
            "resource": f"{base_url.rstrip('/')}/mcp",
            "bearer_methods_supported": ["header"],
            "scopes_supported": ["voice:call", "voice:sms", "voice:read"],
        }
        if settings.oauth_issuer_url:
            metadata["authorization_servers"] = [settings.oauth_issuer_url]
        return JSONResponse(metadata)

    async def _handle_http_mcp(self, request: Request) -> Response:
        settings = self.orchestrator.settings
        client_host = request.client.host if request.client else "unknown"
        origin = request.headers.get("origin")
        if not verify_origin(origin, settings.allowed_origins):
            self.orchestrator.store.log_security_event(
                event_type="mcp_origin_rejected",
                severity="warning",
                actor=client_host,
                detail=f"Rejected Origin header: {origin!r}",
            )
            return JSONResponse({"error": "Origin not allowed"}, status_code=403)

        # Require Bearer authentication whenever mcp_auth_token is configured
        if settings.mcp_auth_token:
            auth_hdr = request.headers.get("authorization")
            if not verify_bearer_token(auth_hdr, settings.mcp_auth_token):
                self.orchestrator.store.log_security_event(
                    event_type="mcp_auth_failed",
                    severity="warning",
                    actor=client_host,
                    detail="Invalid or missing Bearer token on /mcp",
                )
                host = request.headers.get("host", f"{settings.mcp_host}:{settings.mcp_port}")
                base_url = settings.mcp_public_url or f"{request.url.scheme}://{host}"
                return JSONResponse(
                    {"error": "Unauthorized"},
                    status_code=401,
                    headers={
                        "WWW-Authenticate": (
                            f'Bearer resource_metadata="{base_url.rstrip("/")}/.well-known/oauth-protected-resource"'
                        )
                    },
                )

        raw_body = await request.body()
        if len(raw_body) > MAX_MCP_BODY_BYTES:
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32600, "message": "Request body too large"},
                },
                status_code=413,
            )

        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except Exception:
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": "Parse error"},
                },
                status_code=400,
            )

        if isinstance(payload, list):
            responses = []
            for item in payload:
                if isinstance(item, dict):
                    resp = await self.handle_jsonrpc(item)
                    if resp is not None:
                        responses.append(resp)
            if not responses:
                return Response(status_code=202)
            return JSONResponse(responses)

        if not isinstance(payload, dict):
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32600, "message": "Invalid Request"},
                },
                status_code=400,
            )

        resp = await self.handle_jsonrpc(payload)
        if resp is None:
            return Response(status_code=202)
        return JSONResponse(resp)

    async def run_stdio(self) -> None:
        """Run the MCP JSON-RPC 2.0 loop over stdin/stdout for desktop agents."""
        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin)

        while True:
            line = await reader.readline()
            if not line:
                break
            text = line.decode("utf-8", errors="replace").strip()
            if not text:
                continue
            try:
                req = json.loads(text)
            except json.JSONDecodeError:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": "Parse error"},
                }
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()
                continue

            if isinstance(req, dict):
                resp = await self.handle_jsonrpc(req)
                if resp is not None:
                    sys.stdout.write(json.dumps(resp) + "\n")
                    sys.stdout.flush()


def main(argv: list[str] | None = None) -> None:
    """CLI entrypoint for `ai-assistant-voice`."""
    parser = argparse.ArgumentParser(
        prog="ai-assistant-voice",
        description="Standalone SIP-TLS/SRTP-to-Realtime-LLM Voice & SMS MCP Server.",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "http"],
        default=None,
        help="MCP transport mode: 'stdio' (desktop) or 'http' (Streamable HTTP remote server).",
    )
    parser.add_argument(
        "--host",
        default=None,
        help="Bind address for Streamable HTTP transport (default: 127.0.0.1).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Bind port for Streamable HTTP transport (default: 8400).",
    )
    args = parser.parse_args(argv)

    settings = VoiceSettings.from_env()
    if args.transport:
        settings.mcp_transport = args.transport
    if args.host:
        settings.mcp_host = args.host
    if args.port:
        settings.mcp_port = args.port

    server = VoiceMCPServer(VoiceOrchestrator(settings=settings))

    if settings.mcp_transport == "http":
        app = server.create_http_app()
        uvicorn.run(app, host=settings.mcp_host, port=settings.mcp_port, log_level="info")
    else:
        asyncio.run(server.run_stdio())


if __name__ == "__main__":
    main()
