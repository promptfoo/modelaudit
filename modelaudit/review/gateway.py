"""Small bounded Responses relay, run OUTSIDE the credential-free reviewer container.

Bind only to the private review network. Never publish its port to the host.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

MAX_REQUEST_BYTES = 2 * 1024 * 1024


def request_body(raw: bytes, model: str) -> bytes:
    if len(raw) > MAX_REQUEST_BYTES:
        raise ValueError("Request body exceeds gateway limit")
    body = json.loads(raw)
    if not isinstance(body, dict) or body.get("model") != model:
        raise ValueError("Model is not allowed by this gateway")
    limit = body.get("max_output_tokens", 4096)
    if type(limit) is not int or limit <= 0:
        raise ValueError("Invalid output token limit")
    body["max_output_tokens"] = min(limit, 4096)
    body["store"] = False
    # Do not permit provider-hosted tools or background work through this relay.
    if body.get("background") or any(tool.get("type") not in {"function", "custom"} for tool in body.get("tools", [])):
        raise ValueError("Only client-side Codex tools are allowed")
    return json.dumps(body, allow_nan=False).encode()


def gateway_handler(key: str, model: str, max_requests: int) -> type[BaseHTTPRequestHandler]:
    remaining = max_requests

    class Handler(BaseHTTPRequestHandler):
        def setup(self) -> None:
            self.request.settimeout(30)
            super().setup()

        def log_message(self, format: str, *args: Any) -> None:
            pass  # Never log provider headers, model data, or credentials.

        def do_POST(self) -> None:
            nonlocal remaining
            if (
                self.path != "/v1/responses"
                or self.headers.get("Transfer-Encoding")
                or self.headers.get("Content-Encoding")
            ):
                self.send_error(400)
                return
            try:
                size = int(self.headers.get("Content-Length", "-1"))
                if not 0 < size <= MAX_REQUEST_BYTES:
                    raise ValueError("Invalid request size")
                self.connection.settimeout(30)
                body = request_body(self.rfile.read(size), model)
                if remaining <= 0:
                    self.send_error(429)
                    return
                remaining -= 1
            except (ValueError, TypeError, AttributeError, OSError):
                self.send_error(400)
                return
            connection = http.client.HTTPSConnection("api.openai.com", timeout=120)
            sent_headers = False
            try:
                connection.request(
                    "POST",
                    "/v1/responses",
                    body=body,
                    headers={
                        "Authorization": f"Bearer {key}",
                        "Content-Type": "application/json",
                        "Accept": "text/event-stream",
                    },
                )
                response = connection.getresponse()
                self.send_response(response.status)
                self.send_header("Content-Type", response.getheader("Content-Type", "application/json"))
                self.send_header("Connection", "close")
                self.end_headers()
                sent_headers = True
                total = 0
                while chunk := response.read1(65536):
                    total += len(chunk)
                    if total > 16 * 1024 * 1024:
                        break
                    self.wfile.write(chunk)
                    self.wfile.flush()
            except (OSError, http.client.HTTPException):
                if not sent_headers:
                    self.send_error(502)
            finally:
                connection.close()
                self.close_connection = True

    return Handler


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", required=True, help="Gateway's IP on the private Docker network")
    parser.add_argument("--model", required=True)
    parser.add_argument("--max-requests", type=int, default=16)
    args = parser.parse_args()
    key = os.environ.pop("OPENAI_API_KEY", "")
    if not key or args.max_requests <= 0:
        parser.error("Set OPENAI_API_KEY on the gateway only; max-requests must be positive")
    server = HTTPServer((args.bind, 8080), gateway_handler(key, args.model, args.max_requests))
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
