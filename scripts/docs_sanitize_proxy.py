#!/usr/bin/env python3
"""Sanitizing reverse proxy for docs screenshots.

Forwards a MiBee Steward instance to a local port, rewriting device
identifiers in API JSON responses so screenshots contain no real
hostnames / MACs / LAN IPs:

  - explicit name map  (personal device names -> generic demo names)
  - 192.168.63.x -> 192.168.1.x   (center LAN   -> doc-safe main LAN)
  - 192.168.62.x -> 192.168.2.x   (agent LAN    -> doc-safe branch LAN)
  - MAC suffix randomization      (OUI kept, NIC octets hashed)

Static assets pass through untouched. SSE (/changes/watch) is rewritten
line-by-line. Run: python scripts/docs_sanitize_proxy.py [upstream] [port]
"""

import hashlib
import http.server
import json
import os
import re
import sys
import urllib.error
import urllib.request

UPSTREAM = sys.argv[1] if len(sys.argv) > 1 else "http://192.168.63.101:8080"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8081
# NOTE: the map file holds REAL hostnames/MACs — keep it outside the repo.
MAP_PATH = sys.argv[3] if len(sys.argv) > 3 else os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "docs_sanitize_map.json")

HERE = os.path.dirname(os.path.abspath(__file__))
with open(MAP_PATH, encoding="utf-8") as f:
    _MAPPING = json.load(f)

NAME_MAP = dict(sorted(_MAPPING["names"].items(), key=lambda kv: -len(kv[0])))
MAC_MAP = {k.lower(): v for k, v in _MAPPING["macs"].items()}

IP_63 = re.compile(r"\b192\.168\.63\.(\d{1,3})\b")
IP_62 = re.compile(r"\b192\.168\.62\.(\d{1,3})\b")
MAC_RE = re.compile(r"\b([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})\b")


def sanitize(text: str) -> str:
    for real, fake in NAME_MAP.items():
        if real in text:
            text = text.replace(real, fake)
    text = IP_63.sub(lambda m: "192.168.1." + m.group(1), text)
    text = IP_62.sub(lambda m: "192.168.2." + m.group(1), text)

    def mac_sub(m):
        return MAC_MAP.get(m.group(1).lower(), m.group(0))

    return MAC_RE.sub(mac_sub, text)


def looks_like_payload(content_type: str, body: bytes) -> bool:
    if body and content_type and ("json" in content_type or "text" in content_type):
        return True
    return bool(body) and body[:1] in (b"{", b"[")


HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "content-length",
    "host", "origin", "referer",
}


class Proxy(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # quiet
        pass

    def _upstream_url(self):
        return UPSTREAM + self.path

    def _forward(self, body=None):
        headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP_HEADERS}
        # present ourselves as the upstream origin so CSRF same-origin checks pass
        headers["Host"] = UPSTREAM.split("://", 1)[1]
        headers["Origin"] = UPSTREAM
        headers["Referer"] = UPSTREAM + "/"
        req = urllib.request.Request(self._upstream_url(), data=body, headers=headers,
                                     method=self.command)
        try:
            resp = urllib.request.urlopen(req, timeout=60)
        except urllib.error.HTTPError as e:
            resp = e
        except Exception as e:  # upstream down
            self.send_error(502, str(e))
            return

        status, reason = resp.status, getattr(resp, "reason", "")
        ctype = resp.headers.get("Content-Type", "")
        is_sse = "text/event-stream" in ctype

        if is_sse:
            self.send_response(status)
            for k, v in resp.headers.items():
                if k.lower() not in HOP_HEADERS and k.lower() != "content-type":
                    self.send_header(k, v)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            try:
                for line in resp:
                    if line.strip():
                        line = sanitize(line.decode("utf-8", "replace")).encode("utf-8")
                    self.wfile.write(line)
                    self.wfile.flush()
            except Exception:
                pass
            return

        raw = resp.read()
        if looks_like_payload(ctype, raw) and "javascript" not in ctype and "css" not in ctype:
            text = raw.decode("utf-8", "replace")
            cleaned = sanitize(text)
            raw = cleaned.encode("utf-8")

        self.send_response(status, reason)
        for k, v in resp.headers.items():
            if k.lower() not in HOP_HEADERS:
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)

    def do_GET(self):
        self._forward()

    def do_HEAD(self):
        self._forward()

    def do_POST(self):
        self._forward(self._read_body())

    def do_PUT(self):
        self._forward(self._read_body())

    def do_PATCH(self):
        self._forward(self._read_body())

    def do_DELETE(self):
        self._forward()

    def do_OPTIONS(self):
        self._forward()

    def _read_body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else None


if __name__ == "__main__":
    server = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Proxy)
    print(f"sanitize proxy: http://127.0.0.1:{PORT} -> {UPSTREAM}", flush=True)
    server.serve_forever()
