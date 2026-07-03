#!/usr/bin/env python3
import argparse
import datetime as dt
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


DEFAULT_ALLOWED_IPS = {
    "203.0.113.10",
    "203.0.113.11",
    "203.0.113.12",
    "127.0.0.1",
    "::1",
}

HONEYPOT_ALIASES = {
    "bigdata-honeypot-1": "203.0.113.10",
    "ctf-47": "203.0.113.11",
    "bigdata-honeypot-3": "203.0.113.12",
}

write_lock = threading.Lock()


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")


def day_string():
    return dt.datetime.now().strftime("%Y-%m-%d")


def safe_source(value):
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-."
    normalized = HONEYPOT_ALIASES.get(str(value or ""), value)
    cleaned = "".join(ch for ch in str(normalized or "unknown") if ch in allowed)
    return cleaned or "unknown"


class IngestHandler(BaseHTTPRequestHandler):
    server_version = "HoneypotIngest/1.0"

    def do_GET(self):
        if self.path != "/health":
            self.send_json(404, {"ok": False, "error": "not found"})
            return
        self.send_json(200, {"ok": True, "time": utc_now()})

    def do_POST(self):
        if self.path not in {"/ingest", "/ingest/"}:
            self.send_json(404, {"ok": False, "error": "not found"})
            return

        client_ip = self.client_address[0]
        if client_ip not in self.server.allowed_ips:
            self.send_json(403, {"ok": False, "error": "source ip not allowed", "source_ip": client_ip})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_json(400, {"ok": False, "error": "invalid content length"})
            return

        if length <= 0 or length > self.server.max_body_bytes:
            self.send_json(413, {"ok": False, "error": "invalid body size"})
            return

        raw_body = self.rfile.read(length)
        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except Exception as exc:
            self.send_json(400, {"ok": False, "error": f"invalid json: {exc}"})
            return

        source = safe_source(payload.get("source"))
        path = str(payload.get("path") or "")
        sent_at = str(payload.get("sent_at") or "")
        events = payload.get("events")
        lines = payload.get("lines")
        if isinstance(events, list) and events:
            mode = "events"
            items = events
        elif isinstance(lines, list) and lines:
            mode = "lines"
            items = lines
        else:
            self.send_json(400, {"ok": False, "error": "events or lines must be a non-empty list"})
            return

        records = []
        received_at = utc_now()
        for item in items:
            if item is None:
                continue
            if mode == "events":
                if not isinstance(item, dict):
                    continue
                record = dict(item)
                record.setdefault("server_id", source)
                record.setdefault("raw", "")
                record.update(
                    {
                        "received_at": received_at,
                        "source": source,
                        "source_ip": client_ip,
                        "path": path,
                        "sent_at": sent_at,
                    }
                )
            else:
                record = {
                    "received_at": received_at,
                    "source": source,
                    "source_ip": client_ip,
                    "path": path,
                    "sent_at": sent_at,
                    "line": str(item),
                }
            records.append(record)

        if not records:
            self.send_json(400, {"ok": False, "error": f"no valid {mode}"})
            return

        target_dir = os.path.join(self.server.data_dir, day_string())
        os.makedirs(target_dir, exist_ok=True)
        target_file = os.path.join(target_dir, f"{source}.jsonl")

        with write_lock:
            with open(target_file, "a", encoding="utf-8") as handle:
                for record in records:
                    handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")

        self.send_json(200, {"ok": True, "accepted": len(records), "mode": mode, "file": target_file})

    def log_message(self, fmt, *args):
        sys.stdout.write(
            f"{dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} "
            f"{self.client_address[0]} {fmt % args}\n"
        )
        sys.stdout.flush()

    def send_json(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class IngestServer(ThreadingHTTPServer):
    def __init__(self, address, handler, data_dir, allowed_ips, max_body_bytes):
        super().__init__(address, handler)
        self.data_dir = data_dir
        self.allowed_ips = set(allowed_ips)
        self.max_body_bytes = max_body_bytes


def parse_args():
    parser = argparse.ArgumentParser(description="Receive honeypot log lines over HTTP.")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--data-dir", default="/data/honeypot/stream")
    parser.add_argument("--allowed-ip", action="append", default=[])
    parser.add_argument("--max-body-bytes", type=int, default=5 * 1024 * 1024)
    return parser.parse_args()


def main():
    args = parse_args()
    allowed_ips = args.allowed_ip or sorted(DEFAULT_ALLOWED_IPS)
    os.makedirs(args.data_dir, exist_ok=True)
    server = IngestServer(
        (args.host, args.port),
        IngestHandler,
        data_dir=args.data_dir,
        allowed_ips=allowed_ips,
        max_body_bytes=args.max_body_bytes,
    )
    print(f"listening on {args.host}:{args.port}, data_dir={args.data_dir}, allowed_ips={','.join(allowed_ips)}")
    server.serve_forever()


if __name__ == "__main__":
    main()
