#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import io
import json
import os
import shlex
import subprocess
import time
import urllib.parse
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from honeypot_static_server import (
    BEIJING,
    csv_text,
    event_export_match,
    event_field_value,
    load_event,
    parse_fields,
    range_start,
)


DEFAULT_ALLOWED_CLIENTS = "203.0.113.40,127.0.0.1,::1"
DEFAULT_HDFS_ROOT = "/honeypot/dwd/cleaned_events"


def date_partitions(start, end) -> list[str]:
    if start is None or end is None:
        return []
    dates = set()
    for tz in (timezone.utc, BEIJING):
        current = start.astimezone(tz).date()
        last = end.astimezone(tz).date()
        for _ in range(370):
            dates.add(current.isoformat())
            if current >= last:
                break
            current += timedelta(days=1)
    return sorted(dates)


def hdfs_cat_command(root: str, start, end) -> str:
    root = root.rstrip("/")
    partitions = date_partitions(start, end)
    if partitions:
        paths = " ".join(shlex.quote(f"{root}/date={date}/cleaned_events.jsonl") for date in partitions)
        return f"for f in {paths}; do hdfs dfs -test -f \"$f\" 2>/dev/null && hdfs dfs -cat \"$f\"; done"
    return "hdfs dfs -cat {pattern} 2>/dev/null".format(
        pattern=shlex.quote(f"{root}/date=*/cleaned_events.jsonl")
    )


class HdfsExportHandler(BaseHTTPRequestHandler):
    server_version = "HoneypotHdfsExport/1.0"
    hdfs_root = DEFAULT_HDFS_ROOT
    token = ""
    allowed_clients: set[str] = set()
    command_timeout = 1800

    def log_message(self, fmt: str, *args) -> None:
        print("%s - - [%s] %s" % (self.client_address[0], self.log_date_time_string(), fmt % args), flush=True)

    def client_allowed(self) -> bool:
        if not self.allowed_clients:
            return True
        return self.client_address[0] in self.allowed_clients

    def authorized(self) -> bool:
        if not self.client_allowed():
            return False
        provided = self.headers.get("X-Export-Token", "")
        return bool(self.token) and provided == self.token

    def send_text(self, status: int, text: str) -> None:
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urllib.parse.urlparse(self.path).path
        if path == "/health":
            if not self.authorized():
                self.send_text(403, "forbidden\n")
                return
            self.send_health()
            return
        if path == "/export/events.csv":
            if not self.authorized():
                self.send_text(403, "forbidden\n")
                return
            self.handle_events_csv_export()
            return
        self.send_text(404, "not found\n")

    def send_health(self) -> None:
        command = "source /etc/profile.d/hadoop.sh >/dev/null 2>&1 || true; hdfs dfs -test -d {root}".format(
            root=shlex.quote(self.hdfs_root)
        )
        try:
            result = subprocess.run(["bash", "-lc", command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            ok = result.returncode == 0
            detail = "ok" if ok else result.stderr.decode("utf-8", errors="replace")[-300:]
        except subprocess.TimeoutExpired:
            ok = False
            detail = "hdfs health check timed out"
        payload = {
            "ok": ok,
            "hdfsRoot": self.hdfs_root,
            "detail": detail,
            "checkedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(200 if ok else 503)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def handle_events_csv_export(self) -> None:
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        fields = parse_fields(query)
        protocol = (query.get("protocol") or ["ALL"])[0].upper()
        method = (query.get("method") or ["ALL"])[0]
        start, end, range_valid = range_start(query)
        if not range_valid:
            self.send_text(400, "invalid export time range\n")
            return

        command = "source /etc/profile.d/hadoop.sh >/dev/null 2>&1 || true; export HADOOP_USER_NAME=hadoop; " + hdfs_cat_command(
            self.hdfs_root,
            start,
            end,
        )
        process = subprocess.Popen(
            ["bash", "-lc", command],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )

        filename = f"honeypot_events_hdfs_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("X-Export-Source", "hdfs-dwd")
        self.end_headers()

        started = time.monotonic()
        try:
            buffer = io.StringIO()
            writer = csv.writer(buffer)
            buffer.write("\ufeff")
            writer.writerow(fields)
            self.wfile.write(buffer.getvalue().encode("utf-8"))
            self.wfile.flush()
            buffer.seek(0)
            buffer.truncate(0)
            assert process.stdout is not None
            written = 0
            for line in process.stdout:
                if time.monotonic() - started > self.command_timeout:
                    break
                event = load_event(line)
                if not event:
                    continue
                if not event_export_match(event, protocol, method, start, end):
                    continue
                writer.writerow([csv_text(event_field_value(event, field)) for field in fields])
                written += 1
                if written % 1000 == 0 or buffer.tell() >= 1024 * 1024:
                    self.wfile.write(buffer.getvalue().encode("utf-8"))
                    buffer.seek(0)
                    buffer.truncate(0)
            if buffer.tell():
                self.wfile.write(buffer.getvalue().encode("utf-8"))
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            if process.poll() is None:
                process.terminate()


def read_token(path: str) -> str:
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read().strip()


def main() -> None:
    parser = argparse.ArgumentParser(description="Read-only HDFS export API for honeypot DWD events.")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9101)
    parser.add_argument("--hdfs-root", default=DEFAULT_HDFS_ROOT)
    parser.add_argument("--token-file", default="/etc/honeypot-hdfs-export-api/token")
    parser.add_argument("--allowed-client", default=DEFAULT_ALLOWED_CLIENTS)
    parser.add_argument("--command-timeout", type=int, default=1800)
    args = parser.parse_args()

    HdfsExportHandler.hdfs_root = args.hdfs_root.rstrip("/")
    HdfsExportHandler.token = read_token(args.token_file)
    HdfsExportHandler.allowed_clients = {
        item.strip() for item in args.allowed_client.split(",") if item.strip()
    }
    HdfsExportHandler.command_timeout = args.command_timeout

    with ThreadingHTTPServer((args.host, args.port), HdfsExportHandler) as httpd:
        print(f"Serving HDFS export API on {args.host}:{args.port}", flush=True)
        httpd.serve_forever()


if __name__ == "__main__":
    main()
