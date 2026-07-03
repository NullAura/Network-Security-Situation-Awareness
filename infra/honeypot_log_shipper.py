#!/usr/bin/env python3
import argparse
import datetime as dt
import json
import os
import sys
import time
import urllib.error
import urllib.request


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")


def log(message):
    print(f"{dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} {message}", flush=True)


HONEYPOT_ALIASES = {
    "bigdata-honeypot-1": "203.0.113.10",
    "ctf-47": "203.0.113.11",
    "bigdata-honeypot-3": "203.0.113.12",
}

HONEYPOTS = {
    "203.0.113.10": {
        "ip": "203.0.113.10",
        "type": "cowrie",
    },
    "203.0.113.11": {
        "ip": "203.0.113.11",
        "type": "opencanary",
    },
    "203.0.113.12": {
        "ip": "203.0.113.12",
        "type": "honeypot3",
    },
}

PROTOCOL_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    80: "HTTP",
    443: "HTTP",
    445: "SMB",
    1433: "MSSQL",
    1521: "ORACLE",
    1883: "MQTT",
    2323: "TELNET",
    3306: "MYSQL",
    3389: "RDP",
    5432: "POSTGRES",
    5900: "VNC",
    5901: "VNC",
    5902: "VNC",
    5903: "VNC",
    5904: "VNC",
    5905: "VNC",
    6379: "REDIS",
    8080: "HTTP",
}

PROTOCOL_SEVERITY = {
    "SSH": "high",
    "MYSQL": "high",
    "REDIS": "high",
    "RDP": "high",
    "SMB": "high",
    "FTP": "medium",
    "HTTP": "medium",
    "TELNET": "medium",
    "MQTT": "medium",
    "ORACLE": "high",
    "KAFKA": "medium",
    "VNC": "low",
    "POSTGRES": "high",
    "MSSQL": "high",
}


def normalize_time(value):
    if not value:
        return utc_now()
    text = str(value)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    if len(text) >= 5 and text[-5] in {"+", "-"} and text[-3] != ":":
        text = text[:-2] + ":" + text[-2:]
    try:
        parsed = dt.datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed.astimezone(dt.timezone.utc).isoformat(timespec="seconds")
    except Exception:
        return text


def clean_text(value, max_len=500):
    if value is None:
        return ""
    return str(value).replace("\r", "\\r").replace("\n", "\\n")[:max_len]


def normalize_source_id(source):
    text = str(source or "")
    return HONEYPOT_ALIASES.get(text, text)


def norm_protocol(value, dst_port=None, payload=""):
    text = str(value or "").upper()
    if text in {
        "MYSQL",
        "REDIS",
        "SSH",
        "FTP",
        "HTTP",
        "TELNET",
        "RDP",
        "VNC",
        "MQTT",
        "ORACLE",
        "KAFKA",
        "SMB",
        "POSTGRES",
        "MSSQL",
    }:
        return text
    try:
        port = int(dst_port)
        if port in PROTOCOL_PORTS:
            return PROTOCOL_PORTS[port]
    except Exception:
        pass
    probe = str(payload or "").upper()
    if "GET " in probe or "POST " in probe or "HTTP/" in probe:
        return "HTTP"
    if "MQTT" in probe:
        return "MQTT"
    if "KAFKA" in probe:
        return "KAFKA"
    if "VNC" in probe or "RFB " in probe:
        return "VNC"
    if "CONNECT_DATA" in probe or "SERVICE_NAME" in probe:
        return "ORACLE"
    try:
        return f"TCP_{int(dst_port)}"
    except Exception:
        pass
    return "UNKNOWN"


def norm_event_type(obj, protocol):
    raw = str(obj.get("eventid") or obj.get("event_type") or obj.get("logtype") or "connection").lower()
    logdata = obj.get("logdata") if isinstance(obj.get("logdata"), dict) else {}
    detail = " ".join(
        str(value)
        for value in [
            obj.get("payload"),
            obj.get("raw_payload"),
            obj.get("request"),
            obj.get("message"),
            obj.get("raw"),
            json.dumps(logdata, ensure_ascii=False) if logdata else "",
        ]
        if value
    ).lower()
    if "login.failed" in raw or raw in {"6001"}:
        return "login_failed"
    if "login.success" in raw:
        return "login_success"
    if protocol == "VNC" and (raw in {"12001", "vnc"} or "vnc password" in detail or "vnc client response" in detail):
        return "vnc_auth_attempt"
    if "command.input" in raw or raw.endswith(".command"):
        return "command_input"
    if "file_download" in raw or "download" in raw:
        return "file_download"
    if "session.closed" in raw:
        return "session_closed"
    if protocol == "HTTP" and ("request" in raw or raw.isdigit()):
        return "http_request"
    if "payload" in raw:
        return "protocol_probe"
    if "connection" in raw or raw in {"6002"}:
        return "connection"
    if raw.isdigit():
        return f"opencanary_logtype_{raw}"
    return raw.replace("cowrie.", "").replace(".", "_")


def preprocess_line(source, path, line):
    source = normalize_source_id(source)
    raw_line = line.rstrip("\n")
    try:
        obj = json.loads(raw_line)
        if not isinstance(obj, dict):
            obj = {"raw_payload": obj}
    except Exception:
        obj = {"raw_payload": raw_line, "event_type": "parse_error"}

    hp = HONEYPOTS.get(source, {})
    logdata = obj.get("logdata") if isinstance(obj.get("logdata"), dict) else {}
    src_ip = obj.get("src_ip") or obj.get("src_host") or obj.get("source_ip")
    dst_ip = obj.get("dst_ip") or obj.get("dst_host") or hp.get("ip", "")
    dst_port = obj.get("dst_port") or obj.get("dest_port")
    payload = (
        obj.get("payload")
        or obj.get("raw_payload")
        or obj.get("request")
        or obj.get("message")
        or (json.dumps(logdata, ensure_ascii=False) if logdata else "")
    )
    protocol = norm_protocol(obj.get("protocol"), dst_port, payload)
    event_type = norm_event_type(obj, protocol)
    command = obj.get("input") if event_type == "command_input" else obj.get("command")
    username = obj.get("username") or obj.get("user") or logdata.get("USERNAME") or ""
    password = obj.get("password") or logdata.get("PASSWORD") or ""
    event_time = obj.get("timestamp") or obj.get("event_time") or obj.get("utc_time") or obj.get("local_time")
    severity = PROTOCOL_SEVERITY.get(protocol, "low")
    if event_type in {"command_input", "file_download"}:
        severity = "high"

    return {
        "event_time": normalize_time(event_time),
        "server_id": source,
        "honeypot_type": hp.get("type", source),
        "src_ip": str(src_ip or ""),
        "dst_ip": str(dst_ip or ""),
        "dst_port": int(dst_port) if str(dst_port or "").isdigit() else "",
        "protocol": protocol,
        "event_type": event_type,
        "username": clean_text(username, 120),
        "password": clean_text(password, 120),
        "command": clean_text(command, 300),
        "payload": clean_text(payload, 500),
        "country": "unknown",
        "region": "unknown",
        "city": "unknown",
        "isp": "unknown",
        "asn": "unknown",
        "severity": severity,
        "raw": raw_line,
        "source_log_path": path,
    }


def post_batch(endpoint, source, path, events, timeout, raw_mode=False):
    source = normalize_source_id(source)
    key = "lines" if raw_mode else "events"
    body = json.dumps(
        {
            "source": source,
            "path": path,
            "sent_at": utc_now(),
            key: events,
        },
        ensure_ascii=False,
    ).encode("utf-8")
    request = urllib.request.Request(
        endpoint,
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = response.read().decode("utf-8", errors="replace")
        if response.status != 200:
            raise RuntimeError(f"HTTP {response.status}: {payload}")
        return payload


def read_offset(state_file):
    try:
        with open(state_file, "r", encoding="utf-8") as handle:
            return int(handle.read().strip() or "0")
    except FileNotFoundError:
        return None
    except Exception:
        return None


def write_offset(state_file, offset):
    os.makedirs(os.path.dirname(state_file), exist_ok=True)
    tmp = f"{state_file}.tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(str(offset))
    os.replace(tmp, state_file)


def open_at_position(path, state_file, start):
    handle = open(path, "r", encoding="utf-8", errors="replace")
    saved_offset = read_offset(state_file)
    if saved_offset is None:
        if start == "beginning":
            offset = 0
        else:
            handle.seek(0, os.SEEK_END)
            offset = handle.tell()
        write_offset(state_file, offset)
    else:
        size = os.path.getsize(path)
        offset = min(saved_offset, size)
    handle.seek(offset)
    return handle, os.fstat(handle.fileno()).st_ino, offset


def main():
    parser = argparse.ArgumentParser(description="Tail a honeypot log file and POST new lines to the collector.")
    parser.add_argument("--source", required=True)
    parser.add_argument("--path", required=True)
    parser.add_argument("--endpoint", default="http://203.0.113.20:9000/ingest")
    parser.add_argument("--state-file", required=True)
    parser.add_argument("--batch-lines", type=int, default=100)
    parser.add_argument("--flush-seconds", type=float, default=1.0)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--start", choices=["end", "beginning"], default="end")
    parser.add_argument("--raw-lines", action="store_true", help="Send raw lines instead of preprocessed events.")
    args = parser.parse_args()

    log(f"starting source={args.source} path={args.path} endpoint={args.endpoint}")
    handle = None
    inode = None
    committed_offset = 0
    batch = []
    last_flush = time.monotonic()

    while True:
        try:
            if handle is None:
                while not os.path.exists(args.path):
                    log(f"waiting for {args.path}")
                    time.sleep(1.0)
                handle, inode, committed_offset = open_at_position(args.path, args.state_file, args.start)
                log(f"opened {args.path} inode={inode} offset={committed_offset}")

            line = handle.readline()
            if line:
                item = line.rstrip("\n") if args.raw_lines else preprocess_line(args.source, args.path, line)
                batch.append(item)
                if len(batch) >= args.batch_lines:
                    response = post_batch(
                        args.endpoint,
                        args.source,
                        args.path,
                        batch,
                        args.timeout,
                        raw_mode=args.raw_lines,
                    )
                    committed_offset = handle.tell()
                    write_offset(args.state_file, committed_offset)
                    log(f"sent={len(batch)} offset={committed_offset} response={response}")
                    batch.clear()
                    last_flush = time.monotonic()
                continue

            now = time.monotonic()
            if batch and now - last_flush >= args.flush_seconds:
                response = post_batch(
                    args.endpoint,
                    args.source,
                    args.path,
                    batch,
                    args.timeout,
                    raw_mode=args.raw_lines,
                )
                committed_offset = handle.tell()
                write_offset(args.state_file, committed_offset)
                log(f"sent={len(batch)} offset={committed_offset} response={response}")
                batch.clear()
                last_flush = now

            try:
                stat_result = os.stat(args.path)
                current_offset = handle.tell()
                if stat_result.st_ino != inode or stat_result.st_size < current_offset:
                    log("detected rotation or truncation; reopening from beginning")
                    handle.close()
                    handle = open(args.path, "r", encoding="utf-8", errors="replace")
                    inode = os.fstat(handle.fileno()).st_ino
                    committed_offset = 0
                    write_offset(args.state_file, committed_offset)
            except FileNotFoundError:
                log("file disappeared; waiting for it to return")
                handle.close()
                handle = None

            time.sleep(0.2)
        except (urllib.error.URLError, TimeoutError, RuntimeError) as exc:
            log(f"send failed: {exc}; retrying from offset={committed_offset}")
            if handle is not None:
                handle.seek(committed_offset)
            batch.clear()
            time.sleep(2.0)
        except KeyboardInterrupt:
            return 0
        except Exception as exc:
            log(f"unexpected error: {exc}")
            time.sleep(2.0)


if __name__ == "__main__":
    sys.exit(main())
