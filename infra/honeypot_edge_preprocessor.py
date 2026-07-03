#!/usr/bin/env python3
import argparse
import datetime as dt
import ipaddress
import json
import os
import signal
import sys
import time
from pathlib import Path


OWN_TEST_IP = "198.51.100.10"
UTC = dt.timezone.utc
DISPLAY_TZ = dt.timezone(dt.timedelta(hours=8), "Asia/Shanghai")

PORT_PROTOCOLS = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
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
    6379: "REDIS",
    8080: "HTTP",
    8443: "HTTP",
}

METHOD_LABELS = {
    "ssh_connection_probe": "SSH 连接探测",
    "ssh_fingerprint_probe": "SSH 指纹探测",
    "ssh_bruteforce": "SSH 密码爆破",
    "ssh_login_success": "SSH 登录成功",
    "ssh_command_execution": "SSH 命令执行",
    "vnc_bruteforce": "VNC 密码爆破",
    "rdp_bruteforce": "RDP 登录探测",
    "mysql_login_probe": "MySQL 登录探测",
    "postgres_login_probe": "PostgreSQL 登录探测",
    "mssql_login_probe": "MSSQL 登录探测",
    "redis_unauthorized_probe": "Redis 未授权探测",
    "smb_probe": "SMB 服务探测",
    "ftp_login_probe": "FTP 登录探测",
    "http_probe": "HTTP 探测",
    "sql_injection_probe": "SQL 注入探测",
    "payload_probe": "恶意 Payload 探测",
    "mqtt_probe": "MQTT 协议探测",
    "oracle_probe": "Oracle 连接探测",
    "telnet_probe": "Telnet 登录探测",
    "scanner_probe": "扫描探测",
    "sensor_event": "传感器事件",
    "unknown": "未知行为",
}

SQLI_MARKERS = (
    " union ",
    "select ",
    " or 1=1",
    "' or '",
    "\" or \"",
    "sleep(",
    "benchmark(",
    "information_schema",
    "extractvalue(",
    "updatexml(",
    "../",
    "%27",
    "%2527",
)

stop_requested = False


def handle_signal(_signum, _frame):
    global stop_requested
    stop_requested = True


def parse_args():
    parser = argparse.ArgumentParser(description="Preprocess local honeypot log lines before Flume ships them to Kafka.")
    parser.add_argument("--log-path", required=True)
    parser.add_argument("--output-path", required=True)
    parser.add_argument("--state-path", required=True)
    parser.add_argument("--source-ip", required=True)
    parser.add_argument("--honeypot-type", required=True, choices=["cowrie", "opencanary", "honeypot3"])
    parser.add_argument("--poll-interval", type=float, default=0.2)
    parser.add_argument("--start-at-end", action="store_true")
    return parser.parse_args()


def utc_now():
    return dt.datetime.now(UTC)


def parse_time(value):
    if not value:
        return None
    text = str(value).strip()
    candidates = [text]
    if text.endswith("Z"):
        candidates.append(text[:-1] + "+00:00")
    if len(text) >= 5 and text[-5] in {"+", "-"} and text[-3] != ":":
        candidates.append(text[:-2] + ":" + text[-2:])
    for candidate in candidates:
        try:
            parsed = dt.datetime.fromisoformat(candidate)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            return parsed.astimezone(UTC)
        except ValueError:
            pass
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return dt.datetime.strptime(text, fmt).replace(tzinfo=UTC)
        except ValueError:
            pass
    return None


def event_time(obj):
    for key in ("timestamp", "event_time", "utc_time", "time", "local_time_adjusted", "local_time"):
        parsed = parse_time(obj.get(key))
        if parsed:
            return parsed, key
    return utc_now(), "collector_time"


def safe_int(value):
    try:
        if value in ("", None):
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def first_value(obj, keys):
    for key in keys:
        value = obj.get(key)
        if value not in ("", None, -1):
            return value
    return None


def nested_logdata(obj):
    data = obj.get("logdata")
    return data if isinstance(data, dict) else {}


def payload_text(obj):
    pieces = []
    for key in ("raw", "raw_payload", "payload", "input", "message", "request", "request_raw", "uri", "path"):
        value = obj.get(key)
        if value not in ("", None):
            pieces.append(str(value))
    data = nested_logdata(obj)
    for key in ("logdata", "msg", "USERNAME", "PASSWORD", "PATH", "USERAGENT", "HOSTNAME"):
        value = data.get(key)
        if value not in ("", None):
            pieces.append(str(value))
    return " ".join(pieces)


def has_sqli(text):
    lower = f" {text.lower()} "
    return any(marker in lower for marker in SQLI_MARKERS)


def protocol_from(obj, honeypot_type):
    explicit = first_value(obj, ("protocol", "proto", "service"))
    if explicit:
        return str(explicit).upper()
    eventid = str(obj.get("eventid") or obj.get("event_type") or "").lower()
    if eventid.startswith("cowrie.") or "ssh" in eventid:
        return "SSH"
    port = safe_int(first_value(obj, ("dst_port", "destination_port", "local_port")))
    if port in PORT_PROTOCOLS:
        return PORT_PROTOCOLS[port]
    if honeypot_type == "cowrie":
        return "SSH"
    return "UNKNOWN"


def method_for(obj, protocol, honeypot_type, text):
    event = str(obj.get("eventid") or obj.get("event_type") or "").lower()
    logtype = safe_int(obj.get("logtype"))
    if has_sqli(text):
        return "sql_injection_probe"
    if honeypot_type == "cowrie":
        if "command.input" in event:
            return "ssh_command_execution"
        if "login.success" in event:
            return "ssh_login_success"
        if "login.failed" in event or "login" in event:
            return "ssh_bruteforce"
        if "client.version" in event or "client.kex" in event:
            return "ssh_fingerprint_probe"
        if "session.connect" in event:
            return "ssh_connection_probe"
        return "scanner_probe"
    if protocol == "VNC":
        return "vnc_bruteforce"
    if protocol == "RDP":
        return "rdp_bruteforce"
    if protocol == "MYSQL":
        return "mysql_login_probe"
    if protocol == "POSTGRES":
        return "postgres_login_probe"
    if protocol == "MSSQL":
        return "mssql_login_probe"
    if protocol == "REDIS":
        return "redis_unauthorized_probe"
    if protocol == "SMB":
        return "smb_probe"
    if protocol == "FTP":
        return "ftp_login_probe"
    if protocol == "MQTT":
        return "mqtt_probe"
    if protocol == "ORACLE":
        return "oracle_probe"
    if protocol == "TELNET":
        return "telnet_probe"
    if protocol == "HTTP":
        return "http_probe"
    if logtype == 1001 or event.startswith("sensor."):
        return "sensor_event"
    if text.strip():
        return "payload_probe"
    return "unknown"


def is_public_external(ip):
    if not ip or ip == OWN_TEST_IP:
        return False
    try:
        return ipaddress.ip_address(str(ip)).is_global
    except ValueError:
        return False


def normalize_line(line, args):
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        obj = {"raw_payload": line.rstrip("\r\n")}
    if not isinstance(obj, dict):
        obj = {"raw_payload": obj}

    data = nested_logdata(obj)
    event_dt, time_field = event_time(obj)
    protocol = protocol_from(obj, args.honeypot_type)
    text = payload_text(obj)
    method = method_for(obj, protocol, args.honeypot_type, text)
    src_ip = first_value(obj, ("src_ip", "src_host", "source_ip", "remote_ip"))
    dst_ip = first_value(obj, ("dst_ip", "dst_host", "destination_ip", "local_ip"))
    src_port = safe_int(first_value(obj, ("src_port", "source_port", "remote_port")))
    dst_port = safe_int(first_value(obj, ("dst_port", "destination_port", "local_port")))
    username = first_value(obj, ("username", "user", "login"))
    password = first_value(obj, ("password", "passwd"))
    command = first_value(obj, ("input", "command"))
    if not username:
        username = data.get("USERNAME")
    if not password:
        password = data.get("PASSWORD")
    if not command and str(obj.get("eventid") or "").endswith("command.input"):
        command = obj.get("input")

    return {
        "schema_version": "edge-preprocess-v1",
        "preprocessed_at": utc_now().isoformat(timespec="milliseconds"),
        "server_id": args.source_ip,
        "server_ip": args.source_ip,
        "source": args.source_ip,
        "honeypot_type": args.honeypot_type,
        "raw_log_path": args.log_path,
        "raw_time": obj.get(time_field),
        "event_ts_utc": event_dt.isoformat(timespec="milliseconds"),
        "event_time": event_dt.isoformat(timespec="milliseconds"),
        "event_ts_beijing": event_dt.astimezone(DISPLAY_TZ).isoformat(timespec="milliseconds"),
        "event_ts_ms": int(event_dt.timestamp() * 1000),
        "src_ip": src_ip,
        "source_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "destination_ip": dst_ip,
        "dst_port": dst_port,
        "destination_port": dst_port,
        "protocol": protocol,
        "event_type": obj.get("event_type") or obj.get("eventid") or obj.get("logtype") or "unknown",
        "eventid": obj.get("eventid") or obj.get("event_type") or obj.get("logtype") or "unknown",
        "attack_method": method,
        "attack_method_label": METHOD_LABELS.get(method, METHOD_LABELS["unknown"]),
        "username": username,
        "password": password,
        "command": command,
        "payload": text[:4000] if text else "",
        "payload_hex": obj.get("payload_hex", ""),
        "session": obj.get("session") or obj.get("session_id", ""),
        "is_own_test_ip": src_ip == OWN_TEST_IP,
        "is_public_external": is_public_external(src_ip),
        "raw": obj,
        "raw_line": line.rstrip("\r\n"),
    }


def load_state(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_state(path, state):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(state, handle, ensure_ascii=False, separators=(",", ":"))
    os.replace(tmp, path)


def open_log(path, state, start_at_end):
    handle = open(path, "r", encoding="utf-8", errors="replace")
    stat = os.fstat(handle.fileno())
    offset = 0
    if state.get("inode") == stat.st_ino and int(state.get("offset", 0)) <= stat.st_size:
        offset = int(state.get("offset", 0))
    elif start_at_end:
        offset = stat.st_size
    handle.seek(offset)
    return handle, stat.st_ino


def main():
    args = parse_args()
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)
    Path(args.output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(args.state_path).parent.mkdir(parents=True, exist_ok=True)

    state = load_state(args.state_path)
    handle = None
    inode = None
    written = 0
    while not stop_requested:
        try:
            if handle is None:
                handle, inode = open_log(args.log_path, state, args.start_at_end)
            line = handle.readline()
            if not line:
                current = os.stat(args.log_path)
                if current.st_ino != inode or current.st_size < handle.tell():
                    handle.close()
                    handle = None
                time.sleep(args.poll_interval)
                continue
            record = normalize_line(line, args)
            with open(args.output_path, "a", encoding="utf-8") as output:
                output.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
            written += 1
            if written % 20 == 0:
                state = {"inode": inode, "offset": handle.tell(), "updated_at": utc_now().isoformat(timespec="seconds")}
                save_state(args.state_path, state)
        except FileNotFoundError:
            time.sleep(2)
        except Exception as exc:
            print(f"edge preprocessor error: {exc}", file=sys.stderr, flush=True)
            time.sleep(1)

    if handle is not None:
        state = {"inode": inode, "offset": handle.tell(), "updated_at": utc_now().isoformat(timespec="seconds")}
        save_state(args.state_path, state)
        handle.close()


if __name__ == "__main__":
    sys.exit(main())
