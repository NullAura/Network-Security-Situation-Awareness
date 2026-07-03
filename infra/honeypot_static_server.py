#!/usr/bin/env python3
from __future__ import annotations

import argparse
import concurrent.futures
import functools
import ipaddress
import json
import os
import re
import shlex
import subprocess
import time
import urllib.parse
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer


OWN_TEST_IP = "198.51.100.10"
BEIJING = timezone(timedelta(hours=8))

METHOD_NAMES = {
    "vnc_bruteforce": "VNC 密码爆破",
    "ssh_bruteforce": "SSH 弱口令爆破",
    "telnet_bruteforce": "Telnet 弱口令爆破",
    "ftp_bruteforce": "FTP 口令尝试",
    "rdp_bruteforce": "RDP 凭据尝试",
    "remote_login_probe": "远程登录探测",
    "command_execution": "命令执行尝试",
    "payload_delivery": "恶意载荷下载",
    "sql_injection_probe": "SQL 注入探测",
    "web_vuln_scan": "Web 漏洞扫描",
    "http_fingerprint": "HTTP 指纹探测",
    "http_proxy_probe": "HTTP 代理探测",
    "db_login_probe": "数据库口令尝试",
    "db_service_probe": "数据库服务探测",
    "redis_command_probe": "Redis 命令探测",
    "mqtt_probe": "MQTT 连接探测",
    "smb_probe": "SMB 服务探测",
    "tcp_port_scan": "端口扫描探测",
    "protocol_probe": "协议指纹探测",
}

PORT_PROTOCOLS = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    80: "HTTP",
    110: "POP3",
    111: "RPCBIND",
    135: "RPCBIND",
    139: "SMB",
    143: "IMAP",
    389: "LDAP",
    443: "HTTP",
    445: "SMB",
    1433: "MSSQL",
    1521: "ORACLE",
    1883: "MQTT",
    2049: "NFS",
    27017: "MONGODB",
    3306: "MYSQL",
    3389: "RDP",
    5060: "SIP",
    5432: "POSTGRES",
    5900: "VNC",
    5901: "VNC",
    5902: "VNC",
    5903: "VNC",
    5904: "VNC",
    5905: "VNC",
    6379: "REDIS",
    8080: "HTTP",
    8088: "HTTP",
    8089: "HTTP",
    8443: "HTTP",
    8888: "HTTP",
    9200: "ELASTICSEARCH",
    11211: "MEMCACHED",
}

DEFAULT_EVENT_FIELDS = [
    "event_time_beijing",
    "source_ip",
    "country",
    "region",
    "city",
    "isp",
    "asn",
    "protocol",
    "dst_port",
    "attack_method",
    "event_type",
    "severity",
    "username",
    "password",
    "command",
    "payload",
    "honeypot_ip",
    "honeypot_name",
]

ALLOWED_EVENT_FIELDS = {
    "source_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "session_id",
    "country",
    "region",
    "city",
    "isp",
    "asn",
    "latitude",
    "longitude",
    "protocol",
    "service",
    "bytes_in",
    "bytes_out",
    "packet_count",
    "request_path",
    "user_agent",
    "attack_method",
    "attack_method_key",
    "event_type",
    "severity",
    "username",
    "password",
    "command",
    "payload",
    "raw_time",
    "event_time_utc",
    "event_time_beijing",
    "event_ts_ms",
    "event_time_source",
    "honeypot_ip",
    "honeypot_name",
    "sensor_type",
    "log_source",
}


def csv_text(value) -> str:
    if isinstance(value, (list, tuple)):
        return "|".join(csv_text(item) for item in value)
    if value is None:
        return ""
    return str(value)


def raw_json(event: dict) -> dict:
    raw = event.get("raw")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip().startswith("{"):
        try:
            value = json.loads(raw)
            return value if isinstance(value, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def nested_raw_value(event: dict, *keys):
    raw = raw_json(event)
    logdata = raw.get("logdata") if isinstance(raw.get("logdata"), dict) else {}
    for key in keys:
        if key in event and event[key] not in (None, ""):
            return event[key]
        if key in raw and raw[key] not in (None, ""):
            return raw[key]
        if key in logdata and logdata[key] not in (None, ""):
            return logdata[key]
    return ""


def parse_time(value, assume_beijing=False):
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    text = text.replace("Z", "+00:00")
    if re.search(r"[+-]\d{4}$", text):
        text = f"{text[:-5]}{text[-5:-2]}:{text[-2:]}"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
            try:
                parsed = datetime.strptime(text, fmt)
                break
            except ValueError:
                parsed = None
        if parsed is None:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=BEIJING if assume_beijing else timezone.utc)
    return parsed


def event_datetime(event: dict):
    for key, local in (
        ("event_time_utc", False),
        ("event_time", False),
        ("timestamp", False),
        ("utc_time", False),
        ("event_time_local", True),
        ("local_time_adjusted", True),
        ("local_time", True),
        ("raw_time", False),
    ):
        parsed = parse_time(event.get(key), assume_beijing=local)
        if parsed is not None:
            return parsed.astimezone(timezone.utc)
    timestamp = event.get("event_ts_ms") or event.get("timestamp")
    try:
        return datetime.fromtimestamp(float(timestamp) / 1000, timezone.utc)
    except (TypeError, ValueError):
        return None


def event_millis(event: dict):
    parsed = event_datetime(event)
    return int(parsed.timestamp() * 1000) if parsed is not None else ""


def beijing_time(event: dict):
    if event.get("event_time_local"):
        return event["event_time_local"]
    parsed = event_datetime(event)
    return parsed.astimezone(BEIJING).strftime("%Y-%m-%d %H:%M:%S") if parsed else ""


def utc_time(event: dict):
    if event.get("event_time_utc"):
        return event["event_time_utc"]
    parsed = event_datetime(event)
    return parsed.isoformat(timespec="seconds") if parsed else ""


def public_external_ip(ip) -> bool:
    if not ip or ip == OWN_TEST_IP:
        return False
    try:
        return ipaddress.ip_address(str(ip)).is_global
    except ValueError:
        return False


def protocol_for_port(port) -> str:
    try:
        return PORT_PROTOCOLS.get(int(port), "")
    except (TypeError, ValueError):
        return ""


def event_protocol(event: dict) -> str:
    raw_protocol = str(event.get("protocol") or "").strip().upper()
    port = event.get("dst_port") or nested_raw_value(event, "dst_port", "destination_port", "port")
    if raw_protocol.startswith("TCP_"):
        return protocol_for_port(raw_protocol.removeprefix("TCP_")) or protocol_for_port(port) or raw_protocol
    if raw_protocol:
        return raw_protocol
    return protocol_for_port(port)


def event_text(event: dict) -> str:
    return " ".join(
        csv_text(value)
        for value in (
            event_protocol(event),
            event.get("event_type"),
            event.get("payload"),
            event.get("raw"),
            event.get("command"),
            event.get("username"),
            event.get("password"),
            event.get("dst_port"),
        )
        if value not in (None, "")
    ).lower()


def has_credentials(event: dict, text: str) -> bool:
    return bool(event.get("username") or event.get("password") or re.search(r"login|auth|password|credential|username|failed password", text))


def infer_service(event: dict, text: str) -> str:
    protocol = event_protocol(event)
    if protocol:
        return protocol
    port = str(event.get("dst_port") or nested_raw_value(event, "dst_port", "destination_port", "port") or "")
    if port in {"22", "2222"} or "ssh" in text:
        return "SSH"
    if port in {"23", "2323"} or "telnet" in text:
        return "TELNET"
    if port == "21" or "ftp" in text:
        return "FTP"
    if port == "3389" or "rdp" in text:
        return "RDP"
    if re.match(r"590\d", port) or "vnc" in text:
        return "VNC"
    if port in {"3306", "5432", "1433", "1521", "27017"}:
        return "DB"
    if port == "6379" or "redis" in text:
        return "REDIS"
    if port == "1883" or "mqtt" in text:
        return "MQTT"
    if port in {"139", "445"} or "smb" in text:
        return "SMB"
    if port in {"80", "443", "8000", "8080", "8081", "8443"} or re.search(r"https?|user-agent|host:|get\s+|post\s+|head\s+", text):
        return "HTTP"
    return protocol or "UNKNOWN"


def attack_method_key(event: dict) -> str:
    text = event_text(event)
    event_type = str(event.get("event_type") or "").lower()
    service = infer_service(event, text)
    credentials = has_credentials(event, text)

    if re.search(r"file_download|wget|curl|tftp|ftpget|busybox|chmod|\.sh\b|/bin/|powershell|base64|nc\s+-|bash\s+-c|sh\s+-c", text):
        return "payload_delivery"
    if event.get("command") or re.search(r"command_input|command_failed|not a command|shell command|input command", text):
        return "command_execution"
    if re.search(r"\bunion\b.+\bselect\b|information_schema|sleep\s*\(|benchmark\s*\(|or\s+1=1|sqlmap|xp_cmdshell|load_file\s*\(", text):
        return "sql_injection_probe"
    if service == "VNC" and ("vnc_auth_attempt" in event_type or re.search(r"vnc password|vnc client response|vnc server challenge|challenge|response", text)):
        return "vnc_bruteforce"
    if service == "SSH" and credentials:
        return "ssh_bruteforce"
    if service == "TELNET" and ("telnet_login" in event_type or credentials):
        return "telnet_bruteforce"
    if service == "FTP" and credentials:
        return "ftp_bruteforce"
    if service == "RDP" and credentials:
        return "rdp_bruteforce"
    if service in {"MYSQL", "POSTGRES", "MSSQL", "ORACLE", "MONGODB", "DB"}:
        return "db_login_probe" if credentials else "db_service_probe"
    if service == "REDIS":
        return "redis_command_probe"
    if service == "HTTP":
        if re.search(r"connect\s+|proxy|absolute-uri|forwarded|x-forwarded", text):
            return "http_proxy_probe"
        if re.search(r"/\.env|wp-login|phpmyadmin|boaform|cgi-bin|manager/html|shell|cmd=|exec=|cve-|jenkins|solr|actuator|\.git|passwd", text):
            return "web_vuln_scan"
        return "http_fingerprint"
    if service == "MQTT":
        return "mqtt_probe"
    if service == "SMB":
        return "smb_probe"
    if service in {"SSH", "TELNET", "RDP", "VNC", "FTP"}:
        return "remote_login_probe"
    if re.search(r"connect|connection|open|scan|probe", event_type + text):
        return "tcp_port_scan"
    return "protocol_probe"


def coordinates(event: dict, index: int):
    coords = event.get("sourceCoordinates")
    if isinstance(coords, list) and len(coords) == 2:
        return coords[index]
    return event.get("longitude" if index == 0 else "latitude", "")


def event_field_value(event: dict, field: str):
    mapping = {
        "source_ip": lambda: event.get("src_ip") or event.get("source_ip"),
        "dst_ip": lambda: event.get("dst_ip") or event.get("destination_ip") or event.get("honeypot_ip"),
        "src_port": lambda: event.get("src_port") or nested_raw_value(event, "src_port"),
        "dst_port": lambda: event.get("dst_port") or nested_raw_value(event, "dst_port"),
        "session_id": lambda: event.get("session_id") or nested_raw_value(event, "session", "session_id"),
        "country": lambda: event.get("country"),
        "region": lambda: event.get("region"),
        "city": lambda: event.get("city"),
        "isp": lambda: event.get("isp"),
        "asn": lambda: event.get("asn"),
        "latitude": lambda: coordinates(event, 1),
        "longitude": lambda: coordinates(event, 0),
        "protocol": lambda: event_protocol(event),
        "service": lambda: event.get("service") or event.get("app") or infer_service(event, event_text(event)),
        "bytes_in": lambda: event.get("bytes_in") or event.get("bytesIn") or event.get("request_bytes"),
        "bytes_out": lambda: event.get("bytes_out") or event.get("bytesOut") or event.get("response_bytes"),
        "packet_count": lambda: event.get("packet_count") or event.get("packetCount") or event.get("packets"),
        "request_path": lambda: event.get("request_path") or event.get("path") or event.get("uri") or nested_raw_value(event, "request_path", "path", "uri"),
        "user_agent": lambda: event.get("user_agent") or event.get("http_user_agent") or nested_raw_value(event, "user_agent", "User-Agent"),
        "attack_method": lambda: METHOD_NAMES.get(attack_method_key(event), attack_method_key(event)),
        "attack_method_key": lambda: attack_method_key(event),
        "event_type": lambda: event.get("event_type") or event.get("eventid") or nested_raw_value(event, "event_type", "eventid"),
        "severity": lambda: event.get("severity"),
        "username": lambda: event.get("username"),
        "password": lambda: event.get("password"),
        "command": lambda: event.get("command"),
        "payload": lambda: event.get("payload") or event.get("detail"),
        "raw_time": lambda: event.get("raw_time") or event.get("event_time"),
        "event_time_utc": lambda: utc_time(event),
        "event_time_beijing": lambda: beijing_time(event),
        "event_ts_ms": lambda: event.get("event_ts_ms") or event_millis(event),
        "event_time_source": lambda: event.get("event_time_source") or ("timestamp" if event.get("timestamp") else ""),
        "honeypot_ip": lambda: event.get("server_id") or event.get("honeypot_ip") or event.get("source_ip"),
        "honeypot_name": lambda: event.get("server_id") or event.get("honeypot_name") or event.get("source"),
        "sensor_type": lambda: event.get("honeypot_type") or event.get("sensor_type"),
        "log_source": lambda: event.get("source_log_path") or event.get("path") or event.get("source"),
    }
    getter = mapping.get(field)
    return getter() if getter else event.get(field, "")


def parse_fields(query: dict) -> list[str]:
    raw = ",".join(query.get("fields", []))
    fields = [field for field in (item.strip() for item in raw.split(",")) if field in ALLOWED_EVENT_FIELDS]
    deduped = []
    for field in fields or DEFAULT_EVENT_FIELDS:
        if field not in deduped:
            deduped.append(field)
    return deduped


def range_start(query: dict):
    start_param = (query.get("start") or [""])[0]
    end_param = (query.get("end") or [""])[0]
    if start_param or end_param:
        start = parse_time(start_param)
        end = parse_time(end_param)
        if start is None or end is None or start > end:
            return None, None, False
        return start.astimezone(timezone.utc), end.astimezone(timezone.utc), True

    range_key = (query.get("range") or ["all"])[0]
    if range_key == "custom":
        return None, None, False

    days = {"24h": 1, "7d": 7, "30d": 30}.get(range_key)
    if not days:
        return None, None, True
    anchor = parse_time((query.get("anchor") or [""])[0]) or datetime.now(timezone.utc)
    return anchor.astimezone(timezone.utc) - timedelta(days=days), anchor.astimezone(timezone.utc), True


def range_date_paths(root: str, start, end) -> list[str]:
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
    return [f"{root.rstrip('/')}/{date}" for date in sorted(dates)]


def load_event(line: bytes):
    try:
        event = json.loads(line.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return None
    if isinstance(event, dict) and "line" in event:
        try:
            inner = json.loads(str(event.get("line") or ""))
            if isinstance(inner, dict):
                inner.setdefault("source", event.get("source"))
                inner.setdefault("path", event.get("path"))
                inner.setdefault("received_at", event.get("received_at"))
                return inner
        except json.JSONDecodeError:
            return None
    return event if isinstance(event, dict) else None


def event_export_match(event: dict, protocol: str, method: str, start, end) -> bool:
    src_ip = event.get("src_ip") or event.get("source_ip")
    if not public_external_ip(src_ip):
        return False
    if protocol != "ALL" and str(event.get("protocol") or "").upper() != protocol:
        return False
    if method != "ALL" and attack_method_key(event) != method:
        return False
    event_time = event_datetime(event)
    if start and (event_time is None or event_time < start):
        return False
    if end and (event_time is None or event_time > end):
        return False
    return True


def dashboard_events_from_file(path: str) -> list[dict]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return []
    events = payload.get("events") if isinstance(payload, dict) else []
    return [event for event in events if isinstance(event, dict)]


class HoneypotStaticHandler(SimpleHTTPRequestHandler):
    export_api_url = "http://203.0.113.30:9101/export/events.csv"
    export_api_token_file = "/opt/honeypot-cybermap-frontend/hdfs_export_api_token"
    export_api_timeout = 1800
    export_known_hosts_file = "/opt/honeypot-cybermap-frontend/known_hosts"
    runtime_kafka_host = "203.0.113.20"
    runtime_flink_host = "203.0.113.30"
    runtime_hdfs_master_host = "203.0.113.30"
    runtime_hdfs_worker_hosts = ["203.0.113.31", "203.0.113.32"]
    runtime_identity_file = ""
    runtime_known_hosts_file = "/opt/honeypot-cybermap-frontend/known_hosts"
    runtime_health_cache = None
    runtime_health_cache_at = 0.0
    runtime_health_cache_ttl = 30.0

    def is_fresh_data_path(self) -> bool:
        path = self.path.split("?", 1)[0]
        return path in {"", "/", "/index.html"} or path.startswith("/api/")

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/api/export/events.csv":
            self.handle_events_csv_export()
            return
        if path in {"/api/runtime-health", "/api/runtime-health.json"}:
            self.handle_runtime_health()
            return
        super().do_GET()

    def handle_runtime_health(self) -> None:
        payload = self.runtime_health_payload()
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.end_headers()
        self.wfile.write(body)

    def runtime_health_payload(self) -> dict:
        now = time.time()
        cached = self.__class__.runtime_health_cache
        if cached and now - self.__class__.runtime_health_cache_at < self.__class__.runtime_health_cache_ttl:
            return cached

        probe_specs = [
            ("kafka", "Kafka", self.runtime_kafka_host, self.probe_kafka),
            ("flink", "Flink", self.runtime_flink_host, self.probe_flink),
            ("hdfs", "HDFS", self.runtime_hdfs_master_host, self.probe_hdfs),
        ]
        services = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(probe_specs)) as executor:
            futures = [executor.submit(probe) for _, _, _, probe in probe_specs]
            for (key, label, host, _), future in zip(probe_specs, futures):
                try:
                    services.append(future.result(timeout=11))
                except Exception as error:
                    services.append(self.service_probe_payload(
                        key,
                        label,
                        host,
                        {"ok": False, "code": 124, "stderr": f"probe failed: {error}", "elapsedMs": 11000},
                        [{"name": "probe", "ok": False, "message": "probe=timeout"}],
                    ))
        ok_count = sum(1 for service in services if service["status"] == "ok")
        warn_count = sum(1 for service in services if service["status"] == "warn")
        error_count = sum(1 for service in services if service["status"] == "error")
        if error_count:
            status = "error"
            label = "异常"
        elif warn_count:
            status = "warn"
            label = "关注"
        else:
            status = "ok"
            label = "正常"
        payload = {
            "generatedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "generatedAtLocal": datetime.now(BEIJING).strftime("%Y-%m-%d %H:%M:%S"),
            "summary": {
                "status": status,
                "label": label,
                "okCount": ok_count,
                "warnCount": warn_count,
                "errorCount": error_count,
                "total": len(services),
                "detail": "；".join(f"{service['label']} {service['labelStatus']}" for service in services),
            },
            "services": services,
        }
        self.__class__.runtime_health_cache = payload
        self.__class__.runtime_health_cache_at = now
        return payload

    def ssh_command(self, host: str, command: str, timeout: int = 10) -> dict:
        args = [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            f"UserKnownHostsFile={self.runtime_known_hosts_file}",
            "-o",
            "ConnectTimeout=4",
        ]
        if self.runtime_identity_file:
            args.extend(["-i", self.runtime_identity_file])
        args.extend([f"root@{host}", command])
        started = time.time()
        try:
            result = subprocess.run(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
                check=False,
            )
            return {
                "ok": result.returncode == 0,
                "code": result.returncode,
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip(),
                "elapsedMs": round((time.time() - started) * 1000),
            }
        except subprocess.TimeoutExpired as error:
            return {
                "ok": False,
                "code": 124,
                "stdout": (error.stdout or "").strip() if isinstance(error.stdout, str) else "",
                "stderr": "probe timeout",
                "elapsedMs": round((time.time() - started) * 1000),
            }
        except OSError as error:
            return {
                "ok": False,
                "code": 127,
                "stdout": "",
                "stderr": str(error),
                "elapsedMs": round((time.time() - started) * 1000),
            }

    @staticmethod
    def command_value(stdout: str, key: str) -> str:
        prefix = f"{key}="
        for line in stdout.splitlines():
            if line.startswith(prefix):
                return line[len(prefix):].strip()
        return ""

    def service_probe_payload(self, key: str, label: str, host: str, result: dict, checks: list[dict]) -> dict:
        if result["ok"]:
            status = "ok"
            label_status = "正常"
        elif result["code"] == 124 or "timeout" in result.get("stderr", ""):
            status = "warn"
            label_status = "超时"
        else:
            status = "error"
            label_status = "异常"
        detail_parts = [check["message"] for check in checks if check.get("message")]
        if not detail_parts and result.get("stderr"):
            detail_parts.append(result["stderr"].splitlines()[-1][:120])
        return {
            "key": key,
            "label": label,
            "host": host,
            "status": status,
            "labelStatus": label_status,
            "detail": "；".join(detail_parts) or label_status,
            "checkedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "elapsedMs": result.get("elapsedMs", 0),
            "checks": checks,
        }

    def probe_kafka(self) -> dict:
        command = r"""
set -o pipefail
service="$(systemctl is-active kafka 2>/dev/null || systemctl is-active kafka-kraft 2>/dev/null || true)"
port="$(ss -ltn 2>/dev/null | awk '$4 ~ /:9092$/ {print "listen"; exit}')"
topics="not_checked"
echo "service=${service:-unknown}"
echo "port=${port:-closed}"
echo "topics=${topics:-empty}"
test "$service" = "active" || test "$port" = "listen"
"""
        result = self.ssh_command(self.runtime_kafka_host, command)
        service = self.command_value(result["stdout"], "service") or "unknown"
        port = self.command_value(result["stdout"], "port") or "unknown"
        topics = self.command_value(result["stdout"], "topics") or "unknown"
        checks = [
            {"name": "systemd", "ok": service == "active", "message": f"systemd={service}"},
            {"name": "port", "ok": port == "listen", "message": f"9092={port}"},
            {"name": "topics", "ok": topics not in {"unknown", ""}, "message": f"topics={topics}"},
        ]
        return self.service_probe_payload("kafka", "Kafka", self.runtime_kafka_host, result, checks)

    def probe_flink(self) -> dict:
        command = r"""
set -o pipefail
service="$(systemctl is-active flink-standalone 2>/dev/null || true)"
stream="$(systemctl is-active honeypot-flink-stream 2>/dev/null || true)"
rest="unknown"
if command -v curl >/dev/null 2>&1; then
  rest="$(timeout 4 curl -fsS http://127.0.0.1:8081/jobs 2>/dev/null | python3 -c 'import json,sys; data=json.load(sys.stdin); print(len(data.get("jobs", [])))' 2>/dev/null || true)"
fi
jps_line="$(jps 2>/dev/null | grep -E 'StandaloneSessionClusterEntrypoint|TaskManagerRunner|Flink' | paste -sd, -)"
echo "service=${service:-unknown}"
echo "stream=${stream:-unknown}"
echo "jobs=${rest:-unknown}"
echo "jps=${jps_line:-none}"
test "$service" = "active" || test "$stream" = "active" || test "${rest:-unknown}" != "unknown" || test "$jps_line" != ""
"""
        result = self.ssh_command(self.runtime_flink_host, command)
        service = self.command_value(result["stdout"], "service") or "unknown"
        stream = self.command_value(result["stdout"], "stream") or "unknown"
        jobs = self.command_value(result["stdout"], "jobs") or "unknown"
        jps_line = self.command_value(result["stdout"], "jps") or "none"
        checks = [
            {"name": "standalone", "ok": service == "active", "message": f"standalone={service}"},
            {"name": "stream", "ok": stream == "active", "message": f"stream={stream}"},
            {"name": "rest", "ok": jobs not in {"unknown", ""}, "message": f"jobs={jobs}"},
            {"name": "jps", "ok": jps_line != "none", "message": f"jps={jps_line}"},
        ]
        return self.service_probe_payload("flink", "Flink", self.runtime_flink_host, result, checks)

    def probe_hdfs(self) -> dict:
        command = r"""
set -o pipefail
port="$(ss -ltn 2>/dev/null | awk '$4 ~ /:8020$/ {print "listen"; exit}')"
state="unknown"
live="unknown"
dead="unknown"
if command -v curl >/dev/null 2>&1; then
  state="$(timeout 2 curl -fsS 'http://127.0.0.1:9870/jmx?qry=Hadoop:service=NameNode,name=NameNodeStatus' 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("beans", [{}])[0].get("State", "unknown"))' 2>/dev/null || true)"
  fs_state="$(timeout 2 curl -fsS 'http://127.0.0.1:9870/jmx?qry=Hadoop:service=NameNode,name=FSNamesystemState' 2>/dev/null | python3 -c 'import json,sys; b=json.load(sys.stdin).get("beans", [{}])[0]; print(b.get("NumLiveDataNodes", "unknown"), b.get("NumDeadDataNodes", "unknown"))' 2>/dev/null || echo "unknown unknown")"
  live="$(printf '%s' "$fs_state" | awk '{print $1}')"
  dead="$(printf '%s' "$fs_state" | awk '{print $2}')"
fi
nn="$(jps 2>/dev/null | grep -E 'NameNode|DataNode' | paste -sd, -)"
echo "state=${state:-unknown}"
echo "liveDatanodes=${live:-unknown}"
echo "deadDatanodes=${dead:-unknown}"
echo "port=${port:-closed}"
echo "jps=${nn:-none}"
test "${state:-unknown}" = "active" && test "${live:-0}" != "0"
"""
        result = self.ssh_command(self.runtime_hdfs_master_host, command, timeout=8)
        state = self.command_value(result["stdout"], "state") or "unknown"
        live_datanodes = self.command_value(result["stdout"], "liveDatanodes") or "unknown"
        dead_datanodes = self.command_value(result["stdout"], "deadDatanodes") or "unknown"
        port = self.command_value(result["stdout"], "port") or "unknown"
        jps_line = self.command_value(result["stdout"], "jps") or "none"
        checks = [
            {"name": "namenode", "ok": state == "active", "message": f"namenode={state}"},
            {"name": "dfsadmin", "ok": live_datanodes not in {"0", "unknown", ""}, "message": f"liveDatanodes={live_datanodes}"},
            {"name": "dead", "ok": dead_datanodes in {"0", "unknown"}, "message": f"deadDatanodes={dead_datanodes}"},
            {"name": "port", "ok": port == "listen", "message": f"8020={port}"},
            {"name": "jps", "ok": jps_line != "none", "message": f"jps={jps_line}"},
        ]
        payload = self.service_probe_payload("hdfs", "HDFS", self.runtime_hdfs_master_host, result, checks)
        if self.runtime_hdfs_worker_hosts:
            payload["workers"] = self.runtime_hdfs_worker_hosts
        return payload

    def dashboard_fallback_events(self) -> list[dict]:
        api_dir = os.path.join(str(getattr(self, "directory", ".")), "api")
        paths = [
            os.path.join(api_dir, "dashboard-live.json"),
            os.path.join(api_dir, "dashboard.json"),
            os.path.join(api_dir, "dashboard-batch.json"),
        ]
        seen = set()
        events = []
        for path in paths:
            for event in dashboard_events_from_file(path):
                identity = json.dumps(
                    [
                        event.get("id"),
                        event.get("event_time_utc") or event.get("event_time"),
                        event.get("src_ip") or event.get("source_ip"),
                        event.get("server_id"),
                        event.get("protocol"),
                        event.get("event_type"),
                        event.get("dst_port"),
                        event.get("payload") or event.get("command") or event.get("raw"),
                    ],
                    ensure_ascii=False,
                    sort_keys=True,
                )
                if identity in seen:
                    continue
                seen.add(identity)
                events.append(event)
        return events

    def write_export_row(self, writer, event: dict, fields: list[str]) -> None:
        writer.writerow([csv_text(event_field_value(event, field)) for field in fields])

    def export_api_token(self) -> str:
        try:
            with open(self.export_api_token_file, "r", encoding="utf-8") as handle:
                return handle.read().strip()
        except OSError:
            return ""

    def proxy_hdfs_events_csv_export(self) -> bool:
        token = self.export_api_token()
        if not token:
            self.send_response(503)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write("HDFS export API token is not configured\n".encode("utf-8"))
            return False

        query = urllib.parse.urlparse(self.path).query
        url = f"{self.export_api_url}?{query}" if query else self.export_api_url
        request = urllib.request.Request(url, headers={"X-Export-Token": token})
        try:
            with urllib.request.urlopen(request, timeout=self.export_api_timeout) as response:
                status = getattr(response, "status", 200)
                self.send_response(status)
                for header in ("Content-Type", "Content-Disposition", "Cache-Control", "X-Export-Source"):
                    value = response.headers.get(header)
                    if value:
                        self.send_header(header, value)
                self.send_header("X-Export-Proxy", "hdfs-api")
                self.end_headers()
                read_chunk = getattr(response, "read1", response.read)
                while True:
                    chunk = read_chunk(1024 * 64)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    self.wfile.flush()
            return True
        except urllib.error.HTTPError as error:
            body = error.read() or str(error).encode("utf-8", errors="replace")
            self.send_response(error.code)
            self.send_header("Content-Type", error.headers.get("Content-Type", "text/plain; charset=utf-8"))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return False
        except (BrokenPipeError, ConnectionResetError):
            return False
        except (OSError, TimeoutError) as error:
            self.send_response(502)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(f"HDFS export API unavailable: {error}\n".encode("utf-8", errors="replace"))
            return False

    def handle_events_csv_export(self) -> None:
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        fields = parse_fields(query)
        protocol = (query.get("protocol") or ["ALL"])[0].upper()
        method = (query.get("method") or ["ALL"])[0]
        start, end, range_valid = range_start(query)
        if not range_valid:
            self.send_response(400)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            self.end_headers()
            self.wfile.write("invalid export time range".encode("utf-8"))
            return

        self.proxy_hdfs_events_csv_export()
        return

    def send_head(self):
        if self.is_fresh_data_path():
            for header in ("If-Modified-Since", "If-None-Match"):
                if header in self.headers:
                    del self.headers[header]
        return super().send_head()

    def end_headers(self) -> None:
        path = self.path.split("?", 1)[0]
        if self.is_fresh_data_path():
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
        elif path.startswith("/assets/"):
            self.send_header("Cache-Control", "public, max-age=31536000, immutable")
        else:
            self.send_header("Cache-Control", "no-cache")
        super().end_headers()


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve honeypot frontend with cache-safe JSON headers.")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--directory", default="/opt/honeypot-cybermap-frontend/dist")
    parser.add_argument("--export-api-url", default="http://203.0.113.30:9101/export/events.csv")
    parser.add_argument("--export-api-token-file", default="/opt/honeypot-cybermap-frontend/hdfs_export_api_token")
    parser.add_argument("--export-api-timeout", type=int, default=1800)
    parser.add_argument("--export-known-hosts-file", default="/opt/honeypot-cybermap-frontend/known_hosts")
    parser.add_argument("--runtime-kafka-host", default="203.0.113.20")
    parser.add_argument("--runtime-flink-host", default="203.0.113.30")
    parser.add_argument("--runtime-hdfs-master-host", default="203.0.113.30")
    parser.add_argument("--runtime-hdfs-worker-hosts", default="203.0.113.31,203.0.113.32")
    parser.add_argument("--runtime-identity-file", default="")
    parser.add_argument("--runtime-known-hosts-file", default="/opt/honeypot-cybermap-frontend/known_hosts")
    parser.add_argument("--runtime-health-cache-ttl", type=float, default=30.0)
    args = parser.parse_args()

    HoneypotStaticHandler.export_api_url = args.export_api_url
    HoneypotStaticHandler.export_api_token_file = args.export_api_token_file
    HoneypotStaticHandler.export_api_timeout = args.export_api_timeout
    HoneypotStaticHandler.export_known_hosts_file = args.export_known_hosts_file
    HoneypotStaticHandler.runtime_kafka_host = args.runtime_kafka_host
    HoneypotStaticHandler.runtime_flink_host = args.runtime_flink_host
    HoneypotStaticHandler.runtime_hdfs_master_host = args.runtime_hdfs_master_host
    HoneypotStaticHandler.runtime_hdfs_worker_hosts = [
        host.strip() for host in args.runtime_hdfs_worker_hosts.split(",") if host.strip()
    ]
    HoneypotStaticHandler.runtime_identity_file = args.runtime_identity_file
    HoneypotStaticHandler.runtime_known_hosts_file = args.runtime_known_hosts_file
    HoneypotStaticHandler.runtime_health_cache_ttl = args.runtime_health_cache_ttl
    handler = functools.partial(HoneypotStaticHandler, directory=args.directory)
    with ThreadingHTTPServer((args.host, args.port), handler) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
