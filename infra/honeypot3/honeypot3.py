#!/usr/bin/env python3
import argparse
import asyncio
import json
import os
import pwd
import signal
import socket
import time
from datetime import datetime, timezone


SENSOR_ID = "203.0.113.12"
LOG_PATH = "/var/log/honeypot3/events.jsonl"
MAX_READ = 4096
READ_TIMEOUT = 5


SERVICES = [
    {"port": 22, "protocol": "ssh", "mode": "ssh", "banner": b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n"},
    {"port": 21, "protocol": "ftp", "mode": "ftp", "banner": b"220 Ubuntu FTP server ready\r\n"},
    {"port": 2121, "protocol": "ftp", "mode": "ftp", "banner": b"220 Backup FTP server ready\r\n"},
    {"port": 23, "protocol": "telnet", "mode": "telnet", "banner": b"Ubuntu login: "},
    {"port": 2323, "protocol": "telnet", "mode": "telnet", "banner": b"Router login: "},
    {"port": 25, "protocol": "smtp", "mode": "line", "banner": b"220 mail.local ESMTP Postfix\r\n"},
    {"port": 110, "protocol": "pop3", "mode": "line", "banner": b"+OK POP3 server ready\r\n"},
    {"port": 143, "protocol": "imap", "mode": "line", "banner": b"* OK IMAP4rev1 Service Ready\r\n"},
    {"port": 80, "protocol": "http", "mode": "http", "banner": b""},
    {"port": 8080, "protocol": "http-proxy", "mode": "http", "banner": b""},
    {"port": 8888, "protocol": "http-alt", "mode": "http", "banner": b""},
    {"port": 9200, "protocol": "elasticsearch", "mode": "http", "banner": b""},
    {"port": 443, "protocol": "https", "mode": "raw", "banner": b""},
    {"port": 8443, "protocol": "https-alt", "mode": "raw", "banner": b""},
    {"port": 3306, "protocol": "mysql", "mode": "mysql", "banner": b""},
    {"port": 5432, "protocol": "postgresql", "mode": "raw", "banner": b""},
    {"port": 1433, "protocol": "mssql", "mode": "raw", "banner": b""},
    {"port": 1521, "protocol": "oracle", "mode": "raw", "banner": b""},
    {"port": 27017, "protocol": "mongodb", "mode": "raw", "banner": b""},
    {"port": 6379, "protocol": "redis", "mode": "redis", "banner": b""},
    {"port": 11211, "protocol": "memcached", "mode": "line", "banner": b""},
    {"port": 1883, "protocol": "mqtt", "mode": "raw", "banner": b""},
    {"port": 3389, "protocol": "rdp", "mode": "raw", "banner": b""},
    {"port": 5900, "protocol": "vnc", "mode": "vnc", "banner": b"RFB 003.008\n"},
    {"port": 445, "protocol": "smb", "mode": "raw", "banner": b""},
    {"port": 389, "protocol": "ldap", "mode": "raw", "banner": b""},
    {"port": 111, "protocol": "rpcbind", "mode": "raw", "banner": b""},
    {"port": 2049, "protocol": "nfs", "mode": "raw", "banner": b""},
    {"port": 5060, "protocol": "sip", "mode": "line", "banner": b""},
]


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def safe_text(data):
    if not data:
        return ""
    text = data.decode("utf-8", errors="replace")
    return "".join(ch if ch.isprintable() or ch in "\r\n\t" else "." for ch in text)[:1000]


def payload_hex(data):
    return data[:128].hex()


def log_event(record):
    record.setdefault("event_time", now_iso())
    record.setdefault("sensor_id", SENSOR_ID)
    line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
    with open(LOG_PATH, "a", encoding="utf-8") as handle:
        handle.write(line + "\n")


async def read_some(reader, timeout=READ_TIMEOUT):
    try:
        return await asyncio.wait_for(reader.read(MAX_READ), timeout=timeout)
    except asyncio.TimeoutError:
        return b""
    except ConnectionError:
        return b""


def peer_info(writer):
    peer = writer.get_extra_info("peername")
    sock = writer.get_extra_info("sockname")
    src_ip, src_port = ("", -1)
    dst_ip, dst_port = ("", -1)
    if peer:
        src_ip, src_port = peer[0], peer[1]
    if sock:
        dst_ip, dst_port = sock[0], sock[1]
    return src_ip, src_port, dst_ip, dst_port


async def handle_http(reader, writer, service):
    src_ip, src_port, dst_ip, dst_port = peer_info(writer)
    data = await read_some(reader)
    text = safe_text(data)
    first = text.splitlines()[0] if text.splitlines() else ""
    method, path = "", ""
    parts = first.split()
    if len(parts) >= 2:
        method, path = parts[0], parts[1]
    host = ""
    for line in text.splitlines()[1:]:
        if line.lower().startswith("host:"):
            host = line.split(":", 1)[1].strip()
            break
    log_event({
        "event_type": "http.request",
        "protocol": service["protocol"],
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "method": method,
        "path": path,
        "host": host,
        "raw": text,
        "payload_hex": payload_hex(data),
    })
    body = b"<html><title>Admin</title><body><h1>Service Login</h1></body></html>\n"
    headers = (
        b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)\r\n"
        b"Content-Type: text/html\r\nContent-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n"
    )
    writer.write(headers + body)
    await writer.drain()


async def handle_ftp(reader, writer, service):
    src_ip, src_port, dst_ip, dst_port = peer_info(writer)
    writer.write(service["banner"])
    await writer.drain()
    username = ""
    password = ""
    raw_lines = []
    deadline = time.time() + READ_TIMEOUT
    while time.time() < deadline:
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=2)
        except asyncio.TimeoutError:
            break
        if not line:
            break
        text = safe_text(line).strip()
        raw_lines.append(text)
        upper = text.upper()
        if upper.startswith("USER "):
            username = text[5:].strip()
            writer.write(b"331 Password required\r\n")
            await writer.drain()
        elif upper.startswith("PASS "):
            password = text[5:].strip()
            writer.write(b"530 Login incorrect\r\n")
            await writer.drain()
            break
        else:
            writer.write(b"500 Unknown command\r\n")
            await writer.drain()
    log_event({
        "event_type": "ftp.login",
        "protocol": service["protocol"],
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "username": username,
        "password": password,
        "raw": "\n".join(raw_lines),
    })


async def handle_telnet(reader, writer, service):
    src_ip, src_port, dst_ip, dst_port = peer_info(writer)
    writer.write(service["banner"])
    await writer.drain()
    username = safe_text(await read_some(reader, timeout=3)).strip()
    writer.write(b"Password: ")
    await writer.drain()
    password = safe_text(await read_some(reader, timeout=3)).strip()
    writer.write(b"\r\nLogin incorrect\r\n")
    await writer.drain()
    log_event({
        "event_type": "telnet.login",
        "protocol": service["protocol"],
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "username": username,
        "password": password,
    })


async def handle_redis(reader, writer, service):
    src_ip, src_port, dst_ip, dst_port = peer_info(writer)
    data = await read_some(reader)
    text = safe_text(data)
    command = parse_redis_command(text)
    log_event({
        "event_type": "redis.command",
        "protocol": service["protocol"],
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "command": command,
        "raw": text,
        "payload_hex": payload_hex(data),
    })
    writer.write(b"-NOAUTH Authentication required.\r\n")
    await writer.drain()


def parse_redis_command(text):
    parts = []
    for line in text.replace("\r", "\n").split("\n"):
        line = line.strip()
        if not line or line.startswith("*") or line.startswith("$"):
            continue
        parts.append(line)
    return " ".join(parts[:6])[:200]


async def handle_mysql(reader, writer, service):
    src_ip, src_port, dst_ip, dst_port = peer_info(writer)
    writer.write(mysql_handshake())
    await writer.drain()
    data = await read_some(reader)
    log_event({
        "event_type": "mysql.login",
        "protocol": service["protocol"],
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "raw": safe_text(data),
        "payload_hex": payload_hex(data),
    })


def mysql_handshake():
    payload = (
        b"\x0a5.7.31-0ubuntu0.18.04.1\x00"
        b"\x01\x00\x00\x00"
        b"abcdefgh\x00"
        b"\xff\xf7\x21\x02\x00\xff\x81\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"ijklmnopqrst\x00mysql_native_password\x00"
    )
    length = len(payload).to_bytes(3, "little")
    return length + b"\x00" + payload


async def handle_vnc(reader, writer, service):
    src_ip, src_port, dst_ip, dst_port = peer_info(writer)
    writer.write(service["banner"])
    await writer.drain()
    data = await read_some(reader)
    log_event({
        "event_type": "vnc.connect",
        "protocol": service["protocol"],
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "raw": safe_text(data),
        "payload_hex": payload_hex(data),
    })


async def handle_line(reader, writer, service):
    src_ip, src_port, dst_ip, dst_port = peer_info(writer)
    if service["banner"]:
        writer.write(service["banner"])
        await writer.drain()
    data = await read_some(reader)
    log_event({
        "event_type": f"{service['protocol']}.line",
        "protocol": service["protocol"],
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "raw": safe_text(data),
        "payload_hex": payload_hex(data),
    })
    if service["protocol"] == "memcached":
        writer.write(b"ERROR\r\n")
        await writer.drain()


async def handle_raw(reader, writer, service):
    src_ip, src_port, dst_ip, dst_port = peer_info(writer)
    if service["banner"]:
        writer.write(service["banner"])
        await writer.drain()
    data = await read_some(reader)
    log_event({
        "event_type": f"{service['protocol']}.connect",
        "protocol": service["protocol"],
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "raw": safe_text(data),
        "payload_hex": payload_hex(data),
    })


async def handle_client(reader, writer, service):
    src_ip, src_port, dst_ip, dst_port = peer_info(writer)
    log_event({
        "event_type": "connection.open",
        "protocol": service["protocol"],
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
    })
    try:
        mode = service["mode"]
        if mode == "http":
            await handle_http(reader, writer, service)
        elif mode == "ftp":
            await handle_ftp(reader, writer, service)
        elif mode == "telnet":
            await handle_telnet(reader, writer, service)
        elif mode == "redis":
            await handle_redis(reader, writer, service)
        elif mode == "mysql":
            await handle_mysql(reader, writer, service)
        elif mode == "vnc":
            await handle_vnc(reader, writer, service)
        elif mode == "line":
            await handle_line(reader, writer, service)
        else:
            await handle_raw(reader, writer, service)
    except Exception as exc:
        log_event({
            "event_type": "handler.error",
            "protocol": service["protocol"],
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "error": repr(exc),
        })
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def start_service(service):
    async def callback(reader, writer):
        await handle_client(reader, writer, service)

    server = await asyncio.start_server(callback, "0.0.0.0", service["port"], reuse_address=True)
    sockets = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
    print(f"listening {service['protocol']} on {sockets}", flush=True)
    return server


def drop_privileges(user):
    if os.getuid() != 0:
        return
    pw = pwd.getpwnam(user)
    os.initgroups(user, pw.pw_gid)
    os.setgid(pw.pw_gid)
    os.setuid(pw.pw_uid)


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--user", default="honeypot3")
    args = parser.parse_args()

    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    open(LOG_PATH, "a").close()
    if os.getuid() == 0:
        pw = pwd.getpwnam(args.user)
        os.chown(os.path.dirname(LOG_PATH), pw.pw_uid, pw.pw_gid)
        os.chown(LOG_PATH, pw.pw_uid, pw.pw_gid)

    servers = []
    failed = []
    for service in SERVICES:
        try:
            servers.append(await start_service(service))
        except OSError as exc:
            failed.append((service["protocol"], service["port"], str(exc)))

    drop_privileges(args.user)
    log_event({
        "event_type": "sensor.start",
        "protocol": "sensor",
        "listening_ports": [svc["port"] for svc in SERVICES],
        "failed_ports": failed,
    })
    if failed:
        print("failed ports: " + repr(failed), flush=True)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    await stop.wait()
    for server in servers:
        server.close()
        await server.wait_closed()
    log_event({"event_type": "sensor.stop", "protocol": "sensor"})


if __name__ == "__main__":
    asyncio.run(main())
