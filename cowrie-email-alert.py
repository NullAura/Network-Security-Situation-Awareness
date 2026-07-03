#!/usr/bin/env python3
import json
import os
import socket
import subprocess
import time
from email.message import EmailMessage
from pathlib import Path

LOG_PATH = Path(os.environ.get("COWRIE_LOG", "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"))
STATE_PATH = Path(os.environ.get("COWRIE_ALERT_STATE", "/home/cowrie/cowrie/var/lib/cowrie/email-alert.offset"))
RECIPIENT = os.environ.get("COWRIE_ALERT_TO", "")
SENDER = os.environ.get("COWRIE_ALERT_FROM", f"cowrie-alert@{socket.gethostname()}.local")
BATCH_SECONDS = int(os.environ.get("COWRIE_ALERT_BATCH_SECONDS", "30"))
MAX_EVENTS = int(os.environ.get("COWRIE_ALERT_MAX_EVENTS", "20"))
POLL_SECONDS = 2

IMPORTANT_EVENTS = {
    "cowrie.session.connect",
    "cowrie.login.failed",
    "cowrie.login.success",
    "cowrie.command.input",
    "cowrie.session.file_download",
    "cowrie.direct-tcpip.request",
    "cowrie.client.version",
}


def load_offset(path: Path) -> int | None:
    try:
        return int(path.read_text().strip())
    except Exception:
        return None


def save_offset(path: Path, offset: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(offset))


def summarize(event: dict) -> str:
    fields = [
        ("time", event.get("timestamp")),
        ("event", event.get("eventid")),
        ("src", event.get("src_ip")),
        ("user", event.get("username")),
        ("pass", event.get("password")),
        ("cmd", event.get("input")),
        ("session", event.get("session")),
        ("msg", event.get("message")),
    ]
    return " | ".join(f"{key}={value}" for key, value in fields if value not in (None, ""))


def send_email(events: list[dict]) -> None:
    if not events:
        return
    if not RECIPIENT:
        raise RuntimeError("COWRIE_ALERT_TO is required")
    host = socket.gethostname()
    src_ips = sorted({str(event.get("src_ip")) for event in events if event.get("src_ip")})
    subject = f"[Cowrie Honeypot Alert] {host} detected {len(events)} event(s)"
    body_lines = [
        f"Cowrie honeypot detected {len(events)} event(s) on {host}.",
        f"Log file: {LOG_PATH}",
        f"Source IPs: {', '.join(src_ips) if src_ips else 'unknown'}",
        "",
        "Event summary:",
    ]
    body_lines.extend(summarize(event) for event in events[:MAX_EVENTS])
    if len(events) > MAX_EVENTS:
        body_lines.append(f"... {len(events) - MAX_EVENTS} more event(s) omitted in this email.")
    body_lines.append("")
    body_lines.append("Raw JSON lines:")
    body_lines.extend(json.dumps(event, ensure_ascii=False, sort_keys=True) for event in events[:MAX_EVENTS])

    msg = EmailMessage()
    msg["From"] = SENDER
    msg["To"] = RECIPIENT
    msg["Subject"] = subject
    msg.set_content("\n".join(body_lines))

    subprocess.run(["/usr/sbin/sendmail", "-t", "-oi"], input=msg.as_bytes(), check=True)


def main() -> None:
    batch: list[dict] = []
    batch_start = None
    offset = load_offset(STATE_PATH)

    while not LOG_PATH.exists():
        time.sleep(POLL_SECONDS)

    with LOG_PATH.open("r", encoding="utf-8", errors="replace") as log_file:
        if offset is None:
            log_file.seek(0, os.SEEK_END)
            save_offset(STATE_PATH, log_file.tell())
        else:
            log_file.seek(offset)

        while True:
            line = log_file.readline()
            if not line:
                if batch and batch_start and time.time() - batch_start >= BATCH_SECONDS:
                    send_email(batch)
                    batch.clear()
                    batch_start = None
                current_size = LOG_PATH.stat().st_size if LOG_PATH.exists() else 0
                if log_file.tell() > current_size:
                    log_file.seek(0, os.SEEK_END)
                save_offset(STATE_PATH, log_file.tell())
                time.sleep(POLL_SECONDS)
                continue

            save_offset(STATE_PATH, log_file.tell())
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            eventid = event.get("eventid")
            if eventid not in IMPORTANT_EVENTS:
                continue
            if not batch:
                batch_start = time.time()
            batch.append(event)
            if len(batch) >= MAX_EVENTS:
                send_email(batch)
                batch.clear()
                batch_start = None


if __name__ == "__main__":
    main()
