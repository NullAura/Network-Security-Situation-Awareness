#!/usr/bin/env python3
import json
import sys


field = sys.argv[1] if len(sys.argv) > 1 else "protocol"

HONEYPOT_ALIASES = {
    "bigdata-honeypot-1": "203.0.113.10",
    "ctf-47": "203.0.113.11",
    "bigdata-honeypot-3": "203.0.113.12",
}


def emit(metric, value):
    if metric == "server_stats":
        value = HONEYPOT_ALIASES.get(str(value or ""), value)
    if value not in (None, ""):
        print(f"{metric}\t{value}\t1")

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        event = json.loads(line)
    except Exception:
        continue

    if field == "all":
        emit("protocol_stats", event.get("protocol"))
        emit("source_ip_topn", event.get("src_ip"))
        emit("event_type_stats", event.get("event_type"))
        emit("server_stats", event.get("server_id"))
        emit("hourly_trend", str(event.get("event_time", ""))[:13])
        continue
    elif field == "hour":
        value = str(event.get("event_time", ""))[:13]
    else:
        value = event.get(field)

    if value not in (None, ""):
        print(f"{value}\t1")
