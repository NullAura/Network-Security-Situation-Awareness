#!/usr/bin/env python3
import argparse
import collections
import datetime as dt
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import preprocess_honeypot_logs as prep


UTC = dt.timezone.utc
DISPLAY_TZ = dt.timezone(dt.timedelta(hours=8), "Asia/Shanghai")


def log(message):
    print(f"{dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} {message}", flush=True)


def now_utc():
    return dt.datetime.now(UTC)


def now_iso(tz=UTC):
    return dt.datetime.now(tz).isoformat(timespec="seconds")


def run(cmd, timeout):
    return subprocess.run(
        cmd,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
    )


def ssh_options():
    return [
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=5",
        "-o",
        "ControlMaster=auto",
        "-o",
        "ControlPersist=60",
        "-o",
        "ControlPath=/tmp/honeypot-live-%r@%h:%p",
    ]


def publish_frontend(local_path, frontend_host, frontend_path, timeout):
    if not frontend_host:
        return
    remote_tmp = f"{frontend_path}.tmp"
    run(["ssh", *ssh_options(), f"root@{frontend_host}", "mkdir", "-p", os.path.dirname(frontend_path)], timeout)
    run(["scp", "-q", *ssh_options(), str(local_path), f"root@{frontend_host}:{remote_tmp}"], timeout)
    run(
        [
            "ssh",
            *ssh_options(),
            f"root@{frontend_host}",
            f"mv {remote_tmp} {frontend_path} && chmod 644 {frontend_path}",
        ],
        timeout,
    )


def parse_args():
    parser = argparse.ArgumentParser(description="Publish a second-level live dashboard from appended honeypot stream files.")
    parser.add_argument("--input", nargs="+", default=["/data/honeypot/stream/{date}"])
    parser.add_argument("--state", default="/data/honeypot/realtime/live_offsets.json")
    parser.add_argument("--dashboard", default="/data/honeypot/frontend/dashboard-live.json")
    parser.add_argument("--limit-events", type=int, default=160, help="Maximum source IPs represented in live dashboard events.")
    parser.add_argument("--retention-events", type=int, default=2000)
    parser.add_argument("--window-seconds", type=float, default=60.0)
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--warmup-lines", type=int, default=160)
    parser.add_argument("--max-read-bytes", type=int, default=2 * 1024 * 1024)
    parser.add_argument("--publish-timeout", type=float, default=20.0)
    parser.add_argument("--frontend-host", default="203.0.113.40")
    parser.add_argument("--frontend-path", default="/opt/honeypot-cybermap-frontend/dist/api/dashboard-live.json")
    parser.add_argument("--once", action="store_true")
    return parser.parse_args()


def load_state(path):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_state(path, state):
    state_path = Path(path)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = state_path.with_suffix(state_path.suffix + ".tmp")
    tmp.write_text(json.dumps(state, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    os.replace(tmp, state_path)


def iter_input_files(input_patterns):
    run_date = dt.datetime.now().strftime("%Y-%m-%d")
    for pattern in input_patterns:
        path = Path(pattern.format(date=run_date))
        if path.is_file():
            yield path
        elif path.is_dir():
            for child in sorted(path.glob("*.jsonl")):
                if child.is_file():
                    yield child


def read_tail_lines(path, limit):
    if limit <= 0:
        return []
    try:
        lines = collections.deque(maxlen=limit)
        with path.open("rb") as handle:
            for raw_line in handle:
                if raw_line.strip():
                    lines.append(raw_line.decode("utf-8", errors="replace").rstrip("\r\n"))
        return list(lines)
    except Exception as exc:
        log(f"warmup skip {path}: {exc}")
        return []


def read_new_lines(path, offset, max_read_bytes):
    try:
        size = path.stat().st_size
        if offset < 0 or offset > size:
            offset = 0
        with path.open("rb") as handle:
            handle.seek(offset)
            data = handle.read(max_read_bytes)
        if not data:
            return [], offset
        if data.endswith(b"\n"):
            complete = data
            new_offset = offset + len(data)
        else:
            complete, separator, _partial = data.rpartition(b"\n")
            if not separator:
                return [], offset
            complete += separator
            new_offset = offset + len(complete)
        lines = [
            raw.decode("utf-8", errors="replace")
            for raw in complete.splitlines()
            if raw.strip()
        ]
        return lines, new_offset
    except Exception as exc:
        log(f"tail skip {path}: {exc}")
        return [], offset


def apply_cached_geo(events, cache):
    for event in events:
        geo = prep.normalize_geo(cache.get(event.get("src_ip")) or event or prep.UNKNOWN_GEO)
        for key in ("country", "region", "city", "isp", "asn", "geo_source", "geo_level"):
            event[key] = geo.get(key) or "unknown"
        for key in ("longitude", "latitude", "sourceCoordinates"):
            if key in geo:
                event[key] = geo[key]
        event["geo_cached"] = event.get("src_ip") in cache


def normalize_lines(lines, path, geo_cache):
    events = []
    counters = collections.Counter()
    for line in lines:
        counters["input_lines"] += 1
        source, obj = prep.load_line(line, path)
        if not isinstance(obj, dict):
            counters["parse_errors"] += 1
            continue
        record = prep.normalize_record(source, obj)
        if not prep.is_public_external(record["src_ip"]):
            counters["filtered_ip"] += 1
            continue
        events.append(record)
        counters["cleaned_events"] += 1
    apply_cached_geo(events, geo_cache)
    return events, counters


def event_timestamp(event):
    return prep.parse_event_time(event.get("event_time_utc") or event.get("event_time")).timestamp()


def build_live_dashboard(recent_events, counters, server_counts, started_at, event_limit, window_seconds):
    retained_events = sorted(list(recent_events), key=event_timestamp, reverse=True)
    generated_at = now_utc()
    cutoff_ts = generated_at.timestamp() - max(0.0, window_seconds)
    window_events = [
        event
        for event in retained_events
        if event_timestamp(event) >= cutoff_ts
    ] if window_seconds > 0 else retained_events
    events = prep.select_events_by_source_ip(retained_events, event_limit)

    protocol_counts = collections.Counter(event["protocol"] for event in window_events)
    source_counts = collections.Counter(event["src_ip"] for event in window_events)
    event_type_counts = collections.Counter(event["event_type"] for event in window_events)
    server_window_counts = collections.Counter(event["server_id"] for event in window_events)
    server_last_event = {}

    latest_event_ts = None
    for event in retained_events:
        server_id = event["server_id"]
        event_time = event.get("event_time") or ""
        if event_time and event_time > server_last_event.get(server_id, ""):
            server_last_event[server_id] = event_time
        ts = event_timestamp(event)
        if latest_event_ts is None or ts > latest_event_ts:
            latest_event_ts = ts

    last_event_delay = None
    if latest_event_ts:
        last_event_delay = max(0, round(generated_at.timestamp() - latest_event_ts, 3))

    protocols = []
    for key, count in protocol_counts.most_common():
        name, severity, color = prep.PROTOCOL_META.get(key, (key, "low", "#7d8da1"))
        protocols.append({"key": key, "name": name, "count": count, "severity": severity, "color": color, "delta": 0})

    sources = []
    for ip, count in source_counts.most_common():
        sample = next((event for event in events if event["src_ip"] == ip), {})
        sources.append(
            {
                "srcIp": ip,
                "country": sample.get("country") or "unknown",
                "region": sample.get("region") or "unknown",
                "city": sample.get("city") or "unknown",
                "isp": sample.get("isp") or "unknown",
                "asn": sample.get("asn") or "unknown",
                "coordinates": sample.get("sourceCoordinates") or "",
                "total": count,
            }
        )

    honeypots = []
    ingest_status = []
    for server_id, meta in prep.HONEYPOTS.items():
        item = dict(meta)
        live_count = server_window_counts.get(server_id, 0)
        last_seen = server_last_event.get(server_id)
        item["collector"] = "203.0.113.20"
        item["status"] = "online" if live_count or server_counts.get(server_id, 0) else "running"
        item["currentEvents"] = live_count
        item["liveEvents"] = server_counts.get(server_id, 0)
        if last_seen:
            item["lastEventAt"] = last_seen
            item["lastSeen"] = last_seen
        honeypots.append(item)
        ingest_status.append(
            {
                "id": server_id,
                "name": server_id,
                "status": item["status"],
                "parser": meta.get("label", "honeypot"),
                "lastSeen": last_seen or now_iso(),
                "lastSeenLocal": last_seen or now_iso(DISPLAY_TZ),
                "hdfsPartition": "/data/honeypot/stream/{date}",
            }
        )

    elapsed = max(1.0, (generated_at - started_at).total_seconds())
    return {
        "generatedAt": generated_at.isoformat(timespec="seconds"),
        "generatedAtLocal": generated_at.astimezone(DISPLAY_TZ).isoformat(timespec="seconds"),
        "mode": "live",
        "source": "incremental stream tail",
        "events": events,
        "honeypots": honeypots,
        "ingestStatus": ingest_status,
        "protocols": protocols,
        "sources": sources,
        "stats": {
            "liveEventsSinceStart": counters["cleaned_events"],
            "windowEvents": len(window_events),
            "windowSeconds": window_seconds,
            "retainedEvents": len(retained_events),
            "publishedEvents": len(events),
            "eventsPerSecond": round(counters["cleaned_events"] / elapsed, 3),
            "lastEventDelaySeconds": last_event_delay,
            "protocols": dict(protocol_counts.most_common()),
            "eventTypes": dict(event_type_counts.most_common()),
            "servers": dict(server_counts.most_common()),
        },
    }


def write_json_atomic(path, payload):
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    tmp = output.with_suffix(output.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    os.replace(tmp, output)


def main():
    args = parse_args()
    state = load_state(args.state)
    offsets = state.get("offsets") if isinstance(state.get("offsets"), dict) else {}
    retention_events = max(args.limit_events, args.retention_events)
    recent_events = collections.deque(maxlen=retention_events)
    counters = collections.Counter()
    server_counts = collections.Counter()
    started_at = now_utc()
    geo_cache = prep.load_geo_cache()

    for path in iter_input_files(args.input):
        key = str(path)
        if key not in offsets and args.warmup_lines:
            lines = read_tail_lines(path, args.warmup_lines)
            events, warmup_counters = normalize_lines(lines, path, geo_cache)
            recent_events.extend(events)
            counters.update({f"warmup_{key}": len(lines)})
            offsets[key] = path.stat().st_size
            log(f"warmup {path}: lines={len(lines)} events={len(events)}")
        elif key not in offsets:
            offsets[key] = path.stat().st_size

    last_publish = 0.0
    log(f"live publisher started inputs={','.join(args.input)} dashboard={args.dashboard}")
    while True:
        changed = False
        for path in iter_input_files(args.input):
            key = str(path)
            offset = int(offsets.get(key, 0))
            lines, new_offset = read_new_lines(path, offset, args.max_read_bytes)
            offsets[key] = new_offset
            if not lines:
                continue
            events, line_counters = normalize_lines(lines, path, geo_cache)
            counters.update(line_counters)
            recent_events.extend(events)
            for event in events:
                server_counts[event["server_id"]] += 1
            changed = True

        now = time.monotonic()
        if changed or now - last_publish >= max(5.0, args.interval):
            dashboard = build_live_dashboard(
                recent_events,
                counters,
                server_counts,
                started_at,
                args.limit_events,
                args.window_seconds,
            )
            write_json_atomic(args.dashboard, dashboard)
            save_state(args.state, {"offsets": offsets, "updated_at": now_iso()})
            try:
                publish_frontend(args.dashboard, args.frontend_host, args.frontend_path, args.publish_timeout)
            except subprocess.CalledProcessError as exc:
                log(f"publish failed: command exited {exc.returncode}: {exc.stdout.strip()}")
            except Exception as exc:
                log(f"publish failed: {exc}")
            last_publish = now
            if changed:
                stats = dashboard.get("stats", {})
                log(
                    "live refreshed "
                    f"new_lines={counters['input_lines']} "
                    f"live_events={counters['cleaned_events']} "
                    f"window_events={stats.get('windowEvents')} "
                    f"retained_events={stats.get('retainedEvents')}"
                )

        if args.once:
            return 0
        time.sleep(max(0.2, args.interval))


if __name__ == "__main__":
    sys.exit(main())
