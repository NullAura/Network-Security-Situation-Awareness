#!/usr/bin/env python3
import argparse
import collections
import datetime as dt
import ipaddress
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


OWN_TEST_IP = "198.51.100.10"
GEO_CACHE_PATH = os.environ.get("HONEYPOT_GEO_CACHE", "/data/honeypot/geoip_cache.json")
GEO_CACHE_TTL_DAYS = 30
GEO_BATCH_SIZE = 100
GEO_MAX_LOOKUPS_PER_RUN = int(os.environ.get("HONEYPOT_GEO_MAX_LOOKUPS", "100"))
UTC = dt.timezone.utc
DISPLAY_TZ = dt.timezone(dt.timedelta(hours=8), "Asia/Shanghai")
UNKNOWN_GEO = {
    "country": "unknown",
    "region": "unknown",
    "city": "unknown",
    "isp": "unknown",
    "asn": "unknown",
    "geo_source": "unknown",
    "geo_level": "unknown",
}

SKIP_FILE_SUFFIXES = (".log.tmp", ".offset", ".tmp", ".bak", ".backup", ".pre-geo.bak", ".geo-backfill.bak")

HONEYPOT_ALIASES = {
    "bigdata-honeypot-1": "203.0.113.10",
    "ctf-47": "203.0.113.11",
    "bigdata-honeypot-3": "203.0.113.12",
}

SOURCE_HINTS = [
    ("203.0.113.10", "203.0.113.10"),
    ("bigdata-honeypot-1", "203.0.113.10"),
    ("cowrie", "203.0.113.10"),
    ("203.0.113.11", "203.0.113.11"),
    ("ctf-47", "203.0.113.11"),
    ("opencanary-47", "203.0.113.11"),
    ("opencanary", "203.0.113.11"),
    ("203.0.113.12", "203.0.113.12"),
    ("bigdata-honeypot-3", "203.0.113.12"),
    ("honeypot3", "203.0.113.12"),
]

HONEYPOTS = {
    "203.0.113.10": {
        "id": "203.0.113.10",
        "name": "203.0.113.10",
        "label": "Cowrie SSH",
        "ip": "203.0.113.10",
        "city": "北美云节点",
        "country": "United States",
        "coordinates": [-118.2437, 34.0522],
        "color": "#19d3ff",
        "type": "cowrie",
    },
    "203.0.113.11": {
        "id": "203.0.113.11",
        "name": "203.0.113.11",
        "label": "OpenCanary 多协议",
        "ip": "203.0.113.11",
        "city": "华东云节点",
        "country": "China",
        "coordinates": [121.4737, 31.2304],
        "color": "#a7f35a",
        "type": "opencanary",
    },
    "203.0.113.12": {
        "id": "203.0.113.12",
        "name": "203.0.113.12",
        "label": "多协议低交互",
        "ip": "203.0.113.12",
        "city": "第三云节点",
        "country": "Brazil",
        "coordinates": [-46.6333, -23.5505],
        "color": "#ffcf58",
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

PROTOCOL_META = {
    "SSH": ("Cowrie SSH", "high", "#9aff57"),
    "FTP": ("FTP", "medium", "#8a7dff"),
    "HTTP": ("HTTP", "medium", "#27d7ff"),
    "MYSQL": ("MySQL", "high", "#ffcf58"),
    "REDIS": ("Redis", "high", "#ff6048"),
    "TELNET": ("Telnet", "medium", "#a88cff"),
    "RDP": ("RDP", "high", "#58a6ff"),
    "VNC": ("VNC", "low", "#5ab7ff"),
    "MQTT": ("MQTT", "medium", "#31d0aa"),
    "ORACLE": ("Oracle", "high", "#f28c28"),
    "KAFKA": ("Kafka", "medium", "#d7dd48"),
    "SMB": ("SMB", "high", "#ff6f91"),
    "UNKNOWN": ("Unknown", "low", "#7d8da1"),
}


def parse_args():
    parser = argparse.ArgumentParser(description="Normalize honeypot logs into cleaned JSONL.")
    parser.add_argument("--input", nargs="+", required=True, help="Input files or directories.")
    parser.add_argument("--history-input", nargs="+", default=[], help="Optional full-history files or directories used for cumulative dashboard counters.")
    parser.add_argument("--output", required=True, help="Cleaned JSONL output path.")
    parser.add_argument("--summary", required=True, help="Summary JSON output path.")
    parser.add_argument("--dashboard", required=True, help="Frontend dashboard JSON output path.")
    parser.add_argument("--limit-events", type=int, default=120, help="Maximum source IPs represented in dashboard events.")
    return parser.parse_args()


def iter_files(paths):
    for raw_path in paths:
        path = Path(raw_path)
        if path.is_file() and not path.name.endswith(SKIP_FILE_SUFFIXES):
            yield path
        elif path.is_dir():
            for child in sorted(path.rglob("*")):
                if child.is_file() and not child.name.endswith(SKIP_FILE_SUFFIXES):
                    yield child


def build_history_counters(paths):
    if not paths:
        return None

    counters = collections.Counter()
    server_counts = collections.Counter()
    protocol_counts = collections.Counter()
    source_ips = set()
    server_sources = collections.defaultdict(set)
    server_last_event = {}
    daily_buckets = {}
    hourly_buckets = {}
    method_items = {}
    method_names = {}
    high_count = 0
    command_count = 0

    for file_path in iter_files(paths):
        with file_path.open(encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if not line.strip():
                    continue
                counters["history_input_lines"] += 1
                source, obj = load_line(line, file_path)
                if not isinstance(obj, dict):
                    counters["history_parse_errors"] += 1
                    continue
                record = normalized_history_record(source, obj) or normalize_record(source, obj)
                if not is_public_external(record["src_ip"]):
                    counters["history_filtered_ip"] += 1
                    continue

                method = infer_attack_method(record)
                event_is_high = record.get("severity") == "high" or method.get("severity") == "high"
                timestamp = parse_event_time(record.get("event_time_utc") or record.get("event_time")).astimezone(DISPLAY_TZ)
                date_key = timestamp.strftime("%Y-%m-%d")
                hour_key = (date_key, timestamp.hour)
                server_id = record["server_id"]
                src_ip = record["src_ip"]
                protocol = record.get("protocol") or "UNKNOWN"

                counters["history_events"] += 1
                server_counts[server_id] += 1
                protocol_counts[protocol] += 1
                source_ips.add(src_ip)
                server_sources[server_id].add(src_ip)
                update_attack_method_item(method_items, record, method=method)
                method_names[method["key"]] = method["name"]

                if event_is_high:
                    high_count += 1
                if record.get("event_type") == "command_input" or record.get("command"):
                    command_count += 1

                event_time = record.get("event_time") or ""
                if event_time and event_time > server_last_event.get(server_id, ""):
                    server_last_event[server_id] = event_time

                for bucket_map, key in ((daily_buckets, date_key), (hourly_buckets, hour_key)):
                    bucket = bucket_map.setdefault(key, new_history_bucket(date_key, timestamp.hour if isinstance(key, tuple) else None))
                    bucket["total"] += 1
                    if event_is_high:
                        bucket["high"] += 1
                    bucket["sourceIps"].add(src_ip)
                    bucket["methodCounts"][method["key"]] += 1
                    bucket["protocolCounts"][protocol] += 1
                    if event_is_high:
                        bucket["methodHighCounts"][method["key"]] += 1
                        bucket["protocolHighCounts"][protocol] += 1

    return {
        "counters": dict(counters),
        "totalEvents": counters["history_events"],
        "externalIps": len(source_ips),
        "highRisk": high_count,
        "commandCount": command_count,
        "server_counts": dict(server_counts),
        "server_external_ips": {server_id: len(values) for server_id, values in server_sources.items()},
        "server_last_event": dict(server_last_event),
        "protocol_counts": dict(protocol_counts),
        "attackMethods": serialize_attack_method_items(method_items),
        "historyTrend": {
            "timezone": "Asia/Shanghai",
            "availableDates": sorted(daily_buckets.keys(), reverse=True),
            "daily": [serialize_history_bucket(bucket) for _key, bucket in sorted(daily_buckets.items())],
            "hourly": [serialize_history_bucket(bucket) for _key, bucket in sorted(hourly_buckets.items())],
            "methodNames": method_names,
        },
    }


def new_history_bucket(date_key, hour):
    bucket = {
        "date": date_key,
        "hour": hour,
        "total": 0,
        "high": 0,
        "sourceIps": set(),
        "methodCounts": collections.Counter(),
        "protocolCounts": collections.Counter(),
        "methodHighCounts": collections.Counter(),
        "protocolHighCounts": collections.Counter(),
    }
    if hour is not None:
        bucket["label"] = f"{hour:02d}:00"
        bucket["bucketStart"] = f"{date_key}T{hour:02d}:00:00+08:00"
    return bucket


def serialize_history_bucket(bucket):
    method_counts = dict(bucket["methodCounts"].most_common())
    top_method_key = next(iter(method_counts), "")
    return {
        "date": bucket["date"],
        "hour": bucket.get("hour"),
        "label": bucket.get("label") or bucket["date"],
        "bucketStart": bucket.get("bucketStart"),
        "total": bucket["total"],
        "high": bucket["high"],
        "sourceIpCount": len(bucket["sourceIps"]),
        "methodCounts": method_counts,
        "protocolCounts": dict(bucket["protocolCounts"].most_common()),
        "methodHighCounts": dict(bucket["methodHighCounts"].most_common()),
        "protocolHighCounts": dict(bucket["protocolHighCounts"].most_common()),
        "topMethodKey": top_method_key,
    }


def build_history_counters_strict(paths):
    counters = collections.Counter()
    server_counts = collections.Counter()
    source_ips = set()
    server_sources = collections.defaultdict(set)
    server_last_event = {}

    for file_path in iter_files(paths):
        with file_path.open(encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if not line.strip():
                    continue
                counters["history_input_lines"] += 1
                source, obj = load_line(line, file_path)
                if not isinstance(obj, dict):
                    counters["history_parse_errors"] += 1
                    continue
                record = normalize_record(source, obj)
                if not is_public_external(record["src_ip"]):
                    counters["history_filtered_ip"] += 1
                    continue

                server_id = record["server_id"]
                src_ip = record["src_ip"]
                event_time = record.get("event_time") or ""
                counters["history_events"] += 1
                server_counts[server_id] += 1
                source_ips.add(src_ip)
                server_sources[server_id].add(src_ip)
                if event_time and event_time > server_last_event.get(server_id, ""):
                    server_last_event[server_id] = event_time

    return {
        "counters": dict(counters),
        "totalEvents": counters["history_events"],
        "externalIps": len(source_ips),
        "server_counts": dict(server_counts),
        "server_external_ips": {server_id: len(values) for server_id, values in server_sources.items()},
        "server_last_event": dict(server_last_event),
    }


def source_from_path(path):
    text = str(path)
    for source_id in HONEYPOTS:
        if source_id in text:
            return source_id
    if "bigdata-honeypot-1" in text:
        return "203.0.113.10"
    if "ctf-47" in text:
        return "203.0.113.11"
    if "bigdata-honeypot-3" in text:
        return "203.0.113.12"
    if "cowrie" in text:
        return "203.0.113.10"
    if "opencanary" in text:
        return "203.0.113.11"
    if "honeypot3" in text:
        return "203.0.113.12"
    return "unknown"


def normalize_source_id(source):
    text = str(source or "")
    return HONEYPOT_ALIASES.get(text, text)


def infer_source_from_record(obj, fallback):
    source = normalize_source_id(fallback)
    if source in HONEYPOTS:
        return source
    fields = [
        obj.get("server_id"),
        obj.get("source"),
        obj.get("node_id"),
        obj.get("_collector_path"),
        obj.get("raw"),
    ]
    haystack = " ".join(str(value) for value in fields if value).lower()
    for needle, source_id in SOURCE_HINTS:
        if needle.lower() in haystack:
            return source_id
    return source


def load_line(line, path):
    try:
        outer = json.loads(line)
    except Exception:
        return None, None

    if isinstance(outer, dict) and "line" in outer and "source" in outer:
        source = normalize_source_id(outer.get("source") or source_from_path(path))
        try:
            inner = json.loads(str(outer.get("line") or ""))
        except Exception:
            inner = {"raw_payload": outer.get("line")}
        if not isinstance(inner, dict):
            inner = {"raw_payload": inner}
        inner["_collector_received_at"] = outer.get("received_at")
        inner["_collector_path"] = outer.get("path")
        return source, inner

    if isinstance(outer, dict) and (
        "server_id" in outer
        or "src_ip" in outer
        or "event_time" in outer
        or "raw" in outer
    ):
        source = normalize_source_id(outer.get("server_id") or outer.get("source") or source_from_path(path))
        outer["_collector_received_at"] = outer.get("received_at")
        outer["_collector_path"] = outer.get("path")
        return source, outer

    return source_from_path(path), outer


def normalized_history_record(source, obj):
    if not isinstance(obj, dict):
        return None
    if not (obj.get("schema_version") or obj.get("event_ts_ms") or obj.get("event_ts_utc")):
        return None
    src_ip = obj.get("src_ip") or obj.get("source_ip")
    if not src_ip:
        return None
    raw_obj = obj.get("raw") if isinstance(obj.get("raw"), dict) else {}
    logdata = raw_obj.get("logdata") if isinstance(raw_obj.get("logdata"), dict) else {}
    payload = obj.get("payload") or obj.get("raw_line") or ""
    raw_text = obj.get("raw_line") or payload
    if not raw_text and raw_obj:
        raw_text = json.dumps(raw_obj, ensure_ascii=False)
    protocol = norm_protocol(obj.get("protocol"), obj.get("dst_port") or obj.get("destination_port"), payload or raw_text)
    event_type = obj.get("event_type") or obj.get("eventid") or raw_obj.get("event_type") or raw_obj.get("eventid") or "connection"
    command = obj.get("command") or ""
    password = obj.get("password") or logdata.get("VNC Password") or ""
    username = obj.get("username") or raw_obj.get("username") or ""
    severity = PROTOCOL_META.get(protocol, PROTOCOL_META["UNKNOWN"])[1]
    if event_type in {"command_input", "file_download"} or command:
        severity = "high"

    record = {
        "event_time": normalize_time(obj.get("event_ts_beijing") or obj.get("event_time") or obj.get("raw_time"), DISPLAY_TZ),
        "event_time_utc": normalize_time_utc(obj.get("event_ts_utc") or obj.get("event_time") or obj.get("raw_time")),
        "server_id": infer_source_from_record(obj, source),
        "src_ip": str(src_ip),
        "protocol": protocol,
        "event_type": event_type,
        "username": clean_text(username, 120),
        "password": clean_text(password, 120),
        "command": clean_text(command, 300),
        "payload": clean_text(payload, 500),
        "severity": severity,
        "raw": clean_text(raw_text, 1200),
    }
    return record


def is_public_external(ip):
    if not ip or ip == OWN_TEST_IP:
        return False
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def load_geo_cache(path=GEO_CACHE_PATH):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_geo_cache(cache, path=GEO_CACHE_PATH):
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(cache, handle, ensure_ascii=False, separators=(",", ":"))
        os.replace(tmp, path)
    except Exception:
        pass


def cache_is_fresh(item):
    try:
        checked = dt.datetime.fromisoformat(str(item.get("cached_at")))
        if checked.tzinfo is None:
            checked = checked.replace(tzinfo=dt.timezone.utc)
        return dt.datetime.now(dt.timezone.utc) - checked < dt.timedelta(days=GEO_CACHE_TTL_DAYS)
    except Exception:
        return False


def geo_has_coordinates(item):
    if not isinstance(item, dict):
        return False
    coords = item.get("sourceCoordinates")
    if isinstance(coords, list) and len(coords) == 2:
        try:
            return abs(float(coords[0])) > 0.0001 or abs(float(coords[1])) > 0.0001
        except (TypeError, ValueError):
            return False
    try:
        return abs(float(item.get("longitude"))) > 0.0001 or abs(float(item.get("latitude"))) > 0.0001
    except (TypeError, ValueError):
        return False


def normalize_geo(item):
    if not isinstance(item, dict):
        return dict(UNKNOWN_GEO)
    if item.get("success") is False or item.get("status") == "fail":
        return dict(UNKNOWN_GEO)

    connection = item.get("connection") if isinstance(item.get("connection"), dict) else {}
    asn_number = connection.get("asn")
    asn_org = connection.get("org") or connection.get("isp") or ""
    if asn_number and asn_org:
        asn = f"AS{asn_number} {asn_org}"
    elif asn_number:
        asn = f"AS{asn_number}"
    else:
        asn = item.get("as") or item.get("asn") or asn_org or "unknown"

    geo = {
        "country": str(item.get("country") or "unknown"),
        "region": str(item.get("regionName") or item.get("region") or "unknown"),
        "city": str(item.get("city") or "unknown"),
        "isp": str(connection.get("isp") or item.get("isp") or connection.get("org") or "unknown"),
        "asn": str(asn),
        "geo_source": str(item.get("geo_source") or "ipwho.is"),
        "geo_level": str(item.get("geo_level") or "ip"),
    }

    coords = item.get("sourceCoordinates")
    lon = item.get("longitude")
    lat = item.get("latitude")
    if isinstance(coords, list) and len(coords) == 2:
        lon, lat = coords
    try:
        lon = float(lon)
        lat = float(lat)
        geo["longitude"] = lon
        geo["latitude"] = lat
        geo["sourceCoordinates"] = [lon, lat]
    except (TypeError, ValueError):
        pass
    return geo


def fetch_geo_batch(ips, timeout=4.0):
    enriched = {}
    for ip in ips:
        url = "https://ipwho.is/" + urllib.parse.quote(str(ip), safe="")
        request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "honeypot-preprocess/1.0"})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = json.loads(response.read().decode("utf-8", errors="replace"))
            enriched[str(ip)] = normalize_geo(payload)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            continue
    return enriched


def enrich_geo(events):
    cache = load_geo_cache()
    now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    unique_ips = sorted({event["src_ip"] for event in events if is_public_external(event.get("src_ip"))})
    missing = [
        ip for ip in unique_ips
        if ip not in cache
        or not cache_is_fresh(cache[ip])
        or cache[ip].get("country") == "unknown"
        or not geo_has_coordinates(cache[ip])
    ]
    missing = missing[:GEO_MAX_LOOKUPS_PER_RUN]
    for start in range(0, len(missing), GEO_BATCH_SIZE):
        batch = missing[start:start + GEO_BATCH_SIZE]
        for ip, geo in fetch_geo_batch(batch).items():
            cache[ip] = {**geo, "cached_at": now}
    save_geo_cache(cache)

    resolved = 0
    for event in events:
        geo = normalize_geo(cache.get(event["src_ip"]) or event or UNKNOWN_GEO)
        for key in ("country", "region", "city", "isp", "asn", "geo_source", "geo_level"):
            event[key] = geo.get(key) or "unknown"
        for key in ("longitude", "latitude", "sourceCoordinates"):
            if key in geo:
                event[key] = geo[key]
        event["geo_cached"] = event["src_ip"] in cache
        if event["country"] != "unknown" or event["city"] != "unknown":
            resolved += 1
    return resolved


def parse_event_time(value):
    if not value:
        return dt.datetime.now(UTC)
    text = str(value)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    if len(text) >= 5 and text[-5] in {"+", "-"} and text[-3] != ":":
        text = text[:-2] + ":" + text[-2:]
    try:
        parsed = dt.datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed
    except Exception:
        return dt.datetime.now(UTC)


def normalize_time(value, timezone=DISPLAY_TZ):
    return parse_event_time(value).astimezone(timezone).isoformat(timespec="seconds")


def normalize_time_utc(value):
    return normalize_time(value, UTC)


def normalize_time_local(value):
    return parse_event_time(value).astimezone(DISPLAY_TZ).strftime("%Y-%m-%d %H:%M:%S")


def norm_protocol(value, dst_port=None, payload=""):
    text = str(value or "").upper()
    if text in {"MYSQL", "REDIS", "SSH", "FTP", "HTTP", "TELNET", "RDP", "VNC", "MQTT", "ORACLE", "KAFKA", "SMB", "POSTGRES", "MSSQL"}:
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


def norm_event_type(source, obj, protocol):
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


def clean_text(value, max_len=300):
    if value is None:
        return ""
    text = str(value).replace("\r", "\\r").replace("\n", "\\n")
    return text[:max_len]


def normalize_record(source, obj):
    source = infer_source_from_record(obj, source)
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
    event_type = norm_event_type(source, obj, protocol)
    command = obj.get("input") if event_type == "command_input" else obj.get("command")
    username = obj.get("username") or obj.get("user") or logdata.get("USERNAME") or ""
    password = obj.get("password") or logdata.get("PASSWORD") or ""
    event_time = (
        obj.get("timestamp")
        or obj.get("event_time")
        or obj.get("utc_time")
        or obj.get("local_time")
        or obj.get("_collector_received_at")
    )
    event_time_utc = normalize_time_utc(event_time)
    event_time_beijing = normalize_time(event_time, DISPLAY_TZ)
    severity = PROTOCOL_META.get(protocol, PROTOCOL_META["UNKNOWN"])[1]
    if event_type in {"command_input", "file_download"}:
        severity = "high"
    geo = normalize_geo(obj)

    record = {
        "event_time": event_time_beijing,
        "event_time_utc": event_time_utc,
        "event_time_local": normalize_time_local(event_time),
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
        "country": geo.get("country") or "unknown",
        "region": geo.get("region") or "unknown",
        "city": geo.get("city") or "unknown",
        "isp": geo.get("isp") or "unknown",
        "asn": geo.get("asn") or "unknown",
        "geo_source": geo.get("geo_source") or "unknown",
        "geo_level": geo.get("geo_level") or "unknown",
        "geo_cached": bool(obj.get("geo_cached")),
        "severity": severity,
        "raw": clean_text(obj.get("raw") or obj.get("raw_payload") or json.dumps(obj, ensure_ascii=False), 1200),
    }
    for key in ("longitude", "latitude", "sourceCoordinates"):
        if key in geo:
            record[key] = geo[key]
    return record


def infer_attack_method(event):
    protocol = str(event.get("protocol") or "UNKNOWN").upper()
    event_type = str(event.get("event_type") or "").lower()
    command = str(event.get("command") or "")
    payload = str(event.get("payload") or event.get("raw") or "")
    username = str(event.get("username") or "")
    password = str(event.get("password") or "")
    text = f"{event_type} {command} {payload} {username} {password}".lower()

    if command or "command" in event_type or "file_download" in event_type:
        return {
            "key": "command_execution",
            "name": "命令执行/恶意下载",
            "tactic": "execution",
            "severity": "high",
            "description": "交互命令、下载器、shell 脚本或后渗透执行行为。",
        }
    if "select " in text or "union " in text or " or 1=1" in text or "sql" in text:
        return {
            "key": "sql_injection_probe",
            "name": "SQL 注入探测",
            "tactic": "exploit",
            "severity": "high",
            "description": "HTTP 或数据库入口中的 SQL 关键字、布尔条件或联合查询探测。",
        }
    if username or password or "login" in event_type or "auth" in event_type:
        if protocol == "SSH":
            name = "SSH 弱口令爆破"
            key = "ssh_credential_attack"
        elif protocol == "VNC":
            name = "VNC 密码爆破"
            key = "vnc_credential_attack"
        elif protocol in {"MYSQL", "POSTGRES", "MSSQL", "ORACLE"}:
            name = "数据库登录尝试"
            key = "database_login_attempt"
        else:
            name = "账号口令尝试"
            key = "credential_attack"
        return {
            "key": key,
            "name": name,
            "tactic": "credential_access",
            "severity": "high",
            "description": "登录、认证、用户名或密码字段形成的爆破与弱口令尝试。",
        }
    if protocol == "HTTP":
        if any(token in text for token in ("wget", "curl", "chmod", "/bin/sh", "bash", "powershell", "base64")):
            return {
                "key": "http_payload_probe",
                "name": "HTTP Payload 探测",
                "tactic": "exploit",
                "severity": "high",
                "description": "HTTP 请求中携带下载器、命令执行或脚本 payload 特征。",
            }
        return {
            "key": "http_fingerprint_probe",
            "name": "HTTP 指纹探测",
            "tactic": "recon",
            "severity": "medium",
            "description": "HTTP 路径、请求头、User-Agent 或 Web 服务指纹探测。",
        }
    if protocol in {"MYSQL", "POSTGRES", "MSSQL", "ORACLE", "MONGODB"}:
        return {
            "key": "database_probe",
            "name": "数据库服务探测",
            "tactic": "recon",
            "severity": "high",
            "description": "数据库端口握手、版本识别或连接试探。",
        }
    if protocol == "REDIS":
        return {
            "key": "redis_command_probe",
            "name": "Redis 命令探测",
            "tactic": "exploit",
            "severity": "high",
            "description": "Redis INFO、AUTH、CONFIG、SET 等未授权或命令试探。",
        }
    if protocol == "MQTT":
        return {
            "key": "mqtt_probe",
            "name": "MQTT 连接探测",
            "tactic": "probe",
            "severity": "medium",
            "description": "MQTT 连接、订阅或物联网消息入口试探。",
        }
    if protocol == "SMB":
        return {
            "key": "smb_probe",
            "name": "SMB 服务探测",
            "tactic": "probe",
            "severity": "high",
            "description": "SMB/文件共享端口连接、枚举或握手探测。",
        }
    if protocol in {"TELNET", "RDP", "FTP"}:
        return {
            "key": f"{protocol.lower()}_probe",
            "name": f"{protocol} 服务探测",
            "tactic": "probe",
            "severity": "high",
            "description": "高风险远程访问服务的连接或认证入口探测。",
        }
    return {
        "key": "protocol_probe",
        "name": "服务指纹探测",
        "tactic": "recon",
        "severity": "low",
        "description": "端口、握手或服务指纹层面的背景探测。",
    }


def build_attack_method_stats(events):
    methods = {}
    for event in events:
        update_attack_method_item(methods, event)
    return serialize_attack_method_items(methods)


def update_attack_method_item(methods, event, method=None):
    method = method or infer_attack_method(event)
    item = methods.setdefault(method["key"], {
        **method,
        "count": 0,
        "sourceIpCount": 0,
        "protocolCount": 0,
        "protocols": set(),
        "sourceIps": set(),
        "examples": [],
    })
    item["count"] += 1
    if event.get("src_ip"):
        item["sourceIps"].add(event["src_ip"])
    if event.get("protocol"):
        item["protocols"].add(event["protocol"])
    detail = event.get("command") or event.get("payload") or event.get("event_type")
    if detail and len(item["examples"]) < 5:
        item["examples"].append(clean_text(detail, 160))


def serialize_attack_method_items(methods):
    rows = []
    for item in methods.values():
        protocols = sorted(item["protocols"])
        source_ips = item["sourceIps"]
        rows.append({
            **{key: value for key, value in item.items() if key not in {"protocols", "sourceIps"}},
            "sourceIpCount": len(source_ips),
            "protocolCount": len(protocols),
            "protocols": protocols,
        })
    severity_rank = {"high": 3, "medium": 2, "low": 1}
    rows.sort(key=lambda row: (-row["count"], -severity_rank.get(row["severity"], 0), row["name"]))
    return rows


def build_dashboard(events, summary, limit, history=None):
    protocol_counts = collections.Counter(event["protocol"] for event in events)
    if (history or {}).get("protocol_counts"):
        protocol_counts = collections.Counter((history or {}).get("protocol_counts"))
    source_counts = collections.Counter(event["src_ip"] for event in events)
    source_high_counts = collections.Counter(event["src_ip"] for event in events if event.get("severity") == "high")
    source_protocols = collections.defaultdict(set)
    server_counts = collections.Counter(event["server_id"] for event in events)
    server_sources = collections.defaultdict(set)
    server_last_event = {}
    command_count = sum(1 for event in events if event["event_type"] == "command_input" or event["command"])
    high_count = sum(1 for event in events if event.get("severity") == "high")
    sorted_events = sorted(events, key=lambda item: item["event_time"], reverse=True)
    display_events = select_events_by_source_ip(sorted_events, limit)
    attack_methods = (history or {}).get("attackMethods") or build_attack_method_stats(events)

    for event in events:
        server_id = event["server_id"]
        if event.get("src_ip"):
            server_sources[server_id].add(event["src_ip"])
            source_protocols[event["src_ip"]].add(event["protocol"])
        event_time = event.get("event_time") or ""
        if event_time and event_time > server_last_event.get(server_id, ""):
            server_last_event[server_id] = event_time

    protocols = []
    for key, count in protocol_counts.most_common():
        name, severity, color = PROTOCOL_META.get(key, (key, "low", "#7d8da1"))
        protocols.append({"key": key, "name": name, "count": count, "severity": severity, "color": color, "delta": 0})

    sources = []
    for ip, count in source_counts.most_common():
        event = next((item for item in events if item["src_ip"] == ip), {})
        sources.append(
            {
                "srcIp": ip,
                "country": event.get("country") or "unknown",
                "region": event.get("region") or "unknown",
                "city": event.get("city") or "unknown",
                "isp": event.get("isp") or "unknown",
                "asn": event.get("asn") or "unknown",
                "coordinates": event.get("sourceCoordinates") or "",
                "total": count,
                "highEvents": source_high_counts.get(ip, 0),
                "protocols": sorted(source_protocols.get(ip, set())),
            }
        )

    honeypots = []
    for server_id, meta in HONEYPOTS.items():
        item = dict(meta)
        event_count = (history or {}).get("server_counts", {}).get(server_id, server_counts.get(server_id, 0))
        external_ip_count = (history or {}).get("server_external_ips", {}).get(server_id, len(server_sources.get(server_id, set())))
        last_event_at = (history or {}).get("server_last_event", {}).get(server_id, server_last_event.get(server_id))
        item["status"] = "online"
        item["collector"] = "203.0.113.20"
        item["event_count"] = event_count
        item["eventTotal"] = event_count
        item["totalEvents"] = event_count
        item["currentEvents"] = event_count
        item["externalIpCount"] = external_ip_count
        item["external_ip_count"] = external_ip_count
        if last_event_at:
            item["lastEventAt"] = last_event_at
            item["lastSeen"] = last_event_at
        honeypots.append(item)

    return {
        "generatedAt": dt.datetime.now(UTC).isoformat(timespec="seconds"),
        "generatedAtLocal": dt.datetime.now(DISPLAY_TZ).isoformat(timespec="seconds"),
        "honeypots": honeypots,
        "protocols": protocols,
        "attackMethods": attack_methods,
        "sources": sources,
        "events": display_events,
        "stats": {
            "totalEvents": (history or {}).get("totalEvents", len(events)),
            "sessionCount": summary["event_type_counts"].get("connection", 0),
            "externalIps": (history or {}).get("externalIps", len(source_counts)),
            "commandCount": (history or {}).get("commandCount", command_count),
            "highRisk": (history or {}).get("highRisk", high_count),
        },
        "historyStats": {
            "enabled": bool(history),
            "totalEvents": (history or {}).get("totalEvents", len(events)),
            "externalIps": (history or {}).get("externalIps", len(source_counts)),
            "scope": "all available /data/honeypot/stream history" if history else "current input",
            "counters": (history or {}).get("counters", {}),
        },
        "historyTrend": (history or {}).get("historyTrend", {}),
        "ingestStatus": [
            {
                "id": meta["id"],
                "name": meta["name"],
                "status": "online",
                "lastSeen": dt.datetime.now(UTC).isoformat(timespec="seconds"),
                "lastSeenLocal": dt.datetime.now(DISPLAY_TZ).isoformat(timespec="seconds"),
                "hdfsPartition": "/honeypot/dwd/cleaned_events",
            }
            for meta in HONEYPOTS.values()
        ],
    }


def select_events_by_source_ip(sorted_events, ip_limit, per_ip_limit=3):
    if ip_limit <= 0:
        return []
    selected = []
    selected_ips = set()
    per_ip_counts = collections.Counter()
    for event in sorted_events:
        src_ip = event.get("src_ip") or ""
        if not src_ip:
            continue
        if src_ip not in selected_ips and len(selected_ips) >= ip_limit:
            continue
        if per_ip_counts[src_ip] >= per_ip_limit:
            continue
        selected_ips.add(src_ip)
        per_ip_counts[src_ip] += 1
        selected.append(event)
    return selected


def main():
    args = parse_args()
    output = Path(args.output)
    summary_path = Path(args.summary)
    dashboard_path = Path(args.dashboard)
    output.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    dashboard_path.parent.mkdir(parents=True, exist_ok=True)

    events = []
    counters = collections.Counter()
    event_type_counts = collections.Counter()
    protocol_counts = collections.Counter()
    server_counts = collections.Counter()
    source_ip_counts = collections.Counter()

    for file_path in iter_files(args.input):
        for line in file_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            counters["input_lines"] += 1
            source, obj = load_line(line, file_path)
            if not isinstance(obj, dict):
                counters["parse_errors"] += 1
                continue
            record = normalize_record(source, obj)
            if not is_public_external(record["src_ip"]):
                counters["filtered_ip"] += 1
                continue
            events.append(record)
            counters["cleaned_events"] += 1
            event_type_counts[record["event_type"]] += 1
            protocol_counts[record["protocol"]] += 1
            server_counts[record["server_id"]] += 1
            source_ip_counts[record["src_ip"]] += 1

    counters["geo_enriched_events"] = enrich_geo(events)
    counters["geo_unknown_events"] = sum(1 for event in events if event.get("country") == "unknown" and event.get("city") == "unknown")
    history = build_history_counters(args.history_input) if args.history_input else None

    with output.open("w", encoding="utf-8") as out:
        for record in events:
            out.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")

    summary = {
        **counters,
        "event_type_counts": dict(event_type_counts.most_common()),
        "protocol_counts": dict(protocol_counts.most_common()),
        "server_counts": dict(server_counts.most_common()),
        "top_source_ips": dict(source_ip_counts.most_common(30)),
        "history": history or {},
    }
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    dashboard_path.write_text(json.dumps(build_dashboard(events, summary, args.limit_events, history=history), ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
