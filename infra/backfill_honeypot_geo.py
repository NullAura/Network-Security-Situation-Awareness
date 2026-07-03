#!/usr/bin/env python3
import argparse
import collections
import concurrent.futures
import datetime as dt
import ipaddress
import json
import os
import shutil
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


OWN_TEST_IP = "198.51.100.10"
UTC = dt.timezone.utc
EMPTY_VALUES = {"", "-", "unknown", "null", "undefined", None}
GEO_KEYS = ("country", "region", "city", "isp", "asn")
COORD_KEYS = ("longitude", "latitude", "sourceCoordinates")
SKIP_SUFFIXES = (
    ".tmp",
    ".offset",
    ".bak",
    ".backup",
    ".pre-geo.bak",
    ".geo-backfill.bak",
)


def parse_args():
    parser = argparse.ArgumentParser(description="Backfill ipwho.is geolocation into historical honeypot JSONL records.")
    parser.add_argument("--input", nargs="+", required=True, help="JSONL files or directories to scan and update.")
    parser.add_argument("--cache", default="/data/honeypot/geoip_cache.json", help="Geo cache JSON path.")
    parser.add_argument("--backup-dir", default="", help="Directory for original-file backups.")
    parser.add_argument("--report", default="", help="Optional JSON report output path.")
    parser.add_argument("--workers", type=int, default=6, help="Concurrent ipwho.is lookup workers.")
    parser.add_argument("--timeout", type=float, default=8.0, help="Per-IP lookup timeout in seconds.")
    parser.add_argument("--max-lookups", type=int, default=0, help="Maximum new lookups; 0 means unlimited.")
    parser.add_argument("--dry-run", action="store_true", help="Scan and query cache, but do not rewrite files.")
    parser.add_argument("--no-coordinate-refresh", action="store_true", help="Do not refresh known cache entries only to add coordinates.")
    return parser.parse_args()


def now_iso():
    return dt.datetime.now(UTC).isoformat(timespec="seconds")


def is_empty(value):
    if value is None:
        return True
    return str(value).strip().lower() in EMPTY_VALUES


def is_public_external(ip):
    if not ip or ip == OWN_TEST_IP:
        return False
    try:
        return ipaddress.ip_address(str(ip)).is_global
    except ValueError:
        return False


def has_coordinates(item):
    if not isinstance(item, dict):
        return False
    coords = item.get("sourceCoordinates")
    if isinstance(coords, list) and len(coords) == 2:
        try:
            lon = float(coords[0])
            lat = float(coords[1])
            return abs(lon) > 0.0001 or abs(lat) > 0.0001
        except (TypeError, ValueError):
            return False
    try:
        lon = float(item.get("longitude"))
        lat = float(item.get("latitude"))
        return abs(lon) > 0.0001 or abs(lat) > 0.0001
    except (TypeError, ValueError):
        return False


def has_known_geo(item, require_coordinates=True):
    if not isinstance(item, dict):
        return False
    known_text = not is_empty(item.get("country")) or not is_empty(item.get("city"))
    if not known_text:
        return False
    return has_coordinates(item) if require_coordinates else True


def iter_jsonl_files(inputs):
    for raw_path in inputs:
        path = Path(raw_path)
        if path.is_file():
            if should_process_file(path):
                yield path
            continue
        if not path.is_dir():
            continue
        for child in sorted(path.rglob("*")):
            if child.is_file() and should_process_file(child):
                yield child


def should_process_file(path):
    name = path.name
    if any(name.endswith(suffix) for suffix in SKIP_SUFFIXES):
        return False
    return name.endswith((".jsonl", ".log")) or "cowrie.json" in name


def common_input_root(inputs):
    roots = []
    for raw_path in inputs:
        path = Path(raw_path).resolve()
        roots.append(path if path.is_dir() else path.parent)
    if not roots:
        return Path("/").resolve()
    return Path(os.path.commonpath([str(item) for item in roots]))


def read_json_line(line):
    try:
        return json.loads(line)
    except Exception:
        return None


def unwrap_record(outer):
    if isinstance(outer, dict) and isinstance(outer.get("line"), str):
        inner = read_json_line(outer.get("line"))
        if isinstance(inner, dict):
            return inner, True
    if isinstance(outer, dict):
        return outer, False
    return None, False


def source_ip_of(record):
    if not isinstance(record, dict):
        return ""
    for key in ("src_ip", "source_ip", "src_host", "remote_ip"):
        value = record.get(key)
        if not is_empty(value):
            return str(value).strip()
    raw = record.get("raw")
    if isinstance(raw, dict):
        for key in ("src_ip", "source_ip", "src_host", "remote_ip"):
            value = raw.get(key)
            if not is_empty(value):
                return str(value).strip()
    return ""


def load_cache(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_cache(cache, path):
    cache_path = Path(path)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = cache_path.with_suffix(cache_path.suffix + ".tmp")
    tmp.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, cache_path)


def normalize_cache_item(item):
    if not isinstance(item, dict):
        return {}
    normalized = {
        "country": str(item.get("country") or "unknown"),
        "region": str(item.get("region") or item.get("regionName") or "unknown"),
        "city": str(item.get("city") or "unknown"),
        "isp": str(item.get("isp") or item.get("org") or "unknown"),
        "asn": str(item.get("asn") or item.get("as") or "unknown"),
        "cached_at": str(item.get("cached_at") or now_iso()),
        "geo_source": str(item.get("geo_source") or item.get("source") or "cache"),
        "geo_level": str(item.get("geo_level") or "ip"),
    }
    lon = item.get("longitude")
    lat = item.get("latitude")
    coords = item.get("sourceCoordinates")
    if isinstance(coords, list) and len(coords) == 2:
        lon = coords[0]
        lat = coords[1]
    try:
        lon = float(lon)
        lat = float(lat)
        normalized["longitude"] = lon
        normalized["latitude"] = lat
        normalized["sourceCoordinates"] = [lon, lat]
    except (TypeError, ValueError):
        pass
    return normalized


def normalize_ipwho(ip, payload):
    if not isinstance(payload, dict) or not payload.get("success"):
        return {
            "country": "unknown",
            "region": "unknown",
            "city": "unknown",
            "isp": "unknown",
            "asn": "unknown",
            "geo_source": "ipwho.is",
            "geo_level": "unknown",
            "cached_at": now_iso(),
            "lookup_error": str((payload or {}).get("message") or "lookup_failed"),
        }
    connection = payload.get("connection") if isinstance(payload.get("connection"), dict) else {}
    asn_number = connection.get("asn")
    asn_org = connection.get("org") or connection.get("isp") or ""
    if asn_number and asn_org:
        asn = f"AS{asn_number} {asn_org}"
    elif asn_number:
        asn = f"AS{asn_number}"
    else:
        asn = asn_org or "unknown"
    result = {
        "country": str(payload.get("country") or "unknown"),
        "region": str(payload.get("region") or "unknown"),
        "city": str(payload.get("city") or "unknown"),
        "isp": str(connection.get("isp") or connection.get("org") or "unknown"),
        "asn": str(asn),
        "geo_source": "ipwho.is",
        "geo_level": "ip",
        "cached_at": now_iso(),
    }
    try:
        lon = float(payload.get("longitude"))
        lat = float(payload.get("latitude"))
        result["longitude"] = lon
        result["latitude"] = lat
        result["sourceCoordinates"] = [lon, lat]
    except (TypeError, ValueError):
        pass
    return result


def fetch_ipwho(ip, timeout):
    url = "https://ipwho.is/" + urllib.parse.quote(ip, safe="")
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "honeypot-geo-backfill/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8", errors="replace"))
        return ip, normalize_ipwho(ip, payload)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        return ip, normalize_ipwho(ip, {"success": False, "message": str(exc)})


def collect_ips(files, require_coordinates):
    counters = collections.Counter()
    ips = set()
    per_file = {}
    for path in files:
        file_counter = collections.Counter()
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if not line.strip():
                    continue
                counters["lines"] += 1
                file_counter["lines"] += 1
                outer = read_json_line(line)
                record, _wrapped = unwrap_record(outer)
                if not isinstance(record, dict):
                    counters["parse_errors"] += 1
                    file_counter["parse_errors"] += 1
                    continue
                ip = source_ip_of(record)
                if not ip:
                    counters["missing_src_ip"] += 1
                    file_counter["missing_src_ip"] += 1
                    continue
                if not is_public_external(ip):
                    counters["non_external_or_test_ip"] += 1
                    file_counter["non_external_or_test_ip"] += 1
                    continue
                ips.add(ip)
                if has_known_geo(record, require_coordinates=require_coordinates):
                    counters["already_geo"] += 1
                    file_counter["already_geo"] += 1
                else:
                    counters["needs_geo"] += 1
                    file_counter["needs_geo"] += 1
        per_file[str(path)] = dict(file_counter)
    return ips, counters, per_file


def lookup_missing(ips, cache, args):
    require_coordinates = not args.no_coordinate_refresh
    missing = [
        ip for ip in sorted(ips)
        if not has_known_geo(normalize_cache_item(cache.get(ip)), require_coordinates=require_coordinates)
    ]
    if args.max_lookups > 0:
        missing = missing[: args.max_lookups]
    counters = collections.Counter({"cache_hits": len(ips) - len(missing), "lookups_planned": len(missing)})
    if args.dry_run or not missing:
        return counters
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        futures = [pool.submit(fetch_ipwho, ip, args.timeout) for ip in missing]
        for index, future in enumerate(concurrent.futures.as_completed(futures), 1):
            ip, geo = future.result()
            if has_known_geo(geo, require_coordinates=require_coordinates):
                cache[ip] = geo
                counters["lookups_resolved"] += 1
            else:
                existing = normalize_cache_item(cache.get(ip))
                if has_known_geo(existing, require_coordinates=False):
                    counters["lookups_preserved_existing"] += 1
                else:
                    cache[ip] = geo
                counters["lookups_unknown"] += 1
            if index % 100 == 0:
                print(f"lookups {index}/{len(missing)} resolved={counters['lookups_resolved']} unknown={counters['lookups_unknown']}", flush=True)
    return counters


def geo_for_ip(cache, ip):
    geo = normalize_cache_item(cache.get(ip))
    if not geo:
        return {}
    return geo


def apply_geo(record, geo):
    if not isinstance(record, dict) or not geo:
        return False
    changed = False
    for key in GEO_KEYS:
        value = geo.get(key) or "unknown"
        if record.get(key) != value:
            record[key] = value
            changed = True
    for key in ("longitude", "latitude"):
        if key in geo and record.get(key) != geo[key]:
            record[key] = geo[key]
            changed = True
    if "sourceCoordinates" in geo and record.get("sourceCoordinates") != geo["sourceCoordinates"]:
        record["sourceCoordinates"] = geo["sourceCoordinates"]
        changed = True
    for key, value in (("geo_source", geo.get("geo_source") or "ipwho.is"), ("geo_level", geo.get("geo_level") or "ip")):
        if record.get(key) != value:
            record[key] = value
            changed = True
    if record.get("geo_cached") is not True:
        record["geo_cached"] = True
        changed = True
    return changed


def backup_path_for(path, input_root, backup_dir):
    try:
        relative = path.resolve().relative_to(input_root)
    except ValueError:
        relative = Path(str(path).lstrip("/"))
    return backup_dir / relative


def rewrite_file(path, cache, input_root, backup_dir, dry_run):
    counters = collections.Counter()
    changed = False
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    os.close(fd)
    tmp_path = Path(tmp_name)
    try:
        with path.open("r", encoding="utf-8", errors="replace") as source, tmp_path.open("w", encoding="utf-8") as target:
            for line in source:
                if not line.strip():
                    target.write(line)
                    continue
                counters["lines"] += 1
                outer = read_json_line(line)
                record, wrapped = unwrap_record(outer)
                if not isinstance(record, dict):
                    counters["parse_errors"] += 1
                    target.write(line)
                    continue
                ip = source_ip_of(record)
                if not is_public_external(ip):
                    counters["skipped_non_external"] += 1
                    target.write(line)
                    continue
                geo = geo_for_ip(cache, ip)
                if not geo or not has_known_geo(geo, require_coordinates=False):
                    counters["missing_geo_cache"] += 1
                    target.write(line)
                    continue
                if apply_geo(record, geo):
                    counters["updated_records"] += 1
                    changed = True
                if wrapped:
                    outer["line"] = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
                    target.write(json.dumps(outer, ensure_ascii=False, separators=(",", ":")) + "\n")
                else:
                    target.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
        if dry_run or not changed:
            tmp_path.unlink(missing_ok=True)
            return counters
        target_backup = backup_path_for(path, input_root, backup_dir)
        target_backup.parent.mkdir(parents=True, exist_ok=True)
        if not target_backup.exists():
            shutil.copy2(path, target_backup)
        os.replace(tmp_path, path)
        counters["files_rewritten"] = 1
        counters["backup_bytes"] = target_backup.stat().st_size
        return counters
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise


def main():
    args = parse_args()
    files = list(iter_jsonl_files(args.input))
    require_coordinates = not args.no_coordinate_refresh
    cache = {ip: normalize_cache_item(value) for ip, value in load_cache(args.cache).items()}
    ips, scan_counters, per_file = collect_ips(files, require_coordinates=require_coordinates)
    lookup_counters = lookup_missing(ips, cache, args)
    if not args.dry_run:
        save_cache(cache, args.cache)

    input_root = common_input_root(args.input)
    timestamp = dt.datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    backup_dir = Path(args.backup_dir or f"/data/honeypot/backups/geo-backfill/{timestamp}")
    rewrite_counters = collections.Counter()
    for path in files:
        rewrite_counters.update(rewrite_file(path, cache, input_root, backup_dir, args.dry_run))

    report = {
        "generated_at": now_iso(),
        "dry_run": args.dry_run,
        "files": len(files),
        "unique_public_ips": len(ips),
        "cache_path": args.cache,
        "backup_dir": str(backup_dir),
        "scan": dict(scan_counters),
        "lookup": dict(lookup_counters),
        "rewrite": dict(rewrite_counters),
        "per_file": per_file,
    }
    if args.report and not args.dry_run:
        report_path = Path(args.report)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
