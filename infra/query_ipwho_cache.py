#!/usr/bin/env python3
import argparse
import concurrent.futures
import datetime as dt
import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


UTC = dt.timezone.utc


def parse_args():
    parser = argparse.ArgumentParser(description="Resolve an IP list with ipwho.is and write a geo cache shard.")
    parser.add_argument("--ip-list", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--timeout", type=float, default=8.0)
    return parser.parse_args()


def now_iso():
    return dt.datetime.now(UTC).isoformat(timespec="seconds")


def normalize_ipwho(payload):
    if not isinstance(payload, dict) or not payload.get("success"):
        return None
    connection = payload.get("connection") if isinstance(payload.get("connection"), dict) else {}
    asn_number = connection.get("asn")
    asn_org = connection.get("org") or connection.get("isp") or ""
    if asn_number and asn_org:
        asn = f"AS{asn_number} {asn_org}"
    elif asn_number:
        asn = f"AS{asn_number}"
    else:
        asn = asn_org or "unknown"
    item = {
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
        item["longitude"] = lon
        item["latitude"] = lat
        item["sourceCoordinates"] = [lon, lat]
    except (TypeError, ValueError):
        pass
    return item


def fetch(ip, timeout):
    url = "https://ipwho.is/" + urllib.parse.quote(ip, safe="")
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "honeypot-geo-shard/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8", errors="replace"))
        return ip, normalize_ipwho(payload)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return ip, None


def main():
    args = parse_args()
    ips = [line.strip() for line in Path(args.ip_list).read_text(encoding="utf-8").splitlines() if line.strip()]
    results = {}
    failed = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        futures = [pool.submit(fetch, ip, args.timeout) for ip in ips]
        for index, future in enumerate(concurrent.futures.as_completed(futures), 1):
            ip, item = future.result()
            if item:
                results[ip] = item
            else:
                failed.append(ip)
            if index % 100 == 0:
                print(f"resolved {len(results)}/{index} failed={len(failed)}", flush=True)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({"results": results, "failed": failed}, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"input": len(ips), "resolved": len(results), "failed": len(failed), "output": str(output)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
