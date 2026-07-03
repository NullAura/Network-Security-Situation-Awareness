#!/usr/bin/env python3
import argparse
import datetime as dt
import os
import subprocess
import sys
import time
from pathlib import Path


def log(message):
    print(f"{dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} {message}", flush=True)


def run(cmd, timeout):
    return subprocess.run(
        cmd,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
    )


def publish_frontend(local_dashboard, frontend_host, frontend_path, timeout):
    if not frontend_host:
        return
    remote_tmp = f"{frontend_path}.tmp"
    run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", f"root@{frontend_host}", "mkdir", "-p", os.path.dirname(frontend_path)], timeout)
    run(["scp", "-q", str(local_dashboard), f"root@{frontend_host}:{remote_tmp}"], timeout)
    run(
        [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=5",
            f"root@{frontend_host}",
            f"mv {remote_tmp} {frontend_path} && chmod 644 {frontend_path}",
        ],
        timeout,
    )


def publish_batch_dashboard(args):
    batch_dashboard = Path(args.batch_dashboard)
    if batch_dashboard.is_file():
        publish_frontend(batch_dashboard, args.frontend_host, args.batch_frontend_path, args.publish_timeout)


def build_once(args):
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    cleaned = output_dir / "cleaned_events.jsonl"
    summary = output_dir / "preprocess_summary.json"
    dashboard = Path(args.dashboard)
    dashboard.parent.mkdir(parents=True, exist_ok=True)
    dashboard_tmp = dashboard.with_suffix(".json.tmp")

    run_date = dt.datetime.now().strftime("%Y-%m-%d")
    inputs = [item.format(date=run_date) for item in args.input]
    history_inputs = [item.format(date=run_date) for item in args.history_input]

    cmd = [
        "python3",
        str(Path(args.app_dir) / "preprocess_honeypot_logs.py"),
        "--input",
        *inputs,
        "--output",
        str(cleaned),
        "--summary",
        str(summary),
        "--dashboard",
        str(dashboard_tmp),
        "--limit-events",
        str(args.limit_events),
    ]
    if history_inputs:
        cmd.extend(["--history-input", *history_inputs])
    result = run(cmd, args.preprocess_timeout)
    os.replace(dashboard_tmp, dashboard)
    publish_frontend(dashboard, args.frontend_host, args.frontend_path, args.publish_timeout)
    publish_batch_dashboard(args)
    last_line = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else "ok"
    log(f"dashboard refreshed: {dashboard} frontend={args.frontend_host or 'disabled'} result={last_line}")


def parse_args():
    parser = argparse.ArgumentParser(description="Refresh the frontend dashboard JSON from real honeypot stream data.")
    parser.add_argument("--app-dir", default="/opt/honeypot-bigdata")
    parser.add_argument("--input", nargs="+", default=["/data/honeypot/stream/{date}"])
    parser.add_argument("--history-input", nargs="+", default=["/data/honeypot/stream"])
    parser.add_argument("--output-dir", default="/data/honeypot/realtime")
    parser.add_argument("--dashboard", default="/data/honeypot/frontend/dashboard.json")
    parser.add_argument("--limit-events", type=int, default=160, help="Maximum source IPs represented in dashboard events.")
    parser.add_argument("--interval", type=float, default=5.0)
    parser.add_argument("--preprocess-timeout", type=float, default=120.0)
    parser.add_argument("--publish-timeout", type=float, default=20.0)
    parser.add_argument("--frontend-host", default="203.0.113.40")
    parser.add_argument("--frontend-path", default="/opt/honeypot-cybermap-frontend/dist/api/dashboard.json")
    parser.add_argument("--batch-dashboard", default="/data/honeypot/frontend/dashboard-batch.json")
    parser.add_argument("--batch-frontend-path", default="/opt/honeypot-cybermap-frontend/dist/api/dashboard-batch.json")
    parser.add_argument("--once", action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()
    while True:
        started = time.monotonic()
        try:
            build_once(args)
        except subprocess.CalledProcessError as exc:
            log(f"refresh failed: command exited {exc.returncode}: {exc.stdout.strip()}")
        except Exception as exc:
            log(f"refresh failed: {exc}")
        if args.once:
            return 0
        elapsed = time.monotonic() - started
        time.sleep(max(0.2, args.interval - elapsed))


if __name__ == "__main__":
    sys.exit(main())
