#!/usr/bin/env python3
import argparse
import datetime as dt
import json
import os
import signal
import sys
import time
from pathlib import Path

from kafka import KafkaConsumer


TOPIC_SOURCES = {
    "honeypot_cowrie_clean": {
        "source": "203.0.113.10",
        "path": "/var/log/honeypot-preprocessed/events.jsonl",
    },
    "honeypot_opencanary_clean": {
        "source": "203.0.113.11",
        "path": "/var/log/honeypot-preprocessed/events.jsonl",
    },
    "honeypot3_clean": {
        "source": "203.0.113.12",
        "path": "/var/log/honeypot-preprocessed/events.jsonl",
    },
}


stop_requested = False


def handle_signal(_signum, _frame):
    global stop_requested
    stop_requested = True


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")


def day_string():
    return dt.datetime.now().strftime("%Y-%m-%d")


def log(message):
    print(f"{dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} {message}", flush=True)


def safe_source(value):
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-."
    cleaned = "".join(ch for ch in str(value or "unknown") if ch in allowed)
    return cleaned or "unknown"


def decode_message(value):
    if value is None:
        return ""
    return value.decode("utf-8", errors="replace").rstrip("\r\n")


def target_file(data_dir, source):
    day_dir = Path(data_dir) / day_string()
    day_dir.mkdir(parents=True, exist_ok=True)
    return day_dir / f"{safe_source(source)}.jsonl"


def build_record(message, source_info):
    source = source_info["source"]
    line = decode_message(message.value)
    return {
        "received_at": utc_now(),
        "source": source,
        "source_ip": source,
        "path": source_info.get("path", ""),
        "sent_at": "",
        "line": line,
        "kafka_topic": message.topic,
        "kafka_partition": message.partition,
        "kafka_offset": message.offset,
        "kafka_timestamp": message.timestamp,
    }


def append_records(data_dir, messages):
    grouped = {}
    for message in messages:
        source_info = TOPIC_SOURCES.get(message.topic)
        if not source_info:
            log(f"skip unknown topic={message.topic}")
            continue
        record = build_record(message, source_info)
        if not record["line"].strip():
            continue
        grouped.setdefault(source_info["source"], []).append(record)

    written = 0
    for source, records in grouped.items():
        path = target_file(data_dir, source)
        with path.open("a", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
                written += 1
    return written


def parse_args():
    parser = argparse.ArgumentParser(description="Consume raw honeypot Kafka topics and append stream JSONL records.")
    parser.add_argument("--bootstrap-server", default="127.0.0.1:9092")
    parser.add_argument("--topic", action="append", default=[])
    parser.add_argument("--group-id", default="honeypot-stream-writer")
    parser.add_argument("--data-dir", default="/data/honeypot/stream")
    parser.add_argument("--auto-offset-reset", default="latest", choices=["latest", "earliest"])
    parser.add_argument("--poll-timeout-ms", type=int, default=1000)
    parser.add_argument("--max-records", type=int, default=500)
    return parser.parse_args()


def main():
    args = parse_args()
    topics = args.topic or list(TOPIC_SOURCES)
    Path(args.data_dir).mkdir(parents=True, exist_ok=True)
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    consumer = KafkaConsumer(
        *topics,
        bootstrap_servers=args.bootstrap_server,
        group_id=args.group_id,
        auto_offset_reset=args.auto_offset_reset,
        enable_auto_commit=False,
        value_deserializer=None,
        consumer_timeout_ms=1000,
    )
    log(f"consumer started bootstrap={args.bootstrap_server} topics={','.join(topics)} data_dir={args.data_dir}")

    total = 0
    last_report = time.monotonic()
    try:
        while not stop_requested:
            batch = []
            records = consumer.poll(timeout_ms=args.poll_timeout_ms, max_records=args.max_records)
            for messages in records.values():
                batch.extend(messages)
            if not batch:
                continue
            written = append_records(args.data_dir, batch)
            if written:
                consumer.commit()
                total += written
            now = time.monotonic()
            if now - last_report >= 10:
                log(f"written={written} total={total}")
                last_report = now
    finally:
        try:
            consumer.close()
        except Exception:
            pass
        log(f"consumer stopped total={total}")


if __name__ == "__main__":
    sys.exit(main())
