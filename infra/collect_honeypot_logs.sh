#!/usr/bin/env bash
set -euo pipefail

RUN_DATE="${1:-$(date +%F)}"
BASE_DIR="/data/honeypot/raw"
LOG_DIR="/data/honeypot/logs"
LOG_FILE="$LOG_DIR/collect-${RUN_DATE}-$(date +%H%M%S).log"

mkdir -p \
  "$BASE_DIR/cowrie/$RUN_DATE" \
  "$BASE_DIR/opencanary/$RUN_DATE" \
  "$BASE_DIR/honeypot3/$RUN_DATE" \
  "$LOG_DIR"

run() {
  printf "[%s] %s\n" "$(date '+%F %T')" "$*" | tee -a "$LOG_FILE"
  "$@" 2>&1 | tee -a "$LOG_FILE"
}

run rsync -az --ignore-missing-args bigdata-honeypot-1:/home/cowrie/cowrie/var/log/cowrie/cowrie.json "$BASE_DIR/cowrie/$RUN_DATE/"
run rsync -az --ignore-missing-args bigdata-honeypot-1:/home/cowrie/cowrie/var/log/cowrie/cowrie.json.* "$BASE_DIR/cowrie/$RUN_DATE/"
run rsync -az --ignore-missing-args ctf-47:/var/log/opencanary/opencanary.log "$BASE_DIR/opencanary/$RUN_DATE/"
run rsync -az --ignore-missing-args bigdata-honeypot-3:/var/log/honeypot3/events.jsonl "$BASE_DIR/honeypot3/$RUN_DATE/"

printf "[%s] collection complete\n" "$(date '+%F %T')" | tee -a "$LOG_FILE"
find "$BASE_DIR" -maxdepth 3 -type f -printf "%p %s bytes\n" | sort | tee -a "$LOG_FILE"
