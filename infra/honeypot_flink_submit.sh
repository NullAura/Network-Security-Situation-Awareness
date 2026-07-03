#!/usr/bin/env bash
set -euo pipefail

FLINK_HOME="${FLINK_HOME:-/opt/flink}"
JAR_PATH="${JAR_PATH:-/opt/honeypot-flink/honeypot-flink-stream.jar}"
JOB_CLASS="${JOB_CLASS:-edu.bigdata.honeypot.HoneypotFlinkStreamJob}"
JOB_NAME="${JOB_NAME:-honeypot-flink-stream}"
BOOTSTRAP_SERVER="${BOOTSTRAP_SERVER:-203.0.113.20:9092}"
DATA_DIR="${DATA_DIR:-/data/honeypot/stream}"
GROUP_ID="${GROUP_ID:-honeypot-flink-stream-writer}"
AUTO_OFFSET_RESET="${AUTO_OFFSET_RESET:-latest}"
TIMEZONE="${TIMEZONE:-Asia/Shanghai}"

export JAVA_HOME="${JAVA_HOME:-$(dirname "$(dirname "$(readlink -f "$(command -v java)")")")}"

running_job_ids() {
  "${FLINK_HOME}/bin/flink" list -r 2>/dev/null \
    | awk -v name="${JOB_NAME}" '$0 ~ name { print $4 }' \
    | tr -d ':'
}

case "${1:-start}" in
  start)
    if running_job_ids | grep -q .; then
      echo "${JOB_NAME} already running"
      exit 0
    fi
    "${FLINK_HOME}/bin/flink" run -d \
      -c "${JOB_CLASS}" \
      "${JAR_PATH}" \
      --bootstrap-server "${BOOTSTRAP_SERVER}" \
      --group-id "${GROUP_ID}" \
      --data-dir "${DATA_DIR}" \
      --auto-offset-reset "${AUTO_OFFSET_RESET}" \
      --timezone "${TIMEZONE}"
    ;;
  stop|cancel)
    ids="$(running_job_ids || true)"
    if [ -z "${ids}" ]; then
      echo "${JOB_NAME} is not running"
      exit 0
    fi
    for job_id in ${ids}; do
      "${FLINK_HOME}/bin/flink" cancel "${job_id}" || true
    done
    ;;
  status)
    "${FLINK_HOME}/bin/flink" list -r
    ;;
  *)
    echo "usage: $0 {start|stop|cancel|status}" >&2
    exit 2
    ;;
esac
