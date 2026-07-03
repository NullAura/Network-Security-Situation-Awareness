#!/usr/bin/env bash
set -euo pipefail

RUN_DATE="${1:-$(TZ=Asia/Shanghai date +%F)}"
APP_DIR="${APP_DIR:-/opt/honeypot-bigdata}"
LOCAL_BASE="${LOCAL_BASE:-/data/honeypot}"
STREAM_DIR="${LOCAL_BASE}/stream/${RUN_DATE}"
CLEAN_DIR="${LOCAL_BASE}/cleaned/${RUN_DATE}"
RESULT_DIR="${LOCAL_BASE}/results/${RUN_DATE}"
FRONTEND_DIR="${LOCAL_BASE}/frontend"

export JAVA_HOME="${JAVA_HOME:-$(dirname "$(dirname "$(readlink -f "$(command -v java)")")")}"
export HADOOP_HOME="${HADOOP_HOME:-/opt/hadoop}"
export HADOOP_CONF_DIR="${HADOOP_CONF_DIR:-${HADOOP_HOME}/etc/hadoop}"
export HADOOP_CLIENT_OPTS="${HADOOP_CLIENT_OPTS:--Xmx128m}"
export HADOOP_USER_NAME="${HADOOP_USER_NAME:-hadoop}"
export PATH="${PATH}:${HADOOP_HOME}/bin:${HADOOP_HOME}/sbin"

if [ ! -d "${STREAM_DIR}" ]; then
  echo "stream directory not found: ${STREAM_DIR}"
  exit 0
fi

mkdir -p "${CLEAN_DIR}" "${RESULT_DIR}" "${FRONTEND_DIR}"

put_hdfs_atomic() {
  local src="$1"
  local dst="$2"
  local tmp="${dst}.tmp.$(date +%s).$$"

  hdfs dfs -rm -f "${tmp}" >/dev/null 2>&1 || true
  hdfs dfs -put -f "${src}" "${tmp}"
  hdfs dfs -rm -f "${dst}" >/dev/null 2>&1 || true
  hdfs dfs -mv "${tmp}" "${dst}"
}

sync_growing_jsonl() {
  local src="$1"
  local dst="$2"
  local local_size
  local remote_size

  local_size="$(stat -c '%s' "${src}")"
  remote_size="$(hdfs dfs -stat '%b' "${dst}" 2>/dev/null || printf '%s' -1)"

  if [ "${remote_size}" -lt 0 ] || [ "${local_size}" -lt "${remote_size}" ]; then
    put_hdfs_atomic "${src}" "${dst}"
    return
  fi

  if [ "${local_size}" -eq "${remote_size}" ]; then
    return
  fi

  tail -c +"$((remote_size + 1))" "${src}" | hdfs dfs -appendToFile - "${dst}" || put_hdfs_atomic "${src}" "${dst}"
}

hdfs dfs -mkdir -p "/honeypot/ods/stream/${RUN_DATE}"
hdfs dfs -rm -f "/honeypot/ods/stream/${RUN_DATE}/"*.tmp.* >/dev/null 2>&1 || true
for file in "${STREAM_DIR}"/*.jsonl; do
  [ -f "${file}" ] || continue
  sync_growing_jsonl "${file}" "/honeypot/ods/stream/${RUN_DATE}/$(basename "${file}")"
done

python3 "${APP_DIR}/preprocess_honeypot_logs.py" \
  --input "${STREAM_DIR}" \
  --output "${CLEAN_DIR}/cleaned_events.jsonl" \
  --summary "${RESULT_DIR}/preprocess_summary.json" \
  --dashboard "${FRONTEND_DIR}/dashboard-flink.json" \
  --limit-events 180 >/dev/null

hdfs dfs -mkdir -p "/honeypot/dwd/cleaned_events/date=${RUN_DATE}"
put_hdfs_atomic "${CLEAN_DIR}/cleaned_events.jsonl" "/honeypot/dwd/cleaned_events/date=${RUN_DATE}/cleaned_events.jsonl"
put_hdfs_atomic "${RESULT_DIR}/preprocess_summary.json" "/honeypot/dwd/cleaned_events/date=${RUN_DATE}/preprocess_summary.json"

if id hadoop >/dev/null 2>&1; then
  chown -R hadoop:hadoop "${CLEAN_DIR}" "${RESULT_DIR}" "${FRONTEND_DIR}" || true
fi

echo "Flink stream synced to HDFS for ${RUN_DATE}"
