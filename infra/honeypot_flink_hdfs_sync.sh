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
export PATH="${PATH}:${HADOOP_HOME}/bin:${HADOOP_HOME}/sbin"

if [ ! -d "${STREAM_DIR}" ]; then
  echo "stream directory not found: ${STREAM_DIR}"
  exit 0
fi

mkdir -p "${CLEAN_DIR}" "${RESULT_DIR}" "${FRONTEND_DIR}"

hdfs dfs -mkdir -p "/honeypot/ods/stream/${RUN_DATE}"
for file in "${STREAM_DIR}"/*.jsonl; do
  [ -f "${file}" ] || continue
  hdfs dfs -put -f "${file}" "/honeypot/ods/stream/${RUN_DATE}/$(basename "${file}")"
done

python3 "${APP_DIR}/preprocess_honeypot_logs.py" \
  --input "${STREAM_DIR}" \
  --output "${CLEAN_DIR}/cleaned_events.jsonl" \
  --summary "${RESULT_DIR}/preprocess_summary.json" \
  --dashboard "${FRONTEND_DIR}/dashboard-flink.json" \
  --limit-events 180 >/dev/null

hdfs dfs -mkdir -p "/honeypot/dwd/cleaned_events/date=${RUN_DATE}"
hdfs dfs -put -f "${CLEAN_DIR}/cleaned_events.jsonl" "/honeypot/dwd/cleaned_events/date=${RUN_DATE}/cleaned_events.jsonl"
hdfs dfs -put -f "${RESULT_DIR}/preprocess_summary.json" "/honeypot/dwd/cleaned_events/date=${RUN_DATE}/preprocess_summary.json"

echo "Flink stream synced to HDFS for ${RUN_DATE}"
