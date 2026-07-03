#!/usr/bin/env bash
set -euo pipefail

RUN_DATE="${1:-$(date +%F)}"
INCLUDE_RAW="${INCLUDE_RAW:-0}"
APP_DIR="/opt/honeypot-bigdata"
LOCAL_BASE="/data/honeypot"
CLEAN_DIR="${LOCAL_BASE}/cleaned/${RUN_DATE}"
RESULT_DIR="${LOCAL_BASE}/results/${RUN_DATE}"
FRONTEND_DIR="${LOCAL_BASE}/frontend"
BATCH_DASHBOARD="${RESULT_DIR}/dashboard.json"
HADOOP_HOME="${HADOOP_HOME:-/opt/hadoop}"
STREAMING_JAR="$(ls "${HADOOP_HOME}"/share/hadoop/tools/lib/hadoop-streaming-*.jar | head -1)"

export JAVA_HOME="${JAVA_HOME:-$(dirname "$(dirname "$(readlink -f "$(command -v java)")")")}"
export HADOOP_HOME
export HADOOP_CONF_DIR="${HADOOP_HOME}/etc/hadoop"
export PATH="${PATH}:${HADOOP_HOME}/bin:${HADOOP_HOME}/sbin"
export HDFS_NAMENODE_USER=root
export HDFS_DATANODE_USER=root
export HDFS_SECONDARYNAMENODE_USER=root
export YARN_RESOURCEMANAGER_USER=root
export YARN_NODEMANAGER_USER=root

mkdir -p "${CLEAN_DIR}" "${RESULT_DIR}" "${FRONTEND_DIR}"

if ! hdfs dfs -test -d / >/dev/null 2>&1; then
  start-dfs.sh || true
  start-yarn.sh || true
fi

PREPROCESS_INPUTS=()
if [ -d "${LOCAL_BASE}/stream/${RUN_DATE}" ]; then
  PREPROCESS_INPUTS+=("${LOCAL_BASE}/stream/${RUN_DATE}")
else
  PREPROCESS_INPUTS+=("${LOCAL_BASE}/stream")
fi
if [ "${INCLUDE_RAW}" = "1" ] && [ -d "${LOCAL_BASE}/raw" ]; then
  PREPROCESS_INPUTS+=("${LOCAL_BASE}/raw")
fi

python3 "${APP_DIR}/preprocess_honeypot_logs.py" \
  --input "${PREPROCESS_INPUTS[@]}" \
  --output "${CLEAN_DIR}/cleaned_events.jsonl" \
  --summary "${RESULT_DIR}/preprocess_summary.json" \
  --dashboard "${BATCH_DASHBOARD}"

hdfs dfs -mkdir -p /honeypot/ods /honeypot/dwd /honeypot/dws
hdfs dfs -rm -r -f "/honeypot/ods/stream/${RUN_DATE}" >/dev/null 2>&1 || true
if [ -d "${LOCAL_BASE}/stream/${RUN_DATE}" ]; then
  hdfs dfs -mkdir -p /honeypot/ods/stream
  hdfs dfs -put "${LOCAL_BASE}/stream/${RUN_DATE}" /honeypot/ods/stream/
fi

if [ "${INCLUDE_RAW}" = "1" ] && [ -d "${LOCAL_BASE}/raw" ]; then
  hdfs dfs -rm -r -f /honeypot/ods/raw >/dev/null 2>&1 || true
  hdfs dfs -put "${LOCAL_BASE}/raw" /honeypot/ods/raw
fi

hdfs dfs -rm -r -f "/honeypot/dwd/cleaned_events/date=${RUN_DATE}" >/dev/null 2>&1 || true
hdfs dfs -mkdir -p "/honeypot/dwd/cleaned_events/date=${RUN_DATE}"
hdfs dfs -put -f "${CLEAN_DIR}/cleaned_events.jsonl" "/honeypot/dwd/cleaned_events/date=${RUN_DATE}/"

run_all_stats_job() {
  local output="/honeypot/dws/all_stats/date=${RUN_DATE}"
  hdfs dfs -rm -r -f "${output}" >/dev/null 2>&1 || true
  hadoop jar "${STREAMING_JAR}" \
    -D mapreduce.job.name="honeypot-all-stats-${RUN_DATE}" \
    -files "${APP_DIR}/mr_count_mapper.py,${APP_DIR}/mr_sum_reducer.py" \
    -mapper "python3 mr_count_mapper.py all" \
    -reducer "python3 mr_sum_reducer.py" \
    -input "/honeypot/dwd/cleaned_events/date=${RUN_DATE}/cleaned_events.jsonl" \
    -output "${output}"
  hdfs dfs -getmerge "${output}" "${RESULT_DIR}/all_stats.tsv"
}

publish_metric() {
  local name="$2"
  local output="/honeypot/dws/${name}/date=${RUN_DATE}"
  rm -f "${RESULT_DIR}/.${name}.tsv.crc" "${RESULT_DIR}/${name}.tsv.crc"
  awk -F $'\t' -v metric="${name}" '$1 == metric { print $2 "\t" $3 }' "${RESULT_DIR}/all_stats.tsv" \
    | sort -t $'\t' -k2,2nr > "${RESULT_DIR}/${name}.tsv"
  rm -f "${RESULT_DIR}/.${name}.tsv.crc" "${RESULT_DIR}/${name}.tsv.crc"
  hdfs dfs -rm -r -f "${output}" >/dev/null 2>&1 || true
  hdfs dfs -mkdir -p "${output}"
  hdfs dfs -put -f "${RESULT_DIR}/${name}.tsv" "${output}/part-00000"
  hdfs dfs -touchz "${output}/_SUCCESS"
}

run_count_job() {
  local field="$1"
  local name="$2"
  local output="/honeypot/dws/${name}/date=${RUN_DATE}"
  hdfs dfs -rm -r -f "${output}" >/dev/null 2>&1 || true
  hadoop jar "${STREAMING_JAR}" \
    -D mapreduce.job.name="honeypot-${name}-${RUN_DATE}" \
    -files "${APP_DIR}/mr_count_mapper.py,${APP_DIR}/mr_sum_reducer.py" \
    -mapper "python3 mr_count_mapper.py ${field}" \
    -reducer "python3 mr_sum_reducer.py" \
    -input "/honeypot/dwd/cleaned_events/date=${RUN_DATE}/cleaned_events.jsonl" \
    -output "${output}"
  hdfs dfs -getmerge "${output}" "${RESULT_DIR}/${name}.tsv"
  sort -t $'\t' -k2,2nr "${RESULT_DIR}/${name}.tsv" -o "${RESULT_DIR}/${name}.tsv"
}

run_all_stats_job
publish_metric all protocol_stats
publish_metric all source_ip_topn
publish_metric all event_type_stats
publish_metric all server_stats
publish_metric all hourly_trend

cat >"${RESULT_DIR}/hdfs_paths.txt" <<EOF
/honeypot/ods/stream/${RUN_DATE}
/honeypot/ods/raw
/honeypot/dwd/cleaned_events/date=${RUN_DATE}
/honeypot/dws/protocol_stats/date=${RUN_DATE}
/honeypot/dws/source_ip_topn/date=${RUN_DATE}
/honeypot/dws/event_type_stats/date=${RUN_DATE}
/honeypot/dws/server_stats/date=${RUN_DATE}
/honeypot/dws/hourly_trend/date=${RUN_DATE}
EOF

cp "${BATCH_DASHBOARD}" "${FRONTEND_DIR}/dashboard-batch.json"

FRONTEND_DEPLOY_TARGET="${FRONTEND_DEPLOY_TARGET:-}"
if [[ -n "${FRONTEND_DEPLOY_TARGET}" ]] && ssh -o BatchMode=yes -o ConnectTimeout=5 "${FRONTEND_DEPLOY_TARGET}" 'true' >/dev/null 2>&1; then
  ssh "${FRONTEND_DEPLOY_TARGET}" 'mkdir -p /opt/honeypot-cybermap-frontend/dist/api'
  scp "${BATCH_DASHBOARD}" "${FRONTEND_DEPLOY_TARGET}:/opt/honeypot-cybermap-frontend/dist/api/dashboard-batch.json"
else
  echo "Batch dashboard saved locally for publisher: ${FRONTEND_DIR}/dashboard-batch.json"
fi

echo "Pipeline complete for ${RUN_DATE}"
echo "Cleaned events: ${CLEAN_DIR}/cleaned_events.jsonl"
echo "Results: ${RESULT_DIR}"
echo "Batch dashboard: ${BATCH_DASHBOARD}"
hdfs dfs -ls -R /honeypot | tail -80
