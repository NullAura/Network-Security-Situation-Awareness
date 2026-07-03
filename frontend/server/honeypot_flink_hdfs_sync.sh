#!/usr/bin/env bash
set -euo pipefail

RUN_DATE="${1:-$(TZ=Asia/Shanghai date +%F)}"
APP_DIR="${APP_DIR:-/opt/honeypot-bigdata}"
LOCAL_BASE="${LOCAL_BASE:-/data/honeypot}"
STREAM_DIR="${LOCAL_BASE}/stream/${RUN_DATE}"
CLEAN_DIR="${LOCAL_BASE}/cleaned/${RUN_DATE}"
RESULT_DIR="${LOCAL_BASE}/results/${RUN_DATE}"
FRONTEND_DIR="${LOCAL_BASE}/frontend"
PUBLISH_FRONTEND_HOST="${PUBLISH_FRONTEND_HOST:-47.103.220.68}"
PUBLISH_FRONTEND_API_DIR="${PUBLISH_FRONTEND_API_DIR:-/opt/honeypot-cybermap-frontend/dist/api}"
PUBLISH_FRONTEND_TIMEOUT="${PUBLISH_FRONTEND_TIMEOUT:-20}"

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

publish_frontend_snapshot() {
  [ -n "${PUBLISH_FRONTEND_HOST}" ] || return 0
  [ -s "${FRONTEND_DIR}/dashboard-flink.json" ] || return 0

  local remote_tmp="${PUBLISH_FRONTEND_API_DIR}/dashboard-flink.json.tmp"
  local ssh_opts=(
    -o BatchMode=yes
    -o ConnectTimeout=5
    -o ControlMaster=auto
    -o ControlPersist=60
    -o ControlPath=/tmp/honeypot-hdfs-sync-%r@%h:%p
  )

  timeout "${PUBLISH_FRONTEND_TIMEOUT}" \
    ssh "${ssh_opts[@]}" "root@${PUBLISH_FRONTEND_HOST}" "mkdir -p '${PUBLISH_FRONTEND_API_DIR}'"
  timeout "${PUBLISH_FRONTEND_TIMEOUT}" \
    scp -q "${ssh_opts[@]}" "${FRONTEND_DIR}/dashboard-flink.json" "root@${PUBLISH_FRONTEND_HOST}:${remote_tmp}"
  timeout "${PUBLISH_FRONTEND_TIMEOUT}" \
    ssh "${ssh_opts[@]}" "root@${PUBLISH_FRONTEND_HOST}" "API_DIR='${PUBLISH_FRONTEND_API_DIR}' python3 - <<'PY'
import json
import os
import shutil

api_dir = os.environ['API_DIR']
base_path = os.path.join(api_dir, 'dashboard.json')
flink_tmp_path = os.path.join(api_dir, 'dashboard-flink.json.tmp')
flink_path = os.path.join(api_dir, 'dashboard-flink.json')
out_path = os.path.join(api_dir, 'dashboard.json.tmp')
backup_path = os.path.join(api_dir, 'dashboard.json.bak-before-hdfs-sync-merge')

with open(flink_tmp_path, encoding='utf-8') as handle:
    flink = json.load(handle)

base = {}
if os.path.exists(base_path):
    with open(base_path, encoding='utf-8') as handle:
        base = json.load(handle)
    if not os.path.exists(backup_path):
        shutil.copy2(base_path, backup_path)

merged = dict(base) if isinstance(base, dict) and base else dict(flink)
for key in ('events', 'sources', 'honeypots', 'ingestStatus'):
    value = flink.get(key)
    if isinstance(value, list) and value:
        merged[key] = value
for key in ('generatedAt', 'generatedAtLocal'):
    if flink.get(key):
        merged[key] = flink[key]
for key in ('stats', 'attackMethods', 'protocols', 'historyTrend', 'historyStats'):
    if not merged.get(key) and flink.get(key):
        merged[key] = flink[key]

with open(out_path, 'w', encoding='utf-8') as handle:
    json.dump(merged, handle, ensure_ascii=False, separators=(',', ':'))
os.replace(flink_tmp_path, flink_path)
os.replace(out_path, base_path)
os.chmod(flink_path, 0o644)
os.chmod(base_path, 0o644)
PY"
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

publish_frontend_snapshot || echo "frontend dashboard publish failed"

echo "Flink stream synced to HDFS for ${RUN_DATE}"
