#!/usr/bin/env bash
set -euo pipefail

EXPORT_API_PORT="${EXPORT_API_PORT:-9101}"
EXPORT_API_ALLOWED_SOURCES="${EXPORT_API_ALLOWED_SOURCES:-203.0.113.40/32}"
EXPORT_API_CHAIN="${EXPORT_API_CHAIN:-HDFS_EXPORT_API_LOCKDOWN}"

iptables -N "${EXPORT_API_CHAIN}" 2>/dev/null || true
iptables -F "${EXPORT_API_CHAIN}"
iptables -A "${EXPORT_API_CHAIN}" -s 127.0.0.0/8 -j RETURN
for source in ${EXPORT_API_ALLOWED_SOURCES}; do
  iptables -A "${EXPORT_API_CHAIN}" -s "${source}" -j RETURN
done
iptables -A "${EXPORT_API_CHAIN}" -j DROP

iptables -C INPUT -p tcp --dport "${EXPORT_API_PORT}" -j "${EXPORT_API_CHAIN}" 2>/dev/null \
  || iptables -I INPUT 1 -p tcp --dport "${EXPORT_API_PORT}" -j "${EXPORT_API_CHAIN}"
