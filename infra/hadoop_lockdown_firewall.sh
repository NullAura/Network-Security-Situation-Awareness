#!/usr/bin/env bash
set -euo pipefail

# Restrict Hadoop/YARN service ports to the private Hadoop subnet only.
# SSH is intentionally not managed here to avoid locking out administration.

HADOOP_CIDR="${HADOOP_CIDR:-10.0.129.0/24}"
HADOOP_PUBLIC_SOURCES="${HADOOP_PUBLIC_SOURCES:-203.0.113.20/32 203.0.113.30/32 203.0.113.31/32 203.0.113.32/32}"
HADOOP_PORTS="${HADOOP_PORTS:-8020,8030,8031,8032,8033,8040,8041,8042,8088,9864,9866,9867,9870,13562,19888}"
HADOOP_CHAIN="${HADOOP_CHAIN:-HADOOP_LOCKDOWN}"
ALLOW_CLUSTER_SSH="${ALLOW_CLUSTER_SSH:-1}"

if [ "${ALLOW_CLUSTER_SSH}" = "1" ]; then
  iptables -C INPUT -p tcp -s "${HADOOP_CIDR}" --dport 22 -j ACCEPT 2>/dev/null \
    || iptables -I INPUT 1 -p tcp -s "${HADOOP_CIDR}" --dport 22 -j ACCEPT
  for source in ${HADOOP_PUBLIC_SOURCES}; do
    iptables -C INPUT -p tcp -s "${source}" --dport 22 -j ACCEPT 2>/dev/null \
      || iptables -I INPUT 1 -p tcp -s "${source}" --dport 22 -j ACCEPT
  done
fi

iptables -N "${HADOOP_CHAIN}" 2>/dev/null || true
iptables -F "${HADOOP_CHAIN}"
iptables -A "${HADOOP_CHAIN}" -s 127.0.0.0/8 -j RETURN
iptables -A "${HADOOP_CHAIN}" -s "${HADOOP_CIDR}" -j RETURN
for source in ${HADOOP_PUBLIC_SOURCES}; do
  iptables -A "${HADOOP_CHAIN}" -s "${source}" -j RETURN
done
iptables -A "${HADOOP_CHAIN}" -j DROP

iptables -C INPUT -p tcp -m multiport --dports "${HADOOP_PORTS}" -j "${HADOOP_CHAIN}" 2>/dev/null \
  || iptables -I INPUT 1 -p tcp -m multiport --dports "${HADOOP_PORTS}" -j "${HADOOP_CHAIN}"

if [ "${ENABLE_INGEST_LOCKDOWN:-0}" = "1" ]; then
  INGEST_CHAIN="${INGEST_CHAIN:-HONEYPOT_INGEST_LOCKDOWN}"
  INGEST_PORT="${INGEST_PORT:-9000}"

  iptables -N "${INGEST_CHAIN}" 2>/dev/null || true
  iptables -F "${INGEST_CHAIN}"
  iptables -A "${INGEST_CHAIN}" -s 127.0.0.0/8 -j RETURN
  iptables -A "${INGEST_CHAIN}" -s "${HADOOP_CIDR}" -j RETURN
  iptables -A "${INGEST_CHAIN}" -s 203.0.113.10/32 -j RETURN
  iptables -A "${INGEST_CHAIN}" -s 203.0.113.11/32 -j RETURN
  iptables -A "${INGEST_CHAIN}" -s 203.0.113.12/32 -j RETURN
  iptables -A "${INGEST_CHAIN}" -s 198.51.100.10/32 -j RETURN
  iptables -A "${INGEST_CHAIN}" -j DROP

  iptables -C INPUT -p tcp --dport "${INGEST_PORT}" -j "${INGEST_CHAIN}" 2>/dev/null \
    || iptables -I INPUT 1 -p tcp --dport "${INGEST_PORT}" -j "${INGEST_CHAIN}"
fi
