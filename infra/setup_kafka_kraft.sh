#!/usr/bin/env bash
set -euo pipefail

KAFKA_VERSION="${KAFKA_VERSION:-3.7.2}"
KAFKA_SCALA="${KAFKA_SCALA:-2.13}"
KAFKA_ARCHIVE="kafka_${KAFKA_SCALA}-${KAFKA_VERSION}.tgz"
KAFKA_URL="${KAFKA_URL:-https://archive.apache.org/dist/kafka/${KAFKA_VERSION}/${KAFKA_ARCHIVE}}"
KAFKA_HOME="${KAFKA_HOME:-/opt/kafka}"
KAFKA_DATA="${KAFKA_DATA:-/data/kafka}"
KAFKA_ADVERTISED_HOST="${KAFKA_ADVERTISED_HOST:-203.0.113.20}"

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y openjdk-17-jre-headless curl tar python3-venv iptables

mkdir -p /opt "${KAFKA_DATA}" /etc/kafka
cd /tmp
if [ ! -f "${KAFKA_ARCHIVE}" ]; then
  curl -fL "${KAFKA_URL}" -o "${KAFKA_ARCHIVE}"
fi
if ! tar -tzf "${KAFKA_ARCHIVE}" >/dev/null 2>&1; then
  rm -f "${KAFKA_ARCHIVE}"
  curl -fL "${KAFKA_URL}" -o "${KAFKA_ARCHIVE}"
  tar -tzf "${KAFKA_ARCHIVE}" >/dev/null
fi

rm -rf "/tmp/kafka_${KAFKA_SCALA}-${KAFKA_VERSION}" "${KAFKA_HOME}"
tar -xzf "${KAFKA_ARCHIVE}" -C /tmp
mv "/tmp/kafka_${KAFKA_SCALA}-${KAFKA_VERSION}" "${KAFKA_HOME}"

cat > /etc/kafka/server.properties <<EOF
process.roles=broker,controller
node.id=1
controller.quorum.voters=1@127.0.0.1:9093
listeners=PLAINTEXT://0.0.0.0:9092,CONTROLLER://127.0.0.1:9093
advertised.listeners=PLAINTEXT://${KAFKA_ADVERTISED_HOST}:9092
controller.listener.names=CONTROLLER
listener.security.protocol.map=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT
inter.broker.listener.name=PLAINTEXT
log.dirs=${KAFKA_DATA}/kraft-combined-logs
num.partitions=3
offsets.topic.replication.factor=1
transaction.state.log.replication.factor=1
transaction.state.log.min.isr=1
group.initial.rebalance.delay.ms=0
auto.create.topics.enable=false
log.retention.hours=72
log.segment.bytes=1073741824
EOF

if [ ! -f "${KAFKA_DATA}/kraft-combined-logs/meta.properties" ]; then
  CLUSTER_ID="$("${KAFKA_HOME}/bin/kafka-storage.sh" random-uuid)"
  "${KAFKA_HOME}/bin/kafka-storage.sh" format -t "${CLUSTER_ID}" -c /etc/kafka/server.properties
fi

cat > /etc/systemd/system/kafka.service <<EOF
[Unit]
Description=Apache Kafka KRaft broker for honeypot logs
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
Environment=JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
Environment="KAFKA_HEAP_OPTS=-Xms256m -Xmx512m"
ExecStart=${KAFKA_HOME}/bin/kafka-server-start.sh /etc/kafka/server.properties
ExecStop=${KAFKA_HOME}/bin/kafka-server-stop.sh
Restart=always
RestartSec=5
LimitNOFILE=100000

[Install]
WantedBy=multi-user.target
EOF

cat > /usr/local/sbin/honeypot-kafka-firewall.sh <<EOF
#!/usr/bin/env bash
set -euo pipefail

CHAIN=HONEYPOT_KAFKA_LOCKDOWN
iptables -w 10 -N "\${CHAIN}" 2>/dev/null || true
iptables -w 10 -F "\${CHAIN}"

PRIVATE_IP=\$(hostname -I | awk '{print \$1}')
for ip in 127.0.0.0/8 "\${PRIVATE_IP}/32" ${KAFKA_ADVERTISED_HOST}/32 203.0.113.10/32 203.0.113.11/32 203.0.113.12/32 203.0.113.30/32; do
  [ -n "\${ip}" ] || continue
  iptables -w 10 -A "\${CHAIN}" -p tcp -s "\${ip}" --dport 9092 -j ACCEPT
done

iptables -w 10 -A "\${CHAIN}" -p tcp --dport 9092 -j DROP
iptables -w 10 -C INPUT -p tcp --dport 9092 -j "\${CHAIN}" 2>/dev/null \
  || iptables -w 10 -I INPUT 1 -p tcp --dport 9092 -j "\${CHAIN}"
EOF
chmod 0755 /usr/local/sbin/honeypot-kafka-firewall.sh

cat > /etc/systemd/system/honeypot-kafka-firewall.service <<EOF
[Unit]
Description=Apply Kafka 9092 whitelist for honeypot log ingestion
Before=kafka.service
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/honeypot-kafka-firewall.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now honeypot-kafka-firewall.service
systemctl enable --now kafka.service
sleep 5
systemctl is-active kafka.service

for topic in honeypot_cowrie_raw honeypot_opencanary_raw honeypot3_raw honeypot_raw_logs; do
  "${KAFKA_HOME}/bin/kafka-topics.sh" --bootstrap-server "${KAFKA_ADVERTISED_HOST}:9092" --create --if-not-exists --topic "${topic}" --partitions 3 --replication-factor 1
done
"${KAFKA_HOME}/bin/kafka-topics.sh" --bootstrap-server "${KAFKA_ADVERTISED_HOST}:9092" --list
