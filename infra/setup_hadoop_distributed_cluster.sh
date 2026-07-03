#!/usr/bin/env bash
set -euo pipefail

HADOOP_VERSION="${HADOOP_VERSION:-3.4.1}"
HADOOP_ARCHIVE="hadoop-${HADOOP_VERSION}.tar.gz"
HADOOP_URL="${HADOOP_URL:-https://mirrors.aliyun.com/apache/hadoop/common/hadoop-${HADOOP_VERSION}/${HADOOP_ARCHIVE}}"
HADOOP_HOME="${HADOOP_HOME:-/opt/hadoop}"
HADOOP_DATA="${HADOOP_DATA:-/data/hadoop}"
HADOOP_USER="${HADOOP_USER:-hadoop}"

MASTER_NAME="hadoop-master"
MASTER_IP="203.0.113.30"
WORKER_1_NAME="hadoop-worker-2"
WORKER_1_IP="203.0.113.31"
WORKER_2_NAME="hadoop-worker-3"
WORKER_2_IP="203.0.113.32"

NODES=("${MASTER_IP}" "${WORKER_1_IP}" "${WORKER_2_IP}")
WORKERS=("${MASTER_NAME}" "${WORKER_1_NAME}" "${WORKER_2_NAME}")

ssh_root() {
  local host="$1"
  shift
  ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "root@${host}" "$@"
}

copy_to_root() {
  local src="$1"
  local host="$2"
  local dest="$3"
  scp -q -o BatchMode=yes -o StrictHostKeyChecking=accept-new "${src}" "root@${host}:${dest}"
}

configure_hosts_file() {
  local host="$1"
  ssh_root "${host}" "sed -i '/# HONEYPOT HADOOP CLUSTER START/,/# HONEYPOT HADOOP CLUSTER END/d' /etc/hosts && cat >> /etc/hosts <<'EOF'
# HONEYPOT HADOOP CLUSTER START
${MASTER_IP} ${MASTER_NAME}
${WORKER_1_IP} ${WORKER_1_NAME}
${WORKER_2_IP} ${WORKER_2_NAME}
# HONEYPOT HADOOP CLUSTER END
EOF"
}

prepare_node() {
  local host="$1"
  ssh_root "${host}" "set -e
while fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock >/dev/null 2>&1; do
  echo 'waiting for apt/dpkg lock on ${host}...'
  sleep 5
done
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y openjdk-17-jdk-headless curl openssh-server rsync procps
id ${HADOOP_USER} >/dev/null 2>&1 || useradd -m -s /bin/bash ${HADOOP_USER}
mkdir -p ${HADOOP_DATA}/tmp ${HADOOP_DATA}/hdfs/namenode ${HADOOP_DATA}/hdfs/datanode ${HADOOP_HOME}
chown -R ${HADOOP_USER}:${HADOOP_USER} ${HADOOP_DATA}
mkdir -p /home/${HADOOP_USER}/.ssh
chmod 700 /home/${HADOOP_USER}/.ssh
touch /home/${HADOOP_USER}/.ssh/authorized_keys /home/${HADOOP_USER}/.ssh/known_hosts
chown -R ${HADOOP_USER}:${HADOOP_USER} /home/${HADOOP_USER}/.ssh
chmod 600 /home/${HADOOP_USER}/.ssh/authorized_keys /home/${HADOOP_USER}/.ssh/known_hosts
"
}

install_hadoop_on_master() {
  mkdir -p /tmp
  cd /tmp
  if [ ! -f "${HADOOP_ARCHIVE}" ]; then
    curl -fL "${HADOOP_URL}" -o "${HADOOP_ARCHIVE}"
  else
    curl -fL -C - "${HADOOP_URL}" -o "${HADOOP_ARCHIVE}"
  fi
  if ! tar -tzf "${HADOOP_ARCHIVE}" >/dev/null 2>&1; then
    rm -f "${HADOOP_ARCHIVE}"
    curl -fL "${HADOOP_URL}" -o "${HADOOP_ARCHIVE}"
    tar -tzf "${HADOOP_ARCHIVE}" >/dev/null
  fi
  rm -rf "/tmp/hadoop-${HADOOP_VERSION}" "${HADOOP_HOME}"
  tar -xzf "${HADOOP_ARCHIVE}" -C /tmp
  mv "/tmp/hadoop-${HADOOP_VERSION}" "${HADOOP_HOME}"
  chown -R "${HADOOP_USER}:${HADOOP_USER}" "${HADOOP_HOME}"
}

write_hadoop_config() {
  local java_home
  java_home="$(dirname "$(dirname "$(readlink -f "$(command -v java)")")")"

  cat >/etc/profile.d/hadoop.sh <<EOF
export JAVA_HOME=${java_home}
export HADOOP_HOME=${HADOOP_HOME}
export HADOOP_CONF_DIR=${HADOOP_HOME}/etc/hadoop
export PATH=\$PATH:${HADOOP_HOME}/bin:${HADOOP_HOME}/sbin
EOF

cat >"${HADOOP_HOME}/etc/hadoop/hadoop-env.sh" <<EOF
export JAVA_HOME=${java_home}
export HADOOP_HOME=${HADOOP_HOME}
export HADOOP_CONF_DIR=${HADOOP_HOME}/etc/hadoop
export HADOOP_LOG_DIR=${HADOOP_HOME}/logs
export HADOOP_OPTS="\${HADOOP_OPTS:-} --add-opens=java.base/java.lang=ALL-UNNAMED"
export YARN_RESOURCEMANAGER_OPTS="\${YARN_RESOURCEMANAGER_OPTS:-} --add-opens=java.base/java.lang=ALL-UNNAMED"
export YARN_NODEMANAGER_OPTS="\${YARN_NODEMANAGER_OPTS:-} --add-opens=java.base/java.lang=ALL-UNNAMED"
EOF

  cat >"${HADOOP_HOME}/etc/hadoop/core-site.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <property>
    <name>fs.defaultFS</name>
    <value>hdfs://${MASTER_NAME}:8020</value>
  </property>
  <property>
    <name>hadoop.tmp.dir</name>
    <value>${HADOOP_DATA}/tmp</value>
  </property>
</configuration>
EOF

  cat >"${HADOOP_HOME}/etc/hadoop/hdfs-site.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <property>
    <name>dfs.replication</name>
    <value>2</value>
  </property>
  <property>
    <name>dfs.namenode.name.dir</name>
    <value>file://${HADOOP_DATA}/hdfs/namenode</value>
  </property>
  <property>
    <name>dfs.datanode.data.dir</name>
    <value>file://${HADOOP_DATA}/hdfs/datanode</value>
  </property>
  <property>
    <name>dfs.namenode.rpc-address</name>
    <value>${MASTER_NAME}:8020</value>
  </property>
  <property>
    <name>dfs.namenode.rpc-bind-host</name>
    <value>0.0.0.0</value>
  </property>
  <property>
    <name>dfs.namenode.http-address</name>
    <value>0.0.0.0:9870</value>
  </property>
</configuration>
EOF

  cat >"${HADOOP_HOME}/etc/hadoop/mapred-site.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <property>
    <name>mapreduce.framework.name</name>
    <value>yarn</value>
  </property>
  <property>
    <name>mapreduce.map.memory.mb</name>
    <value>512</value>
  </property>
  <property>
    <name>mapreduce.reduce.memory.mb</name>
    <value>512</value>
  </property>
  <property>
    <name>yarn.app.mapreduce.am.resource.mb</name>
    <value>512</value>
  </property>
  <property>
    <name>yarn.app.mapreduce.am.env</name>
    <value>HADOOP_MAPRED_HOME=${HADOOP_HOME}</value>
  </property>
  <property>
    <name>mapreduce.map.env</name>
    <value>HADOOP_MAPRED_HOME=${HADOOP_HOME}</value>
  </property>
  <property>
    <name>mapreduce.reduce.env</name>
    <value>HADOOP_MAPRED_HOME=${HADOOP_HOME}</value>
  </property>
  <property>
    <name>mapreduce.map.java.opts</name>
    <value>-Xmx384m</value>
  </property>
  <property>
    <name>mapreduce.reduce.java.opts</name>
    <value>-Xmx384m</value>
  </property>
  <property>
    <name>yarn.app.mapreduce.am.command-opts</name>
    <value>-Xmx384m</value>
  </property>
  <property>
    <name>mapreduce.shuffle.port</name>
    <value>13562</value>
  </property>
  <property>
    <name>mapreduce.client.submit.file.replication</name>
    <value>2</value>
  </property>
  <property>
    <name>mapreduce.application.classpath</name>
    <value>\$HADOOP_MAPRED_HOME/share/hadoop/mapreduce/*,\$HADOOP_MAPRED_HOME/share/hadoop/mapreduce/lib/*,\$HADOOP_COMMON_HOME/share/hadoop/common/*,\$HADOOP_COMMON_HOME/share/hadoop/common/lib/*,\$HADOOP_HDFS_HOME/share/hadoop/hdfs/*,\$HADOOP_HDFS_HOME/share/hadoop/hdfs/lib/*,\$HADOOP_YARN_HOME/share/hadoop/yarn/*,\$HADOOP_YARN_HOME/share/hadoop/yarn/lib/*</value>
  </property>
</configuration>
EOF

  cat >"${HADOOP_HOME}/etc/hadoop/yarn-site.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <property>
    <name>yarn.resourcemanager.hostname</name>
    <value>${MASTER_NAME}</value>
  </property>
  <property>
    <name>yarn.resourcemanager.bind-host</name>
    <value>0.0.0.0</value>
  </property>
  <property>
    <name>yarn.resourcemanager.webapp.address</name>
    <value>${MASTER_NAME}:8088</value>
  </property>
  <property>
    <name>yarn.acl.enable</name>
    <value>true</value>
  </property>
  <property>
    <name>yarn.admin.acl</name>
    <value>${HADOOP_USER}</value>
  </property>
  <property>
    <name>yarn.nodemanager.aux-services</name>
    <value>mapreduce_shuffle</value>
  </property>
  <property>
    <name>yarn.nodemanager.hostname</name>
    <value>${MASTER_NAME}</value>
  </property>
  <property>
    <name>yarn.nodemanager.address</name>
    <value>\${yarn.nodemanager.hostname}:8041</value>
  </property>
  <property>
    <name>yarn.nodemanager.bind-host</name>
    <value>0.0.0.0</value>
  </property>
  <property>
    <name>yarn.nodemanager.localizer.address</name>
    <value>\${yarn.nodemanager.hostname}:8040</value>
  </property>
  <property>
    <name>yarn.nodemanager.webapp.address</name>
    <value>\${yarn.nodemanager.hostname}:8042</value>
  </property>
  <property>
    <name>yarn.nodemanager.resource.memory-mb</name>
    <value>1536</value>
  </property>
  <property>
    <name>yarn.scheduler.minimum-allocation-mb</name>
    <value>256</value>
  </property>
  <property>
    <name>yarn.scheduler.maximum-allocation-mb</name>
    <value>1536</value>
  </property>
  <property>
    <name>yarn.nodemanager.vmem-check-enabled</name>
    <value>false</value>
  </property>
</configuration>
EOF

  if [ -f "${HADOOP_HOME}/etc/hadoop/capacity-scheduler.xml" ]; then
    sed -i "/<name>yarn.scheduler.capacity.maximum-am-resource-percent<\\/name>/{n;s#<value>.*</value>#<value>0.5</value>#}" "${HADOOP_HOME}/etc/hadoop/capacity-scheduler.xml"
    sed -i "/<name>yarn.scheduler.capacity.root.default.acl_submit_applications<\\/name>/{n;s#<value>.*</value>#<value>${HADOOP_USER}</value>#}" "${HADOOP_HOME}/etc/hadoop/capacity-scheduler.xml"
    sed -i "/<name>yarn.scheduler.capacity.root.default.acl_administer_queue<\\/name>/{n;s#<value>.*</value>#<value>${HADOOP_USER}</value>#}" "${HADOOP_HOME}/etc/hadoop/capacity-scheduler.xml"
    if ! grep -q "<name>yarn.scheduler.capacity.root.acl_submit_applications</name>" "${HADOOP_HOME}/etc/hadoop/capacity-scheduler.xml"; then
      sed -i "/<\\/configuration>/i\\  <property>\\n    <name>yarn.scheduler.capacity.root.acl_submit_applications</name>\\n    <value>${HADOOP_USER}</value>\\n  </property>\\n  <property>\\n    <name>yarn.scheduler.capacity.root.acl_administer_queue</name>\\n    <value>${HADOOP_USER}</value>\\n  </property>" "${HADOOP_HOME}/etc/hadoop/capacity-scheduler.xml"
    fi
  fi

  printf "%s\n" "${WORKERS[@]}" >"${HADOOP_HOME}/etc/hadoop/workers"
  chown -R "${HADOOP_USER}:${HADOOP_USER}" "${HADOOP_HOME}"
}

configure_hadoop_ssh() {
  mkdir -p "/home/${HADOOP_USER}/.ssh"
  if [ ! -f "/home/${HADOOP_USER}/.ssh/id_ed25519" ]; then
    sudo -u "${HADOOP_USER}" ssh-keygen -t ed25519 -N "" -f "/home/${HADOOP_USER}/.ssh/id_ed25519" -C "${HADOOP_USER}@${MASTER_NAME}"
  fi
  local pub_key
  pub_key="$(cat "/home/${HADOOP_USER}/.ssh/id_ed25519.pub")"
  for host in "${NODES[@]}"; do
    ssh_root "${host}" "grep -qxF '${pub_key}' /home/${HADOOP_USER}/.ssh/authorized_keys || echo '${pub_key}' >> /home/${HADOOP_USER}/.ssh/authorized_keys; chown ${HADOOP_USER}:${HADOOP_USER} /home/${HADOOP_USER}/.ssh/authorized_keys; chmod 600 /home/${HADOOP_USER}/.ssh/authorized_keys"
  done
  ssh-keyscan -H "${MASTER_NAME}" "${MASTER_IP}" "${WORKER_1_NAME}" "${WORKER_1_IP}" "${WORKER_2_NAME}" "${WORKER_2_IP}" >> "/home/${HADOOP_USER}/.ssh/known_hosts" 2>/dev/null || true
  chown "${HADOOP_USER}:${HADOOP_USER}" "/home/${HADOOP_USER}/.ssh/known_hosts"
  chmod 600 "/home/${HADOOP_USER}/.ssh/known_hosts"
}

sync_hadoop_to_workers() {
  for worker in "${WORKER_1_IP}:${WORKER_1_NAME}" "${WORKER_2_IP}:${WORKER_2_NAME}"; do
    local host="${worker%%:*}"
    local node_name="${worker##*:}"
    rsync -az --delete -e "ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new" "${HADOOP_HOME}/" "root@${host}:${HADOOP_HOME}/"
    ssh_root "${host}" "python3 - <<PY
from pathlib import Path
import re
p = Path('${HADOOP_HOME}/etc/hadoop/yarn-site.xml')
s = p.read_text()
s = re.sub(r'(<name>yarn\\.nodemanager\\.hostname</name>\\s*<value>)[^<]*(</value>)', r'\\1${node_name}\\2', s)
p.write_text(s)
PY
chown -R ${HADOOP_USER}:${HADOOP_USER} ${HADOOP_HOME} ${HADOOP_DATA}; cp /etc/profile.d/hadoop.sh /etc/profile.d/hadoop.sh 2>/dev/null || true"
    scp -q /etc/profile.d/hadoop.sh "root@${host}:/etc/profile.d/hadoop.sh"
  done
}

configure_firewall() {
  for host in "${NODES[@]}"; do
    ssh_root "${host}" "if command -v ufw >/dev/null 2>&1 && ufw status | grep -q 'Status: active'; then
      ufw allow from ${MASTER_IP} >/dev/null || true
      ufw allow from ${WORKER_1_IP} >/dev/null || true
      ufw allow from ${WORKER_2_IP} >/dev/null || true
    fi"
  done
}

start_cluster() {
  chown -R "${HADOOP_USER}:${HADOOP_USER}" "${HADOOP_HOME}" "${HADOOP_DATA}"
  sudo -iu "${HADOOP_USER}" bash -lc "source /etc/profile.d/hadoop.sh; stop-yarn.sh >/dev/null 2>&1 || true; stop-dfs.sh >/dev/null 2>&1 || true"
  if [ ! -f "${HADOOP_DATA}/hdfs/namenode/current/VERSION" ]; then
    sudo -iu "${HADOOP_USER}" bash -lc "source /etc/profile.d/hadoop.sh; hdfs namenode -format -force -nonInteractive"
  fi
  sudo -iu "${HADOOP_USER}" bash -lc "source /etc/profile.d/hadoop.sh; start-dfs.sh; start-yarn.sh; hdfs dfs -mkdir -p /tmp /user/${HADOOP_USER} /honeypot/ods /honeypot/dwd /honeypot/dws; hdfs dfs -chmod 1777 /tmp; hdfs dfs -chown -R ${HADOOP_USER}:${HADOOP_USER} /user/${HADOOP_USER} /honeypot; jps; hdfs dfsadmin -report | sed -n '1,80p'"
}

main() {
  for host in "${NODES[@]}"; do
    configure_hosts_file "${host}"
    prepare_node "${host}"
  done

  install_hadoop_on_master
  write_hadoop_config
  configure_hadoop_ssh
  sync_hadoop_to_workers
  configure_firewall
  chown -R "${HADOOP_USER}:${HADOOP_USER}" /data/honeypot/cleaned /data/honeypot/results /data/honeypot/frontend 2>/dev/null || true
  start_cluster
}

main "$@"
