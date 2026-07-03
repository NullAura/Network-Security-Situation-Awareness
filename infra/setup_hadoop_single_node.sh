#!/usr/bin/env bash
set -euo pipefail

HADOOP_VERSION="${HADOOP_VERSION:-3.4.1}"
HADOOP_ARCHIVE="hadoop-${HADOOP_VERSION}.tar.gz"
HADOOP_URL="${HADOOP_URL:-https://archive.apache.org/dist/hadoop/common/hadoop-${HADOOP_VERSION}/${HADOOP_ARCHIVE}}"
HADOOP_HOME="/opt/hadoop"
HADOOP_DATA="/data/hadoop"

if ! command -v java >/dev/null 2>&1; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y openjdk-17-jdk-headless
fi

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y curl openssh-server rsync

mkdir -p /root/.ssh
chmod 700 /root/.ssh
if [ ! -f /root/.ssh/id_ed25519 ]; then
  ssh-keygen -t ed25519 -N "" -f /root/.ssh/id_ed25519 -C "root@$(hostname)-hadoop"
fi
touch /root/.ssh/authorized_keys
grep -qxF "$(cat /root/.ssh/id_ed25519.pub)" /root/.ssh/authorized_keys || cat /root/.ssh/id_ed25519.pub >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
ssh-keyscan -H localhost 127.0.0.1 "$(hostname)" >> /root/.ssh/known_hosts 2>/dev/null || true

if [ ! -d "${HADOOP_HOME}" ]; then
  cd /tmp
  curl -fL "${HADOOP_URL}" -o "${HADOOP_ARCHIVE}"
  tar -xzf "${HADOOP_ARCHIVE}"
  rm -rf "${HADOOP_HOME}"
  mv "hadoop-${HADOOP_VERSION}" "${HADOOP_HOME}"
fi

JAVA_HOME_VALUE="$(dirname "$(dirname "$(readlink -f "$(command -v java)")")")"
mkdir -p "${HADOOP_DATA}/tmp" "${HADOOP_DATA}/hdfs/namenode" "${HADOOP_DATA}/hdfs/datanode"

cat >/etc/profile.d/hadoop.sh <<EOF
export JAVA_HOME=${JAVA_HOME_VALUE}
export HADOOP_HOME=${HADOOP_HOME}
export HADOOP_CONF_DIR=${HADOOP_HOME}/etc/hadoop
export PATH=\\$PATH:${HADOOP_HOME}/bin:${HADOOP_HOME}/sbin
EOF

cat >"${HADOOP_HOME}/etc/hadoop/hadoop-env.sh" <<EOF
export JAVA_HOME=${JAVA_HOME_VALUE}
export HADOOP_HOME=${HADOOP_HOME}
export HADOOP_CONF_DIR=${HADOOP_HOME}/etc/hadoop
export HADOOP_LOG_DIR=${HADOOP_HOME}/logs
export HDFS_NAMENODE_USER=root
export HDFS_DATANODE_USER=root
export HDFS_SECONDARYNAMENODE_USER=root
export YARN_RESOURCEMANAGER_USER=root
export YARN_NODEMANAGER_USER=root
EOF

cat >"${HADOOP_HOME}/etc/hadoop/core-site.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <property>
    <name>fs.defaultFS</name>
    <value>hdfs://127.0.0.1:8020</value>
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
    <value>1</value>
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
    <name>mapreduce.application.classpath</name>
    <value>\$HADOOP_MAPRED_HOME/share/hadoop/mapreduce/*,\$HADOOP_MAPRED_HOME/share/hadoop/mapreduce/lib/*,\$HADOOP_COMMON_HOME/share/hadoop/common/*,\$HADOOP_COMMON_HOME/share/hadoop/common/lib/*,\$HADOOP_HDFS_HOME/share/hadoop/hdfs/*,\$HADOOP_HDFS_HOME/share/hadoop/hdfs/lib/*,\$HADOOP_YARN_HOME/share/hadoop/yarn/*,\$HADOOP_YARN_HOME/share/hadoop/yarn/lib/*</value>
  </property>
</configuration>
EOF

cat >"${HADOOP_HOME}/etc/hadoop/yarn-site.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <property>
    <name>yarn.nodemanager.aux-services</name>
    <value>mapreduce_shuffle</value>
  </property>
  <property>
    <name>yarn.resourcemanager.hostname</name>
    <value>127.0.0.1</value>
  </property>
  <property>
    <name>yarn.nodemanager.resource.memory-mb</name>
    <value>2048</value>
  </property>
  <property>
    <name>yarn.scheduler.maximum-allocation-mb</name>
    <value>2048</value>
  </property>
  <property>
    <name>yarn.nodemanager.vmem-check-enabled</name>
    <value>false</value>
  </property>
</configuration>
EOF

echo "localhost" >"${HADOOP_HOME}/etc/hadoop/workers"

export JAVA_HOME="${JAVA_HOME_VALUE}"
export HADOOP_HOME="${HADOOP_HOME}"
export HADOOP_CONF_DIR="${HADOOP_HOME}/etc/hadoop"
export PATH="${PATH}:${HADOOP_HOME}/bin:${HADOOP_HOME}/sbin"
export HDFS_NAMENODE_USER=root
export HDFS_DATANODE_USER=root
export HDFS_SECONDARYNAMENODE_USER=root
export YARN_RESOURCEMANAGER_USER=root
export YARN_NODEMANAGER_USER=root

if [ ! -f "${HADOOP_DATA}/hdfs/namenode/current/VERSION" ]; then
  hdfs namenode -format -force -nonInteractive
fi

start-dfs.sh || true
start-yarn.sh || true

hdfs dfs -mkdir -p /tmp /user/root /honeypot/ods /honeypot/dwd /honeypot/dws
hdfs dfs -chmod 1777 /tmp

jps
hdfs dfs -ls /
