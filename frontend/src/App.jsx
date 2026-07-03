import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  CheckCircle2,
  Clock,
  Database,
  Download,
  FileJson,
  FileSpreadsheet,
  Fingerprint,
  Gauge,
  Globe2,
  GripVertical,
  KeyRound,
  Link2,
  LayoutDashboard,
  MapPin,
  Maximize2,
  Minimize2,
  Network,
  Pause,
  Play,
  RadioTower,
  RefreshCw,
  Search,
  Server,
  Shield,
  Target,
  TerminalSquare,
  Wifi,
} from "lucide-react";
import { geoDistance, geoGraticule, geoNaturalEarth1, geoOrthographic, geoPath } from "d3-geo";
import { feature } from "topojson-client";
import world from "world-atlas/countries-110m.json";
import {
  createFallbackSnapshot,
  fetchThreatSnapshot,
} from "./services/threatApi.js";

const protocolIcons = {
  SSH: TerminalSquare,
  FTP: Database,
  HTTP: Globe2,
  HTTP_ALT: Globe2,
  HTTPS_ALT: Globe2,
  MYSQL: Database,
  REDIS: Server,
  TELNET: TerminalSquare,
  RDP: LayoutDashboard,
  VNC: Wifi,
  POSTGRES: Database,
  MSSQL: Database,
  ORACLE: Database,
  MONGODB: Database,
  MEMCACHED: Server,
  ELASTICSEARCH: Database,
  MQTT: RadioTower,
  SMTP: RadioTower,
  POP3: Database,
  IMAP: Database,
  SMB: Server,
  SIP: RadioTower,
  LDAP: Network,
  NFS: Server,
  RPCBIND: Network,
};

const attackMethodIcons = {
  vnc_bruteforce: KeyRound,
  ssh_bruteforce: KeyRound,
  telnet_bruteforce: KeyRound,
  ftp_bruteforce: KeyRound,
  rdp_bruteforce: KeyRound,
  remote_login_probe: TerminalSquare,
  command_execution: TerminalSquare,
  payload_delivery: Download,
  sql_injection_probe: Database,
  web_vuln_scan: Globe2,
  http_fingerprint: Globe2,
  http_proxy_probe: Globe2,
  db_login_probe: Database,
  db_service_probe: Database,
  redis_command_probe: Server,
  mqtt_probe: RadioTower,
  smb_probe: Server,
  tcp_port_scan: Search,
  protocol_probe: Fingerprint,
};

const severityLabel = {
  high: "高危",
  medium: "中危",
  low: "低危",
};

const statusLabel = {
  online: "在线",
  running: "运行中",
  reserved: "预留",
  error: "异常",
  offline: "离线",
  unknown: "未知",
};

const severityWeight = { low: 1, medium: 2, high: 3 };

const payloadFieldLabels = {
  "VNC Client Response": "VNC 客户端响应",
  "VNC Password": "VNC 口令判断",
  "VNC Server Challenge": "VNC 服务端挑战",
  event_type: "事件类型",
  protocol: "协议",
  src_ip: "源 IP",
  src_host: "源 IP",
  src_port: "源端口",
  dst_ip: "目标 IP",
  dst_host: "内部目标",
  dst_port: "目标端口",
  username: "用户名",
  password: "密码",
  sensor_id: "传感器",
  node_id: "采集节点",
  logtype: "日志类型",
  local_time: "采集时间",
  local_time_adjusted: "本地时间",
  utc_time: "UTC 时间",
};

const payloadFieldPriority = [
  "event_type",
  "protocol",
  "src_ip",
  "src_host",
  "src_port",
  "dst_ip",
  "dst_host",
  "dst_port",
  "username",
  "password",
  "VNC Password",
  "VNC Client Response",
  "VNC Server Challenge",
  "sensor_id",
  "node_id",
  "logtype",
];

const attackMethodDefinitions = [
  {
    key: "vnc_bruteforce",
    name: "VNC 密码爆破",
    tactic: "credential",
    severity: "high",
    color: "#ff6848",
    description: "VNC 认证握手、challenge/response 或口令字典判断，说明正在尝试远控口令。",
  },
  {
    key: "ssh_bruteforce",
    name: "SSH 弱口令爆破",
    tactic: "credential",
    severity: "high",
    color: "#ff8a4c",
    description: "SSH 登录、认证或用户名/密码尝试。",
  },
  {
    key: "telnet_bruteforce",
    name: "Telnet 弱口令爆破",
    tactic: "credential",
    severity: "high",
    color: "#ffcf58",
    description: "Telnet 登录事件或账号口令字段，常见于 IoT 弱口令尝试。",
  },
  {
    key: "ftp_bruteforce",
    name: "FTP 口令尝试",
    tactic: "credential",
    severity: "medium",
    color: "#a88cff",
    description: "FTP 登录、匿名访问或凭据尝试。",
  },
  {
    key: "rdp_bruteforce",
    name: "RDP 凭据尝试",
    tactic: "credential",
    severity: "high",
    color: "#58a6ff",
    description: "远程桌面认证或登录行为。",
  },
  {
    key: "remote_login_probe",
    name: "远程登录探测",
    tactic: "probe",
    severity: "medium",
    color: "#6ea8ff",
    description: "SSH/Telnet/RDP/VNC/FTP 等远程入口的连接和握手探测。",
  },
  {
    key: "command_execution",
    name: "命令执行尝试",
    tactic: "execution",
    severity: "high",
    color: "#ff4e63",
    description: "蜜罐捕获到交互命令、命令失败或 shell 输入。",
  },
  {
    key: "payload_delivery",
    name: "恶意载荷下载",
    tactic: "execution",
    severity: "high",
    color: "#ff3f2f",
    description: "出现 wget/curl/tftp/chmod/shell 等下载或执行链迹象。",
  },
  {
    key: "sql_injection_probe",
    name: "SQL 注入探测",
    tactic: "exploit",
    severity: "high",
    color: "#f0dc4e",
    description: "HTTP 参数中出现 union select、information_schema、sleep、or 1=1 等 SQLi 特征。",
  },
  {
    key: "web_vuln_scan",
    name: "Web 漏洞扫描",
    tactic: "exploit",
    severity: "medium",
    color: "#20d9ff",
    description: "扫描敏感路径、管理后台、CVE/CGI、环境文件或命令参数。",
  },
  {
    key: "http_fingerprint",
    name: "HTTP 指纹探测",
    tactic: "recon",
    severity: "medium",
    color: "#27d7ff",
    description: "HTTP 请求、Host、User-Agent 或路径访问，用于识别 Web 暴露面。",
  },
  {
    key: "http_proxy_probe",
    name: "HTTP 代理探测",
    tactic: "recon",
    severity: "medium",
    color: "#2ed8b6",
    description: "CONNECT、代理访问或转发测试。",
  },
  {
    key: "db_login_probe",
    name: "数据库口令尝试",
    tactic: "credential",
    severity: "high",
    color: "#ffba52",
    description: "MySQL/PostgreSQL/MSSQL/Oracle/MongoDB 等数据库登录或认证尝试。",
  },
  {
    key: "db_service_probe",
    name: "数据库服务探测",
    tactic: "probe",
    severity: "high",
    color: "#ffcf58",
    description: "数据库端口握手、版本识别或连接试探。",
  },
  {
    key: "redis_command_probe",
    name: "Redis 命令探测",
    tactic: "exploit",
    severity: "high",
    color: "#ff6048",
    description: "Redis INFO/AUTH/CONFIG/SET/SLAVEOF 等未授权或命令试探。",
  },
  {
    key: "mqtt_probe",
    name: "MQTT 连接探测",
    tactic: "probe",
    severity: "medium",
    color: "#35d0aa",
    description: "MQTT 连接、订阅或物联网消息入口试探。",
  },
  {
    key: "smb_probe",
    name: "SMB 服务探测",
    tactic: "probe",
    severity: "high",
    color: "#8b7cff",
    description: "SMB/文件共享端口连接、枚举或握手探测。",
  },
  {
    key: "tcp_port_scan",
    name: "端口扫描探测",
    tactic: "recon",
    severity: "medium",
    color: "#8ba6b1",
    description: "仅打开连接或命中扩展 TCP 端口，尚未形成更具体攻击语义。",
  },
  {
    key: "protocol_probe",
    name: "服务指纹探测",
    tactic: "recon",
    severity: "low",
    color: "#7aa8b5",
    description: "端口、握手或服务指纹层面的背景探测。",
  },
];

const attackMethodByKey = new Map(attackMethodDefinitions.map((method) => [method.key, method]));
const historyMethodKeyAliases = {
  vnc_bruteforce: ["vnc_credential_attack"],
  ssh_bruteforce: ["ssh_credential_attack", "credential_attack"],
  telnet_bruteforce: ["telnet_probe", "credential_attack"],
  ftp_bruteforce: ["ftp_probe", "credential_attack"],
  rdp_bruteforce: ["rdp_probe"],
  remote_login_probe: ["credential_attack", "telnet_probe", "rdp_probe", "ftp_probe"],
  payload_delivery: ["http_payload_probe"],
  http_fingerprint: ["http_fingerprint_probe"],
  db_login_probe: ["database_login_attempt"],
  db_service_probe: ["database_probe"],
};

const DEFAULT_TAB = "态势总览";
const tabs = ["态势总览", "攻击分析", "源 IP 画像", "系统与导出"];
const viewRouteByTab = {
  态势总览: "overview",
  攻击分析: "threat-analysis",
  "源 IP 画像": "source-profile",
  系统与导出: "system-export",
};
const tabByViewRoute = Object.fromEntries(Object.entries(viewRouteByTab).map(([tab, route]) => [route, tab]));
const REFRESH_INTERVAL_MS = 1000;
const BEIJING_TIME_ZONE = "Asia/Shanghai";
const BEIJING_OFFSET_MS = 8 * 60 * 60 * 1000;
const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;
const EMPTY_FIELD_VALUES = new Set(["", "-", "unknown", "null", "undefined"]);
const MAP_TIME_RANGE_OPTIONS = [
  { key: "live", label: "实时", ms: 60 * 1000 },
  { key: "all", label: "全部", ms: null },
  { key: "1h", label: "过去1小时", ms: 60 * 60 * 1000 },
  { key: "24h", label: "过去24小时", ms: 24 * 60 * 60 * 1000 },
  { key: "7d", label: "过去7天", ms: 7 * 24 * 60 * 60 * 1000 },
  { key: "30d", label: "过去30天", ms: 30 * 24 * 60 * 60 * 1000 },
];
const MAP_TIME_RANGE_KEYS = new Set(MAP_TIME_RANGE_OPTIONS.map((option) => option.key));
const MAP_SOURCE_IP_LIMIT = 160;

function isKnown(value) {
  return !EMPTY_FIELD_VALUES.has(String(value ?? "").trim().toLowerCase());
}

function displayValue(value, fallback = "未识别") {
  return isKnown(value) ? String(value) : fallback;
}

function dataModeLabel(mode, paused = false) {
  if (paused) return "已暂停";
  if (mode === "api") return "API 实时";
  if (mode === "loading") return "连接中";
  if (mode === "error") return "数据不可用";
  return "未知状态";
}

function formatNumber(value) {
  if (value === null || value === undefined || value === "") return "--";
  const number = Number(value);
  return Number.isFinite(number) ? new Intl.NumberFormat("zh-CN").format(number) : "--";
}

function optionalMetric(value, fallback = "--") {
  const number = Number(value);
  return Number.isFinite(number) ? formatNumber(number) : fallback;
}

function optionalDelta(value) {
  const number = Number(value);
  return Number.isFinite(number) ? `${number}%` : "无基线";
}

function readUrlViewState() {
  if (typeof window === "undefined") {
    return {
      activeTab: DEFAULT_TAB,
      activeProtocol: "ALL",
      activeMethod: "ALL",
      highOnly: false,
      mapTimeRange: "all",
      query: "",
      rankingMode: "event",
      selectedIp: "",
    };
  }
  const params = new URLSearchParams(window.location.search);
  const viewParam = params.get("view") || params.get("tab") || "";
  const tab = tabByViewRoute[viewParam] || (tabs.includes(viewParam) ? viewParam : DEFAULT_TAB);
  const rankingMode = ["event", "risk", "protocol"].includes(params.get("rank")) ? params.get("rank") : "event";
  return {
    activeTab: tab,
    activeProtocol: displayValue(params.get("protocol"), "ALL"),
    activeMethod: displayValue(params.get("method"), "ALL"),
    highOnly: params.get("high") === "1" || params.get("risk") === "high",
    mapTimeRange: MAP_TIME_RANGE_KEYS.has(params.get("mapRange")) ? params.get("mapRange") : "all",
    query: params.get("q") || "",
    rankingMode,
    selectedIp: params.get("ip") || "",
  };
}

function buildUrlViewSearch({ activeTab, activeProtocol, activeMethod, highOnly, mapTimeRange, query, rankingMode, selectedIp }) {
  const params = new URLSearchParams();
  const viewRoute = viewRouteByTab[activeTab] || "overview";
  if (viewRoute !== "overview") params.set("view", viewRoute);
  if (activeProtocol && activeProtocol !== "ALL") params.set("protocol", activeProtocol);
  if (activeMethod && activeMethod !== "ALL") params.set("method", activeMethod);
  if (highOnly) params.set("high", "1");
  if (mapTimeRange && mapTimeRange !== "all") params.set("mapRange", mapTimeRange);
  if (query.trim()) params.set("q", query.trim());
  if (rankingMode && rankingMode !== "event") params.set("rank", rankingMode);
  if (selectedIp) params.set("ip", selectedIp);
  const search = params.toString();
  return search ? `?${search}` : "";
}

function compactText(value, maxLength = 120) {
  const text = displayValue(value, "");
  if (!text) return "";
  return text.length > maxLength ? `${text.slice(0, maxLength - 1)}…` : text;
}

function evidenceTextValue(value) {
  if (!isKnown(value)) return "";
  if (typeof value === "object") {
    const extracted = extractPayloadLine(value);
    return isKnown(extracted) ? extracted : "";
  }
  return String(value).trim();
}

function isMetadataDump(text) {
  const value = String(text || "").trim();
  if (!value.startsWith("{") && !value.startsWith("[")) return false;
  const lower = value.toLowerCase();
  const metadataHits = ["event_type", "protocol", "src_ip", "src_port", "dst_ip", "dst_port", "event_time"].filter((key) => lower.includes(key)).length;
  const evidenceHits = ["payload", "raw_payload", "request", "command", "username", "password", "input", "vnc"].filter((key) => lower.includes(key)).length;
  return metadataHits >= 3 && evidenceHits === 0;
}

function eventSearchHaystack(event) {
  const method = attackBehavior(event);
  return [
    event.srcIp,
    event.country,
    event.region,
    event.city,
    event.isp,
    event.asn,
    event.protocol,
    event.username,
    event.eventType,
    event.command,
    event.payload,
    event.detail,
    event.honeypot,
    event.honeypotLabel,
    method.key,
    method.name,
    method.tactic,
    method.evidence?.join(" "),
  ].join(" ").toLowerCase();
}

function matchesEventQuery(event, normalizedQuery) {
  if (!normalizedQuery) return true;
  return eventSearchHaystack(event).includes(normalizedQuery);
}

function filterEventsByScope(events, { activeProtocol = "ALL", activeMethod = "ALL", highOnly = false, query = "" } = {}) {
  const normalizedQuery = query.trim().toLowerCase();
  return events.filter((event) => {
    if (activeProtocol !== "ALL" && event.protocol !== activeProtocol) return false;
    if (activeMethod !== "ALL" && attackBehavior(event).key !== activeMethod) return false;
    if (highOnly && effectiveSeverity(event) !== "high") return false;
    return matchesEventQuery(event, normalizedQuery);
  });
}

function eventTimestampMs(event) {
  const direct = Number(event.eventTsMs ?? event.timestamp);
  if (Number.isFinite(direct)) return direct;
  const parsed = Date.parse(event.eventTimeUtc || event.event_time_utc || event.eventTime || event.event_time || event.timestamp);
  return Number.isFinite(parsed) ? parsed : null;
}

function mapTimeRangeOption(key) {
  return MAP_TIME_RANGE_OPTIONS.find((option) => option.key === key) || MAP_TIME_RANGE_OPTIONS[0];
}

function filterEventsByMapTimeRange(events, rangeKey, anchorTime) {
  const option = mapTimeRangeOption(rangeKey);
  if (!option.ms) return events;
  const parsedAnchor = typeof anchorTime === "number" ? anchorTime : Date.parse(anchorTime);
  const latest = latestEventTime(events);
  const anchor = Math.max(
    Number.isFinite(parsedAnchor) ? parsedAnchor : Date.now(),
    latest || 0,
  );
  const cutoff = anchor - option.ms;
  return events.filter((event) => {
    const timestamp = eventTimestampMs(event);
    return timestamp !== null && timestamp >= cutoff && timestamp <= anchor + 5 * 60 * 1000;
  });
}

function buildMapRangeBounds(rangeKey, anchorTime, events = []) {
  const option = mapTimeRangeOption(rangeKey);
  if (!option.ms) return { startMs: null, endMs: null, valid: true };
  const parsedAnchor = typeof anchorTime === "number" ? anchorTime : Date.parse(anchorTime);
  const latest = latestEventTime(events);
  const endMs = Math.max(
    Number.isFinite(parsedAnchor) ? parsedAnchor : Date.now(),
    latest || 0,
  );
  return {
    startMs: endMs - option.ms,
    endMs,
    valid: Number.isFinite(endMs),
  };
}

function historyTimeRangeCoversAll(historyTrend, rangeKey, anchorTime) {
  const option = mapTimeRangeOption(rangeKey);
  if (!option.ms) return true;
  if (!Array.isArray(historyTrend?.availableDates) || !historyTrend.availableDates.length) return false;
  const bounds = buildMapRangeBounds(rangeKey, anchorTime);
  if (!bounds.valid || !Number.isFinite(bounds.startMs)) return false;
  const earliest = historyTrend.availableDates
    .map(parseBeijingDateInput)
    .filter(Number.isFinite)
    .sort((left, right) => left - right)[0];
  return Number.isFinite(earliest) && earliest >= bounds.startMs;
}

function selectMapEventsBySourceIp(events, limit = MAP_SOURCE_IP_LIMIT) {
  const selected = [];
  const seenIps = new Set();
  for (const event of events) {
    if (!isKnown(event.srcIp) || seenIps.has(event.srcIp)) continue;
    if (!hasUsableCoordinates(event.sourceCoordinates) || !hasUsableCoordinates(event.targetCoordinates)) continue;
    seenIps.add(event.srcIp);
    selected.push(event);
    if (selected.length >= limit) break;
  }
  return selected;
}

function formatEventClock(timestamp) {
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) return "时间未知";
  return date.toLocaleString("zh-CN", { timeZone: BEIJING_TIME_ZONE, hour12: false });
}

function latestEventTime(events) {
  const timestamps = events
    .map(eventTimestampMs)
    .filter((timestamp) => Number.isFinite(timestamp));
  return timestamps.length ? Math.max(...timestamps) : null;
}

function beijingDayStartMs(timestamp) {
  const shifted = new Date(timestamp + BEIJING_OFFSET_MS);
  return Date.UTC(shifted.getUTCFullYear(), shifted.getUTCMonth(), shifted.getUTCDate()) - BEIJING_OFFSET_MS;
}

function beijingHourStartMs(timestamp) {
  const shifted = new Date(timestamp + BEIJING_OFFSET_MS);
  return Date.UTC(
    shifted.getUTCFullYear(),
    shifted.getUTCMonth(),
    shifted.getUTCDate(),
    shifted.getUTCHours(),
  ) - BEIJING_OFFSET_MS;
}

function formatBeijingDateLabel(timestamp) {
  return new Date(timestamp).toLocaleDateString("zh-CN", {
    timeZone: BEIJING_TIME_ZONE,
    month: "2-digit",
    day: "2-digit",
    weekday: "short",
  });
}

function formatBeijingDateInput(timestamp) {
  if (!Number.isFinite(timestamp)) return "";
  const shifted = new Date(timestamp + BEIJING_OFFSET_MS);
  const year = shifted.getUTCFullYear();
  const month = String(shifted.getUTCMonth() + 1).padStart(2, "0");
  const day = String(shifted.getUTCDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}

function parseBeijingDateInput(value) {
  const match = String(value || "").match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!match) return Number.NaN;
  return Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3])) - BEIJING_OFFSET_MS;
}

function formatBeijingDateTimeInput(timestamp) {
  if (!Number.isFinite(timestamp)) return "";
  const shifted = new Date(timestamp + BEIJING_OFFSET_MS);
  const year = shifted.getUTCFullYear();
  const month = String(shifted.getUTCMonth() + 1).padStart(2, "0");
  const day = String(shifted.getUTCDate()).padStart(2, "0");
  const hour = String(shifted.getUTCHours()).padStart(2, "0");
  const minute = String(shifted.getUTCMinutes()).padStart(2, "0");
  return `${year}-${month}-${day}T${hour}:${minute}`;
}

function parseBeijingDateTimeInput(value) {
  const match = String(value || "").match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/);
  if (!match) return Number.NaN;
  return Date.UTC(
    Number(match[1]),
    Number(match[2]) - 1,
    Number(match[3]),
    Number(match[4]),
    Number(match[5]),
  ) - BEIJING_OFFSET_MS;
}

function formatBeijingDateTimeCompact(timestamp) {
  return new Date(timestamp).toLocaleString("zh-CN", {
    timeZone: BEIJING_TIME_ZONE,
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
}

function formatBeijingHourCompact(timestamp) {
  return new Date(timestamp).toLocaleTimeString("zh-CN", {
    timeZone: BEIJING_TIME_ZONE,
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
}

function eventDateOptions(events) {
  return [...new Set(events.map(eventTimestampMs).filter(Number.isFinite).map(formatBeijingDateInput))]
    .filter(Boolean)
    .sort()
    .reverse();
}

function trendDateOptions(historyTrend, events) {
  if (Array.isArray(historyTrend?.availableDates) && historyTrend.availableDates.length) {
    return [...new Set(historyTrend.availableDates.filter(Boolean))].sort().reverse();
  }
  return eventDateOptions(events);
}

function niceTickStep(value) {
  if (!Number.isFinite(value) || value <= 0) return 1;
  const magnitude = 10 ** Math.floor(Math.log10(value));
  const normalized = value / magnitude;
  const multiplier = normalized <= 1 ? 1 : normalized <= 2 ? 2 : normalized <= 5 ? 5 : 10;
  return multiplier * magnitude;
}

function buildYAxisTicks(maxValue, targetTicks = 5) {
  if (!Number.isFinite(maxValue) || maxValue <= 0) return [0, 1];
  const step = niceTickStep(maxValue / Math.max(1, targetTicks - 1));
  const maxTick = Math.ceil(maxValue / step) * step;
  const ticks = [];
  for (let value = 0; value <= maxTick + step / 2; value += step) {
    ticks.push(value);
  }
  return ticks;
}

function historyBucketTimestamp(bucket) {
  const direct = Date.parse(bucket?.bucketStart || "");
  if (Number.isFinite(direct)) return direct;
  const dateStart = parseBeijingDateInput(bucket?.date || "");
  const hour = Number(bucket?.hour ?? 0);
  if (!Number.isFinite(dateStart) || !Number.isFinite(hour)) return NaN;
  return dateStart + Math.max(0, Math.min(23, hour)) * HOUR_MS;
}

function historyCountForFilter(bucket, { activeMethod = "ALL", activeProtocol = "ALL" } = {}, high = false) {
  const methodCounts = high ? bucket.methodHighCounts : bucket.methodCounts;
  const protocolCounts = high ? bucket.protocolHighCounts : bucket.protocolCounts;
  const methodKeys = activeMethod === "ALL" ? [] : [activeMethod, ...(historyMethodKeyAliases[activeMethod] || [])];
  const methodValue = activeMethod === "ALL"
    ? null
    : methodKeys.reduce((sum, key) => sum + Number(methodCounts?.[key] ?? 0), 0);
  const protocolValue = activeProtocol === "ALL" ? null : Number(protocolCounts?.[activeProtocol] ?? 0);
  if (methodValue !== null && protocolValue !== null) return Math.min(methodValue, protocolValue);
  if (methodValue !== null) return methodValue;
  if (protocolValue !== null) return protocolValue;
  return Number(high ? bucket.high : bucket.total) || 0;
}

function topHistoryMethod(bucket, methodNames = {}) {
  const entries = Object.entries(bucket.methodCounts || {}).sort((left, right) => Number(right[1]) - Number(left[1]));
  const key = bucket.topMethodKey || entries[0]?.[0] || "";
  return methodNames[key] || (key ? methodLabel(key) : "无事件");
}

function buildAttackTimeSeriesTrend(events, {
  activeMethod = "ALL",
  activeProtocol = "ALL",
  historyTrend,
  mode = "last24h",
  selectedDate = "",
  anchorTime,
} = {}) {
  const historyRows = Array.isArray(historyTrend?.hourly) ? historyTrend.hourly : [];
  const latestHistory = historyRows
    .filter((bucket) => Number(bucket.total) > 0)
    .map(historyBucketTimestamp)
    .filter(Number.isFinite)
    .sort((left, right) => right - left)[0];
  const latest = latestHistory ?? latestEventTime(events);
  const parsedAnchor = typeof anchorTime === "number" ? anchorTime : Date.parse(anchorTime);
  const anchor = latest ?? (Number.isFinite(parsedAnchor) ? parsedAnchor : Date.now());
  const selectedDateStart = parseBeijingDateInput(selectedDate);
  const useDateRange = mode === "date" && Number.isFinite(selectedDateStart);
  const rollingEnd = beijingHourStartMs(anchor) + HOUR_MS;
  const start = useDateRange ? selectedDateStart : rollingEnd - DAY_MS;
  const end = useDateRange ? start + DAY_MS : rollingEnd;
  const buckets = Array.from({ length: 24 }, (_, index) => ({
    index,
    hour: useDateRange ? index : new Date(start + index * HOUR_MS + BEIJING_OFFSET_MS).getUTCHours(),
    label: useDateRange ? `${String(index).padStart(2, "0")}:00` : formatBeijingHourCompact(start + index * HOUR_MS),
    total: 0,
    high: 0,
    sourceCount: 0,
    sourceIps: new Set(),
    methods: new Map(),
  }));

  const usingHistoryTrend = historyRows.length > 0;
  if (usingHistoryTrend) {
    historyRows.forEach((historyBucket) => {
      const timestamp = historyBucketTimestamp(historyBucket);
      if (!Number.isFinite(timestamp) || timestamp < start || timestamp >= end) return;
      const total = historyCountForFilter(historyBucket, { activeMethod, activeProtocol });
      const high = historyCountForFilter(historyBucket, { activeMethod, activeProtocol }, true);
      if (!total && !high) return;
      const bucketIndex = Math.min(23, Math.max(0, Math.floor((timestamp - start) / HOUR_MS)));
      const bucket = buckets[bucketIndex];
      const method = activeMethod === "ALL" ? topHistoryMethod(historyBucket, historyTrend.methodNames) : methodLabel(activeMethod);
      bucket.total += total;
      bucket.high += high;
      bucket.sourceCount = Math.max(bucket.sourceCount, Number(historyBucket.sourceIpCount) || 0);
      bucket.methods.set(method, (bucket.methods.get(method) || 0) + total);
    });
  } else {
    events.forEach((event) => {
      const timestamp = eventTimestampMs(event);
      if (!Number.isFinite(timestamp) || timestamp < start || timestamp >= end) return;
      const bucketIndex = Math.min(23, Math.max(0, Math.floor((timestamp - start) / HOUR_MS)));
      const bucket = buckets[bucketIndex];
      const method = attackBehavior(event).name;
      bucket.total += 1;
      if (effectiveSeverity(event) === "high") bucket.high += 1;
      if (isKnown(event.srcIp)) bucket.sourceIps.add(event.srcIp);
      bucket.methods.set(method, (bucket.methods.get(method) || 0) + 1);
    });
  }

  const normalizedBuckets = buckets.map((bucket) => {
    const topMethod = [...bucket.methods.entries()]
      .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))[0];
    return {
      index: bucket.index,
      hour: bucket.hour,
      label: bucket.label,
      total: bucket.total,
      high: bucket.high,
      sourceCount: Math.max(bucket.sourceCount || 0, bucket.sourceIps.size),
      topMethod: topMethod?.[0] || "无事件",
    };
  });
  const total = normalizedBuckets.reduce((sum, bucket) => sum + bucket.total, 0);
  const highTotal = normalizedBuckets.reduce((sum, bucket) => sum + bucket.high, 0);
  const activeHours = normalizedBuckets.filter((bucket) => bucket.total > 0).length;
  const peak = normalizedBuckets.reduce(
    (best, bucket) => (bucket.total > best.total ? bucket : best),
    normalizedBuckets[0]
  );
  const yTicks = buildYAxisTicks(Math.max(...normalizedBuckets.map((bucket) => bucket.total)), 5);
  const yMax = yTicks[yTicks.length - 1] || 1;

  return {
    activeHours,
    buckets: normalizedBuckets,
    dateLabel: useDateRange ? formatBeijingDateLabel(start) : "过去 24 小时",
    highTotal,
    maxTotal: yMax,
    mode,
    peak,
    rangeLabel: useDateRange
      ? `${formatBeijingDateLabel(start)} 00:00 - 23:59`
      : `${formatBeijingDateTimeCompact(start)} - ${formatBeijingDateTimeCompact(end - HOUR_MS)}`,
    selectedDate: useDateRange ? formatBeijingDateInput(start) : formatBeijingDateInput(anchor),
    source: usingHistoryTrend ? "history" : "events",
    total,
    yTicks,
  };
}

function formatSecondsCompact(value) {
  const seconds = Number(value);
  if (!Number.isFinite(seconds)) return "等待";
  if (seconds < 60) return `${Math.max(0, Math.round(seconds))}s`;
  const minutes = Math.floor(seconds / 60);
  const remain = Math.round(seconds % 60);
  return `${minutes}m ${remain}s`;
}

function formatSnapshotTime(value) {
  const date = new Date(value || "");
  return Number.isNaN(date.getTime()) ? "等待快照" : date.toLocaleString("zh-CN", { hour12: false });
}

function timeSourceLabel(source) {
  const value = String(source || "");
  const labels = {
    timestamp: "timestamp",
    event_time_utc: "event_time_utc",
    utc_time: "utc_time",
    "@timestamp": "@timestamp",
    event_time: "event_time",
    event_time_local: "event_time_local",
    local_time_adjusted: "local_time_adjusted",
    local_time: "local_time",
    time: "time",
    datetime: "datetime",
    created_at: "created_at",
    log_time: "log_time",
    fallback_now: "旧版兜底当前时间",
    missing: "缺失时间字段",
  };
  if (labels[value]) return labels[value];
  if (value.startsWith("payload.")) return `payload.${value.slice(8)}`;
  if (value.startsWith("raw.")) return `raw.${value.slice(4)}`;
  return displayValue(value, "未知来源");
}

function beijingPartitionPath(timestamp) {
  if (!Number.isFinite(timestamp)) return "/honeypot/dwd/events/dt=unknown/hour=unknown";
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: BEIJING_TIME_ZONE,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    hourCycle: "h23",
  }).formatToParts(new Date(timestamp));
  const value = (type) => parts.find((part) => part.type === type)?.value || "00";
  return `/honeypot/dwd/events/dt=${value("year")}-${value("month")}-${value("day")}/hour=${value("hour")}`;
}

function buildTimeNormalizationStats(events, snapshot) {
  const total = events.length;
  const normalizedEvents = events.filter((event) => event.timeNormalized !== false && Number.isFinite(Number(event.eventTsMs ?? event.timestamp)));
  const fallbackCount = Math.max(0, total - normalizedEvents.length);
  const timestamps = events
    .map((event) => Number(event.eventTsMs ?? event.timestamp))
    .filter((timestamp) => Number.isFinite(timestamp));
  const latest = timestamps.length ? Math.max(...timestamps) : null;
  const earliest = timestamps.length ? Math.min(...timestamps) : null;
  const sourceCounts = events.reduce((counter, event) => {
    const key = timeSourceLabel(event.eventTimeSource);
    counter.set(key, (counter.get(key) || 0) + 1);
    return counter;
  }, new Map());
  const generatedAt = new Date(snapshot.generatedAt || snapshot.lastUpdated).getTime();
  const latencySeconds = Number.isFinite(generatedAt) && latest ? Math.max(0, Math.round((generatedAt - latest) / 1000)) : null;

  return {
    total,
    normalized: normalizedEvents.length,
    fallbackCount,
    coverage: total ? Math.round((normalizedEvents.length / total) * 100) : 0,
    earliest,
    latest,
    latencySeconds,
    partition: beijingPartitionPath(latest || generatedAt),
    sourceCounts: [...sourceCounts.entries()]
      .map(([source, count]) => ({ source, count, rate: total ? Math.round((count / total) * 100) : 0 }))
      .sort((left, right) => right.count - left.count || left.source.localeCompare(right.source)),
  };
}

function formatDelta(change) {
  if (change === "动态") return "动态";
  const numeric = Number(String(change ?? "").replace("%", ""));
  if (!Number.isFinite(numeric)) return displayValue(change, "未知");
  if (numeric === 0) return "持平";
  return numeric > 0 ? `↑ ${numeric}%` : `↓ ${Math.abs(numeric)}%`;
}

function joinKnown(parts, fallback = "未归因") {
  const text = parts.filter(isKnown).join(" / ");
  return text || fallback;
}

function tryParseJson(value) {
  if (!isKnown(value)) return null;
  if (typeof value === "object") return value;
  const text = String(value).trim();
  if (!text.startsWith("{") && !text.startsWith("[")) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function valueToText(value) {
  if (value === null || value === undefined || value === "") return "unknown";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function payloadFieldLabel(key) {
  return payloadFieldLabels[key] || key;
}

function payloadFieldValue(key, value) {
  const text = valueToText(value);
  if (!isKnown(text)) return "空值";
  if (key === "VNC Password" && /not in the common list/i.test(text)) {
    return "未命中常见口令字典";
  }
  return text;
}

function payloadFieldRank(key) {
  const index = payloadFieldPriority.indexOf(key);
  return index === -1 ? payloadFieldPriority.length + 1 : index;
}

function structuredFields(value, maxItems = 10) {
  const parsed = tryParseJson(value);
  if (!parsed || Array.isArray(parsed)) return [];
  const nestedLogdata = parsed.logdata && typeof parsed.logdata === "object" && !Array.isArray(parsed.logdata)
    ? Object.entries(parsed.logdata)
    : [];
  const entries = [
    ...nestedLogdata,
    ...Object.entries(parsed).filter(([key]) => key !== "logdata"),
  ];
  const seen = new Set();
  return entries
    .map(([key, nestedValue], index) => ({ key, nestedValue, index }))
    .filter(({ key }) => {
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    })
    .sort((left, right) => payloadFieldRank(left.key) - payloadFieldRank(right.key) || left.index - right.index)
    .slice(0, maxItems)
    .map(({ key, nestedValue }) => [payloadFieldLabel(key), payloadFieldValue(key, nestedValue)]);
}

const payloadLineKeys = [
  "payload",
  "raw_payload",
  "request",
  "request_line",
  "http_request",
  "body",
  "message",
  "input",
  "command",
  "cmd",
  "data",
  "query",
  "uri",
  "url",
  "path",
];

const evidenceKeyLabels = {
  username: "登录用户名",
  user: "登录用户名",
  login: "登录用户名",
  password: "尝试密码",
  pass: "尝试密码",
  command: "命令输入",
  cmd: "命令输入",
  input: "输入内容",
  payload: "Payload",
  raw_payload: "Payload",
  raw: "Payload",
  request: "HTTP 请求",
  request_line: "HTTP 请求行",
  http_request: "HTTP 请求",
  body: "请求正文",
  message: "消息内容",
  query: "查询参数",
  uri: "请求路径",
  url: "请求 URL",
  path: "请求路径",
  user_agent: "User-Agent",
  http_user_agent: "User-Agent",
  "User-Agent": "User-Agent",
  "VNC Password": "VNC 口令判断",
  "VNC Client Response": "VNC 客户端响应",
  "VNC Server Challenge": "VNC 服务端挑战",
};

const evidencePriorityKeys = [
  "username",
  "user",
  "login",
  "password",
  "pass",
  "command",
  "cmd",
  "input",
  "payload",
  "raw_payload",
  "request",
  "request_line",
  "http_request",
  "body",
  "message",
  "query",
  "uri",
  "url",
  "path",
  "user_agent",
  "http_user_agent",
  "User-Agent",
  "VNC Password",
  "VNC Client Response",
  "VNC Server Challenge",
];

const regexEvidenceKeys = [...evidencePriorityKeys, "raw"];

function evidenceLabel(key) {
  return evidenceKeyLabels[key] || payloadFieldLabel(key);
}

function normalizeEvidenceText(value) {
  const extracted = evidenceTextValue(value);
  if (!isKnown(extracted) || isMetadataDump(extracted)) return "";
  const unescaped = extracted.replace(/\\r/g, "\r").replace(/\\n/g, "\n").replace(/\\t/g, "\t").trim();
  const replacementCount = (unescaped.match(/\uFFFD/g) || []).length;
  const visibleCount = [...unescaped].filter((char) => /[\p{L}\p{N}\p{P}\p{S}\s]/u.test(char) && char !== "\uFFFD").length;
  const readableRatio = unescaped.length ? visibleCount / unescaped.length : 1;
  if (replacementCount >= 2 || readableRatio < 0.72) {
    return "二进制/加密握手 payload（不可读文本）";
  }
  return unescaped.replace(/\s+/g, " ");
}

function addEvidenceItem(items, seen, label, value, maxLength = 280) {
  const text = normalizeEvidenceText(value);
  if (!text) return;
  const compacted = compactText(text, maxLength);
  const signature = `${label}:${compacted.replace(/\s+/g, " ").trim().toLowerCase()}`;
  if (seen.has(signature)) return;
  seen.add(signature);
  items.push({ label, value: compacted });
}

function addEvidenceFromObject(items, seen, value, depth = 0) {
  if (!value || typeof value !== "object" || Array.isArray(value) || depth > 3) return;
  const logdata = value.logdata && typeof value.logdata === "object" && !Array.isArray(value.logdata) ? value.logdata : null;
  for (const key of evidencePriorityKeys) {
    if (Object.prototype.hasOwnProperty.call(value, key)) {
      addEvidenceItem(items, seen, evidenceLabel(key), value[key]);
    }
    if (logdata && Object.prototype.hasOwnProperty.call(logdata, key)) {
      addEvidenceItem(items, seen, evidenceLabel(key), logdata[key]);
    }
  }
  for (const nestedKey of ["payload_data", "detail", "event", "raw"]) {
    const nested = value[nestedKey];
    if (nested && typeof nested === "object") addEvidenceFromObject(items, seen, nested, depth + 1);
  }
}

function addEvidenceFromTextRecord(items, seen, value) {
  if (!isKnown(value) || typeof value !== "string") return;
  const text = value.trim();
  if (!text.startsWith("{") && !text.startsWith("[")) return;
  for (const key of regexEvidenceKeys) {
    const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const pattern = new RegExp(`["']${escaped}["']\\s*:\\s*(?:(["'])(.*?)\\1|([^,}\\n]+))`, "is");
    const match = text.match(pattern);
    const matchedValue = match?.[2] ?? match?.[3] ?? "";
    addEvidenceItem(items, seen, evidenceLabel(key), matchedValue);
  }
}

function extractPayloadLine(value, depth = 0) {
  if (!isKnown(value) || depth > 3) return "";

  if (Array.isArray(value)) {
    return value.map((item) => extractPayloadLine(item, depth + 1)).find(isKnown) || "";
  }

  if (typeof value === "object") {
    for (const key of payloadLineKeys) {
      if (Object.prototype.hasOwnProperty.call(value, key)) {
        const extracted = extractPayloadLine(value[key], depth + 1);
        if (isKnown(extracted)) return extracted;
      }
    }
    for (const key of ["logdata", "payload_data", "raw", "event", "detail"]) {
      if (Object.prototype.hasOwnProperty.call(value, key)) {
        const extracted = extractPayloadLine(value[key], depth + 1);
        if (isKnown(extracted)) return extracted;
      }
    }
    return "";
  }

  const text = String(value).trim();
  if (!isKnown(text)) return "";

  const parsed = tryParseJson(text);
  if (parsed) return extractPayloadLine(parsed, depth + 1);

  if (/^\s*[{[]/.test(text)) {
    for (const key of payloadLineKeys) {
      const pattern = new RegExp(`["']${key}["']\\s*:\\s*(["'])(.*?)\\1`, "is");
      const match = text.match(pattern);
      if (match?.[2] && isKnown(match[2])) return match[2].replace(/\\n/g, " ").trim();
    }
    return "";
  }

  return text;
}

function eventPayloadLine(event, fallback = "无 payload") {
  const candidates = [
    event?.payload,
    event?.command,
    event?.raw,
  ];
  for (const candidate of candidates) {
    const extracted = extractPayloadLine(candidate);
    if (isKnown(extracted)) return compactText(extracted, 260);
  }
  return fallback;
}

function eventEvidenceItems(event, maxItems = 8) {
  const items = [];
  const seen = new Set();
  addEvidenceItem(items, seen, "登录用户名", event?.username);
  addEvidenceItem(items, seen, "尝试密码", event?.password);
  addEvidenceItem(items, seen, "命令输入", event?.command);

  for (const value of [event?.payload, event?.raw]) {
    if (value && typeof value === "object") {
      addEvidenceFromObject(items, seen, value);
    } else {
      addEvidenceFromTextRecord(items, seen, value);
    }
    const line = extractPayloadLine(value);
    if (isKnown(line)) addEvidenceItem(items, seen, "Payload", line);
  }

  return items.slice(0, maxItems);
}

function eventEvidenceLine(event, fallback = "") {
  const items = eventEvidenceItems(event, 4);
  if (!items.length) return fallback;
  return items.map((item) => `${item.label}: ${item.value}`).join("；");
}

function attackMethodDefinition(key) {
  return attackMethodByKey.get(key) || attackMethodByKey.get("protocol_probe");
}

function methodLabel(key) {
  if (key === "ALL") return "全部攻击方式";
  return attackMethodDefinition(key)?.name || key;
}

function eventText(event) {
  return [
    event.protocol,
    event.eventType,
    event.detail,
    event.payload,
    event.raw,
    event.command,
    event.username,
    event.password,
    event.dstPort,
  ].filter(isKnown).join(" ").toLowerCase();
}

function hasCredentialSignal(event, text = eventText(event)) {
  return (
    isKnown(event.username) ||
    isKnown(event.password) ||
    /login|auth|password|credential|username|userauth|failed password|login_success|login_failed/.test(text)
  );
}

function hasCommandSignal(event, text = eventText(event)) {
  return isKnown(event.command) || /command_input|command_failed|not a command|shell command|input command/.test(text);
}

function hasPayloadDeliverySignal(text) {
  return /file_download|wget|curl|tftp|ftpget|busybox|chmod|\.sh\b|\/bin\/|powershell|base64|nc\s+-|bash\s+-c|sh\s+-c/.test(text);
}

function inferServiceHint(protocol, eventType, text, event) {
  if (["SSH", "TELNET", "RDP", "VNC", "FTP", "MYSQL", "POSTGRES", "MSSQL", "ORACLE", "MONGODB", "REDIS", "MQTT", "SMB", "HTTP", "HTTP_ALT", "HTTPS_ALT"].includes(protocol)) {
    return protocol;
  }
  const protocolPort = /^TCP_(\d+)$/i.exec(protocol)?.[1];
  const port = String(event.dstPort || event.destPort || event.destinationPort || event.port || protocolPort || "");
  if (/mongodb/.test(eventType + text) || port === "27017") return "MONGODB";
  if (/mysql/.test(eventType + text) || port === "3306") return "MYSQL";
  if (/postgres/.test(eventType + text) || port === "5432") return "POSTGRES";
  if (/mssql/.test(eventType + text) || port === "1433") return "MSSQL";
  if (/oracle|tns/.test(eventType + text) || port === "1521") return "ORACLE";
  if (/redis/.test(eventType + text) || port === "6379") return "REDIS";
  if (/vnc/.test(eventType + text) || /^590\d$/.test(port)) return "VNC";
  if (/ssh/.test(eventType + text) || port === "22") return "SSH";
  if (/telnet/.test(eventType + text) || ["23", "2323"].includes(port)) return "TELNET";
  if (/rdp/.test(eventType + text) || port === "3389") return "RDP";
  if (/ftp/.test(eventType + text) || port === "21") return "FTP";
  if (/mqtt/.test(eventType + text) || port === "1883") return "MQTT";
  if (/smb/.test(eventType + text) || ["139", "445"].includes(port)) return "SMB";
  if (/https?|http_request|user-agent|host:|uri|path|get\s+|post\s+|head\s+/.test(eventType + text) || ["80", "443", "8000", "8080", "8081", "8443"].includes(port)) return "HTTP";
  return protocol;
}

function buildAttackBehavior(key, event, evidence = []) {
  const method = attackMethodDefinition(key);
  const protocol = displayValue(event.protocol, "UNKNOWN");
  const port = isKnown(event.dstPort) ? `端口 ${event.dstPort}` : "";
  const baseEvidence = evidence.length ? evidence : [method.description];
  return {
    ...method,
    protocol,
    evidence: [...baseEvidence, port].filter(isKnown).slice(0, 4),
  };
}

function attackBehavior(event) {
  const protocol = String(event.protocol || "").toUpperCase();
  const eventType = String(event.eventType || "").toLowerCase();
  const text = eventText(event);
  const credentialSignal = hasCredentialSignal(event, text);
  const commandSignal = hasCommandSignal(event, text);
  const payloadDelivery = hasPayloadDeliverySignal(text);
  const serviceHint = inferServiceHint(protocol, eventType, text, event);

  if (payloadDelivery) {
    return buildAttackBehavior("payload_delivery", event, ["下载/执行链特征", compactText(event.command || event.detail || event.payload || event.raw, 64)]);
  }
  if (commandSignal) {
    return buildAttackBehavior("command_execution", event, ["命令输入或命令失败事件", compactText(event.command || event.detail || event.eventType, 64)]);
  }
  if (
    /(\bunion\b.+\bselect\b|information_schema|sleep\s*\(|benchmark\s*\(|or\s+1=1|['\"]\s*or\s*['\"]?1['\"]?=['\"]?1|sqlmap|xp_cmdshell|load_file\s*\()/i.test(text)
  ) {
    return buildAttackBehavior("sql_injection_probe", event, ["HTTP 参数命中 SQL 注入特征"]);
  }
  if (serviceHint === "VNC" && (/vnc_auth_attempt/.test(eventType) || /vnc password|vnc client response|vnc server challenge|challenge|response/.test(text))) {
    return buildAttackBehavior("vnc_bruteforce", event, ["VNC challenge/response 认证尝试", /not in the common list/.test(text) ? "口令未命中常见字典" : "捕获到 VNC 口令判断"]);
  }
  if (serviceHint === "SSH" && credentialSignal) {
    return buildAttackBehavior("ssh_bruteforce", event, ["SSH 登录/认证字段", compactText(`${event.username || ""}/${event.password || ""}`, 40)]);
  }
  if (serviceHint === "TELNET" && (/telnet_login/.test(eventType) || credentialSignal)) {
    return buildAttackBehavior("telnet_bruteforce", event, ["Telnet 登录事件或账号口令字段"]);
  }
  if (serviceHint === "FTP" && credentialSignal) {
    return buildAttackBehavior("ftp_bruteforce", event, ["FTP 登录或匿名访问尝试"]);
  }
  if (serviceHint === "RDP" && credentialSignal) {
    return buildAttackBehavior("rdp_bruteforce", event, ["RDP 登录或认证尝试"]);
  }
  if (["MYSQL", "POSTGRES", "MSSQL", "ORACLE", "MONGODB"].includes(serviceHint)) {
    return buildAttackBehavior(credentialSignal ? "db_login_probe" : "db_service_probe", event, [
      credentialSignal ? "数据库登录/认证字段" : "数据库端口连接或握手",
      serviceHint,
    ]);
  }
  if (serviceHint === "REDIS") {
    return buildAttackBehavior("redis_command_probe", event, [/info|auth|config|set|slaveof|replicaof|flushall/.test(text) ? "Redis 命令特征" : "Redis 端口探测"]);
  }
  if (["HTTP", "HTTP_ALT", "HTTPS_ALT"].includes(serviceHint) || /http|host:|user-agent|uri|path|GET\s+|POST\s+|HEAD\s+/.test(text)) {
    if (/connect\s+|proxy|absolute-uri|forwarded|x-forwarded/.test(text)) {
      return buildAttackBehavior("http_proxy_probe", event, ["HTTP 代理/转发测试特征"]);
    }
    if (/\/\.env|wp-login|phpmyadmin|boaform|cgi-bin|manager\/html|shell|cmd=|exec=|cve-|jenkins|solr|actuator|\.git|passwd/.test(text)) {
      return buildAttackBehavior("web_vuln_scan", event, ["敏感路径、后台或漏洞扫描特征"]);
    }
    return buildAttackBehavior("http_fingerprint", event, ["HTTP 请求头或路径探测"]);
  }
  if (serviceHint === "MQTT") {
    return buildAttackBehavior("mqtt_probe", event, ["MQTT 物联网消息入口探测"]);
  }
  if (serviceHint === "SMB") {
    return buildAttackBehavior("smb_probe", event, ["SMB 文件共享入口探测"]);
  }
  if (["SSH", "TELNET", "RDP", "VNC", "FTP"].includes(serviceHint)) {
    return buildAttackBehavior("remote_login_probe", event, [`${serviceHint} 连接/握手探测`]);
  }
  if (protocol.startsWith("TCP_") || /connect|connection|open|scan|probe/.test(eventType + text)) {
    return buildAttackBehavior("tcp_port_scan", event, ["连接打开或扩展 TCP 端口命中"]);
  }
  return buildAttackBehavior("protocol_probe", event, ["未命中更具体规则，保留为服务指纹探测"]);
}

function effectiveSeverity(event) {
  const methodSeverity = attackBehavior(event).severity || "low";
  const eventSeverity = event.severity || "low";
  return severityWeight[methodSeverity] > severityWeight[eventSeverity] ? methodSeverity : eventSeverity;
}

function eventVisualColor(event) {
  return attackBehavior(event).color || "#20d9ff";
}

function buildAttackMethodStats(events) {
  const methodMap = new Map();
  events.forEach((event) => {
    const method = attackBehavior(event);
    const current = methodMap.get(method.key) || {
      ...method,
      total: 0,
      live: 0,
      highCount: 0,
      sources: new Set(),
      protocols: new Set(),
      examples: [],
    };
    current.total += 1;
    current.live += 1;
    if (effectiveSeverity(event) === "high") current.highCount += 1;
    if (isKnown(event.srcIp)) current.sources.add(event.srcIp);
    if (isKnown(event.protocol)) current.protocols.add(event.protocol);
    if (current.examples.length < 2) current.examples.push(compactText(event.detail || event.eventType || method.description, 56));
    methodMap.set(method.key, current);
  });

  return [...methodMap.values()]
    .map((method) => ({
      ...method,
      sourceCount: method.sources.size,
      protocolCount: method.protocols.size,
      protocols: [...method.protocols],
      description: `${method.description}；${method.sourceCount || method.sources.size} 个源 IP`,
    }))
    .sort((left, right) => right.total - left.total || severityWeight[right.severity] - severityWeight[left.severity] || left.name.localeCompare(right.name));
}

function buildHistoryAttackMethodStats(historyTrend, {
  anchorTime,
  highOnly = false,
  rangeKey = "all",
} = {}) {
  if (!historyTrend) return [];
  const hourly = Array.isArray(historyTrend.hourly) ? historyTrend.hourly : [];
  const daily = Array.isArray(historyTrend.daily) ? historyTrend.daily : [];
  const bounds = buildMapRangeBounds(rangeKey, anchorTime);
  const useHourly = hourly.length && Number.isFinite(bounds.startMs) && Number.isFinite(bounds.endMs);
  const rows = useHourly ? hourly : daily.length ? daily : hourly;
  if (!rows.length) return [];

  const totals = new Map();
  const highTotals = new Map();
  rows.forEach((bucket) => {
    if (Number.isFinite(bounds.startMs) && Number.isFinite(bounds.endMs)) {
      const timestamp = historyBucketTimestamp(bucket);
      if (!Number.isFinite(timestamp) || timestamp < bounds.startMs || timestamp > bounds.endMs) return;
    }

    const methodCounts = highOnly ? bucket.methodHighCounts : bucket.methodCounts;
    Object.entries(methodCounts || {}).forEach(([key, count]) => {
      const numeric = Number(count);
      if (!key || !Number.isFinite(numeric) || numeric <= 0) return;
      totals.set(key, (totals.get(key) || 0) + numeric);
    });

    Object.entries(bucket.methodHighCounts || {}).forEach(([key, count]) => {
      const numeric = Number(count);
      if (!key || !Number.isFinite(numeric) || numeric <= 0) return;
      highTotals.set(key, (highTotals.get(key) || 0) + numeric);
    });
  });

  return [...totals.entries()]
    .map(([key, total]) => {
      const definition = attackMethodDefinition(key);
      return {
        ...definition,
        key,
        name: historyTrend.methodNames?.[key] || definition.name || key,
        total,
        live: 0,
        highCount: highOnly ? total : (highTotals.get(key) || 0),
        sourceCount: undefined,
        protocolCount: undefined,
        protocols: [],
        examples: [],
        description: `${definition.description || "历史聚合攻击方式"}；历史聚合口径`,
        delta: "历史",
      };
    })
    .sort((left, right) => right.total - left.total || severityWeight[right.severity] - severityWeight[left.severity] || left.name.localeCompare(right.name));
}

function detectorAttackMethodStats(snapshot, events, {
  activeProtocol = "ALL",
  highOnly = false,
  mapTimeRange = "all",
  query = "",
} = {}) {
  const canUseHistory = activeProtocol === "ALL" && !query.trim();
  if (canUseHistory && !highOnly && snapshot.attackMethodStats?.length && historyTimeRangeCoversAll(snapshot.historyTrend, mapTimeRange, snapshot.generatedAt || snapshot.lastUpdated)) {
    return snapshot.attackMethodStats;
  }

  if (canUseHistory && mapTimeRange !== "live") {
    const historyMethods = buildHistoryAttackMethodStats(snapshot.historyTrend, {
      anchorTime: snapshot.generatedAt || snapshot.lastUpdated,
      highOnly,
      rangeKey: mapTimeRange,
    });
    if (historyMethods.length) return historyMethods;
  }

  return buildAttackMethodStats(events);
}

function exportTimestamp() {
  return new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
}

function csvCell(value) {
  const text = Array.isArray(value) ? value.join("|") : valueToText(value);
  return `"${text.replace(/"/g, '""')}"`;
}

function coordinateValue(coordinates, index) {
  return hasUsableCoordinates(coordinates) ? coordinates[index] : "unknown";
}

function buildCsv(rows, columns) {
  const header = columns.map((column) => csvCell(column.label)).join(",");
  const body = rows.map((row) => columns.map((column) => csvCell(column.value(row))).join(",")).join("\n");
  return `\ufeff${header}\n${body}`;
}

function markdownCell(value) {
  return valueToText(value)
    .replace(/\|/g, "\\|")
    .replace(/\r?\n/g, " ")
    .trim();
}

function buildMarkdownTable(headers, rows) {
  if (!rows.length) return "暂无数据";
  const header = `| ${headers.map(markdownCell).join(" | ")} |`;
  const divider = `| ${headers.map(() => "---").join(" | ")} |`;
  const body = rows.map((row) => `| ${row.map(markdownCell).join(" | ")} |`).join("\n");
  return `${header}\n${divider}\n${body}`;
}

function downloadTextFile(filename, content, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function downloadUrlFile(url, filename) {
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.rel = "noopener";
  document.body.appendChild(link);
  link.click();
  link.remove();
}

function sourceRowsForExport(snapshot, events = snapshot.events) {
  const sourceByIp = new Map(snapshot.sourceStats.map((source) => [source.srcIp, source]));
  const rows = new Map();
  events.forEach((event) => {
    const base = sourceByIp.get(event.srcIp) || {
      srcIp: event.srcIp,
      country: event.country,
      region: event.region,
      city: event.city,
      isp: event.isp,
      asn: event.asn,
      total: 0,
      eventTotal: 0,
      riskScore: 0,
    };
    if (!rows.has(event.srcIp)) {
      rows.set(event.srcIp, {
        ...base,
        events: 0,
        highEvents: 0,
        filteredProtocols: new Set(),
        filteredMethods: new Set(),
      });
    }
    const current = rows.get(event.srcIp);
    if (!hasUsableCoordinates(current.coordinates) && hasUsableCoordinates(event.sourceCoordinates)) {
      current.coordinates = event.sourceCoordinates;
    }
    current.events += 1;
    if (effectiveSeverity(event) === "high") current.highEvents += 1;
    current.filteredProtocols.add(event.protocol);
    current.filteredMethods.add(attackBehavior(event).name);
  });

  return [...rows.values()]
    .map(({ filteredProtocols, filteredMethods, ...source }) => ({
      ...source,
      protocolCount: filteredProtocols.size,
      protocols: [...filteredProtocols],
      methodCount: filteredMethods.size,
      attackMethods: [...filteredMethods],
      windowRiskScore: source.events + source.highEvents * 500 + filteredMethods.size * 160 + filteredProtocols.size * 70,
      score: source.riskScore ?? source.score ?? 0,
    }))
    .sort((a, b) => b.events - a.events || (b.eventTotal ?? b.total ?? 0) - (a.eventTotal ?? a.total ?? 0));
}

function allSourceRowsForExport(snapshot, events = snapshot.events) {
  const windowRows = new Map(sourceRowsForExport(snapshot, events).map((source) => [source.srcIp, source]));
  return snapshot.sourceStats
    .map((source) => {
      const windowSource = windowRows.get(source.srcIp);
      return {
        ...source,
        events: windowSource?.events || 0,
        highCurrentEvents: windowSource?.highEvents || 0,
        highEvents: source.highEvents ?? 0,
        filteredProtocols: windowSource?.protocols || [],
        filteredMethods: windowSource?.attackMethods || [],
        filteredProtocolCount: windowSource?.protocolCount || 0,
        filteredMethodCount: windowSource?.methodCount || 0,
        filteredRiskScore: windowSource?.windowRiskScore || 0,
      };
    })
    .sort((a, b) => (b.eventTotal ?? b.total ?? 0) - (a.eventTotal ?? a.total ?? 0) || (b.riskScore ?? 0) - (a.riskScore ?? 0));
}

function eventFallbackValue(event, keys, fallback = "unknown") {
  const raw = event?.raw && typeof event.raw === "object" ? event.raw : {};
  for (const key of keys) {
    const value = event?.[key] ?? raw?.[key];
    if (isKnown(value)) return value;
  }
  return fallback;
}

function eventTimestampValue(event) {
  const value = Number(event?.eventTsMs ?? event?.timestamp);
  return Number.isFinite(value) ? value : Number.NaN;
}

function eventUtcValue(event) {
  if (isKnown(event?.eventTimeUtc)) return event.eventTimeUtc;
  const timestamp = eventTimestampValue(event);
  return Number.isFinite(timestamp) ? new Date(timestamp).toISOString() : "unknown";
}

function eventBeijingValue(event) {
  if (isKnown(event?.eventTimeLocal)) return event.eventTimeLocal;
  const timestamp = eventTimestampValue(event);
  return Number.isFinite(timestamp) ? formatEventClock(timestamp) : "unknown";
}

const EVENT_CSV_FIELD_GROUPS = [
  {
    key: "identity",
    label: "IP 与会话",
    fields: [
      { key: "source_ip", label: "source_ip", value: (event) => event.srcIp },
      { key: "dst_ip", label: "dst_ip", value: (event) => event.destinationIp || event.dstIp || event.honeypotIp },
      { key: "src_port", label: "src_port", value: (event) => event.srcPort },
      { key: "dst_port", label: "dst_port", value: (event) => event.dstPort },
      { key: "session_id", label: "session_id", value: (event) => eventFallbackValue(event, ["sessionId", "session", "session_id"]) },
    ],
  },
  {
    key: "geo",
    label: "地理位置",
    fields: [
      { key: "country", label: "country", value: (event) => event.country },
      { key: "region", label: "region", value: (event) => event.region },
      { key: "city", label: "city", value: (event) => event.city },
      { key: "isp", label: "isp", value: (event) => event.isp },
      { key: "asn", label: "asn", value: (event) => event.asn },
      { key: "latitude", label: "latitude", value: (event) => coordinateValue(event.sourceCoordinates, 1) },
      { key: "longitude", label: "longitude", value: (event) => coordinateValue(event.sourceCoordinates, 0) },
    ],
  },
  {
    key: "traffic",
    label: "流量数据",
    fields: [
      { key: "protocol", label: "protocol", value: (event) => event.protocol },
      { key: "service", label: "service", value: (event) => eventFallbackValue(event, ["service", "app", "application"]) },
      { key: "bytes_in", label: "bytes_in", value: (event) => eventFallbackValue(event, ["bytesIn", "bytes_in", "request_bytes"]) },
      { key: "bytes_out", label: "bytes_out", value: (event) => eventFallbackValue(event, ["bytesOut", "bytes_out", "response_bytes"]) },
      { key: "packet_count", label: "packet_count", value: (event) => eventFallbackValue(event, ["packetCount", "packet_count", "packets"]) },
      { key: "request_path", label: "request_path", value: (event) => eventFallbackValue(event, ["requestPath", "request_path", "path", "uri"]) },
      { key: "user_agent", label: "user_agent", value: (event) => eventFallbackValue(event, ["userAgent", "user_agent", "http_user_agent"]) },
    ],
  },
  {
    key: "behavior",
    label: "攻击行为",
    fields: [
      { key: "attack_method", label: "attack_method", value: (event) => attackBehavior(event).name },
      { key: "attack_method_key", label: "attack_method_key", value: (event) => attackBehavior(event).key },
      { key: "event_type", label: "event_type", value: (event) => event.eventType },
      { key: "severity", label: "severity", value: (event) => severityLabel[effectiveSeverity(event)] || effectiveSeverity(event) },
      { key: "username", label: "username", value: (event) => event.username },
      { key: "password", label: "password", value: (event) => event.password },
      { key: "command", label: "command", value: (event) => event.command },
      { key: "payload", label: "payload", value: (event) => event.payload || event.detail },
    ],
  },
  {
    key: "time",
    label: "时间字段",
    fields: [
      { key: "raw_time", label: "raw_time", value: (event) => event.eventTimeOriginal },
      { key: "event_time_utc", label: "event_time_utc", value: eventUtcValue },
      { key: "event_time_beijing", label: "event_time_beijing", value: eventBeijingValue },
      { key: "event_ts_ms", label: "event_ts_ms", value: (event) => event.eventTsMs ?? event.timestamp },
      { key: "event_time_source", label: "event_time_source", value: (event) => event.eventTimeSource },
    ],
  },
  {
    key: "honeypot",
    label: "蜜罐字段",
    fields: [
      { key: "honeypot_ip", label: "honeypot_ip", value: (event) => event.honeypotIp },
      { key: "honeypot_name", label: "honeypot_name", value: (event) => event.honeypot },
      { key: "sensor_type", label: "sensor_type", value: (event) => eventFallbackValue(event, ["sensorType", "sensor_type", "honeypotType"]) },
      { key: "log_source", label: "log_source", value: (event) => eventFallbackValue(event, ["logSource", "log_source", "source"]) },
    ],
  },
];

const EVENT_CSV_FIELD_LOOKUP = new Map(
  EVENT_CSV_FIELD_GROUPS.flatMap((group) => group.fields.map((field) => [field.key, field])),
);

const ALL_EVENT_CSV_FIELD_KEYS = EVENT_CSV_FIELD_GROUPS.flatMap((group) => group.fields.map((field) => field.key));
const COMMON_EVENT_CSV_FIELD_KEYS = [
  "event_time_beijing",
  "source_ip",
  "country",
  "region",
  "city",
  "isp",
  "asn",
  "protocol",
  "dst_port",
  "attack_method",
  "event_type",
  "severity",
  "username",
  "password",
  "command",
  "payload",
  "honeypot_ip",
  "honeypot_name",
];
function eventCsvColumnsFor(fieldKeys = COMMON_EVENT_CSV_FIELD_KEYS) {
  const keys = fieldKeys.filter((key, index, list) => EVENT_CSV_FIELD_LOOKUP.has(key) && list.indexOf(key) === index);
  const selectedKeys = keys.length ? keys : COMMON_EVENT_CSV_FIELD_KEYS;
  return selectedKeys.map((key) => EVENT_CSV_FIELD_LOOKUP.get(key));
}

function moveListItem(list, fromIndex, toIndex) {
  if (fromIndex < 0 || toIndex < 0 || fromIndex === toIndex || fromIndex >= list.length || toIndex >= list.length) {
    return list;
  }
  const next = [...list];
  const [item] = next.splice(fromIndex, 1);
  next.splice(toIndex, 0, item);
  return next;
}

function buildExportTimeRange(rangeKey, customRange = {}, anchorTime, events = []) {
  if (rangeKey === "all") {
    return { key: rangeKey, startMs: null, endMs: null, valid: true };
  }

  if (rangeKey === "custom") {
    const startMs = parseBeijingDateTimeInput(customRange.start);
    const endMs = parseBeijingDateTimeInput(customRange.end);
    return {
      key: rangeKey,
      startMs,
      endMs,
      valid: Number.isFinite(startMs) && Number.isFinite(endMs) && startMs < endMs,
    };
  }

  const rangeMs = {
    "24h": 24 * 60 * 60 * 1000,
    "7d": 7 * 24 * 60 * 60 * 1000,
    "30d": 30 * 24 * 60 * 60 * 1000,
  }[rangeKey];
  if (!rangeMs) {
    return { key: rangeKey, startMs: null, endMs: null, valid: true };
  }

  const parsedAnchor = Date.parse(anchorTime || "");
  const latest = latestEventTime(events);
  const endMs = Math.max(Number.isFinite(parsedAnchor) ? parsedAnchor : Date.now(), latest || 0);
  return {
    key: rangeKey,
    startMs: endMs - rangeMs,
    endMs,
    valid: true,
  };
}

function filterEventsByExportTimeRange(events, rangeBounds) {
  if (!Array.isArray(events)) return [];
  if (!rangeBounds?.valid) return [];
  if (!Number.isFinite(rangeBounds.startMs) || !Number.isFinite(rangeBounds.endMs)) return events;
  return events.filter((event) => {
    const ts = Number(event.eventTsMs ?? event.timestamp ?? Date.parse(event.eventTimeUtc || event.eventTimeLocal || ""));
    return Number.isFinite(ts) && ts >= rangeBounds.startMs && ts <= rangeBounds.endMs;
  });
}

function historyCountForExportRange(historyTrend, { activeMethod = "ALL", activeProtocol = "ALL", rangeBounds } = {}) {
  if (!historyTrend || !rangeBounds?.valid) return null;
  const daily = Array.isArray(historyTrend.daily) ? historyTrend.daily : [];
  const hourly = Array.isArray(historyTrend.hourly) ? historyTrend.hourly : [];
  const countBucket = (bucket) => historyCountForFilter(bucket, { activeMethod, activeProtocol });

  if (!Number.isFinite(rangeBounds.startMs) || !Number.isFinite(rangeBounds.endMs)) {
    const rows = daily.length ? daily : hourly;
    return rows.length ? rows.reduce((sum, bucket) => sum + countBucket(bucket), 0) : null;
  }

  if (hourly.length) {
    return hourly.reduce((sum, bucket) => {
      const timestamp = historyBucketTimestamp(bucket);
      if (!Number.isFinite(timestamp) || timestamp < rangeBounds.startMs || timestamp > rangeBounds.endMs) {
        return sum;
      }
      return sum + countBucket(bucket);
    }, 0);
  }

  if (daily.length) {
    return daily.reduce((sum, bucket) => {
      const dayStart = parseBeijingDateInput(bucket.date);
      const dayEnd = dayStart + DAY_MS;
      if (!Number.isFinite(dayStart) || dayEnd < rangeBounds.startMs || dayStart > rangeBounds.endMs) {
        return sum;
      }
      return sum + countBucket(bucket);
    }, 0);
  }

  return null;
}

function exportRangeDescription(rangeKey, rangeBounds) {
  if (rangeKey === "all") return "全部历史";
  if (!rangeBounds?.valid) return "请选择有效起止时间";
  return `${formatBeijingDateTimeCompact(rangeBounds.startMs)} - ${formatBeijingDateTimeCompact(rangeBounds.endMs)}`;
}

function incrementCounter(counter, key, amount = 1) {
  const normalizedKey = displayValue(key, "");
  if (!normalizedKey) return;
  counter.set(normalizedKey, (counter.get(normalizedKey) || 0) + amount);
}

function topCounterEntries(counter, limit = 4) {
  return [...counter.entries()]
    .map(([name, count]) => ({ name, count }))
    .sort((left, right) => right.count - left.count || left.name.localeCompare(right.name))
    .slice(0, limit);
}

function eventEvidenceText(event, fallback = "暂无载荷摘要") {
  const credential = [event.username, event.password].filter(isKnown).join(" / ");
  const fields = [
    event.command,
    credential,
    event.payload,
    event.detail,
    event.raw,
    event.eventType,
  ].filter(isKnown);
  return compactText(fields[0], 96) || fallback;
}

function buildAttackFamilyInsights(events) {
  const familyMap = new Map();

  events.filter((event) => isKnown(event.srcIp)).forEach((event) => {
    const method = attackBehavior(event);
    const family = familyMap.get(method.key) || {
      key: method.key,
      name: method.name,
      color: method.color || "#20d9ff",
      tactic: method.tactic,
      severity: method.severity,
      description: method.description,
      count: 0,
      highCount: 0,
      protocols: new Map(),
      countries: new Map(),
      cities: new Map(),
      honeypots: new Map(),
      evidence: new Map(),
      sources: new Map(),
      samples: [],
    };
    const srcIp = event.srcIp;
    const source = family.sources.get(srcIp) || {
      srcIp,
      count: 0,
      highCount: 0,
      country: displayValue(event.country, "位置未知"),
      region: displayValue(event.region, ""),
      city: displayValue(event.city, ""),
      isp: displayValue(event.isp, "unknown"),
      asn: displayValue(event.asn, "unknown"),
      protocols: new Map(),
      honeypots: new Map(),
      evidence: new Map(),
      firstSeen: null,
      lastSeen: null,
      samples: [],
    };
    const timestamp = eventTimestampMs(event);
    const honeypot = displayValue(event.honeypotLabel || event.honeypot || event.honeypotIp, "未知蜜罐");
    const protocol = displayValue(event.protocol, "UNKNOWN");
    const evidence = eventEvidenceText(event, method.evidence?.[0] || method.description);
    const severity = effectiveSeverity(event);

    family.count += 1;
    if (severity === "high") family.highCount += 1;
    incrementCounter(family.protocols, protocol);
    incrementCounter(family.countries, displayValue(event.country, "位置未知"));
    incrementCounter(family.cities, joinKnown([event.country, event.city], "位置未知"));
    incrementCounter(family.honeypots, honeypot);
    method.evidence?.forEach((item) => incrementCounter(family.evidence, item));
    incrementCounter(family.evidence, evidence);

    source.count += 1;
    if (severity === "high") source.highCount += 1;
    incrementCounter(source.protocols, protocol);
    incrementCounter(source.honeypots, honeypot);
    incrementCounter(source.evidence, evidence);
    source.country = displayValue(event.country, source.country);
    source.region = displayValue(event.region, source.region);
    source.city = displayValue(event.city, source.city);
    source.isp = displayValue(event.isp, source.isp);
    source.asn = displayValue(event.asn, source.asn);
    if (Number.isFinite(timestamp)) {
      source.firstSeen = source.firstSeen === null ? timestamp : Math.min(source.firstSeen, timestamp);
      source.lastSeen = source.lastSeen === null ? timestamp : Math.max(source.lastSeen, timestamp);
    }
    if (source.samples.length < 3) {
      source.samples.push({
        time: timestamp,
        protocol,
        honeypot,
        evidence,
      });
    }
    family.sources.set(srcIp, source);
    if (family.samples.length < 12) {
      family.samples.push({
        id: `${method.key}-${srcIp}-${family.count}`,
        time: timestamp,
        srcIp,
        location: joinKnown([event.country, event.city], "位置未知"),
        protocol,
        honeypot,
        severity,
        evidence,
        eventType: displayValue(event.eventType, "未知事件"),
      });
    }
    familyMap.set(method.key, family);
  });

  const families = [...familyMap.values()]
    .map((family) => {
      const sources = [...family.sources.values()]
        .map((source) => ({
          ...source,
          protocols: topCounterEntries(source.protocols, 3),
          honeypots: topCounterEntries(source.honeypots, 2),
          evidence: topCounterEntries(source.evidence, 2),
        }))
        .sort((left, right) => right.count - left.count || right.highCount - left.highCount || left.srcIp.localeCompare(right.srcIp));
      const samples = family.samples
        .slice()
        .sort((left, right) => (right.time || 0) - (left.time || 0))
        .slice(0, 5);
      return {
        ...family,
        sourceCount: sources.length,
        sources,
        topSources: sources.slice(0, 8),
        protocols: topCounterEntries(family.protocols, 4),
        countries: topCounterEntries(family.countries, 4),
        cities: topCounterEntries(family.cities, 4),
        honeypots: topCounterEntries(family.honeypots, 4),
        evidence: topCounterEntries(family.evidence, 4),
        samples,
        dominantProtocol: topCounterEntries(family.protocols, 1)[0]?.name || "UNKNOWN",
        dominantGeo: topCounterEntries(family.cities, 1)[0]?.name || "位置未知",
      };
    })
    .sort((left, right) =>
      right.count - left.count ||
      severityWeight[right.severity] - severityWeight[left.severity] ||
      left.name.localeCompare(right.name)
    );

  return {
    families,
    familyByKey: new Map(families.map((family) => [family.key, family])),
    totalEvents: events.length,
    totalSources: new Set(events.map((event) => event.srcIp).filter(isKnown)).size,
  };
}

function buildRelationInsights(events, allSourceStats = []) {
  const sourceMap = new Map();
  const methodMap = new Map();
  const relationMap = new Map();
  const honeypotMap = new Map();

  events.filter((event) => isKnown(event.srcIp)).forEach((event) => {
    const method = attackBehavior(event);
    const methodKey = method.key;
    const methodName = method.name;
    const honeypot = displayValue(event.honeypotLabel || event.honeypot || event.honeypotIp, "未知蜜罐");
    const source = sourceMap.get(event.srcIp) || {
      srcIp: event.srcIp,
      country: event.country,
      city: event.city,
      count: 0,
      highCount: 0,
      protocols: new Map(),
      methods: new Map(),
      honeypots: new Map(),
    };
    source.count += 1;
    if (effectiveSeverity(event) === "high") source.highCount += 1;
    source.protocols.set(displayValue(event.protocol, "UNKNOWN"), (source.protocols.get(displayValue(event.protocol, "UNKNOWN")) || 0) + 1);
    source.methods.set(methodKey, (source.methods.get(methodKey) || 0) + 1);
    source.honeypots.set(honeypot, (source.honeypots.get(honeypot) || 0) + 1);
    sourceMap.set(event.srcIp, source);

    const methodEntry = methodMap.get(methodKey) || {
      key: methodKey,
      name: methodName,
      color: method.color || "var(--cyan)",
      count: 0,
    };
    methodEntry.count += 1;
    methodMap.set(methodKey, methodEntry);

    const honeypotEntry = honeypotMap.get(honeypot) || {
      name: honeypot,
      count: 0,
      highCount: 0,
      protocols: new Set(),
      sources: new Set(),
    };
    honeypotEntry.count += 1;
    if (effectiveSeverity(event) === "high") honeypotEntry.highCount += 1;
    honeypotEntry.protocols.add(methodName);
    honeypotEntry.sources.add(event.srcIp);
    honeypotMap.set(honeypot, honeypotEntry);

    const relationKey = `${event.srcIp}|||${methodKey}|||${honeypot}`;
    const relation = relationMap.get(relationKey) || {
      sourceIp: event.srcIp,
      protocol: methodName,
      methodKey,
      honeypot,
      count: 0,
    };
    relation.count += 1;
    relationMap.set(relationKey, relation);
  });

  const sourceStats = [...sourceMap.values()].map((source) => ({
    ...source,
    protocolCount: source.protocols.size,
    methodCount: source.methods.size,
    honeypotCount: source.honeypots.size,
    topProtocol: [...source.methods.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([key]) => methodMap.get(key)?.name || key)[0] || "unknown",
  }));
  const sourceByIp = new Map(sourceStats.map((source) => [source.srcIp, source]));
  const topSources = [...sourceStats]
    .sort((left, right) => right.count - left.count || right.methodCount - left.methodCount)
    .slice(0, 6);
  const topProtocols = [...methodMap.values()].sort((left, right) => right.count - left.count).slice(0, 5);
  const topRelations = [...relationMap.values()].sort((left, right) => right.count - left.count);
  const topRelation = topRelations[0] || null;
  const widestSource = [...sourceStats]
    .sort((left, right) =>
      right.protocolCount - left.protocolCount ||
      right.honeypotCount - left.honeypotCount ||
      right.count - left.count
    )[0] || null;
  const matrixRows = topSources.map((source) => ({
    ...source,
    cells: topProtocols.map((protocol) => ({
      protocol: protocol.key,
      name: protocol.name,
      color: protocol.color,
      count: source.methods.get(protocol.key) || 0,
    })),
  }));
  const maxCell = Math.max(1, ...matrixRows.flatMap((row) => row.cells.map((cell) => cell.count)));
  const geoKnownCount = events.filter((event) => isKnown(event.srcIp) && isKnown(event.country)).length;
  const pathRows = topRelations.slice(0, 4).map((relation) => {
    const source = sourceByIp.get(relation.sourceIp);
    const crossProtocol = Number(source?.methodCount || 0) > 1;
    const crossHoneypot = Number(source?.honeypotCount || 0) > 1;
    const pattern = crossProtocol && crossHoneypot
      ? "多方式跨节点扫描"
      : crossProtocol
        ? "多方式探测"
        : crossHoneypot
          ? "跨节点扫描"
        : /弱口令|密码|凭据|口令/.test(relation.protocol)
            ? "同类认证攻击"
            : "单一攻击方式高频访问";
    return {
      ...relation,
      rate: events.length ? Math.round((relation.count / events.length) * 100) : 0,
      pattern,
    };
  });
  const honeypotRows = [...honeypotMap.values()]
    .map((honeypot) => ({
      name: honeypot.name,
      count: honeypot.count,
      rate: events.length ? Math.round((honeypot.count / events.length) * 100) : 0,
      sourceCount: honeypot.sources.size,
      protocolCount: honeypot.protocols.size,
      highCount: honeypot.highCount,
    }))
    .sort((left, right) => right.count - left.count || right.protocolCount - left.protocolCount)
    .slice(0, 3);
  const graphSources = allSourceStats.length ? allSourceStats : sourceStats;
  const attributionGraph = buildIpAttributionGraph(events, graphSources);

  return {
    eventCount: events.length,
    sourceCount: graphSources.length || sourceMap.size,
    protocolCount: methodMap.size,
    topProtocols,
    matrixRows,
    maxCell,
    topRelation,
    widestSource,
    pathRows,
    honeypotRows,
    attributionGraph,
    attributionEdgeCount: attributionGraph.links.length,
    attributionClusterCount: attributionGraph.clusters.length,
    topAttributionLink: attributionGraph.topLink,
    topAttributionCluster: attributionGraph.clusters[0] || null,
    strongestRelationRate: topRelation && events.length ? Math.round((topRelation.count / events.length) * 100) : 0,
    multiProtocolSourceCount: sourceStats.filter((source) => source.methodCount > 1).length,
    multiHoneypotSourceCount: sourceStats.filter((source) => source.honeypotCount > 1).length,
    geoKnownRatio: events.length ? Math.round((geoKnownCount / events.length) * 100) : 0,
  };
}

const attributionClusterColors = ["#20d9ff", "#a7f35a", "#ffcf58", "#ff6848", "#8b7cff", "#35d0aa"];
const attributionFeatureDefinitions = [
  { key: "patterns", label: "攻击模式", weight: 30, candidate: true, maxFanout: 220, strong: true },
  { key: "methods", label: "攻击方式", weight: 26, candidate: true, maxFanout: 180, strong: true },
  { key: "protocols", label: "协议背景", weight: 4, candidate: false },
  { key: "honeypots", label: "目标蜜罐", weight: 10, candidate: true, maxFanout: 90 },
  { key: "eventTypes", label: "事件类型", weight: 15, candidate: true, maxFanout: 110, strong: true },
  { key: "credentials", label: "账号口令", weight: 26, candidate: true, maxFanout: 180, strong: true },
  { key: "commands", label: "命令输入", weight: 28, candidate: true, maxFanout: 180, strong: true },
  { key: "payloadTokens", label: "Payload 特征", weight: 24, candidate: true, maxFanout: 150, strong: true },
  { key: "ports", label: "端口", weight: 10, candidate: true, maxFanout: 120, strong: true },
  { key: "stages", label: "攻击阶段", weight: 13, candidate: true, maxFanout: 150 },
  { key: "timeBuckets", label: "时间窗口", weight: 20, candidate: true, maxFanout: 240 },
  { key: "netblocks", label: "同 /24 网段", weight: 17, candidate: true, maxFanout: 120, strong: true },
  { key: "parentNetblocks", label: "同 /16 网段", weight: 6, candidate: true, maxFanout: 160 },
];
const strongAttributionFeatures = new Set(attributionFeatureDefinitions.filter((feature) => feature.strong).map((feature) => feature.key));
const familyEvidenceFeatures = new Set(["credentials", "commands", "payloadTokens", "netblocks", "asn", "isp"]);
const contextEvidenceFeatures = new Set(["methods", "protocols", "honeypots", "eventTypes", "ports", "stages", "timeBuckets", "parentNetblocks"]);
const ignoredPayloadTokens = new Set([
  "connection",
  "attempt",
  "requested",
  "password",
  "challenge",
  "unknown",
  "undefined",
  "null",
  "none",
  "http",
  "https",
  "host",
  "user-agent",
  "mozilla",
  "windows",
  "linux",
  "python",
  "curl",
  "wget",
]);

function addWeightedFeature(map, value, weight = 1) {
  if (!isKnown(value)) return;
  const key = String(value).trim().toLowerCase();
  if (!key || ignoredPayloadTokens.has(key)) return;
  map.set(key, (map.get(key) || 0) + weight);
}

function extractBehaviorTokens(...values) {
  const text = values.filter(isKnown).join(" ").toLowerCase();
  const tokens = text.match(/[a-z0-9_./:-]{3,}/g) || [];
  return [...new Set(tokens)]
    .filter((token) => !ignoredPayloadTokens.has(token) && !/^\d+$/.test(token) && token.length <= 64)
    .slice(0, 16);
}

function weightedJaccard(left = new Map(), right = new Map(), idf = new Map()) {
  if (!left.size || !right.size) return 0;
  const keys = new Set([...left.keys(), ...right.keys()]);
  let shared = 0;
  let union = 0;
  keys.forEach((key) => {
    const rarity = idf.get(key) || 1;
    const leftValue = left.get(key) || 0;
    const rightValue = right.get(key) || 0;
    shared += Math.min(leftValue, rightValue) * rarity;
    union += Math.max(leftValue, rightValue) * rarity;
  });
  return union ? shared / union : 0;
}

function sharedFeatureLabels(left = new Map(), right = new Map(), limit = 3, idf = new Map()) {
  return [...left.keys()]
    .filter((key) => right.has(key))
    .sort((a, b) =>
      Math.min(right.get(b), left.get(b)) * (idf.get(b) || 1) -
      Math.min(right.get(a), left.get(a)) * (idf.get(a) || 1) ||
      a.localeCompare(b)
    )
    .slice(0, limit)
    .map((value) => compactText(value, 24));
}

function sameKnownValue(left, right) {
  if (!isKnown(left) || !isKnown(right)) return 0;
  return String(left).trim().toLowerCase() === String(right).trim().toLowerCase() ? 1 : 0;
}

function buildIpProfiles(events) {
  const profileMap = new Map();
  events.filter((event) => isKnown(event.srcIp)).forEach((event) => {
    const srcIp = String(event.srcIp);
    const profile = profileMap.get(srcIp) || {
      srcIp,
      country: event.country,
      city: event.city,
      isp: event.isp,
      asn: event.asn,
      count: 0,
      highCount: 0,
      firstSeen: Number.POSITIVE_INFINITY,
      lastSeen: 0,
      protocols: new Map(),
      patterns: new Map(),
      methods: new Map(),
      honeypots: new Map(),
      eventTypes: new Map(),
      credentials: new Map(),
      commands: new Map(),
      payloadTokens: new Map(),
      ports: new Map(),
      stages: new Map(),
      timeBuckets: new Map(),
      netblocks: new Map(),
      parentNetblocks: new Map(),
    };
    const timestamp = Number(event.eventTsMs ?? event.timestamp);
    const honeypot = displayValue(event.honeypotLabel || event.honeypot || event.honeypotIp, "未知蜜罐");
    const protocol = displayValue(event.protocol, "UNKNOWN").toUpperCase();
    const method = attackBehavior(event);
    const stage = attackStageForEvent(event);
    const port = event.dstPort || event.srcPort;
    profile.count += 1;
    if (effectiveSeverity(event) === "high") profile.highCount += 1;
    if (Number.isFinite(timestamp)) {
      profile.firstSeen = Math.min(profile.firstSeen, timestamp);
      profile.lastSeen = Math.max(profile.lastSeen, timestamp);
      addWeightedFeature(profile.timeBuckets, `hour:${Math.floor(timestamp / 3600000)}`, 1);
      addWeightedFeature(profile.timeBuckets, `10m:${Math.floor(timestamp / 600000)}`, 0.7);
      addWeightedFeature(profile.patterns, `${method.name}|hour:${Math.floor(timestamp / 3600000)}`, 2);
    }
    addWeightedFeature(profile.protocols, protocol);
    addWeightedFeature(profile.methods, method.name, 2);
    addWeightedFeature(profile.honeypots, honeypot);
    addWeightedFeature(profile.eventTypes, event.eventType);
    addWeightedFeature(profile.ports, port);
    addWeightedFeature(profile.stages, stage);
    addWeightedFeature(profile.patterns, `${method.name}|${stage}`, 2);
    if (isKnown(port)) {
      addWeightedFeature(profile.patterns, `${method.name}|${protocol}|${port}`, 2);
    }
    addWeightedFeature(profile.netblocks, ipv4Prefix24(srcIp), 2);
    addWeightedFeature(profile.parentNetblocks, ipv4Prefix16(srcIp));
    if (isKnown(event.username) || isKnown(event.password)) {
      addWeightedFeature(profile.credentials, `${displayValue(event.username, "-")}/${displayValue(event.password, "-")}`, 2);
    }
    if (isKnown(event.command)) {
      addWeightedFeature(profile.commands, event.command, 3);
    }
    extractBehaviorTokens(event.command, event.payload, event.raw, event.detail, event.eventType).forEach((token) => {
      addWeightedFeature(profile.payloadTokens, token);
    });
    profileMap.set(srcIp, profile);
  });

  return [...profileMap.values()].map((profile) => ({
    ...profile,
    firstSeen: Number.isFinite(profile.firstSeen) ? profile.firstSeen : 0,
    protocolCount: profile.protocols.size,
    honeypotCount: profile.honeypots.size,
    signalCount:
      profile.protocols.size +
      profile.patterns.size +
      profile.methods.size +
      profile.honeypots.size +
      profile.eventTypes.size +
      profile.credentials.size +
      profile.commands.size +
      profile.payloadTokens.size +
      profile.netblocks.size +
      profile.parentNetblocks.size,
  }));
}

function ipv4Prefix24(ip) {
  const match = String(ip || "").match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\d{1,3}$/);
  if (!match) return "";
  return `${match[1]}.${match[2]}.${match[3]}.0/24`;
}

function ipv4Prefix16(ip) {
  const match = String(ip || "").match(/^(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}$/);
  if (!match) return "";
  return `${match[1]}.${match[2]}.0.0/16`;
}

function profileRank(profile) {
  return profile.count + profile.highCount * 6 + profile.signalCount * 2 + profile.protocolCount + profile.honeypotCount;
}

function buildFeatureIdf(profiles, featureDefinitions = attributionFeatureDefinitions) {
  const total = Math.max(1, profiles.length);
  return Object.fromEntries(featureDefinitions.map((definition) => {
    const counts = new Map();
    profiles.forEach((profile) => {
      const featureMap = profile[definition.key];
      if (!featureMap?.size) return;
      featureMap.forEach((_, key) => counts.set(key, (counts.get(key) || 0) + 1));
    });
    const idf = new Map([...counts.entries()].map(([key, count]) => [key, Math.log((total + 1) / (count + 1)) + 1]));
    return [definition.key, idf];
  }));
}

function pairKey(leftIp, rightIp) {
  return leftIp < rightIp ? `${leftIp}|||${rightIp}` : `${rightIp}|||${leftIp}`;
}

function buildIpSimilarityCandidatePairs(profiles, featureDefinitions = attributionFeatureDefinitions) {
  const candidates = new Map();
  featureDefinitions.filter((definition) => definition.candidate).forEach((definition) => {
    const valueIndex = new Map();
    profiles.forEach((profile) => {
      const featureMap = profile[definition.key];
      if (!featureMap?.size) return;
      featureMap.forEach((weight, value) => {
        if (!isKnown(value)) return;
        if (!valueIndex.has(value)) valueIndex.set(value, []);
        valueIndex.get(value).push({ profile, weight });
      });
    });

    valueIndex.forEach((rows) => {
      if (rows.length < 2) return;
      const cappedRows = rows
        .sort((left, right) => profileRank(right.profile) - profileRank(left.profile))
        .slice(0, definition.maxFanout || 100);
      const rarity = Math.log((profiles.length + 1) / (rows.length + 1)) + 1;
      for (let leftIndex = 0; leftIndex < cappedRows.length; leftIndex += 1) {
        for (let rightIndex = leftIndex + 1; rightIndex < cappedRows.length; rightIndex += 1) {
          const left = cappedRows[leftIndex];
          const right = cappedRows[rightIndex];
          const key = pairKey(left.profile.srcIp, right.profile.srcIp);
          const current = candidates.get(key) || 0;
          candidates.set(key, current + definition.weight * rarity * Math.min(2, Math.min(left.weight, right.weight)));
        }
      }
    });
  });
  return [...candidates.entries()]
    .sort((left, right) => right[1] - left[1])
    .slice(0, 12000)
    .map(([key]) => key);
}

function scoreIpSimilarity(left, right, idfByFeature = {}) {
  const featureScores = attributionFeatureDefinitions.map((definition) => {
    const idf = idfByFeature[definition.key] || new Map();
    return {
      ...definition,
      score: weightedJaccard(left[definition.key], right[definition.key], idf),
      examples: sharedFeatureLabels(left[definition.key], right[definition.key], definition.strong ? 3 : 2, idf),
    };
  });
  const asnScore = sameKnownValue(left.asn, right.asn);
  const ispScore = sameKnownValue(left.isp, right.isp);
  featureScores.push(
    { key: "asn", label: "ASN", weight: 3, score: asnScore, examples: asnScore ? [left.asn] : [] },
    { key: "isp", label: "ISP", weight: 2, score: ispScore, examples: ispScore ? [left.isp] : [] },
  );
  const weightTotal = featureScores.reduce((sum, item) => sum + item.weight, 0);
  const weighted = featureScores.reduce((sum, item) => sum + item.score * item.weight, 0);
  const score = Math.round((weighted / weightTotal) * 100);
  const evidence = featureScores
    .filter((item) => item.score >= 0.14 || (item.score === 1 && item.examples.length))
    .sort((leftItem, rightItem) => rightItem.score * rightItem.weight - leftItem.score * leftItem.weight)
    .slice(0, 4)
    .map((item) => ({
      key: item.key,
      label: item.label,
      score: Math.round(item.score * 100),
      examples: item.examples,
    }));
  const strongEvidenceCount = evidence.filter((item) => strongAttributionFeatures.has(item.key) && item.score >= 18).length;

  return {
    score,
    evidence,
    strongEvidenceCount,
    confidence: score >= 58 && strongEvidenceCount >= 2 ? "high" : score >= 36 && strongEvidenceCount >= 1 ? "medium" : "low",
  };
}

function evidenceKeySet(link) {
  return new Set((link.evidence || []).map((item) => item.key).filter(Boolean));
}

function familyAttributionRank(link) {
  const keys = evidenceKeySet(link);
  const familyEvidenceCount = [...keys].filter((key) => familyEvidenceFeatures.has(key)).length;
  const contextEvidenceCount = [...keys].filter((key) => contextEvidenceFeatures.has(key)).length;
  return link.score + familyEvidenceCount * 9 + contextEvidenceCount * 2 + (link.strongEvidenceCount || 0) * 4;
}

function isFamilyAttributionLink(link) {
  const keys = evidenceKeySet(link);
  const familyEvidenceCount = [...keys].filter((key) => familyEvidenceFeatures.has(key)).length;
  const contextEvidenceCount = [...keys].filter((key) => contextEvidenceFeatures.has(key)).length;

  if (link.score >= 52 && familyEvidenceCount >= 1 && contextEvidenceCount >= 1) return true;
  if (link.score >= 46 && familyEvidenceCount >= 2) return true;
  if (link.score >= 44 && familyEvidenceCount >= 1 && contextEvidenceCount >= 2) return true;
  if (link.score >= 42 && keys.has("credentials") && keys.has("payloadTokens") && keys.has("methods")) return true;
  if (link.score >= 44 && keys.has("netblocks") && (keys.has("methods") || keys.has("eventTypes") || keys.has("timeBuckets"))) return true;
  return false;
}

function buildFamilyCommunityLinks(links, maxLinksPerIp = 4) {
  const eligibleLinks = links
    .filter(isFamilyAttributionLink)
    .map((link) => ({ ...link, familyRank: familyAttributionRank(link) }));
  const topLinkIdsByIp = new Map();
  eligibleLinks.forEach((link) => {
    [link.source, link.target].forEach((ip) => {
      if (!topLinkIdsByIp.has(ip)) topLinkIdsByIp.set(ip, []);
      topLinkIdsByIp.get(ip).push(link);
    });
  });
  topLinkIdsByIp.forEach((rows, ip) => {
    topLinkIdsByIp.set(
      ip,
      new Set(
        rows
          .sort((left, right) =>
            right.familyRank - left.familyRank ||
            right.score - left.score ||
            right.evidence.length - left.evidence.length
          )
          .slice(0, maxLinksPerIp)
          .map((link) => link.id)
      )
    );
  });

  return eligibleLinks
    .filter((link) => {
      const sourceTop = topLinkIdsByIp.get(link.source);
      const targetTop = topLinkIdsByIp.get(link.target);
      const mutualNearest = sourceTop?.has(link.id) && targetTop?.has(link.id);
      const strongBridge = link.score >= 58 && link.strongEvidenceCount >= 2;
      return mutualNearest || strongBridge;
    })
    .sort((left, right) =>
      right.familyRank - left.familyRank ||
      right.score - left.score ||
      right.strongEvidenceCount - left.strongEvidenceCount ||
      right.evidence.length - left.evidence.length
    );
}

function detectIpCommunities(profiles, links) {
  const communityByIp = new Map(profiles.map((profile) => [profile.srcIp, profile.srcIp]));
  const neighborWeights = new Map(profiles.map((profile) => [profile.srcIp, []]));
  links.filter((link) => link.score >= 26).forEach((link) => {
    const weight = Math.max(1, link.score);
    neighborWeights.get(link.source)?.push({ ip: link.target, weight });
    neighborWeights.get(link.target)?.push({ ip: link.source, weight });
  });
  const orderedIps = profiles
    .map((profile) => profile.srcIp)
    .sort((left, right) => (neighborWeights.get(right)?.length || 0) - (neighborWeights.get(left)?.length || 0));

  for (let iteration = 0; iteration < 10; iteration += 1) {
    let changed = false;
    orderedIps.forEach((ip) => {
      const neighbors = neighborWeights.get(ip) || [];
      if (!neighbors.length) return;
      const scores = new Map([[communityByIp.get(ip), 2]]);
      neighbors.forEach((neighbor) => {
        const community = communityByIp.get(neighbor.ip);
        scores.set(community, (scores.get(community) || 0) + neighbor.weight);
      });
      const [bestCommunity, bestScore] = [...scores.entries()].sort((left, right) => right[1] - left[1] || String(left[0]).localeCompare(String(right[0])))[0];
      const currentCommunity = communityByIp.get(ip);
      const currentScore = scores.get(currentCommunity) || 0;
      if (bestCommunity !== currentCommunity && bestScore > currentScore + 4) {
        communityByIp.set(ip, bestCommunity);
        changed = true;
      }
    });
    if (!changed) break;
  }
  return communityByIp;
}

function fitIpPositionsToCenteredBox(nodePositions, ips, width, height, { fillRatio = 1, paddingX = 74, paddingY = 52, maxScale = 1 } = {}) {
  const active = ips.map((ip) => nodePositions.get(ip)).filter(Boolean);
  if (!active.length) return;
  const minX = Math.min(...active.map((position) => position.x));
  const maxX = Math.max(...active.map((position) => position.x));
  const minY = Math.min(...active.map((position) => position.y));
  const maxY = Math.max(...active.map((position) => position.y));
  const rangeX = Math.max(1, maxX - minX);
  const rangeY = Math.max(1, maxY - minY);
  const allowedWidth = Math.max(1, width - paddingX * 2);
  const allowedHeight = Math.max(1, height - paddingY * 2);
  const targetWidth = allowedWidth * fillRatio;
  const targetHeight = allowedHeight * fillRatio;
  const scale = Math.min(maxScale, targetWidth / rangeX, targetHeight / rangeY);
  const groupCenterX = (minX + maxX) / 2;
  const groupCenterY = (minY + maxY) / 2;
  const canvasCenterX = width / 2;
  const canvasCenterY = height / 2;

  ips.forEach((ip) => {
    const position = nodePositions.get(ip);
    if (!position) return;
    position.x = Math.max(paddingX, Math.min(width - paddingX, canvasCenterX + (position.x - groupCenterX) * scale));
    position.y = Math.max(paddingY, Math.min(height - paddingY, canvasCenterY + (position.y - groupCenterY) * scale));
  });
}

function enforceIpGraphSafeZone(nodePositions, ips, width, height, { paddingX = width * 0.13, paddingY = height * 0.14, pull = 0.08 } = {}) {
  const centerX = width / 2;
  const centerY = height / 2;
  ips.forEach((ip) => {
    const position = nodePositions.get(ip);
    if (!position) return;
    position.x = Math.max(paddingX, Math.min(width - paddingX, centerX + (position.x - centerX) * (1 - pull)));
    position.y = Math.max(paddingY, Math.min(height - paddingY, centerY + (position.y - centerY) * (1 - pull)));
  });
}

function layoutHashUnit(value, salt = 0) {
  let hash = 2166136261 ^ salt;
  const text = String(value);
  for (let index = 0; index < text.length; index += 1) {
    hash ^= text.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return ((hash >>> 0) % 10000) / 10000;
}

function centerIpGraphLayout(nodePositions, profiles, links, width, height) {
  const connectedIps = new Set();
  links.forEach((link) => {
    connectedIps.add(link.source);
    connectedIps.add(link.target);
  });
  const connected = profiles.map((profile) => profile.srcIp).filter((ip) => connectedIps.has(ip) && nodePositions.has(ip));
  const isolated = profiles.map((profile) => profile.srcIp).filter((ip) => !connectedIps.has(ip) && nodePositions.has(ip));
  const centerX = width / 2;
  const centerY = height / 2;

  fitIpPositionsToCenteredBox(nodePositions, connected, width, height, {
    fillRatio: 0.9,
    paddingX: width * 0.12,
    paddingY: height * 0.13,
    maxScale: 1.18,
  });

  connected.forEach((ip) => {
    const position = nodePositions.get(ip);
    if (!position) return;
    position.x = Math.max(width * 0.12, Math.min(width * 0.88, centerX + (position.x - centerX) * 0.96));
    position.y = Math.max(height * 0.13, Math.min(height * 0.87, centerY + (position.y - centerY) * 0.92));
  });

  connected.forEach((ip) => {
    const position = nodePositions.get(ip);
    if (!position) return;
    const dx = position.x - centerX;
    const dy = position.y - centerY;
    const ellipseX = width * 0.36;
    const ellipseY = height * 0.32;
    const normalized = Math.sqrt((dx / ellipseX) ** 2 + (dy / ellipseY) ** 2);
    if (normalized <= 0.88) return;
    const targetNormalized = 0.88 + (normalized - 0.88) * 0.26;
    const scale = targetNormalized / normalized;
    const edgeWeight = Math.min(1, Math.max(0, (normalized - 0.88) / 0.24));
    position.x = Math.max(width * 0.12, Math.min(width * 0.88, centerX + dx * scale + (layoutHashUnit(ip, 101) - 0.5) * edgeWeight * 12));
    position.y = Math.max(height * 0.13, Math.min(height * 0.87, centerY + dy * scale + (layoutHashUnit(ip, 103) - 0.5) * edgeWeight * 9));
  });

  isolated.forEach((ip) => {
    const position = nodePositions.get(ip);
    if (!position) return;
    position.x = Math.max(width * 0.12, Math.min(width * 0.88, centerX + (position.x - centerX) * 0.78));
    position.y = Math.max(height * 0.13, Math.min(height * 0.87, centerY + (position.y - centerY) * 0.72));
  });

  const allIps = profiles.map((profile) => profile.srcIp);
  fitIpPositionsToCenteredBox(nodePositions, allIps, width, height, {
    fillRatio: 0.92,
    paddingX: width * 0.12,
    paddingY: height * 0.13,
    maxScale: 1.42,
  });
  enforceIpGraphSafeZone(nodePositions, allIps, width, height, {
    paddingX: width * 0.12,
    paddingY: height * 0.13,
    pull: 0.02,
  });
}

function relaxIpGraphLayout(nodePositions, profiles, links, clusterIndexByIp, clusters, width, height) {
  const linkedIps = new Set();
  links.forEach((link) => {
    linkedIps.add(link.source);
    linkedIps.add(link.target);
  });
  const activeIps = [...linkedIps].filter((ip) => nodePositions.has(ip)).slice(0, 360);
  if (activeIps.length < 2) return;
  const activeIpSet = new Set(activeIps);
  const velocities = new Map(activeIps.map((ip) => [ip, { x: 0, y: 0 }]));
  const degreeByIp = new Map(activeIps.map((ip) => [ip, 0]));
  const scoreByIp = new Map(activeIps.map((ip) => [ip, 0]));
  const clusterByIndex = new Map((clusters || []).map((cluster) => [cluster.index, cluster]));
  const maxClusterSize = Math.max(1, ...(clusters || []).map((cluster) => cluster.ips.length));
  const centerByCluster = new Map();
  profiles.forEach((profile) => {
    if (!activeIpSet.has(profile.srcIp)) return;
    const position = nodePositions.get(profile.srcIp);
    const clusterIndex = clusterIndexByIp.get(profile.srcIp) ?? 0;
    const current = centerByCluster.get(clusterIndex) || { x: 0, y: 0, count: 0 };
    current.x += position.x;
    current.y += position.y;
    current.count += 1;
    centerByCluster.set(clusterIndex, current);
  });
  centerByCluster.forEach((center) => {
    center.x /= Math.max(1, center.count);
    center.y /= Math.max(1, center.count);
  });
  const activeLinks = links.filter((link) => activeIpSet.has(link.source) && activeIpSet.has(link.target));
  activeLinks.forEach((link) => {
    degreeByIp.set(link.source, (degreeByIp.get(link.source) || 0) + 1);
    degreeByIp.set(link.target, (degreeByIp.get(link.target) || 0) + 1);
    scoreByIp.set(link.source, (scoreByIp.get(link.source) || 0) + link.score);
    scoreByIp.set(link.target, (scoreByIp.get(link.target) || 0) + link.score);
  });
  const maxDegree = Math.max(1, ...activeIps.map((ip) => degreeByIp.get(ip) || 0));
  const maxScore = Math.max(1, ...activeIps.map((ip) => scoreByIp.get(ip) || 0));
  const profileByIp = new Map(profiles.map((profile) => [profile.srcIp, profile]));
  const clamp = (position, paddingX = 72, paddingY = 58) => {
    position.x = Math.max(paddingX, Math.min(width - paddingX, position.x));
    position.y = Math.max(paddingY, Math.min(height - paddingY, position.y));
  };

  for (let iteration = 0; iteration < 90; iteration += 1) {
    for (let leftIndex = 0; leftIndex < activeIps.length; leftIndex += 1) {
      for (let rightIndex = leftIndex + 1; rightIndex < activeIps.length; rightIndex += 1) {
        const leftIp = activeIps[leftIndex];
        const rightIp = activeIps[rightIndex];
        const left = nodePositions.get(leftIp);
        const right = nodePositions.get(rightIp);
        const dx = left.x - right.x;
        const dy = left.y - right.y;
        const distanceSq = Math.max(49, dx * dx + dy * dy);
        const force = 138 / distanceSq;
        const fx = dx * force;
        const fy = dy * force;
        velocities.get(leftIp).x += fx;
        velocities.get(leftIp).y += fy;
        velocities.get(rightIp).x -= fx;
        velocities.get(rightIp).y -= fy;
      }
    }

    activeLinks.forEach((link) => {
      const source = nodePositions.get(link.source);
      const target = nodePositions.get(link.target);
      const dx = target.x - source.x;
      const dy = target.y - source.y;
      const distance = Math.max(1, Math.sqrt(dx * dx + dy * dy));
      const desired = 30 + (100 - link.score) * 0.34;
      const force = (distance - desired) * (0.0056 + link.score / 26000);
      const fx = (dx / distance) * force;
      const fy = (dy / distance) * force;
      source.x += fx;
      source.y += fy;
      target.x -= fx;
      target.y -= fy;
      clamp(source);
      clamp(target);
    });

    activeIps.forEach((ip) => {
      const position = nodePositions.get(ip);
      const velocity = velocities.get(ip);
      const clusterIndex = clusterIndexByIp.get(ip) ?? 0;
      const clusterCenter = centerByCluster.get(clusterIndex) || { x: width / 2, y: height / 2 };
      const cluster = clusterByIndex.get(clusterIndex);
      const clusterRatio = Math.min(1, (cluster?.ips.length || 1) / maxClusterSize);
      const degreeRatio = Math.min(1, (degreeByIp.get(ip) || 0) / maxDegree);
      const scoreRatio = Math.min(1, (scoreByIp.get(ip) || 0) / maxScore);
      const profile = profileByIp.get(ip);
      const dxFromCenter = position.x - width / 2;
      const dyFromCenter = position.y - height / 2;
      const distanceFromCenter = Math.max(1, Math.sqrt(dxFromCenter * dxFromCenter + dyFromCenter * dyFromCenter));
      const outwardX = dxFromCenter / distanceFromCenter;
      const outwardY = dyFromCenter / distanceFromCenter;
      const targetRadius = 34 + (1 - clusterRatio) * 118 + (1 - degreeRatio) * 42 + (1 - scoreRatio) * 22;
      const targetX = width / 2 + outwardX * targetRadius;
      const targetY = height / 2 + outwardY * targetRadius * 0.74;
      const clusterTargetX = width / 2 + (clusterCenter.x - width / 2) * 0.48;
      const clusterTargetY = height / 2 + (clusterCenter.y - height / 2) * 0.48;
      const clusterGravity = 0.0018 + clusterRatio * 0.0034 + (profile?.count > 1 ? 0.001 : 0.0018);
      const radialGravity = 0.0022 + (1 - clusterRatio) * 0.0014;
      const centerGravity = 0.0014 + degreeRatio * 0.0012 + scoreRatio * 0.0012;
      velocity.x += (clusterTargetX - position.x) * clusterGravity;
      velocity.y += (clusterTargetY - position.y) * clusterGravity;
      velocity.x += (targetX - position.x) * radialGravity;
      velocity.y += (targetY - position.y) * radialGravity;
      velocity.x += (width / 2 - position.x) * centerGravity;
      velocity.y += (height / 2 - position.y) * centerGravity;
      position.x += velocity.x;
      position.y += velocity.y;
      velocity.x *= 0.62;
      velocity.y *= 0.62;
      clamp(position);
    });
  }
}

function buildIpAttributionGraph(events, sourceStats = []) {
  const width = 920;
  const height = 460;
  const profiles = buildIpProfiles(events);
  const sourceByIp = new Map(sourceStats.map((source) => [source.srcIp, source]));
  const profileByIp = new Map(profiles.map((profile) => [profile.srcIp, profile]));
  sourceStats.filter((source) => isKnown(source.srcIp)).forEach((source) => {
    if (profileByIp.has(source.srcIp)) return;
    const protocols = Array.isArray(source.protocols) ? source.protocols : [];
    const fallbackProfile = {
      srcIp: source.srcIp,
      country: source.country,
      city: source.city,
      isp: source.isp,
      asn: source.asn,
      count: Number(source.eventTotal ?? source.total ?? source.events ?? 0),
      highCount: Number(source.highEvents ?? source.high_events ?? 0),
      firstSeen: 0,
      lastSeen: 0,
      protocols: new Map(protocols.map((protocol) => [String(protocol).toUpperCase(), 1])),
      patterns: new Map(),
      methods: new Map(),
      honeypots: new Map(),
      eventTypes: new Map(),
      credentials: new Map(),
      commands: new Map(),
      payloadTokens: new Map(),
      ports: new Map(),
      stages: new Map(),
      timeBuckets: new Map(),
      netblocks: new Map(),
      parentNetblocks: new Map(),
      protocolCount: Number(source.protocolCount ?? protocols.length ?? 0),
      honeypotCount: 0,
      signalCount: Number(source.protocolCount ?? protocols.length ?? 0),
    };
    addWeightedFeature(fallbackProfile.netblocks, ipv4Prefix24(source.srcIp), 2);
    addWeightedFeature(fallbackProfile.parentNetblocks, ipv4Prefix16(source.srcIp));
    profileByIp.set(source.srcIp, fallbackProfile);
    profiles.push(fallbackProfile);
  });
  const candidateProfiles = [...profiles].sort((left, right) =>
    (right.count + right.highCount * 6 + right.signalCount * 2) -
    (left.count + left.highCount * 6 + left.signalCount * 2)
  );
  const idfByFeature = buildFeatureIdf(candidateProfiles);
  const candidatePairKeys = buildIpSimilarityCandidatePairs(candidateProfiles);
  const fallbackPairProfiles = candidateProfiles.slice(0, Math.min(220, candidateProfiles.length));
  const fallbackPairKeys = [];
  for (let leftIndex = 0; leftIndex < fallbackPairProfiles.length; leftIndex += 1) {
    for (let rightIndex = leftIndex + 1; rightIndex < fallbackPairProfiles.length; rightIndex += 1) {
      fallbackPairKeys.push(pairKey(fallbackPairProfiles[leftIndex].srcIp, fallbackPairProfiles[rightIndex].srcIp));
    }
  }
  const pairKeys = [...new Set([...candidatePairKeys, ...fallbackPairKeys])].slice(0, 16000);
  const rawLinks = [];
  pairKeys.forEach((key) => {
    const [leftIp, rightIp] = key.split("|||");
    const left = profileByIp.get(leftIp);
    const right = profileByIp.get(rightIp);
    if (!left || !right) return;
    const similarity = scoreIpSimilarity(left, right, idfByFeature);
    const hasBehaviorEvidence = similarity.strongEvidenceCount > 0 || similarity.score >= 42;
    if (similarity.score < 24 || similarity.evidence.length < 2 || !hasBehaviorEvidence) return;
    rawLinks.push({
      id: `${left.srcIp}--${right.srcIp}`,
      source: left.srcIp,
      target: right.srcIp,
      score: similarity.score,
      evidence: similarity.evidence,
      confidence: similarity.confidence,
      strongEvidenceCount: similarity.strongEvidenceCount,
    });
  });

  const sortedLinks = rawLinks
    .sort((left, right) =>
      right.score - left.score ||
      right.strongEvidenceCount - left.strongEvidenceCount ||
      right.evidence.length - left.evidence.length
    )
    .slice(0, Math.min(260, Math.max(60, candidateProfiles.length * 3)));
  const visibleProfiles = candidateProfiles;
  const visibleIpSet = new Set(visibleProfiles.map((profile) => profile.srcIp));
  const visibleLinks = sortedLinks.filter((link) => visibleIpSet.has(link.source) && visibleIpSet.has(link.target));
  const communityLinks = buildFamilyCommunityLinks(visibleLinks);
  const degreeByIp = new Map(visibleProfiles.map((profile) => [profile.srcIp, 0]));
  const linkScoreByIp = new Map(visibleProfiles.map((profile) => [profile.srcIp, 0]));
  visibleLinks.forEach((link) => {
    degreeByIp.set(link.source, (degreeByIp.get(link.source) || 0) + 1);
    degreeByIp.set(link.target, (degreeByIp.get(link.target) || 0) + 1);
    linkScoreByIp.set(link.source, (linkScoreByIp.get(link.source) || 0) + link.score);
    linkScoreByIp.set(link.target, (linkScoreByIp.get(link.target) || 0) + link.score);
  });
  const communityByIp = detectIpCommunities(visibleProfiles, communityLinks);
  const clustersByRoot = new Map();
  visibleProfiles.forEach((profile) => {
    const root = communityByIp.get(profile.srcIp) || profile.srcIp;
    const cluster = clustersByRoot.get(root) || {
      id: root,
      ips: [],
      eventCount: 0,
      highCount: 0,
      protocols: new Set(),
      methods: new Set(),
      honeypots: new Set(),
    };
    cluster.ips.push(profile.srcIp);
    cluster.eventCount += profile.count;
    cluster.highCount += profile.highCount;
    profile.protocols.forEach((_, protocol) => cluster.protocols.add(protocol));
    profile.methods.forEach((_, method) => cluster.methods.add(method));
    profile.honeypots.forEach((_, honeypot) => cluster.honeypots.add(honeypot));
    clustersByRoot.set(root, cluster);
  });
  const clusters = [...clustersByRoot.values()]
    .map((cluster) => {
      const ipSet = new Set(cluster.ips);
      const internalEdgeCount = communityLinks.filter((link) => ipSet.has(link.source) && ipSet.has(link.target)).length;
      const incidentEdgeCount = visibleLinks.filter((link) => ipSet.has(link.source) || ipSet.has(link.target)).length;
      const possibleEdges = Math.max(1, (cluster.ips.length * (cluster.ips.length - 1)) / 2);
      const topIp = cluster.ips.slice().sort((left, right) =>
        (degreeByIp.get(right) || 0) - (degreeByIp.get(left) || 0) ||
        (linkScoreByIp.get(right) || 0) - (linkScoreByIp.get(left) || 0) ||
        (profileByIp.get(right)?.count || 0) - (profileByIp.get(left)?.count || 0)
      )[0];

      return {
        ...cluster,
        edgeCount: incidentEdgeCount,
        internalEdgeCount,
        density: cluster.ips.length > 1 ? Math.round((internalEdgeCount / possibleEdges) * 1000) / 10 : 0,
        topIp,
      };
    })
    .sort((left, right) =>
      right.edgeCount - left.edgeCount ||
      right.ips.length - left.ips.length ||
      right.eventCount - left.eventCount ||
      right.highCount - left.highCount
    )
    .map((cluster, index) => {
      return {
        ...cluster,
        index,
        label: `攻击簇 ${index + 1}`,
        color: attributionClusterColors[index % attributionClusterColors.length],
      };
    });
  const clusterIndexByIp = new Map();
  clusters.forEach((cluster) => cluster.ips.forEach((ip) => clusterIndexByIp.set(ip, cluster.index)));
  const centerX = width / 2;
  const centerY = height / 2 + 2;
  const nodePositions = new Map();
  const hashUnit = (value, salt = 0) => {
    let hash = 2166136261 ^ salt;
    const text = String(value);
    for (let index = 0; index < text.length; index += 1) {
      hash ^= text.charCodeAt(index);
      hash = Math.imul(hash, 16777619);
    }
    return ((hash >>> 0) % 10000) / 10000;
  };
  const clampPoint = (x, y, padding = 72) => ({
    x: Math.max(padding, Math.min(width - padding, x)),
    y: Math.max(padding, Math.min(height - padding, y)),
  });
  const connectedClusters = clusters.filter((cluster) => cluster.edgeCount > 0 || cluster.ips.length > 1);
  const maxConnectedClusterSize = Math.max(1, ...connectedClusters.map((cluster) => cluster.ips.length));

  connectedClusters.slice(0, 18).forEach((cluster, communityIndex) => {
    const clusterRatio = Math.min(1, cluster.ips.length / maxConnectedClusterSize);
    const angle = communityIndex === 0
      ? -0.42
      : communityIndex * 2.399963 + hashUnit(cluster.id, 83) * 0.54;
    const ringDistance = 22 + (1 - clusterRatio) * 148 + Math.min(46, Math.max(0, communityIndex - 1) * 7);
    const slot = [
      centerX + Math.cos(angle) * ringDistance,
      centerY + Math.sin(angle) * ringDistance * 0.74,
    ];
    const center = clampPoint(slot[0], slot[1], 92);
    const orderedIps = cluster.ips.slice().sort((left, right) =>
      (degreeByIp.get(right) || 0) - (degreeByIp.get(left) || 0) ||
      (linkScoreByIp.get(right) || 0) - (linkScoreByIp.get(left) || 0) ||
      (profileByIp.get(right)?.count || 0) - (profileByIp.get(left)?.count || 0)
    );
    const communityRadius = Math.min(78, Math.max(26, 14 + Math.sqrt(orderedIps.length) * 7 + Math.log10(cluster.eventCount + 10) * 6));

    orderedIps.forEach((ip, index) => {
      if (index === 0 && orderedIps.length > 2) {
        nodePositions.set(ip, clampPoint(
          center.x + (hashUnit(ip, 41) - 0.5) * 10,
          center.y + (hashUnit(ip, 43) - 0.5) * 10,
          78
        ));
        return;
      }
      const angle = hashUnit(`${cluster.id}:${ip}:node-angle`, 53) * Math.PI * 2;
      const distanceRatio = Math.sqrt((index + 0.35) / Math.max(2, orderedIps.length));
      const radius = 12 + communityRadius * (0.32 + distanceRatio * 0.76) + (hashUnit(ip, 59) - 0.5) * 18;
      nodePositions.set(ip, clampPoint(
        center.x + Math.cos(angle) * radius * (0.84 + hashUnit(ip, 61) * 0.42),
        center.y + Math.sin(angle) * radius * (0.66 + hashUnit(ip, 63) * 0.34),
        76
      ));
    });
  });

  const isolatedProfiles = visibleProfiles.filter((profile) => !nodePositions.has(profile.srcIp));
  isolatedProfiles.forEach((profile, index) => {
    const total = Math.max(1, isolatedProfiles.length);
    const angle = hashUnit(`${profile.srcIp}:isolated-angle`, 67) * Math.PI * 2;
    const band = Math.sqrt((index + 0.5) / total);
    const distance = 104 + band * 142 + (hashUnit(profile.srcIp, 71) - 0.5) * 32;
    nodePositions.set(profile.srcIp, clampPoint(
      centerX + Math.cos(angle) * distance * (0.92 + hashUnit(profile.srcIp, 73) * 0.24),
      centerY + Math.sin(angle) * distance * (0.54 + hashUnit(profile.srcIp, 79) * 0.22),
      82
    ));
  });
  relaxIpGraphLayout(nodePositions, visibleProfiles, visibleLinks, clusterIndexByIp, clusters, width, height);
  centerIpGraphLayout(nodePositions, visibleProfiles, visibleLinks, width, height);

  const maxEventCount = Math.max(1, ...visibleProfiles.map((profile) => profile.count));
  const maxDegree = Math.max(1, ...visibleProfiles.map((profile) => degreeByIp.get(profile.srcIp) || 0));
  const labelCandidates = visibleProfiles
    .slice()
    .sort((left, right) =>
      (degreeByIp.get(right.srcIp) || 0) - (degreeByIp.get(left.srcIp) || 0) ||
      (linkScoreByIp.get(right.srcIp) || 0) - (linkScoreByIp.get(left.srcIp) || 0) ||
      right.count - left.count
    );
  const labelIps = new Set(
    labelCandidates
      .filter((profile) => (degreeByIp.get(profile.srcIp) || 0) > 0)
      .slice(0, 4)
      .map((profile) => profile.srcIp)
  );
  if (labelIps.size === 0) {
    labelCandidates.slice(0, 3).forEach((profile) => labelIps.add(profile.srcIp));
  }
  const nodes = visibleProfiles.map((profile) => {
    const meta = sourceByIp.get(profile.srcIp) || {};
    const position = nodePositions.get(profile.srcIp) || { x: centerX, y: centerY };
    const clusterIndex = clusterIndexByIp.get(profile.srcIp) ?? 0;
    const color = attributionClusterColors[clusterIndex % attributionClusterColors.length];
    const degree = degreeByIp.get(profile.srcIp) || 0;
    const isHub = labelIps.has(profile.srcIp) || degree >= Math.max(3, Math.ceil(maxDegree * 0.58));
    const eventWeight = Math.log1p(profile.count) / Math.log1p(maxEventCount);
    const degreeWeight = degree / maxDegree;
    const radius = Math.max(2.35, Math.min(isHub ? 7.4 : 5.15, 2.35 + eventWeight * 1.9 + degreeWeight * 2.15 + Math.min(0.62, profile.highCount * 0.045)));
    const labelAngle = Math.atan2(position.y - centerY, position.x - centerX);
    const labelDistance = radius + 10;
    const labelDx = Math.cos(labelAngle) * labelDistance;
    const labelDy = Math.sin(labelAngle) * labelDistance;
    const labelAnchor = Math.cos(labelAngle) > 0.25 ? "start" : Math.cos(labelAngle) < -0.25 ? "end" : "middle";
    return {
      id: profile.srcIp,
      label: profile.srcIp,
      x: position.x,
      y: position.y,
      radius,
      labelDx,
      labelDy,
      labelAnchor,
      color,
      clusterIndex,
      clusterLabel: `攻击簇 ${clusterIndex + 1}`,
      showLabel: labelIps.has(profile.srcIp),
      degree,
      linkScore: linkScoreByIp.get(profile.srcIp) || 0,
      isHub,
      clusterSize: clusters[clusterIndex]?.ips.length || 1,
      clusterEdgeCount: clusters[clusterIndex]?.edgeCount || 0,
      count: profile.count,
      highCount: profile.highCount,
      country: displayValue(profile.country || meta.country, "位置未知"),
      city: displayValue(profile.city || meta.city, ""),
      isp: displayValue(profile.isp || meta.isp, "unknown"),
      asn: displayValue(profile.asn || meta.asn, "unknown"),
      dominantProtocol: [...profile.protocols.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] || "unknown",
      dominantMethod: [...profile.methods.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] || "unknown",
    };
  });
  const nodeByIp = new Map(nodes.map((node) => [node.id, node]));
  const communityLinkIds = new Set(communityLinks.map((link) => link.id));
  const links = visibleLinks
    .filter((link) => nodeByIp.has(link.source) && nodeByIp.has(link.target))
    .sort((left, right) => left.score - right.score)
    .map((link) => {
      const source = nodeByIp.get(link.source);
      const target = nodeByIp.get(link.target);
      return {
        ...link,
        sourceNode: source,
        targetNode: target,
        width: Math.max(0.55, Math.min(2.35, 0.42 + (link.score / 100) * 2.35)),
        opacity: 0.14 + (link.score / 100) * 0.42,
        color: source.clusterIndex === target.clusterIndex ? source.color : "#7aa8b5",
        isCommunityLink: communityLinkIds.has(link.id),
      };
    });
  const visibleCommunityRows = (connectedClusters.length ? connectedClusters : clusters).slice(0, 8);
  const maxCommunityEdgeCount = Math.max(1, ...visibleCommunityRows.map((cluster) => cluster.edgeCount));
  const communityRows = visibleCommunityRows
    .map((cluster) => ({
      ...cluster,
      coreIp: cluster.topIp || cluster.ips[0],
      avgEvents: cluster.ips.length ? Math.round(cluster.eventCount / cluster.ips.length) : cluster.eventCount,
      edgeShare: Math.round((cluster.edgeCount / maxCommunityEdgeCount) * 1000) / 10,
    }));
  const focusNodeId = labelCandidates[0]?.srcIp || nodes[0]?.id || null;

  return {
    width,
    height,
    viewBox: {
      x: 0,
      y: 0,
      width,
      height,
    },
    nodePaddingX: 86,
    nodePaddingY: 66,
    nodes,
    links,
    communityEdgeCount: communityLinks.length,
    clusters,
    communityRows,
    focusNodeId,
    topLink: [...links].sort((left, right) => right.score - left.score)[0] || null,
    profileCount: profiles.length,
    candidateCount: candidateProfiles.length,
    pairCandidateCount: pairKeys.length,
    algorithmLabel: "宽松行为模式相似度 + 时间窗口增强 + 社区传播布局",
  };
}

const attackStageDefinitions = [
  {
    key: "connect",
    name: "建连扫描",
    color: "#20d9ff",
    meaning: "连接打开、端口触达和批量扫描，是攻击行为的入口层。",
  },
  {
    key: "protocol",
    name: "暴露面探测",
    color: "#6ea8ff",
    meaning: "识别 HTTP、数据库、远程登录等服务暴露面，形成攻击入口画像。",
  },
  {
    key: "credential",
    name: "账号尝试",
    color: "#a7f35a",
    meaning: "登录、密码和认证行为，用于分析弱口令与爆破尝试。",
  },
  {
    key: "risk",
    name: "风险命中",
    color: "#ffca57",
    meaning: "命中高危攻击方式或异常行为，说明攻击链进入重点关注阶段。",
  },
  {
    key: "command",
    name: "命令执行",
    color: "#ff6848",
    meaning: "交互式命令或 payload 输入，是入侵尝试的强证据。",
  },
  {
    key: "other",
    name: "其他事件",
    color: "#8ba6b1",
    meaning: "暂未归入明确阶段的背景噪声或补充事件。",
  },
];

const attackStageOrder = new Map(attackStageDefinitions.map((stage, index) => [stage.key, index]));

function attackStageForEvent(event) {
  const method = attackBehavior(event);
  const eventType = String(event.eventType || "").toLowerCase();
  const protocol = String(event.protocol || "").toUpperCase();
  const detail = `${event.detail || ""} ${event.payload || ""} ${event.raw || ""}`.toLowerCase();

  if (method.tactic === "execution") return "command";
  if (method.tactic === "credential") return "credential";
  if (method.tactic === "exploit") return "risk";
  if (effectiveSeverity(event) === "high") return "risk";
  if (/connect|connection|open|scan|probe/.test(eventType + detail)) return "connect";
  if (["probe", "recon"].includes(method.tactic)) return "protocol";
  if (protocol) return "protocol";
  return "other";
}

function buildAttackSequenceInsights(events) {
  const total = events.length;
  const stageMap = new Map(attackStageDefinitions.map((stage) => [
    stage.key,
    {
      ...stage,
      count: 0,
      highCount: 0,
      sources: new Set(),
      protocols: new Map(),
      methods: new Map(),
      honeypots: new Map(),
    },
  ]));
  const sourceMap = new Map();

  events.forEach((event) => {
    const stageKey = attackStageForEvent(event);
    const stage = stageMap.get(stageKey) || stageMap.get("other");
    const method = attackBehavior(event);
    const sourceIp = displayValue(event.srcIp, "unknown");
    const protocol = displayValue(event.protocol, "UNKNOWN");
    const honeypot = displayValue(event.honeypotLabel || event.honeypot || event.honeypotIp, "未知蜜罐");
    stage.count += 1;
    if (effectiveSeverity(event) === "high") stage.highCount += 1;
    if (isKnown(sourceIp)) stage.sources.add(sourceIp);
    stage.protocols.set(protocol, (stage.protocols.get(protocol) || 0) + 1);
    stage.methods.set(method.name, (stage.methods.get(method.name) || 0) + 1);
    stage.honeypots.set(honeypot, (stage.honeypots.get(honeypot) || 0) + 1);

    if (!sourceMap.has(sourceIp)) {
      sourceMap.set(sourceIp, {
        srcIp: sourceIp,
        country: event.country,
        city: event.city,
        events: [],
        stages: new Set(),
      });
    }
    const source = sourceMap.get(sourceIp);
    source.events.push({
      stageKey,
      timestamp: event.eventTsMs ?? (new Date(event.timestamp).getTime() || 0),
      protocol,
      methodName: method.name,
      honeypot,
    });
    source.stages.add(stageKey);
  });

  const rate = (count) => (total ? Math.round((count / total) * 100) : 0);
  const stageRows = [...stageMap.values()]
    .map((stage) => {
      const topProtocol = [...stage.protocols.entries()].sort((a, b) => b[1] - a[1])[0];
      const topMethod = [...stage.methods.entries()].sort((a, b) => b[1] - a[1])[0];
      const topHoneypot = [...stage.honeypots.entries()].sort((a, b) => b[1] - a[1])[0];
      return {
        ...stage,
        rate: rate(stage.count),
        sourceCount: stage.sources.size,
        topProtocol: topProtocol?.[0] || "unknown",
        topProtocolCount: topProtocol?.[1] || 0,
        topMethod: topMethod?.[0] || "unknown",
        topMethodCount: topMethod?.[1] || 0,
        topHoneypot: topHoneypot?.[0] || "unknown",
      };
    })
    .filter((stage) => stage.count > 0)
    .sort((left, right) => attackStageOrder.get(left.key) - attackStageOrder.get(right.key));

  const transitionMap = new Map();
  const sourceJourneys = [...sourceMap.values()].map((source) => {
    const ordered = [...source.events].sort((left, right) => left.timestamp - right.timestamp);
    const stages = [];
    ordered.forEach((event) => {
      const lastStage = stages[stages.length - 1];
      if (lastStage !== event.stageKey) stages.push(event.stageKey);
    });
    stages.forEach((stageKey, index) => {
      const nextStage = stages[index + 1];
      if (!nextStage || nextStage === stageKey) return;
      const key = `${stageKey}→${nextStage}`;
      transitionMap.set(key, (transitionMap.get(key) || 0) + 1);
    });
    return {
      srcIp: source.srcIp,
      location: joinKnown([source.country, source.city], "位置未知"),
      eventCount: ordered.length,
      stageCount: source.stages.size,
      stageKeys: stages,
      firstStage: stages[0] || "other",
      lastStage: stages[stages.length - 1] || "other",
    };
  });

  const stageName = (key) => stageMap.get(key)?.name || key;
  const totalTransitions = [...transitionMap.values()].reduce((sum, count) => sum + count, 0);
  const transitionRows = [...transitionMap.entries()]
    .map(([key, count]) => {
      const [from, to] = key.split("→");
      return {
        key,
        from,
        to,
        fromName: stageName(from),
        toName: stageName(to),
        count,
        rate: totalTransitions ? Math.round((count / totalTransitions) * 100) : 0,
      };
    })
    .sort((left, right) => right.count - left.count)
    .slice(0, 4);

  const journeyRows = sourceJourneys
    .filter((source) => source.stageKeys.length > 0)
    .sort((left, right) => right.stageCount - left.stageCount || right.eventCount - left.eventCount)
    .slice(0, 3)
    .map((source) => ({
      ...source,
      stageNames: source.stageKeys.slice(0, 5).map(stageName),
    }));
  const dominantStage = [...stageRows].sort((left, right) => right.count - left.count)[0] || null;
  const deepestJourney = journeyRows[0] || null;
  const topTransition = transitionRows[0] || null;
  const credentialStage = stageRows.find((stage) => stage.key === "credential");
  const commandStage = stageRows.find((stage) => stage.key === "command");

  return {
    total,
    stageRows,
    transitionRows,
    journeyRows,
    dominantStage,
    deepestJourney,
    topTransition,
    credentialRate: credentialStage?.rate || 0,
    commandCount: commandStage?.count || 0,
    sourceCount: sourceMap.size,
  };
}

function buildQualityInsights(events) {
  const total = events.length;
  const countWhere = (predicate) => events.filter(predicate).length;
  const rate = (count) => (total ? Math.round((count / total) * 100) : 0);
  const timeCount = countWhere((event) => event.timeNormalized !== false && isKnown(event.eventTimeLocal) && isKnown(event.eventTimeUtc));
  const geoCount = countWhere((event) => isKnown(event.country) || isKnown(event.city));
  const networkCount = countWhere((event) => isKnown(event.isp) || isKnown(event.asn));
  const payloadCount = countWhere((event) => structuredFields(event.payload).length || structuredFields(event.raw).length || isKnown(event.payload));
  const credentialCount = countWhere((event) => attackBehavior(event).tactic === "credential");
  const commandCount = countWhere((event) => attackBehavior(event).tactic === "execution");
  const uniqueIpCount = new Set(events.map((event) => event.srcIp).filter(isKnown)).size;
  const uniqueProtocolCount = new Set(events.map((event) => event.protocol).filter(isKnown)).size;
  const uniqueMethodCount = new Set(events.map((event) => attackBehavior(event).key).filter(isKnown)).size;
  const categoryMap = events.reduce((counter, event) => {
    const category = attackBehavior(event);
    const current = counter.get(category.name) || { count: 0, color: category.color };
    current.count += 1;
    counter.set(category.name, current);
    return counter;
  }, new Map());
  const categories = [...categoryMap.entries()]
    .map(([name, item]) => ({ name, count: item.count, rate: rate(item.count), color: item.color || "#20d9ff" }))
    .sort((left, right) => right.count - left.count);
  const qualityRows = [
    ["时间标准化", timeCount, "统一北京时间与 UTC，便于跨节点对齐和窗口统计"],
    ["地理归因", geoCount, "为地图、国家/城市聚合和攻击来源画像提供维度"],
    ["网络归因", networkCount, "补充 ISP/ASN，用于识别云厂商、扫描平台和出口网络"],
    ["Payload 结构化", payloadCount, "把原始报文拆成字段，支持账号、命令和攻击行为分析"],
    ["账号口令", credentialCount, "提取登录尝试，支撑弱口令和爆破行为统计"],
    ["命令输入", commandCount, "识别交互式攻击行为，区分扫描与入侵尝试"],
  ].map(([name, count, meaning]) => ({ name, count, rate: rate(count), meaning }));
  const scoreBase = [timeCount, geoCount, networkCount, payloadCount].map(rate);
  const qualityScore = scoreBase.length ? Math.round(scoreBase.reduce((sum, value) => sum + value, 0) / scoreBase.length) : 0;

  return {
    total,
    uniqueIpCount,
    uniqueProtocolCount,
    uniqueMethodCount,
    qualityScore,
    categories,
    qualityRows,
  };
}

function buildCollectorHealthStats(snapshot) {
  const servers = snapshot.serverStats || [];
  const windowTotal = servers.reduce((sum, server) => sum + Number(server.currentEvents ?? 0), 0);
  const totalEvents = servers.reduce((sum, server) => sum + Number(server.totalEvents ?? server.events ?? 0), 0);
  const activeServers = servers.filter((server) => Number(server.currentEvents ?? 0) > 0);
  const quietServers = servers.filter((server) => {
    const status = String(server.status || "").toLowerCase();
    return ["online", "running"].includes(status) && Number(server.currentEvents ?? 0) === 0;
  });
  const sortedServers = [...servers].sort((left, right) => Number(right.currentEvents ?? 0) - Number(left.currentEvents ?? 0));
  const dominantServer = sortedServers[0] || null;
  const dominantWindowCount = Number(dominantServer?.currentEvents ?? 0);
  const dominantShare = windowTotal ? Math.round((dominantWindowCount / windowTotal) * 100) : 0;
  const skewLabel = !servers.length
    ? "等待节点"
    : !windowTotal
      ? "等待新增"
      : dominantShare >= 75
        ? "高度偏斜"
        : dominantShare >= 55
          ? "中度偏斜"
          : "较均衡";
  const rows = servers.map((server) => {
    const status = String(server.status || "").toLowerCase();
    const currentEvents = Number(server.currentEvents ?? 0);
    const serverTotal = Number(server.totalEvents ?? server.events ?? 0);
    const eventShare = windowTotal ? Math.round((currentEvents / windowTotal) * 100) : 0;
    const diagnosis = !["online", "running"].includes(status)
      ? "节点状态异常，当前聚合可能缺失"
      : currentEvents > 0
        ? "当前窗口有新增，采集链路正常"
        : serverTotal > 0
          ? "累计有数据，当前窗口暂无新增"
          : "在线但无事件，需核对日志路径、端口暴露或采集权限";
    const tone = !["online", "running"].includes(status)
      ? "danger"
      : currentEvents > 0
        ? "ok"
        : "warn";

    return {
      id: server.id,
      name: server.name,
      label: server.label,
      ip: server.ip,
      status: statusLabel[server.status] || server.status,
      currentEvents,
      totalEvents: serverTotal,
      eventShare,
      externalIps: Number(server.currentExternalIps ?? server.externalIps ?? 0),
      protocolText: serverProtocolCopy(server),
      diagnosis,
      hdfsPartition: server.hdfsPartition,
      tone,
    };
  });

  return {
    serverCount: servers.length,
    activeCount: activeServers.length,
    quietCount: quietServers.length,
    windowTotal,
    totalEvents,
    dominantServer,
    dominantShare,
    skewLabel,
    rows,
  };
}

function buildResearchInsights(events) {
  const total = events.length;
  const rate = (count) => (total ? Math.round((count / total) * 100) : 0);
  const countBy = (selector) => {
    const counter = new Map();
    events.forEach((event) => {
      const key = selector(event);
      if (!isKnown(key)) return;
      counter.set(key, (counter.get(key) || 0) + 1);
    });
    return [...counter.entries()]
      .map(([key, count]) => ({ key, count, rate: rate(count) }))
      .sort((left, right) => right.count - left.count || String(left.key).localeCompare(String(right.key)));
  };
  const sourceCounts = countBy((event) => event.srcIp);
  const protocolCounts = countBy((event) => displayValue(event.protocol, ""));
  const methodCounts = countBy((event) => attackBehavior(event).name);
  const countryCounts = countBy((event) => event.country);
  const topSource = sourceCounts[0] || null;
  const topProtocol = protocolCounts[0] || null;
  const topCategory = methodCounts[0] || null;
  const topCountry = countryCounts[0] || null;
  const highCount = events.filter((event) => effectiveSeverity(event) === "high").length;
  const commandCount = events.filter((event) => attackBehavior(event).tactic === "execution").length;
  const credentialCount = events.filter((event) => attackBehavior(event).tactic === "credential").length;
  const geoKnownCount = events.filter((event) => isKnown(event.country) || isKnown(event.city)).length;
  const highRate = rate(highCount);
  const geoCoverage = rate(geoKnownCount);
  const concentrationLabel = !topSource
    ? "等待事件"
    : topSource.rate >= 60
      ? "高度集中"
      : topSource.rate >= 35
        ? "中度集中"
        : "分散分布";
  const riskLabel = highRate >= 35 ? "高危活跃" : highRate >= 12 ? "中等风险" : total ? "低风险占优" : "等待事件";
  const behaviorLabel = topCategory?.key || "等待事件";
  const conclusions = total
    ? [
        `当前窗口共 ${formatNumber(total)} 条事件，来自 ${formatNumber(sourceCounts.length)} 个源 IP，识别出 ${formatNumber(methodCounts.length)} 类攻击方式、${formatNumber(protocolCounts.length)} 类协议背景。`,
        topSource
          ? `最活跃源 ${topSource.key} 贡献 ${formatNumber(topSource.count)} 条，占 ${topSource.rate}%，来源集中度为${concentrationLabel}。`
          : "当前没有可识别源 IP。",
        topCategory
          ? `主导攻击方式为 ${topCategory.key}，占 ${topCategory.rate}%，预处理已把原始协议日志提升为可计算行为特征。`
          : "当前暂无可分类行为语义。",
        topProtocol
          ? `协议背景中 ${topProtocol.key} 占 ${topProtocol.rate}%，用于解释暴露面，但不再作为首要攻击类型。`
          : "当前没有可识别协议背景。",
        `高危事件 ${formatNumber(highCount)} 条，占 ${highRate}%；命令输入 ${formatNumber(commandCount)} 条，账号口令相关 ${formatNumber(credentialCount)} 条。`,
        topCountry
          ? `地理归因覆盖 ${geoCoverage}%，主要来源国家/地区为 ${topCountry.key}。`
          : `地理归因覆盖 ${geoCoverage}%，后续可继续补全 IP 画像。`,
      ]
    : [];

  return {
    total,
    sourceCount: sourceCounts.length,
    protocolCount: protocolCounts.length,
    methodCount: methodCounts.length,
    topSource,
    topProtocol,
    topCategory,
    topCountry,
    highCount,
    highRate,
    commandCount,
    credentialCount,
    geoCoverage,
    concentrationLabel,
    riskLabel,
    behaviorLabel,
    conclusions,
  };
}

function experimentEvidenceLevel(insights, relationInsights, sequenceInsights) {
  if (!insights.total) {
    return {
      label: "等待样本",
      tone: "muted",
      copy: "当前筛选条件没有事件，暂不展示推断信息。",
    };
  }

  const enoughVolume = insights.total >= 100;
  const hasCrossDimension = relationInsights.sourceCount >= 2 && relationInsights.protocolCount >= 2;
  const hasBehaviorSignal = Boolean(sequenceInsights.dominantStage) && (insights.credentialCount > 0 || insights.commandCount > 0 || insights.highCount > 0);
  const hasAttribution = insights.geoCoverage >= 30;

  if (enoughVolume && hasCrossDimension && hasBehaviorSignal && hasAttribution) {
    return {
      label: "证据较完整",
      tone: "strong",
      copy: "样本量、关系维度、行为阶段和归因字段较完整，可用于后续研判分析。",
    };
  }
  if (insights.total >= 20 || hasCrossDimension || hasBehaviorSignal) {
    return {
      label: "可继续分析",
      tone: "medium",
      copy: "当前样本已能展示主要攻击面和行为结构，后续可继续补充地理或跨节点证据。",
    };
  }
  return {
    label: "样本较少",
    tone: "weak",
    copy: "当前更适合做样例查看，建议放宽筛选或等待更多事件后再深入分析。",
  };
}

function buildExperimentVerdict(insights, relationInsights, sequenceInsights) {
  const evidence = experimentEvidenceLevel(insights, relationInsights, sequenceInsights);
  if (!insights.total) {
    return {
      evidence,
      title: "等待可分析事件",
      summary: "筛选窗口为空，当前页面保留分析框架，等待可用样本后再展示推断信息。",
      question: "当前筛选条件是否仍有可分析样本",
      rows: [
        { label: "样本口径", value: "0 条事件", detail: "需要恢复筛选或等待采集" },
        { label: "关系证据", value: "暂无路径", detail: "源 IP、攻击方式、蜜罐节点无法聚合" },
        { label: "行为阶段", value: "暂无阶段", detail: "未形成攻击链条" },
      ],
    };
  }

  const relation = relationInsights.topRelation;
  const sequence = sequenceInsights.dominantStage;
  const relationCopy = relation
    ? `${relation.sourceIp} / ${relation.protocol}`
    : "暂无最强路径";
  const behaviorCopy = sequence
    ? `${sequence.name}占 ${sequence.rate}%`
    : insights.behaviorLabel;
  const title = `${insights.behaviorLabel}主导，${insights.concentrationLabel}，${insights.riskLabel}`;
  const summary = relation
    ? `当前筛选窗口显示 ${relation.sourceIp} 对 ${relation.honeypot} 的 ${relation.protocol} 行为最集中，结合 ${behaviorCopy}，可作为多源蜜罐日志预处理和关联聚合后的重点观察对象。`
    : `当前筛选窗口以 ${insights.behaviorLabel} 为主，协议仅作为背景字段，适合优先做攻击方式统计。`;
  const question = insights.topCategory
    ? `${insights.topCategory.key} 是否存在集中来源或同源工具簇`
    : "多源蜜罐日志能否形成可解释攻击画像";

  return {
    evidence,
    title,
    summary,
    question,
    rows: [
      {
        label: "样本口径",
        value: `${formatNumber(insights.total)} 事件 / ${formatNumber(insights.sourceCount)} IP`,
        detail: `${formatNumber(insights.methodCount)} 类攻击方式 / ${formatNumber(insights.protocolCount)} 类协议背景`,
      },
      {
        label: "关系证据",
        value: relationCopy,
        detail: relation ? `${formatNumber(relation.count)} 条指向 ${relation.honeypot}` : "等待源 IP × 攻击方式 × 蜜罐路径",
      },
      {
        label: "行为阶段",
        value: behaviorCopy,
        detail: sequenceInsights.topTransition
          ? `${sequenceInsights.topTransition.fromName} -> ${sequenceInsights.topTransition.toName}`
          : "暂无明显阶段转移",
      },
      {
        label: "数据质量",
        value: `${insights.geoCoverage}% 地理归因`,
        detail: `${formatNumber(insights.credentialCount)} 条账号口令 / ${formatNumber(insights.commandCount)} 条命令`,
      },
    ],
  };
}

function exportSourceIps(snapshot, events) {
  const columns = [
    { label: "source_ip", value: (source) => source.srcIp },
    { label: "country", value: (source) => source.country },
    { label: "region", value: (source) => source.region },
    { label: "city", value: (source) => source.city },
    { label: "longitude", value: (source) => coordinateValue(source.coordinates, 0) },
    { label: "latitude", value: (source) => coordinateValue(source.coordinates, 1) },
    { label: "isp", value: (source) => source.isp },
    { label: "asn", value: (source) => source.asn },
    { label: "event_count", value: (source) => source.eventTotal ?? source.total ?? 0 },
    { label: "filtered_event_count", value: (source) => source.events || 0 },
    { label: "representative_window_events", value: (source) => source.events || 0 },
    { label: "high_risk_total_events", value: (source) => source.highEvents || 0 },
    { label: "high_risk_window_events", value: (source) => source.highCurrentEvents || 0 },
    { label: "protocol_count", value: (source) => source.protocolCount || 0 },
    { label: "protocols", value: (source) => source.protocols || [] },
    { label: "filtered_protocol_count", value: (source) => source.filteredProtocolCount || source.protocolCount || 0 },
    { label: "filtered_protocols", value: (source) => source.filteredProtocols || source.protocols || [] },
    { label: "filtered_attack_method_count", value: (source) => source.filteredMethodCount || source.methodCount || 0 },
    { label: "filtered_attack_methods", value: (source) => source.filteredMethods || source.attackMethods || [] },
    { label: "risk_score", value: (source) => source.riskScore ?? source.score ?? 0 },
    { label: "filtered_risk_score", value: (source) => source.filteredRiskScore ?? source.windowRiskScore ?? 0 },
  ];
  const rows = allSourceRowsForExport(snapshot, events);
  downloadTextFile(`honeypot_source_ips_${exportTimestamp()}.csv`, buildCsv(rows, columns), "text/csv;charset=utf-8");
}

function exportSourceIpList(snapshot, events) {
  const rows = allSourceRowsForExport(snapshot, events);
  const ips = rows.map((source) => source.srcIp).filter(isKnown);
  downloadTextFile(`honeypot_source_ip_list_${exportTimestamp()}.txt`, ips.join("\n"), "text/plain;charset=utf-8");
}

async function exportFullEventsCsv({
  activeMethod = "ALL",
  activeProtocol = "ALL",
  anchorTime,
  events = [],
  fieldKeys,
  range,
  rangeBounds,
}) {
  const selectedKeys = eventCsvColumnsFor(fieldKeys).map((field) => field.key);
  const params = new URLSearchParams();
  params.set("fields", selectedKeys.join(","));
  params.set("range", range || "all");
  params.set("protocol", activeProtocol || "ALL");
  params.set("method", activeMethod || "ALL");
  if (anchorTime) params.set("anchor", anchorTime);
  if (Number.isFinite(rangeBounds?.startMs) && Number.isFinite(rangeBounds?.endMs)) {
    params.set("start", new Date(rangeBounds.startMs).toISOString());
    params.set("end", new Date(rangeBounds.endMs).toISOString());
  }
  const filename = `honeypot_events_${exportTimestamp()}.csv`;
  const serverUrl = `/api/export/events.csv?${params.toString()}`;
  downloadUrlFile(serverUrl, filename);
  return {
    mode: "server-stream",
    rowCount: null,
  };
}

function exportProtocolStats(snapshot, events) {
  const currentCounts = events.reduce((counter, event) => {
    counter.set(event.protocol, (counter.get(event.protocol) || 0) + 1);
    return counter;
  }, new Map());
  const columns = [
    { label: "protocol", value: (protocol) => protocol.key },
    { label: "protocol_name", value: (protocol) => protocol.name },
    { label: "total_event_count", value: (protocol) => protocol.total ?? protocol.count ?? 0 },
    { label: "filtered_event_count", value: (protocol) => currentCounts.get(protocol.key) || 0 },
    { label: "severity", value: (protocol) => severityLabel[protocol.severity] || protocol.severity },
    { label: "delta", value: (protocol) => protocol.delta ?? 0 },
    { label: "description", value: (protocol) => protocol.description },
  ];
  downloadTextFile(`honeypot_protocol_stats_${exportTimestamp()}.csv`, buildCsv(snapshot.protocolStats, columns), "text/csv;charset=utf-8");
}

function exportAttackMethodStats(snapshot, events) {
  const rows = events?.length ? buildAttackMethodStats(events) : (snapshot.attackMethodStats || []);
  const columns = [
    { label: "attack_method_key", value: (method) => method.key },
    { label: "attack_method", value: (method) => method.name },
    { label: "tactic", value: (method) => method.tactic },
    { label: "event_count", value: (method) => method.total },
    { label: "source_ip_count", value: (method) => method.sourceCount },
    { label: "protocol_count", value: (method) => method.protocolCount },
    { label: "protocols", value: (method) => method.protocols },
    { label: "severity", value: (method) => severityLabel[method.severity] || method.severity },
    { label: "description", value: (method) => method.description },
    { label: "examples", value: (method) => method.examples },
  ];
  downloadTextFile(`honeypot_attack_methods_${exportTimestamp()}.csv`, buildCsv(rows, columns), "text/csv;charset=utf-8");
}

function exportHoneypotStats(snapshot, events) {
  const currentCounts = events.reduce((counter, event) => {
    const key = event.honeypotIp || event.honeypot || "unknown";
    counter.set(key, (counter.get(key) || 0) + 1);
    return counter;
  }, new Map());
  const currentIps = events.reduce((counter, event) => {
    const key = event.honeypotIp || event.honeypot || "unknown";
    if (!counter.has(key)) counter.set(key, new Set());
    counter.get(key).add(event.srcIp);
    return counter;
  }, new Map());
  const columns = [
    { label: "honeypot_ip", value: (server) => server.ip },
    { label: "honeypot_name", value: (server) => server.name },
    { label: "honeypot_type", value: (server) => server.label },
    { label: "country", value: (server) => server.country },
    { label: "city", value: (server) => server.city },
    { label: "total_event_count", value: (server) => server.totalEvents ?? server.events ?? 0 },
    { label: "filtered_event_count", value: (server) => currentCounts.get(server.ip) || currentCounts.get(server.name) || 0 },
    { label: "external_ip_count", value: (server) => server.externalIps ?? 0 },
    { label: "filtered_external_ip_count", value: (server) => currentIps.get(server.ip)?.size || currentIps.get(server.name)?.size || 0 },
    { label: "protocols", value: (server) => server.protocols || [] },
    { label: "status", value: (server) => server.status },
    { label: "last_seen", value: (server) => server.lastSeen },
    { label: "hdfs_partition", value: (server) => server.hdfsPartition },
  ];
  downloadTextFile(`honeypot_honeypot_stats_${exportTimestamp()}.csv`, buildCsv(snapshot.serverStats, columns), "text/csv;charset=utf-8");
}

function exportResearchReportMarkdown(snapshot, events, activeProtocol, activeMethod) {
  const scope = [
    activeMethod === "ALL" ? "全部攻击方式" : methodLabel(activeMethod),
    activeProtocol === "ALL" ? "" : `协议 ${activeProtocol}`,
  ].filter(Boolean).join(" / ");
  const research = buildResearchInsights(events);
  const relation = buildRelationInsights(events);
  const quality = buildQualityInsights(events);
  const timeStats = buildTimeNormalizationStats(events, snapshot);
  const collector = buildCollectorHealthStats(snapshot);
  const generatedAt = snapshot.generatedAtLocal || snapshot.generatedAt || snapshot.lastUpdated || "unknown";
  const latestEvent = timeStats.latest
    ? new Date(timeStats.latest).toLocaleString("zh-CN", { timeZone: BEIJING_TIME_ZONE, hour12: false })
    : "暂无事件";
  const lines = [
    "# 多源蜜罐大数据态势感知分析摘要",
    "",
    `- 导出时间：${new Date().toLocaleString("zh-CN", { timeZone: BEIJING_TIME_ZONE, hour12: false })}`,
    `- 快照时间：${generatedAt}`,
    `- 分析范围：${scope}`,
    `- 当前窗口事件：${formatNumber(events.length)} 条`,
    `- 累计事件：${formatNumber(snapshot.stats?.totalEvents ?? 0)} 条`,
    "",
    "## 1. 数据采集与预处理",
    "",
    `本系统采集 Cowrie、OpenCanary 和多协议低交互蜜罐日志，预处理阶段统一字段、时间、IP 归因、协议、账号口令、payload 和目标节点信息，并进一步生成 attack_method 攻击方式字段。当前窗口清洗可用度为 ${quality.qualityScore}%。`,
    "",
    buildMarkdownTable(
      ["字段/特征", "覆盖数量", "覆盖率", "分析意义"],
      quality.qualityRows.map((row) => [row.name, `${formatNumber(row.count)} / ${formatNumber(quality.total)}`, `${row.rate}%`, row.meaning]),
    ),
    "",
    "## 2. 时间标准化",
    "",
    `预处理保留 raw_time，并生成 event_time_utc、event_time_local 和 event_ts_ms，用于跨节点窗口聚合。当前时间标准化覆盖率为 ${timeStats.coverage}%，最新事件时间为 ${latestEvent}，存储分区示例为 \`${timeStats.partition}\`。`,
    "",
    buildMarkdownTable(
      ["时间来源", "事件数", "占比"],
      timeStats.sourceCounts.map((row) => [row.source, formatNumber(row.count), `${row.rate}%`]),
    ),
    "",
    "## 3. 采集健康与节点偏斜",
    "",
    `当前活跃节点 ${formatNumber(collector.activeCount)} / ${formatNumber(collector.serverCount)}，窗口事件 ${formatNumber(collector.windowTotal)} 条，主导节点 ${collector.dominantServer?.name || "暂无"}，分布状态为 ${collector.skewLabel}。`,
    "",
    buildMarkdownTable(
      ["节点", "状态", "累计事件", "窗口事件", "窗口 IP", "协议背景", "诊断"],
      collector.rows.map((row) => [row.name, row.status, formatNumber(row.totalEvents), formatNumber(row.currentEvents), formatNumber(row.externalIps), row.protocolText, row.diagnosis]),
    ),
    "",
    "## 4. 研究洞察",
    "",
    research.conclusions.length
      ? research.conclusions.map((conclusion) => `- ${conclusion}`).join("\n")
      : "- 当前筛选条件下暂无事件，暂不能生成研究洞察。",
    "",
    "## 5. 攻击关系分析",
    "",
    `关系矩阵以源 IP、攻击方式和目标蜜罐为聚合键。当前窗口包含 ${formatNumber(relation.sourceCount)} 个源 IP、${formatNumber(relation.protocolCount)} 类攻击方式，最强关联为 ${relation.topRelation ? `${relation.topRelation.sourceIp} / ${relation.topRelation.protocol} -> ${relation.topRelation.honeypot}` : "暂无"}。`,
    "",
    buildMarkdownTable(
      ["源 IP", "攻击方式", "目标蜜罐", "事件数", "占比", "模式"],
      relation.pathRows.map((path) => [path.sourceIp, path.protocol, path.honeypot, formatNumber(path.count), `${path.rate}%`, path.pattern]),
    ),
    "",
    "## 6. 说明",
    "",
    "- 城市级地理定位为近似结果，应作为来源画像参考，而不是精确物理位置。",
    "- 若某蜜罐节点在线但窗口事件为 0，应结合日志路径、采集权限、端口暴露和当前攻击流量共同解释。",
    "- 本摘要基于当前前端筛选窗口生成，CSV/JSON 导出可作为附表进一步复核。",
    "",
  ];

  downloadTextFile(
    `honeypot_research_report_${exportTimestamp()}.md`,
    lines.join("\n"),
    "text/markdown;charset=utf-8",
  );
}

function exportStatsSnapshot(snapshot, events, activeProtocol, activeMethod) {
  const currentSourceIps = sourceRowsForExport(snapshot, events);
  const allSourceIps = allSourceRowsForExport(snapshot, events);
  const payload = {
    exportedAt: new Date().toISOString(),
    activeProtocol,
    activeMethod,
    activeMethodName: methodLabel(activeMethod),
    generatedAt: snapshot.generatedAt || snapshot.lastUpdated,
    generatedAtLocal: snapshot.generatedAtLocal,
    mode: snapshot.mode,
    stats: snapshot.stats,
    attackMethods: snapshot.attackMethodStats?.length ? snapshot.attackMethodStats : buildAttackMethodStats(events),
    currentAttackMethods: buildAttackMethodStats(events),
    protocols: snapshot.protocolStats,
    honeypots: snapshot.serverStats,
    sourceIps: currentSourceIps,
    allSourceIps,
    currentEvents: events,
  };
  downloadTextFile(
    `honeypot_stats_snapshot_${exportTimestamp()}.json`,
    JSON.stringify(payload, null, 2),
    "application/json;charset=utf-8",
  );
}

function createLoadingSnapshot() {
  const snapshot = createFallbackSnapshot();
  return {
    ...snapshot,
    mode: "loading",
    apiMessage: "正在连接 /api/dashboard",
    protocolStats: [],
    sourceStats: [],
    events: [],
    stats: {
      totalEvents: 0,
      totalDelta: 0,
      sessionCount: 0,
      sessionDelta: 0,
      externalIps: 0,
      ipDelta: 0,
      commandCount: 0,
      commandDelta: 0,
    },
    honeypots: snapshot.honeypots.map((honeypot) => ({
      ...honeypot,
      currentEvents: 0,
      windowEvents: 0,
      externalIps: 0,
      activeProtocols: [],
      protocols: [],
    })),
    serverStats: snapshot.serverStats.map((server) => ({
      ...server,
      totalEvents: 0,
      currentEvents: 0,
      windowEvents: 0,
      externalIps: 0,
      activeProtocols: [],
      protocols: [],
    })),
    trend: snapshot.trend.map((point) => ({ ...point, total: 0, high: 0 })),
  };
}

function App() {
  const [initialViewState] = useState(readUrlViewState);
  const [snapshot, setSnapshot] = useState(createLoadingSnapshot);
  const [paused, setPaused] = useState(false);
  const [activeProtocol, setActiveProtocol] = useState(initialViewState.activeProtocol);
  const [activeMethod, setActiveMethod] = useState(initialViewState.activeMethod);
  const [selectedIp, setSelectedIp] = useState(() => initialViewState.selectedIp || snapshot.sourceStats[0]?.srcIp || "");
  const [highOnly, setHighOnly] = useState(initialViewState.highOnly);
  const [query, setQuery] = useState(initialViewState.query);
  const [activeTab, setActiveTab] = useState(initialViewState.activeTab);
  const [rankingMode, setRankingMode] = useState(initialViewState.rankingMode);
  const [mapTimeRange, setMapTimeRange] = useState(initialViewState.mapTimeRange);
  const [refreshing, setRefreshing] = useState(false);
  const [apiError, setApiError] = useState("");
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [shareCopied, setShareCopied] = useState(false);

  const refreshSnapshot = useCallback(async ({ silent = false, force = false } = {}) => {
    if (!silent) setRefreshing(true);
    try {
      const nextSnapshot = await fetchThreatSnapshot({ force });
      setSnapshot((current) => {
        if (
          current?.mode &&
          current.mode !== "loading" &&
          current.stats?.liveConnected &&
          !nextSnapshot.stats?.liveConnected
        ) {
          return {
            ...nextSnapshot,
            stats: {
              ...nextSnapshot.stats,
              liveConnected: false,
              liveEventsSinceStart: current.stats.liveEventsSinceStart,
              liveWindowEvents: current.stats.liveWindowEvents,
              liveEventsPerSecond: current.stats.liveEventsPerSecond,
              liveLastEventDelaySeconds: current.stats.liveLastEventDelaySeconds,
            },
          };
        }
        return nextSnapshot;
      });
      setApiError(nextSnapshot.mode === "error" ? nextSnapshot.apiMessage : "");
    } catch (error) {
      const fallback = createFallbackSnapshot(error);
      setSnapshot((current) => {
        if (current?.mode && current.mode !== "loading" && current.events?.length) {
          return {
            ...current,
            apiMessage: `接口暂时不可用，保留上一版快照：${fallback.apiMessage}`,
          };
        }
        return fallback;
      });
      setApiError(fallback.apiMessage);
    } finally {
      if (!silent) setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    refreshSnapshot({ silent: true });
  }, [refreshSnapshot]);

  useEffect(() => {
    if (paused) return undefined;
    const timer = window.setInterval(() => refreshSnapshot({ silent: true }), REFRESH_INTERVAL_MS);
    return () => window.clearInterval(timer);
  }, [paused, refreshSnapshot]);

  const filteredEvents = useMemo(() => {
    return filterEventsByScope(snapshot.events, { activeProtocol, activeMethod, highOnly, query });
  }, [activeMethod, activeProtocol, highOnly, query, snapshot.events]);

  const detectorScopeEvents = useMemo(() => {
    const scopedEvents = filterEventsByScope(snapshot.events, {
      activeProtocol,
      activeMethod: "ALL",
      highOnly,
      query,
    });
    return filterEventsByMapTimeRange(scopedEvents, mapTimeRange, snapshot.generatedAt || snapshot.lastUpdated);
  }, [activeProtocol, highOnly, mapTimeRange, query, snapshot.events, snapshot.generatedAt, snapshot.lastUpdated]);
  const attackMethodStats = useMemo(() => detectorAttackMethodStats(snapshot, detectorScopeEvents, {
    activeProtocol,
    highOnly,
    mapTimeRange,
    query,
  }), [activeProtocol, detectorScopeEvents, highOnly, mapTimeRange, query, snapshot]);

  const hasScopedFilters = activeProtocol !== "ALL" || activeMethod !== "ALL" || highOnly || query.trim() !== "";
  const rankingSources = useMemo(() => {
    return hasScopedFilters || rankingMode === "protocol" ? sourceRowsForExport(snapshot, filteredEvents) : snapshot.sourceStats;
  }, [filteredEvents, hasScopedFilters, rankingMode, snapshot]);

  const rankings = useMemo(() => {
    const sorted = [...rankingSources];
    if (rankingMode === "risk") {
      if (hasScopedFilters) {
        return sorted.sort((a, b) => (b.windowRiskScore || 0) - (a.windowRiskScore || 0) || (b.events || 0) - (a.events || 0));
      }
      return sorted.sort((a, b) => b.riskScore - a.riskScore || b.eventTotal - a.eventTotal);
    }
    if (rankingMode === "protocol") {
      return sorted.sort((a, b) => (b.methodCount || b.protocolCount || 0) - (a.methodCount || a.protocolCount || 0) || (b.events || b.eventTotal || 0) - (a.events || a.eventTotal || 0));
    }
    if (hasScopedFilters) {
      return sorted.sort((a, b) => (b.events || 0) - (a.events || 0) || (b.eventTotal || b.total || 0) - (a.eventTotal || a.total || 0));
    }
    return sorted.sort((a, b) => b.eventTotal - a.eventTotal || b.riskScore - a.riskScore);
  }, [hasScopedFilters, rankingMode, rankingSources]);

  useEffect(() => {
    if (rankings.length && !rankings.some((source) => source.srcIp === selectedIp)) {
      setSelectedIp(rankings[0].srcIp);
    } else if (!rankings.length && selectedIp) {
      setSelectedIp("");
    }
  }, [rankings, selectedIp]);

  const selectedSource = useMemo(() => {
    return rankings.find((source) => source.srcIp === selectedIp) ?? rankings[0];
  }, [rankings, selectedIp]);

  const selectedIpForUrl = selectedIp && selectedIp !== rankings[0]?.srcIp ? selectedIp : "";
  const shareableSearch = useMemo(() => buildUrlViewSearch({
    activeTab,
    activeProtocol,
    activeMethod,
    highOnly,
    mapTimeRange,
    query,
    rankingMode,
    selectedIp: selectedIpForUrl,
  }), [activeMethod, activeProtocol, activeTab, highOnly, mapTimeRange, query, rankingMode, selectedIpForUrl]);

  const shareableUrl = useMemo(() => {
    if (typeof window === "undefined") return "";
    return `${window.location.origin}${window.location.pathname}${shareableSearch}`;
  }, [shareableSearch]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const nextUrl = `${window.location.pathname}${shareableSearch}`;
    const currentUrl = `${window.location.pathname}${window.location.search}`;
    if (nextUrl !== currentUrl) {
      window.history.replaceState(null, "", nextUrl);
    }
  }, [shareableSearch]);

  useEffect(() => {
    if (!shareCopied) return undefined;
    const timer = window.setTimeout(() => setShareCopied(false), 1800);
    return () => window.clearTimeout(timer);
  }, [shareCopied]);

  useEffect(() => {
    const handleFullscreenChange = () => setIsFullscreen(Boolean(document.fullscreenElement));
    document.addEventListener("fullscreenchange", handleFullscreenChange);
    handleFullscreenChange();
    return () => document.removeEventListener("fullscreenchange", handleFullscreenChange);
  }, []);

  const enterFullscreen = useCallback(async () => {
    if (!document.fullscreenElement && document.documentElement.requestFullscreen) {
      await document.documentElement.requestFullscreen().catch(() => {});
    }
  }, []);

  const toggleFullscreen = useCallback(async () => {
    if (document.fullscreenElement && document.exitFullscreen) {
      await document.exitFullscreen().catch(() => {});
      return;
    }
    await enterFullscreen();
  }, [enterFullscreen]);

  const copyShareLink = useCallback(async () => {
    if (!shareableUrl) return;
    try {
      await navigator.clipboard.writeText(shareableUrl);
    } catch {
      const textarea = document.createElement("textarea");
      textarea.value = shareableUrl;
      textarea.setAttribute("readonly", "");
      textarea.style.position = "fixed";
      textarea.style.opacity = "0";
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand("copy");
      textarea.remove();
    }
    setShareCopied(true);
  }, [shareableUrl]);

  function handleTabClick(tab) {
    setActiveTab(tab);
  }

  const commonProps = {
    activeProtocol,
    activeMethod,
    apiError,
    attackMethodStats,
    filteredEvents,
    highOnly,
    isScopedWindow: hasScopedFilters,
    mapTimeRange,
    paused,
    query,
    rankingMode,
    rankings,
    selectedIp,
    sourceProfileSelectedIp: selectedIpForUrl ? selectedIp : "",
    selectedSource,
    setActiveProtocol,
    setActiveMethod,
    setHighOnly,
    setMapTimeRange,
    setPaused,
    setQuery,
    setRankingMode,
    setSelectedIp,
    snapshot,
  };

  return (
    <div className="app-shell">
      <Header
        activeTab={activeTab}
        paused={paused}
        refreshing={refreshing}
        snapshot={snapshot}
        tabs={tabs}
        isFullscreen={isFullscreen}
        shareCopied={shareCopied}
        onRefresh={() => refreshSnapshot({ force: true })}
        onCopyShareLink={copyShareLink}
        onTabClick={handleTabClick}
        onToggleFullscreen={toggleFullscreen}
        onTogglePause={() => setPaused((value) => !value)}
      />

      {activeTab === "攻击分析" ? (
        <AnalyticsView {...commonProps} defaultGroup="summary" />
      ) : activeTab === "源 IP 画像" ? (
        <AnalyticsView {...commonProps} defaultGroup="relations" />
      ) : activeTab === "系统与导出" ? (
        <DataSourceView {...commonProps} defaultGroup="collection" />
      ) : (
        <MapDashboard {...commonProps} />
      )}
    </div>
  );
}

function Header({
  activeTab,
  isFullscreen,
  paused,
  refreshing,
  shareCopied,
  snapshot,
  tabs,
  onCopyShareLink,
  onRefresh,
  onTabClick,
  onToggleFullscreen,
  onTogglePause,
}) {
  const [menuOpen, setMenuOpen] = useState(false);
  const modeText = dataModeLabel(snapshot.mode, paused);
  const updatedAt = formatSnapshotTime(snapshot.lastUpdated);
  const handleNavClick = (tab) => {
    onTabClick(tab);
    setMenuOpen(false);
  };

  return (
    <header className="topbar">
      <div className="brand-area">
        <button
          aria-controls="quick-nav-menu"
          aria-expanded={menuOpen}
          aria-label={menuOpen ? "关闭菜单" : "打开菜单"}
          className={menuOpen ? "menu-button active" : "menu-button"}
          onClick={() => setMenuOpen((value) => !value)}
          type="button"
        >
          <span />
          <span />
          <span />
        </button>
        <div className="brand-mark" aria-hidden="true">
          <Shield size={26} />
        </div>
        <div className="brand-copy">
          <h1 title="基于多源威胁情报大数据的实时网络安全态势感知系统">基于多源威胁情报大数据的实时网络安全态势感知系统</h1>
          <p>Distributed Honeypot Threat Intelligence</p>
        </div>
        {menuOpen && (
          <div className="quick-nav-menu" id="quick-nav-menu" role="menu" aria-label="快速切换">
            {tabs.map((tab) => (
              <button
                className={activeTab === tab ? "active" : ""}
                key={tab}
                onClick={() => handleNavClick(tab)}
                role="menuitem"
                type="button"
              >
                {tab}
              </button>
            ))}
          </div>
        )}
      </div>

      <nav className="top-tabs" aria-label="主导航">
        {tabs.map((tab) => (
          <button
            className={activeTab === tab ? "active" : ""}
            key={tab}
            onClick={() => handleNavClick(tab)}
            type="button"
          >
            {tab}
          </button>
        ))}
      </nav>

      <div className="top-status">
        <span>{updatedAt}</span>
        <span className={`status-dot ${paused ? "paused" : snapshot.mode}`} />
        <strong>{modeText}</strong>
        <button
          className={shareCopied ? "icon-action share-action copied" : "icon-action share-action"}
          onClick={onCopyShareLink}
          type="button"
          aria-label={shareCopied ? "当前分析链接已复制" : "复制当前分析链接"}
          title={shareCopied ? "已复制当前分析链接" : "复制当前分析链接"}
        >
          {shareCopied ? <CheckCircle2 size={18} /> : <Link2 size={18} />}
        </button>
        <button className="icon-action" onClick={onRefresh} type="button" aria-label="刷新接口数据">
          <RefreshCw size={18} className={refreshing ? "spin" : ""} />
        </button>
        <button className="icon-action" onClick={onTogglePause} type="button" aria-label={paused ? "继续自动刷新" : "暂停自动刷新"}>
          {paused ? <Play size={18} /> : <Pause size={18} />}
        </button>
        <button className="icon-action" onClick={onToggleFullscreen} type="button" aria-label={isFullscreen ? "退出全屏" : "全屏"}>
          {isFullscreen ? <Minimize2 size={18} /> : <Maximize2 size={18} />}
        </button>
      </div>
    </header>
  );
}

function MapDashboard({
  activeMethod,
  activeProtocol,
  apiError,
  attackMethodStats,
  filteredEvents,
  highOnly,
  isScopedWindow,
  mapTimeRange,
  paused,
  query,
  rankingMode,
  rankings,
  selectedIp,
  selectedSource,
  setActiveMethod,
  setActiveProtocol,
  setHighOnly,
  setMapTimeRange,
  setPaused,
  setQuery,
  setRankingMode,
  setSelectedIp,
  snapshot,
}) {
  const collectorHealth = buildCollectorHealthStats(snapshot);
  const onlineCount = snapshot.serverStats.filter((server) => ["online", "running"].includes(String(server.status || "").toLowerCase())).length;
  const [mapFullscreen, setMapFullscreen] = useState(false);
  const [globeIntroActive, setGlobeIntroActive] = useState(false);
  const [selectedMapEvent, setSelectedMapEvent] = useState(null);
  const mapRangeEvents = useMemo(
    () => filterEventsByMapTimeRange(filteredEvents, mapTimeRange, snapshot.generatedAt || snapshot.lastUpdated),
    [filteredEvents, mapTimeRange, snapshot.generatedAt, snapshot.lastUpdated],
  );
  const mapFlowEvents = useMemo(() => selectMapEventsBySourceIp(mapRangeEvents), [mapRangeEvents]);
  const overviewStreamEvents = useMemo(() => mapRangeEvents.slice(0, 80), [mapRangeEvents]);
  const handleMapEventSelect = useCallback((event, pointerEvent) => {
    if (!event) {
      setSelectedMapEvent(null);
      return;
    }
    const clientX = Number(pointerEvent?.clientX);
    const clientY = Number(pointerEvent?.clientY);
    const eventTarget = pointerEvent?.currentTarget;
    const panelElement = eventTarget?.closest?.(".map-panel")
      || eventTarget?.ownerSVGElement?.closest?.(".map-panel")
      || (typeof document === "undefined" ? null : document.querySelector(".map-panel"));
    const panelRect = pointerEvent?.mapBounds || panelElement?.getBoundingClientRect?.();
    const panelBounds = panelRect
      ? {
          left: panelRect.left,
          right: panelRect.right,
          top: panelRect.top,
          bottom: panelRect.bottom,
          width: panelRect.width,
          height: panelRect.height,
        }
      : null;
    setSelectedMapEvent({
      event,
      x: Number.isFinite(clientX) ? clientX : 0,
      y: Number.isFinite(clientY) ? clientY : 0,
      bounds: panelBounds,
    });
    if (isKnown(event.srcIp)) setSelectedIp(event.srcIp);
  }, [setSelectedIp]);

  useEffect(() => {
    if (!mapFullscreen) return undefined;
    document.body.classList.add("map-fullscreen-open");
    const handleKeyDown = (event) => {
      if (event.key === "Escape") setMapFullscreen(false);
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => {
      document.body.classList.remove("map-fullscreen-open");
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [mapFullscreen]);

  useEffect(() => {
    if (!mapFullscreen) {
      setGlobeIntroActive(false);
      return undefined;
    }
    setGlobeIntroActive(true);
    const introTimer = window.setTimeout(() => setGlobeIntroActive(false), 1500);
    return () => window.clearTimeout(introTimer);
  }, [mapFullscreen]);

  return (
    <main className="dashboard-grid">
      <aside className="left-rail" aria-label="态势总览左侧控制">
        <DetectorPanel
          activeMethod={activeMethod}
          activeProtocol={activeProtocol}
          methods={attackMethodStats}
          mode={snapshot.mode}
          scopeLabel={mapTimeRangeOption(mapTimeRange).label}
          serverCount={snapshot.honeypots.length}
          onSelectMethod={setActiveMethod}
          onSelectProtocol={setActiveProtocol}
        />
      </aside>

      <KpiRow
        loading={snapshot.mode === "loading"}
        onlineCount={onlineCount}
        serverTotal={snapshot.serverStats.length || snapshot.honeypots.length}
        stats={snapshot.stats}
      />

      <section className={mapFullscreen ? "map-panel map-panel-fullscreen" : "map-panel"} aria-label="世界攻击态势地图">
        {mapFullscreen ? (
          <FullscreenMapChrome
            activeMethod={activeMethod}
            activeProtocol={activeProtocol}
            apiError={apiError}
            dataMode={snapshot.mode}
            events={mapRangeEvents}
            highOnly={highOnly}
            mapEventCount={mapRangeEvents.length}
            mapSourceCount={mapFlowEvents.length}
            mapTimeRange={mapTimeRange}
            onlineCount={onlineCount}
            paused={paused}
            query={query}
            snapshot={snapshot}
            onMapTimeRangeChange={setMapTimeRange}
            onQueryChange={setQuery}
            onToggleHighOnly={() => setHighOnly((value) => !value)}
            onToggleMapFullscreen={() => setMapFullscreen(false)}
            onTogglePause={() => setPaused((value) => !value)}
          />
        ) : (
          <MapToolbar
            activeMethod={activeMethod}
            activeProtocol={activeProtocol}
            apiError={apiError}
            dataMode={snapshot.mode}
            highOnly={highOnly}
            mapEventCount={mapRangeEvents.length}
            mapFullscreen={mapFullscreen}
            mapSourceCount={mapFlowEvents.length}
            mapTimeRange={mapTimeRange}
            paused={paused}
            query={query}
            onMapTimeRangeChange={setMapTimeRange}
            onQueryChange={setQuery}
            onToggleHighOnly={() => setHighOnly((value) => !value)}
            onToggleMapFullscreen={() => setMapFullscreen((value) => !value)}
            onTogglePause={() => setPaused((value) => !value)}
          />
        )}
        <ThreatMap
          events={mapFlowEvents}
          fullscreen={mapFullscreen}
          globeIntroActive={globeIntroActive}
          honeypots={snapshot.honeypots}
          selectedEventId={selectedMapEvent?.event.id}
          selectedIp={selectedIp}
          onSelectEvent={handleMapEventSelect}
          onSelectIp={setSelectedIp}
        />
        {selectedMapEvent && (
          <MapEventPopover
            bounds={selectedMapEvent.bounds}
            event={selectedMapEvent.event}
            x={selectedMapEvent.x}
            y={selectedMapEvent.y}
            onClose={() => setSelectedMapEvent(null)}
          />
        )}
      </section>

      <section className="event-panel overview-event-panel" aria-label="态势总览实时事件流">
        <EventStream
          activeMethod={activeMethod}
          activeProtocol={activeProtocol}
          compact
          detailMode="none"
          events={overviewStreamEvents}
          onPause={() => setPaused((value) => !value)}
          paused={paused}
          showSummaryColumn={false}
          summaryOnSelect
          wide
        />
      </section>

      <aside className="overview-source-panel" aria-label="态势总览选中源详情">
        <SourceDetail compact isScopedWindow={isScopedWindow} source={selectedSource} />
      </aside>

      <RankingPanel
        isScopedWindow={isScopedWindow}
        rankingMode={rankingMode}
        rankings={rankings}
        selectedIp={selectedIp}
        selectedSource={selectedSource}
        onRankingModeChange={setRankingMode}
        onSelectIp={setSelectedIp}
        compact
        limit={9}
      />

      <HoneypotStatusPanel collectorHealth={collectorHealth} events={filteredEvents} snapshot={snapshot} />
    </main>
  );
}

function AnalyticsView({
  activeMethod,
  activeProtocol,
  defaultGroup = "summary",
  filteredEvents,
  highOnly,
  query,
  selectedIp,
  setSelectedIp,
  sourceProfileSelectedIp,
  snapshot,
}) {
  const activeGroup = defaultGroup;

  return (
    <main className="workspace-grid analytics-grid grouped-workspace">
      {activeGroup === "summary" && (
        <>
          <KpiRow
            loading={snapshot.mode === "loading"}
            onlineCount={snapshot.serverStats.filter((server) => ["online", "running"].includes(String(server.status || "").toLowerCase())).length}
            serverTotal={snapshot.serverStats.length || snapshot.honeypots.length}
            stats={snapshot.stats}
          />

          <section className="analysis-panel insight-panel">
            <AttackTimeSeriesPanel
              activeMethod={activeMethod}
              activeProtocol={activeProtocol}
              events={filteredEvents}
              loading={snapshot.mode === "loading"}
              snapshot={snapshot}
            />
          </section>
        </>
      )}

      {activeGroup === "relations" && (
        <section className="analysis-panel relation-panel">
          <RelationshipPanel events={snapshot.events} selectedIp={sourceProfileSelectedIp || ""} sourceStats={snapshot.sourceStats} onSelectIp={setSelectedIp} />
        </section>
      )}
    </main>
  );
}

function DataSourceView({ activeMethod, activeProtocol, filteredEvents, snapshot }) {
  const [exportRange, setExportRange] = useState("all");
  const [customRange, setCustomRange] = useState(() => {
    const end = Date.now();
    return {
      start: formatBeijingDateTimeInput(end - DAY_MS),
      end: formatBeijingDateTimeInput(end),
    };
  });
  const [selectedFieldKeys, setSelectedFieldKeys] = useState(COMMON_EVENT_CSV_FIELD_KEYS);
  const [previewLimit, setPreviewLimit] = useState(6);
  const [tasks, setTasks] = useState([]);
  const [eventExporting, setEventExporting] = useState(false);

  const selectedColumns = useMemo(() => eventCsvColumnsFor(selectedFieldKeys), [selectedFieldKeys]);
  const exportAnchor = snapshot.generatedAt || snapshot.lastUpdated;
  const exportRangeBounds = useMemo(
    () => buildExportTimeRange(exportRange, customRange, exportAnchor, filteredEvents),
    [customRange.end, customRange.start, exportAnchor, exportRange, filteredEvents],
  );
  const exportEventsInRange = useMemo(
    () => filterEventsByExportTimeRange(filteredEvents, exportRangeBounds),
    [exportRangeBounds, filteredEvents],
  );
  const historyExportEventCount = useMemo(
    () => historyCountForExportRange(snapshot.historyTrend, { activeMethod, activeProtocol, rangeBounds: exportRangeBounds }),
    [activeMethod, activeProtocol, exportRangeBounds, snapshot.historyTrend],
  );
  const allSourceRows = useMemo(() => allSourceRowsForExport(snapshot, filteredEvents), [filteredEvents, snapshot]);
  const methodRows = useMemo(() => buildAttackMethodStats(exportEventsInRange), [exportEventsInRange]);
  const fieldCount = selectedFieldKeys.length;
  const usePreviewExportCount = exportEventsInRange.length > 0 && (!historyExportEventCount || historyExportEventCount < exportEventsInRange.length);
  const exportEventCount = usePreviewExportCount ? exportEventsInRange.length : (historyExportEventCount ?? exportEventsInRange.length);
  const exportCountSource = usePreviewExportCount ? "当前快照可导出" : historyExportEventCount !== null ? "历史聚合参考" : "当前预览";
  const exportRangeText = exportRangeDescription(exportRange, exportRangeBounds);
  const snapshotExportEventCount = exportEventsInRange.length;
  const hasHistoryAggregateCount = Number.isFinite(historyExportEventCount);
  const hasHistorySnapshotGap = hasHistoryAggregateCount && historyExportEventCount > snapshotExportEventCount;
  const eventExportMeta = hasHistorySnapshotGap
    ? `历史聚合参考 ${formatNumber(historyExportEventCount)} 条 · 当前预览 ${formatNumber(snapshotExportEventCount)} 条 · ${exportRangeText} · 已选择 ${formatNumber(fieldCount)} 个字段`
    : `${formatNumber(exportEventCount)} 条${exportCountSource} · ${exportRangeText} · 已选择 ${formatNumber(fieldCount)} 个字段`;
  const exportRangeReady = Boolean(exportRangeBounds.valid);
  const exportScope = [
    activeMethod === "ALL" ? "全部攻击方式" : methodLabel(activeMethod),
    activeProtocol === "ALL" ? "" : `协议 ${activeProtocol}`,
  ].filter(Boolean).join(" / ");

  const addTask = useCallback((file, range = exportRange, count = fieldCount, status = "已完成") => {
    const rangeLabel = EXPORT_RANGE_OPTIONS.find((option) => option.key === range)?.label || "全部";
    setTasks((current) => [
      {
        id: `${Date.now()}-${file}`,
        time: new Date().toLocaleTimeString("zh-CN", { hour12: false }),
        range: rangeLabel,
        fieldCount: count,
        file,
        status,
      },
      ...current,
    ].slice(0, 5));
  }, [exportRange, fieldCount]);

  const toggleField = useCallback((fieldKey) => {
    setSelectedFieldKeys((current) => (
      current.includes(fieldKey)
        ? current.filter((key) => key !== fieldKey)
        : [...current, fieldKey]
    ));
  }, []);

  const reorderField = useCallback((sourceKey, targetKey) => {
    setSelectedFieldKeys((current) => {
      const sourceIndex = current.indexOf(sourceKey);
      const targetIndex = current.indexOf(targetKey);
      return moveListItem(current, sourceIndex, targetIndex);
    });
  }, []);

  const handleEventExport = async () => {
    if (!exportRangeReady || !exportEventCount || !fieldCount || eventExporting) return;
    setEventExporting(true);
    try {
      const result = await exportFullEventsCsv({
        activeMethod,
        activeProtocol,
        anchorTime: exportAnchor,
        events: exportEventsInRange,
        fieldKeys: selectedFieldKeys,
        range: exportRange,
        rangeBounds: exportRangeBounds,
      });
      const sourceLabel =
        result.mode === "server-stream" ? "后端流式" : result.mode === "server" ? "后端全量" : "本地快照";
      const rowLabel = Number.isFinite(Number(result.rowCount)) ? `${formatNumber(result.rowCount)} 行` : "浏览器下载";
      addTask(`攻击事件 CSV · ${sourceLabel} · ${rowLabel}`, exportRange, fieldCount);
    } finally {
      setEventExporting(false);
    }
  };

  const exportRows = [
    {
      key: "source-list",
      name: "源 IP 列表 TXT",
      meta: `${formatNumber(allSourceRows.length)} 个去重源 IP`,
      disabled: !allSourceRows.length,
      icon: Download,
      action: () => {
        exportSourceIpList(snapshot, filteredEvents);
        addTask("源 IP 列表 TXT", "all", "-");
      },
    },
    {
      key: "source-profile",
      name: "源 IP 画像 CSV",
      meta: "去重源 IP、地理位置、ASN、事件数和风险分",
      disabled: !allSourceRows.length,
      icon: FileSpreadsheet,
      action: () => {
        exportSourceIps(snapshot, filteredEvents);
        addTask("源 IP 画像 CSV", "all", "-");
      },
    },
    {
      key: "attack-methods",
      name: "攻击方式聚合 CSV",
      meta: `${formatNumber(methodRows.length)} 类攻击方式`,
      disabled: !methodRows.length,
      icon: FileSpreadsheet,
      action: () => {
        exportAttackMethodStats(snapshot, exportEventsInRange);
        addTask("攻击方式聚合 CSV", exportRange, "-");
      },
    },
    {
      key: "honeypot-nodes",
      name: "蜜罐节点聚合 CSV",
      meta: `${formatNumber(snapshot.serverStats.length)} 个采集节点`,
      disabled: !snapshot.serverStats.length,
      icon: FileSpreadsheet,
      action: () => {
        exportHoneypotStats(snapshot, filteredEvents);
        addTask("蜜罐节点聚合 CSV", "all", "-");
      },
    },
    {
      key: "report-md",
      name: "分析摘要 MD",
      meta: "统计结论与研判素材",
      icon: FileJson,
      action: () => {
        exportResearchReportMarkdown(snapshot, filteredEvents, activeProtocol, activeMethod);
        addTask("分析摘要 MD", exportRange, "-");
      },
    },
    {
      key: "snapshot-json",
      name: "统计快照 JSON",
      meta: exportScope,
      icon: FileJson,
      action: () => {
        exportStatsSnapshot(snapshot, filteredEvents, activeProtocol, activeMethod);
        addTask("统计快照 JSON", "all", "-");
      },
    },
  ];

  const runtimeRows = buildExportRuntimeRows(snapshot);
  const dataSourceRows = [
    {
      label: "快照来源",
      value: snapshot.mode === "api" ? "dashboard.json + dashboard-live.json" : snapshot.apiMessage || "未连接",
    },
    {
      label: "事件导出",
      value: "/api/export/events.csv；47 代理受控 HDFS DWD API，小结果校验后导出",
    },
    {
      label: "字段选择",
      value: `${formatNumber(fieldCount)} / ${formatNumber(ALL_EVENT_CSV_FIELD_KEYS.length)} 个 CSV 字段`,
    },
    {
      label: "地理位置",
      value: "使用后端 geo 字段和 ipwho.is 缓存结果",
    },
  ];

  return (
    <main className="workspace-grid export-workspace">
      <section className="analysis-panel export-hero-panel">
        <div>
          <span>报表导出</span>
          <h2>系统设置与数据导出</h2>
          <p>按范围生成导出文件，并自定义攻击事件 CSV 字段。</p>
        </div>
        <div className="export-hero-meta" aria-label="导出页摘要">
          <strong>{formatNumber(snapshot.stats?.totalEvents ?? filteredEvents.length)}</strong>
          <span>历史事件</span>
          <strong>{formatNumber(allSourceRows.length)}</strong>
          <span>源 IP 画像</span>
        </div>
      </section>

      <div className="export-main-stack">
        <section className="analysis-panel export-center-panel">
          <PanelHeading icon={Download} title="导出中心" subtitle="选择范围、文件类型和攻击事件 CSV 字段" />
          <SegmentedControl options={EXPORT_RANGE_OPTIONS} value={exportRange} onChange={setExportRange} ariaLabel="导出时间范围" />
          {exportRange === "custom" && (
            <CustomExportRangeControl
              range={customRange}
              rangeReady={exportRangeReady}
              onChange={setCustomRange}
            />
          )}

          <div className="export-type-list" aria-label="导出文件类型">
            <article className="export-type-row expanded">
              <div className="export-type-main">
                <span className="export-type-icon"><FileSpreadsheet size={17} /></span>
                <div>
                  <strong>攻击事件 CSV</strong>
                  <small>{eventExportMeta}</small>
                </div>
                <button className="export-row-action primary" type="button" disabled={!exportRangeReady || !exportEventCount || !fieldCount || eventExporting} onClick={handleEventExport}>
                  {eventExporting ? "生成中" : "生成 CSV"}
                </button>
              </div>
              {hasHistorySnapshotGap && (
                <p className="export-count-note">
                  历史聚合只用于估算范围内事件规模；CSV 会优先请求后端全量明细，若后端明细源没有行，则使用当前快照事件兜底。源 IP 列表和画像按 IP 去重，所以数量会明显小于攻击事件行数。
                </p>
              )}
              <CsvFieldSelector
                selectedFieldKeys={selectedFieldKeys}
                onReorderField={reorderField}
                onToggleField={toggleField}
                onSelectAll={() => setSelectedFieldKeys(ALL_EVENT_CSV_FIELD_KEYS)}
                onSelectCommon={() => setSelectedFieldKeys(COMMON_EVENT_CSV_FIELD_KEYS)}
                onClear={() => setSelectedFieldKeys([])}
              />
            </article>

            {exportRows.map(({ action, disabled, icon: Icon, key, meta, name }) => (
              <button className="export-type-row compact" disabled={disabled} key={key} onClick={action} type="button">
                <span className="export-type-icon"><Icon size={17} /></span>
                <span>
                  <strong>{name}</strong>
                  <small>{meta}</small>
                </span>
                <em>导出</em>
              </button>
            ))}
          </div>
        </section>

        <section className="analysis-panel export-task-panel">
          <ExportTaskTable tasks={tasks} />
        </section>
      </div>

      <aside className="export-side-stack">
        <section className="analysis-panel export-preview-panel">
          <PanelHeading icon={FileSpreadsheet} title="导出预览" subtitle="跟随字段选择展示 CSV 前几列" />
          <ExportPreview columns={selectedColumns} events={exportEventsInRange} limit={previewLimit} scopeCount={exportEventCount} />
          <div className="export-panel-actions">
            <button className="tool-button" type="button" onClick={() => setPreviewLimit(20)}>预览前 20 行</button>
            <button className="tool-button" type="button" onClick={() => setPreviewLimit(6)}>收起预览</button>
          </div>
        </section>

        <section className="analysis-panel export-config-panel">
          <PanelHeading icon={Shield} title="数据来源" subtitle="只展示当前真实接入状态，不提供前端伪开关" />
          <div className="config-grid">
            {dataSourceRows.map((row) => (
              <article className="config-control readonly" key={row.label}>
                <span>{row.label}</span>
                <strong>{row.value}</strong>
              </article>
            ))}
          </div>
        </section>

        <section className="analysis-panel export-runtime-panel">
          <RuntimeStatusTable rows={runtimeRows} />
        </section>
      </aside>
    </main>
  );
}

const EXPORT_RANGE_OPTIONS = [
  { key: "all", label: "全部" },
  { key: "24h", label: "24小时" },
  { key: "7d", label: "7天" },
  { key: "30d", label: "30天" },
  { key: "custom", label: "自定义" },
];

function SegmentedControl({ ariaLabel, onChange, options, value }) {
  return (
    <div className="segmented-control" role="tablist" aria-label={ariaLabel}>
      {options.map((option) => (
        <button
          aria-selected={value === option.key}
          className={value === option.key ? "active" : ""}
          key={option.key}
          onClick={() => onChange(option.key)}
          role="tab"
          type="button"
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}

function CustomExportRangeControl({ onChange, range, rangeReady }) {
  const updateRange = (key, value) => {
    onChange((current) => ({ ...current, [key]: value }));
  };

  return (
    <div className={rangeReady ? "custom-export-range" : "custom-export-range invalid"} aria-label="自定义导出时间范围">
      <label>
        <span>开始时间</span>
        <input
          max={range.end || undefined}
          onChange={(event) => updateRange("start", event.target.value)}
          type="datetime-local"
          value={range.start}
        />
      </label>
      <label>
        <span>结束时间</span>
        <input
          min={range.start || undefined}
          onChange={(event) => updateRange("end", event.target.value)}
          type="datetime-local"
          value={range.end}
        />
      </label>
      <small>{rangeReady ? "按北京时间筛选历史事件" : "结束时间必须晚于开始时间"}</small>
    </div>
  );
}

function CsvFieldSelector({ onClear, onReorderField, onSelectAll, onSelectCommon, onToggleField, selectedFieldKeys }) {
  const [draggedFieldKey, setDraggedFieldKey] = useState("");
  const selectedFields = selectedFieldKeys.map((key) => EVENT_CSV_FIELD_LOOKUP.get(key)).filter(Boolean);

  const handleDragStart = (event, fieldKey) => {
    setDraggedFieldKey(fieldKey);
    event.dataTransfer.effectAllowed = "move";
    event.dataTransfer.setData("text/plain", fieldKey);
  };

  const handleDrop = (event, targetKey) => {
    event.preventDefault();
    const sourceKey = event.dataTransfer.getData("text/plain") || draggedFieldKey;
    if (sourceKey && sourceKey !== targetKey) {
      onReorderField(sourceKey, targetKey);
    }
    setDraggedFieldKey("");
  };

  const handleOrderKeyDown = (event, fieldKey) => {
    if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
    const currentIndex = selectedFieldKeys.indexOf(fieldKey);
    const targetIndex = event.key === "ArrowLeft" ? currentIndex - 1 : currentIndex + 1;
    const targetKey = selectedFieldKeys[targetIndex];
    if (!targetKey) return;
    event.preventDefault();
    onReorderField(fieldKey, targetKey);
  };

  return (
    <div className="csv-field-selector" aria-label="攻击事件 CSV 字段选择">
      <div className="csv-field-toolbar">
        <span>{formatNumber(selectedFieldKeys.length)} / {formatNumber(ALL_EVENT_CSV_FIELD_KEYS.length)} 字段</span>
        <div>
          <button type="button" onClick={onSelectAll}>全选</button>
          <button type="button" onClick={onSelectCommon}>仅常用</button>
          <button type="button" onClick={onClear}>清空</button>
        </div>
      </div>
      {selectedFields.length > 0 && (
        <div className="csv-field-order" aria-label="CSV 字段输出顺序">
          <div className="csv-field-order-head">
            <strong>导出列顺序</strong>
            <span>{formatNumber(selectedFields.length)} 列</span>
          </div>
          <div className="csv-field-order-list" role="listbox" aria-label="导出列顺序">
            {selectedFields.map((field, index) => (
              <div
                aria-label={`${field.label} 第 ${index + 1} 列`}
                className={draggedFieldKey === field.key ? "field-order-chip dragging" : "field-order-chip"}
                draggable
                key={field.key}
                onDragEnd={() => setDraggedFieldKey("")}
                onDragOver={(event) => event.preventDefault()}
                onDragStart={(event) => handleDragStart(event, field.key)}
                onDrop={(event) => handleDrop(event, field.key)}
                onKeyDown={(event) => handleOrderKeyDown(event, field.key)}
                role="option"
                tabIndex={0}
              >
                <GripVertical size={13} aria-hidden="true" />
                <span>{index + 1}</span>
                <strong>{field.label}</strong>
              </div>
            ))}
          </div>
        </div>
      )}
      <div className="csv-field-groups">
        {EVENT_CSV_FIELD_GROUPS.map((group) => (
          <fieldset className="csv-field-group" key={group.key}>
            <legend>{group.label}</legend>
            <div>
              {group.fields.map((field) => (
                <label className="field-check" key={field.key}>
                  <input
                    checked={selectedFieldKeys.includes(field.key)}
                    onChange={() => onToggleField(field.key)}
                    type="checkbox"
                  />
                  <span>{field.label}</span>
                </label>
              ))}
            </div>
          </fieldset>
        ))}
      </div>
    </div>
  );
}

function ExportPreview({ columns, events, limit, scopeCount = events.length }) {
  const previewColumns = columns;
  const previewEvents = events.slice(0, limit);
  const minTableWidth = Math.max(previewColumns.length * 132, 520);

  if (!previewColumns.length) {
    return <p className="empty-note">请选择至少一个字段后预览 CSV 结构。</p>;
  }

  if (!previewEvents.length) {
    const message = scopeCount > 0
      ? `当前快照没有可预览样例；后端会按历史全量日志导出 ${formatNumber(scopeCount)} 条匹配事件。`
      : "当前范围内暂无可预览事件。";
    return <p className="empty-note">{message}</p>;
  }

  return (
    <>
      <div className="csv-preview-scroll-hint">左右滑动查看全部 {formatNumber(previewColumns.length)} 个字段</div>
      <div className="csv-preview-table" aria-label="攻击事件 CSV 预览">
        <table style={{ minWidth: `${minTableWidth}px` }}>
          <thead>
            <tr>
              {previewColumns.map((column) => <th key={column.label}>{column.label}</th>)}
            </tr>
          </thead>
          <tbody>
            {previewEvents.map((event, index) => (
              <tr key={`${event.srcIp}-${event.timestamp}-${index}`}>
                {previewColumns.map((column) => (
                  <td key={column.label}>{compactText(valueToText(column.value(event)), 34)}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

function ExportTaskTable({ tasks }) {
  const visibleTasks = tasks.length ? tasks : [
    {
      id: "empty",
      time: "--",
      range: "等待选择",
      fieldCount: "--",
      file: "暂无导出任务",
      status: "未生成",
    },
  ];

  return (
    <>
      <PanelHeading icon={Clock} title="导出任务" subtitle="最近生成的导出文件记录" />
      <div className="compact-data-table">
        <table>
          <thead>
            <tr>
              <th>时间</th>
              <th>范围</th>
              <th>字段数</th>
              <th>文件</th>
              <th>状态</th>
            </tr>
          </thead>
          <tbody>
            {visibleTasks.map((task) => (
              <tr key={task.id}>
                <td>{task.time}</td>
                <td>{task.range}</td>
                <td>{task.fieldCount}</td>
                <td>{task.file}</td>
                <td><span className={`state-chip ${task.status === "已完成" ? "ok" : "muted"}`}>{task.status}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

function RuntimeStatusTable({ rows }) {
  return (
    <>
      <PanelHeading icon={Activity} title="运行状态" subtitle="导出依赖的采集、计算和发布链路" />
      <div className="runtime-list">
        {rows.map((row) => (
          <div className="runtime-row" key={row.label}>
            <span className={`state-dot ${row.tone}`} />
            <strong>{row.label}</strong>
            <p>{row.detail}</p>
            <em className={`state-chip ${row.tone}`}>{row.status}</em>
          </div>
        ))}
      </div>
    </>
  );
}

function buildExportRuntimeRows(snapshot) {
  const serverCount = snapshot.serverStats?.length || 0;
  const onlineCount = snapshot.serverStats?.filter((server) => ["online", "running"].includes(String(server.status || "").toLowerCase())).length || 0;
  const liveConnected = Boolean(snapshot.stats?.liveConnected);
  const apiConnected = snapshot.mode === "api";
  const endpointByKey = new Map((snapshot.endpoints || []).map((endpoint) => [endpoint.key, endpoint.status]));
  const runtimeHealth = snapshot.runtimeHealth;
  const runtimeSummary = runtimeHealth?.available ? runtimeHealth.summary : null;
  const runtimeTone = runtimeSummary?.status === "ok"
    ? "ok"
    : runtimeSummary?.status === "error"
      ? "warn"
      : "warn";
  const runtimeStatus = runtimeSummary?.label || "未探测";
  const runtimeDetail = runtimeSummary
    ? `${runtimeSummary.detail}；${formatNumber(runtimeSummary.okCount)} / ${formatNumber(runtimeSummary.total)} 项正常`
    : "后端健康探针未返回，不能仅凭页面判定 Kafka/Flink/HDFS 正常";
  return [
    {
      label: "蜜罐节点快照",
      detail: serverCount ? `${formatNumber(onlineCount)} / ${formatNumber(serverCount)} 个节点上报在线` : "等待节点快照",
      status: onlineCount === serverCount && serverCount ? "正常" : "关注",
      tone: onlineCount === serverCount && serverCount ? "ok" : "warn",
    },
    {
      label: "历史快照 API",
      detail: endpointByKey.get("dashboard") === "connected" ? "/api/dashboard.json 已连接" : "dashboard 快照未连接",
      status: endpointByKey.get("dashboard") === "connected" ? "正常" : "关注",
      tone: endpointByKey.get("dashboard") === "connected" ? "ok" : "warn",
    },
    {
      label: "秒级快照",
      detail: liveConnected ? "dashboard-live.json 正在发布" : "等待 live 快照",
      status: liveConnected ? "正常" : "关注",
      tone: liveConnected ? "ok" : "warn",
    },
    {
      label: "Kafka / Flink / HDFS",
      detail: runtimeDetail,
      status: runtimeStatus,
      tone: runtimeTone,
    },
    {
      label: "前端发布",
      detail: snapshot.generatedAtLocal || snapshot.generatedAt || "等待快照时间",
      status: apiConnected ? "正常" : "不可用",
      tone: apiConnected ? "ok" : "muted",
    },
  ];
}

function BigDataArchitecturePanel({ snapshot }) {
  const isLoading = snapshot.mode === "loading";
  const connectedEndpointCount = snapshot.endpoints.filter((endpoint) => endpoint.status === "connected").length;
  const evidence = {
    events: isLoading ? "等待快照" : `${formatNumber(snapshot.stats.totalEvents || snapshot.events.length)} 条事件`,
    fields: formatNumber(snapshot.fieldMappings.length),
    protocols: isLoading ? "等待聚合结果" : `${formatNumber(buildAttackMethodStats(snapshot.events).length)} 类攻击方式 / ${formatNumber(snapshot.sourceStats.length)} 个源 IP`,
    endpoints: `${formatNumber(connectedEndpointCount)} 个已连接接口`,
  };
  const layers = [
    {
      key: "ods",
      name: "ODS 原始日志层",
      icon: FileJson,
      input: "Cowrie / OpenCanary / Honeypot3",
      process: "保留原始 JSON/JSONL 与 raw_time，按采集批次写入日志服务器明细目录",
      output: "原始事件、payload、连接记录",
      metric: evidence.events,
    },
    {
      key: "dwd",
      name: "DWD 明细宽表层",
      icon: Fingerprint,
      input: "ODS 原始事件",
      process: "统一 UTC、北京时间、event_ts_ms、源 IP、协议背景、地理、账号、命令和攻击方式字段",
      output: "可查询、可筛选、可导出的结构化攻击行为事件",
      metric: `${evidence.fields} 个标准字段`,
    },
    {
      key: "dws",
      name: "DWS 聚合计算层",
      icon: BarChart3,
      input: "DWD 事件宽表",
      process: "前端接入 dashboard 聚合快照，并通过后端探针展示 Kafka/Flink/HDFS 健康状态",
      output: "攻击关系矩阵、趋势、风险和画像指标",
      metric: evidence.protocols,
    },
    {
      key: "ads",
      name: "ADS 应用服务层",
      icon: LayoutDashboard,
      input: "DWS 聚合结果",
      process: "后端发布 dashboard、live 快照和事件导出接口",
      output: "实时态势大屏、统计页、数据来源页",
      metric: evidence.endpoints,
    },
  ];

  return (
    <>
      <PanelHeading
        icon={Database}
        title="大数据分层架构"
        subtitle="把蜜罐日志按 ODS → DWD → DWS → ADS 分层，形成可采集、可清洗、可计算、可展示的数据链路"
      />
      <div className="architecture-flow" aria-label="大数据分层架构">
        {layers.map(({ icon: Icon, ...layer }, index) => (
          <article className={`architecture-card ${layer.key}`} key={layer.key}>
            <div className="architecture-card-head">
              <span>{String(index + 1).padStart(2, "0")}</span>
              <i aria-hidden="true"><Icon size={18} /></i>
            </div>
            <strong>{layer.name}</strong>
            <dl>
              <div>
                <dt>输入</dt>
                <dd>{layer.input}</dd>
              </div>
              <div>
                <dt>处理</dt>
                <dd>{layer.process}</dd>
              </div>
              <div>
                <dt>输出</dt>
                <dd>{layer.output}</dd>
              </div>
            </dl>
            <em>{layer.metric}</em>
          </article>
        ))}
      </div>
      <div className="architecture-note">
        <strong>数据闭环</strong>
        <span>采集端完成轻量预处理并推送日志，日志服务器按 event_ts_ms 组织明细与聚合快照；Kafka/Flink/HDFS 状态由后端只读健康探针确认，前端只展示已接入的真实 API 数据。</span>
      </div>
    </>
  );
}

function KpiRow({ loading = false, onlineCount, serverTotal, stats }) {
  const value = (number) => (loading ? "加载中" : optionalMetric(number));
  const delta = (number) => (loading ? "等待" : optionalDelta(number));
  const liveWindowEvents = Number(stats.liveWindowEvents ?? 0);
  const liveWindowSeconds = Number(stats.liveWindowSeconds ?? 60);
  const liveWindowHint = Number.isFinite(liveWindowSeconds) && liveWindowSeconds >= 60
    ? `最近 ${Math.round(liveWindowSeconds / 60)} 分钟`
    : `最近 ${Math.round(liveWindowSeconds)} 秒`;
  const liveStatus = stats.liveConnected ? "动态" : "未连接";
  const delaySeconds = Number(stats.liveLastEventDelaySeconds);
  const onlineValue = Number.isFinite(Number(onlineCount)) ? Number(onlineCount) : Number(stats.onlineHoneypots ?? 0);
  const totalServers = Number.isFinite(Number(serverTotal)) ? Number(serverTotal) : Number(stats.serverTotal ?? stats.honeypotCount ?? 0);
  return (
    <section className="kpi-row" aria-label="实时指标">
      <KpiCard icon={Shield} label="历史所有事件" hint="全量日志累计" value={value(stats.totalEvents)} change={delta(stats.totalDelta)} loading={loading} />
      <KpiCard icon={Activity} label="实时窗口事件" hint={liveWindowHint} value={value(liveWindowEvents)} change={loading ? "等待" : liveStatus} loading={loading} />
      <KpiCard icon={Globe2} label="外部攻击 IP" hint="去除测试与内网" value={value(stats.externalIps)} change={delta(stats.ipDelta)} loading={loading} />
      <KpiCard icon={Server} label="在线蜜罐" hint="采集节点状态" value={loading ? "加载中" : `${onlineValue}/${totalServers}`} change={loading ? "等待" : "真实状态"} loading={loading} />
      <KpiCard icon={Clock} label="数据延迟" hint="最新事件到前端" value={loading ? "加载中" : formatSecondsCompact(delaySeconds)} change={loading ? "等待" : stats.liveConnected ? "秒级" : "待确认"} loading={loading} />
    </section>
  );
}

function KpiCard({ icon: Icon, label, hint, value, change, loading = false }) {
  return (
    <article className={`kpi-card ${loading ? "loading" : ""}`}>
      <div className="kpi-icon">
        <Icon size={28} />
      </div>
      <div className="kpi-copy">
        <span>{label}</span>
        {hint && <small>{hint}</small>}
        <strong>{value}</strong>
      </div>
      <em className="kpi-change">{formatDelta(change)}</em>
    </article>
  );
}

function DetectorPanel({
  activeMethod,
  activeProtocol,
  methods,
  mode,
  scopeLabel,
  serverCount,
  onSelectMethod,
  onSelectProtocol,
}) {
  const modeLabel = dataModeLabel(mode).replace("API 实时", "API 数据");
  const methodRows = methods.length ? methods : buildAttackMethodStats([]);
  const topMethods = methodRows.slice(0, 5);
  const selectedMethod = activeMethod === "ALL" ? null : methodRows.find((method) => method.key === activeMethod);
  const visibleMethods = selectedMethod && !topMethods.some((method) => method.key === activeMethod)
    ? [selectedMethod, ...topMethods.slice(0, 4)]
    : topMethods;
  return (
    <aside className="detector-panel" aria-label="攻击方式识别器">
      <div className="panel-title-row">
        <div>
          <h2>攻击方式 TOP5</h2>
          <span>{serverCount} 个蜜罐 · {modeLabel} · {scopeLabel} · 点击筛选态势</span>
        </div>
        <button
          className={activeMethod === "ALL" ? "small-switch active" : "small-switch"}
          onClick={() => {
            onSelectMethod("ALL");
            onSelectProtocol("ALL");
          }}
          type="button"
        >
          全部
        </button>
      </div>

      <div className="protocol-list">
        {visibleMethods.map((protocol) => (
          <ProtocolRow
            key={protocol.key}
            protocol={protocol}
            active={activeMethod === protocol.key}
            onClick={() => onSelectMethod(activeMethod === protocol.key ? "ALL" : protocol.key)}
          />
        ))}
      </div>
    </aside>
  );
}

function HoneypotStatusPanel({ collectorHealth, events, snapshot }) {
  const onlineCount = snapshot.serverStats.filter((server) => ["online", "running"].includes(String(server.status || "").toLowerCase())).length;
  const highRiskCount = events.filter((event) => effectiveSeverity(event) === "high").length;
  const sourceIpCount = new Set(events.map((event) => event.srcIp).filter(isKnown)).size;
  const rows = [
    {
      icon: CheckCircle2,
      label: "在线蜜罐",
      value: `${onlineCount}/${snapshot.serverStats.length || snapshot.honeypots.length || 0}`,
      tone: "ok",
    },
    {
      icon: Activity,
      label: "当前窗口事件",
      value: formatNumber(collectorHealth.windowTotal || events.length),
      tone: "neutral",
    },
    {
      icon: Globe2,
      label: "窗口源 IP",
      value: formatNumber(sourceIpCount),
      tone: "neutral",
    },
    {
      icon: AlertTriangle,
      label: "高危事件",
      value: formatNumber(highRiskCount),
      tone: highRiskCount ? "danger" : "ok",
    },
  ];

  return (
    <section className="honeypot-status-panel" aria-label="蜜罐状态概览">
      <div className="panel-title-row">
        <div>
          <h2>蜜罐状态概览</h2>
          <span>{collectorHealth.skewLabel} · {formatNumber(collectorHealth.totalEvents)} 累计事件</span>
        </div>
      </div>

      <div className="status-metric-list">
        {rows.map(({ icon: Icon, label, tone, value }) => (
          <article className={`status-metric ${tone}`} key={label}>
            <i aria-hidden="true"><Icon size={15} /></i>
            <span>{label}</span>
            <strong>{value}</strong>
          </article>
        ))}
      </div>
    </section>
  );
}

function ProtocolRow({ protocol, active, onClick }) {
  const Icon = attackMethodIcons[protocol.key] ?? protocolIcons[protocol.key] ?? Activity;
  const meta = protocol.sourceCount !== undefined
    ? `${formatNumber(protocol.sourceCount)} IP`
    : formatDelta(protocol.delta);

  return (
    <button
      className={active ? "protocol-row active" : "protocol-row"}
      data-testid={`protocol-${protocol.key}`}
      onClick={onClick}
      style={{ "--protocol-color": protocol.color }}
      type="button"
    >
      <span className="protocol-icon">
        <Icon size={22} />
      </span>
      <span className="protocol-copy">
        <strong>{protocol.name}</strong>
        <small>{formatNumber(protocol.total)}</small>
      </span>
      <span className="protocol-pulse" aria-hidden="true" />
      <span className="protocol-delta">{meta}</span>
    </button>
  );
}

function MapToolbar({
  activeMethod,
  activeProtocol,
  apiError,
  dataMode,
  highOnly,
  mapEventCount,
  mapFullscreen,
  mapSourceCount,
  mapTimeRange,
  paused,
  query,
  onMapTimeRangeChange,
  onQueryChange,
  onToggleHighOnly,
  onToggleMapFullscreen,
  onTogglePause,
}) {
  const modeLabel = dataModeLabel(dataMode).replace("API 实时", "动态接口");
  const rangeLabel = mapTimeRangeOption(mapTimeRange).label;
  return (
    <div className="map-toolbar">
      <div>
        <h2>全球攻击流向</h2>
        <span>
          {activeMethod === "ALL" ? "全部攻击方式" : methodLabel(activeMethod)}
          {activeProtocol !== "ALL" ? ` · 协议 ${activeProtocol}` : ""} · {modeLabel}
          {` · ${rangeLabel} ${formatNumber(mapSourceCount)} IP / ${formatNumber(mapEventCount)} 条`}
          {apiError ? ` · ${apiError}` : ""}
        </span>
      </div>
      <div className="toolbar-actions">
        <label className="range-select" title="地图时间范围">
          <Clock size={16} />
          <select
            aria-label="全球攻击流向时间范围"
            data-testid="map-time-range"
            onChange={(event) => onMapTimeRangeChange(event.target.value)}
            value={mapTimeRange}
          >
            {MAP_TIME_RANGE_OPTIONS.map((option) => (
              <option key={option.key} value={option.key}>{option.label}</option>
            ))}
          </select>
        </label>
        <button className="tool-button" type="button" onClick={onTogglePause}>
          {paused ? <Play size={16} /> : <Pause size={16} />}
          {paused ? "继续" : "暂停"}
        </button>
        <button
          className={highOnly ? "tool-button active" : "tool-button"}
          data-testid="high-risk-toggle"
          type="button"
          onClick={onToggleHighOnly}
        >
          <Gauge size={16} />
          仅高危
        </button>
        <button
          className="tool-button"
          data-testid="map-fullscreen-toggle"
          type="button"
          onClick={onToggleMapFullscreen}
          aria-label={mapFullscreen ? "退出地图全屏" : "地图全屏显示"}
          title={mapFullscreen ? "退出地图全屏" : "地图全屏显示"}
        >
          {mapFullscreen ? <Minimize2 size={16} /> : <Maximize2 size={16} />}
          {mapFullscreen ? "退出全屏" : "全屏地图"}
        </button>
        <label className="search-box">
          <Search size={16} />
          <input
            data-testid="map-search"
            value={query}
            onChange={(event) => onQueryChange(event.target.value)}
            placeholder="搜索 IP / 攻击方式 / 协议 / ASN / Payload"
          />
        </label>
      </div>
    </div>
  );
}

function FullscreenMapChrome({
  activeMethod,
  activeProtocol,
  apiError,
  dataMode,
  events,
  highOnly,
  mapEventCount,
  mapSourceCount,
  mapTimeRange,
  onlineCount,
  paused,
  query,
  snapshot,
  onMapTimeRangeChange,
  onQueryChange,
  onToggleHighOnly,
  onToggleMapFullscreen,
  onTogglePause,
}) {
  const stats = snapshot.stats || {};
  const snapshotTime = new Date(snapshot.lastUpdated);
  const updatedAt = Number.isNaN(snapshotTime.getTime()) ? "等待快照" : snapshotTime.toLocaleString("zh-CN", { hour12: false });
  const highRiskCount = events.filter((event) => effectiveSeverity(event) === "high").length;
  const sourceIpCount = new Set(events.map((event) => event.srcIp).filter(isKnown)).size;
  const modeLabel = dataModeLabel(dataMode, paused);
  const methodText = activeMethod === "ALL" ? "全部攻击方式" : methodLabel(activeMethod);
  const protocolText = activeProtocol === "ALL" ? "全部协议" : activeProtocol;
  const rangeLabel = mapTimeRangeOption(mapTimeRange).label;
  const metricRows = [
    ["历史事件", formatNumber(stats.totalEvents || snapshot.events.length)],
    [rangeLabel, formatNumber(mapEventCount ?? events.length)],
    ["外部 IP", formatNumber(stats.externalIps ?? sourceIpCount)],
    ["高危命中", formatNumber(stats.highRisk ?? highRiskCount)],
    ["在线蜜罐", `${onlineCount}/${snapshot.serverStats.length || snapshot.honeypots.length || 0}`],
  ];

  return (
    <div className="fullscreen-map-chrome">
      <div className="fullscreen-map-header">
        <div className="fullscreen-map-status">
          <span className={`fullscreen-state ${paused ? "paused" : dataMode}`}>{modeLabel}</span>
          <span>{methodText}</span>
          <span>{protocolText}</span>
          <span>{formatNumber(mapSourceCount)} IP</span>
        </div>
        <div className="fullscreen-map-title">
          <h2>全球攻击态势大屏</h2>
          <p>{apiError ? apiError : "多源蜜罐日志 · 攻击来源定位 · 实时威胁流向"}</p>
        </div>
        <div className="fullscreen-map-clock">
          <span>{updatedAt}</span>
          <button
            className="tool-button"
            data-testid="map-fullscreen-toggle"
            type="button"
            onClick={onToggleMapFullscreen}
            aria-label="退出地图全屏"
            title="退出地图全屏"
          >
            <Minimize2 size={16} />
            退出大屏
          </button>
        </div>
      </div>

      <div className="fullscreen-map-controls" aria-label="大屏地图控制">
        <label className="range-select" title="地图时间范围">
          <Clock size={16} />
          <select
            aria-label="全球攻击流向时间范围"
            data-testid="map-time-range"
            onChange={(event) => onMapTimeRangeChange(event.target.value)}
            value={mapTimeRange}
          >
            {MAP_TIME_RANGE_OPTIONS.map((option) => (
              <option key={option.key} value={option.key}>{option.label}</option>
            ))}
          </select>
        </label>
        <button className="tool-button" type="button" onClick={onTogglePause}>
          {paused ? <Play size={16} /> : <Pause size={16} />}
          {paused ? "继续" : "暂停"}
        </button>
        <button
          className={highOnly ? "tool-button active" : "tool-button"}
          data-testid="high-risk-toggle"
          type="button"
          onClick={onToggleHighOnly}
        >
          <Gauge size={16} />
          仅高危
        </button>
        <label className="search-box">
          <Search size={16} />
          <input
            data-testid="map-search"
            value={query}
            onChange={(event) => onQueryChange(event.target.value)}
            placeholder="搜索 IP / 攻击方式 / 协议 / ASN / Payload"
          />
        </label>
      </div>

      <div className="fullscreen-map-metrics" aria-label="大屏关键指标">
        {metricRows.map(([label, value]) => (
          <div className="fullscreen-map-metric" key={label}>
            <span>{label}</span>
            <strong>{value}</strong>
          </div>
        ))}
      </div>
    </div>
  );
}

function ThreatMap({ events, fullscreen = false, globeIntroActive = false, honeypots, selectedEventId, selectedIp, onSelectEvent, onSelectIp }) {
  const width = 900;
  const height = 520;
  const [globeRotation, setGlobeRotation] = useState(0);
  const countries = useMemo(() => feature(world, world.objects.countries), []);
  const graticule = useMemo(() => geoGraticule().step(fullscreen ? [15, 15] : [30, 30])(), [fullscreen]);
  const globeCenter = useMemo(() => [normalizeLongitude(-globeRotation), 12], [globeRotation]);
  const projection = useMemo(() => {
    if (!fullscreen) {
      return geoNaturalEarth1().fitSize([width, height], { type: "Sphere" });
    }
    return geoOrthographic()
      .scale(Math.min(width, height) * 0.47)
      .translate([width / 2, height / 2 + 12])
      .rotate([globeRotation, -12, 0])
      .clipAngle(90)
      .precision(0.7);
  }, [fullscreen, globeRotation]);
  const path = useMemo(() => geoPath(projection), [projection]);
  const recentSources = useMemo(() => {
    const map = new Map();
    events.forEach((event) => {
      if (!hasUsableCoordinates(event.sourceCoordinates)) return;
      if (fullscreen && !isGlobePointVisible(event.sourceCoordinates, globeCenter)) return;
      if (!map.has(event.srcIp)) map.set(event.srcIp, event);
    });
    return [...map.values()].slice(0, MAP_SOURCE_IP_LIMIT);
  }, [events, fullscreen, globeCenter]);

  useEffect(() => {
    if (!fullscreen || prefersReducedMotion()) {
      setGlobeRotation(0);
      return undefined;
    }
    const rotationTimer = window.setInterval(() => {
      setGlobeRotation((current) => (current + 0.42) % 360);
    }, 80);
    return () => window.clearInterval(rotationTimer);
  }, [fullscreen]);

  const stageClassName = [
    "map-stage",
    fullscreen ? "globe-mode" : "",
    globeIntroActive ? "globe-intro" : "",
  ].filter(Boolean).join(" ");
  const mapClassName = fullscreen ? "world-map world-map-globe" : "world-map";
  const getMapBounds = useCallback((interactionEvent) => {
    const interactionTarget = interactionEvent?.currentTarget;
    const panelElement = interactionTarget?.closest?.(".map-panel")
      || interactionTarget?.ownerSVGElement?.closest?.(".map-panel")
      || (typeof document === "undefined" ? null : document.querySelector(".map-panel"));
    const rect = panelElement?.getBoundingClientRect?.();
    if (!rect) return null;
    return {
      left: rect.left,
      right: rect.right,
      top: rect.top,
      bottom: rect.bottom,
      width: rect.width,
      height: rect.height,
    };
  }, []);
  const selectMapEvent = useCallback((event, interactionEvent) => {
    onSelectEvent?.(event, {
      clientX: interactionEvent?.clientX,
      clientY: interactionEvent?.clientY,
      currentTarget: interactionEvent?.currentTarget,
      mapBounds: getMapBounds(interactionEvent),
    });
  }, [getMapBounds, onSelectEvent]);

  return (
    <div className={stageClassName}>
      <div className="scan-layer" aria-hidden="true" />
      <svg viewBox={`0 0 ${width} ${height}`} className={mapClassName} role="img" aria-label={fullscreen ? "旋转地球攻击来源地图" : "全球蜜罐攻击来源地图"}>
        <defs>
          <filter id="softGlow" x="-40%" y="-40%" width="180%" height="180%">
            <feGaussianBlur stdDeviation="3.5" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          <filter id="globeAtmosphere" x="-24%" y="-24%" width="148%" height="148%">
            <feGaussianBlur stdDeviation="5" result="blur" />
            <feColorMatrix
              in="blur"
              result="cyanGlow"
              type="matrix"
              values="0 0 0 0 0.12  0 0 0 0 0.72  0 0 0 0 1  0 0 0 0.72 0"
            />
            <feMerge>
              <feMergeNode in="cyanGlow" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          <radialGradient id="globeSphereGradient" cx="38%" cy="34%" r="66%">
            <stop offset="0%" stopColor="rgba(18, 83, 122, 0.42)" />
            <stop offset="48%" stopColor="rgba(2, 25, 47, 0.9)" />
            <stop offset="100%" stopColor="rgba(0, 4, 12, 1)" />
          </radialGradient>
          <linearGradient id="attackGradient" x1="0%" x2="100%" y1="0%" y2="0%">
            <stop offset="0%" stopColor="#ff6b42" />
            <stop offset="55%" stopColor="#20d9ff" />
            <stop offset="100%" stopColor="#a6ff5f" />
          </linearGradient>
        </defs>

        <path className="sphere" d={path({ type: "Sphere" })} />
        <path className="graticule" d={path(graticule)} />
        {countries.features.map((country, index) => {
          const countryPath = path(country);
          if (!countryPath) return null;
          return <path className="country" d={countryPath} key={country.id ?? `country-${index}`} />;
        })}

        {events.map((event, index) => {
          if (!hasUsableCoordinates(event.sourceCoordinates) || !hasUsableCoordinates(event.targetCoordinates)) return null;
          if (fullscreen && (!isGlobePointVisible(event.sourceCoordinates, globeCenter) || !isGlobePointVisible(event.targetCoordinates, globeCenter))) {
            return null;
          }
          const start = projection(event.sourceCoordinates);
          const end = projection(event.targetCoordinates);
          if (!start || !end) return null;
          const route = createRoute(start, end, index);
          const severity = effectiveSeverity(event);
          const routeColor = eventVisualColor(event);
          const routeDelay = `${(index % 13) * -0.23}s`;
          const routeDuration = `${2.25 + (index % 5) * 0.2}s`;
          const routeStyle = {
            "--route-color": routeColor,
            "--route-delay": routeDelay,
            "--route-duration": routeDuration,
          };
          const selected = event.id === selectedEventId;
          const handleKeyboardSelect = (keyboardEvent) => {
            if (keyboardEvent.key !== "Enter" && keyboardEvent.key !== " ") return;
            keyboardEvent.preventDefault();
            const rect = keyboardEvent.currentTarget.getBoundingClientRect();
            selectMapEvent(event, {
              clientX: rect.left + rect.width / 2,
              clientY: rect.top + rect.height / 2,
              currentTarget: keyboardEvent.currentTarget,
            });
          };
          return (
            <g
              key={event.id}
              className={`route-group ${severity}${selected ? " selected" : ""}`}
              onClick={(pointerEvent) => selectMapEvent(event, pointerEvent)}
              onKeyDown={handleKeyboardSelect}
              role="button"
              tabIndex="0"
              aria-label={`查看 ${event.srcIp} ${attackBehavior(event).name} 攻击详情`}
            >
              <path
                className="attack-route attack-route-glow"
                d={route}
                style={routeStyle}
              />
              <path
                className="attack-route attack-route-core"
                d={route}
                style={routeStyle}
              />
              <path
                className="attack-route-hitbox"
                d={route}
              />
              {index < 42 && (
                <circle
                  className="route-particle"
                  r={severity === "high" ? "1.75" : "1.45"}
                  style={{
                    "--route-color": routeColor,
                    "--route-delay": routeDelay,
                    "--route-duration": routeDuration,
                    offsetPath: `path("${route}")`,
                  }}
                />
              )}
            </g>
          );
        })}

        {recentSources.map((event, index) => {
          const point = projection(event.sourceCoordinates);
          if (!point) return null;
          const sourceColor = eventVisualColor(event);
          return (
            <g
              key={event.srcIp}
              className={event.srcIp === selectedIp ? "source-node selected" : "source-node"}
              style={{
                "--source-color": sourceColor,
                "--source-delay": `${(index % 11) * -0.19}s`,
              }}
              onClick={(pointerEvent) => {
                onSelectIp?.(event.srcIp);
                selectMapEvent(event, pointerEvent);
              }}
              onKeyDown={(keyboardEvent) => {
                if (keyboardEvent.key !== "Enter" && keyboardEvent.key !== " ") return;
                keyboardEvent.preventDefault();
                const rect = keyboardEvent.currentTarget.getBoundingClientRect();
                onSelectIp?.(event.srcIp);
                selectMapEvent(event, {
                  clientX: rect.left + rect.width / 2,
                  clientY: rect.top + rect.height / 2,
                  currentTarget: keyboardEvent.currentTarget,
                });
              }}
              role="button"
              tabIndex="0"
              aria-label={`${event.srcIp} ${event.city}, ${event.country}`}
            >
              <circle className="source-halo" cx={point[0]} cy={point[1]} r="6.4" />
              <circle className="source-dot" cx={point[0]} cy={point[1]} r="2.7" />
              <title>{`${event.srcIp} ${event.city}, ${event.country}`}</title>
            </g>
          );
        })}

        {honeypots.map((honeypot) => {
          if (fullscreen && !isGlobePointVisible(honeypot.coordinates, globeCenter)) return null;
          const point = projection(honeypot.coordinates);
          if (!point) return null;
          return (
            <g className="honeypot-node" key={honeypot.id} transform={`translate(${point[0]} ${point[1]})`}>
              <circle r="8.4" style={{ stroke: honeypot.color }} />
              <circle r="3.2" style={{ fill: honeypot.color }} />
              <text x="14" y="-6">{honeypot.name}</text>
              <text x="14" y="8" className="node-ip">{honeypot.ip}</text>
            </g>
          );
        })}
      </svg>

      <div className="map-legend">
        <span><i className="low" />低危事件</span>
        <span><i className="medium" />中危事件</span>
        <span><i className="high" />高危事件</span>
        <span><b />蜜罐节点</span>
      </div>
    </div>
  );
}

function MapEventPopover({ bounds, event, x, y, onClose }) {
  if (!event) return null;
  const behavior = attackBehavior(event);
  const severity = effectiveSeverity(event);
  const eventColor = eventVisualColor(event);
  const location = joinKnown([event.country, event.region, event.city]);
  const network = joinKnown([event.isp, event.asn]);
  const target = joinKnown([
    event.honeypotLabel || event.honeypot,
    event.honeypotIp,
    isKnown(event.dstPort) ? `端口 ${event.dstPort}` : "",
  ], "目标未知");
  const source = joinKnown([
    event.srcIp,
    isKnown(event.srcPort) ? `源端口 ${event.srcPort}` : "",
  ], "来源未知");
  const credential = [event.username, event.password].filter(isKnown).join(" / ");
  const evidence = behavior.evidence?.filter(isKnown).join("；") || behavior.description;
  const content = eventEvidenceLine(event, "");
  const viewportWidth = typeof window === "undefined" ? 1280 : window.innerWidth;
  const viewportHeight = typeof window === "undefined" ? 720 : window.innerHeight;
  const fallbackBounds = {
    left: 12,
    right: viewportWidth - 12,
    top: 72,
    bottom: viewportHeight - 12,
    width: viewportWidth - 24,
    height: viewportHeight - 84,
  };
  const hasPanelBounds = bounds && Number.isFinite(bounds.left) && Number.isFinite(bounds.right);
  const safeBounds = hasPanelBounds
    ? {
        left: Math.max(12, bounds.left + 10),
        right: Math.min(viewportWidth - 12, bounds.right - 10),
        top: Math.max(72, bounds.top + 10),
        bottom: Math.min(viewportHeight - 12, bounds.bottom - 10),
        width: Math.max(0, bounds.width - 20),
        height: Math.max(0, bounds.height - 20),
      }
    : fallbackBounds;
  const popoverWidth = Math.max(280, Math.min(360, safeBounds.width, viewportWidth - 24));
  const popoverMaxHeight = Math.max(220, Math.min(420, safeBounds.height, viewportHeight - 86));
  const pointerX = Number.isFinite(Number(x)) ? Number(x) : viewportWidth / 2;
  const pointerY = Number.isFinite(Number(y)) ? Number(y) : viewportHeight / 2;
  const gap = 16;
  const leftRoom = pointerX - safeBounds.left - gap;
  const rightRoom = safeBounds.right - pointerX - gap;
  const preferredLeft = rightRoom >= popoverWidth || rightRoom >= leftRoom
    ? pointerX + gap
    : pointerX - popoverWidth - gap;
  const leftLimit = Math.max(safeBounds.left, safeBounds.right - popoverWidth);
  const topLimit = Math.max(safeBounds.top, safeBounds.bottom - popoverMaxHeight);
  const left = Math.min(Math.max(safeBounds.left, preferredLeft), leftLimit);
  const top = Math.min(Math.max(safeBounds.top, pointerY + gap), topLimit);
  const styleLeft = hasPanelBounds ? left - bounds.left : left;
  const styleTop = hasPanelBounds ? top - bounds.top : top;

  return (
    <aside
      className={`map-event-popover ${severity}`}
      style={{ left: styleLeft, maxHeight: popoverMaxHeight, top: styleTop, width: popoverWidth, "--event-color": eventColor }}
      role="dialog"
      aria-label="攻击事件详情"
    >
      <div className="map-popover-header">
        <div>
          <span>选中攻击事件</span>
          <h3>{behavior.name}</h3>
        </div>
        <button type="button" onClick={onClose} aria-label="关闭攻击事件详情">关闭</button>
      </div>

      <dl className="map-popover-list">
        <div>
          <dt>来源</dt>
          <dd className="mono">{source}</dd>
        </div>
        <div>
          <dt>目标</dt>
          <dd>{target}</dd>
        </div>
        <div>
          <dt>时间</dt>
          <dd>{event.eventTimeLocal || formatEventClock(event.eventTsMs ?? event.timestamp)}</dd>
        </div>
        <div>
          <dt>位置</dt>
          <dd>{location}</dd>
        </div>
        <div>
          <dt>归属</dt>
          <dd>{network}</dd>
        </div>
        <div>
          <dt>协议/类型</dt>
          <dd>{joinKnown([event.protocol, event.eventType], "未识别")}</dd>
        </div>
        {credential && (
          <div>
            <dt>账号口令</dt>
            <dd className="mono">{credential}</dd>
          </div>
        )}
        <div>
          <dt>判定</dt>
          <dd>{evidence}</dd>
        </div>
      </dl>

      {content && (
        <p className="map-popover-payload">
          {content}
        </p>
      )}
    </aside>
  );
}

function normalizeLongitude(longitude) {
  return ((((Number(longitude) || 0) + 180) % 360) + 360) % 360 - 180;
}

function isGlobePointVisible(coordinates, center) {
  if (!hasUsableCoordinates(coordinates) || !hasUsableCoordinates(center)) return false;
  return geoDistance(center, coordinates) <= Math.PI / 2 + 0.035;
}

function prefersReducedMotion() {
  return typeof window !== "undefined" && window.matchMedia?.("(prefers-reduced-motion: reduce)")?.matches;
}

function hasUsableCoordinates(coordinates) {
  if (!Array.isArray(coordinates) || coordinates.length < 2) return false;
  const [longitude, latitude] = coordinates.map(Number);
  if (!Number.isFinite(longitude) || !Number.isFinite(latitude)) return false;
  return Math.abs(longitude) > 0.0001 || Math.abs(latitude) > 0.0001;
}

function createRoute(start, end, index) {
  const [sx, sy] = start;
  const [ex, ey] = end;
  const dx = ex - sx;
  const dy = ey - sy;
  const curve = Math.min(120, Math.max(44, Math.hypot(dx, dy) * 0.18));
  const sign = index % 2 === 0 ? 1 : -1;
  const mx = sx + dx * 0.5 - dy * 0.12 * sign;
  const my = sy + dy * 0.5 - curve;
  return `M ${sx.toFixed(2)} ${sy.toFixed(2)} Q ${mx.toFixed(2)} ${my.toFixed(2)} ${ex.toFixed(2)} ${ey.toFixed(2)}`;
}

function RankingPanel({
  compact = false,
  isScopedWindow,
  limit = 10,
  rankingMode,
  rankings,
  selectedIp,
  selectedSource,
  onRankingModeChange,
  onSelectIp,
}) {
  const metricValue = (source) => {
    if (rankingMode === "risk") return isScopedWindow ? source.windowRiskScore || 0 : source.riskScore || 0;
    if (rankingMode === "protocol") return source.methodCount || source.protocolCount || 0;
    if (isScopedWindow) return source.events || 0;
    return source.eventTotal || source.total || 0;
  };
  const modeCopy = {
    event: isScopedWindow ? "按当前筛选事件数排行" : "按全量事件数排行",
    risk: isScopedWindow ? "按当前筛选风险排行" : "按风险分排行",
    protocol: isScopedWindow ? "按当前筛选攻击方式覆盖排行" : "按当前窗口攻击方式覆盖排行",
  };
  const metricCopy = {
    event: isScopedWindow ? "筛选事件" : "事件数",
    risk: isScopedWindow ? "筛选风险" : "风险分",
    protocol: isScopedWindow ? "筛选方式" : "攻击方式",
  };
  const maxMetric = Math.max(1, ...rankings.map(metricValue));

  return (
    <aside className={compact ? "ranking-panel compact" : "ranking-panel"} aria-label="国家和 IP 排行">
      <div className="panel-title-row">
        <div>
          <h2>源 IP 排行</h2>
          <span>{modeCopy[rankingMode]}</span>
        </div>
        <select aria-label="排行维度" value={rankingMode} onChange={(event) => onRankingModeChange(event.target.value)}>
          <option value="event">按事件数</option>
          <option value="risk">按风险</option>
          <option value="protocol">按攻击方式</option>
        </select>
      </div>

      <div className="ranking-list">
        {rankings.length ? (
          rankings.slice(0, limit).map((source, index) => (
            <button
              className={source.srcIp === selectedIp ? "ranking-row selected" : "ranking-row"}
              key={source.srcIp}
              onClick={() => onSelectIp(source.srcIp)}
              type="button"
            >
              <span className="rank-index">{String(index + 1).padStart(2, "0")}</span>
              <span>
                <strong>{displayValue(source.country)}</strong>
                <small>{source.srcIp}</small>
              </span>
              <span className="rank-bar" aria-hidden="true">
                <i style={{ width: `${Math.max(12, (metricValue(source) / maxMetric) * 100)}%` }} />
              </span>
              <span className="rank-count">
                <strong>{formatNumber(metricValue(source))}</strong>
                <small>{metricCopy[rankingMode]}</small>
              </span>
            </button>
          ))
        ) : (
          <p className="empty-copy">当前筛选条件下暂无源 IP。</p>
        )}
      </div>

      {!compact && <SourceDetail isScopedWindow={isScopedWindow} source={selectedSource} />}
    </aside>
  );
}

function SourceDetail({ compact = false, isScopedWindow, source }) {
  if (!source) {
    return (
      <div className="source-detail">
        <h3>选中源详情</h3>
        <p className="empty-copy">暂无源 IP 数据。</p>
      </div>
    );
  }

  return (
    <div className="source-detail">
      <h3>选中源详情</h3>
      <dl>
        <div>
          <dt>国家</dt>
          <dd>{displayValue(source.country)}</dd>
        </div>
        <div>
          <dt>地区</dt>
          <dd>{displayValue(source.region)}</dd>
        </div>
        <div>
          <dt>城市</dt>
          <dd>{displayValue(source.city)}</dd>
        </div>
        <div>
          <dt>ISP</dt>
          <dd>{displayValue(source.isp)}</dd>
        </div>
        <div>
          <dt>ASN</dt>
          <dd>{displayValue(source.asn)}</dd>
        </div>
        {!compact && (
          <>
            <div>
              <dt>事件数</dt>
              <dd>{formatNumber(source.eventTotal ?? source.total ?? 0)}</dd>
            </div>
            <div>
              <dt>{isScopedWindow ? "筛选命中" : "当前窗口"}</dt>
              <dd>{formatNumber(source.events ?? 0)}</dd>
            </div>
          </>
        )}
        <div>
          <dt>{isScopedWindow ? "筛选方式数" : "窗口方式数"}</dt>
          <dd>{formatNumber(source.methodCount ?? source.protocolCount ?? 0)}</dd>
        </div>
        <div>
          <dt>{isScopedWindow ? "筛选高危" : "窗口高危"}</dt>
          <dd>{formatNumber(source.highEvents ?? 0)}</dd>
        </div>
        <div>
          <dt>{isScopedWindow ? "筛选风险" : "风险分"}</dt>
          <dd>{formatNumber(isScopedWindow ? source.windowRiskScore ?? 0 : source.riskScore ?? source.score ?? 0)}</dd>
        </div>
      </dl>
    </div>
  );
}

function eventStreamKey(event, index = 0) {
  if (isKnown(event?.id)) return String(event.id);
  return [
    event?.eventTsMs ?? event?.timestamp ?? "",
    event?.srcIp ?? "",
    event?.eventType ?? "",
    event?.honeypot ?? "",
    index,
  ].join("|");
}

function EventStream({
  events,
  paused,
  activeMethod,
  activeProtocol,
  onPause,
  compact = false,
  detailMode = "inline",
  showSummaryColumn = true,
  summaryOnSelect = false,
  wide = false,
}) {
  const [selectedEventKey, setSelectedEventKey] = useState("");
  const shouldAutoSelectEvent = !summaryOnSelect && detailMode !== "none";
  const selectedEvent = useMemo(() => {
    return events.find((event, index) => eventStreamKey(event, index) === selectedEventKey) ?? (shouldAutoSelectEvent ? events[0] ?? null : null);
  }, [events, selectedEventKey, shouldAutoSelectEvent]);

  useEffect(() => {
    if (!selectedEvent && selectedEventKey) {
      setSelectedEventKey("");
    } else if (shouldAutoSelectEvent && selectedEvent && eventStreamKey(selectedEvent, 0) !== selectedEventKey) {
      setSelectedEventKey(eventStreamKey(selectedEvent, 0));
    }
  }, [selectedEvent, selectedEventKey, shouldAutoSelectEvent]);

  return (
    <div className={`event-stream ${compact ? "compact" : ""} ${wide ? "wide" : ""} ${showSummaryColumn ? "" : "no-summary-column"} ${summaryOnSelect ? "summary-on-select" : ""}`}>
      <div className="event-header">
        <div>
          <h2>实时事件流</h2>
          <span>
            {activeMethod === "ALL" ? "全部攻击方式" : methodLabel(activeMethod)}
            {activeProtocol !== "ALL" ? ` · 协议 ${activeProtocol}` : ""} · 结构化事件画像
          </span>
        </div>
        <button className="tool-button compact" onClick={onPause} type="button">
          {paused ? <Play size={16} /> : <Pause size={16} />}
          {paused ? "继续" : "暂停"}
        </button>
      </div>

      <div className="event-body">
        <div className="event-table" role="table" aria-label="实时事件列表">
          <div className="event-row header" role="row">
            <span className="event-cell-time">时间</span>
            <span className="event-cell-ip">源 IP</span>
            <span className="event-cell-location">国家 / 城市</span>
            <span className="event-cell-protocol">攻击方式</span>
            <span className="event-cell-user">用户</span>
            <span className="event-cell-type">事件类型</span>
            {showSummaryColumn && <span className="event-cell-summary">摘要</span>}
            <span className="event-cell-target">目标蜜罐</span>
          </div>
          {events.map((event, index) => {
            const severity = effectiveSeverity(event);
            const eventColor = eventVisualColor(event);
            const eventKey = eventStreamKey(event, index);
            const selected = selectedEventKey === eventKey;
            return (
            <Fragment key={eventKey}>
            <button
              aria-current={selected ? "true" : undefined}
              className={`event-row event-row-button ${severity} ${selected ? "selected" : ""}`}
              style={{ "--event-color": eventColor }}
              onClick={() => setSelectedEventKey(eventKey)}
              role="row"
              type="button"
            >
              <span className="event-cell-time">{new Date(event.eventTsMs ?? event.timestamp).toLocaleTimeString("zh-CN", { timeZone: BEIJING_TIME_ZONE, hour12: false })}</span>
              <span className="event-cell-ip mono">{event.srcIp}</span>
              <span className="event-cell-location">{displayValue(event.country)} / {displayValue(event.city)}</span>
              <span className="event-cell-protocol"><AttackMethodBadge event={event} /></span>
              <span className="event-cell-user">{displayValue(event.username, "-")}</span>
              <span className="event-cell-type event-type">{event.eventType}</span>
              {showSummaryColumn && <span className="event-cell-summary" title={event.detail}>{compactText(event.detail, 110)}</span>}
              <span className="event-cell-target target">{event.honeypot}</span>
            </button>
            {summaryOnSelect && selected && (
              <div className="event-row-summary" role="row">
                <span>Payload</span>
                <strong>{eventPayloadLine(event)}</strong>
              </div>
            )}
            </Fragment>
            );
          })}
          {!events.length && (
            <div className="event-row empty-row" role="row">
              <span>当前筛选条件下暂无匹配事件。</span>
            </div>
          )}
        </div>
        {detailMode === "none" ? null : detailMode === "collapsible" ? (
          <details className="event-detail-disclosure">
            <summary>查看选中事件详情</summary>
            <EventDetailCard event={selectedEvent} />
          </details>
        ) : (
          <EventDetailCard event={selectedEvent} />
        )}
      </div>
    </div>
  );
}

function EventDetailCard({ event }) {
  if (!event) {
    return (
      <aside className="event-detail-card empty">
        <FileJson size={18} />
        <span>暂无事件</span>
      </aside>
    );
  }

  const location = joinKnown([event.country, event.region, event.city]);
  const network = joinKnown([event.isp, event.asn]);
  const payloadFields = structuredFields(event.payload);
  const visibleFields = payloadFields;
  const evidenceItems = eventEvidenceItems(event);
  const commandText = compactText(event.command, 260);
  const behavior = attackBehavior(event);
  const severity = effectiveSeverity(event);
  const eventColor = eventVisualColor(event);
  const hasCredential = isKnown(event.username) || isKnown(event.password);
  const hasSourcePort = isKnown(event.srcPort);
  const hasDistinctInternalTarget = isKnown(event.destinationIp) && event.destinationIp !== event.honeypotIp;
  const internalTarget = joinKnown([event.destinationIp, event.dstPort ? `端口 ${event.dstPort}` : ""], "");
  const sourceMeta = joinKnown([location, hasSourcePort ? `源端口 ${event.srcPort}` : ""]);
  const targetPort = isKnown(event.dstPort) ? `端口 ${event.dstPort}` : "端口未知";

  return (
    <aside className={`event-detail-card ${severity}`} style={{ "--event-color": eventColor }} aria-label="选中事件详情">
      <div className="event-detail-top">
        <div>
          <span className="eyebrow">事件画像</span>
          <h3>{behavior.name}</h3>
        </div>
        <AttackMethodBadge event={event} />
      </div>

      <div className="event-route">
        <div>
          <span>来源</span>
          <strong className="mono">{event.srcIp}</strong>
          <small>{sourceMeta}</small>
        </div>
        <i aria-hidden="true" />
        <div>
          <span>目标</span>
          <strong className="mono">{displayValue(event.honeypotIp || event.honeypot)}</strong>
          <small>{targetPort}</small>
        </div>
      </div>

      <dl className="event-detail-list">
        <DetailItem icon={Clock} label="北京时间" value={event.eventTimeLocal || formatEventClock(event.eventTsMs ?? event.timestamp)} />
        {event.eventTimeUtc && <DetailItem icon={Clock} label="UTC 时间" value={event.eventTimeUtc} mono />}
        <DetailItem icon={Clock} label="时间来源" value={timeSourceLabel(event.eventTimeSource)} />
        <DetailItem icon={Clock} label="event_ts_ms" value={event.eventTsMs ?? event.timestamp} mono />
        <DetailItem icon={MapPin} label="位置" value={location} />
        <DetailItem icon={Network} label="网络归属" value={network} />
        {hasSourcePort && <DetailItem icon={RadioTower} label="源端口" value={event.srcPort} mono />}
        <DetailItem icon={Target} label="蜜罐节点" value={joinKnown([event.honeypotLabel, event.honeypot])} />
        {hasDistinctInternalTarget && (
          <DetailItem icon={Server} label="内部目标" value={internalTarget} mono />
        )}
        <DetailItem icon={Fingerprint} label="攻击方式" value={behavior.name} />
        <DetailItem icon={Fingerprint} label="判定依据" value={behavior.evidence.join("；")} />
        <DetailItem icon={RadioTower} label="协议背景" value={event.protocol} />
        <DetailItem icon={Fingerprint} label="事件类型" value={event.eventType} />
        {hasCredential && (
          <DetailItem
            icon={KeyRound}
            label="账号口令"
            value={`${displayValue(event.username, "-")} / ${displayValue(event.password, "-")}`}
            mono
          />
        )}
        {isKnown(commandText) && <DetailItem icon={TerminalSquare} label="命令输入" value={commandText} mono />}
      </dl>

      <div className="payload-panel">
        <h4>攻击证据</h4>
        {evidenceItems.length ? (
          <dl className="payload-fields">
            {evidenceItems.map((item) => (
              <div key={`${item.label}-${item.value}`}>
                <dt>{item.label}</dt>
                <dd>{item.value}</dd>
              </div>
            ))}
          </dl>
        ) : visibleFields.length ? (
          <dl className="payload-fields">
            {visibleFields.map(([key, value]) => (
              <div key={key}>
                <dt>{key}</dt>
                <dd>{compactText(value, 180)}</dd>
              </div>
            ))}
          </dl>
        ) : (
          <p>无可展示的 payload、口令或命令输入。</p>
        )}
      </div>
    </aside>
  );
}

function DetailItem({ icon: Icon, label, value, mono = false }) {
  return (
    <div>
      <dt>
        <Icon size={14} />
        {label}
      </dt>
      <dd className={mono ? "mono" : undefined}>{displayValue(value)}</dd>
    </div>
  );
}

function AttackMethodBadge({ event }) {
  const behavior = attackBehavior(event);
  return (
    <mark className={`method-badge attack-method-badge ${effectiveSeverity(event)}`} style={{ "--badge-color": eventVisualColor(event) }}>
      {behavior.name}
    </mark>
  );
}

function PanelHeading({ icon: Icon, title, subtitle }) {
  const needsVisualCentering = Icon === Activity || Icon === Database;
  const iconClassName = needsVisualCentering ? "panel-heading-icon visual-center-icon" : "panel-heading-icon";

  return (
    <div className="panel-title-row panel-heading">
      <div>
        <h2>{title}</h2>
        <span>{subtitle}</span>
      </div>
      <span className={iconClassName} aria-hidden="true">
        <Icon size={18} />
      </span>
    </div>
  );
}

function serverProtocolCopy(server) {
  if (Array.isArray(server.protocols) && server.protocols.length) return server.protocols.join(", ");
  if (Number(server.currentEvents ?? 0) > 0) return "协议背景待归类";
  if (Number(server.totalEvents ?? server.events ?? 0) > 0) return "当前窗口暂无事件";
  return "无实时事件";
}

function confidenceLabel(confidence) {
  if (confidence === "high") return "高置信";
  if (confidence === "medium") return "中置信";
  return "低置信";
}

function AttackFamilyDrilldown({ insights, onSelectFamily, onSelectIp, selectedFamilyKey = "", selectedIp = "" }) {
  const activeFamily = insights.familyByKey.get(selectedFamilyKey) || insights.families[0];
  if (!activeFamily) {
    return <p className="empty-copy">当前筛选条件下暂无攻击族可钻取。</p>;
  }
  const tacticLabel = {
    credential: "凭据攻击",
    execution: "命令与载荷",
    exploit: "漏洞利用",
    probe: "服务探测",
    recon: "侦察扫描",
  }[activeFamily.tactic] || "背景探测";
  const severityText = severityLabel[activeFamily.severity] || activeFamily.severity || "未知";

  return (
    <section className="attack-family-drilldown" aria-label="攻击族钻取">
      <div className="relation-subhead">
        <strong>攻击族钻取</strong>
        <span>点击攻击族查看相关 IP、样本事件和归类证据</span>
      </div>
      <div className="attack-family-layout">
        <div className="attack-family-list" role="listbox" aria-label="攻击族列表">
          {insights.families.map((family) => {
            const active = family.key === activeFamily.key;
            return (
              <button
                aria-selected={active}
                className={active ? "active" : undefined}
                key={family.key}
                onClick={() => onSelectFamily?.(family.key)}
                style={{ "--family-color": family.color }}
                type="button"
              >
                <span>
                  <i aria-hidden="true" />
                  <strong>{family.name}</strong>
                </span>
                <small>{formatNumber(family.count)} 事件 · {formatNumber(family.sourceCount)} IP · 高危 {formatNumber(family.highCount)}</small>
              </button>
            );
          })}
        </div>

        <div className="attack-family-detail">
          <div className="attack-family-hero" style={{ "--family-color": activeFamily.color }}>
            <div>
              <span>{tacticLabel} · {severityText}</span>
              <strong>{activeFamily.name}</strong>
              <small>{activeFamily.description}</small>
            </div>
            <div className="attack-family-kpis" aria-label="攻击族统计">
              <article>
                <span>事件</span>
                <strong>{formatNumber(activeFamily.count)}</strong>
              </article>
              <article>
                <span>源 IP</span>
                <strong>{formatNumber(activeFamily.sourceCount)}</strong>
              </article>
              <article>
                <span>主协议</span>
                <strong>{activeFamily.dominantProtocol}</strong>
              </article>
              <article>
                <span>主地理</span>
                <strong>{activeFamily.dominantGeo}</strong>
              </article>
            </div>
          </div>

          <div className="attack-family-grid">
            <div className="attack-family-sources">
              <div className="relation-subhead compact">
                <strong>相关源 IP</strong>
                <span>按该攻击族事件数排序</span>
              </div>
              <div className="attack-family-source-list">
                {activeFamily.topSources.map((source) => {
                  const active = source.srcIp === selectedIp;
                  return (
                    <button
                      className={active ? "active" : undefined}
                      key={source.srcIp}
                      onClick={() => onSelectIp?.(source.srcIp)}
                      type="button"
                    >
                      <span>
                        <strong className="mono">{source.srcIp}</strong>
                        <b>{formatNumber(source.count)} 次</b>
                      </span>
                      <small>{joinKnown([source.country, source.city], "位置未知")} · {joinKnown([source.isp, source.asn], "网络未知")}</small>
                      <em>
                        {source.protocols.map((item) => `${item.name} ${item.count}`).join(" / ") || "协议未知"}
                        {source.lastSeen ? ` · 最近 ${formatEventClock(source.lastSeen)}` : ""}
                      </em>
                    </button>
                  );
                })}
              </div>
            </div>

            <div className="attack-family-facts">
              <div className="attack-family-fact-card">
                <strong>归类证据</strong>
                {activeFamily.evidence.map((item) => (
                  <span key={item.name}>{item.name}<b>{formatNumber(item.count)}</b></span>
                ))}
              </div>
              <div className="attack-family-fact-card">
                <strong>分布特征</strong>
                <span>协议 {activeFamily.protocols.map((item) => `${item.name} ${item.count}`).join(" / ") || "未知"}</span>
                <span>地域 {activeFamily.countries.map((item) => `${item.name} ${item.count}`).join(" / ") || "未知"}</span>
                <span>目标 {activeFamily.honeypots.map((item) => `${item.name} ${item.count}`).join(" / ") || "未知"}</span>
              </div>
            </div>
          </div>

          <div className="attack-family-samples">
            <div className="relation-subhead compact">
              <strong>样本事件</strong>
              <span>最近代表性日志</span>
            </div>
            <div className="attack-family-sample-list">
              {activeFamily.samples.map((sample) => (
                <article key={sample.id}>
                  <span>{Number.isFinite(sample.time) ? formatEventClock(sample.time) : "时间未知"}</span>
                  <strong className="mono">{sample.srcIp}</strong>
                  <small>{sample.location} · {sample.protocol} · {sample.honeypot}</small>
                  <p>{sample.eventType} · {sample.evidence}</p>
                </article>
              ))}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

function RelationshipPanel({ events, selectedIp = "", sourceStats = [], onSelectIp }) {
  const highlightedFamilyIps = useMemo(() => new Set(), []);
  const insights = useMemo(() => buildRelationInsights(events, sourceStats), [events, sourceStats]);
  const hasEvents = insights.eventCount > 0;
  const topIpEdge = insights.topAttributionLink;
  const topCluster = insights.topAttributionCluster;
  const relationCopy = topIpEdge
    ? `${topIpEdge.source} ↔ ${topIpEdge.target}`
    : "等待 IP 边";
  const fanoutCopy = topCluster
    ? `${topCluster.label} · ${topCluster.ips.length} 个 IP`
    : "等待攻击簇";
  const selectedGraphIp = selectedIp && insights.attributionGraph.nodes.some((node) => node.id === selectedIp)
    ? selectedIp
    : "";
  const globalAttributionRows = insights.attributionGraph.links
    .slice()
    .sort((left, right) => right.score - left.score)
    .slice(0, 4);
  const selectedAttributionRows = selectedGraphIp
    ? insights.attributionGraph.links
      .filter((edge) => edge.source === selectedGraphIp || edge.target === selectedGraphIp)
      .sort((left, right) => right.score - left.score || right.evidence.length - left.evidence.length)
      .slice(0, 4)
    : [];
  const attributionRows = selectedAttributionRows.length ? selectedAttributionRows : globalAttributionRows;
  const evidenceScopeCopy = selectedAttributionRows.length
    ? `${selectedGraphIp} 的一跳关联证据`
    : selectedGraphIp
      ? `${selectedGraphIp} 暂无强关联边，显示全局最强关联`
      : "全局最强 IP 关联边";

  return (
    <div className="source-profile-layout">
      <PanelHeading
        icon={Network}
        title="源 IP 图计算画像"
        subtitle="全量节点恒定显示；点击 IP 查看画像，点击社群只做高亮与展开，不过滤节点"
      />
      <div className="source-profile-kpis relation-summary" aria-label="攻击关系摘要">
        <article>
          <span>图规模</span>
          <strong>{formatNumber(insights.sourceCount)} IP / {formatNumber(insights.attributionEdgeCount)} 边</strong>
          <small>全量图计算 · {formatNumber(insights.eventCount)} 条事件参与特征计算</small>
        </article>
        <article>
          <span>最强 IP 关联</span>
          <strong>{relationCopy}</strong>
          <small>{topIpEdge ? `${topIpEdge.score} 分 · ${confidenceLabel(topIpEdge.confidence)} · ${topIpEdge.evidence.map((item) => item.label).join(" / ")}` : "暂无"}</small>
        </article>
        <article>
          <span>疑似攻击社群</span>
          <strong>{fanoutCopy}</strong>
          <small>{topCluster ? `${formatNumber(topCluster.eventCount)} 条事件 / 高危 ${formatNumber(topCluster.highCount)}` : "暂无"}</small>
        </article>
        <article>
          <span>图计算结果</span>
          <strong>{formatNumber(insights.attributionClusterCount)} 个簇</strong>
          <small>候选 {formatNumber(insights.attributionGraph.pairCandidateCount || 0)} 对 · 依据相似行为连边</small>
        </article>
      </div>

      {hasEvents && (
        <IpAttributionGraph
          graph={insights.attributionGraph}
          highlightLabel="未选择社群"
          highlightNodeIds={highlightedFamilyIps}
          selectedIp={selectedIp}
          onSelectIp={onSelectIp}
        />
      )}

      {hasEvents && (
        <div className="source-profile-evidence relation-evidence-grid">
          <div className="attack-path-list" aria-label="强关联 IP 边排行">
            <div className="relation-subhead">
              <strong>关联证据</strong>
              <span>{evidenceScopeCopy}</span>
            </div>
            {attributionRows.map((edge) => (
              <article key={edge.id}>
                <div>
                  <strong className="mono">{selectedGraphIp ? (edge.source === selectedGraphIp ? edge.target : edge.source) : edge.source}</strong>
                  <span>关联度 {edge.score} 分 · {confidenceLabel(edge.confidence)}</span>
                </div>
                <p>
                  <b>{edge.source}</b>
                  <i aria-hidden="true" />
                  <b>{edge.target}</b>
                </p>
                <small>{edge.evidence.map((item) => `${item.label}${item.examples.length ? `：${item.examples.join("、")}` : ""}`).join("；")}</small>
              </article>
            ))}
          </div>

          <div className="honeypot-distribution" aria-label="目标蜜罐分布">
            <div className="relation-subhead">
              <strong>目标特征分布</strong>
              <span>只作为计算边权的证据，不作为图节点</span>
            </div>
            {insights.honeypotRows.map((honeypot) => (
              <article key={honeypot.name}>
                <div>
                  <strong>{honeypot.name}</strong>
                  <span>{formatNumber(honeypot.count)} 条 · {honeypot.rate}%</span>
                </div>
                <i aria-hidden="true"><b style={{ width: `${Math.max(4, honeypot.rate)}%` }} /></i>
                <small>{formatNumber(honeypot.sourceCount)} 个源 IP / {formatNumber(honeypot.protocolCount)} 类攻击方式 / 高危 {formatNumber(honeypot.highCount)}</small>
              </article>
            ))}
          </div>
        </div>
      )}

      {!hasEvents && (
        <p className="empty-copy">当前筛选条件下暂无可聚合事件。</p>
      )}
    </div>
  );
}

function ipGraphLabelGeometry(node, graph) {
  const centerX = graph.width / 2;
  const centerY = graph.height / 2;
  const labelAngle = Math.atan2(node.y - centerY, node.x - centerX);
  const labelDistance = node.radius + 10;
  return {
    labelDx: Math.cos(labelAngle) * labelDistance,
    labelDy: Math.sin(labelAngle) * labelDistance,
    labelAnchor: Math.cos(labelAngle) > 0.25 ? "start" : Math.cos(labelAngle) < -0.25 ? "end" : "middle",
  };
}

function graphLayoutHash(value, salt = 0) {
  let hash = 2166136261 ^ salt;
  const text = String(value);
  for (let index = 0; index < text.length; index += 1) {
    hash ^= text.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return ((hash >>> 0) % 10000) / 10000;
}

function expandedClusterLayout(nodes, graph, clusterIndex) {
  const clusterNodes = nodes
    .filter((node) => node.clusterIndex === clusterIndex)
    .slice()
    .sort((left, right) =>
      right.degree - left.degree ||
      right.count - left.count ||
      right.highCount - left.highCount ||
      left.id.localeCompare(right.id)
    );
  if (!clusterNodes.length) return new Map();
  const centerX = graph.width / 2;
  const centerY = graph.height / 2;
  const paddingX = 88;
  const paddingY = 64;
  const columns = Math.max(1, Math.ceil(Math.sqrt(clusterNodes.length * 1.35)));
  const rows = Math.max(1, Math.ceil(clusterNodes.length / columns));
  const usableWidth = graph.width - paddingX * 2;
  const usableHeight = graph.height - paddingY * 2;
  const spacingX = columns === 1 ? 0 : Math.min(88, Math.max(34, usableWidth / Math.max(1, columns - 1)));
  const spacingY = rows === 1 ? 0 : Math.min(66, Math.max(30, usableHeight / Math.max(1, rows - 1)));
  const totalWidth = (columns - 1) * spacingX;
  const totalHeight = (rows - 1) * spacingY;
  const startX = centerX - totalWidth / 2;
  const startY = centerY - totalHeight / 2;
  const overrides = new Map();

  clusterNodes.forEach((node, index) => {
    const row = Math.floor(index / columns);
    const column = index % columns;
    const rowOffset = rows > 1 && row % 2 === 1 ? spacingX * 0.28 : 0;
    const jitterX = (graphLayoutHash(node.id, 97) - 0.5) * Math.min(10, spacingX * 0.2 || 8);
    const jitterY = (graphLayoutHash(node.id, 101) - 0.5) * Math.min(8, spacingY * 0.2 || 7);
    const x = startX + column * spacingX + rowOffset + jitterX;
    const y = startY + row * spacingY + jitterY;
    overrides.set(node.id, {
      x: Math.max(paddingX, Math.min(graph.width - paddingX, x)),
      y: Math.max(paddingY, Math.min(graph.height - paddingY, y)),
    });
  });

  return overrides;
}

function IpNodeDetailCard({ links = [], node, onSelectNode }) {
  if (!node) {
    return (
      <div className="ip-node-detail-card empty">
        <span>当前节点</span>
        <strong>未选中</strong>
        <small>点击图中的源 IP 节点查看画像、归属、一跳关联和边权证据。</small>
      </div>
    );
  }

  const visibleLinks = links.slice(0, 6);
  const visibleDegree = links.length;
  const location = joinKnown([node.country, node.city], "位置未知");
  const network = joinKnown([node.isp, node.asn], "网络归属未知");

  return (
    <div className="ip-node-detail-card">
      <div className="ip-node-detail-head">
        <span>当前节点</span>
        <strong className="mono">{node.label}</strong>
        <small>{node.clusterLabel} · {formatNumber(node.count)} 事件 · {formatNumber(visibleDegree)} 条可见关联边</small>
      </div>
      <div className="ip-node-kpis" aria-label="节点指标">
        <div>
          <span>高危</span>
          <strong>{formatNumber(node.highCount)}</strong>
        </div>
        <div>
          <span>关联</span>
          <strong>{formatNumber(visibleDegree)}</strong>
        </div>
        <div>
          <span>簇规模</span>
          <strong>{formatNumber(node.clusterSize)} IP</strong>
        </div>
      </div>
      <dl className="ip-node-meta-grid">
        <div>
          <dt>主要方式</dt>
          <dd>{displayValue(node.dominantMethod)}</dd>
        </div>
        <div>
          <dt>协议</dt>
          <dd>{displayValue(node.dominantProtocol)}</dd>
        </div>
        <div>
          <dt>归属地</dt>
          <dd>{location}</dd>
        </div>
        <div>
          <dt>网络</dt>
          <dd>{network}</dd>
        </div>
      </dl>
      <div className="ip-neighbor-block">
        <div className="ip-neighbor-title">
          <strong>一跳关联</strong>
          <span>{formatNumber(links.length)} 条</span>
        </div>
        {visibleLinks.length ? (
          <div className="ip-neighbor-list">
            {visibleLinks.map((link) => {
              const neighbor = link.source === node.id ? link.targetNode : link.sourceNode;
              if (!neighbor) return null;
              const evidenceText = link.evidence?.map((item) => item.label).join(" / ") || "行为相似";
              return (
                <button className="ip-neighbor-row" key={link.id} onClick={() => onSelectNode?.(neighbor.id)} type="button">
                  <span>
                    <strong className="mono">{neighbor.label}</strong>
                    <b>{link.score} 分</b>
                  </span>
                  <small>{confidenceLabel(link.confidence)} · {evidenceText}</small>
                </button>
              );
            })}
          </div>
        ) : (
          <p className="ip-neighbor-empty">暂无强关联邻居。</p>
        )}
      </div>
    </div>
  );
}

function IpAttributionGraph({ graph, highlightLabel = "", highlightNodeIds = new Set(), selectedIp = "", onSelectIp }) {
  const [dragState, setDragState] = useState(null);
  const [nodePositionOverrides, setNodePositionOverrides] = useState({});
  const [selectedNodeId, setSelectedNodeId] = useState(null);
  const [expandedClusterIndex, setExpandedClusterIndex] = useState(null);
  const [sourceIpQuery, setSourceIpQuery] = useState("");
  const [queryFeedback, setQueryFeedback] = useState("");
  const dragStateRef = useRef(null);
  const dragFrameRef = useRef(null);
  const pendingDragPositionRef = useRef(null);
  const graphKey = graph?.nodes?.map((node) => node.id).join("|") || "";

  useEffect(() => {
    dragStateRef.current = null;
    pendingDragPositionRef.current = null;
    if (dragFrameRef.current) {
      window.cancelAnimationFrame(dragFrameRef.current);
      dragFrameRef.current = null;
    }
    setDragState(null);
    setExpandedClusterIndex(null);
    setQueryFeedback("");
    setNodePositionOverrides((current) => {
      const next = {};
      const validIds = new Set(graph?.nodes?.map((node) => node.id) || []);
      Object.entries(current).forEach(([id, position]) => {
        if (validIds.has(id)) next[id] = position;
      });
      return next;
    });
    setSelectedNodeId((current) => (
      graph?.nodes?.some((node) => node.id === current) ? current : null
    ));
  }, [graphKey]);

  useEffect(() => {
    if (!selectedIp || !graph?.nodes?.some((node) => node.id === selectedIp)) return;
    setSelectedNodeId(selectedIp);
  }, [graphKey, graph?.nodes, selectedIp]);

  useEffect(() => () => {
    if (dragFrameRef.current) {
      window.cancelAnimationFrame(dragFrameRef.current);
      dragFrameRef.current = null;
    }
  }, []);

  if (!graph?.nodes?.length) {
    return <p className="empty-copy">当前筛选条件下暂无可绘制的 IP 关联图。</p>;
  }
  const baseNodes = graph.nodes.map((node) => ({
    ...node,
    ...(nodePositionOverrides[node.id] || {}),
  }));
  const clusterPositionOverrides = expandedClusterIndex !== null
    ? expandedClusterLayout(baseNodes, graph, expandedClusterIndex)
    : new Map();
  const renderedNodes = baseNodes.map((node) => {
    const withPosition = {
      ...node,
      ...(clusterPositionOverrides.get(node.id) || {}),
    };
    return {
      ...withPosition,
      ...ipGraphLabelGeometry(withPosition, graph),
    };
  });
  const nodeById = new Map(renderedNodes.map((node) => [node.id, node]));
  const renderedLinks = graph.links
    .map((link) => ({
      ...link,
      sourceNode: nodeById.get(link.source),
      targetNode: nodeById.get(link.target),
    }))
    .filter((link) => link.sourceNode && link.targetNode);
  const activeNodeId = selectedNodeId && nodeById.has(selectedNodeId) ? selectedNodeId : null;
  const activeNode = activeNodeId ? nodeById.get(activeNodeId) : null;
  const isExpandedClusterLink = (link) => (
    expandedClusterIndex !== null
    && link.isCommunityLink
    && link.sourceNode.clusterIndex === expandedClusterIndex
    && link.targetNode.clusterIndex === expandedClusterIndex
  );
  const graphDisplayLinks = renderedLinks.filter((link) => {
    if (expandedClusterIndex !== null) return isExpandedClusterLink(link);
    if (activeNodeId) return link.source === activeNodeId || link.target === activeNodeId;
    return true;
  });
  const distanceForLink = (link) => {
    const dx = link.sourceNode.x - link.targetNode.x;
    const dy = link.sourceNode.y - link.targetNode.y;
    return Math.sqrt(dx * dx + dy * dy);
  };
  const connectedActiveLinks = activeNodeId
    ? graphDisplayLinks.filter((link) => link.source === activeNodeId || link.target === activeNodeId)
    : [];
  const sortedConnectedActiveLinks = connectedActiveLinks
    .slice()
    .sort((left, right) => distanceForLink(left) - distanceForLink(right) || right.score - left.score);
  const activeNeighborIds = new Set(
    sortedConnectedActiveLinks
      .map((link) => (link.source === activeNodeId ? link.target : link.source))
  );
  const neighborLabelLimit = activeNodeId && sortedConnectedActiveLinks.length <= 24
    ? sortedConnectedActiveLinks.length
    : 12;
  const labeledNeighborIds = new Set(
    sortedConnectedActiveLinks
      .slice(0, neighborLabelLimit)
      .map((link) => (link.source === activeNodeId ? link.target : link.source))
  );
  const highlightedNodeCount = [...highlightNodeIds].filter((id) => nodeById.has(id)).length;
  const expandedClusterNodeCount = expandedClusterIndex !== null
    ? renderedNodes.filter((node) => node.clusterIndex === expandedClusterIndex).length
    : 0;
  const baseCommunityRows = graph.communityRows || [];
  const activeClusterForRows = activeNode
    ? graph.clusters?.find((cluster) => cluster.index === activeNode.clusterIndex)
    : null;
  const communityRows = activeClusterForRows && !baseCommunityRows.some((cluster) => cluster.index === activeClusterForRows.index)
    ? [
      ...baseCommunityRows.slice(0, 7),
      {
        ...activeClusterForRows,
        coreIp: activeClusterForRows.topIp || activeClusterForRows.ips[0],
        avgEvents: activeClusterForRows.ips.length
          ? Math.round(activeClusterForRows.eventCount / activeClusterForRows.ips.length)
          : activeClusterForRows.eventCount,
        edgeShare: Math.round((activeClusterForRows.edgeCount / Math.max(1, baseCommunityRows[0]?.edgeCount || activeClusterForRows.edgeCount)) * 1000) / 10,
      },
    ]
    : baseCommunityRows;
  const neighborDetailLinks = connectedActiveLinks
    .slice()
    .sort((left, right) => right.score - left.score || distanceForLink(left) - distanceForLink(right));
  const graphViewBox = graph.viewBox || {
    x: 0,
    y: 0,
    width: graph.width,
    height: graph.height,
  };
  const selectNode = (nodeId, options = {}) => {
    if (!nodeId || !nodeById.has(nodeId)) return;
    setSelectedNodeId(nodeId);
    onSelectIp?.(nodeId);
    if (!options.keepExpandedCluster) {
      setExpandedClusterIndex(null);
    }
  };
  const focusCluster = (cluster) => {
    if (!cluster) return;
    const canExpandCluster = cluster.ips.length > 1 && cluster.internalEdgeCount > 0;
    if (canExpandCluster) {
      setExpandedClusterIndex(cluster.index);
      selectNode(cluster.coreIp, { keepExpandedCluster: true });
      setQueryFeedback(`已展开 ${cluster.label}，点击图空白处恢复原位`);
      return;
    }
    setExpandedClusterIndex(null);
    selectNode(cluster.coreIp);
    setQueryFeedback(`已定位 ${cluster.label} 核心 IP ${cluster.coreIp}`);
  };
  const handleIpSearchSubmit = (event) => {
    event.preventDefault();
    const query = sourceIpQuery.trim();
    if (!query) {
      setQueryFeedback("请输入源 IP 或部分 IP");
      return;
    }
    const normalizedQuery = query.toLowerCase();
    const matches = renderedNodes
      .filter((node) => node.label.toLowerCase().includes(normalizedQuery))
      .sort((left, right) => {
        const leftExact = left.label.toLowerCase() === normalizedQuery ? 1 : 0;
        const rightExact = right.label.toLowerCase() === normalizedQuery ? 1 : 0;
        const leftPrefix = left.label.toLowerCase().startsWith(normalizedQuery) ? 1 : 0;
        const rightPrefix = right.label.toLowerCase().startsWith(normalizedQuery) ? 1 : 0;
        return rightExact - leftExact || rightPrefix - leftPrefix || right.count - left.count || left.label.localeCompare(right.label);
      });
    const match = matches[0];
    if (!match) {
      setQueryFeedback("未找到匹配源 IP");
      return;
    }
    selectNode(match.id);
    setQueryFeedback(matches.length > 1 ? `定位 ${match.label}，共 ${formatNumber(matches.length)} 个匹配` : `已定位 ${match.label}`);
  };
  const pointFromPointer = (event) => {
    const svg = event.currentTarget.ownerSVGElement || event.currentTarget;
    const point = svg.createSVGPoint();
    point.x = event.clientX;
    point.y = event.clientY;
    return point.matrixTransform(svg.getScreenCTM().inverse());
  };
  const handleNodePointerDown = (event, node) => {
    event.preventDefault();
    event.stopPropagation();
    selectNode(node.id, { keepExpandedCluster: expandedClusterIndex === node.clusterIndex });
    const svg = event.currentTarget.ownerSVGElement;
    const point = pointFromPointer(event);
    const nextDragState = {
      id: node.id,
      offsetX: point.x - node.x,
      offsetY: point.y - node.y,
      pointerId: event.pointerId,
    };
    dragStateRef.current = nextDragState;
    if (event.pointerId !== undefined) {
      svg?.setPointerCapture?.(event.pointerId);
    }
    setDragState(nextDragState);
  };
  const scheduleDragPosition = (id, x, y) => {
    pendingDragPositionRef.current = { id, x, y };
    if (dragFrameRef.current) return;
    dragFrameRef.current = window.requestAnimationFrame(() => {
      dragFrameRef.current = null;
      const pending = pendingDragPositionRef.current;
      if (!pending) return;
      setNodePositionOverrides((current) => ({
        ...current,
        [pending.id]: {
          x: pending.x,
          y: pending.y,
        },
      }));
    });
  };
  const handleGraphPointerMove = (event) => {
    const currentDrag = dragStateRef.current;
    if (!currentDrag) return;
    const point = pointFromPointer(event);
    const dragPaddingX = graph.nodePaddingX || 48;
    const dragPaddingY = graph.nodePaddingY || 46;
    scheduleDragPosition(
      currentDrag.id,
      Math.max(dragPaddingX, Math.min(graph.width - dragPaddingX, point.x - currentDrag.offsetX)),
      Math.max(dragPaddingY, Math.min(graph.height - dragPaddingY, point.y - currentDrag.offsetY))
    );
  };
  const stopDragging = (event) => {
    if (dragStateRef.current?.pointerId !== undefined) {
      try {
        event.currentTarget.releasePointerCapture?.(dragStateRef.current.pointerId);
      } catch {
        // Pointer capture may already be released when the pointer leaves the SVG.
      }
    }
    dragStateRef.current = null;
    pendingDragPositionRef.current = null;
    setDragState(null);
  };
  const handleGraphBackgroundPointerDown = () => {
    setExpandedClusterIndex(null);
    setSelectedNodeId(null);
    setQueryFeedback("");
  };

  return (
    <div className="relation-network-card ip-attribution-card" aria-label="历史攻击 IP 图计算溯源关系网">
      <div className="relation-subhead">
        <strong>历史攻击 IP 点状关系网</strong>
        <span>全量显示 {formatNumber(renderedNodes.length)} 个节点；{highlightedNodeCount ? `${highlightLabel} 高亮 ${formatNumber(highlightedNodeCount)} 个 IP` : "查询或点击节点只做高亮"}</span>
      </div>
      <div className="ip-graph-shell">
        <svg
          viewBox={`${graphViewBox.x} ${graphViewBox.y} ${graphViewBox.width} ${graphViewBox.height}`}
          role="img"
          aria-label="攻击源 IP 节点和 IP 之间的相似度边"
          onPointerMove={handleGraphPointerMove}
          onPointerUp={stopDragging}
          onPointerCancel={stopDragging}
          onPointerLeave={stopDragging}
        >
          <rect
            className="ip-graph-hit-surface"
            height={graphViewBox.height}
            width={graphViewBox.width}
            x={graphViewBox.x}
            y={graphViewBox.y}
            onPointerDown={handleGraphBackgroundPointerDown}
          />
          <g className="ip-graph-links">
            {graphDisplayLinks.map((link) => {
              const isActive = link.source === activeNodeId || link.target === activeNodeId;
              const isHighlightedFamilyLink = highlightNodeIds.has(link.source) && highlightNodeIds.has(link.target);
              const isFocusedClusterLink = expandedClusterIndex !== null
                && link.isCommunityLink
                && link.sourceNode.clusterIndex === expandedClusterIndex
                && link.targetNode.clusterIndex === expandedClusterIndex;
              const isDimmed = !isActive && !isFocusedClusterLink && (activeNodeId || expandedClusterIndex !== null);
              return (
                <line
                  className={isActive ? "active" : isFocusedClusterLink ? "cluster-highlight" : isHighlightedFamilyLink ? "family-highlight" : isDimmed ? "dimmed" : undefined}
                  key={link.id}
                  x1={link.sourceNode.x}
                  x2={link.targetNode.x}
                  y1={link.sourceNode.y}
                  y2={link.targetNode.y}
                  style={{
                    "--network-link-color": link.color,
                    opacity: isActive ? Math.min(0.86, link.opacity + 0.24) : isFocusedClusterLink ? Math.min(0.72, link.opacity + 0.18) : isDimmed ? 0.02 : isHighlightedFamilyLink ? Math.min(0.64, link.opacity + 0.16) : link.opacity,
                    strokeWidth: isActive ? link.width + 0.75 : isFocusedClusterLink ? link.width + 0.45 : isHighlightedFamilyLink ? link.width + 0.35 : link.width,
                  }}
                >
                  <title>{`${link.source} ↔ ${link.target}: 关联度 ${link.score} 分，${confidenceLabel(link.confidence)}；${link.evidence.map((item) => item.label).join("、")}`}</title>
                </line>
              );
            })}
          </g>
          <g className="ip-graph-nodes">
            {renderedNodes.map((node) => {
              const isActive = node.id === activeNodeId;
              const isRelated = activeNeighborIds.has(node.id);
              const isFamilyHighlighted = highlightNodeIds.has(node.id);
              const isInExpandedCluster = expandedClusterIndex !== null && node.clusterIndex === expandedClusterIndex;
              const isDimmed = (activeNodeId && !isActive && !isRelated && !isInExpandedCluster) || (expandedClusterIndex !== null && !isInExpandedCluster);
              const shouldShowLabel = isActive || labeledNeighborIds.has(node.id) || (isFamilyHighlighted && highlightedNodeCount <= 24) || (isInExpandedCluster && expandedClusterNodeCount <= 56);
              const nodeClassName = [
                "ip-graph-node",
                node.isHub ? "hub" : "",
                isActive ? "active" : "",
                isRelated ? "related" : "",
                isFamilyHighlighted ? "family-highlight" : "",
                isInExpandedCluster ? "cluster-focused" : "",
                isDimmed ? "dimmed" : "",
                dragState?.id === node.id ? "dragging" : "",
              ].filter(Boolean).join(" ");
              return (
                <g
                  className={nodeClassName}
                  key={node.id}
                  onPointerDown={(event) => handleNodePointerDown(event, node)}
                  style={{ "--network-node-color": node.color }}
                  transform={`translate(${node.x} ${node.y})`}
                >
                  <circle className="ip-node-halo" r={node.radius + (node.isHub ? 7 : 4)} />
                  <circle className="ip-node-dot" r={node.radius} />
                  <circle className="ip-node-core" r={Math.max(1.45, node.radius * 0.38)} />
                  {shouldShowLabel && (
                    <>
                      <text className="ip-node-label" x={node.labelDx} y={node.labelDy} textAnchor={node.labelAnchor}>{compactText(node.label, 18)}</text>
                      <text className="ip-node-meta" x={node.labelDx} y={node.labelDy + 12} textAnchor={node.labelAnchor}>{node.clusterLabel}</text>
                    </>
                  )}
                  <title>{`${node.label} · ${node.clusterLabel} · ${formatNumber(node.count)} 条事件 · 关联 ${formatNumber(node.degree)} 条边 · 高危 ${formatNumber(node.highCount)} · ${node.dominantMethod} · ${node.isp} ${node.asn}`}</title>
                </g>
              );
            })}
          </g>
        </svg>
        <aside className="ip-community-panel" aria-label="源 IP 节点画像">
          <form className="ip-search-control" onSubmit={handleIpSearchSubmit}>
            <label htmlFor="source-ip-search">查询源 IP</label>
            <div>
              <Search size={14} aria-hidden="true" />
              <input
                id="source-ip-search"
                onChange={(event) => setSourceIpQuery(event.target.value)}
                placeholder="输入完整或部分 IP"
                value={sourceIpQuery}
              />
              <button type="submit">定位</button>
            </div>
            {queryFeedback && <small>{queryFeedback}</small>}
          </form>
          <IpNodeDetailCard links={neighborDetailLinks} node={activeNode} onSelectNode={(nodeId) => selectNode(nodeId, { keepExpandedCluster: expandedClusterIndex === nodeById.get(nodeId)?.clusterIndex })} />
        </aside>
      </div>

      <section className="ip-community-board" aria-label="疑似攻击者社群">
        <div className="relation-subhead">
          <strong>疑似攻击者社群</strong>
          <span>{expandedClusterIndex !== null ? "已展开当前社群，点击图空白处恢复原位" : `${formatNumber(communityRows.length)} 个重点社群，点击后只高亮与展开节点`}</span>
        </div>
        <div className="ip-community-list">
          {communityRows.slice(0, 8).map((cluster) => (
            <button
              className={expandedClusterIndex === cluster.index || activeNode?.clusterIndex === cluster.index ? "active" : undefined}
              key={cluster.id}
              type="button"
              onClick={() => focusCluster(cluster)}
            >
              <span>
                <strong>{cluster.label}</strong>
                <b>{cluster.ips.length} IP</b>
              </span>
              <small className="mono">核心 {cluster.coreIp}</small>
              <em>{formatNumber(cluster.eventCount)} 事件 · {formatNumber(cluster.edgeCount)} 关联边 · 簇内 {formatNumber(cluster.internalEdgeCount || 0)} 边</em>
              <i aria-hidden="true"><b style={{ width: `${Math.max(6, Math.min(100, cluster.edgeShare || 0))}%` }} /></i>
            </button>
          ))}
        </div>
      </section>

      <div className="relation-network-legend">
        {graph.clusters.slice(0, 6).map((cluster) => (
          <span key={cluster.id}><i style={{ background: cluster.color }} />{cluster.label} · {cluster.ips.length} IP</span>
        ))}
      </div>
    </div>
  );
}

function AttackTimeSeriesPanel({ activeMethod = "ALL", activeProtocol = "ALL", events, loading = false, snapshot }) {
  const availableDates = useMemo(() => trendDateOptions(snapshot.historyTrend, events), [events, snapshot.historyTrend]);
  const latestDate = availableDates[0] || formatBeijingDateInput(Date.now());
  const [timeRangeMode, setTimeRangeMode] = useState("last24h");
  const [selectedDate, setSelectedDate] = useState("");

  useEffect(() => {
    if (!selectedDate && latestDate) setSelectedDate(latestDate);
  }, [latestDate, selectedDate]);

  const activeDate = selectedDate || latestDate;
  const trend = useMemo(
    () => buildAttackTimeSeriesTrend(events, {
      activeMethod,
      activeProtocol,
      anchorTime: snapshot.generatedAt || snapshot.lastUpdated,
      historyTrend: snapshot.historyTrend,
      mode: timeRangeMode,
      selectedDate: activeDate,
    }),
    [activeDate, activeMethod, activeProtocol, events, snapshot.generatedAt, snapshot.historyTrend, snapshot.lastUpdated, timeRangeMode]
  );
  const trendSourceLabel = trend.source === "history" ? "历史全量聚合" : "代表事件回退";
  const chartWidth = 820;
  const chartHeight = 268;
  const padding = { top: 26, right: 28, bottom: 38, left: 46 };
  const plotWidth = chartWidth - padding.left - padding.right;
  const plotHeight = chartHeight - padding.top - padding.bottom;
  const baselineY = padding.top + plotHeight;
  const pointForBucket = (bucket) => {
    const x = padding.left + (bucket.index / 23) * plotWidth;
    const y = baselineY - (bucket.total / trend.maxTotal) * plotHeight;
    const highY = baselineY - (bucket.high / trend.maxTotal) * plotHeight;
    return { ...bucket, x, y, highY };
  };
  const points = trend.buckets.map(pointForBucket);
  const linePath = points.map((point, index) => `${index ? "L" : "M"} ${point.x.toFixed(1)} ${point.y.toFixed(1)}`).join(" ");
  const highLinePath = points.map((point, index) => `${index ? "L" : "M"} ${point.x.toFixed(1)} ${point.highY.toFixed(1)}`).join(" ");
  const yTicks = trend.yTicks;
  const xTickIndexes = [0, 4, 8, 12, 16, 20, 23];
  const topHours = trend.buckets
    .filter((bucket) => bucket.total > 0)
    .sort((left, right) => right.total - left.total || left.index - right.index)
    .slice(0, 4);

  return (
    <>
      <PanelHeading
        icon={Activity}
        title="攻击事件时间序列"
        subtitle="按北京时间小时聚合历史日志，支持最近 24 小时与指定日期切换"
      />
      <div className="attack-trend-shell">
        <div className="timeline-control-row">
          <div>
            <span>分析范围</span>
            <strong>{trend.rangeLabel} · {trendSourceLabel}</strong>
          </div>
          <div className="timeline-range-controls" aria-label="攻击事件时间范围">
            <button
              className={timeRangeMode === "last24h" ? "active" : ""}
              type="button"
              onClick={() => setTimeRangeMode("last24h")}
            >
              过去24小时
            </button>
            <label className={timeRangeMode === "date" ? "timeline-date-control active" : "timeline-date-control"}>
              <span>指定日期</span>
              <input
                aria-label="选择攻击分析日期"
                list="attack-trend-date-options"
                onChange={(event) => {
                  setSelectedDate(event.target.value);
                  setTimeRangeMode("date");
                }}
                onFocus={() => setTimeRangeMode("date")}
                type="date"
                value={activeDate}
              />
            </label>
            <datalist id="attack-trend-date-options">
              {availableDates.map((date) => <option key={date} value={date} />)}
            </datalist>
          </div>
        </div>

        <div className="attack-trend-summary">
          <article>
            <span>{timeRangeMode === "last24h" ? "过去24小时事件" : "指定日期事件"}</span>
            <strong>{loading ? "等待" : formatNumber(trend.total)}</strong>
            <small>{trend.dateLabel}</small>
          </article>
          <article>
            <span>峰值小时</span>
            <strong>{trend.peak.total ? trend.peak.label : "无峰值"}</strong>
            <small>{trend.peak.total ? `${formatNumber(trend.peak.total)} 条事件` : "当前范围未命中事件"}</small>
          </article>
          <article>
            <span>活跃小时</span>
            <strong>{loading ? "等待" : `${trend.activeHours}/24`}</strong>
            <small>有事件的小时数</small>
          </article>
          <article>
            <span>高危事件</span>
            <strong>{loading ? "等待" : formatNumber(trend.highTotal)}</strong>
            <small>高危曲线单独叠加</small>
          </article>
        </div>

        <div className="timeline-chart-layout">
          <div className="timeline-chart-card">
            <div className="timeline-chart-head">
              <div>
                <span>小时级攻击节奏</span>
                <strong>{trend.dateLabel} · {trendSourceLabel}</strong>
              </div>
              <div className="timeline-legend">
                <i className="total" /> 总事件
                <i className="high" /> 高危
              </div>
            </div>
            {loading ? (
              <p className="empty-copy">正在等待后端快照。</p>
            ) : (
              <svg className="timeline-curve" viewBox={`0 0 ${chartWidth} ${chartHeight}`} role="img" aria-label="攻击事件小时分布曲线">
                <rect className="timeline-plot-background" x={padding.left} y={padding.top} width={plotWidth} height={plotHeight} />
                {yTicks.map((tick, index) => {
                  const y = baselineY - (tick / trend.maxTotal) * plotHeight;
                  return (
                    <g className="timeline-grid-line" key={`${tick}-${index}`}>
                      <line x1={padding.left} x2={padding.left + plotWidth} y1={y} y2={y} />
                      <text x={padding.left - 10} y={y + 4} textAnchor="end">{formatNumber(tick)}</text>
                    </g>
                  );
                })}
                <line className="timeline-axis" x1={padding.left} x2={padding.left} y1={padding.top} y2={baselineY} />
                <line className="timeline-axis" x1={padding.left} x2={padding.left + plotWidth} y1={baselineY} y2={baselineY} />
                {xTickIndexes.map((bucketIndex) => {
                  const point = points[bucketIndex];
                  return (
                    <g className="timeline-x-tick" key={bucketIndex}>
                      <line x1={point.x} x2={point.x} y1={baselineY} y2={baselineY + 5} />
                      <text className="timeline-x-label" x={point.x} y={chartHeight - 12} textAnchor={bucketIndex === 0 ? "start" : bucketIndex === 23 ? "end" : "middle"}>
                        {point.label}
                      </text>
                    </g>
                  );
                })}
                <text className="timeline-axis-title timeline-y-title" transform={`translate(14 ${padding.top + plotHeight / 2}) rotate(-90)`} textAnchor="middle">
                  事件数
                </text>
                <text className="timeline-axis-title timeline-x-title" x={padding.left + plotWidth / 2} y={chartHeight - 2} textAnchor="middle">
                  时间（北京时间）
                </text>
                <path className="timeline-total-line" d={linePath} />
                <path className="timeline-high-line" d={highLinePath} />
                {points.filter((point) => point.total > 0).map((point) => (
                  <g className={point.total === trend.peak.total ? "timeline-point peak" : "timeline-point"} key={`point-${point.index}`}>
                    <circle cx={point.x} cy={point.y} r={point.total === trend.peak.total ? 4 : 2.6} />
                  </g>
                ))}
                {points.filter((point) => point.high > 0).map((point) => (
                  <g className="timeline-high-point" key={`high-point-${point.index}`}>
                    <circle cx={point.x} cy={point.highY} r={2.4} />
                  </g>
                ))}
                {trend.peak.total > 0 && (
                  <g className="timeline-peak-label">
                    <line x1={points[trend.peak.index].x} x2={points[trend.peak.index].x} y1={points[trend.peak.index].y} y2={baselineY} />
                    <text x={Math.min(chartWidth - 112, Math.max(108, points[trend.peak.index].x))} y={Math.max(18, points[trend.peak.index].y - 10)} textAnchor="middle">
                      峰值: {trend.peak.label}, {formatNumber(trend.peak.total)}
                    </text>
                  </g>
                )}
              </svg>
            )}
          </div>

          <div className="timeline-peak-list">
            <div>
              <span>高峰时段</span>
              <strong>{topHours.length ? `${topHours.length} 个主要小时` : "当前范围无事件"}</strong>
            </div>
            {topHours.length ? (
              topHours.map((hour) => (
                <article key={hour.hour}>
                  <b>{hour.label}</b>
                  <span>{formatNumber(hour.total)} 条 / {formatNumber(hour.sourceCount)} IP</span>
                  <small>{hour.topMethod}</small>
                </article>
              ))
            ) : (
              <p>当前筛选条件下，这个时间范围内没有可展示事件。</p>
            )}
          </div>
        </div>
      </div>
    </>
  );
}

function DataQualityPanel({ events, loading = false }) {
  const insights = useMemo(() => buildQualityInsights(events), [events]);
  const topCategory = insights.categories[0];

  return (
    <>
      <PanelHeading
        icon={Fingerprint}
        title="数据质量与语义抽取"
        subtitle="从 ODS 原始日志清洗到 DWD 事件宽表后，评估字段覆盖率和攻击行为语义"
      />
      <div className="quality-overview">
        <article className="quality-score-card">
          <span>清洗可用度</span>
          <strong>{loading ? "等待" : `${insights.qualityScore}%`}</strong>
          <small>
            {loading
              ? "等待后端快照后评估字段覆盖率"
              : `${formatNumber(insights.total)} 条当前事件 · ${formatNumber(insights.uniqueIpCount)} 个源 IP · ${formatNumber(insights.uniqueMethodCount)} 类攻击方式`}
          </small>
        </article>
        <article>
          <span>主要语义</span>
          <strong>{loading ? "等待分类" : topCategory ? topCategory.name : "等待事件"}</strong>
          <small>{loading ? "快照返回后生成行为语义" : topCategory ? `${formatNumber(topCategory.count)} 条，占 ${topCategory.rate}%` : "暂无可分类事件"}</small>
        </article>
      </div>

      <div className="quality-layout">
        <div className="quality-metrics" aria-label="字段覆盖率">
          {insights.qualityRows.map((row) => (
            <article key={row.name}>
              <div>
                <strong>{row.name}</strong>
                <span>{loading ? "等待快照" : `${formatNumber(row.count)} / ${formatNumber(insights.total)}`}</span>
              </div>
              <i aria-hidden="true"><b style={{ width: `${loading ? 0 : row.rate}%` }} /></i>
              <p>{row.meaning}</p>
            </article>
          ))}
        </div>
        <div className="semantic-stack" aria-label="事件语义分类">
          {loading ? (
            <p className="empty-copy">等待快照后生成语义分类。</p>
          ) : insights.categories.length ? (
            insights.categories.slice(0, 7).map((category) => (
              <div key={category.name} style={{ "--semantic-color": category.color }}>
                <span>{category.name}</span>
                <i aria-hidden="true"><b style={{ width: `${Math.max(4, category.rate)}%` }} /></i>
                <strong>{formatNumber(category.count)}</strong>
              </div>
            ))
          ) : (
            <p className="empty-copy">当前窗口暂无可分类事件。</p>
          )}
        </div>
      </div>
    </>
  );
}

function CollectorHealthPanel({ snapshot, loading = false }) {
  const stats = useMemo(() => buildCollectorHealthStats(snapshot), [snapshot]);
  const dominantName = stats.dominantServer?.name || "等待节点";
  const windowCopy = loading ? "等待快照" : `${formatNumber(stats.windowTotal)} 条窗口事件`;

  return (
    <>
      <PanelHeading
        icon={Server}
        title="采集健康与数据偏斜"
        subtitle="按 server_id 汇总采集窗口，识别在线无数据、节点偏斜和明细写入分区"
      />
      <div className="collector-health-layout">
        <div className="collector-health-summary" aria-label="采集健康摘要">
          <article className="collector-score-card">
            <span>活跃节点</span>
            <strong>{loading ? "等待" : `${formatNumber(stats.activeCount)} / ${formatNumber(stats.serverCount)}`}</strong>
            <small>{loading ? "等待后端快照" : `${formatNumber(stats.quietCount)} 个在线静默节点`}</small>
          </article>
          <article>
            <span>窗口事件</span>
            <strong>{windowCopy}</strong>
            <small>用于判断当前采集是否有新增日志</small>
          </article>
          <article>
            <span>主导节点</span>
            <strong>{dominantName}</strong>
            <small>{loading ? "等待节点分布" : `${stats.dominantShare}% 当前窗口占比`}</small>
          </article>
          <article>
            <span>分布状态</span>
            <strong>{loading ? "等待" : stats.skewLabel}</strong>
          <small>偏斜高时，研判结论需说明节点暴露面差异</small>
          </article>
        </div>

        <div className="collector-node-list" aria-label="采集节点健康明细">
          {loading ? (
            <p className="empty-copy">等待快照后显示每台蜜罐的采集状态。</p>
          ) : stats.rows.length ? (
            stats.rows.map((row) => (
              <article className={`collector-node-card ${row.tone}`} key={row.id}>
                <div className="collector-node-top">
                  <div>
                    <strong>{row.name}</strong>
                    <span>{row.label} · {row.ip}</span>
                  </div>
                  <em>{row.status}</em>
                </div>
                <div className="collector-node-meter">
                  <span>窗口占比</span>
                  <i aria-hidden="true"><b style={{ width: `${Math.max(row.eventShare ? 4 : 0, row.eventShare)}%` }} /></i>
                  <strong>{row.eventShare}%</strong>
                </div>
                <dl>
                  <div><dt>累计事件</dt><dd>{formatNumber(row.totalEvents)}</dd></div>
                  <div><dt>窗口事件</dt><dd>{formatNumber(row.currentEvents)}</dd></div>
                  <div><dt>窗口 IP</dt><dd>{formatNumber(row.externalIps)}</dd></div>
                  <div><dt>协议背景</dt><dd>{row.protocolText}</dd></div>
                </dl>
                <p>{row.diagnosis}</p>
                {isKnown(row.hdfsPartition) && <small className="mono">{row.hdfsPartition}</small>}
              </article>
            ))
          ) : (
            <p className="empty-copy">当前快照没有采集节点信息。</p>
          )}
        </div>
      </div>
    </>
  );
}

function TimeNormalizationPanel({ events, loading = false, snapshot }) {
  const stats = useMemo(() => buildTimeNormalizationStats(events, snapshot), [events, snapshot]);
  const latencyCopy = stats.latencySeconds === null
    ? "等待数据"
    : stats.latencySeconds < 60
      ? `${stats.latencySeconds} 秒`
      : `${Math.floor(stats.latencySeconds / 60)} 分 ${stats.latencySeconds % 60} 秒`;
  const sourceRows = loading
    ? []
    : stats.sourceCounts.slice(0, 4);

  return (
    <>
      <PanelHeading
        icon={Clock}
        title="时间标准化"
        subtitle="预处理保留 raw_time，并统一生成 UTC、北京时间和 event_ts_ms"
      />
      <div className="time-normalization-layout">
        <div className="time-normalization-summary">
          <article className="time-score-card">
            <span>标准化覆盖</span>
            <strong>{loading ? "等待" : `${stats.coverage}%`}</strong>
            <small>{loading ? "等待后端快照" : `${formatNumber(stats.normalized)} / ${formatNumber(stats.total)} 条来自日志时间字段`}</small>
          </article>
          <article>
            <span>最新事件</span>
            <strong>{loading ? "等待事件" : stats.latest ? formatEventClock(stats.latest) : "无事件"}</strong>
            <small>{loading ? "统一展示为北京时间" : stats.earliest ? `最早 ${formatEventClock(stats.earliest)}` : "统一展示为北京时间"}</small>
          </article>
          <article>
            <span>展示延迟</span>
            <strong>{loading ? "等待" : latencyCopy}</strong>
            <small>快照生成时间 - 最新事件时间</small>
          </article>
          <article>
            <span>兜底时间</span>
            <strong>{loading ? "等待" : formatNumber(stats.fallbackCount)}</strong>
            <small>未解析到原始时间时才使用当前时间</small>
          </article>
        </div>

        <div className="time-normalization-flow" aria-label="时间字段处理流程">
          {[
            ["raw_time", "保留原始时间"],
            ["event_time_utc", "统一 UTC ISO"],
            ["event_time_local", "统一北京时间"],
            ["event_ts_ms", "窗口排序与聚合"],
          ].map(([field, copy]) => (
            <article key={field}>
              <strong>{field}</strong>
              <span>{copy}</span>
            </article>
          ))}
        </div>

        <div className="time-normalization-footer">
          <div>
            <span>存储分区示例</span>
            <strong className="mono">{loading ? "等待快照" : stats.partition}</strong>
          </div>
          <div>
            <span>时间来源分布</span>
            <p>
              {loading
                ? "等待快照后统计来源字段"
                : sourceRows.length
                  ? sourceRows.map((row) => `${row.source} ${formatNumber(row.count)} 条`).join("；")
                  : "当前暂无事件"}
            </p>
          </div>
        </div>
      </div>
    </>
  );
}

function StatusLine({ label, value, tone = "neutral" }) {
  return (
    <div className="status-line">
      <span className={`status-icon ${tone}`}>
        {tone === "api" ? <CheckCircle2 size={15} /> : tone === "loading" ? <RefreshCw size={15} /> : <AlertTriangle size={15} />}
      </span>
      <strong>{label}</strong>
      <p>{value}</p>
    </div>
  );
}

function EndpointTable({ endpoints }) {
  const statusCopy = {
    connected: "已连接",
    bundled: "快照字段",
    reserved: "未接入",
  };
  return (
    <div className="endpoint-table">
      <div className="endpoint-row header">
        <span>接口</span>
        <span>方法</span>
        <span>负责人</span>
        <span>状态</span>
        <span>用途</span>
      </div>
      {endpoints.map((endpoint) => (
        <div className="endpoint-row" key={endpoint.key}>
          <span className="endpoint-cell mono">
            <span className="endpoint-cell-label">接口</span>
            <span className="endpoint-cell-value">{endpoint.path}</span>
          </span>
          <span className="endpoint-cell">
            <span className="endpoint-cell-label">方法</span>
            <span className="endpoint-cell-value">{endpoint.method}</span>
          </span>
          <span className="endpoint-cell">
            <span className="endpoint-cell-label">负责人</span>
            <span className="endpoint-cell-value">{endpoint.owner}</span>
          </span>
          <span className={`endpoint-cell ${endpoint.status}`}>
            <span className="endpoint-cell-label">状态</span>
            <span className="endpoint-cell-value">{statusCopy[endpoint.status] || endpoint.status}</span>
          </span>
          <span className="endpoint-cell">
            <span className="endpoint-cell-label">用途</span>
            <span className="endpoint-cell-value">{endpoint.description}</span>
          </span>
        </div>
      ))}
    </div>
  );
}

function IngestList({ items }) {
  return (
    <div className="ingest-list">
      {items.map((item) => (
        <article key={item.id}>
          <div>
            <strong>{item.name}</strong>
            <span>{item.parser}</span>
          </div>
          <em>{statusLabel[item.status] || item.status}</em>
          <dl>
            <div>
              <dt>最后采集</dt>
              <dd>{formatEventClock(item.lastSeen)}</dd>
            </div>
            <div>
              <dt>写入分区</dt>
              <dd>{item.hdfsPartition}</dd>
            </div>
          </dl>
        </article>
      ))}
    </div>
  );
}

function FieldMapping({ mappings }) {
  return (
    <div className="field-grid">
      {mappings.map(([field, label, description]) => (
        <article key={field}>
          <strong>{field}</strong>
          <span>{label}</span>
          <p>{description}</p>
        </article>
      ))}
    </div>
  );
}

function Pipeline() {
  const steps = [
    ["采集", "各蜜罐本地监听日志新增行"],
    ["预处理", "采集端生成 raw_time、UTC、北京时间和 event_ts_ms"],
    ["采集链路", "Flume Taildir 读取预处理 JSONL 并写入 Kafka Topic"],
    ["流式计算", "Flink 消费 Kafka 并输出清洗流；作业状态由后端健康探针确认"],
    ["历史存储", "目标为 HDFS/分区目录保留历史数据；当前以前端可读快照为准"],
    ["接口", "发布 dashboard.json 与 dashboard-live.json 给前端展示"],
  ];

  return (
    <div className="pipeline">
      {steps.map(([title, copy], index) => (
        <article key={title}>
          <span>{String(index + 1).padStart(2, "0")}</span>
          <strong>{title}</strong>
          <p>{copy}</p>
        </article>
      ))}
    </div>
  );
}

export default App;
