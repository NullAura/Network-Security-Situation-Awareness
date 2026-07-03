export const API_BASE =
  import.meta.env.VITE_HONEYPOT_API_BASE ||
  window.__HONEYPOT_API_BASE__ ||
  "";

const FETCH_TIMEOUT_MS = 12000;
const LIVE_FETCH_TIMEOUT_MS = 5000;
const DASHBOARD_CACHE_TTL_MS = 60000;
const RUNTIME_HEALTH_CACHE_TTL_MS = 30000;
const DISPLAY_SOURCE_IP_LIMIT = 160;
const DISPLAY_EVENTS_PER_SOURCE_IP = 3;
const BEIJING_TIME_ZONE = "Asia/Shanghai";
const BEIJING_OFFSET_MINUTES = 8 * 60;
const DEFAULT_NODE_COLORS = ["#19d3ff", "#a7f35a", "#ffcf58", "#9a86ff", "#ff6848"];

const KNOWN_HONEYPOT_CONFIG = [
  {
    id: "203.0.113.10",
    name: "203.0.113.10",
    label: "Cowrie SSH",
    ip: "203.0.113.10",
    city: "北美云节点",
    country: "United States",
    coordinates: [-118.2437, 34.0522],
    color: "#19d3ff",
  },
  {
    id: "203.0.113.11",
    name: "203.0.113.11",
    label: "OpenCanary 多协议",
    ip: "203.0.113.11",
    city: "华东云节点",
    country: "China",
    coordinates: [121.4737, 31.2304],
    color: "#a7f35a",
  },
  {
    id: "203.0.113.12",
    name: "203.0.113.12",
    label: "多协议低交互",
    ip: "203.0.113.12",
    city: "第三云节点",
    country: "Brazil",
    coordinates: [-46.6333, -23.5505],
    color: "#ffcf58",
  },
];

let cachedDashboardPayload = null;
let cachedDashboardFetchedAt = 0;
let cachedRuntimeHealthPayload = null;
let cachedRuntimeHealthFetchedAt = 0;

const HONEYPOT_ALIASES = {
  "bigdata-honeypot-1": "203.0.113.10",
  "ctf-47": "203.0.113.11",
  "bigdata-honeypot-3": "203.0.113.12",
};

const PROTOCOL_METADATA = {
  SSH: { name: "SSH", severity: "high" },
  FTP: { name: "FTP", severity: "medium" },
  HTTP: { name: "HTTP", severity: "medium" },
  HTTPS_ALT: { name: "HTTPS 扩展端口", severity: "medium" },
  HTTP_ALT: { name: "HTTP 扩展端口", severity: "medium" },
  MYSQL: { name: "MySQL", severity: "high" },
  REDIS: { name: "Redis", severity: "high" },
  TELNET: { name: "Telnet", severity: "high" },
  RDP: { name: "RDP", severity: "high" },
  VNC: { name: "VNC", severity: "high" },
  POSTGRES: { name: "PostgreSQL", severity: "high" },
  MSSQL: { name: "MSSQL", severity: "high" },
  ORACLE: { name: "Oracle", severity: "high" },
  MONGODB: { name: "MongoDB", severity: "high" },
  MEMCACHED: { name: "Memcached", severity: "high" },
  ELASTICSEARCH: { name: "Elasticsearch", severity: "high" },
  MQTT: { name: "MQTT", severity: "medium" },
  SMTP: { name: "SMTP", severity: "medium" },
  POP3: { name: "POP3", severity: "medium" },
  IMAP: { name: "IMAP", severity: "medium" },
  SMB: { name: "SMB", severity: "high" },
  SIP: { name: "SIP", severity: "medium" },
  LDAP: { name: "LDAP", severity: "medium" },
  NFS: { name: "NFS", severity: "medium" },
  RPCBIND: { name: "RPCBind", severity: "medium" },
  UNKNOWN: { name: "未识别协议", severity: "low" },
};

const PORT_PROTOCOLS = {
  21: "FTP",
  22: "SSH",
  23: "TELNET",
  25: "SMTP",
  80: "HTTP",
  110: "POP3",
  111: "RPCBIND",
  135: "RPCBIND",
  139: "SMB",
  143: "IMAP",
  389: "LDAP",
  443: "HTTP",
  445: "SMB",
  1433: "MSSQL",
  1521: "ORACLE",
  1883: "MQTT",
  2049: "NFS",
  27017: "MONGODB",
  3306: "MYSQL",
  3389: "RDP",
  5060: "SIP",
  5432: "POSTGRES",
  5900: "VNC",
  5901: "VNC",
  5902: "VNC",
  5903: "VNC",
  5904: "VNC",
  5905: "VNC",
  6379: "REDIS",
  8080: "HTTP_ALT",
  8088: "HTTP_ALT",
  8089: "HTTP_ALT",
  8443: "HTTPS_ALT",
  8888: "HTTP_ALT",
  9200: "ELASTICSEARCH",
  11211: "MEMCACHED",
};

const SEVERITY_WEIGHT = { low: 1, medium: 2, high: 3 };

const SUMMARY_FIELD_LABELS = {
  "VNC Client Response": "VNC 响应",
  "VNC Password": "VNC 口令",
  "VNC Server Challenge": "VNC 挑战",
  event_type: "事件",
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
};

const SUMMARY_FIELD_PRIORITY = [
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

const LOCATION_COORDINATES = new Map(
  [
    ["United States", "New Jersey", "North Bergen", [-74.0121, 40.8043]],
    ["United States", "California", "Santa Clara", [-121.9552, 37.3541]],
    ["United States", "Arizona", "Tempe", [-111.94, 33.4255]],
    ["United States", "Arizona", "Phoenix", [-112.074, 33.4484]],
    ["Canada", "Ontario", "Toronto", [-79.3832, 43.6532]],
    ["The Netherlands", "Limburg", "Eygelshoven", [6.0596, 50.8922]],
    ["The Netherlands", "North Holland", "Amsterdam", [4.9041, 52.3676]],
    ["Poland", "Mazovia", "Warsaw", [21.0122, 52.2297]],
    ["China", "Zhejiang", "Hangzhou", [120.1551, 30.2741]],
    ["China", "Jiangsu", "Suzhou", [120.5853, 31.2989]],
    ["China", "Liaoning", "Shenyang", [123.4315, 41.8057]],
    ["China", "Hubei", "Shizishan", [114.356, 30.523]],
    ["China", "Heilongjiang", "Harbin", [126.6424, 45.756]],
    ["China", "Beijing", "Beijing", [116.4074, 39.9042]],
    ["Belgium", "Brussels Capital", "Brussels", [4.3517, 50.8503]],
    ["Ireland", "Leinster", "Dublin", [-6.2603, 53.3498]],
    ["Vietnam", "Hai Phong", "Đố Sơn", [106.7942, 20.7197]],
    ["Hong Kong", "Yau Tsim Mong District", "Tai Kok Tsui", [114.162, 22.321]],
    ["Hong Kong", "Central and Western District", "Hong Kong", [114.1694, 22.3193]],
    ["Bulgaria", "Sofia-Capital", "Sofia", [23.3219, 42.6977]],
    ["Turkey", "Istanbul", "Ataşehir", [29.127, 40.992]],
    ["Thailand", "Bangkok", "Bangkok", [100.5018, 13.7563]],
    ["Brazil", "Sao Paulo", "São Paulo", [-46.6333, -23.5505]],
    ["Germany", "Hesse", "Frankfurt am Main", [8.6821, 50.1109]],
    ["Germany", "Bavaria", "Nuremberg", [11.0767, 49.4521]],
    ["Germany", "Bavaria", "Augsburg", [10.8985, 48.3705]],
    ["South Korea", "Gangwon-do", "Chuncheon", [127.7298, 37.8813]],
    ["South Korea", "Seoul", "Seoul", [126.978, 37.5665]],
    ["Japan", "Tokyo", "Tokyo", [139.6917, 35.6895]],
    ["Japan", "Tokyo", "Chiyoda City", [139.753, 35.694]],
    ["Pakistan", "Islamabad", "Islamabad", [73.0479, 33.6844]],
    ["Sweden", "Stockholm County", "Stockholm", [18.0686, 59.3293]],
    ["India", "Maharashtra", "Mumbai", [72.8777, 19.076]],
    ["Singapore", "North West", "Singapore", [103.8198, 1.3521]],
    ["United Kingdom", "Wales", "Swansea", [-3.9436, 51.6214]],
  ].map(([country, region, city, coordinates]) => [locationKey(country, region, city), coordinates]),
);

export const endpointContracts = [
  {
    key: "dashboard",
    method: "GET",
    path: "/api/dashboard.json",
    owner: "后端聚合层",
    description: "分钟级历史聚合快照，承载全量统计、IP 画像和历史事件窗口。",
  },
  {
    key: "live",
    method: "GET",
    path: "/api/dashboard-live.json",
    owner: "实时发布层",
    description: "秒级增量快照，只承载新增事件窗口和实时采集状态。",
  },
  {
    key: "events",
    method: "GET",
    path: "/api/events?limit=120",
    owner: "日志明细层",
    description: "返回统一字段后的事件流，支持 limit、protocol、source_ip、server_id 参数。",
  },
  {
    key: "stats",
    method: "GET",
    path: "/api/stats",
    owner: "DWS 聚合结果层",
    description: "返回总事件数、会话数、外部 IP 数、命令数、协议统计和小时趋势。",
  },
  {
    key: "honeypots",
    method: "GET",
    path: "/api/honeypots",
    owner: "配置中心",
    description: "返回可公开展示的蜜罐节点配置，不暴露 SSH 密钥、日志路径等私有配置。",
  },
  {
    key: "sources",
    method: "GET",
    path: "/api/sources",
    owner: "IP 画像层",
    description: "返回源 IP、国家、地区、城市、ISP、ASN、坐标和事件计数。",
  },
  {
    key: "protocols",
    method: "GET",
    path: "/api/protocols",
    owner: "协议统计层",
    description: "返回协议维度聚合统计，可由 dashboard 快照字段承载。",
  },
  {
    key: "ingest",
    method: "GET",
    path: "/api/ingest/status",
    owner: "采集调度层",
    description: "返回每台蜜罐的采集状态、最后采集时间、明细写入分区和错误信息。",
  },
  {
    key: "runtimeHealth",
    method: "GET",
    path: "/api/runtime-health.json",
    owner: "后端健康探针",
    description: "返回 Kafka、Flink 和 HDFS 的只读健康探测结果。",
  },
];

export const fieldMappings = [
  ["raw_time", "原始事件时间", "保留 Cowrie/OpenCanary/Honeypot3 原始时间字符串，便于追溯"],
  ["event_time_utc", "UTC 时间", "所有日志时间统一为 UTC ISO 字符串，避免跨节点时区偏差"],
  ["event_time_local", "北京时间", "按 Asia/Shanghai 输出展示时间，便于人工核对"],
  ["event_ts_ms", "毫秒时间戳", "统一用于排序、窗口聚合、展示延迟和小时分区"],
  ["event_time_source", "时间来源", "记录使用 timestamp、event_time、utc_time 或 payload 内字段完成归一化"],
  ["server_id", "蜜罐节点", "203.0.113.10 / 203.0.113.11 / 203.0.113.12"],
  ["honeypot_type", "蜜罐类型", "cowrie / opencanary / multiprotocol"],
  ["src_ip", "源 IP", "攻击或扫描来源地址"],
  ["dst_port", "目标端口", "用于协议识别和风险统计"],
  ["protocol", "协议", "SSH / FTP / HTTP / MySQL / Redis / Telnet / RDP / VNC 等"],
  ["event_type", "事件类型", "登录、命令、连接、扫描、下载等统一事件名"],
  ["username/password", "账号口令", "仅用于攻击行为统计展示，不作为登录凭据使用"],
  ["country/region/city", "地理位置", "公开 IP 库近似定位，城市级别不保证精确"],
  ["isp/asn", "网络归属", "运营商、云厂商或自治系统归属"],
];

export async function fetchThreatSnapshot({ force = false } = {}) {
  try {
    const dashboard = await fetchDashboardPayload({ force });
    const live = await fetchLivePayload().catch(() => null);
    const runtimeHealth = await fetchRuntimeHealthPayload({ force }).catch(() => null);
    const mergedDashboard = mergeDashboardWithLive(dashboard, live);
    return buildSnapshot({
      honeypots: mergedDashboard.honeypots,
      protocols: mergedDashboard.protocols,
      attackMethods: mergedDashboard.attackMethods,
      sources: mergedDashboard.sources,
      events: mergedDashboard.events,
      stats: mergedDashboard.stats,
      historyTrend: mergedDashboard.historyTrend || mergedDashboard.history_trend,
      ingestStatus: mergedDashboard.ingestStatus,
      mode: "api",
      apiMessage: live ? "已连接历史快照 + 秒级 live 增量" : "已连接 /api/dashboard.json 历史快照",
      generatedAt: mergedDashboard.generatedAt,
      generatedAtLocal: mergedDashboard.generatedAtLocal,
      runtimeHealth,
      connectedEndpoints: [
        "dashboard",
        ...(live ? ["live"] : []),
        ...(runtimeHealth ? ["runtimeHealth"] : []),
      ],
      bundledEndpoints: [],
    });
  } catch (dashboardError) {
    const partial = await fetchPartialSnapshot();
    if (partial.connected) {
      return buildSnapshot({
        ...partial,
        mode: "api",
        apiMessage: "已连接分离式 API",
        bundledEndpoints: [],
      });
    }

    return createFallbackSnapshot(dashboardError);
  }
}

async function fetchDashboardPayload({ force = false } = {}) {
  const now = Date.now();
  if (!force && cachedDashboardPayload && now - cachedDashboardFetchedAt < DASHBOARD_CACHE_TTL_MS) {
    return cachedDashboardPayload;
  }
  const dashboard = await fetchJson(cacheBustPath("/api/dashboard.json"), {
    cache: "no-store",
  }).catch(() => fetchJson(cacheBustPath("/api/dashboard"), {
    cache: "no-store",
  }));
  cachedDashboardPayload = dashboard;
  cachedDashboardFetchedAt = now;
  return dashboard;
}

async function fetchLivePayload() {
  return fetchJson(cacheBustPath("/api/dashboard-live.json"), {
    cache: "no-store",
    timeoutMs: LIVE_FETCH_TIMEOUT_MS,
  });
}

async function fetchRuntimeHealthPayload({ force = false } = {}) {
  const now = Date.now();
  if (!force && cachedRuntimeHealthPayload && now - cachedRuntimeHealthFetchedAt < RUNTIME_HEALTH_CACHE_TTL_MS) {
    return cachedRuntimeHealthPayload;
  }
  const payload = await fetchJson(cacheBustPath("/api/runtime-health.json"), {
    cache: "no-store",
    timeoutMs: 20000,
  });
  cachedRuntimeHealthPayload = payload;
  cachedRuntimeHealthFetchedAt = now;
  return payload;
}

function cacheBustPath(path) {
  const separator = path.includes("?") ? "&" : "?";
  return `${path}${separator}_=${Date.now()}`;
}

function mergeDashboardWithLive(dashboard, live) {
  if (!live || typeof live !== "object") return dashboard;
  return {
    ...dashboard,
    generatedAt: live.generatedAt || dashboard.generatedAt,
    generatedAtLocal: live.generatedAtLocal || dashboard.generatedAtLocal,
    events: mergeEventWindows(live.events, dashboard.events),
    honeypots: mergeHoneypotStatus(dashboard.honeypots, live.honeypots),
    ingestStatus: mergeIngestStatusPayload(dashboard.ingestStatus, live.ingestStatus),
    stats: {
      ...(dashboard.stats || {}),
      liveConnected: true,
      liveEventsSinceStart: live.stats?.liveEventsSinceStart,
      liveWindowEvents: live.stats?.windowEvents,
      liveWindowSeconds: live.stats?.windowSeconds,
      liveRetainedEvents: live.stats?.retainedEvents,
      livePublishedEvents: live.stats?.publishedEvents,
      liveEventsPerSecond: live.stats?.eventsPerSecond,
      liveLastEventDelaySeconds: live.stats?.lastEventDelaySeconds,
    },
  };
}

function mergeEventWindows(primary = [], secondary = []) {
  const seen = new Set();
  const deduped = [...(Array.isArray(primary) ? primary : []), ...(Array.isArray(secondary) ? secondary : [])]
    .filter((event) => {
      const key = eventIdentity(event);
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  return limitEventsBySourceIp(deduped, DISPLAY_SOURCE_IP_LIMIT, DISPLAY_EVENTS_PER_SOURCE_IP);
}

function sourceIpOf(event) {
  return event?.src_ip || event?.srcIp || event?.source_ip || event?.srcHost || "";
}

function limitEventsBySourceIp(events, ipLimit, perIpLimit) {
  const selected = [];
  const selectedIps = new Set();
  const perIpCounts = new Map();
  for (const event of events) {
    const srcIp = sourceIpOf(event);
    if (!srcIp) continue;
    if (!selectedIps.has(srcIp) && selectedIps.size >= ipLimit) continue;
    const count = perIpCounts.get(srcIp) || 0;
    if (count >= perIpLimit) continue;
    selectedIps.add(srcIp);
    perIpCounts.set(srcIp, count + 1);
    selected.push(event);
  }
  return selected;
}

function eventIdentity(event) {
  return [
    event?.id,
    event?.event_time_utc,
    event?.event_time,
    event?.eventTime,
    event?.src_ip || event?.srcIp,
    event?.server_id || event?.honeypotIp,
    event?.protocol,
    event?.event_type || event?.eventType,
    event?.dst_port || event?.dstPort,
    event?.payload || event?.command || event?.raw,
  ]
    .filter((value) => value !== undefined && value !== null && value !== "")
    .join("|");
}

function mergeHoneypotStatus(base = [], live = []) {
  if (!Array.isArray(base) || !base.length || !Array.isArray(live) || !live.length) return base;
  const liveById = new Map(live.map((item) => [normalizeHoneypotId(item.id || item.ip || item.name), item]));
  return base.map((item) => {
    const id = normalizeHoneypotId(item.id || item.ip || item.name);
    const liveItem = liveById.get(id);
    if (!liveItem) return item;
    return {
      ...item,
      status: liveItem.status || item.status,
      currentEvents: liveItem.currentEvents ?? item.currentEvents,
      liveEvents: liveItem.liveEvents ?? item.liveEvents,
      lastEventAt: liveItem.lastEventAt || item.lastEventAt,
      lastSeen: liveItem.lastSeen || item.lastSeen,
    };
  });
}

function mergeIngestStatusPayload(base = [], live = []) {
  if (!Array.isArray(base) || !base.length) return live || base;
  if (!Array.isArray(live) || !live.length) return base;
  const liveById = new Map(live.map((item) => [normalizeHoneypotId(item.id || item.server_id || item.name), item]));
  return base.map((item) => {
    const id = normalizeHoneypotId(item.id || item.server_id || item.name);
    const liveItem = liveById.get(id);
    return liveItem ? { ...item, ...liveItem } : item;
  });
}

export function createFallbackSnapshot(error) {
  return buildSnapshot({
    honeypots: KNOWN_HONEYPOT_CONFIG,
    protocols: [],
    sources: [],
    events: [],
    stats: null,
    ingestStatus: [],
    mode: "error",
    apiMessage: error ? `接口不可用：${normalizeError(error)}` : "等待真实数据接口",
  });
}

async function fetchPartialSnapshot() {
  const endpointKeys = ["honeypots", "events", "stats", "sources", "protocols", "ingest", "runtimeHealth"];
  const requests = await Promise.allSettled([
    fetchJson("/api/honeypots"),
    fetchJson("/api/events?limit=120"),
    fetchJson("/api/stats"),
    fetchJson("/api/sources"),
    fetchJson("/api/protocols"),
    fetchJson("/api/ingest/status"),
    fetchRuntimeHealthPayload(),
  ]);

  const [honeypots, events, stats, sources, protocols, ingestStatus, runtimeHealth] = requests.map((result) =>
    result.status === "fulfilled" ? result.value : undefined,
  );
  const connected = requests.some((result) => result.status === "fulfilled");
  const connectedEndpoints = endpointKeys.filter((_, index) => requests[index]?.status === "fulfilled");

  return {
    connected,
    connectedEndpoints,
    honeypots: unwrap(honeypots, "honeypots"),
    events: unwrap(events, "events"),
    stats,
    sources: unwrap(sources, "sources"),
    protocols: unwrap(protocols, "protocols"),
    ingestStatus: unwrap(ingestStatus, "ingestStatus"),
    runtimeHealth,
  };
}

async function fetchJson(path, options = {}) {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), options.timeoutMs || FETCH_TIMEOUT_MS);
  const url = `${API_BASE}${path}`;

  try {
    const response = await fetch(url, {
      headers: {
        Accept: "application/json",
        "Cache-Control": "no-cache",
        Pragma: "no-cache",
      },
      signal: controller.signal,
      cache: options.cache || "no-store",
    });
    if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
    const contentType = response.headers.get("content-type") || "";
    if (!contentType.includes("application/json")) throw new Error("non-json response");
    return await response.json();
  } finally {
    window.clearTimeout(timeout);
  }
}

function unwrap(payload, key) {
  if (!payload) return undefined;
  if (Array.isArray(payload)) return payload;
  if (payload[key]) return payload[key];
  if (payload.data) return Array.isArray(payload.data) ? payload.data : payload.data[key];
  return payload;
}

function buildSnapshot({
  honeypots,
  protocols,
  attackMethods,
  sources,
  events,
  stats,
  historyTrend,
  ingestStatus,
  mode,
  apiMessage,
  generatedAt,
  generatedAtLocal,
  runtimeHealth,
  connectedEndpoints = [],
  bundledEndpoints = [],
}) {
  const normalizedHoneypots = normalizeHoneypots(honeypots);
  const normalizedProtocols = normalizeProtocols(protocols);
  const normalizedAttackMethods = normalizeAttackMethods(attackMethods);
  const normalizedSources = normalizeSources(sources);
  const context = {
    honeypots: normalizedHoneypots,
    protocols: normalizedProtocols,
    sources: normalizedSources,
  };
  const normalizedEvents = normalizeEvents(events, context);
  const sourceStats = buildSourceStats(normalizedSources, normalizedEvents);
  const protocolStats = buildProtocolStats(normalizedProtocols, normalizedEvents, stats);
  const serverStats = buildServerStats(normalizedHoneypots, normalizedEvents, ingestStatus);
  const trend = buildTrend(normalizedEvents);
  const computedStats = buildStats(stats, protocolStats, sourceStats, normalizedEvents);

  return {
    mode,
    apiBase: API_BASE || "same-origin",
    apiMessage,
    generatedAt: generatedAt || "",
    generatedAtLocal,
    lastUpdated: generatedAt || "",
    endpoints: buildEndpointStatuses(mode, connectedEndpoints, bundledEndpoints),
    fieldMappings,
    honeypots: normalizedHoneypots,
    protocols: normalizedProtocols,
    attackMethodStats: normalizedAttackMethods,
    protocolStats,
    sources: normalizedSources,
    sourceStats,
    events: normalizedEvents,
    serverStats,
    trend,
    historyTrend: normalizeHistoryTrend(historyTrend),
    stats: computedStats,
    ingestStatus: normalizeIngestStatus(ingestStatus, normalizedHoneypots, mode),
    runtimeHealth: normalizeRuntimeHealth(runtimeHealth),
  };
}

function normalizeRuntimeHealth(input) {
  if (!input || typeof input !== "object") {
    return {
      available: false,
      generatedAt: "",
      generatedAtLocal: "",
      summary: {
        status: "unknown",
        label: "未探测",
        detail: "后端健康探针未返回",
        okCount: 0,
        warnCount: 0,
        errorCount: 0,
        total: 0,
      },
      services: [],
    };
  }
  const services = Array.isArray(input.services)
    ? input.services.map((service) => ({
        key: service.key || service.name || "unknown",
        label: service.label || service.key || "unknown",
        host: service.host || "",
        status: normalizeRuntimeStatus(service.status),
        labelStatus: service.labelStatus || statusToRuntimeLabel(service.status),
        detail: service.detail || "",
        checkedAt: service.checkedAt || "",
        elapsedMs: Number(service.elapsedMs ?? 0),
        checks: Array.isArray(service.checks) ? service.checks : [],
      }))
    : [];
  const summaryStatus = normalizeRuntimeStatus(input.summary?.status);
  return {
    available: true,
    generatedAt: input.generatedAt || "",
    generatedAtLocal: input.generatedAtLocal || "",
    summary: {
      status: summaryStatus,
      label: input.summary?.label || statusToRuntimeLabel(summaryStatus),
      detail: input.summary?.detail || services.map((service) => `${service.label} ${service.labelStatus}`).join("；"),
      okCount: Number(input.summary?.okCount ?? services.filter((service) => service.status === "ok").length),
      warnCount: Number(input.summary?.warnCount ?? services.filter((service) => service.status === "warn").length),
      errorCount: Number(input.summary?.errorCount ?? services.filter((service) => service.status === "error").length),
      total: Number(input.summary?.total ?? services.length),
    },
    services,
  };
}

function normalizeRuntimeStatus(status) {
  const value = String(status || "unknown").toLowerCase();
  if (["ok", "normal", "healthy", "connected", "active"].includes(value)) return "ok";
  if (["warn", "warning", "timeout", "degraded", "attention"].includes(value)) return "warn";
  if (["error", "failed", "down", "offline", "unavailable"].includes(value)) return "error";
  return "unknown";
}

function statusToRuntimeLabel(status) {
  const normalized = normalizeRuntimeStatus(status);
  if (normalized === "ok") return "正常";
  if (normalized === "warn") return "关注";
  if (normalized === "error") return "异常";
  return "未探测";
}

function normalizeHistoryTrend(input) {
  if (!input || typeof input !== "object") {
    return { availableDates: [], daily: [], hourly: [], methodNames: {}, timezone: BEIJING_TIME_ZONE };
  }
  const hourly = Array.isArray(input.hourly)
    ? input.hourly.map((bucket) => ({
        date: bucket.date || "",
        hour: Number(bucket.hour ?? 0),
        label: bucket.label || `${String(Number(bucket.hour ?? 0)).padStart(2, "0")}:00`,
        bucketStart: bucket.bucketStart || bucket.bucket_start || "",
        total: Number(bucket.total ?? bucket.count ?? 0),
        high: Number(bucket.high ?? bucket.highRisk ?? bucket.high_risk ?? 0),
        sourceIpCount: Number(bucket.sourceIpCount ?? bucket.source_ip_count ?? 0),
        methodCounts: normalizeCountMap(bucket.methodCounts || bucket.method_counts),
        protocolCounts: normalizeCountMap(bucket.protocolCounts || bucket.protocol_counts),
        methodHighCounts: normalizeCountMap(bucket.methodHighCounts || bucket.method_high_counts),
        protocolHighCounts: normalizeCountMap(bucket.protocolHighCounts || bucket.protocol_high_counts),
        topMethodKey: bucket.topMethodKey || bucket.top_method_key || "",
      })).filter((bucket) => bucket.date && Number.isFinite(bucket.hour))
    : [];
  const daily = Array.isArray(input.daily)
    ? input.daily.map((bucket) => ({
        date: bucket.date || "",
        total: Number(bucket.total ?? bucket.count ?? 0),
        high: Number(bucket.high ?? bucket.highRisk ?? bucket.high_risk ?? 0),
        sourceIpCount: Number(bucket.sourceIpCount ?? bucket.source_ip_count ?? 0),
        methodCounts: normalizeCountMap(bucket.methodCounts || bucket.method_counts),
        protocolCounts: normalizeCountMap(bucket.protocolCounts || bucket.protocol_counts),
      })).filter((bucket) => bucket.date)
    : [];
  const availableDates = Array.isArray(input.availableDates)
    ? input.availableDates.filter(Boolean)
    : [...new Set([...daily.map((bucket) => bucket.date), ...hourly.map((bucket) => bucket.date)])];

  return {
    timezone: input.timezone || BEIJING_TIME_ZONE,
    availableDates: [...availableDates].sort().reverse(),
    daily,
    hourly,
    methodNames: input.methodNames && typeof input.methodNames === "object" ? input.methodNames : {},
  };
}

function normalizeCountMap(input) {
  if (!input || typeof input !== "object") return {};
  return Object.fromEntries(
    Object.entries(input)
      .map(([key, value]) => [key, Number(value ?? 0)])
      .filter(([key, value]) => key && Number.isFinite(value) && value > 0)
  );
}

function normalizeAttackMethods(input) {
  if (!Array.isArray(input)) return [];
  return input.map((item) => ({
    key: item.key || item.attack_method_key || item.attackMethodKey || item.name || "unknown",
    name: item.name || item.attack_method || item.attackMethod || item.key || "未知攻击方式",
    tactic: item.tactic || item.attack_tactic || "unknown",
    total: Number(item.total ?? item.count ?? item.event_count ?? 0),
    sourceCount: Number(item.sourceCount ?? item.sourceIpCount ?? item.source_ip_count ?? 0),
    protocolCount: Number(item.protocolCount ?? item.protocol_count ?? 0),
    protocols: Array.isArray(item.protocols) ? item.protocols : String(item.protocols || "").split("|").filter(Boolean),
    severity: normalizeSeverity(item.severity, item.protocol),
    description: item.description || "",
    examples: Array.isArray(item.examples) ? item.examples : [],
  })).sort((left, right) => right.total - left.total || right.sourceCount - left.sourceCount);
}

function buildEndpointStatuses(mode, connectedEndpoints, bundledEndpoints) {
  const connected = new Set(connectedEndpoints);
  const bundled = new Set(bundledEndpoints);
  return endpointContracts.map((endpoint) => {
    let status = "reserved";
    if (mode === "api" && connected.has(endpoint.key)) status = "connected";
    else if (mode === "api" && bundled.has(endpoint.key)) status = "bundled";
    return { ...endpoint, status };
  });
}

function normalizeHoneypots(input) {
  const items = Array.isArray(input) && input.length ? input : KNOWN_HONEYPOT_CONFIG;
  return items.map((item, index) => {
    const ip = normalizeHoneypotId(item.ip || item.publicIp || item.public_ip || item.dst_ip || item.server_id || item.id || item.name);
    return {
      id: ip || `honeypot-${index + 1}`,
      name: ip || item.name || item.server_id || `采集节点 ${index + 1}`,
      label: item.label || item.type || item.honeypot_type || "Honeypot",
      ip: ip || "unknown",
      city: item.city || "unknown",
      country: item.country || "unknown",
      coordinates: normalizeCoordinates(item.coordinates, item.longitude, item.latitude, KNOWN_HONEYPOT_CONFIG[index]?.coordinates || [0, 0]),
      color: item.color || DEFAULT_NODE_COLORS[index % DEFAULT_NODE_COLORS.length],
      protocols: item.protocols || [],
      collector: item.collector || item.sshHost || item.ssh_host || "configured",
      status: item.status || "unknown",
      totalEvents: Number(item.totalEvents ?? item.total_events ?? item.event_count ?? item.total ?? 0),
      externalIpCount: Number(item.externalIpCount ?? item.external_ip_count ?? item.unique_ip_count ?? 0),
    };
  });
}

function normalizeProtocols(input) {
  const items = Array.isArray(input) && input.length ? input : [];
  const byKey = new Map();
  items.forEach((item, index) => {
    const key = normalizeProtocolKey(item.key || item.protocol || item.name || `P${index}`);
    const current = byKey.get(key);
    const next = {
      key,
      name: protocolDisplayName(key, item.name || item.protocolName || item.protocol_name),
      count: Number(item.count ?? item.total ?? item.event_count ?? 0),
      delta: Number(item.delta ?? item.change ?? 0),
      severity: normalizeSeverity(item.severity, key),
      color: item.color || DEFAULT_NODE_COLORS[index % DEFAULT_NODE_COLORS.length],
      description: item.description || "来自后端协议聚合结果",
    };
    if (current) {
      current.count += next.count;
      current.delta = Math.max(current.delta, next.delta);
      current.severity = maxSeverity(current.severity, next.severity);
      return;
    }
    byKey.set(key, next);
  });
  return [...byKey.values()].sort((a, b) => b.count - a.count);
}

function normalizeSources(input) {
  const items = Array.isArray(input) && input.length ? input : [];
  return items.map((item, index) => {
    const protocols = Array.isArray(item.protocols)
      ? item.protocols.map(normalizeProtocolKey)
      : String(item.protocols || "")
          .split(",")
          .map((value) => normalizeProtocolKey(value.trim()))
          .filter((value) => value && value !== "UNKNOWN");
    return {
      srcIp: item.srcIp || item.src_ip || item.source_ip || item.ip || "unknown",
      country: item.country || "unknown",
      region: item.region || "unknown",
      city: item.city || "unknown",
      isp: item.isp || "unknown",
      asn: item.asn || "unknown",
      coordinates: normalizeCoordinates(item.coordinates, item.longitude, item.latitude, [0, 0]),
      total: Number(item.total ?? item.event_count ?? item.events ?? 0),
      highEvents: Number(item.highEvents ?? item.high_events ?? item.high_risk ?? 0),
      riskScore: Number(item.riskScore ?? item.risk_score ?? 0),
      protocols,
    };
  });
}

function normalizeEvents(input, context) {
  const items = Array.isArray(input) && input.length ? input : [];
  return items.map((item, index) => normalizeEvent(item, context, index));
}

function normalizeEvent(item, context, index) {
  const srcIp = item.srcIp || item.src_ip || item.source_ip || item.ip || "unknown";
  const source = context.sources.find((candidate) => candidate.srcIp === srcIp) || {};
  const protocolKey = normalizeProtocolKey(item.protocol || item.protocolName || item.protocol_name || item.dst_port);
  const protocol = context.protocols.find((candidate) => candidate.key === protocolKey) || context.protocols[0] || {};
  const honeypot = findHoneypot(item, context.honeypots, index);
  const command = item.command || item.input || "";
  const payload = item.payload || item.request || item.message || "";
  const raw = item.raw || item.raw_payload || "";
  const eventTime = normalizeEventTime(item, payload, raw);
  const timestamp = eventTime.timestamp;
  const eventTimeLocal = Number.isFinite(timestamp) ? formatBeijingTime(timestamp) : "";
  const eventTimeUtc = Number.isFinite(timestamp) ? new Date(timestamp).toISOString() : "";
  const srcPort = item.srcPort || item.src_port || item.source_port || payloadField(raw || payload, ["src_port", "srcPort"]);
  const detail = item.detail || command || summarizePayload(payload) || summarizePayload(raw) || "connection attempt";
  const honeypotIp = normalizeHoneypotId(item.honeypotIp || item.honeypot_ip || item.server_id || honeypot.ip || item.honeypot) || honeypot.ip;
  const destinationIp = item.destinationIp || item.destination_ip || item.dst_ip || item.target_ip || "";

  return {
    id: item.id || `${timestamp}-${index}-${srcIp}-${protocolKey}`,
    timestamp,
    eventTsMs: timestamp,
    eventTimeOriginal: eventTime.original,
    eventTimeLocal,
    eventTimeUtc,
    eventTimeSource: eventTime.source,
    timeNormalized: !eventTime.fallback,
    srcIp,
    srcPort,
    country: item.country || source.country || "unknown",
    region: item.region || source.region || "unknown",
    city: item.city || source.city || "unknown",
    isp: item.isp || source.isp || "unknown",
    asn: item.asn || source.asn || "unknown",
    sourceCoordinates: deriveSourceCoordinates(item, source, context.sources),
    protocol: protocolKey,
    protocolName: item.protocolName || item.protocol_name || protocol.name || protocolKey,
    eventType: item.eventType || item.event_type || item.eventid || "connection.open",
    severity: normalizeSeverity(item.severity || protocol.severity, protocolKey, item.eventType || item.event_type || item.eventid),
    username: item.username || item.user || "-",
    password: item.password || "",
    command,
    payload,
    raw,
    dstPort: item.dstPort || item.dst_port || item.dest_port || item.port || "",
    destinationIp,
    detail,
    honeypot: normalizeHoneypotId(item.honeypot || item.server_id || honeypot.name) || honeypot.name,
    honeypotIp,
    honeypotLabel: item.honeypotLabel || honeypot.label,
    targetCoordinates: honeypot.coordinates,
    targetColor: honeypot.color,
    protocolColor: protocol.color || "#1dd6ff",
  };
}

function deriveSourceCoordinates(item, exactSource, sources) {
  const direct = normalizeCoordinates(
    item.sourceCoordinates || item.source_coordinates || item.coordinates,
    item.longitude || item.src_lon,
    item.latitude || item.src_lat,
    [0, 0],
  );
  if (hasUsableCoordinates(direct)) return direct;
  if (hasUsableCoordinates(exactSource.coordinates)) return exactSource.coordinates;

  const country = item.country || exactSource.country;
  const region = item.region || exactSource.region;
  const city = item.city || exactSource.city;
  const cityMatch = sources.find(
    (candidate) =>
      hasUsableCoordinates(candidate.coordinates) &&
      sameText(candidate.country, country) &&
      sameText(candidate.region, region) &&
      sameText(candidate.city, city),
  );
  if (cityMatch) return cityMatch.coordinates;

  const regionMatch = sources.find(
    (candidate) =>
      hasUsableCoordinates(candidate.coordinates) &&
      sameText(candidate.country, country) &&
      sameText(candidate.region, region),
  );
  if (regionMatch) return regionMatch.coordinates;

  return LOCATION_COORDINATES.get(locationKey(country, region, city)) || [0, 0];
}

function summaryFieldRank(key) {
  const index = SUMMARY_FIELD_PRIORITY.indexOf(key);
  return index === -1 ? SUMMARY_FIELD_PRIORITY.length + 1 : index;
}

function summaryFieldValue(key, value) {
  if (value === undefined || value === null || value === "") return "";
  const text = typeof value === "object" ? JSON.stringify(value) : String(value);
  if (!text.trim()) return "";
  if (key === "VNC Password" && /not in the common list/i.test(text)) {
    return "未命中常见口令字典";
  }
  return text;
}

function flattenedPayloadEntries(parsed) {
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return [];
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
    .sort((left, right) => summaryFieldRank(left.key) - summaryFieldRank(right.key) || left.index - right.index);
}

function payloadField(value, keys) {
  if (value === undefined || value === null || value === "") return "";
  try {
    const parsed = typeof value === "string" ? JSON.parse(value) : value;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return "";
    const entries = flattenedPayloadEntries(parsed);
    const match = entries.find(({ key }) => keys.includes(key));
    return match ? summaryFieldValue(match.key, match.nestedValue) : "";
  } catch {
    return "";
  }
}

function summarizePayload(value, maxLength = 180) {
  if (value === undefined || value === null || value === "") return "";
  const text = String(value);
  try {
    const parsed = JSON.parse(text);
    if (parsed && typeof parsed === "object") {
      const readable = flattenedPayloadEntries(parsed)
        .filter(({ key, nestedValue }) => summaryFieldValue(key, nestedValue))
        .slice(0, 5)
        .map(({ key, nestedValue }) => `${SUMMARY_FIELD_LABELS[key] || key}: ${summaryFieldValue(key, nestedValue)}`)
        .join("; ");
      return readable.length > maxLength ? `${readable.slice(0, maxLength - 1)}…` : readable;
    }
  } catch {
    // Plain protocol payloads are expected here.
  }
  return text.length > maxLength ? `${text.slice(0, maxLength - 1)}…` : text;
}

function findHoneypot(item, honeypots, index) {
  const publicTarget = normalizeHoneypotId(item.honeypotIp || item.honeypot_ip || item.publicIp || item.public_ip || item.server_id || item.honeypot);
  const internalTarget = normalizeHoneypotId(item.target_ip || item.dst_ip);
  const exactPublicMatch = honeypots.find(
    (honeypot) => honeypot.ip === publicTarget || honeypot.id === publicTarget || honeypot.name === publicTarget,
  );
  if (exactPublicMatch) return exactPublicMatch;

  const exactInternalMatch = honeypots.find(
    (honeypot) => honeypot.ip === internalTarget || honeypot.id === internalTarget || honeypot.name === internalTarget,
  );
  return exactInternalMatch || honeypots[index % honeypots.length] || KNOWN_HONEYPOT_CONFIG[0];
}

function buildSourceStats(sources, events) {
  const counts = new Map(
    sources.map((source) => [
      source.srcIp,
      { ...source, currentEvents: 0, highCurrentEvents: 0, protocols: new Set(source.protocols || []) },
    ]),
  );
  events.forEach((event) => {
    if (!counts.has(event.srcIp)) {
      counts.set(event.srcIp, {
        srcIp: event.srcIp,
        country: event.country,
        region: event.region,
        city: event.city,
        isp: event.isp,
        asn: event.asn,
        coordinates: event.sourceCoordinates,
        total: 0,
        currentEvents: 0,
        highCurrentEvents: 0,
        protocols: new Set(),
      });
    }
    const current = counts.get(event.srcIp);
    if (!hasUsableCoordinates(current.coordinates) && hasUsableCoordinates(event.sourceCoordinates)) {
      current.coordinates = event.sourceCoordinates;
    }
    current.currentEvents += 1;
    if (event.severity === "high") current.highCurrentEvents += 1;
    current.protocols.add(event.protocol);
  });
  return [...counts.values()]
    .map((source) => {
      const protocolCount = source.protocols.size;
      const eventTotal = source.total > 0 ? source.total : source.currentEvents;
      const highEvents = source.highEvents || source.highCurrentEvents;
      const riskScore = source.riskScore || eventTotal + highEvents * 500 + protocolCount * 120;
      return {
        ...source,
        total: eventTotal,
        events: source.currentEvents,
        highEvents,
        protocolCount,
        protocols: [...source.protocols],
        eventTotal,
        riskScore,
        score: riskScore,
      };
    })
    .sort((a, b) => b.eventTotal - a.eventTotal || b.riskScore - a.riskScore);
}

function buildProtocolStats(protocols, events, stats) {
  const counts = new Map(protocols.map((protocol) => [protocol.key, 0]));
  events.forEach((event) => counts.set(event.protocol, (counts.get(event.protocol) || 0) + 1));
  const apiProtocolStats = stats?.protocols || stats?.protocolStats || [];
  const apiTotals = new Map();
  if (Array.isArray(apiProtocolStats)) {
    apiProtocolStats.forEach((item) => {
      const key = normalizeProtocolKey(item.key || item.protocol || item.name);
      const value = Number(item.total ?? item.count ?? item.event_count ?? 0);
      apiTotals.set(key, (apiTotals.get(key) || 0) + value);
    });
  }

  return protocols.map((protocol) => {
    const live = counts.get(protocol.key) || 0;
    return {
      ...protocol,
      live,
      total: Number(apiTotals.get(protocol.key) ?? (protocol.count || live)),
      delta: Number(protocol.delta),
    };
  });
}

function buildServerStats(honeypots, events, ingestStatus) {
  const ingestItems = Array.isArray(ingestStatus) ? ingestStatus : [];
  return honeypots.map((honeypot) => {
    const relatedEvents = events.filter((event) => event.honeypotIp === honeypot.ip || event.honeypot === honeypot.name);
    const protocols = new Set(relatedEvents.map((event) => event.protocol));
    const externalIps = new Set(relatedEvents.map((event) => event.srcIp));
    const ingest = ingestItems.find((item) => {
      const ingestId = normalizeHoneypotId(item.id || item.server_id || item.name);
      return ingestId === honeypot.id || ingestId === honeypot.ip || ingestId === honeypot.name;
    });
    const totalEvents = honeypot.totalEvents || relatedEvents.length;
    const currentEvents = relatedEvents.length;
    return {
      ...honeypot,
      events: totalEvents,
      totalEvents,
      currentEvents,
      externalIps: honeypot.externalIpCount || externalIps.size,
      currentExternalIps: externalIps.size,
      protocols: protocols.size ? [...protocols] : honeypot.protocols,
      status: ingest?.status || honeypot.status || "unknown",
      lastSeen: ingest?.lastSeen || ingest?.last_seen || honeypot.lastSeen || honeypot.last_seen || "",
      hdfsPartition: ingest?.hdfsPartition || ingest?.hdfs_partition || honeypot.hdfsPartition || "",
    };
  });
}

function buildTrend(events) {
  const buckets = new Map();
  const eventTimes = events
    .map((event) => new Date(event.timestamp).getTime())
    .filter((timestamp) => Number.isFinite(timestamp));
  const anchorTime = eventTimes.length ? Math.max(...eventTimes) : Date.now();
  const currentHour = new Date(anchorTime);
  currentHour.setMinutes(0, 0, 0);

  for (let i = 7; i >= 0; i -= 1) {
    const start = new Date(currentHour.getTime() - i * 60 * 60 * 1000);
    buckets.set(start.getTime(), {
      label: start.toLocaleTimeString("zh-CN", { hour: "2-digit", minute: "2-digit", hour12: false }),
      total: 0,
      high: 0,
    });
  }

  events.forEach((event) => {
    const bucketHour = new Date(event.timestamp);
    if (Number.isNaN(bucketHour.getTime())) return;
    bucketHour.setMinutes(0, 0, 0);
    const bucket = buckets.get(bucketHour.getTime());
    if (!bucket) return;
    bucket.total += 1;
    if (event.severity === "high") bucket.high += 1;
  });

  return [...buckets.values()];
}

function optionalNumber(...values) {
  for (const value of values) {
    if (value === undefined || value === null || value === "") continue;
    const number = Number(value);
    if (Number.isFinite(number)) return number;
  }
  return null;
}

function commandEventCount(events) {
  return events.filter((event) =>
    event.command ||
    /(command|input|shell|exec|download)/i.test(`${event.eventType || ""} ${event.detail || ""}`),
  ).length;
}

function buildStats(stats, protocolStats, sourceStats, events) {
  const protocolTotal = protocolStats.reduce((sum, item) => sum + Number(item.total || 0), 0);
  const totalEvents = optionalNumber(stats?.totalEvents, stats?.total_events, protocolTotal || events.length) ?? 0;
  const sessionCount = optionalNumber(stats?.sessionCount, stats?.sessions, stats?.session_count);
  const externalIps = optionalNumber(stats?.externalIps, stats?.external_ip_count, sourceStats.length) ?? 0;
  const commandCount = optionalNumber(stats?.commandCount, stats?.commands, stats?.command_count, commandEventCount(events));
  const highRisk = optionalNumber(stats?.highRisk, stats?.high_risk, events.filter((event) => event.severity === "high").length) ?? 0;

  return {
    totalEvents,
    sessionCount,
    externalIps,
    commandCount,
    highRisk,
    totalDelta: optionalNumber(stats?.totalDelta, stats?.total_delta),
    sessionDelta: optionalNumber(stats?.sessionDelta, stats?.session_delta),
    ipDelta: optionalNumber(stats?.ipDelta, stats?.ip_delta),
    commandDelta: optionalNumber(stats?.commandDelta, stats?.command_delta),
    liveEventsSinceStart: Number(stats?.liveEventsSinceStart ?? 0),
    liveWindowEvents: Number(stats?.liveWindowEvents ?? 0),
    liveWindowSeconds: Number(stats?.liveWindowSeconds ?? 60),
    liveRetainedEvents: Number(stats?.liveRetainedEvents ?? 0),
    livePublishedEvents: Number(stats?.livePublishedEvents ?? 0),
    liveEventsPerSecond: Number(stats?.liveEventsPerSecond ?? 0),
    liveLastEventDelaySeconds: Number(stats?.liveLastEventDelaySeconds ?? 0),
    liveConnected: Boolean(stats?.liveConnected),
  };
}

function normalizeIngestStatus(input, honeypots, mode) {
  if (Array.isArray(input) && input.length) {
    return input.map((item, index) => {
      const id = normalizeHoneypotId(item.id || item.server_id || item.name || honeypots[index]?.id);
      return {
        id: id || `ingest-${index}`,
        name: id || honeypots[index]?.name || `采集节点 ${index + 1}`,
        status: item.status || "unknown",
        parser: item.parser || item.type || honeypots[index]?.label || "unknown",
        lastSeen: item.lastSeen || item.last_seen || "",
        hdfsPartition: item.hdfsPartition || item.hdfs_partition || "",
        mode,
      };
    });
  }

  return [];
}

function normalizeProtocolKey(value) {
  const raw = String(value || "UNKNOWN").trim().toLowerCase();
  if (!raw || raw === "unknown") return "UNKNOWN";
  const portMatch = raw.match(/^(?:(?:tcp|udp|port)[_:\s-]*)?(\d{2,5})$/);
  if (portMatch) {
    const port = Number(portMatch[1]);
    return PORT_PROTOCOLS[port] || `TCP_${port}`;
  }
  if (raw.includes("ssh") || raw.includes("cowrie")) return "SSH";
  if (raw.includes("ftp")) return "FTP";
  if (raw.includes("https")) return "HTTPS_ALT";
  if (raw.includes("http") || raw.includes("web")) return "HTTP";
  if (raw.includes("mysql")) return "MYSQL";
  if (raw.includes("redis")) return "REDIS";
  if (raw.includes("telnet")) return "TELNET";
  if (raw.includes("rdp")) return "RDP";
  if (raw.includes("vnc")) return "VNC";
  if (raw.includes("postgres") || raw.includes("pgsql")) return "POSTGRES";
  if (raw.includes("mssql") || raw.includes("sqlserver")) return "MSSQL";
  if (raw.includes("oracle")) return "ORACLE";
  if (raw.includes("mongo")) return "MONGODB";
  if (raw.includes("memcache")) return "MEMCACHED";
  if (raw.includes("elastic")) return "ELASTICSEARCH";
  if (raw.includes("mqtt")) return "MQTT";
  if (raw.includes("smtp")) return "SMTP";
  if (raw.includes("pop3")) return "POP3";
  if (raw.includes("imap")) return "IMAP";
  if (raw.includes("smb")) return "SMB";
  if (raw.includes("sip")) return "SIP";
  if (raw.includes("ldap")) return "LDAP";
  if (raw.includes("nfs")) return "NFS";
  if (raw.includes("rpc")) return "RPCBIND";
  return raw.toUpperCase();
}

function normalizeHoneypotId(value) {
  const text = String(value || "");
  return HONEYPOT_ALIASES[text] || text;
}

function protocolDisplayName(key, providedName) {
  if (PROTOCOL_METADATA[key]?.name) return PROTOCOL_METADATA[key].name;
  const normalizedProvided = String(providedName || "").trim().toUpperCase();
  if (PROTOCOL_METADATA[normalizedProvided]?.name) return PROTOCOL_METADATA[normalizedProvided].name;
  if (key.startsWith("TCP_")) return `TCP ${key.slice(4)}`;
  return providedName || key;
}

function normalizeSeverity(input, protocolKey, eventType = "") {
  const current = String(input || "").toLowerCase();
  if (SEVERITY_WEIGHT[current]) return current;

  let derived = severityForProtocol(protocolKey);
  const normalizedType = String(eventType || "").toLowerCase();
  if (/(auth|login|password|credential|command|input|download)/.test(normalizedType)) {
    derived = maxSeverity(derived, ["SSH", "TELNET", "VNC", "RDP"].includes(protocolKey) ? "high" : "medium");
  }
  return derived;
}

function maxSeverity(left, right) {
  return SEVERITY_WEIGHT[left] >= SEVERITY_WEIGHT[right] ? left : right;
}

function severityForProtocol(value) {
  const key = normalizeProtocolKey(value);
  if (PROTOCOL_METADATA[key]?.severity) return PROTOCOL_METADATA[key].severity;
  if (["SSH", "MYSQL", "REDIS", "TELNET", "RDP", "VNC", "POSTGRES", "MSSQL", "ORACLE", "SMB"].includes(key)) return "high";
  if (["FTP", "HTTP", "HTTP_ALT", "HTTPS_ALT", "SMTP", "POP3", "IMAP"].includes(key)) return "medium";
  return "low";
}

function normalizeCoordinates(coordinates, longitude, latitude, fallback = [0, 0]) {
  if (Array.isArray(coordinates) && coordinates.length >= 2) return [Number(coordinates[0]), Number(coordinates[1])];
  if (longitude !== undefined && latitude !== undefined) return [Number(longitude), Number(latitude)];
  return fallback || [0, 0];
}

function hasUsableCoordinates(coordinates) {
  if (!Array.isArray(coordinates) || coordinates.length < 2) return false;
  const [longitude, latitude] = coordinates.map(Number);
  if (!Number.isFinite(longitude) || !Number.isFinite(latitude)) return false;
  return Math.abs(longitude) > 0.0001 || Math.abs(latitude) > 0.0001;
}

function sameText(left, right) {
  const normalizedLeft = String(left || "").trim().toLowerCase();
  const normalizedRight = String(right || "").trim().toLowerCase();
  return Boolean(normalizedLeft && normalizedRight && normalizedLeft === normalizedRight);
}

function locationKey(country, region, city) {
  return [country, region, city].map((value) => String(value || "").trim().toLowerCase()).join("|");
}

function normalizeTimestamp(value) {
  const parsed = parseTimestampValue(value);
  return Number.isFinite(parsed) ? parsed : Number.NaN;
}

function normalizeEventTime(item, payload, raw) {
  const candidates = [
    ["timestamp", item.timestamp, "auto"],
    ["event_time_utc", item.event_time_utc, "utc"],
    ["utc_time", item.utc_time, "utc"],
    ["@timestamp", item["@timestamp"], "utc"],
    ["event_time", item.event_time || item.eventTime, "beijing"],
    ["event_time_local", item.event_time_local || item.eventTimeLocal, "beijing"],
    ["local_time_adjusted", item.local_time_adjusted, "beijing"],
    ["local_time", item.local_time, "beijing"],
    ["time", item.time, "beijing"],
    ["datetime", item.datetime, "beijing"],
    ["created_at", item.created_at, "beijing"],
    ["log_time", item.log_time, "beijing"],
    ["payload.utc_time", payloadField(payload, ["utc_time", "utcTime", "@timestamp"]), "utc"],
    ["raw.utc_time", payloadField(raw, ["utc_time", "utcTime", "@timestamp"]), "utc"],
    ["payload.local_time_adjusted", payloadField(payload, ["local_time_adjusted", "localTimeAdjusted"]), "beijing"],
    ["raw.local_time_adjusted", payloadField(raw, ["local_time_adjusted", "localTimeAdjusted"]), "beijing"],
    ["payload.local_time", payloadField(payload, ["local_time", "localTime", "time", "datetime"]), "beijing"],
    ["raw.local_time", payloadField(raw, ["local_time", "localTime", "time", "datetime"]), "beijing"],
  ];

  for (const [source, value, zoneHint] of candidates) {
    const timestamp = parseTimestampValue(value, zoneHint);
    if (Number.isFinite(timestamp)) {
      return {
        timestamp,
        source,
        original: timeValueToText(value),
        fallback: false,
      };
    }
  }

  return {
    timestamp: Number.NaN,
    source: "missing",
    original: "",
    fallback: true,
  };
}

function parseTimestampValue(value, zoneHint = "beijing") {
  if (value === undefined || value === null || value === "") return Number.NaN;
  if (value instanceof Date) {
    const timestamp = value.getTime();
    return Number.isFinite(timestamp) ? timestamp : Number.NaN;
  }
  if (typeof value === "number") return normalizeNumericTimestamp(value);

  const text = String(value).trim();
  if (!text) return Number.NaN;
  if (/^\d+(?:\.\d+)?$/.test(text)) return normalizeNumericTimestamp(Number(text));

  const isoCandidate = text.replace(" ", "T");
  if (hasExplicitTimezone(isoCandidate)) {
    const parsed = Date.parse(isoCandidate);
    if (!Number.isNaN(parsed)) return parsed;
  }

  const offsetMinutes = zoneHint === "utc" ? 0 : BEIJING_OFFSET_MINUTES;
  const structured = parseStructuredTimestamp(text, offsetMinutes);
  if (Number.isFinite(structured)) return structured;

  const parsed = Date.parse(text);
  return Number.isNaN(parsed) ? Number.NaN : parsed;
}

function normalizeNumericTimestamp(value) {
  if (!Number.isFinite(value)) return Number.NaN;
  return Math.abs(value) < 100000000000 ? value * 1000 : value;
}

function hasExplicitTimezone(value) {
  return /(?:z|[+-]\d{2}:?\d{2})$/i.test(value);
}

function parseStructuredTimestamp(value, offsetMinutes) {
  const match = String(value).trim().match(
    /^(\d{4})[-/](\d{1,2})[-/](\d{1,2})(?:[ T](\d{1,2}):(\d{2})(?::(\d{2})(?:\.(\d{1,3}))?)?)?$/,
  );
  if (!match) return Number.NaN;
  const [, year, month, day, hour = "0", minute = "0", second = "0", millisecond = "0"] = match;
  const paddedMs = String(millisecond).padEnd(3, "0").slice(0, 3);
  return Date.UTC(
    Number(year),
    Number(month) - 1,
    Number(day),
    Number(hour),
    Number(minute),
    Number(second),
    Number(paddedMs),
  ) - offsetMinutes * 60 * 1000;
}

function formatBeijingTime(timestamp) {
  if (!Number.isFinite(timestamp)) return "";
  return new Date(timestamp).toLocaleString("zh-CN", {
    timeZone: BEIJING_TIME_ZONE,
    hour12: false,
  });
}

function formatBeijingDate(timestamp) {
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) return new Date().toISOString().slice(0, 10);
  return new Intl.DateTimeFormat("en-CA", {
    timeZone: BEIJING_TIME_ZONE,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).format(date);
}

function timeValueToText(value) {
  if (value === undefined || value === null) return "";
  if (value instanceof Date) return value.toISOString();
  return typeof value === "object" ? JSON.stringify(value) : String(value);
}

function normalizeError(error) {
  if (!error) return "unknown";
  if (error.name === "AbortError") return "timeout";
  return error.message || String(error);
}
