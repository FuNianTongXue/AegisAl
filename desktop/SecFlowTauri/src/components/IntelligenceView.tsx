import { Activity, AlertTriangle, Bug, CalendarDays, RefreshCcw, ShieldAlert, ShieldCheck } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { api } from "../lib/api";
import type { DashboardSnapshot } from "../types";

export function IntelligenceView() {
  const [data, setData] = useState<DashboardSnapshot>();
  const [loading, setLoading] = useState(true);
  const load = async () => { setLoading(true); try { setData(await api.dashboard()); } finally { setLoading(false); } };
  useEffect(() => { void load(); }, []);
  const stats = data?.stats || {};
  const total = Number(stats.total || data?.records?.length || 0);
  const severities = [
    { label: "严重", value: Number(stats.critical || 0), color: "#d14343" },
    { label: "高危", value: Number(stats.high || 0), color: "#e4762c" },
    { label: "中危", value: Number(stats.medium || 0), color: "#d9a124" },
    { label: "低危", value: Number(stats.low || 0), color: "#3c9b73" },
  ];
  const donut = useMemo(() => buildConic(severities, total), [total, stats.critical, stats.high, stats.medium, stats.low]);
  const trend = useMemo(() => normalizeTrend(data?.trend), [data?.trend]);
  const catalogStatus = data?.catalog_status || "pending";

  return (
    <div className="page-scroll intelligence-view">
      <div className="page-heading"><div><h1>漏洞情报</h1><p>公开漏洞情报统计，不代表项目扫描结果。</p></div><button className="secondary" onClick={() => void load()} disabled={loading}><RefreshCcw size={14} className={loading ? "spin" : ""} />刷新情报</button></div>
      {catalogStatus !== "ready" ? <div className={`catalog-progress ${catalogStatus}`}><span><DatabaseStatus status={catalogStatus} /><strong>{catalogStatus === "retrying" ? "完整漏洞目录等待断点续传" : catalogStatus === "building" ? "正在构建完整漏洞目录" : "正在准备完整漏洞目录"}</strong></span><small>{data?.catalog_error || `已收录 ${(data?.catalog_count || total).toLocaleString("zh-CN")} 条，基线进度 ${data?.catalog_progress || 0}%`}</small>{catalogStatus === "building" ? <i><b style={{ width: `${data?.catalog_progress || 0}%` }} /></i> : null}</div> : null}
      <div className="stat-grid">
        <Stat icon={<Bug />} label="漏洞总量" value={total} change="当前筛选范围" />
        <Stat icon={<ShieldAlert />} label="严重与高危" value={Number(stats.critical || 0) + Number(stats.high || 0)} change={`${percent(Number(stats.critical || 0) + Number(stats.high || 0), total)}%`} tone="danger" />
        <Stat icon={<AlertTriangle />} label="CISA KEV" value={Number(stats.kev || 0)} change="已知在野利用" tone="warning" />
        <Stat icon={<ShieldCheck />} label="已验证利用" value={Number(stats.poc || 0)} change="具有公开 PoC" tone="success" />
      </div>
      <div className="dashboard-grid">
        <section className="dashboard-section severity-overview">
          <header><div><h2>严重度分布</h2><p>按 CVSS 与情报源评级聚合</p></div><Activity size={17} /></header>
          <div className="donut-layout"><div className="donut-chart" style={{ background: donut }}><span><strong>{total}</strong><small>漏洞</small></span></div><div className="legend-list">{severities.map((item) => <div key={item.label}><span style={{ background: item.color }} /><strong>{item.label}</strong><small>{item.value} · {percent(item.value, total)}%</small></div>)}</div></div>
        </section>
        <section className="dashboard-section activity-chart">
          <header><div><h2>近期情报更新趋势</h2><p>近 7 天按更新时间统计情报变更</p></div><CalendarDays size={17} /></header>
          <TrendChart items={trend} />
        </section>
      </div>
      <section className="record-band">
        <header><div><h2>优先关注</h2><p>最近更新的高风险漏洞情报</p></div></header>
        <div className="record-table"><div className="table-head"><span>漏洞</span><span>严重度</span><span>来源</span><span>更新时间</span></div>{(data?.records || []).slice(0, 12).map((record) => <div className="table-row" key={record.id}><span><strong>{record.id}</strong><small>{record.title}</small></span><span><b className={`severity ${record.severity?.toLowerCase() || "unknown"}`}>{severityLabel(record.severity)}</b></span><span>{record.source || "公开情报"}</span><span>{formatDate(record.updated_at || record.published_at)}</span></div>)}</div>
      </section>
    </div>
  );
}

function DatabaseStatus({ status }: { status: string }) {
  return status === "retrying" ? <AlertTriangle size={16} /> : <Activity size={16} className={status === "building" ? "spin" : ""} />;
}

function TrendChart({ items }: { items: Array<{ date: string; count: number; ratio: number }> }) {
  if (!items.length) return <div className="trend-empty">暂无近期情报更新数据</div>;
  const width = 700;
  const height = 190;
  const baseline = 158;
  const top = 18;
  const points = items.map((item, index) => ({
    ...item,
    x: items.length === 1 ? width / 2 : (index / (items.length - 1)) * width,
    y: baseline - item.ratio * (baseline - top),
  }));
  const line = points.map((point, index) => `${index ? "L" : "M"}${point.x.toFixed(1)},${point.y.toFixed(1)}`).join(" ");
  const area = `${line} L${points.at(-1)?.x.toFixed(1)},${baseline} L${points[0].x.toFixed(1)},${baseline} Z`;
  return (
    <div className="trend-chart">
      <svg viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" role="img" aria-label="近 7 天情报更新趋势">
        <defs>
          <linearGradient id="intelligenceTrendFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--primary)" stopOpacity="0.28" />
            <stop offset="100%" stopColor="var(--primary)" stopOpacity="0.02" />
          </linearGradient>
        </defs>
        {[top, (top + baseline) / 2, baseline].map((y) => <line key={y} className="trend-grid-line" x1="0" x2={width} y1={y} y2={y} />)}
        <path className="trend-area" d={area} />
        <path className="trend-line" d={line} />
        {points.map((point) => <circle key={point.date} className="trend-point" cx={point.x} cy={point.y} r="3"><title>{point.date}：{point.count}</title></circle>)}
      </svg>
      <div className="trend-labels">{points.map((point, index) => <small key={point.date} className={index % 2 ? "compact-label" : ""}>{point.date.slice(5)}</small>)}</div>
    </div>
  );
}

function Stat({ icon, label, value, change, tone = "neutral" }: { icon: React.ReactNode; label: string; value: number; change: string; tone?: string }) {
  return <div className={`stat-card ${tone}`}><span className="stat-icon">{icon}</span><div><small>{label}</small><strong>{value.toLocaleString("zh-CN")}</strong><p>{change}</p></div></div>;
}

function buildConic(items: Array<{ value: number; color: string }>, total: number) {
  if (!total) return "conic-gradient(#dfe5ed 0 100%)";
  let cursor = 0;
  const stops = items.map((item) => { const start = cursor; cursor += (item.value / total) * 100; return `${item.color} ${start}% ${cursor}%`; });
  if (cursor < 100) stops.push(`#dfe5ed ${cursor}% 100%`);
  return `conic-gradient(${stops.join(",")})`;
}

function normalizeTrend(trend?: Array<{ date: string; count: number }>) {
  const values = trend?.slice(-7) || [];
  const max = Math.max(1, ...values.map((item) => item.count));
  return values.map((item) => ({ ...item, ratio: item.count / max }));
}

const percent = (value: number, total: number) => total ? Math.round((value / total) * 100) : 0;
const severityLabel = (value?: string) => ({ critical: "严重", high: "高危", medium: "中危", low: "低危" }[value?.toLowerCase() || ""] || "待定");
const formatDate = (value?: string) => value ? new Intl.DateTimeFormat("zh-CN", { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false }).format(new Date(value)) : "-";
