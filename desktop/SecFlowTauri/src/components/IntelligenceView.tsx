import { Activity, AlertTriangle, Bug, CalendarDays, RefreshCcw, ShieldAlert, ShieldCheck } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";

import { brandDisplayText } from "../branding";
import { clientLocaleTag, type ClientLocale, useI18n } from "../i18n";
import { api } from "../lib/api";
import type { DashboardSnapshot } from "../types";
import {
  VulnerabilityReadiness,
  vulnerabilityTitle,
} from "./VulnerabilityTranslationStatus";
import { StructuredDataTable } from "./StructuredDataTable";
import type { StructuredDataTableModel } from "./structuredData";
import { BeautifulLoadingState } from "./beautiful-ui/BeautifulUI";

export function IntelligenceView() {
  const { locale, t } = useI18n();
  const [data, setData] = useState<DashboardSnapshot>();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const load = useCallback(async (refresh = false) => {
    setLoading(true);
    setError("");
    try {
      setData(await api.dashboard(locale, refresh));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setLoading(false);
    }
  }, [locale]);
  useEffect(() => { void load(); }, [load]);
  const stats = data?.stats || {};
  const total = Number(stats.total || data?.records?.length || 0);
  const severities = [
    { label: t("严重"), value: Number(stats.critical || 0), color: "#d14343" },
    { label: t("高危"), value: Number(stats.high || 0), color: "#e4762c" },
    { label: t("中危"), value: Number(stats.medium || 0), color: "#d9a124" },
    { label: t("低危"), value: Number(stats.low || 0), color: "#3c9b73" },
  ];
  const donut = useMemo(() => buildConic(severities, total), [total, stats.critical, stats.high, stats.medium, stats.low]);
  const trend = useMemo(() => normalizeTrend(data?.trend), [data?.trend]);
  const priorityTable = useMemo<StructuredDataTableModel>(() => ({
    id: "priority-vulnerabilities",
    caption: t("最近更新的高风险漏洞情报"),
    columns: [
      {
        key: "id",
        label: t("漏洞"),
        kind: "text",
        width: "48%",
        render: (_value, row) => (
          <span className="structured-primary-cell">
            <strong translate="no">{String(row.id || "-")}</strong>
            <small>{String(row.title || t("暂无漏洞标题"))}</small>
          </span>
        ),
      },
      { key: "severity", label: t("严重度"), kind: "status", width: "14%" },
      { key: "source", label: t("来源"), kind: "text", width: "18%" },
      { key: "updated_at", label: t("更新时间"), kind: "date", width: "20%" },
    ],
    rows: (data?.records || []).slice(0, 12).map((record) => ({
      id: record.id,
      title: vulnerabilityTitle(record, locale) || t("暂无漏洞标题"),
      severity: severityLabel(record.severity, t),
      source: brandDisplayText(record.source) || t("公开情报"),
      updated_at: formatDate(record.updated_at || record.published_at, locale),
    })),
  }), [data?.records, locale, t]);

  return (
    <div className="page-scroll intelligence-view">
      <div className="page-heading"><div><h1>{t("漏洞情报")}</h1><p>{t("公开漏洞情报统计，不代表项目扫描结果。")}</p></div><button className="secondary" onClick={() => void load(true)} disabled={loading}><RefreshCcw size={14} className={loading ? "spin" : ""} aria-hidden="true" />{t("刷新情报")}</button></div>
      {error ? <div className="records-load-error" role="alert"><span>{t("漏洞情报加载失败：{error}", { error: brandDisplayText(error) })}</span><button className="secondary" onClick={() => void load(true)}>{t("重新加载")}</button></div> : null}
      {loading && !data ? (
        <BeautifulLoadingState
          className="empty-list-state"
          label={t("正在加载漏洞记录…")}
          detail={t("正在读取本机聚合情报索引")}
          showElapsed
        />
      ) : null}
      {data ? <VulnerabilityReadiness snapshot={data} /> : null}
      {data ? <>
      <div className="stat-grid">
        <Stat icon={<Bug />} label={t("漏洞总量")} value={total} change={t("当前筛选范围")} locale={locale} />
        <Stat icon={<ShieldAlert />} label={t("严重与高危")} value={Number(stats.critical || 0) + Number(stats.high || 0)} change={`${percent(Number(stats.critical || 0) + Number(stats.high || 0), total)}%`} tone="danger" locale={locale} />
        <Stat icon={<AlertTriangle />} label="CISA KEV" value={Number(stats.kev || 0)} change={t("已知在野利用")} tone="warning" locale={locale} />
        <Stat icon={<ShieldCheck />} label={t("已验证利用")} value={Number(stats.poc || 0)} change={t("具有公开 PoC")} tone="success" locale={locale} />
      </div>
      <div className="dashboard-grid">
        <section className="dashboard-section severity-overview">
          <header><div><h2>{t("严重度分布")}</h2><p>{t("按 CVSS 与情报源评级聚合")}</p></div><Activity size={17} aria-hidden="true" /></header>
          <div className="donut-layout"><div className="donut-chart" style={{ background: donut }}><span><strong>{formatNumber(total, locale)}</strong><small>{t("漏洞")}</small></span></div><div className="legend-list">{severities.map((item) => <div key={item.label}><span style={{ background: item.color }} /><strong>{item.label}</strong><small>{formatNumber(item.value, locale)} · {percent(item.value, total)}%</small></div>)}</div></div>
        </section>
        <section className="dashboard-section activity-chart">
          <header><div><h2>{t("近期情报更新趋势")}</h2><p>{t("近 7 天按更新时间统计情报变更")}</p></div><CalendarDays size={17} aria-hidden="true" /></header>
          <TrendChart items={trend} locale={locale} t={t} />
        </section>
      </div>
      <section className="record-band">
        <header><div><h2>{t("优先关注")}</h2><p>{t("最近更新的高风险漏洞情报")}</p></div></header>
        <StructuredDataTable model={priorityTable} emptyLabel={t("暂无漏洞情报")} />
      </section>
      </> : null}
    </div>
  );
}

function TrendChart({ items, locale, t }: { items: Array<{ date: string; count: number; ratio: number }>; locale: ClientLocale; t: (source: string) => string }) {
  if (!items.length) return <div className="trend-empty">{t("暂无近期情报更新数据")}</div>;
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
      <svg viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" role="img" aria-label={t("近 7 天情报更新趋势")}>
        <defs>
          <linearGradient id="intelligenceTrendFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--primary)" stopOpacity="0.28" />
            <stop offset="100%" stopColor="var(--primary)" stopOpacity="0.02" />
          </linearGradient>
        </defs>
        {[top, (top + baseline) / 2, baseline].map((y) => <line key={y} className="trend-grid-line" x1="0" x2={width} y1={y} y2={y} />)}
        <path className="trend-area" d={area} />
        <path className="trend-line" d={line} />
        {points.map((point) => <circle key={point.date} className="trend-point" cx={point.x} cy={point.y} r="3"><title>{formatTrendDate(point.date, locale)}：{formatNumber(point.count, locale)}</title></circle>)}
      </svg>
      <div className="trend-labels">{points.map((point, index) => <small key={point.date} className={index % 2 ? "compact-label" : ""}>{formatTrendDate(point.date, locale)}</small>)}</div>
    </div>
  );
}

function Stat({ icon, label, value, change, locale, tone = "neutral" }: { icon: React.ReactNode; label: string; value: number; change: string; locale: ClientLocale; tone?: string }) {
  return <div className={`stat-card ${tone}`}><span className="stat-icon" aria-hidden="true">{icon}</span><div><small>{label}</small><strong>{formatNumber(value, locale)}</strong><p>{change}</p></div></div>;
}

function buildConic(items: Array<{ value: number; color: string }>, total: number) {
  if (!total) return "conic-gradient(var(--border) 0 100%)";
  let cursor = 0;
  const stops = items.map((item) => { const start = cursor; cursor += (item.value / total) * 100; return `${item.color} ${start}% ${cursor}%`; });
  if (cursor < 100) stops.push(`var(--border) ${cursor}% 100%`);
  return `conic-gradient(${stops.join(",")})`;
}

function normalizeTrend(trend?: Array<{ date: string; count: number }>) {
  const values = trend?.slice(-7) || [];
  const max = Math.max(1, ...values.map((item) => item.count));
  return values.map((item) => ({ ...item, ratio: item.count / max }));
}

const percent = (value: number, total: number) => total ? Math.round((value / total) * 100) : 0;
const severityLabel = (value: string | undefined, t: (source: string) => string) => t({ critical: "严重", high: "高危", medium: "中危", low: "低危" }[value?.toLowerCase() || ""] || "待定");
const formatNumber = (value: number, locale: ClientLocale) => new Intl.NumberFormat(clientLocaleTag(locale)).format(Number(value || 0));
const formatTrendDate = (value: string, locale: ClientLocale) => {
  const parsed = new Date(`${value}T00:00:00Z`);
  if (Number.isNaN(parsed.getTime())) return value;
  return new Intl.DateTimeFormat(clientLocaleTag(locale), { month: "2-digit", day: "2-digit", timeZone: "UTC" }).format(parsed);
};
const formatDate = (value: string | undefined, locale: ClientLocale) => {
  if (!value) return "-";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return "-";
  return new Intl.DateTimeFormat(clientLocaleTag(locale), { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false }).format(parsed);
};
