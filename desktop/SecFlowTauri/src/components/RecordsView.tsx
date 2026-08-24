import { ExternalLink, Filter, Search, ShieldAlert, X } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";

import { brandDisplayText } from "../branding";
import { clientLocaleTag, type ClientLocale, useI18n } from "../i18n";
import { api } from "../lib/api";
import { openExternalUrl } from "../lib/platform";
import type { DashboardSnapshot, VulnerabilityRecord } from "../types";
import {
  VulnerabilityReadiness,
  vulnerabilityDescription,
  vulnerabilitySearchText,
  vulnerabilityTitle,
} from "./VulnerabilityTranslationStatus";
import { BeautifulEmptyState, BeautifulLoadingState } from "./beautiful-ui/BeautifulUI";

export function RecordsView() {
  const { locale, t } = useI18n();
  const [data, setData] = useState<DashboardSnapshot>();
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const [searchRecords, setSearchRecords] = useState<VulnerabilityRecord[]>();
  const [selectedRecord, setSelectedRecord] = useState<VulnerabilityRecord>();
  const [loading, setLoading] = useState(true);
  const [searching, setSearching] = useState(false);
  const [error, setError] = useState("");
  const [searchError, setSearchError] = useState("");
  const [searchRevision, setSearchRevision] = useState(0);
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
  useEffect(() => {
    const cleanQuery = query.trim();
    setSelectedRecord(undefined);
    setSearchError("");
    if (!cleanQuery) {
      setSearchRecords(undefined);
      setSearching(false);
      return;
    }
    if (cleanQuery.length < 3) {
      setSearchRecords([]);
      setSearching(false);
      return;
    }
    let active = true;
    const controller = new AbortController();
    setSearching(true);
    const timer = window.setTimeout(() => {
      void api.vulnerabilities(locale, cleanQuery, controller.signal).then((records) => {
        if (active) setSearchRecords(records);
      }).catch((reason) => {
        if (active) {
          setSearchRecords([]);
          setSearchError(reason instanceof Error ? reason.message : String(reason));
        }
      }).finally(() => {
        if (active) setSearching(false);
      });
    }, 280);
    return () => {
      active = false;
      controller.abort();
      window.clearTimeout(timer);
    };
  }, [locale, query, searchRevision]);

  const cleanQuery = query.trim();
  const records = cleanQuery ? searchRecords || [] : data?.records || [];
  const filtered = useMemo(() => records.filter((record) => {
    const matchesText = !cleanQuery || vulnerabilitySearchText(record, locale)
      .toLocaleLowerCase()
      .includes(cleanQuery.toLocaleLowerCase());
    return matchesText && (severity === "all" || record.severity?.toLowerCase() === severity);
  }), [cleanQuery, locale, records, severity]);
  const visibleError = searchError || error;
  const busy = loading || searching;

  return (
    <div className="page-scroll records-view">
      <div className="page-heading"><div><h1>{t("漏洞库")}</h1><p>{t("查询聚合后的公开漏洞事实与影响范围。")}</p></div></div>
      {data ? <VulnerabilityReadiness snapshot={data} /> : null}
      <div className="records-toolbar"><label><Search size={16} aria-hidden="true" /><input aria-label={t("搜索漏洞记录")} name="vulnerability_query" autoComplete="off" value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t("例如 CVE-2026-1234 或 OpenSSL…")} /></label><label><Filter size={15} aria-hidden="true" /><select aria-label={t("按严重度筛选")} name="vulnerability_severity" autoComplete="off" value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="all">{t("全部严重度")}</option><option value="critical">{t("严重")}</option><option value="high">{t("高危")}</option><option value="medium">{t("中危")}</option><option value="low">{t("低危")}</option></select></label></div>
      {visibleError ? <div className="records-load-error" role="alert"><span>{t("漏洞记录加载失败：{error}", { error: brandDisplayText(visibleError) })}</span><button className="secondary" onClick={() => cleanQuery ? setSearchRevision((value) => value + 1) : void load(true)}>{t("重新加载")}</button></div> : null}
      <div className="vulnerability-list" aria-busy={busy}>{filtered.map((record) => <article key={record.id}><button type="button" className="vulnerability-card-button" onClick={() => setSelectedRecord(record)} aria-label={t("查看 {id} 的网站漏洞信息", { id: record.id })}><span className="vuln-leading"><span><ShieldAlert size={16} aria-hidden="true" /></span><span><strong className="vuln-id" role="heading" aria-level={2} translate="no">{record.id}</strong><span className="vuln-title">{vulnerabilityTitle(record, locale) || t("暂无漏洞标题")}</span></span></span><b className={`severity ${safeSeverityClass(record.severity)}`}>{severityLabel(record.severity, t)}</b><span className="vuln-description">{vulnerabilityDescription(record, locale) || t("暂无漏洞描述")}</span><span className="vuln-footer"><span translate="no">{brandDisplayText(record.source) || t("公开情报")}</span><span translate="no">CVSS {record.cvss ?? "-"}</span>{record.affected_products?.length ? <span translate="no">{record.affected_products.slice(0, 3).join(" / ")}</span> : null}<span className="vuln-detail-hint">{t("查看网站信息")}<ExternalLink aria-hidden="true" /></span></span></button></article>)}{busy ? (
        <BeautifulLoadingState
          className="empty-list-state"
          label={cleanQuery ? t("正在搜索完整漏洞库…") : t("正在加载漏洞记录…")}
          detail={cleanQuery ? t("正在匹配 CVE 编号、组件和漏洞描述") : t("正在读取本机漏洞索引")}
          compact={filtered.length > 0}
          showElapsed
        />
      ) : !visibleError && !filtered.length ? (
        <BeautifulEmptyState
          className="empty-list-state"
          title={t("没有匹配的漏洞记录")}
          query={cleanQuery || undefined}
          detail={t("请检查 CVE 编号或尝试组件名称")}
        />
      ) : null}</div>
      {selectedRecord ? <VulnerabilityDetail record={selectedRecord} locale={locale} onClose={() => setSelectedRecord(undefined)} /> : null}
    </div>
  );
}

function VulnerabilityDetail({ record, locale, onClose }: { record: VulnerabilityRecord; locale: ClientLocale; onClose: () => void }) {
  const { t } = useI18n();
  const links = useMemo(() => vulnerabilityWebsiteLinks(record), [record]);
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [onClose]);

  return (
    <div className="vulnerability-detail-backdrop" onMouseDown={onClose}>
      <section className="vulnerability-detail" role="dialog" aria-modal="true" aria-labelledby="vulnerability-detail-title" onMouseDown={(event) => event.stopPropagation()}>
        <header><div><small>{t("网站漏洞信息")}</small><h2 id="vulnerability-detail-title" translate="no">{record.id}</h2></div><button type="button" onClick={onClose} aria-label={t("关闭漏洞详情")}><X aria-hidden="true" /></button></header>
        <div className="vulnerability-detail-body">
          <section className="vulnerability-detail-summary"><b className={`severity ${safeSeverityClass(record.severity)}`}>{severityLabel(record.severity, t)}</b><h3>{vulnerabilityTitle(record, locale) || t("暂无漏洞标题")}</h3><p>{vulnerabilityDescription(record, locale) || t("暂无漏洞描述")}</p></section>
          <dl className="vulnerability-facts">
            <div><dt>CVSS</dt><dd translate="no">{record.cvss ?? "-"}</dd></div>
            <div><dt>{t("来源")}</dt><dd translate="no">{brandDisplayText(record.source) || t("公开情报")}</dd></div>
            <div><dt>{t("发布时间")}</dt><dd>{formatDate(record.published_at, locale)}</dd></div>
            <div><dt>{t("更新时间")}</dt><dd>{formatDate(record.updated_at, locale)}</dd></div>
          </dl>
          <FactList label={t("受影响产品")} values={record.affected_products} />
          <FactList label={t("受影响版本")} values={record.affected_versions} />
          <FactList label={t("修复版本")} values={record.fixed_versions} />
          <FactList label={t("漏洞别名")} values={record.aliases} />
          <FactList label="CWE" values={record.cwes} />
          <section className="vulnerability-websites"><h3>{t("公开漏洞网站")}</h3><p>{t("点击下方入口，在系统浏览器中查看该网站发布的原始漏洞资料。")}</p>{links.length ? <div>{links.map((link) => <button type="button" key={link.url} onClick={() => void openExternalUrl(link.url)}><span><strong>{link.label}</strong><small translate="no">{link.url}</small></span><ExternalLink aria-hidden="true" /></button>)}</div> : <small>{t("暂无公开漏洞网页")}</small>}</section>
        </div>
      </section>
    </div>
  );
}

function FactList({ label, values }: { label: string; values?: string[] }) {
  if (!values?.length) return null;
  return <section className="vulnerability-fact-list"><h3>{label}</h3><div>{values.slice(0, 20).map((value) => <span key={value} translate="no">{value}</span>)}</div></section>;
}

function vulnerabilityWebsiteLinks(record: VulnerabilityRecord) {
  const candidates: Array<{ label: string; url: string }> = [];
  const identifiers = [record.id, ...(record.aliases || [])].map((value) => value.toUpperCase());
  const cve = identifiers.find((value) => /^CVE-\d{4}-\d{4,8}$/.test(value));
  const ghsa = identifiers.find((value) => /^GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(value));
  if (cve) candidates.push({ label: "NVD", url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}` });
  if (cve) candidates.push({ label: "CVE.org", url: `https://www.cve.org/CVERecord?id=${encodeURIComponent(cve)}` });
  if (ghsa) candidates.push({ label: "GitHub Advisory", url: `https://github.com/advisories/${encodeURIComponent(ghsa)}` });
  for (const value of record.references || []) {
    try {
      const url = new URL(value);
      if (url.protocol !== "https:" && url.protocol !== "http:") continue;
      candidates.push({ label: url.hostname.replace(/^www\./, ""), url: url.toString() });
    } catch {
      // Ignore malformed source links returned by public feeds.
    }
  }
  const seen = new Set<string>();
  return candidates.filter((item) => {
    if (seen.has(item.url)) return false;
    seen.add(item.url);
    return true;
  }).slice(0, 12);
}

const severityLabel = (value: string | undefined, t: (source: string) => string) => t({ critical: "严重", high: "高危", medium: "中危", low: "低危" }[value?.toLowerCase() || ""] || "待定");
const safeSeverityClass = (value?: string) => ["critical", "high", "medium", "low"].includes(value?.toLowerCase() || "") ? value!.toLowerCase() : "unknown";
const formatDate = (value: string | undefined, locale: ClientLocale) => {
  if (!value) return "-";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return "-";
  return new Intl.DateTimeFormat(clientLocaleTag(locale), { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false }).format(parsed);
};
