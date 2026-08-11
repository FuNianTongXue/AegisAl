import { Filter, Search, ShieldAlert } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { api } from "../lib/api";
import type { VulnerabilityRecord } from "../types";

export function RecordsView() {
  const [records, setRecords] = useState<VulnerabilityRecord[]>([]);
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  useEffect(() => { void api.dashboard().then((value) => setRecords(value.records || [])); }, []);
  const filtered = useMemo(() => records.filter((record) => {
    const matchesText = `${record.id} ${record.title} ${record.description || ""}`.toLowerCase().includes(query.toLowerCase());
    return matchesText && (severity === "all" || record.severity?.toLowerCase() === severity);
  }), [query, records, severity]);
  return (
    <div className="page-scroll records-view">
      <div className="page-heading"><div><h1>漏洞库</h1><p>查询聚合后的公开漏洞事实与影响范围。</p></div></div>
      <div className="records-toolbar"><label><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索 CVE、组件或漏洞描述" /></label><label><Filter size={15} /><select value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="all">全部严重度</option><option value="critical">严重</option><option value="high">高危</option><option value="medium">中危</option><option value="low">低危</option></select></label></div>
      <div className="vulnerability-list">{filtered.map((record) => <article key={record.id}><div className="vuln-leading"><span><ShieldAlert size={16} /></span><div><h2>{record.id}</h2><p>{record.title}</p></div></div><b className={`severity ${record.severity?.toLowerCase() || "unknown"}`}>{record.severity || "待定"}</b><p className="vuln-description">{record.description || "暂无中文漏洞描述"}</p><footer><span>{record.source || "公开情报"}</span><span>CVSS {record.cvss ?? "-"}</span><span>{(record.affected_products || []).slice(0, 3).join(" / ")}</span></footer></article>)}{!filtered.length ? <div className="empty-list-state">没有匹配的漏洞记录</div> : null}</div>
    </div>
  );
}
