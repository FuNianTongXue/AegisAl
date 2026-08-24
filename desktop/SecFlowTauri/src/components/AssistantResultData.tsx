import { useMemo } from "react";

import { useI18n } from "../i18n";
import { brandDisplayText } from "../branding";
import type { AssistantDataTable, AskResult, JsonObject } from "../types";
import {
  StructuredDataTable,
  type StructuredDataEditLabels,
} from "./StructuredDataTable";
import {
  inferStructuredColumnKind,
  type StructuredColumnKind,
  type StructuredDataColumn,
  type StructuredDataRow,
  type StructuredDataTableModel,
} from "./structuredData";

const MAX_PREVIEW_ROWS = 200;
const INTERNAL_FIELD_LABELS = new Set([
  "意图",
  "長期記憶",
  "长期记忆",
  "短期記憶",
  "短期记忆",
  "模型调用状态",
  "模型調用狀態",
  "漏洞数据策略",
  "漏洞資料策略",
  "扫描策略",
  "掃描策略",
  "语义规划器",
  "語義規劃器",
  "数据路径",
  "資料路徑",
  "记忆持久化",
  "記憶持久化",
  "情报链路",
  "情資鏈路",
  "结果指纹",
  "結果指紋",
]);

type Translate = (source: string, replacements?: Record<string, string | number>) => string;

export function AssistantResultData({
  result,
  content,
  onResultChange,
}: {
  result?: AskResult;
  content: string;
  onResultChange?: (result: AskResult) => void | Promise<void>;
}) {
  const { locale, t } = useI18n();
  const models = useMemo(
    () => result ? assistantTableModels(result, locale, t, hasMarkdownTable(content)).map(brandTableModel) : [],
    [content, locale, result, t],
  );
  const editLabels = useMemo<StructuredDataEditLabels>(() => ({
    edit: t("编辑记录表"),
    save: t("保存修改"),
    cancel: t("取消编辑"),
    saving: t("正在保存修改…"),
    saved: t("修改已保存"),
    edited: t("已修改"),
    saveError: t("保存修改失败"),
    invalidValue: t("请输入有效值"),
    row: t("第"),
    yes: t("是"),
    no: t("否"),
  }), [t]);

  if (!models.length) return null;
  return (
    <div className="assistant-structured-data" aria-label={t("结构化数据")}>
      {models.map((model, index) => (
        <StructuredDataTable
          key={model.id || `${model.caption}:${index}`}
          model={model}
          emptyLabel={t("暂无数据")}
          countLabel={tableCountLabel(model, t)}
          editLabels={editLabels}
          onModelChange={onResultChange ? async (nextModel) => {
            if (!result) return;
            const editedModels = models.map((item, itemIndex) => itemIndex === index ? nextModel : item);
            await onResultChange({
              ...result,
              structured_data_edits: editedModels.map(toAssistantDataTable),
            });
          } : undefined}
        />
      ))}
    </div>
  );
}

function brandTableModel(model: StructuredDataTableModel): StructuredDataTableModel {
  return {
    ...model,
    title: brandDisplayText(model.title),
    caption: brandDisplayText(model.caption),
    columns: model.columns.map((column) => ({ ...column, label: brandDisplayText(column.label) })),
  };
}

function assistantTableModels(
  result: AskResult,
  locale: string,
  t: Translate,
  markdownTablePresent: boolean,
): StructuredDataTableModel[] {
  const edited = editedTableModels(result, locale, t);
  if (edited.length) return edited;

  const explicit = explicitTableModels(result, locale, t);
  if (explicit.length) return explicit;

  const componentDetail = componentDetailModel(result.component_detail, locale, t);
  if (componentDetail) return [componentDetail];

  const records = vulnerabilityRecordsModel(result.records, result.total, locale, t);
  if (records) return [records];

  const vulnerabilityCard = propertyTableModel(
    result.vulnerability_card,
    t("漏洞详情"),
    "assistant-vulnerability-card",
    locale,
    t,
  );
  if (vulnerabilityCard) return [vulnerabilityCard];

  if (markdownTablePresent) return [];

  const visibleFields = Object.fromEntries(
    Object.entries(result.fields || {}).filter(([label, value]) => isPublicField(label, value)),
  );
  const fields = propertyTableModel(visibleFields, t("数据概览"), "assistant-result-fields", locale, t);
  return fields ? [fields] : [];
}

function editedTableModels(result: AskResult, locale: string, t: Translate) {
  return (result.structured_data_edits || [])
    .map((candidate, index) => normalizeExplicitTable(candidate, index, locale, t, true))
    .filter((model): model is StructuredDataTableModel => Boolean(model));
}

function explicitTableModels(result: AskResult, locale: string, t: Translate) {
  const candidates: unknown[] = [];
  if (Array.isArray(result.tables)) candidates.push(...result.tables);
  if (result.table && typeof result.table === "object") candidates.push(result.table);
  for (const card of result.cards || []) {
    if (isTablePayload(card)) candidates.push(card);
  }
  return candidates
    .map((candidate, index) => normalizeExplicitTable(candidate, index, locale, t, false))
    .filter((model): model is StructuredDataTableModel => Boolean(model));
}

function normalizeExplicitTable(
  candidate: unknown,
  index: number,
  locale: string,
  t: Translate,
  edited: boolean,
): StructuredDataTableModel | null {
  const value = asObject(candidate);
  const rawRows = Array.isArray(value.rows) ? value.rows : Array.isArray(value.data) ? value.data : [];
  const rawColumns = Array.isArray(value.columns) ? value.columns : [];
  const firstObjectRow = rawRows.find((row) => row && typeof row === "object" && !Array.isArray(row));
  const objectRowKeys = firstObjectRow
    ? Object.keys(firstObjectRow as JsonObject).filter((key) => !isLocalizedShadowKey(key))
    : [];
  const columns = rawColumns
    .map((column, columnIndex) => normalizeExplicitColumn(
      column,
      columnIndex,
      locale,
      t,
      objectRowKeys,
    ))
    .filter((column): column is StructuredDataColumn => Boolean(column));
  if (!columns.length) {
    if (firstObjectRow) {
      for (const key of Object.keys(firstObjectRow as JsonObject)) {
        if (isLocalizedShadowKey(key)) continue;
        const label = localizedCommonLabel(humanizeLabel(key), key, locale, t);
        columns.push({ key, label, kind: inferStructuredColumnKind(`${label} ${key}`) });
      }
    }
  }
  if (!columns.length) return null;

  const rows = rawRows.slice(0, MAX_PREVIEW_ROWS).map((row) => normalizeExplicitRow(row, columns, locale));
  const title = localizedObjectText(value, "title", locale)
    || localizedObjectText(value, "name", locale)
    || localizedObjectText(value, "label", locale)
    || t("数据表");
  const total = positiveInteger(value.total ?? value.row_count ?? value.count) || rawRows.length;
  return {
    id: stringValue(value.id) || `assistant-table-${index}`,
    title,
    caption: localizedObjectText(value, "caption", locale) || title,
    columns,
    rows,
    total,
    edited: edited || Boolean(value.edited),
  };
}

function normalizeExplicitColumn(
  value: unknown,
  index: number,
  locale: string,
  t: Translate,
  objectRowKeys: string[],
): StructuredDataColumn | null {
  if (typeof value === "string" && value.trim()) {
    const sourceLabel = value.trim();
    const key = matchingObjectRowKey(sourceLabel, objectRowKeys, t) || objectRowKeys[index] || sourceLabel;
    const label = localizedCommonLabel(humanizeLabel(sourceLabel), key, locale, t);
    return { key, label, kind: inferStructuredColumnKind(`${label} ${key}`) };
  }
  const column = asObject(value);
  const key = stringValue(column.key || column.id || column.field || column.accessor) || `column_${index + 1}`;
  const sourceLabel = localizedObjectText(column, "label", locale)
    || localizedObjectText(column, "title", locale)
    || localizedObjectText(column, "name", locale)
    || humanizeLabel(key);
  const label = localizedCommonLabel(sourceLabel, key, locale, t);
  const kind = normalizeColumnKind(column.kind || column.type) || inferStructuredColumnKind(`${label} ${key}`);
  return { key, label, kind, editable: column.editable !== false };
}

function normalizeExplicitRow(value: unknown, columns: StructuredDataColumn[], locale: string): StructuredDataRow {
  if (Array.isArray(value)) {
    return Object.fromEntries(columns.map((column, index) => [column.key, value[index]]));
  }
  const row = asObject(value);
  return Object.fromEntries(columns.map((column) => [column.key, localizedRowValue(row, column.key, locale)]));
}

function componentDetailModel(value: unknown, locale: string, t: Translate): StructuredDataTableModel | null {
  const detail = asObject(value);
  const vulnerabilities = Array.isArray(detail.vulnerabilities)
    ? detail.vulnerabilities.map(asObject).filter((item) => Object.keys(item).length)
    : [];
  if (!vulnerabilities.length) return null;
  const component = asObject(detail.component);
  const coordinate = [component.ecosystem, component.name, component.version].filter(Boolean).map(String).join(" / ");
  const title = coordinate ? `${t("组件漏洞")} · ${coordinate}` : t("组件漏洞");
  const rows = vulnerabilities.slice(0, MAX_PREVIEW_ROWS).map((item) => ({
    id: item.id,
    title: localizedRecordText(item, locale, "title", "summary", "description"),
    severity: item.severity_label || item.severity,
    cvss: asObject(item.cvss).score ?? asObject(item.cvss).rating,
    affected_versions: item.affected_versions,
    fixed_versions: item.fixed_versions,
    exploit_status: item.exploit_status,
    updated_at: item.updated_at || item.published_at,
  }));
  return {
    id: "assistant-component-detail",
    title,
    caption: title,
    total: positiveInteger(detail.total) || vulnerabilities.length,
    columns: [
      { key: "id", label: t("漏洞编号"), kind: "text" },
      { key: "title", label: t("标题"), kind: "text" },
      { key: "severity", label: t("严重度"), kind: "status" },
      { key: "cvss", label: "CVSS", kind: "number" },
      { key: "affected_versions", label: t("受影响版本"), kind: "tags" },
      { key: "fixed_versions", label: t("修复版本"), kind: "tags" },
      { key: "exploit_status", label: t("利用状态"), kind: "status" },
      { key: "updated_at", label: t("更新时间"), kind: "date" },
    ].filter((column) => rows.some((row) => hasDisplayValue(row[column.key as keyof typeof row]))) as StructuredDataColumn[],
    rows,
  };
}

function vulnerabilityRecordsModel(
  value: unknown,
  totalValue: unknown,
  locale: string,
  t: Translate,
): StructuredDataTableModel | null {
  const records = Array.isArray(value) ? value.map(asObject).filter((item) => Object.keys(item).length) : [];
  if (!records.length) return null;
  const keys = vulnerabilityRecordKeys(records);
  const rows = records.slice(0, MAX_PREVIEW_ROWS).map((record) => Object.fromEntries(
    keys.map((key) => [key, localizedVulnerabilityRecordValue(record, key, locale, t)]),
  ));
  const columns = keys.map((key) => {
    const label = vulnerabilityRecordLabel(key, t);
    return {
      key,
      label,
      kind: inferStructuredColumnKind(`${label} ${key}`),
    } satisfies StructuredDataColumn;
  });
  const title = t("数据概览");
  return {
    id: "assistant-vulnerability-records",
    title,
    caption: title,
    columns,
    rows,
    total: positiveInteger(totalValue) || records.length,
  };
}

const VULNERABILITY_RECORD_COLUMN_ORDER = [
  "id",
  "identifier",
  "aliases",
  "title",
  "summary",
  "description",
  "severity",
  "cvss_score",
  "cvss",
  "cwes",
  "components",
  "affected_products",
  "affected_versions",
  "fixed_versions",
  "exploit_status",
  "has_poc",
  "reference_links",
  "published_at",
  "updated_at",
] as const;

const INTERNAL_VULNERABILITY_RECORD_KEYS = new Set([
  "canonical_id",
  "catalog_translation",
  "collection",
  "collection_name",
  "content_language",
  "embedding",
  "internal_id",
  "metadata",
  "provider",
  "provenance",
  "raw",
  "references",
  "search_text",
  "source",
  "source_status",
  "sources",
  "translation_audit",
  "translation_error",
  "translation_progress",
  "translation_status",
]);

function vulnerabilityRecordKeys(records: JsonObject[]) {
  const discovered: string[] = [];
  const seen = new Set<string>();
  for (const record of records) {
    for (const sourceKey of Object.keys(record)) {
      const key = localizedVulnerabilityBaseKey(sourceKey);
      if (!isPublicVulnerabilityRecordKey(key) || seen.has(key)) continue;
      seen.add(key);
      discovered.push(key);
    }
  }
  const priority = new Map<string, number>(
    VULNERABILITY_RECORD_COLUMN_ORDER.map((key, index) => [key, index]),
  );
  return discovered.sort((left, right) => {
    const leftPriority = priority.get(left) ?? Number.MAX_SAFE_INTEGER;
    const rightPriority = priority.get(right) ?? Number.MAX_SAFE_INTEGER;
    return leftPriority - rightPriority;
  });
}

function localizedVulnerabilityBaseKey(key: string) {
  if (/_original$/iu.test(key)) return "";
  return key.replace(/_(?:zh|zh_hant)$/iu, "");
}

function isPublicVulnerabilityRecordKey(key: string) {
  const normalized = key.trim();
  if (!normalized || normalized.startsWith("_") || isLocalizedShadowKey(normalized)) return false;
  return !INTERNAL_VULNERABILITY_RECORD_KEYS.has(normalized.toLowerCase());
}

function localizedVulnerabilityRecordValue(
  record: JsonObject,
  key: string,
  locale: string,
  t: Translate,
) {
  const value = localizedRowValue(record, key, locale);
  if (key === "severity") return localizedSeverity(value, locale, t);
  if (value == null || typeof value !== "string") return value;
  return localizedKnownValue(value, locale, t);
}

function vulnerabilityRecordLabel(key: string, t: Translate) {
  const normalized = key.trim().toLowerCase().replace(/[\s-]+/g, "_");
  const sourceLabel = VULNERABILITY_RECORD_LABELS[normalized] || humanizeLabel(key);
  return t(sourceLabel);
}

const VULNERABILITY_RECORD_LABELS: Record<string, string> = {
  id: "漏洞编号",
  identifier: "漏洞编号",
  cve: "漏洞编号",
  cve_id: "漏洞编号",
  vulnerability_id: "漏洞编号",
  aliases: "漏洞别名",
  title: "标题",
  summary: "摘要",
  description: "描述",
  severity: "严重度",
  cvss: "CVSS",
  cvss_score: "CVSS",
  cwes: "CWE",
  components: "受影响组件",
  affected_components: "受影响组件",
  affected_products: "受影响产品",
  affected_versions: "受影响版本",
  fixed_versions: "修复版本",
  exploit_status: "利用状态",
  has_poc: "PoC",
  reference_links: "参考",
  published_at: "发布时间",
  updated_at: "更新时间",
};

function propertyTableModel(value: unknown, title: string, id: string, locale: string, t: Translate): StructuredDataTableModel | null {
  const rows = Object.entries(asObject(value))
    .filter(([, item]) => hasDisplayValue(item))
    .slice(0, MAX_PREVIEW_ROWS)
    .map(([property, item]) => ({
      property: localizedCommonLabel(humanizeLabel(property), property, locale, t),
      value: localizedKnownValue(item, locale, t),
    }));
  if (!rows.length) return null;
  return {
    id,
    title,
    caption: title,
    total: rows.length,
    columns: [
      { key: "property", label: t("属性"), kind: "text", width: "28%", editable: false },
      { key: "value", label: t("值"), kind: "text" },
    ],
    rows,
  };
}

function tableCountLabel(model: StructuredDataTableModel, t: Translate) {
  const total = model.total || model.rows.length;
  return total > model.rows.length
    ? t("显示 {shown} / {total} 条", { shown: model.rows.length, total })
    : t("共 {count} 条", { count: model.rows.length });
}

function isPublicField(label: string, value: unknown) {
  if (!hasDisplayValue(value) || INTERNAL_FIELD_LABELS.has(label.trim())) return false;
  return !/(^|\b)(intent|memory|model status|planner|fingerprint|retrieval path)(\b|$)/i.test(label.trim());
}

function hasMarkdownTable(content: string) {
  return /(?:^|\n)\s*\|?.+\|.+\r?\n\s*\|?\s*:?-{3,}\s*\|/m.test(content);
}

function hasDisplayValue(value: unknown): boolean {
  if (value == null || value === "") return false;
  if (Array.isArray(value)) return value.some(hasDisplayValue);
  if (typeof value === "object") return Object.values(value as JsonObject).some(hasDisplayValue);
  return true;
}

function localizedSeverity(value: unknown, locale: string, t: Translate) {
  const severity = String(value || "").trim().toUpperCase();
  if (locale === "en") return severity || "UNKNOWN";
  return {
    CRITICAL: t("严重"),
    SEVERE: t("严重"),
    HIGH: t("高危"),
    MEDIUM: t("中危"),
    MODERATE: t("中危"),
    LOW: t("低危"),
  }[severity] || String(value || t("待定"));
}

function normalizeColumnKind(value: unknown): StructuredColumnKind | undefined {
  const kind = String(value || "").trim().toLowerCase();
  if (["date", "datetime", "time"].includes(kind)) return "date";
  if (["link", "url"].includes(kind)) return "link";
  if (["number", "numeric", "integer", "score"].includes(kind)) return "number";
  if (["status", "severity", "state", "badge"].includes(kind)) return "status";
  if (["tags", "tag", "array", "list", "multi_select", "multiselect"].includes(kind)) return "tags";
  if (["text", "string"].includes(kind)) return "text";
  return undefined;
}

function isTablePayload(value: unknown) {
  const item = asObject(value);
  if (Array.isArray(item.rows) && Array.isArray(item.columns)) return true;
  const type = String(item.type || item.kind || item.renderer || "").trim().toLowerCase();
  return ["table", "data-table", "records-table", "structured-data-table"].includes(type);
}

function humanizeLabel(value: string) {
  return value.replace(/[_-]+/g, " ").replace(/\b\w/g, (character) => character.toUpperCase());
}

function positiveInteger(value: unknown) {
  const number = Number(value);
  return Number.isFinite(number) && number > 0 ? Math.floor(number) : 0;
}

function stringValue(value: unknown) {
  return typeof value === "string" || typeof value === "number" ? String(value).trim() : "";
}

function asObject(value: unknown): JsonObject {
  return value && typeof value === "object" && !Array.isArray(value) ? value as JsonObject : {};
}

function toAssistantDataTable(model: StructuredDataTableModel): AssistantDataTable {
  return {
    id: model.id,
    type: "records-table",
    title: model.title,
    caption: model.caption,
    columns: model.columns.map((column) => ({
      key: column.key,
      label: column.label,
      kind: column.kind,
      editable: column.editable,
    })),
    rows: model.rows.map((row) => ({ ...row })),
    total: model.total,
    edited: true,
  };
}

function localizedObjectText(value: JsonObject, field: string, locale: string) {
  if (locale === "en") return stringValue(value[`${field}_original`] || value[field]);
  if (locale === "zh-Hant") {
    return stringValue(value[`${field}_zh_hant`] || value[`${field}_zh_Hant`] || value[field]);
  }
  return stringValue(value[`${field}_zh`] || value[field]);
}

function localizedRowValue(row: JsonObject, key: string, locale: string) {
  if (locale === "en") return row[`${key}_original`] ?? row[key];
  if (locale === "zh-Hant") return row[`${key}_zh_hant`] ?? row[`${key}_zh_Hant`] ?? row[key];
  return row[`${key}_zh`] ?? row[key];
}

function localizedRecordText(record: JsonObject, locale: string, ...fields: string[]) {
  const localizedFields = locale === "zh-Hant"
    ? fields.flatMap((field) => [`${field}_zh_hant`, `${field}_zh_Hant`])
    : locale === "en"
      ? fields.map((field) => `${field}_original`)
      : fields.map((field) => `${field}_zh`);
  for (const field of localizedFields) {
    const value = record[field];
    if (hasDisplayValue(value)) return value;
  }
  for (const field of fields) {
    const value = record[field];
    if (hasDisplayValue(value)) return value;
  }
  return "";
}

function localizedKnownValue(value: unknown, locale: string, t: Translate): unknown {
  if (Array.isArray(value)) return value.map((item) => localizedKnownValue(item, locale, t));
  if (value && typeof value === "object") return value;
  const normalized = String(value ?? "").trim().toLowerCase();
  const label = ({
    critical: "严重",
    severe: "严重",
    high: "高危",
    medium: "中危",
    moderate: "中危",
    low: "低危",
    pending: "待处理",
    running: "进行中",
    completed: "已完成",
    complete: "已完成",
    success: "成功",
    failed: "失败",
    failure: "失败",
    yes: "是",
    no: "否",
    true: "是",
    false: "否",
  } as Record<string, string>)[normalized];
  return label && locale !== "en" ? t(label) : value;
}

const COMMON_TABLE_LABELS: Record<string, string> = {
  id: "编号",
  identifier: "编号",
  name: "名称",
  title: "标题",
  summary: "摘要",
  description: "描述",
  status: "状态",
  state: "状态",
  severity: "严重度",
  risk: "风险",
  score: "评分",
  cvss_score: "评分",
  count: "数量",
  total: "总计",
  category: "分类",
  categories: "分类",
  tags: "标签",
  component: "组件",
  components: "组件",
  affected_components: "受影响组件",
  affected_versions: "受影响版本",
  fixed_versions: "修复版本",
  exploit_status: "利用状态",
  source: "来源",
  updated_at: "更新时间",
  published_at: "发布时间",
  created_at: "创建时间",
  url: "链接",
  link: "链接",
  reference: "参考",
  references: "参考",
  value: "值",
  property: "属性",
};

function localizedCommonLabel(label: string, key: string, locale: string, t: Translate) {
  if (locale === "en" || /[\u3400-\u9fff]/u.test(label)) return label;
  const normalized = key.trim().toLowerCase().replace(/[\s-]+/g, "_");
  return COMMON_TABLE_LABELS[normalized] ? t(COMMON_TABLE_LABELS[normalized]) : label;
}

function isLocalizedShadowKey(key: string) {
  return /_(?:original|zh|zh_hant|zh_Hant)$/u.test(key);
}

const COMMON_TABLE_LABEL_ALIASES: Record<string, string[]> = {
  id: ["漏洞编号"],
  identifier: ["漏洞编号"],
  cve: ["漏洞编号"],
  cve_id: ["漏洞编号"],
  vulnerability_id: ["漏洞编号"],
};

function matchingObjectRowKey(label: string, keys: string[], t: Translate) {
  const normalizedLabel = normalizeComparableLabel(label);
  const direct = keys.find((key) => (
    normalizeComparableLabel(key) === normalizedLabel
    || normalizeComparableLabel(humanizeLabel(key)) === normalizedLabel
  ));
  if (direct) return direct;

  return keys.find((key) => {
    const normalizedKey = key.trim().toLowerCase().replace(/[\s-]+/g, "_");
    const sourceLabels = [
      COMMON_TABLE_LABELS[normalizedKey],
      ...(COMMON_TABLE_LABEL_ALIASES[normalizedKey] || []),
    ].filter((value): value is string => Boolean(value));
    return sourceLabels.some((sourceLabel) => (
      normalizeComparableLabel(sourceLabel) === normalizedLabel
      || normalizeComparableLabel(t(sourceLabel)) === normalizedLabel
    ));
  });
}

function normalizeComparableLabel(value: string) {
  return value.trim().toLowerCase().replace(/[\s_-]+/g, "");
}
