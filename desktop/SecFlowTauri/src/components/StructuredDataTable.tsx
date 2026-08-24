import {
  AlignLeft,
  CalendarDays,
  Check,
  CircleDot,
  Database,
  ExternalLink,
  Hash,
  Link2,
  LoaderCircle,
  Pencil,
  Tags,
  X,
} from "lucide-react";
import {
  isValidElement,
  useEffect,
  useId,
  useState,
  type ComponentPropsWithoutRef,
  type KeyboardEvent,
  type ReactNode,
} from "react";

import {
  inferStructuredColumnKind,
  type StructuredColumnKind,
  type StructuredDataRow,
  type StructuredDataTableModel,
} from "./structuredData";

import "./structured-data-table.css";

export type { StructuredDataColumn, StructuredDataRow, StructuredDataTableModel } from "./structuredData";

export interface StructuredDataEditLabels {
  edit: string;
  save: string;
  cancel: string;
  saving: string;
  saved: string;
  edited: string;
  saveError: string;
  invalidValue: string;
  row: string;
  yes: string;
  no: string;
}

export function StructuredDataTable({
  model,
  emptyLabel,
  countLabel,
  className = "",
  stickyFirstColumn = true,
  rowKey,
  onModelChange,
  editLabels,
}: {
  model: StructuredDataTableModel;
  emptyLabel: string;
  countLabel?: string;
  className?: string;
  stickyFirstColumn?: boolean;
  rowKey?: (row: StructuredDataRow, rowIndex: number) => string;
  onModelChange?: (model: StructuredDataTableModel) => void | Promise<void>;
  editLabels?: StructuredDataEditLabels;
}) {
  const [editing, setEditing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState("");
  const [savedMessage, setSavedMessage] = useState("");
  const [committedRows, setCommittedRows] = useState(() => model.rows);
  const [draftValues, setDraftValues] = useState(() => editableValues(model));
  const liveRegionId = useId();

  useEffect(() => {
    if (editing) return;
    setCommittedRows(model.rows);
    setDraftValues(editableValues(model));
  }, [editing, model]);

  const beginEditing = () => {
    setDraftValues(editableValues({ ...model, rows: committedRows }));
    setSaveError("");
    setSavedMessage("");
    setEditing(true);
  };
  const cancelEditing = () => {
    setDraftValues(editableValues({ ...model, rows: committedRows }));
    setSaveError("");
    setEditing(false);
  };
  const saveChanges = async () => {
    if (!onModelChange || !editLabels || saving) return;
    setSaving(true);
    setSaveError("");
    try {
      const rows = committedRows.map((row, rowIndex) => Object.fromEntries(
        model.columns.map((column, columnIndex) => {
          const originalValue = row[column.key];
          const draftValue = draftValues[rowIndex]?.[columnIndex] ?? "";
          const changed = draftValue !== serializeEditableValue(originalValue);
          return [
            column.key,
            isEditableCell(column, originalValue) && changed
              ? parseEditableValue(
                  draftValue,
                  originalValue,
                  column.kind,
                  editLabels.invalidValue,
                  column.label,
                )
              : originalValue,
          ];
        }),
      ));
      const nextModel = { ...model, rows, edited: true };
      await onModelChange(nextModel);
      setCommittedRows(rows);
      setSavedMessage(editLabels.saved);
      setEditing(false);
    } catch (error) {
      const detail = error instanceof Error && error.message ? error.message : String(error);
      setSaveError(`${editLabels.saveError}${detail ? `：${detail}` : ""}`);
    } finally {
      setSaving(false);
    }
  };
  const handleEditorKeyDown = (event: KeyboardEvent<HTMLElement>) => {
    if (event.key === "Escape") {
      event.preventDefault();
      cancelEditing();
      return;
    }
    if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) {
      event.preventDefault();
      void saveChanges();
    }
  };

  const table = (
    <div
      className="structured-data-table-wrap"
      role="region"
      aria-label={model.caption}
      tabIndex={0}
    >
      <table
        className={`structured-data-table ${className}`.trim()}
        data-sticky-first={stickyFirstColumn || undefined}
      >
        <caption className="sr-only">{model.caption}</caption>
        <colgroup>
          {model.columns.map((column) => (
            <col key={column.key} style={column.width ? { width: column.width } : undefined} />
          ))}
        </colgroup>
        <thead>
          <tr>
            {model.columns.map((column) => (
              <th key={column.key} scope="col">
                <StructuredHeader label={column.label} kind={column.kind} />
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {committedRows.map((row, rowIndex) => (
            <tr key={rowKey?.(row, rowIndex) || stableRowKey(row, rowIndex)}>
              {model.columns.map((column, columnIndex) => {
                const value = row[column.key];
                const rendered = column.render?.(value, row, rowIndex);
                const cellEditable = editing && rendered == null && isEditableCell(column, value);
                return (
                  <td
                    key={column.key}
                    data-editing={cellEditable || undefined}
                    data-tone={!editing && rendered == null ? valueTone(value, column.kind) || undefined : undefined}
                  >
                    {cellEditable && editLabels ? (
                      <StructuredValueEditor
                        value={draftValues[rowIndex]?.[columnIndex] ?? ""}
                        originalValue={value}
                        kind={column.kind}
                        label={`${column.label}，${editLabels.row} ${rowIndex + 1}`}
                        yesLabel={editLabels.yes}
                        noLabel={editLabels.no}
                        onChange={(nextValue) => setDraftValues((current) => updateDraftValue(
                          current,
                          rowIndex,
                          columnIndex,
                          nextValue,
                        ))}
                      />
                    ) : rendered == null
                      ? (
                          <StructuredValue
                            value={value}
                            kind={column.kind}
                            yesLabel={editLabels?.yes}
                            noLabel={editLabels?.no}
                          />
                        )
                      : rendered}
                  </td>
                );
              })}
            </tr>
          ))}
          {!committedRows.length ? (
            <tr>
              <td className="structured-data-empty" colSpan={Math.max(model.columns.length, 1)}>{emptyLabel}</td>
            </tr>
          ) : null}
        </tbody>
      </table>
    </div>
  );

  if (!model.title) return table;
  return (
    <section
      className="structured-data-panel"
      aria-label={model.title}
      data-editing={editing || undefined}
      onKeyDown={editing ? handleEditorKeyDown : undefined}
    >
      <header className="structured-data-panel-header">
        <Database size={15} aria-hidden="true" />
        <strong>{model.title}</strong>
        {model.edited ? <span className="structured-data-edited-badge">{editLabels?.edited || "Edited"}</span> : null}
        <small>{countLabel || committedRows.length}</small>
        {onModelChange && editLabels ? (
          <span className="structured-data-edit-actions">
            {editing ? (
              <>
                <button
                  type="button"
                  className="structured-data-icon-button primary"
                  aria-label={saving ? editLabels.saving : editLabels.save}
                  title={saving ? editLabels.saving : editLabels.save}
                  aria-describedby={liveRegionId}
                  disabled={saving}
                  onClick={() => void saveChanges()}
                >
                  {saving ? <LoaderCircle className="spin" aria-hidden="true" /> : <Check aria-hidden="true" />}
                </button>
                <button
                  type="button"
                  className="structured-data-icon-button"
                  aria-label={editLabels.cancel}
                  title={editLabels.cancel}
                  disabled={saving}
                  onClick={cancelEditing}
                >
                  <X aria-hidden="true" />
                </button>
              </>
            ) : (
              <button
                type="button"
                className="structured-data-icon-button"
                aria-label={editLabels.edit}
                title={editLabels.edit}
                onClick={beginEditing}
              >
                <Pencil aria-hidden="true" />
              </button>
            )}
          </span>
        ) : null}
      </header>
      <span id={liveRegionId} className="sr-only" role="status" aria-live="polite">
        {saveError || savedMessage}
      </span>
      {saveError ? <div className="structured-data-edit-error" role="alert">{saveError}</div> : null}
      {table}
    </section>
  );
}

export function MarkdownDataTable({
  children,
  label,
}: {
  children?: ReactNode;
  label: string;
}) {
  return (
    <div className="structured-data-table-wrap markdown-data-table-wrap" role="region" aria-label={label} tabIndex={0}>
      <table className="structured-data-table markdown-data-table" data-sticky-first="true">
        <caption className="sr-only">{label}</caption>
        {children}
      </table>
    </div>
  );
}

export function MarkdownDataHeaderCell({
  children,
  ...props
}: ComponentPropsWithoutRef<"th">) {
  const label = reactNodeText(children);
  return (
    <th {...props} scope="col">
      <StructuredHeader label={children} kind={inferStructuredColumnKind(label)} />
    </th>
  );
}

export function MarkdownDataCell({
  children,
  ...props
}: ComponentPropsWithoutRef<"td">) {
  const tone = valueTone(reactNodeText(children));
  return (
    <td {...props} data-tone={tone || undefined}>
      {tone ? (
        <span className={`structured-data-chip tone-${tone}`}>
          <span className="structured-data-status-dot" aria-hidden="true" />
          {children}
        </span>
      ) : <span className="structured-data-plain">{children}</span>}
    </td>
  );
}

function StructuredHeader({ label, kind }: { label: ReactNode; kind?: StructuredColumnKind }) {
  const resolvedKind = kind || inferStructuredColumnKind(reactNodeText(label));
  return (
    <span className="structured-data-header-label">
      <ColumnIcon kind={resolvedKind} />
      <span>{label}</span>
    </span>
  );
}

function ColumnIcon({ kind }: { kind: StructuredColumnKind }) {
  const props = { size: 13, strokeWidth: 1.9, "aria-hidden": true as const };
  if (kind === "status") return <CircleDot {...props} />;
  if (kind === "date") return <CalendarDays {...props} />;
  if (kind === "link") return <Link2 {...props} />;
  if (kind === "tags") return <Tags {...props} />;
  if (kind === "number") return <Hash {...props} />;
  return <AlignLeft {...props} />;
}

function StructuredValue({
  value,
  kind,
  yesLabel = "Yes",
  noLabel = "No",
}: {
  value: unknown;
  kind?: StructuredColumnKind;
  yesLabel?: string;
  noLabel?: string;
}) {
  if (value == null || value === "") return <span className="structured-data-muted">-</span>;
  if (isValidElement(value)) return value;
  if (Array.isArray(value)) {
    const links = kind === "link"
      ? value.map((item) => safeExternalUrl(item)).filter(Boolean)
      : [];
    if (links.length === value.length && links.length) {
      return (
        <span className="structured-data-link-list">
          {links.map((link) => <StructuredLink key={link} href={link} label={link} />)}
        </span>
      );
    }
    return <StructuredTags values={value} />;
  }
  if (typeof value === "object") {
    const item = value as Record<string, unknown>;
    const url = safeExternalUrl(item.url);
    if (url) return <StructuredLink href={url} label={String(item.title || item.label || url)} />;
    return <span className="structured-data-plain">{formatObjectValue(item)}</span>;
  }

  const text = typeof value === "boolean" ? (value ? yesLabel : noLabel) : String(value);
  const links = text.split(/\r?\n/).map((item) => item.trim()).filter(Boolean);
  if (links.length && links.every((item) => Boolean(safeExternalUrl(item)))) {
    return (
      <span className="structured-data-link-list">
        {links.map((link) => <StructuredLink key={link} href={link} label={link} />)}
      </span>
    );
  }
  const url = safeExternalUrl(text);
  if (url) return <StructuredLink href={url} label={text} />;
  const tone = valueTone(text, kind);
  if (tone) {
    return (
      <span className={`structured-data-chip tone-${tone}`}>
        <span className="structured-data-status-dot" aria-hidden="true" />
        {text}
      </span>
    );
  }
  return <span className="structured-data-plain">{text}</span>;
}

function StructuredValueEditor({
  value,
  originalValue,
  kind,
  label,
  yesLabel,
  noLabel,
  onChange,
}: {
  value: string;
  originalValue: unknown;
  kind?: StructuredColumnKind;
  label: string;
  yesLabel: string;
  noLabel: string;
  onChange: (value: string) => void;
}) {
  if (typeof originalValue === "boolean") {
    return (
      <label className="structured-data-boolean-editor">
        <input
          type="checkbox"
          checked={value === "true"}
          aria-label={label}
          onChange={(event) => onChange(String(event.target.checked))}
        />
        <span>{value === "true" ? yesLabel : noLabel}</span>
      </label>
    );
  }
  return (
    <textarea
      className="structured-data-cell-editor"
      aria-label={label}
      inputMode={kind === "number" ? "decimal" : undefined}
      rows={1}
      value={value}
      onChange={(event) => onChange(event.target.value)}
    />
  );
}

function StructuredTags({ values }: { values: unknown[] }) {
  const labels = values.map(formatCompactValue).filter(Boolean);
  if (!labels.length) return <span className="structured-data-muted">-</span>;
  const visible = labels.slice(0, 4);
  return (
    <span className="structured-data-tags" title={labels.join(", ")}>
      {visible.map((label, index) => (
        <span key={`${label}:${index}`} className="structured-data-tag" data-tag-tone={tagTone(label)}>{label}</span>
      ))}
      {labels.length > visible.length ? <span className="structured-data-tag-more">+{labels.length - visible.length}</span> : null}
    </span>
  );
}

function StructuredLink({ href, label }: { href: string; label: string }) {
  return (
    <a className="structured-data-link" href={href} target="_blank" rel="noreferrer" title={label}>
      <span>{label}</span>
      <ExternalLink size={12} aria-hidden="true" />
    </a>
  );
}

function valueTone(value: unknown, kind?: StructuredColumnKind) {
  if (value == null || typeof value === "object") return "";
  const text = String(value).trim().toLowerCase();
  if (!text || (kind && kind !== "status" && kind !== "text")) return "";
  if (/^(critical|severe|严重|嚴重)$/.test(text)) return "critical";
  if (/^(high|高危|高风险|高風險)$/.test(text)) return "high";
  if (/^(medium|moderate|中危|中风险|中風險)$/.test(text)) return "medium";
  if (/^(low|低危|低风险|低風險)$/.test(text)) return "low";
  if (/^(completed|complete|success|passed|resolved|active|yes|true|已完成|完成|成功|通过|通過|是)$/.test(text)) return "success";
  if (/^(failed|failure|error|blocked|cancelled|no|false|失败|失敗|错误|錯誤|阻塞|已取消|否)$/.test(text)) return "danger";
  if (/^(pending|running|warning|unknown|unrated|queued|待处理|待處理|进行中|進行中|警告|未知|待定|排队|排隊)$/.test(text)) return "warning";
  return "";
}

function safeExternalUrl(value: unknown) {
  const text = String(value || "").trim();
  if (!text) return "";
  try {
    const url = new URL(text);
    return url.protocol === "http:" || url.protocol === "https:" ? url.toString() : "";
  } catch {
    return "";
  }
}

function formatObjectValue(value: Record<string, unknown>) {
  const coordinate = [value.ecosystem, value.name].filter(Boolean).map(String).join(" / ");
  if (coordinate) return `${coordinate}${value.version ? ` @ ${String(value.version)}` : ""}`;
  return Object.entries(value)
    .slice(0, 5)
    .map(([key, item]) => `${key}: ${formatCompactValue(item)}`)
    .join(" · ");
}

function formatCompactValue(value: unknown): string {
  if (value == null) return "";
  if (Array.isArray(value)) return value.map(formatCompactValue).filter(Boolean).join(", ");
  if (typeof value === "object") return formatObjectValue(value as Record<string, unknown>);
  return String(value).trim();
}

function tagTone(value: string) {
  let hash = 0;
  for (const character of value) hash = ((hash << 5) - hash + character.charCodeAt(0)) | 0;
  return Math.abs(hash) % 5;
}

function stableRowKey(row: StructuredDataRow, rowIndex: number) {
  for (const key of ["id", "key", "name", "identifier", "漏洞编号"]) {
    if (row[key] != null && row[key] !== "") return `${key}:${String(row[key])}`;
  }
  return `row:${rowIndex}`;
}

function reactNodeText(value: ReactNode): string {
  if (value == null || typeof value === "boolean") return "";
  if (typeof value === "string" || typeof value === "number") return String(value);
  if (Array.isArray(value)) return value.map(reactNodeText).join("");
  if (isValidElement(value)) return reactNodeText((value.props as { children?: ReactNode }).children);
  return "";
}

function editableValues(model: StructuredDataTableModel) {
  return model.rows.map((row) => model.columns.map((column) => serializeEditableValue(row[column.key])));
}

function serializeEditableValue(value: unknown): string {
  if (value == null) return "";
  if (Array.isArray(value)) return value.map(formatCompactValue).filter(Boolean).join(", ");
  if (typeof value === "object") {
    if (isValidElement(value)) return reactNodeText(value);
    return JSON.stringify(value, null, 2);
  }
  return String(value);
}

function parseEditableValue(
  value: string,
  originalValue: unknown,
  kind: StructuredColumnKind | undefined,
  invalidValueLabel: string,
  columnLabel: string,
): unknown {
  const text = value.trim();
  if (Array.isArray(originalValue) || kind === "tags") {
    return text ? text.split(/[\n,，;；]+/u).map((item) => item.trim()).filter(Boolean) : [];
  }
  if (typeof originalValue === "boolean") return value === "true";
  if (typeof originalValue === "number" || kind === "number") {
    if (!text) return null;
    const number = Number(text);
    if (!Number.isFinite(number)) throw new Error(`${columnLabel}：${invalidValueLabel}`);
    return number;
  }
  if (kind === "link" && text) {
    const links = text.split(/\r?\n/).map((item) => item.trim()).filter(Boolean);
    if (!links.length || links.some((link) => !safeExternalUrl(link))) {
      throw new Error(`${columnLabel}：${invalidValueLabel}`);
    }
  }
  if (originalValue && typeof originalValue === "object" && !isValidElement(originalValue)) {
    if (!text) return {};
    try {
      return JSON.parse(text) as unknown;
    } catch {
      throw new Error(`${columnLabel}：${invalidValueLabel}`);
    }
  }
  return value;
}

function isEditableCell(column: StructuredDataTableModel["columns"][number], value: unknown) {
  if (column.editable === false || column.render || isValidElement(value)) return false;
  if (/^(?:id|key|identifier|cve|cve_id|漏洞编号)$/iu.test(column.key.trim())) return false;
  return value == null || typeof value !== "object" || Array.isArray(value);
}

function updateDraftValue(values: string[][], rowIndex: number, columnIndex: number, value: string) {
  return values.map((row, currentRowIndex) => currentRowIndex === rowIndex
    ? row.map((cell, currentColumnIndex) => currentColumnIndex === columnIndex ? value : cell)
    : row);
}
