import type { CSSProperties, ReactNode } from "react";

export type StructuredColumnKind = "date" | "link" | "number" | "status" | "tags" | "text";
export type StructuredDataRow = Record<string, unknown>;

export interface StructuredDataColumn {
  key: string;
  label: string;
  kind?: StructuredColumnKind;
  width?: CSSProperties["width"];
  editable?: boolean;
  render?: (value: unknown, row: StructuredDataRow, rowIndex: number) => ReactNode;
}

export interface StructuredDataTableModel {
  id?: string;
  title?: string;
  caption: string;
  columns: StructuredDataColumn[];
  rows: StructuredDataRow[];
  total?: number;
  edited?: boolean;
}

export function inferStructuredColumnKind(label: string): StructuredColumnKind {
  const value = label.trim().toLowerCase();
  if (/(severity|risk|status|state|严重|風險|风险|状态|狀態|级别|等級)/i.test(value)) return "status";
  if (/(date|time|updated|published|created|日期|时间|時間|更新|发布|發布)/i.test(value)) return "date";
  if (/(url|link|reference|href|链接|連結|参考|參考)/i.test(value)) return "link";
  if (/(tags?|labels?|categories|components|products|标签|標籤|分类|分類|组件|元件|产品|產品)/i.test(value)) return "tags";
  if (/(count|score|total|number|cvss|数量|數量|评分|評分|总计|總計)/i.test(value)) return "number";
  return "text";
}
