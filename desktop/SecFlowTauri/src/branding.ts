/** Public product names. Internal SecFlow identifiers remain stable for compatibility. */
export const BRAND_NAME_ZH = "神盾";
export const BRAND_NAME_EN = "AegisAl";
export const BRAND_SECURITY_AGENT = `${BRAND_NAME_EN} Security Agent`;

/** Normalize legacy product names only at user-facing presentation boundaries. */
export function brandDisplayText(value: unknown): string {
  if (typeof value !== "string") return "";
  return value
    .replace(/安全智脑客户端/g, `${BRAND_NAME_ZH}客户端`)
    .replace(/安全智脑/g, BRAND_NAME_ZH)
    .replace(/AegisAI/gi, BRAND_NAME_EN)
    .replace(/SecFlow/gi, BRAND_NAME_EN);
}

/** Rewrite copied Markdown prose while leaving inline and block code byte-for-byte intact. */
export function brandMarkdownDisplayText(value: unknown): string {
  if (typeof value !== "string") return "";
  const lines = value.match(/[^\r\n]*(?:\r\n|\n|\r|$)/g)?.filter(Boolean) || [];
  let fence: { marker: "`" | "~"; length: number } | null = null;

  return lines.map((line) => {
    const source = line.replace(/(?:\r\n|\n|\r)$/, "");
    const ending = line.slice(source.length);
    if (fence) {
      const close = new RegExp(`^ {0,3}${fence.marker}{${fence.length},}[ \t]*$`);
      if (close.test(source)) fence = null;
      return line;
    }

    const opening = /^ {0,3}(`{3,}|~{3,})/.exec(source);
    if (opening) {
      fence = { marker: opening[1][0] as "`" | "~", length: opening[1].length };
      return line;
    }
    if (/^(?: {4}|\t)/.test(source)) return line;
    return `${brandInlineMarkdownProse(source)}${ending}`;
  }).join("");
}

function brandInlineMarkdownProse(value: string): string {
  let output = "";
  let proseStart = 0;
  let cursor = 0;
  while (cursor < value.length) {
    if (value[cursor] !== "`") {
      cursor += 1;
      continue;
    }
    let markerEnd = cursor + 1;
    while (value[markerEnd] === "`") markerEnd += 1;
    const marker = value.slice(cursor, markerEnd);
    const closing = value.indexOf(marker, markerEnd);
    if (closing < 0) {
      cursor = markerEnd;
      continue;
    }
    output += brandDisplayText(value.slice(proseStart, cursor));
    output += value.slice(cursor, closing + marker.length);
    cursor = closing + marker.length;
    proseStart = cursor;
  }
  return output + brandDisplayText(value.slice(proseStart));
}

type MarkdownNode = {
  type?: string;
  value?: unknown;
  children?: MarkdownNode[];
};

/** Rewrite legacy brands in prose while preserving code blocks and technical identifiers. */
export function remarkBrandDisplayText() {
  return (tree: MarkdownNode) => {
    const visit = (node: MarkdownNode) => {
      if (node.type === "code" || node.type === "inlineCode") return;
      if (node.type === "text" && typeof node.value === "string") {
        node.value = brandDisplayText(node.value);
      }
      node.children?.forEach(visit);
    };
    visit(tree);
  };
}
