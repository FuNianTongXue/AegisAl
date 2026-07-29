---
name: secflow-report-generation
description: Generate and download auditable SecFlow scan reports through format-specific Mermaid, Markdown, Word, and PDF MCP services. Use after a completed code or dependency scan, or when a user requests an existing report in one or all supported formats. Keep generation and download human-confirmed.
---

# SecFlow Report Generation

## Semantic Routing

1. Infer whether the user wants to generate a report from a completed scan, download an existing report, choose one format, or download all formats. Do not require fixed wording or a slash command.
2. Do not route ordinary security questions to report generation merely because the answer contains Markdown.
3. A report requires completed, user-authorized scan facts. Never start another scan or query new vulnerability facts during format conversion.

## Required Pipeline

1. Interrupt before report generation and ask for confirmation.
2. Normalize dependency, code finding, evidence snippet, remediation, metrics, and source facts into `secflow.scan-results/v1` JSON. Verify the JSON round trip and payload SHA-256.
3. Invoke Report Chart MCP with that exact JSON.
4. Invoke Mermaid MCP with the same scan hash and chart output. Mermaid may express only relationships and severity values present in those inputs.
5. Invoke Markdown MCP to generate the `.md` report and embed the verified Mermaid diagrams.
6. Invoke Word MCP to generate a real `.docx` from the canonical report JSON. Preserve headings, real lists, wrapped evidence code, remediation, explicit table geometry, and audit hashes.
7. Invoke PDF MCP to generate `.pdf` from the same canonical report JSON. Preserve line breaks, code line numbers, Chinese labels, percentages, and China Standard Time.
8. Generate HTML only from the verified Markdown/report JSON; it must not rewrite scan facts.
9. Record one audit entry per MCP: server, tool, status, invocation time, input SHA-256, output SHA-256, media type, artifact size, renderer, and error when applicable.
10. Do not register an artifact whose signature or output hash fails validation. A request for all formats succeeds only when MD, HTML, DOCX, and PDF are all available.
11. Interrupt again after generation and ask the user whether to download and which format. Preserve single-format, current-report all-formats, and all-report archive choices.

## Report Content

- Keep verified vulnerability evidence snippets and exact line numbers with wrapping that does not overflow the page.
- Include actionable remediation for each reportable finding.
- Keep vulnerability descriptions user-visible in the selected language while preserving identifiers, package names, versions, code, and URLs.
- Do not restore deprecated “扫描文件与规则”, “格式”, or “模式” sections.
- Do not invent findings, PoCs, exploit steps, fixed versions, source links, or Mermaid relationships.

## Evaluation Isolation

- This workflow formats completed user-project scan results only.
- Do not change static rules, AST/CFG/DFG/taint behavior, scanner time limits, frozen 500-project evaluation manifests, truth labels, metrics, failure attribution, or regression gates.
