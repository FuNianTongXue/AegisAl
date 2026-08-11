---
name: secflow-report-generation
description: Generate and download auditable SecFlow scan reports through SARIF, Mermaid JPEG, Markdown, Word, PDF, and Excel MCP services. Use after a completed code scan, SBOM generation, or full scan, or when a user requests an existing report in one or all supported formats. Report content scope is determined by scan_type context. Keep generation and download human-confirmed.
---

# SecFlow Report Generation

## Semantic Routing

1. Infer whether the user wants to generate a report from a completed scan, download an existing report, choose one format, or download all formats. Do not require fixed wording or a slash command.
2. Do not route ordinary security questions to report generation merely because the answer contains Markdown.
3. A report requires completed, user-authorized scan facts. Never start another scan or query new vulnerability facts during format conversion.

## Scan Type Context

Report content **must** be scoped by the `scan_type` context passed from the caller:

| `scan_type` | Report Content | Available Formats |
|---|---|---|
| `code_scan` | Code vulnerability findings, taint paths, severity breakdown, remediation — **no** SBOM, licenses, or component inventory sections | SARIF, Mermaid JPEG, Markdown, Word, PDF |
| `sbom` | Component inventory, license information, component vulnerability matching — **no** code vulnerability findings, taint paths, or SARIF thread flows | Markdown, Word, PDF, Excel |
| `full_scan` | All of the above: code vulnerabilities + SBOM + licenses + component vulnerabilities | SARIF, Mermaid JPEG, Markdown, Word, PDF, Excel |

**Strict rules:**
- When `scan_type=code_scan`: do not include SBOM sections, license tables, or component inventory in any report format. Skip SARIF, Charts, and Mermaid pipeline steps when generating from SBOM-only data.
- When `scan_type=sbom`: do not include code vulnerability findings, taint diagrams, or SARIF thread flows in any report format. Skip the SARIF, Charts, and Mermaid pipeline steps entirely.
- When `scan_type` is not explicitly provided by the caller, **ask the user to clarify before proceeding**.
- Never mix code vulnerability data into an SBOM report, or SBOM/license data into a code scan report.

## Required Pipeline

1. Resolve `scan_type` context from the caller (`code_scan`, `sbom`, or `full_scan`). If ambiguous or missing, ask the user to clarify before proceeding.
2. Interrupt before report generation and ask for confirmation.
3. Normalize dependency, code finding, evidence snippet, remediation, metrics, and source facts into `secflow.scan-results/v1` JSON. Verify the JSON round trip and payload SHA-256.
4. Invoke SARIF MCP with that exact JSON. Emit SARIF 2.1.0 `codeFlows/threadFlows/locations` for every scanner-supplied taint node, preserving original order, role, file, line, label, and code snippet. Never synthesize or truncate propagation nodes. **Skip this step for `scan_type=sbom`.**
5. Invoke Report Chart MCP with the same scan hash. **Skip this step for `scan_type=sbom`.**
6. Invoke Mermaid MCP with the verified SARIF envelope and chart output. Build one Mermaid flowchart per SARIF thread flow, preserve every location in execution order, retain the auditable Mermaid source, and render it to a hash-verified JPEG. Require SARIF `thread_flow_location_count`, Mermaid `taint_node_count`, and per-image `node_count` to agree. **Skip this step for `scan_type=sbom`.**
7. Invoke SBOM Excel MCP with the finalized CycloneDX JSON for SBOM/full-scan reports. **Skip this step for `scan_type=code_scan`.**
8. Build one canonical `secflow.report-document/v1` JSON containing report blocks, SARIF, Mermaid source metadata, JPEG references, and SHA-256 values. Content scope must respect `scan_type`. Markdown is an output format, not an interchange protocol for Word or PDF.
9. Invoke Markdown MCP to generate the `.md` report and reference each rendered Mermaid JPEG. Keep Mermaid source only as hidden audit metadata; the visible body must not fall back to a Mermaid code block, raw relation JSON, or state dump.
10. Generate HTML directly from canonical JSON blocks and embed the exact hash-verified JPEG bytes.
11. Invoke Word MCP to generate a real `.docx` directly from canonical JSON blocks and embed the same JPEG bytes as document pictures. Preserve headings, real lists, wrapped evidence code, remediation, explicit table geometry, and audit hashes.
12. Invoke PDF MCP to generate `.pdf` directly from canonical JSON blocks and embed the same JPEG bytes as page graphics. Preserve line breaks, code line numbers, Chinese labels, percentages, and China Standard Time.
13. Record one audit entry per MCP: server, tool, status, invocation time, input SHA-256, output SHA-256, media type, artifact size, renderer, and error when applicable.
14. Preserve canonical JSON and SARIF JSON as downloadable audit artifacts when packaging all formats. Do not register an artifact whose signature or output hash fails validation. A request for all formats succeeds only when all available formats for the current `scan_type` are generated.
15. Interrupt again after generation and ask the user whether to download and which format. Only offer formats valid for the current `scan_type`. Preserve single-format, current-report all-formats, and all-report archive choices.

## Report Content

- Keep verified vulnerability evidence snippets and exact line numbers with wrapping that does not overflow the page.
- A taint diagram is complete only when its SARIF thread-flow location count, Mermaid node count, and rendered JPEG node count agree. Do not cap the number of path nodes for layout convenience; grow the image canvas instead.
- Include actionable remediation for each reportable finding.
- Keep vulnerability descriptions user-visible in the selected language while preserving identifiers, package names, versions, code, and URLs.
- Do not restore deprecated “扫描文件与规则”, “格式”, or “模式” sections.
- Do not invent findings, PoCs, exploit steps, fixed versions, source links, or Mermaid relationships.
- If SARIF conversion or Mermaid JPEG rendering fails, stop report generation with an explicit MCP failure. Never substitute raw Python state, relationship JSON, or a text table as the visible relationship diagram.

## HTML And PDF Visual Contract

- Render HTML and PDF with the same `secure-code-scan-v1` visual profile and the same canonical JSON facts.
- Use a blue-to-teal project masthead with report badge, verified project metadata, and a circular risk score. Never fabricate branch, commit, duration, or scan counts to fill the header.
- Follow the masthead with four severity/scope metric cards, then a numbered report layout scoped by `scan_type`:
  - **`code_scan`**: scan overview, two-column vulnerability distribution, finding evidence, remediation priorities, and appendix content when those facts exist.
  - **`sbom`**: scan overview, component inventory, license summary, component vulnerability matching, and appendix content when those facts exist.
  - **`full_scan`**: scan overview, two-column vulnerability distribution, finding evidence, dependency inventory, component vulnerability matching, remediation priorities, and appendix content when those facts exist.
- Use white section cards on a restrained light-gray page, compact colored number badges, Chinese severity labels and percentages, dark line-numbered evidence code, a red vulnerable-code header, and a green remediation-code header.
- Use the same section order, colors, metrics, chart values, code evidence, and Mermaid JPEG bytes in HTML and PDF. A4 pagination may split sections, but headings and code labels must remain with the following content and no table, code line, or URL may overflow.
- Keep responsive HTML readable at desktop and mobile widths. The PDF must preserve the visual hierarchy across pages with page numbers and repeated project identity, without exposing raw JSON or rendering state.

## Evaluation Isolation

- This workflow formats completed user-project scan results only.
- Do not change static rules, AST/CFG/DFG/taint behavior, scanner time limits, frozen 500-project evaluation manifests, truth labels, metrics, failure attribution, or regression gates.
