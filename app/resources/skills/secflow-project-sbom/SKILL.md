---
name: secflow-project-sbom
description: Build an auditable CycloneDX-compatible SBOM JSON and Excel workbook from a user-authorized project, own project-license identification through a capability-scoped MCP and OSI License API, optionally match versioned components, and answer read-only follow-ups from stored SBOM facts. Use when the user wants a software bill of materials, project dependency inventory, supply-chain component inventory, license inventory, equivalent workbook, or existing SBOM result details. Do not use for ordinary code vulnerability scans or frozen evaluation corpora.
---

# SecFlow Project SBOM

## Semantic Routing

1. Infer the desired outcome from the complete user objective, attached workspace, conversation context, requested artifact, and destination. Do not require the literal token `SBOM` and do not route from one keyword alone.
2. Use this workflow only when a project workspace is authorized and the requested output is a project software-component inventory or its Excel artifact.
3. Keep ordinary code scanning, static-rule analysis, AST/CFG/DFG/taint analysis, and scan-report generation on their existing workflows.
4. **Boundary enforcement** — This skill produces SBOM, license, and component data only. It must **not** include code vulnerability findings, taint paths, SARIF data, or any output from Code Scan. If the user later requests a combined report, the Supervisor coordinates both skills and passes `scan_type=full_scan` to the Report specialist.

## Required Workflow

1. Resolve and validate the authorized project path without allowing symlink scope expansion.
2. Read only authoritative dependency manifests and lockfiles. If none are present, return an empty component inventory with an explicit warning; never inspect source imports or invoke static code analysis as a fallback.
3. As the SBOM Agent, call the independent `SecFlow License MCP` tool `identify_project_licenses`. Code Scan, Conversation, and Report agents cannot invoke it. Detect SPDX identifiers, structured manifest license fields, and project license files without running project code.
4. Standardize detected licenses with `https://opensource.org/api/licenses`. Preserve the local result if OSI is unavailable, mark coverage `partial`, and never translate an upstream failure into “no license”.
5. Normalize extracted dependencies and project-license evidence into one CycloneDX-compatible JSON document before invoking any workbook tool. Attach project licenses to `metadata.component.licenses` and retain evidence and API audit fields.
6. Interrupt and ask whether the user wants component vulnerability intelligence matching. Match only concrete component versions; label unresolved versions and partial coverage explicitly.
7. Keep vulnerability matches separate and auditable, translate every user-visible vulnerability description to Simplified Chinese while preserving identifiers, package names, versions, URLs, and the original source description in audit JSON, then attach CycloneDX `vulnerabilities` entries to matching component `bom-ref` values.
8. Interrupt again before generating Excel. The Excel MCP must consume the already-fixed JSON and must not re-query or rewrite source facts.
9. Generate the sheets `摘要`, `SBOM 组件`, `项目许可`, `漏洞匹配`, and `来源与审计` with wrapped cells, readable widths, frozen headers, filters, JSON fingerprints, OSI status, and coverage status.
10. Interrupt after generation and ask whether to download. Available formats for SBOM reports: **Excel (.xlsx), Markdown (.md), Word (.docx), PDF (.pdf)**. Do not offer SARIF or Mermaid — those are code-scan-only formats. If the user requested Desktop, Downloads, or Documents, emit only a destination hint; the native client must resolve the current user's system directory.

## Result Follow-up

1. Persist a user-isolated operation reference after every SBOM interrupt: thread identifier, project/session association, component count, matching coverage and counts, matching records, license facts, artifacts, and pending interrupt kind.
2. When the same user asks what vulnerabilities, components, or licenses the generated SBOM contains, route to `sbom_result_follow_up`. Read the pending checkpoint without advancing it; if the checkpoint has completed and been cleaned, use the encrypted operation snapshot.
3. A result follow-up is never an implicit confirmation or cancellation. Preserve the original generation/download interrupt, and do not re-query vulnerability intelligence unless the user explicitly asks for a fresh match.
4. Do not place complete SBOM JSON in a general LLM prompt. The SBOM Agent formats deterministic facts directly from the checkpoint or snapshot.

## Evidence And Safety

- Preserve ecosystem, component, version, source manifest, declaration, confidence, package URL, and the original vulnerability description when available. The `漏洞匹配` worksheet must display a complete Simplified Chinese description rather than copying English source text.
- Never claim a versionless component is vulnerability-free. Mark it as unresolved and excluded from version-specific matching.
- Never turn a timeout or upstream failure into a clean result. Record partial coverage and batch failures.
- OSI `approved=false` means the API did not provide a positive approval marker; do not automatically present it as a legal conclusion that a license is prohibited or invalid.
- Do not execute project build scripts, package lifecycle hooks, or arbitrary repository commands to produce the SBOM.
- Do not expose credentials, private API endpoints, absolute workspace paths, or internal collection names in the workbook.
- State that automated license identification is an engineering inventory aid, not legal advice, and that dependency package licenses require separate repository or release-artifact verification.

## Evaluation Isolation

- This is a user-project artifact workflow only.
- Do not modify scanner rules, parser behavior, project Overlay behavior, frozen evaluation manifests, truth labels, metrics, failure attribution, or regression gates.
