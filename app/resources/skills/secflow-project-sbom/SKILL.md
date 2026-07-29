---
name: secflow-project-sbom
description: Build an auditable CycloneDX-compatible SBOM JSON and Excel workbook from a user-authorized project, optionally matching versioned components against vulnerability intelligence. Use when the user wants a software bill of materials, project dependency inventory, supply-chain component inventory, or equivalent workbook. Do not use for ordinary code vulnerability scans or frozen evaluation corpora.
---

# SecFlow Project SBOM

## Semantic Routing

1. Infer the desired outcome from the complete user objective, attached workspace, conversation context, requested artifact, and destination. Do not require the literal token `SBOM` and do not route from one keyword alone.
2. Use this workflow only when a project workspace is authorized and the requested output is a project software-component inventory or its Excel artifact.
3. Keep ordinary code scanning, static-rule analysis, AST/CFG/DFG/taint analysis, and scan-report generation on their existing workflows.

## Required Workflow

1. Resolve and validate the authorized project path without allowing symlink scope expansion.
2. Prefer authoritative manifests and lockfiles, then use supported source imports only when no project manifest is available.
3. Normalize extracted dependencies into one CycloneDX-compatible JSON document before invoking any workbook tool.
4. Interrupt and ask whether the user wants component vulnerability intelligence matching. Match only concrete component versions; label unresolved versions and partial coverage explicitly.
5. Keep vulnerability matches separate and auditable, translate every user-visible vulnerability description to Simplified Chinese while preserving identifiers, package names, versions, URLs, and the original source description in audit JSON, then attach CycloneDX `vulnerabilities` entries to matching component `bom-ref` values.
6. Interrupt again before generating Excel. The Excel MCP must consume the already-fixed JSON and must not re-query or rewrite source facts.
7. Generate the sheets `摘要`, `SBOM 组件`, `漏洞匹配`, and `来源与审计` with wrapped cells, readable widths, frozen headers, filters, JSON fingerprints, and coverage status.
8. Interrupt after generation and ask whether to download. If the user requested Desktop, Downloads, or Documents, emit only a destination hint; the native client must resolve the current user's system directory.

## Evidence And Safety

- Preserve ecosystem, component, version, source manifest, declaration, confidence, package URL, and the original vulnerability description when available. The `漏洞匹配` worksheet must display a complete Simplified Chinese description rather than copying English source text.
- Never claim a versionless component is vulnerability-free. Mark it as unresolved and excluded from version-specific matching.
- Never turn a timeout or upstream failure into a clean result. Record partial coverage and batch failures.
- Do not execute project build scripts, package lifecycle hooks, or arbitrary repository commands to produce the SBOM.
- Do not expose credentials, private API endpoints, absolute workspace paths, or internal collection names in the workbook.

## Evaluation Isolation

- This is a user-project artifact workflow only.
- Do not modify scanner rules, parser behavior, project Overlay behavior, frozen evaluation manifests, truth labels, metrics, failure attribution, or regression gates.
