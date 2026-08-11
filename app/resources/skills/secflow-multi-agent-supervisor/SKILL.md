---
name: secflow-multi-agent-supervisor
description: Coordinate SecFlow specialist agents through explicit, auditable handoffs. Use for assistant questions, authorized project scans, SBOM generation, full scans (code scan + SBOM), component intelligence, vulnerability research, scan follow-up, and report operations. When a user requests a scan without specifying the type, ask them to choose: code scan, SBOM scan, or full scan. Give each specialist only its allowed tools, preserve human interrupts, and keep online project adaptation isolated from frozen evaluation corpora.
---

# SecFlow Multi-Agent Supervisor

## Planning And Handoff

1. Understand the requested outcome from the complete question, authorized workspace state, active task, artifacts, and conversation context. Do not route from one keyword alone.
2. Select exactly one initial specialist: Project Context, Code Scan, Component Intelligence, SBOM, Vulnerability Intelligence, Report, or Security Conversation.
3. Use Project Context only to recover and validate a user-owned workspace. After successful validation, hand off to Code Scan or SBOM; otherwise stop and ask the user to reselect the source directory.
4. Use Code Scan for an actual project scan, user-requested rescan, or a follow-up grounded in a stored scan task. Use SBOM for dependency, license, supply-chain, or software-bill-of-materials artifacts and for read-only follow-ups grounded in the current user's latest SBOM operation.
5. Use Report only for generation or download from completed fixed scan facts. Report generation and filesystem download must retain separate human interrupts.
6. Record every handoff with source agent, target agent, selected capability, and a concise reason. Never expose private chain-of-thought.
7. When one request asks to execute a scan and mentions a report only as a later, confirmation-gated outcome, hand off to Code Scan first. A future report clause must never bypass task creation or the completed-scan gate.

## Scan Type Confirmation

When a user requests a scan but does **not** explicitly specify the scan type (e.g., "扫描这个项目", "scan this project", or other ambiguous phrasing), the Supervisor **must** interrupt and ask the user to choose via `AskUserQuestion` **before** dispatching to any specialist:

| Option | Description | Dispatch Target | `scan_type` Context |
|---|---|---|---|
| **代码扫描 (Code Scan)** | 仅执行代码安全扫描，检测源代码漏洞，生成代码漏洞报告 | Code Scan → Report | `code_scan` |
| **SBOM 扫描 (SBOM Scan)** | 仅生成软件物料清单和许可证报告，含组件漏洞匹配 | SBOM → Report | `sbom` |
| **完整扫描 (Full Scan)** | 执行代码扫描 + SBOM 生成，报告包含代码漏洞和 SBOM/许可证 | Code Scan → SBOM → Report | `full_scan` |

When the user explicitly specifies a scan type (e.g., "代码扫描", "SBOM", "完整扫描", "code scan", "SBOM scan", "full scan"), dispatch directly to the corresponding specialist without asking.

## Full Scan Pipeline

For `scan_type=full_scan`, execute the following sequence. Each step requires user confirmation before proceeding to the next:

1. **Code Scan** — Hand off to Code Scan specialist. Execute `scan_language` for each detected language. Produce canonical scan JSON with code vulnerability findings.
2. **SBOM Generation** — After code scan completion, hand off to SBOM specialist. Extract dependency manifests, identify licenses, normalize CycloneDX JSON, optionally match component vulnerabilities.
3. **Comprehensive Report** — After both complete, hand off to Report specialist with `scan_type=full_scan` context. Generate reports containing code vulnerabilities + SBOM + licenses + component vulnerabilities. Available formats: SARIF, Mermaid JPEG, Markdown, Word, PDF, Excel.
4. **Download** — Ask the user whether to download and which format.

Report specialist receives `scan_type=full_scan` and includes all sections: vulnerability distribution, finding evidence, dependency inventory, component vulnerability matching, license summary, and remediation priorities.

## Agent Boundaries

- The Supervisor may plan and hand off but cannot scan files, query vulnerability providers, generate artifacts, or modify rules.
- Project Context may read encrypted project links and user-owned task metadata but cannot infer a path from an SBOM or report name.
- Code Scan may create or rescan authorized tasks and call only `scan_language` on the loopback SSE Code Scan MCP. It cannot identify project licenses, generate reports, or promote project overlays into global rules.
- SBOM exclusively owns project-license identification, may extract dependencies, match component vulnerabilities, answer stored SBOM-result follow-ups, and invoke the SBOM Excel MCP. It cannot perform source-code vulnerability scanning or consume a pending interrupt during a read-only follow-up.
- Component and Vulnerability Intelligence agents may query their respective verified data capabilities but cannot access local project paths.
- Report may consume canonical scan JSON, fixed SBOM Agent license facts, and format-specific MCP outputs but cannot scan licenses, rescan, or change vulnerability facts. Report content must respect `scan_type` context: `code_scan` excludes SBOM/license sections, `sbom` excludes code vulnerability/taint sections, `full_scan` includes all.
- Result Aggregator may merge public structured results and audit metadata but cannot call analysis tools.

## Safety And Evaluation Isolation

1. Keep local absolute paths, credentials, provider configuration, private collection names, and raw tool payloads outside model-visible and exported data.
2. Limit online self-adaptation to a versioned project/task Overlay with evidence IDs, bounded iterations, and rescan comparison.
3. Never let an online agent edit global static rules, parser behavior, CFG/DFG/taint implementations, truth labels, evaluation manifests, or regression gates.
4. Keep the frozen 500-project evaluation deterministic and isolated. Only an offline evaluation workflow may propose global promotion after all qualification gates pass.
5. Stop on ambiguous ownership, unavailable workspaces, failed MCP audit validation, stale interrupts, or incomplete scan results instead of claiming success.
