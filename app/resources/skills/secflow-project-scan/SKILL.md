---
name: secflow-project-scan
description: "Understand and execute user-authorized project scans, user-requested rescans with baseline comparison, and follow-up questions grounded in stored SecFlow scan evidence. Keep per-run project Overlay adaptation separate from user-level rescans and keep frozen evaluation corpora unchanged."
---

# SecFlow Project Scan

## Semantic Routing

1. Infer the requested outcome from the complete question, attached workspace, active task metadata, task status, and prior scan availability. Do not route from one keyword alone.
2. Select `project_scan` when the user wants to execute code, dependency, AST, CFG, DFG, taint, or security scanning. A missing workspace is a recoverable resource state, not a reason to reinterpret an execution request as general Q&A.
3. Select `project_rescan` only when a completed active scan exists and the user wants a new scan run, regression scan, comparison, or verification after changes.
4. Select `scan_result_follow_up` when the user asks for explanation, remediation, fixed code, verification, prioritization, or other analysis of the stored scan result.
5. Do not confuse a user-level rescan with the bounded project Overlay rescan performed internally during one scan run. A user-level rescan creates a new task linked to an immutable baseline task.
6. If the same request says to scan now and generate or download a report after completion, select the scan intent first. Preserve report generation and download as later human-confirmed operations over the completed canonical scan JSON.

## Project Context Recovery

1. Resolve source access with deterministic, user-isolated code. Priority is the explicit workspace, the current session/task association, an exact artifact-to-project association, and then an unambiguous user-owned historical project.
2. Treat an SBOM or report file name as a display identifier only. Never derive, guess, or construct a local filesystem path from that name.
3. Validate every recovered workspace immediately: it must still exist, be readable, not be a symlink, and not be a filesystem root. Long-term memory proves prior association, not current availability.
4. If the project moved or more than one candidate matches, do not start a scan. Ask the user to keep the source in a locally accessible location and reselect the original project directory.
5. Keep local absolute paths in encrypted local project-link storage. Do not embed them in exported SBOM workbooks, reports, model prompts, or cross-user memory.

## Evidence Contract

1. Load scan facts by task identifier from the task store. Do not rely on conversational memory to reconstruct findings.
2. Ground follow-up answers in canonical finding JSON: rule, severity, location, source, sink, taint path, evidence snippet, remediation, and validation fields.
3. State when evidence is missing or ambiguous. Do not invent code, paths, call chains, fixes, verification results, or resolved findings.
4. Contextualize remediation by actual usage. For example, distinguish password hashing from identifiers, integrity checks, and non-security random offsets.
5. Keep task identifiers, baseline linkage, engine/ruleset fingerprints, finding fingerprints, and result-diff counts auditable.

## Scan Engine MCP Contract

1. For a user-authorized project scan, dispatch every selected language node to `SecFlow Code Scan MCP / scan_language` through the Host-managed local stdio sandbox process. Project-license identification is delegated to the SBOM Agent and its independent `SecFlow License MCP`; the Code Scan MCP does not expose a license tool.
2. Treat the MCP output as untrusted structured data until the result object, input hash, output hash, server identity, tool identity, transport, and process identifier are present and valid.
3. Keep dependency extraction, project profiling, evidence fusion, project Overlay decisions, verification, report interrupts, and task persistence in LangGraph. The Code Scan MCP executes analysis only and must not decide user intent or report actions.
4. Never silently replace a failed user-scan MCP call with an in-process scan. Surface the failure so the task cannot claim independent execution without audit evidence.
5. The MCP may read only relative files already admitted by the authorized workspace inventory. It must not follow symlinks or execute source code, builds, tests, package hooks, or project commands.
6. Project submission must be written to the current user's long-term memory with project name, task identifier, objective, and session ownership. Memory failure must be visible in task audit state but must not cancel the authorized scan.
7. When a scan report includes license facts, they must be the fixed output delegated from the SBOM Agent. Reports carry that canonical license list, evidence files, detection methods, OSI source status, and a non-legal-advice limitation into every generated format without rescanning.
8. **Boundary enforcement** — This skill produces code vulnerability findings only. It must **not** include SBOM data, license information, component inventory, or any output from the SBOM Agent. If the user later requests a combined report, the Supervisor coordinates both skills and passes `scan_type=full_scan` to the Report specialist.

## Rescan Contract

1. Create a new task and preserve the completed task as `baseline_task_id`.
2. Reuse the baseline's authorized workspace only after ownership and availability checks.
3. Compare canonical findings using stable fingerprints rather than display line numbers alone.
4. Report new, resolved, unchanged, and changed findings separately.
5. Never mutate scanner rules, parser behavior, truth labels, evaluation manifests, metrics, or regression gates as a side effect of a user rescan.

## Evaluation Isolation

- User-project scans and rescans may use project-scoped Overlay behavior already supported by the task graph.
- Frozen 500-project evaluation tasks remain isolated, deterministic, and in-process so an MCP transport change cannot alter historical coverage, timing, or qualification metrics.
- Project follow-up answers cannot write global rules or engine syntax.
