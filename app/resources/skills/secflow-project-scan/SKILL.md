---
name: secflow-project-scan
description: Understand and execute user-authorized project scans, user-requested rescans with baseline comparison, and follow-up questions grounded in stored SecFlow scan evidence. Keep per-run project Overlay adaptation separate from user-level rescans and keep frozen evaluation corpora unchanged.
---

# SecFlow Project Scan

## Semantic Routing

1. Infer the requested outcome from the complete question, attached workspace, active task metadata, task status, and prior scan availability. Do not route from one keyword alone.
2. Select `project_scan` only when a workspace is available and the user wants code, dependency, AST, CFG, DFG, taint, or security scanning.
3. Select `project_rescan` only when a completed active scan exists and the user wants a new scan run, regression scan, comparison, or verification after changes.
4. Select `scan_result_follow_up` when the user asks for explanation, remediation, fixed code, verification, prioritization, or other analysis of the stored scan result.
5. Do not confuse a user-level rescan with the bounded project Overlay rescan performed internally during one scan run. A user-level rescan creates a new task linked to an immutable baseline task.

## Evidence Contract

1. Load scan facts by task identifier from the task store. Do not rely on conversational memory to reconstruct findings.
2. Ground follow-up answers in canonical finding JSON: rule, severity, location, source, sink, taint path, evidence snippet, remediation, and validation fields.
3. State when evidence is missing or ambiguous. Do not invent code, paths, call chains, fixes, verification results, or resolved findings.
4. Contextualize remediation by actual usage. For example, distinguish password hashing from identifiers, integrity checks, and non-security random offsets.
5. Keep task identifiers, baseline linkage, engine/ruleset fingerprints, finding fingerprints, and result-diff counts auditable.

## Rescan Contract

1. Create a new task and preserve the completed task as `baseline_task_id`.
2. Reuse the baseline's authorized workspace only after ownership and availability checks.
3. Compare canonical findings using stable fingerprints rather than display line numbers alone.
4. Report new, resolved, unchanged, and changed findings separately.
5. Never mutate scanner rules, parser behavior, truth labels, evaluation manifests, metrics, or regression gates as a side effect of a user rescan.

## Evaluation Isolation

- User-project scans and rescans may use project-scoped Overlay behavior already supported by the task graph.
- Frozen 500-project evaluation tasks remain isolated and deterministic.
- Project follow-up answers cannot write global rules or engine syntax.
