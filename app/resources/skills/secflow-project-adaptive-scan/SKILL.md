---
name: secflow-project-adaptive-scan
description: "Adapt AegisAl scans for one user-uploaded project by fusing static-rule findings with AST/CFG/DFG and taint evidence, then producing a bounded project-only analysis Overlay. Use for uploaded workspace or file scans that need project-specific source, sink, sanitizer, parser-definition, false-positive review, or missed-flow recovery. Never use it to tune, label, or score frozen evaluation corpora."
---

# AegisAl Project Adaptive Scan

## Workflow

1. Infer the requested scan scope and output from the whole conversation and uploaded workspace. Do not trigger or alter the workflow from one keyword alone.
2. Build a project profile from authorized source files, dependency manifests, build metadata, languages, and framework names.
3. Run the frozen static rules and semantic AST/CFG/DFG analysis before proposing any adjustment.
4. Fuse confirmed findings, review candidates, parser gaps, and available runtime or truth evidence into stable evidence IDs.
5. Propose only a project-scoped Overlay. Keep global rules and core parser, CFG, DFG, and taint implementations unchanged.
6. Apply the Overlay in a sandboxed rescan, compare the baseline and adapted results, and stop after three iterations or when no evidence-backed change remains.
7. Preserve the prompt version, skill hash, Overlay hash, evidence IDs, before/after metrics, and termination reason.

## Evidence Rules

- Treat a false negative as verified only when an independent truth label, executable security test, runtime trace, or equivalent external evidence identifies the missed source-to-sink flow.
- Treat a false positive as verified only when evidence proves the source is not controllable, the sink is unreachable, or an effective sanitizer dominates the sink path.
- Do not infer that an undetected vulnerability is absent from an empty scan result.
- Keep uncertain alerts in the review set. Demote rather than delete evidence.
- Require every promotion, demotion, parser definition, and taint model to cite evidence IDs from the current uploaded project.

## Overlay Boundaries

- Allow simple project-specific Semgrep taint sources, sinks, and sanitizers.
- Allow project-specific preprocessor definitions when a manifest, compile database, or parser diagnostic supports them.
- Allow promotion of an existing review candidate and demotion of an existing primary finding.
- Reject arbitrary executable code, shell commands, exploit payloads, global rule edits, and unreferenced claims.
- Keep the Overlay local to the task and version it by a canonical SHA-256 fingerprint.

## User-Facing Result

- Emit real graph events for rules, AST/CFG/DFG, taint analysis, Overlay decisions, rescans, and report interrupts. Never synthesize progress events solely for display.
- Summarize verified findings, affected paths, risk, remediation, evidence sources, and remaining uncertainty with only the applicable Markdown sections.
- Keep tool calls collapsed by default in the client and limit Thinking labels to high-level task names; never expose private chain-of-thought.
- Show public references when present, but hide credentials, private endpoints, internal collections, and complete tool payloads.
- Do not generate weaponized PoCs or attack instructions.

## Evaluation Isolation

- Disable model adaptation and Overlay application for frozen evaluation mode.
- Never expose sealed labels to the adaptation prompt.
- Never use the same samples for model-guided adjustment and qualification scoring.
- Preserve the existing 500-project manifest, baseline scanner behavior, truth artifacts, metrics, failure attribution, and regression gates.
