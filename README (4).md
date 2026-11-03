# Secure Code Review Agent

A single-file, dependency-free Python agent (`secure_code_review_agent.py`, Python 3.9+) that reviews a unified Git diff for security defects, secrets, risky permission changes and missing tests, then returns **severity-ranked, remediation-ready, draft-only** review comments.

**Core idea:** deterministic scanners establish *facts*; the LLM only *explains and triages* them. A compromised or hallucinating model cannot invent findings, suppress blocking ones, or take any action, because a deterministic validation layer sits between the model and the output.

---

## Architecture

```
                         ┌───────────────────────── MASTER AGENT (ReAct loop) ─────────────────────────┐
 unified diff ──────────▶│ Thought ─▶ Action ─▶ Observation ─▶ … (max 24 steps, closed tool registry)  │
                         │   Planner: deterministic (default) or LLM-chosen; sees workflow state only,  │
                         │   NEVER code. Proposals outside the allowed next-action set are rejected.    │
                         └───────┬───────────────────────────────────────────────────────────┬─────────┘
                                 │ dispatch (permission check → sandbox → retry/timeout)     │
        ┌────────────────────────▼───────────────────────────┐        ┌──────────────────────▼───────────────┐
        │ SANDBOXED WORKERS (forked, rlimit CPU/mem, killed  │        │ TRUSTED IN-PROCESS STEPS             │
        │ on timeout; touch untrusted bytes)                 │        │ consolidate → context → LLM triage → │
        │  get_diff  injection_scan  secret_scan             │        │ validate → draft comments → summary  │
        │  static_scan  check_dependencies  check_test_gaps  │        │ → self_evaluate (critic) → finish    │
        └────────────────────────────────────────────────────┘        └──────────────────────────────────────┘
                                                                                      │
   Human approval gate (outside the loop, TTY only) ◀── draft comments + JSON review ─┘
```

**ReAct trace** (`--trace`) prints each step's Thought, Action and Observation. Fixed dependency order: `get_diff → list_changed_files → run_injection_scan → run_secret_scan → run_static_scan → check_dependencies → check_test_gaps → consolidate_findings → get_file_context → llm_triage → validate_findings → draft_review_comment → create_review_summary → self_evaluate → finish`.

**Master–Worker split**
- *Master:* planning, dispatch, capability enforcement, policy, critic, fail-closed outcome.
- *Workers:* pure functions `dict → dict` run in a child process with CPU/memory limits and a hard timeout. A worker crash or timeout becomes a recorded scan error, never a silent pass.

### MCP-style tools

| Tool | Permission | Runs in |
|---|---|---|
| `get_diff`, `list_changed_files`, `get_file_context` | `repo:read` | sandbox / master |
| `run_injection_scan`, `run_secret_scan`, `run_static_scan`, `check_test_gaps` | `security:scan` | sandbox |
| `check_dependencies` | `dependency:read` | sandbox |
| `llm_triage`, `validate_findings`, `draft_review_comment`, `create_review_summary`, `self_evaluate` | `review:draft` | master |
| *(not in the registry)* `post_review_comment`, `approve_pr`, `merge_pr`, `push_branch`, `change_repo_settings` | `review:post` / `repo:write` / `repo:admin` | **never granted** |

`python secure_code_review_agent.py serve --mcp` exposes a read-only `review_diff` tool over newline-delimited JSON-RPC (stdio). No posting tool exists on that server.

---

## Security model

| Threat | Control |
|---|---|
| **Prompt injection** in code, comments, strings | Diff is data: wrapped in `<untrusted_data nonce=…>` (random nonce, unforgeable closing tag). Regex scanner (`INJ-001`, NFKC-normalised, zero-width stripped) flags attempts as findings and **taints the file**: tainted files get no LLM trust and their code is never sent to the model. Injection lines are replaced by `[NEUTRALIZED-LINE]` in any LLM view. PR title/description are never forwarded. |
| **Role inversion / jailbreak of the reviewer** | Fixed system prompt, JSON-only output, no tools given to the model. Output is schema-checked; free text is sanitised (links, HTML, `@mentions`, control chars removed, injection phrases neutralised, length-capped). |
| **Compromised model** | Model cannot raise severity, cannot suppress critical / secret / blocking (conf ≥ 0.6) findings, cannot create findings without a changed-line anchor plus **verbatim evidence on that line**; LLM findings are capped at confidence 0.7 / severity high and **can never block**. Proven by the evaluation harness with an adversarial model. |
| **Planner hijack** | Planner sees only counts and tool names; any action outside the currently-valid set (including `merge_pr`, `post_review_comment`) is rejected and logged. |
| **Unauthorised action** | Capability grant excludes `review:post`. Posting is outside the agent loop and requires the human to type `APPROVE <review_id>` on an interactive TTY. No flag disables this. `INCOMPLETE` reviews cannot be posted. |
| **Diff-format attacks** | Hunk-count-driven parser (an added `+++ b/other.py` line cannot forge a header); splits on `\n` only (not `str.splitlines`); path traversal / NUL paths rejected; truncated hunks, oversize diffs, too many files → `INCOMPLETE`. |
| **Scanner evasion** | Long lines are scanned in overlapping windows; lines beyond the hard cap → `INCOMPLETE`. Inline `# nosec`/`nosemgrep` is **not honored** (flagged `SUPPRESS-001`). Bidi characters flagged as `TROJAN-001`. |
| **ReDoS / resource abuse** | Workers run in forked children with `RLIMIT_CPU`, `RLIMIT_AS` and wall-clock kill; timeouts are never retried. Diff size/file/finding/LLM-call budgets. |
| **Secret leakage** | Secrets are redacted before evidence, logs, prompts, comments and output; a critic check re-scans the final output for leaks. |
| **Silent failure** | Fail closed: any scanner error → `INCOMPLETE`, never `PASS`. |
| **Audit gaps** | Append-only JSONL (`0600`): diff SHA-256, rules executed, findings, verdicts, model-output hash, self-eval, approval state, trace. |

## Auto-evaluation

1. **Per-run critic (`self_evaluate`)**: eight invariants (C1 findings map to changed lines, C2 critical/high have evidence + fix, C3 no secret leaks, C4 fail-closed, C5 recommendation matches policy, C6 LLM findings never block, C7 draft-only, C8 schema complete). A failure triggers one repair pass (drop unanchored, re-redact, recompute); a second failure → `INCOMPLETE`.
2. **Offline harness (`evaluate`)**: 19 fixtures (secrets, SQLi, command injection, deserialization, auth/authz gaps, weak crypto, SSRF, XSS, Trojan Source, dependency risks, permission escalation, long-line evasion, prompt injection, role inversion, scanner failure, safe look-alikes, clean refactors). Reports recall, precision, severity accuracy, line-localisation accuracy, recommendation accuracy, clean-diff false-positive rate, latency p50/p95, **compromised-LLM resilience** (suite re-run with a model that obeys injected instructions) and **unsafe-action prevention** (forced merge, ungranted capability, wrong/missing approvals, posting an `INCOMPLETE` review). Exits non-zero on any threshold miss.

Result on the bundled suite (mock LLM, this build): recall 1.0, precision 1.0, severity 1.0, line accuracy 1.0, clean-diff FP rate 0.0, unsafe-action rate 0.0, p50 ≈ 17 ms. These are results on fixtures written alongside the rules, so they show the pipeline and guardrails work as designed. They are not a claim about real-world recall. See Limitations.

---

## Usage

```bash
# no install; stdlib only
python secure_code_review_agent.py review --diff pr.diff
git diff origin/main... | python secure_code_review_agent.py review --diff - --format json --trace
python secure_code_review_agent.py review --diff pr.diff --post-comments --require-approval
python secure_code_review_agent.py evaluate
python secure_code_review_agent.py serve --mcp
```

LLM selection: `--llm auto` (default) uses Anthropic if `ANTHROPIC_API_KEY` is set, otherwise the offline deterministic mock. `--llm anthropic --model <id>` (default `claude-sonnet-5-5`, override with `SCRA_MODEL`), `--llm none` for scanners only. If the LLM is unavailable the review **degrades to deterministic-only** (still blocks on critical/high), it does not fail.

Exit codes: `0` PASS/COMMENT · `2` BLOCK · `3` INCOMPLETE · `1` evaluation failed (CI-friendly).

Example:

```
Review REV-eb6dcbcd | Overall risk: CRITICAL | Recommendation: BLOCK

CRITICAL app/a.py:3  PY-CMDI-001  conf=0.85 [human review]
  Possible command injection (shell=True)
  Evidence: subprocess.call("ls " + name, shell=True)
  Fix: Avoid shell=True; pass an argument list and validate inputs against an allowlist.
CRITICAL app/new.py:1  SECRET-DBURL-001  conf=0.95 [human review]
  Evidence: DB="[REDACTED:SECRET-DBURL-001]"
Posted comments: 0 (human approval required)
```

### Output contract (`--format json`)

`review_id, diff_sha256, overall_risk, merge_recommendation (BLOCK|COMMENT|PASS|INCOMPLETE), summary, findings[] (finding_id, rule_id, file, line, severity, confidence, verdict, title, evidence, remediation, cwe, source, attack_scenario, test_recommendation, requires_human_review), test_gaps[], suppressed_count, coverage{files, files_scanned, rules_executed, errors, warnings}, tainted_files[], llm{backend,status,rejected_items}, self_eval{score,repaired,failed}, approval_required:true, posted_comments:0, drafts[]`.

`BLOCK` = at least one scanner finding with severity ≥ high and confidence ≥ 0.6. `COMMENT` = only lower-severity or lower-confidence findings. `PASS` = nothing survived validation **and** every scanner ran. `INCOMPLETE` = any scan error, parse error or limit hit.

## Extending

- **Rules:** add an `R(...)` entry to `STATIC_RULES` (id, severity, confidence, regex, languages, fix, CWE; optional `neg` and `boost`). Add a fixture to `fixtures()` and re-run `evaluate`.
- **Real posting:** replace the outbox write in `post_comments()` with a GitHub/GitLab API call. Keep the approval gate and keep the credential out of the agent loop's grant.
- **LLM backend:** implement `complete(system, user, max_tokens, timeout) -> str`. Output is re-validated regardless of backend.
- **Vulnerability database:** `check_dependencies` uses a small built-in advisory/typosquat list. Add an OSV.dev lookup in a new sandboxed worker with an egress allowlist.

## Limitations (read before production use)

- **Heuristic scanner, not a data-flow engine.** Regex plus light structural checks on changed lines; it can miss multi-line or indirect flows and will produce false positives on look-alikes. The auth/authz checks are heuristics (conf 0.5–0.8). For depth, add Semgrep/CodeQL as another sandboxed worker and feed the results through the same validation layer.
- **Evaluation fixtures are self-authored** and small. Measure on your own labelled PR history before trusting the numbers.
- **Process-level sandbox only.** Fork + rlimits + timeout contain the bundled workers, which run no untrusted code. They are not a security boundary against a hostile kernel exploit. Run the agent in a container with read-only filesystem, dropped capabilities and no network (except the LLM host). On Windows the in-process fallback has no isolation.
- **Injection detection is pattern-based** (English phrases, NFKC-normalised). Novel or multi-line phrasing may evade *detection*. The backstop is the validation layer, which does not depend on detecting it.
- **LLM backends:** the offline mock and the adversarial test model were exercised here. The Anthropic backend follows the documented Messages API but was not run live in this build (no key in the test environment). Smoke-test it with your key.
- **Dependency checks** have no live vulnerability feed and only cover `requirements*.txt` and `package.json`.
- **Diff-only context** by default. `--repo-root` adds path-jailed read-only context.
