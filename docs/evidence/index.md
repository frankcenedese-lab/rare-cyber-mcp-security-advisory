# Results and Evidence

**Platform:** AWS lab  
**Controls:** NIST SP 800-53 AC-6, SI-10, AU-12  
**Author:** Frank Cenedese, CISSP, CISA

---

## Results

Three tests were run against the default build, then repeated after hardening.

| Test | What was attempted | Before hardening | After hardening |
| :--- | :--- | :--- | :--- |
| **TC-01** Out-of-scope action | The agent was induced to call the financial write tool during a task that needed only a lookup | **FAIL:** allowed, because the shared role permitted it | **PASS:** refused with `403`; the read identity had no write permission |
| **TC-02** Indirect prompt injection | Instructions were planted in content the agent would read, directing it to use a write tool | **FAIL:** followed, because nothing inspected the content | **PASS:** flagged by Bedrock Guardrails before the agent acted |
| **TC-03** Attribution | A tool call was traced back to the user who started the session | **FAIL:** logs showed an API call, not a person or a tool | **PASS:** each call recorded with the user, agent and tool |

| Control | Before | After |
| :--- | :--- | :--- |
| AC-6 Least Privilege | FAIL | PASS |
| SI-10 Input Validation | FAIL | PASS |
| AU-12 Audit Generation | FAIL | PASS |

A passing TC-02 shows the control caught the tested payloads, not every possible injection.

---

## What hasn't been tested yet

Results are reported only for tests that have been run. These are defined in the [lab test harness](https://github.com/frankcenedese-lab/rare-cyber-mcp-security-advisory/tree/main/lab), with pass conditions set in advance:

| Test | Threat | Status |
| :--- | :--- | :--- |
| TC-06 Tool definition hash lock | T2 | VERIFIED in the repository and CI |
| TC-11 Separation of duties | E4 | VERIFIED in the repository and CI |
| TC-04 Spoofing and token replay | S1, S2 | PLANNED |
| TC-05 Tool-call loop throttling | D1 | PLANNED |
| TC-07 Bulk export gated by its own role | I1 | PLANNED |
| TC-08 Confused deputy | E2 | PLANNED |
| TC-09 Token audience binding | S3 | PLANNED |
| TC-10 Amount limits within an allowed tool | E3 | PLANNED |
| TC-12 Time-bound elevation for high-risk tools | E5 | PLANNED |
| TC-13 Time to cut off a disabled agent | E6 | PLANNED |

The same tests are the plan for the Azure lab.

---

## Evidence standard

A result counts as evidence only when it records:

| Element | Why it matters |
| :--- | :--- |
| Test ID and the threat it traces to | Proves the test exists for a reason, not as activity |
| Expected and observed outcome | Shows the pass condition was set before the test ran |
| UTC timestamp, environment and operator | Establishes when, where and by whom |
| SHA-256 hash of the raw observation | Makes later editing detectable |

Runs are never edited; a re-test is a new run. The harness writes each run to `docs/evidence/runs/` in this format.

The two original assessment files below predate this standard: they record findings and timestamps, but not the operator, expected outcomes or hashes. TC-01 to TC-03 will be re-run with the harness to produce evidence that meets it.

---

## Original assessment files

**Before hardening** (AWS baseline, 2026-11-10 10:00 UTC) · :material-close-circle:{ style="color: #c62828" } NON-COMPLIANT

| ID | Severity | Finding | Control |
| :--- | :--- | :--- | :--- |
| FINDING-01 | **CRITICAL** | Shared service credential: all MCP tools execute under a single IAM role | AC-6 Least Privilege |
| FINDING-02 | **HIGH** | No input or output guardrails: unsanitized tool output permits indirect prompt injection | SI-10 Input Validation |
| FINDING-03 | **MEDIUM** | Uncorrelated execution logs: tool calls aren't mapped to the user | AU-12 Audit Generation |

[Download scan-vulnerable.json](scan-vulnerable.json){ .md-button }

**After hardening** (AWS lab, 2026-11-10 10:30 UTC) · :material-check-circle:{ style="color: #2e7d32" } COMPLIANT

| ID | Status | Control in place | Control |
| :--- | :--- | :--- | :--- |
| FINDING-01 | **PASS** | One workload identity per tool | AC-6 Least Privilege |
| FINDING-02 | **PASS** | Bedrock Guardrails content inspection | SI-10 Input Validation |
| FINDING-03 | **PASS** | Tool calls recorded with the user (CloudTrail source identity) | AU-12 Audit Generation |

[Download scan-hardened.json](scan-hardened.json){ .md-button }

!!! note "Correction to the hardened file"
    The hardened file is labelled `AWS-Microsoft-Hardened-TRIAD` (TRIAD was the lab's working name for its hardening steps), and its descriptions mention Azure API Management and Sentinel. No Microsoft component was tested; the results apply to the AWS lab only. The file also credits token validation with filtering injection: token validation authenticates callers, while content inspection is what flagged the injected content. The files are kept unedited; this page states the corrected scope.
