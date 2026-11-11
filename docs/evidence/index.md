# Results and Evidence

Results from the lab, reported only for tests that have been run. The run log comes first, then the evidence standard, then the original baseline and hardened findings. Each finding maps to a NIST SP 800-53 control and to a validation test in the [Testing Guide](../advisory/testing-guide.md#5-validation-test-plan).

Statuses: **PASS** means the test was run against the deployed lab. **VERIFIED** means the control logic was checked in the repository and CI, not in a deployed environment. **PLANNED** means the test is defined but not yet run.

## Test run log

| Test | Threat | AWS | Azure | Notes |
| :--- | :--- | :--- | :--- | :--- |
| TC-01 Out-of-scope tool call | E1 | PASS | PLANNED | v1.0 baseline (2026-11-10 10:00 UTC) and hardened (10:30 UTC) assessments, AWS lab |
| TC-02 Indirect prompt injection | T1 | PASS | PLANNED | v1.0 assessments, AWS lab |
| TC-03 Identity correlation | R1 | PASS | PLANNED | v1.0 assessments, AWS lab: user recorded for attribution |
| TC-04 Spoofing | S1, S2 | PLANNED | PLANNED | Defined in v1.1 |
| TC-05 Denial of service | D1 | PLANNED | PLANNED | Defined in v1.1 |
| TC-06 Tool poisoning | T2 | VERIFIED | VERIFIED | Hash check logic verified in the repository harness and CI, 2026-11-10; deployment pipelines not yet tested |
| TC-07 Data export | I1 | PLANNED | PLANNED | Defined in v1.1 |
| TC-08 Confused deputy | E2 | PLANNED | PLANNED | Defined in v1.1 |
| TC-09 Audience binding | S3 | PLANNED | PLANNED | Defined in v1.2 |
| TC-10 Parameter policy | E3 | PLANNED | PLANNED | Defined in v1.2 |
| TC-11 Separation of duties | E4 | VERIFIED | VERIFIED | Role assignment check verified in the repository harness and CI, 2026-11-10; IAM and Entra assignments not yet tested |
| TC-12 Just-in-time elevation | E5 | PLANNED | PLANNED | Defined in v1.2 |
| TC-13 Revocation time | E6 | PLANNED | PLANNED | Defined in v1.2 |

Harness output for each run is committed under `docs/evidence/runs/` and listed here with its date.

!!! note "About this evidence"
    The baseline files below are from the lab environment; account identifiers are placeholders. New results come from the [lab test harness](https://github.com/frankcenedese-lab/rare-cyber-mcp-security-advisory/tree/main/lab) and are added to the run log as each test is run.

## Evidence standard

A result counts as evidence only when it records:

| Element | Why it matters |
| :--- | :--- |
| Test ID and the threat it traces to | Proves the test exists for a reason, not as activity |
| Expected and observed outcome | Shows the pass condition was set before the test ran |
| UTC timestamp, environment and operator | Establishes when, where and by whom |
| SHA-256 hash of the raw observation | Makes later editing detectable |
| Attached output for manual tests | Lets a reviewer re-perform the check |

Runs are never edited. A re-test is a new run.

The two v1.0 assessment files below predate this standard: they record findings and timestamps but not the operator, expected outcomes or hashes. TC-01 to TC-03 will be re-run with the harness to produce evidence that meets it.

---

## Erratum (version 1.3)

The hardened assessment file is labelled `AWS-Microsoft-Hardened-TRIAD`, and its descriptions of FINDING-02 and FINDING-03 mention Azure API Management and Sentinel. Those Microsoft components were not tested; the results apply to the **AWS lab only**. FINDING-02's description also credits token (JWT) validation with filtering injection: token validation authenticates callers, while content inspection (Bedrock Guardrails in the lab) is what flags injected content. The files are kept unedited under the evidence standard; the tables below state the corrected scope.

---

## Before hardening

**Environment:** AWS baseline, unhardened · **Status:** :material-close-circle:{ style="color: #c62828" } NON-COMPLIANT

| ID | Pillar | Severity (v1.0) | Finding | NIST control |
| :--- | :--- | :--- | :--- | :--- |
| FINDING-01 | Rigid Identity Decoupling | **CRITICAL** | Shared service credential detected (Identity Flattening). All MCP tools execute under a single IAM role. | AC-6 Least Privilege |
| FINDING-02 | Threat Modelling & Poison Analysis | **HIGH** | Missing input/output guardrails. Unsanitized tool output permits indirect prompt injection. | SI-10 Input Validation |
| FINDING-03 | Audit Telemetry & Correlation | **MEDIUM** | Uncorrelated execution logs. Tool calls aren't mapped to the user principal. | AU-12 Audit Generation |

Severities are as recorded in the v1.0 assessment. The v1.1 threat model re-rated indirect prompt injection (T1) as Critical and attribution (R1) as High.

[Download scan-vulnerable.json](scan-vulnerable.json){ .md-button }

---

## After hardening

**Environment:** AWS lab, TRIAD hardened (see erratum) · **Status:** :material-check-circle:{ style="color: #2e7d32" } COMPLIANT

| ID | Pillar | Status | Control in place | NIST control |
| :--- | :--- | :--- | :--- | :--- |
| FINDING-01 | Rigid Identity Decoupling | **PASS** | Per-tool workload identities (`MCPTool.CustomerRead` vs `MCPTool.FinancialWrite`) | AC-6 Least Privilege |
| FINDING-02 | Threat Modelling & Poison Analysis | **PASS** | Bedrock Guardrails content inspection flags indirect prompt injection | SI-10 Input Validation |
| FINDING-03 | Audit Telemetry & Correlation | **PASS** | Tool calls recorded with the user principal for attribution (CloudTrail) | AU-12 Audit Generation |

[Download scan-hardened.json](scan-hardened.json){ .md-button }
