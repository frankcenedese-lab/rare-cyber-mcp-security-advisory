# Evidence Baseline

Assessment output from the TRIAD baseline, before and after hardening. Each finding maps to a NIST SP 800-53 control and to a validation test in the [Testing Guide](../advisory/testing-guide.md#5-validation-test-plan).

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

---

## Before hardening

**Environment:** AWS baseline, unhardened · **Status:** :material-close-circle:{ style="color: #c62828" } NON-COMPLIANT · **Risk score:** CRITICAL (8.9/10)

| ID | Pillar | Severity | Finding | NIST control |
| :--- | :--- | :--- | :--- | :--- |
| FINDING-01 | Rigid Identity Decoupling | **CRITICAL** | Shared service credential detected (Identity Flattening). All MCP tools execute under a single IAM role. | AC-6 Least Privilege |
| FINDING-02 | Threat Modeling & Poison Analysis | **HIGH** | Missing input/output guardrails. Unsanitized tool output permits indirect prompt injection. | SI-10 Input Validation |
| FINDING-03 | Audit Telemetry & Correlation | **MEDIUM** | Uncorrelated execution logs. Tool calls aren't mapped to the user principal. | AU-12 Audit Generation |

[Download scan-vulnerable.json](scan-vulnerable.json){ .md-button }

---

## After hardening

**Environment:** AWS + Microsoft, TRIAD hardened · **Status:** :material-check-circle:{ style="color: #2e7d32" } COMPLIANT · **Risk score:** LOW (0.2/10)

| ID | Pillar | Status | Control in place | NIST control |
| :--- | :--- | :--- | :--- | :--- |
| FINDING-01 | Rigid Identity Decoupling | **PASS** | Per-tool workload identities (`MCPTool.CustomerRead` vs `MCPTool.FinancialWrite`) | AC-6 Least Privilege |
| FINDING-02 | Threat Modeling & Poison Analysis | **PASS** | Guardrails and APIM JWT/schema policies filter indirect prompt injection | SI-10 Input Validation |
| FINDING-03 | Audit Telemetry & Correlation | **PASS** | Tool calls correlated to the user principal in Sentinel | AU-12 Audit Generation |

[Download scan-hardened.json](scan-hardened.json){ .md-button }
