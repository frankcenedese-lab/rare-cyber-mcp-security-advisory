# Evidence Baseline

Assessment output from the TRIAD baseline, before and after hardening. Each finding maps to a NIST SP 800-53 control and to a validation test in the [Microsoft Architecture Guide](../advisory/azure-copilot-mapping.md#5-validation-test-plan).

!!! note "About this evidence"
    These files are a **sample of the assessment output format** produced against a lab environment. Account identifiers are placeholders. Microsoft results are added as each test in the validation plan is run in a tenant.

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
