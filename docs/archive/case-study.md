# Method and Environment: Building and Hardening the AI Agent Lab

**Platforms:** AWS lab (tested) · Azure reference design (validation in progress)  
**Frameworks:** NIST SP 800-53 · NIST AI RMF · ISO/IEC 42001 · OWASP  
**Author:** Frank Cenedese, CISSP, CISA

---

## At a glance

| | |
| :--- | :--- |
| **Question** | When an AI agent is connected to business systems through the Model Context Protocol (MCP), what can it actually do, and can anyone prove it afterwards? |
| **Environment** | An MCP environment on AWS: one AI agent, an API gateway and four tools ranging from a read-only lookup to financial writes, approvals and exports. |
| **Method** | Deploy with default settings, assess, harden with a control framework (TRIAD), and re-assess with the same tests. |
| **Outputs** | A threat model, an identity architecture, configuration and policy changes before and after, an automated test harness and assessment evidence. |

---

## 1. The question

Organizations are connecting AI agents to production systems faster than security teams can review them. MCP makes that connection simple: one server can expose many tools to an agent with little configuration.

Whether an agent can be manipulated is already well established. This lab asks the auditor's question instead: **if an agent took a harmful action, could the organization show who allowed it, under which policy, and what the agent actually did?**

---

## 2. The environment

The baseline was deployed the way a team building a pilot often would: working, fast and relying on defaults.

- An AI agent connected to an MCP tool server through Amazon API Gateway
- Four tools with different risk levels: `customer_lookup` (read), `post_journal_entry` (financial write), `approve_journal_entry` (approval) and `export_records` (bulk export)
- **One shared IAM role** used by every tool, read and write alike
- Content guardrails not configured
- Standard API logging, with no link between a tool call and the person behind it

Together, these defaults create **Identity Flattening**: the agent holds the keys to everything its most powerful tool can reach.

The attack scenarios use one agent. The separation of duties checks added in version 1.2 define three agent identities (finance, reporting and approvals) to model which duties may and may not be combined.

---

## 3. Assessment of the baseline

Three tests were run against the baseline. Each maps to a TRIAD control and a NIST SP 800-53 control.

| Test | What was attempted | Result on the baseline |
| :--- | :--- | :--- |
| **Out-of-scope action** | The agent was induced to call the financial write tool during a task that needed only a lookup | Allowed: the shared role permitted it |
| **Indirect prompt injection** | Instructions were planted in content the agent would read, directing it to use a write tool | Followed: nothing inspected the content |
| **Accountability** | A tool call was traced back to the user who started the session | Failed: logs showed an API call, not a person or a tool |

The baseline failed three controls: AC-6 Least Privilege, SI-10 Input Validation and AU-12 Audit Generation.

---

## 4. Hardening with TRIAD

TRIAD is an acronym of its five elements, not a reference to three controls. The first four are controls; the fifth is the principle that governs how they're applied.

- **T**hreat modelling and poison analysis: inspect untrusted content before the agent acts on it
- **R**igid identity decoupling: one scoped identity per tool
- **I**mmutable governance: tool definitions version controlled and hashed, so they can't drift
- **A**udit telemetry: every tool call recorded with the user, the agent and the arguments
- **D**ual-ecosystem enforcement: the same policy and the same tests on every platform. AWS is tested; Azure is the next validation target

---

## 5. Results

After hardening, the same three tests were run again.

| Control | Before | After |
| :--- | :--- | :--- |
| Least privilege (AC-6) | FAIL | PASS |
| Input validation (SI-10) | FAIL | PASS |
| Audit generation (AU-12) | FAIL | PASS |

The out-of-scope call was refused with a `403`, because the identity used for the read task held no permission for the write tool. The injected content was flagged by Bedrock Guardrails before the agent acted on it. Each tool call was recorded with the user, agent and tool together.

Recording the user is **attribution**: it answers who was behind an action. It isn't yet **authorization by the user's rights**, where the agent is refused anything the user couldn't do directly. That is level 3 of the agent identity maturity model, designed in the [Identity Architecture](identity-architecture.md) section and tested by TC-08.

The assessment output is on the [Results](evidence/index.md) page, threats not covered by these three tests are listed in the [Threat Model](threat-model.md), and the report's limits are set out in [Scope and Limitations](limitations.md).

---

## 6. Applying the design on Azure

The results above are from AWS. The same problem exists on Azure, but in a different form, and an equivalent that only maps service names misses it.

On Azure, the over-provisioned account is usually **one managed identity shared by every tool** in the MCP server, holding broad Azure roles and often a tenant-wide Microsoft Graph permission. Least privilege has to be applied at two layers:

- **Caller authorization:** which tools an agent may call. API Management checks a per-tool app role in the agent's token.
- **Tool credential:** what each tool can reach. Each tool runs with its own user-assigned managed identity, scoped to one resource.

Several Azure behaviours change how the controls work: managed identity tokens can be cached for around 24 hours, Conditional Access doesn't cover managed identities, and a managed identity call carries no user downstream. The [Testing Guide](advisory/testing-guide.md) sets out the Azure reference design, the platform differences and the Azure method for each test. No Azure test has been run yet; results will be added once they are.

Agents built in Copilot Studio or Microsoft 365 Copilot use connectors with their own credentials and don't pass through a customer gateway by default. They need a separate analysis and are out of scope for this report.
