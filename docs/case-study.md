# The Build: Breaking and Hardening an AI Agent Environment

**Type:** Hands-on case study  
**Platforms:** AWS lab build · Microsoft control mapping  
**Frameworks:** NIST SP 800-53 · NIST AI RMF · ISO/IEC 42001 · OWASP  
**Built by:** Frank Cenedese, Rare Cyber

---

## At a glance

| | |
| :--- | :--- |
| **The question** | When an AI agent is wired into business systems through the Model Context Protocol (MCP), what can it actually do, and can anyone prove it afterwards? |
| **What I built** | A working MCP environment on AWS with an AI agent, an API gateway and tool functions ranging from read-only lookups to financial writes. |
| **What I did to it** | Deployed it the way most teams do by default, attacked it, hardened it with a control framework I designed (TRIAD), then attacked it again. |
| **What came out** | Before and after assessment evidence, a control mapping to Microsoft's stack, and an executive brief, all published on this site. |

---

## 1. The challenge

Teams are connecting AI agents to real systems faster than security can review them. MCP makes that easy: one server can expose a dozen tools to an agent in an afternoon.

The question I wanted to answer wasn't "can an agent be tricked?" That's well known. It was the auditor's question: **if an agent took a harmful action tomorrow, could the organization show who allowed it, under which policy, and what the agent actually did?**

---

## 2. The environment I built

I deployed the baseline the way a busy team would: working, fast, and trusting defaults.

- An AI agent connected to an MCP tool server through an API gateway
- Tool functions with very different risk levels, from customer lookups to financial journal entries
- **One shared IAM role** used by every tool, read and write alike
- Content guardrails switched off
- Standard API logging, with no link between a tool call and the person behind it

Every one of those choices is common in pilots. Together they create what I call **Identity Flattening**: the agent holds the keys to everything its most powerful tool can reach.

---

## 3. Attacking it

I ran three tests against the baseline. Each one maps to a control in the framework and to a NIST SP 800-53 control.

| Test | What I tried | Result on the baseline |
| :--- | :--- | :--- |
| **Out-of-scope action** | Made the agent call a financial write tool during a task that only needed a lookup | Allowed: the shared role permitted it |
| **Indirect prompt injection** | Planted instructions inside content the agent would read, telling it to use a write tool | Followed: nothing inspected the content |
| **Accountability** | Tried to trace a tool call back to the human user who started the session | Failed: logs showed an API call, not a person or a tool |

The assessment scored the baseline **CRITICAL (8.9/10)** with three failed controls: AC-6 Least Privilege, SI-10 Input Validation and AU-12 Audit Generation.

---

## 4. Hardening it with TRIAD

I designed TRIAD as five controls that can be enforced the same way on any cloud:

- **T**hreat modeling and poison analysis: inspect untrusted content before the agent acts on it
- **R**igid identity decoupling: one scoped identity per tool, checked at the gateway on every call
- **I**mmutable governance: tool definitions version controlled and hashed, so they can't drift
- **A**udit telemetry: every tool call tied to the user, the agent and the arguments
- **D**ual-ecosystem enforcement: the same policy and the same tests on AWS and Microsoft

---

## 5. Results

After hardening, the same three tests were run again.

| Control | Before | After |
| :--- | :--- | :--- |
| Least privilege (AC-6) | FAIL | PASS |
| Input validation (SI-10) | FAIL | PASS |
| Audit generation (AU-12) | FAIL | PASS |

The out-of-scope call was refused at the gateway with a `403`, the injected content was flagged before it reached the agent, and each event was logged with the user, agent and tool together. The full assessment output is on the [Evidence](evidence/index.md) page.

---

## 6. Taking it to Microsoft

Most enterprise AI agents will run on Microsoft: Copilot Studio, Foundry and Microsoft 365 Copilot. I mapped every control to its Microsoft equivalent: Entra Agent ID for agent identity, Azure API Management for scope enforcement, Prompt Shields for injection defence, and Sentinel and Purview for audit. The [Testing Guide](advisory/testing-guide.md) shows how each test runs on both clouds and includes a reference gateway policy, a detection query and the validation test plan.

---

## 7. What this work demonstrates

| For a GRC or advisory role | For an organization adopting AI agents |
| :--- | :--- |
| Designing controls and mapping them to NIST SP 800-53, the NIST AI RMF and ISO/IEC 42001 | A clear picture of what your agents can reach today |
| Producing evidence an auditor will accept, before and after remediation | Controls that work on the cloud you already run |
| Hands-on identity and access architecture across AWS and Microsoft | Evidence your board, auditors and insurer can rely on |
| Writing for both engineers and executives | A roadmap your team can actually implement |

---

*Rare Cyber Advisory Services: Establishing Trust in Enterprise AI Infrastructure.*
