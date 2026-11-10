# Threat Model: STRIDE Analysis of the AI Agent Lab

**Method:** STRIDE, extended for agentic AI  
**Scope:** AI agent, MCP gateway, tool server and data in the AWS lab, with Microsoft equivalents  
**Status:** Living model, updated as tests are run  
**Last reviewed:** November 2026

---

## Why threat model first

Every test in this lab exists because the threat model said it should. That is the chain an auditor or reviewer should be able to follow: **threat → control → test → evidence.** If a test can't be traced back to a threat, it's activity, not assurance.

---

## The system being modelled

<div class="figure-slot" data-figure="stride"></div>

| Component | Role in the lab | Trust level |
| :--- | :--- | :--- |
| **External content** | Emails, documents, tickets and web pages the agent reads | Untrusted |
| **User** | The person who starts the agent session | Authenticated |
| **AI agent (MCP client)** | Decides which tools to call based on the user's request and the content it reads | Semi-trusted: it can be steered |
| **Identity provider** | IAM on AWS, Entra Agent ID on Microsoft | Trusted |
| **API gateway** | Amazon API Gateway or Azure API Management; checks every tool call | Trusted control point |
| **Tool registry** | Where approved tool definitions live (Git, Azure API Center) | Trusted, change controlled |
| **MCP tool server** | Read tools, a financial write tool and a data export tool | Trusted, but only as safe as the identity it runs under |
| **Business data** | Finance and customer records | Crown jewels |
| **Audit logging** | CloudTrail on AWS, Sentinel and Purview on Microsoft | Trusted, must be tamper resistant |

**Trust boundaries:** TB1 content to agent · TB2 agent to gateway · TB3 gateway to tool server · TB4 tool server to data · TB5 registry to tool server.

---

## STRIDE analysis

| ID | STRIDE | Threat | Risk | TRIAD control | Test | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **S1** | Spoofing | Agent connects to an unapproved or look-alike MCP server | High | **I** Approved registry; gateway is the only route to tools | TC-04 | PLANNED |
| **S2** | Spoofing | Agent token stolen or replayed from another context | High | **R** Short-lived tokens; Conditional Access for agents | TC-04 | PLANNED |
| **T1** | Tampering | Instructions hidden in content steer the agent (indirect prompt injection) | Critical | **T** Content inspection before the agent acts | TC-02 | TESTED |
| **T2** | Tampering | A tool's definition or description is changed to mislead the agent (tool poisoning) | High | **I** Hashed, version-controlled definitions | TC-06 | TESTED |
| **R1** | Repudiation | A harmful action can't be traced to a user, agent or policy | High | **A** User, agent and tool correlated in one log | TC-03 | TESTED |
| **I1** | Information disclosure | Agent exports records beyond what the task needs | Critical | **R** Export tool gated by its own role | TC-07 | PLANNED |
| **I2** | Information disclosure | Sensitive data leaks into prompts, responses or logs | Medium | DLP and Purview labels; log redaction | Review | OPEN |
| **D1** | Denial of service | Agent loops on tool calls, exhausting quotas or budget | Medium | Gateway rate limits and quotas per agent | TC-05 | PLANNED |
| **E1** | Elevation of privilege | All tools share one role, so a read task can perform writes (Identity Flattening) | Critical | **R** One scoped identity per tool | TC-01 | TESTED |
| **E2** | Elevation of privilege | Confused deputy: agent uses its own broad rights on an attacker's behalf | High | **R** Gateway checks the user's context, not just the agent's | TC-08 | PLANNED |

Risk ratings are initial, set before testing, and are revisited as each test produces evidence.

---

## Where STRIDE falls short for agents

STRIDE assumes each component has one fixed role. An AI agent doesn't: in the same session it acts as a process, a data flow, a store of context and an actor making decisions. Two frameworks cover the gaps:

* **CSA MAESTRO** breaks an agentic system into seven layers, from the foundation model to the agent ecosystem, and catches threats such as memory poisoning and agent-to-agent trust that STRIDE doesn't name.
* **The OWASP Top 10 for Agentic Applications** gives a shared vocabulary for agent-specific risks like goal hijacking and tool misuse.

In this lab, STRIDE is the backbone because every security team already knows it. MAESTRO and OWASP are used as checklists to confirm nothing agent-specific was missed.

---

## How the model is built and maintained

1. **Describe the architecture:** components, identities, tools and trust boundaries, as above.
2. **First pass with tooling:** an AI-assisted tool such as STRIDE GPT, which supports agentic systems, produces a draft list of threats.
3. **Expert review:** every generated threat is accepted, merged or rejected by a practitioner. The tool speeds up the work; the judgement stays human.
4. **Trace to tests:** each accepted threat gets a control and a test on both AWS and Microsoft.
5. **Update on evidence:** when a test runs, its status and the risk rating are updated here and on the [Results](evidence/index.md) page.

Every test is automated in the [lab test harness](https://github.com/frankcenedese-lab/rare-cyber-mcp-security-advisory/tree/main/lab), so any result on this site can be re-run and reproduced.

---

## Planned tests from this model

| Test | Threat | What will be attempted |
| :--- | :--- | :--- |
| **TC-04** Spoofing | S1, S2 | Point the agent at an unregistered MCP server; replay an expired or out-of-context agent token |
| **TC-05** Denial of service | D1 | Drive the agent into a tool-call loop and confirm the gateway throttles it |
| **TC-06** Tool poisoning | T2 | Change a tool description outside the pipeline and confirm the hash check blocks deployment |
| **TC-07** Data export | I1 | Call the export tool with an identity that holds read and write roles but not export |
| **TC-08** Confused deputy | E2 | Have the agent act for a user who lacks write rights, and confirm the gateway refuses |

Full methods for every test, on both platforms, are in the [Testing Guide](advisory/testing-guide.md#5-validation-test-plan).
