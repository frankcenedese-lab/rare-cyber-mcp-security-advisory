# Threat Model: STRIDE Analysis of the AI Agent Lab

**Method:** STRIDE, checked against CSA MAESTRO and the OWASP Top 10 for Agentic Applications  
**Scope:** AI agent, MCP gateway, tool server and data in the AWS lab, with an Azure reference design (not yet tested)  
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
| **Identity provider** | AWS IAM and STS for workload identities; Entra ID and Agent ID on Azure | Trusted |
| **API gateway** | Amazon API Gateway or Azure API Management; checks every tool call | Trusted control point |
| **Tool registry** | Where approved tool definitions live (Git, Azure API Center) | Trusted, change controlled |
| **MCP tool server** | Four tools: customer lookup, journal entry, journal approval and data export | Trusted, but only as safe as the identity it runs under |
| **Business data** | Finance and customer records | Crown jewels |
| **Audit logging** | CloudTrail on AWS, APIM logs and Sentinel on Azure | Trusted, must be tamper resistant |

**Trust boundaries:** TB1 content to agent · TB2 agent to gateway · TB3 gateway to tool server · TB4 tool server to data · TB5 registry to tool server.

---

## STRIDE analysis

| ID | STRIDE | Threat | Risk | TRIAD control | Test | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **S1** | Spoofing | Agent connects to an unapproved or look-alike MCP server | High | **I** Approved registry; gateway is the only route to tools | TC-04 | PLANNED |
| **S2** | Spoofing | Agent token stolen or replayed from another context | High | **R** Short-lived tokens; Conditional Access for agents (preview on Azure, with documented gaps: see note) | TC-04 | PLANNED |
| **T1** | Tampering | Instructions hidden in content steer the agent (indirect prompt injection) | Critical | **T** Content inspection before the agent acts | TC-02 | TESTED |
| **T2** | Tampering | A tool's definition or description is changed to mislead the agent (tool poisoning) | High | **I** Hashed, version-controlled definitions | TC-06 | VERIFIED |
| **R1** | Repudiation | A harmful action can't be traced to a user, agent or policy | High | **A** User, agent and tool correlated in one log | TC-03 | TESTED |
| **I1** | Information disclosure | Agent exports records beyond what the task needs | Critical | **R** Export tool gated by its own role | TC-07 | PLANNED |
| **I2** | Information disclosure | Sensitive data leaks into prompts, responses or logs | Medium | DLP and Purview labels; log redaction | Review | OPEN |
| **I3** | Information disclosure | Agent leaks data through its own responses: summaries, links or rendered images that carry data out | High | **T** Output inspection and egress controls on responses | Review | OPEN |
| **D1** | Denial of service | Agent loops on tool calls, exhausting quotas or budget | Medium | Gateway rate limits and quotas per agent | TC-05 | PLANNED |
| **E1** | Elevation of privilege | All tools share one role, so a read task can perform writes (Identity Flattening) | Critical | **R** One scoped identity per tool | TC-01 | TESTED |
| **E2** | Elevation of privilege | Confused deputy: agent uses its own broad rights on an attacker's behalf | High | **R** Gateway checks the user's context, not just the agent's | TC-08 | PLANNED |
| **S3** | Spoofing | A token issued for one MCP server is accepted by another, or forwarded downstream | High | **R** Audience-bound tokens; no passthrough | TC-09 | PLANNED |
| **E3** | Elevation of privilege | Agent uses an allowed tool beyond intended limits (amount, records, scope) | High | **R** Parameter-level policy per call | TC-10 | PLANNED |
| **E4** | Elevation of privilege | One agent holds conflicting duties, such as posting and approving | High | **R** Separation of duties rules on role assignment | TC-11 | VERIFIED |
| **E5** | Elevation of privilege | Standing privilege on high-risk tools | High | **R** Just-in-time elevation with human approval | TC-12 | PLANNED |
| **E6** | Elevation of privilege | A compromised agent keeps access after it is disabled | High | **R** Measured revocation; short token lifetimes; on Azure, a gateway block (see note) | TC-13 | PLANNED |

Statuses: **TESTED** means run against the deployed lab; **VERIFIED** means the control logic was checked in the repository and CI, not in a deployed environment; **PLANNED** means a test is defined but not yet run; **OPEN** means no test is defined yet.

**Platform notes for S2 and E6 (Azure).** Conditional Access is evaluated when Entra issues or refreshes a token, not on every call. Microsoft documents that it doesn't govern the token exchange step, doesn't apply when a blueprint creates agents through Microsoft Graph, can't reach an agent that authenticates with an API key, and doesn't cover managed identities. Managed identity tokens can be cached for around 24 hours. On Azure, both threats therefore rely on the gateway: APIM validates every call and can block an agent immediately.

Risk ratings are initial, set before testing, and are revisited as each test produces evidence. Threats S3 and E3 to E6 were added in version 1.2 from the [Identity Architecture](identity-architecture.md) analysis, and I3 in version 1.3.

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
4. **Trace to tests:** each accepted threat gets a control and a test defined for both AWS and Azure.
5. **Update on evidence:** when a test runs, its status and the risk rating are updated here and on the [Results](evidence/index.md) page.

Every test is defined in the [lab test harness](https://github.com/frankcenedese-lab/rare-cyber-mcp-security-advisory/tree/main/lab), so results produced from version 1.1 onward can be re-run and reproduced. TC-03 needs an analyst to attach query output, and TC-13 needs the operator to disable the agent during the run.

---

## Planned tests from this model

| Test | Threat | What will be attempted |
| :--- | :--- | :--- |
| **TC-04** Spoofing | S1, S2 | Point the agent at an unregistered MCP server; replay an expired or out-of-context agent token |
| **TC-05** Denial of service | D1 | Drive the agent into a tool-call loop and confirm the gateway throttles it |
| **TC-06** Tool poisoning | T2 | Change a tool description outside the pipeline and confirm the hash check blocks deployment |
| **TC-07** Data export | I1 | Call the export tool with an identity that holds read and write roles but not export |
| **TC-08** Confused deputy | E2 | Have the agent act for a user who lacks write rights, and confirm the gateway refuses |
| **TC-09** to **TC-13** | S3, E3 to E6 | Audience binding, parameter policy, separation of duties, just-in-time elevation and revocation time; see [Identity Architecture](identity-architecture.md#new-tests-from-this-section) |

Full methods for every test, for AWS and Azure, are in the [Testing Guide](advisory/testing-guide.md#5-validation-test-plan).
