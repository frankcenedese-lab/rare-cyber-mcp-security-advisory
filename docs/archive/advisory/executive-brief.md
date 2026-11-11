# Appendix: Executive Summary for Decision-Makers

**For:** Security, technology and risk leaders  
**Author:** Frank Cenedese, CISSP, CISA  
**Reading time:** 5 minutes

This appendix restates the report's findings for a non-technical audience: why AI agents are a privileged access problem, what it could mean for an organization, and the decisions it raises.

---

## Bottom line

AI agents connected to business systems now hold the kind of access you would never give a person without approval, monitoring and periodic review. In most deployments they hold it through a single shared credential, can be steered by content they read, and leave logs that can't show who authorized what.

**The risk isn't only that an agent gets tricked. It's that afterwards you can't prove what happened or who was accountable.**

The fix is familiar: treat agents like privileged users. Give each one its own identity, limit each tool to what it needs, inspect what the agent reads, and keep evidence.

---

## Why now

This is no longer theoretical. Two public cases from 2025 show both halves of the problem:

* **An agent turned against its own user.** Researchers showed that a malicious issue posted in a public GitHub repository could hijack a developer's AI agent and make it leak data from the developer's private repositories. The agent was using a broad access token that could reach everything the user could. ([Invariant Labs](https://invariantlabs.ai/blog/mcp-github-vulnerability))
* **A vendor's AI connector leaked across customers.** A logic flaw in Asana's MCP server exposed some customers' data to users at other organizations for over a month, affecting roughly 1,000 customers. ([BleepingComputer](https://www.bleepingcomputer.com/news/security/asana-warns-mcp-ai-feature-exposed-customer-data-to-other-orgs/))

Meanwhile, platforms such as Copilot Studio, Microsoft Foundry and Amazon Bedrock make it easy for business teams to connect agents to systems, and security review often lags behind.

---

## What it could mean for you

| Scenario | Business consequence |
| :--- | :--- |
| A poisoned invoice or email steers a finance agent into posting a journal entry | Financial misstatement, fraud investigation, audit finding on internal controls |
| A support agent with broad CRM access is tricked into exporting customer records | Privacy breach notification, regulator inquiry, customer trust damage |
| An agent takes an action nobody approved, and the logs can't name a person | You can't answer the regulator's, auditor's or insurer's first question: who authorized this? |

---

## Five questions to ask your team this week

1. **Do we have an inventory** of every AI agent in production and pilot, and the systems each one can reach?
2. **Does each agent have its own identity,** or do they run on a shared service account or a developer's personal token?
3. **Are high-risk actions** (payments, data exports, deletions) limited to specific agents and checked on every call?
4. **Is content from outside** (email, documents, tickets, web pages) inspected before an agent acts on it?
5. **If an agent did something harmful tomorrow,** could we name the person, the agent and the policy that allowed it, within a day?

If the answer to any of these is "no" or "not sure," the organization likely has the same exposure the lab baseline had.

---

## What good looks like

<div class="figure-slot" data-figure="attack"></div>

The TRIAD framework describes five outcomes, not products:

| Outcome | In plain terms |
| :--- | :--- |
| **Untrusted content is inspected** | Instructions hidden in documents and emails are caught before the agent acts |
| **Every agent has its own identity, every tool its own permission** | A lookup agent can't make payments, even if it's tricked into trying |
| **Tool definitions can't change silently** | What was approved is what runs |
| **Every action is attributable** | Each tool call is logged with the user, the agent and what it did |
| **The same standard applies on every platform** | AWS, Azure or both: one policy, one set of tests, one evidence standard. On Azure, least privilege must cover both which tools an agent may call and what each tool's own managed identity can reach |

---

## How mature is your agent identity?

The report places agent identity on five levels. Most organizations start at **level 1**, where every tool shares one credential. The lab reached **level 2**: each tool has its own identity and every action is recorded against a person. The levels that matter most for accountability come next: the agent can never do more than the person it acts for (level 3); high-risk actions need time-limited approval and can't be combined, such as posting and approving a payment (level 4); and every agent has an owner, regular access reviews and a measured cut-off time (level 5).

---

## Decisions for leadership

1. **Adopt a standard:** no AI agent reaches production systems without its own identity and scoped permissions.
2. **Fund an inventory:** find every agent and connector already in use, including pilots.
3. **Set the evidence bar:** agree now what proof you'll need to show a board, auditor or insurer that agent controls exist and work.

---

## Standards alignment

| Outcome | NIST SP 800-53 | NIST AI RMF 1.0 | ISO/IEC 42001 |
| :--- | :--- | :--- | :--- |
| Scoped agent and tool identity | AC-2, AC-6 | GOVERN 1.2, MEASURE 2.7 | 6.1.3 AI risk treatment |
| Untrusted content inspection | SI-10 | MEASURE 2.7 | 8.3 AI risk treatment |
| Attributable audit trail | AU-2, AU-12 | MEASURE 2.8 | 9.1 Monitoring and measurement |

The technical design behind these outcomes is in the [Testing Guide](testing-guide.md), and the lab results are on the [Results](../evidence/index.md) page.
