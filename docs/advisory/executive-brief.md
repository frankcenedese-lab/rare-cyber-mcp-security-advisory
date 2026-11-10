# Executive Brief: Your AI Agents Are Becoming Privileged Users

**Prepared for:** Security, technology and risk leaders  
**Author:** Rare Cyber Advisory Services  
**Reading time:** 5 minutes

!!! info "Two ways to read this brief"
    **If you lead security or technology,** this is written for you: the risk, the questions to ask, and the decisions to make.
    **If you're hiring an advisor,** this is a sample of how I brief executives: plain language, real cases, and a clear ask.

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

Meanwhile the platforms are making agents easier to build: Copilot Studio, Microsoft Foundry and Amazon Bedrock all let business teams connect agents to systems with little or no security review.

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

If the answer to any of these is "no" or "not sure," you have the same exposure the lab baseline had.

---

## What good looks like

<div class="figure-slot" data-figure="attack"></div>

The TRIAD baseline describes five outcomes, not products:

| Outcome | In plain terms |
| :--- | :--- |
| **Untrusted content is inspected** | Instructions hidden in documents and emails are caught before the agent acts |
| **Every agent has its own identity, every tool its own permission** | A lookup agent can't make payments, even if it's tricked into trying |
| **Tool definitions can't change silently** | What was approved is what runs |
| **Every action is attributable** | Each tool call is logged with the user, the agent and what it did |
| **The same standard applies on every platform** | AWS, Microsoft or both: one policy, one set of tests, one evidence standard |

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

The technical design behind these outcomes is in the [Testing Guide](testing-guide.md), and the lab results are on the [Evidence](../evidence/index.md) page.

---

*Rare Cyber Advisory Services: Establishing Trust in Enterprise AI Infrastructure.*
