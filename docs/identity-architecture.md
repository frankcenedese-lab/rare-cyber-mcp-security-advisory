# Identity Architecture: Separating and Constraining Agent Identities

**Method:** Delegated authorization, least privilege in scope and time, identity lifecycle  
**Standards:** MCP authorization specification · OAuth 2.1 · RFC 8693 · RFC 8707 · RFC 9449  
**Status:** Levels 1 and 2 implemented and tested; levels 3 to 5 designed, with tests defined  
**Last reviewed:** November 2026

---

## Why identity is the control plane

Every control in this report ultimately asks one question: **who is allowed to do this, right now, on whose behalf?** Prompt injection steers an agent; identity decides how much damage a steered agent can do. Per-tool roles (level 2) answer only part of that question. They say which tool an agent may call. They don't say for whom, with what limits, for how long, or who is accountable for the agent itself.

This section separates the identities involved, defines a maturity model for constraining them, and maps each level to controls and tests on AWS and Microsoft.

---

## Four identities, not one

| Identity | What it is | What it must never do |
| :--- | :--- | :--- |
| **User** | The person whose request started the session | Gain rights through the agent that they don't hold directly |
| **Agent** | The AI client acting for the user, with its own identity (an IAM role or an Entra Agent ID) | Act with standing rights broader than the current task needs |
| **MCP server** | A resource server that accepts tokens issued for it | Accept a token issued for another server, or forward the token it received |
| **Downstream API** | The system of record (ERP, CRM) the tool finally changes | Receive a token that wasn't issued for it |

The MCP authorization specification makes the third row a requirement: MCP servers act as OAuth resource servers, clients must request tokens bound to a specific server using resource indicators (RFC 8707), and token passthrough to downstream APIs is forbidden ([MCP authorization specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)).

---

## Identity flow: what each token carries

<div class="figure-slot" data-figure="idflow"></div>

Each hop gets a new token, bound to the next audience. The agent's token names both the user (`sub`) and the agent (`act`), so the gateway can cap the agent at the user's rights. The MCP server never forwards that token; it obtains its own for the downstream API.

---

## Agent identity maturity model

<div class="figure-slot" data-figure="maturity"></div>

| Level | Name | What it means | Lab status |
| :--- | :--- | :--- | :--- |
| **1** | Shared credential | Every tool runs under one service identity | Baseline, tested |
| **2** | Per-tool identity | Each tool has its own role; the gateway checks it on every call | Implemented, tested |
| **3** | Delegated and audience-bound | Tokens carry user and agent; each is bound to one server; no passthrough | Designed, tests TC-08, TC-09 |
| **4** | Least privilege in scope and time | Parameter-level policy, separation of duties, just-in-time elevation with approval, sender-constrained tokens | Designed, tests TC-10 to TC-12 |
| **5** | Governed | Every agent has an owner, access reviews, orphan detection, measured revocation and behavioural detection | Designed, test TC-13 |

---

## Level 3: delegated and audience-bound

**Delegation.** The agent exchanges the user's token for one that names both parties. On AWS, the agent assumes the per-tool role with the user set as the session's source identity. With a standards-based identity provider, OAuth token exchange (RFC 8693) adds an `act` claim naming the agent. On Microsoft, the on-behalf-of flow issues a token that keeps the user's identity and roles. Either way, the gateway can refuse any call the user couldn't make directly (TC-08).

**Audience binding.** The agent requests each token for one MCP server, using the `resource` parameter. The gateway and the MCP server reject any token whose audience isn't theirs (TC-09).

**No passthrough.** The MCP server calls the downstream API with a token issued to the server for that API, never the agent's token.

---

## Level 4: least privilege in scope and time

**Parameter-level policy.** A role decides which tool; a policy decides what the call may do. Limits such as a maximum journal amount or an allowed record segment are evaluated per call by a policy engine (Amazon Verified Permissions with Cedar, or a gateway policy in Azure API Management) (TC-10).

```cedar
permit (
  principal in Role::"FinancialWrite",
  action == Action::"post_journal_entry",
  resource
) when { context.amount <= 1000 && context.user_has_finance_role };
```

```xml
<!-- Azure API Management: refuse journal entries above the agent limit -->
<choose>
  <when condition="@((decimal?)context.Request.Body.As<JObject>(preserveContent: true)?["params"]?["arguments"]?["amount"] > 1000)">
    <return-response>
      <set-status code="403" reason="Amount exceeds agent limit" />
    </return-response>
  </when>
</choose>
```

**Separation of duties.** No agent may hold roles that together let it complete a sensitive process alone: posting and approving a journal entry, or changing vendor bank details and releasing a payment. Conflicting pairs are defined in a rule file and checked whenever role assignments change (TC-11).

**Just-in-time elevation.** High-risk tools are not held standing. The agent requests elevation for one task, a person approves it, and a short-lived token is issued that expires when the task ends (TC-12). This is zero standing privilege, applied to agents.

**Sender-constrained tokens.** Where the identity provider supports it, tokens are bound to the agent's key using DPoP (RFC 9449) or mutual TLS, so a stolen token can't be replayed from another machine.

**No static secrets.** Agents and MCP servers authenticate with workload identity federation or managed identities; any remaining secret is held in a vault and rotated.

---

## Level 5: governed

| Control | AWS | Microsoft |
| :--- | :--- | :--- |
| Every agent has a named owner and sponsor | Required resource tags on agent roles | Agent ID sponsor and owner |
| Periodic access review of agent roles | IAM Access Analyzer findings reviewed on a schedule | Entra ID Governance access reviews |
| Orphaned agents detected and removed | Unused role reports | Agents with no sponsor or recent sign-in |
| Revocation measured, not assumed | Revoke active sessions on the role | Disable the agent identity; continuous access evaluation where the resource supports it |
| Unusual agent behaviour detected | GuardDuty and CloudTrail anomaly detection | Entra ID Protection for agents, Sentinel analytics |

Revocation deserves a number. An access token stays valid until it expires unless the resource re-checks it, so "we disabled the agent" can still mean minutes of continued access. TC-13 measures that window.

---

## New tests from this section

| Test | Threat | What is attempted | Pass condition |
| :--- | :--- | :--- | :--- |
| **TC-09** Audience binding | S3 | Present a token issued for one MCP server to another | `401`/`403`; the token is refused for the wrong audience |
| **TC-10** Parameter policy | E3 | Post a journal entry above the agent limit, then one within it | Over the limit refused; within the limit allowed |
| **TC-11** Separation of duties | E4 | Assign an agent two conflicting roles | The conflict is detected and the assignment rejected |
| **TC-12** Just-in-time elevation | E5 | Call the payment tool with a standing token, then with an approved elevated token | Standing token refused; elevated token allowed until it expires |
| **TC-13** Revocation time | E6 | Disable the agent identity while it is making calls | Calls stop within the target time (default 300 seconds); the measured time is recorded |

All five are in the [lab test harness](https://github.com/frankcenedese-lab/rare-cyber-mcp-security-advisory/tree/main/lab). TC-11 runs offline against the role assignment files in the repository.
