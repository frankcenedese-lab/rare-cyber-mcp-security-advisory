# Testing Guide: Validating TRIAD on AWS and Azure

**Author:** Frank Cenedese, CISSP, CISA  
**Environments:** AWS lab (tested) · Azure reference design (validation in progress)  
**Last reviewed:** November 2026

---

## 1. Two environments, one standard

The TRIAD controls were built and tested in an **AWS** lab: an AI agent calling MCP tools through Amazon API Gateway, with an IAM role per tool and Amazon Bedrock Guardrails. This guide also sets out the **Azure** reference design for the same lab: an MCP server on Azure Functions behind Azure API Management, with Entra ID identities.

!!! note "Status"
    AWS results are tested. The Azure column is a reference design based on Microsoft's documentation; no Azure test has been run yet. Agents built in Copilot Studio or Microsoft 365 Copilot follow a different model and are out of scope.

The problem being tested is the same on either cloud. Without identity isolation, every tool an agent can call, from a read-only lookup to a destructive write, runs under one broad identity: **Identity Flattening**.

### Least privilege has two layers

| Layer | Question | AWS lab | Azure reference design |
| :--- | :--- | :--- | :--- |
| **Caller authorization** | Which tools may this agent call? | MCP server checks the tool's `required_role` | APIM checks a per-tool app role in the agent's token |
| **Tool credential** | What can each tool reach once it runs? | One IAM execution role per Lambda function | One user-assigned managed identity per tool, each in its own Function app, with Azure RBAC at resource scope |

The over-provisioned account the lab found sits in the second layer. On AWS it was one IAM role shared by every tool. **On Azure it is usually one managed identity shared by every tool**, holding broad roles such as Contributor and often a tenant-wide Microsoft Graph permission. A design that only checks which tools an agent may call leaves that account in place.

### Control equivalence

<div class="figure-slot" data-figure="matrix"></div>

| Control | AWS (tested) | Azure (reference design) |
| :--- | :--- | :--- |
| Endpoint authentication | API Gateway with IAM (SigV4) | API Management with `validate-azure-ad-token` |
| Caller authorization per tool | Check in the MCP server | APIM policy reading the tool name from the request body |
| Tool credential | IAM execution role per tool | User-assigned managed identity per tool; Graph narrowed with Sites.Selected or Exchange RBAC for Applications |
| Agent identity | IAM role for the agent runtime | Entra agent identity from an agent identity blueprint, with a sponsor |
| Prompt injection defence | Bedrock Guardrails (`ApplyGuardrail` on tool output) | Prompt Shields in Azure AI Content Safety (document mode) |
| Edge protection | AWS WAF | Azure WAF (Application Gateway or Front Door) in front of APIM |
| Sensitive data discovery | Amazon Macie | Microsoft Purview, Defender for Storage sensitive data threat detection |
| Audit and correlation | CloudTrail and CloudWatch | APIM logs in Log Analytics, Entra sign-in logs, Microsoft Sentinel |

### Where Azure differs from AWS

These differences change how a control is built or tested, not just which service provides it.

| Topic | AWS | Azure | Consequence |
| :--- | :--- | :--- | :--- |
| **Separating tool identities** | Each Lambda has one execution role | Any code in an app can request a token for any managed identity attached to it | One identity per tool only works if each tool runs in its own app or container |
| **Scope of permissions** | IAM policies can name individual resource ARNs | Azure RBAC can be scoped to a resource, but Microsoft Graph application permissions are tenant wide by default | Narrow Graph access with Sites.Selected or Exchange RBAC for Applications, and remove the broad permission |
| **Token lifetime** | STS role sessions can be as short as 15 minutes | Managed identity tokens are cached per resource for around 24 hours and can't be force refreshed | The 60 and 15 minute standard can't be met with managed identities; the gateway becomes the short-lived control |
| **Access conditions** | IAM condition keys on any role | Conditional Access covers agent identities (preview) and single-tenant service principals (Workload Identities Premium), not managed identities, API keys or the token exchange step | Don't count on Conditional Access for the tool layer |
| **Revocation** | Revoke the role's active sessions | Disabling an identity stops new tokens; issued tokens run to expiry. Continuous access evaluation for workloads covers Microsoft Graph only and excludes managed identities | Block at APIM first; TC-13 measures both |
| **User attribution downstream** | Source identity stays on the role session and appears in CloudTrail | A managed identity call carries no user | The APIM trace (C3) is the only record linking user, agent and tool |
| **Where per-tool checks run** | In the MCP server, because API Gateway authorizers can't read the request body | In APIM, which can read the body | Azure can enforce at the gateway; AWS enforces in the server |

---

## 2. Azure implementation by TRIAD pillar

### T: Threat modelling and poison analysis

| Control objective | Azure or Microsoft service | How it's applied |
| :--- | :--- | :--- |
| Detect injected instructions in tool output, documents and email | **Azure AI Content Safety: Prompt Shields** | Prompt Shields covers both direct (jailbreak) and indirect attacks, and both are generally available. Send untrusted tool output through the *documents* input so it's evaluated as third-party content, not as the user's prompt. |
| Enforce a strict request contract | **APIM `validate-content` policy** | Reject JSON-RPC payloads that don't match the expected schema before they reach the MCP backend. |
| Limit what the gateway exposes | **APIM MCP server configuration** | Expose only the tools the agent needs. Note that MCP servers built from REST APIs in APIM currently support tools only, not MCP resources or prompts. |

### R: Rigid identity decoupling

| Control objective | Azure or Microsoft service | How it's applied |
| :--- | :--- | :--- |
| Give every agent its own identity | **Microsoft Entra Agent ID** | Create agent identities from an **agent identity blueprint**, one blueprint per agent class, each with at least one sponsor. Agents built on current versions of Microsoft Foundry, Copilot Studio and Security Copilot receive an Agent ID automatically; older agents may have none, which is itself an assessment finding. Non-Microsoft agents (including Amazon Bedrock agents) can be integrated through the sidecar or federation patterns. |
| One scope per tool, not one credential for all tools | **App roles on the APIM-fronted API** | Define roles such as `MCPTool.CustomerRead` and `MCPTool.FinancialWrite`. Grant each agent only the roles it needs. |
| Enforce scope at the gateway | **APIM `validate-azure-ad-token` policy** | Check the `roles` claim against the specific tool being called (see the reference policy in section 3). |
| Limit what each tool can reach | **User-assigned managed identity per tool** | Each tool runs in its own Function app with one identity, granted a data-plane role on one resource (see C1 in [Configuration](../configuration.md)). Narrow Graph access with Sites.Selected or Exchange RBAC for Applications. |
| Constrain where and when an agent can authenticate | **Conditional Access for agents** (preview) | Requires Entra ID P1 or P2 and a Microsoft Agent 365 license per user. Evaluated when a token is issued or refreshed; doesn't cover managed identities, API-key access or the token exchange step. ID Protection for agents requires P2 during preview. |
| Remove stored secrets from the gateway to the backend | **Managed identity for APIM** | APIM authenticates to the MCP backend with its own managed identity rather than a shared key. This protects the gateway hop; the tool credentials are covered above. |

### I: Immutable governance and versioning

| Control objective | Azure or Microsoft service | How it's applied |
| :--- | :--- | :--- |
| Approved tool inventory | **Azure API Center** | A central registry for MCP servers, both those exposed through APIM and those hosted elsewhere. Anything not registered is treated as shadow AI. |
| Change control on tool definitions | **APIM MCP versioning + Bicep / Terraform** | MCP servers in APIM can be managed through the REST API, ARM, Bicep, the Azure CLI and Terraform. Keep definitions in Git and deploy only through the pipeline. |
| Tamper evidence | **Pipeline hash check** | Hash each tool definition at build time and compare at deploy time. A mismatch fails the release. |

### A: Audit telemetry and correlation

| Control objective | Azure or Microsoft service | How it's applied |
| :--- | :--- | :--- |
| Gateway level evidence of every tool call | **Azure Monitor / Application Insights** | APIM's built-in integration logs gateway activity, including allowed and denied MCP calls. |
| Agent authentication evidence | **Entra sign-in and audit logs** | For agents with an Agent ID, authentication activity is logged in Entra ID. |
| Copilot Studio agent activity | **Microsoft Purview Audit** | Admin and interaction events are logged in Purview and available through the Office 365 Management API. |
| SOC correlation | **Microsoft Sentinel** | The Microsoft Copilot data connector (public preview) ingests Copilot audit logs into Sentinel and the Sentinel data lake. |
| Runtime agent protection | **Defender for Cloud Apps: AI agent protection** | Monitors Copilot Studio agent activity and raises alerts into Defender XDR incidents alongside identity and endpoint signals. |

### D: Dual-ecosystem enforcement

The same tests (section 5) are defined for both AWS and Azure. AWS has been tested; Azure is next. A control isn't considered in place on either platform until its test passes and the evidence is retained.

---

## 3. Reference APIM policy: per-tool scope enforcement

This pattern reads the MCP method and tool name from the JSON-RPC request. Every caller needs a valid token for the API; every tool call needs the role for that tool; any tool not listed is refused. It's a **reference pattern**: test it in a non-production APIM instance before use.

```xml
<policies>
  <inbound>
    <base />
    <!-- Every caller needs a valid Entra token for this API -->
    <validate-azure-ad-token tenant-id="{{tenant-id}}" header-name="Authorization"
        failed-validation-httpcode="401" failed-validation-error-message="Unauthorized">
      <audiences>
        <audience>{{mcp-api-audience}}</audience>
      </audiences>
    </validate-azure-ad-token>

    <!-- Identify the MCP method and tool -->
    <set-variable name="mcpMethod"
      value="@(context.Request.Body.As<JObject>(preserveContent: true)?["method"]?.ToString() ?? "")" />
    <set-variable name="toolName"
      value="@(context.Request.Body.As<JObject>(preserveContent: true)?["params"]?["name"]?.ToString() ?? "")" />
    <set-variable name="requiredRole" value="@{
      switch (context.Variables.GetValueOrDefault<string>("toolName")) {
        case "customer_lookup":       return "MCPTool.CustomerRead";
        case "post_journal_entry":    return "MCPTool.FinancialWrite";
        case "approve_journal_entry": return "MCPTool.FinancialApprove";
        case "export_records":        return "MCPTool.ExportWrite";
        default:                      return "";
      }
    }" />

    <choose>
      <!-- Default deny: a tool call for an unlisted tool is refused -->
      <when condition="@(context.Variables.GetValueOrDefault<string>("mcpMethod") == "tools/call"
                         && context.Variables.GetValueOrDefault<string>("requiredRole") == "")">
        <return-response>
          <set-status code="403" reason="Tool not permitted" />
        </return-response>
      </when>
      <!-- Every listed tool requires its own role in the token -->
      <when condition="@(context.Variables.GetValueOrDefault<string>("mcpMethod") == "tools/call"
                         && !(context.Request.Headers.GetValueOrDefault("Authorization","").Split(' ').Last()
                              .AsJwt()?.Claims.GetValueOrDefault("roles", "") ?? "").Split(',')
                              .Contains(context.Variables.GetValueOrDefault<string>("requiredRole")))">
        <return-response>
          <set-status code="403" reason="Role missing for this tool" />
        </return-response>
      </when>
    </choose>
  </inbound>
  <backend>
    <base />
  </backend>
  <outbound>
    <base />
  </outbound>
  <on-error>
    <base />
  </on-error>
</policies>
```

On AWS, API Gateway authorizers can't read the request body, so the same per-tool check runs in the MCP server against each tool's `required_role` (see [Configuration](../configuration.md)).

---

## 4. Reference Sentinel query: denied tool calls

A starting point for detecting agents that repeatedly attempt tools outside their scope. It assumes APIM diagnostics are sent to Log Analytics in resource-specific mode.

```kql
ApiManagementGatewayLogs
| where TimeGenerated > ago(24h)
| where ApiId has "mcp"
| where ResponseCode in (401, 403)
| summarize DeniedCalls = count() by ApiId, CallerIpAddress, bin(TimeGenerated, 1h)
| where DeniedCalls > 5
| order by DeniedCalls desc
```

---

## 5. Validation test plan

Each test traces to a threat in the [Threat Model](../threat-model.md); TC-01 to TC-03 also trace to findings in the v1.0 [assessment](../evidence/index.md). Each has a method for both environments, and results are recorded only after a test has been run. Azure methods are design until run.

| Test | Traces to | What is attempted | AWS check | Azure check | Pass condition |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TC-01** Out-of-scope tool call | E1 · FINDING-01 | Call a financial write tool with an identity scoped only for reads | MCP server per-tool role check refuses the call; the read role has no write permission | Both layers: APIM refuses the call for the missing app role, and, calling the write resource directly with the read tool's managed identity, Azure RBAC returns `403 AuthorizationFailed` | `403`, logged with the caller identity |
| **TC-02** Indirect prompt injection | T1 · FINDING-02 | Return a poisoned document from a read tool; automate variations with **PyRIT** | Bedrock Guardrails prompt attack filter via `ApplyGuardrail` on tool output | Prompt Shields document analysis | Attack detected; no write tool invoked |
| **TC-03** Identity correlation | R1 · FINDING-03 | Trigger a tool call from a named test user | CloudTrail event links user, role and tool | Sentinel query over the APIM `mcp-audit` trace links user (`oid`), agent (`azp`) and tool. The downstream managed identity call carries no user, so the APIM record is the evidence | One query returns user, agent and tool together |
| **TC-04** Spoofing *(planned)* | S1, S2 | Connect to an unregistered MCP server; replay an out-of-context agent token | Gateway rejects unknown backends; IAM rejects expired session | APIM blocks unregistered servers; Entra rejects the token | Both attempts refused and logged |
| **TC-05** Denial of service *(planned)* | D1 | Drive the agent into a tool-call loop | API Gateway throttling and usage plans | APIM `rate-limit-by-key` per agent | Calls throttled; alert raised |
| **TC-06** Tool poisoning *(verified in repository)* | T2 | Change a tool description outside the pipeline | Pipeline hash check fails the release | Bicep deployment hash check fails | Change blocked before it reaches the agent |
| **TC-07** Data export *(planned)* | I1 | Call the export tool with an identity holding read and write roles but not export | MCP server requires `MCPTool.ExportWrite`; IAM denies the export role's actions | APIM requires `MCPTool.ExportWrite` | `403`, logged with the caller identity |
| **TC-08** Confused deputy *(planned)* | E2 | Agent acts for a user who lacks write rights | Amazon Verified Permissions checks the source identity's entitlements | On-behalf-of token carries the user's roles; APIM checks them | `403`; the agent can't exceed the user |
| **TC-09** Audience binding *(planned)* | S3 | Present a token issued for a different MCP server | Cognito token `aud` checked; roles scoped to resource ARNs | APIM `validate-azure-ad-token` audience check; server validates `aud` | `401`/`403`; downstream calls use the server's own token |
| **TC-10** Parameter policy *(planned)* | E3 | Post a journal entry over the agent limit, then one within it | Amazon Verified Permissions (Cedar) policy on `amount` | APIM `choose` policy on `amount` | Over limit refused; within limit allowed |
| **TC-11** Separation of duties *(verified in repository)* | E4 | Add a conflicting role to an agent's assignments | `lab/sod_check.py` in CI | Same check, plus Entra ID Governance separation of duties on access packages | Conflict detected; assignment rejected |
| **TC-12** Just-in-time elevation *(planned)* | E5 | Call the payment tool with a standing token, then an approved elevated token | Short-session role assumed after approval | Approval workflow grants the role, and APIM enforces the expiry (removing a managed identity's role doesn't end access promptly). Method to be verified | Standing refused; elevated allowed until expiry |
| **TC-13** Revocation time *(planned)* | E6 | Disable the agent while it is calling tools | Revoke active sessions on the role | Measure two times: blocking the agent at APIM, and disabling the agent identity. Also record how long a tool's managed identity keeps access after its role is removed | Cut off within 300 seconds at the control point; all times recorded |

---

## 6. Running the tests

All thirteen tests are defined in the [lab test harness](https://github.com/frankcenedese-lab/rare-cyber-mcp-security-advisory/tree/main/lab), except TC-03, which needs an analyst to run a query and attach the result, and TC-13, which asks the operator to disable the agent mid-test. Each run writes a timestamped evidence file with a SHA-256 hash of every observation, so results can be reproduced and can't be quietly edited.

```bash
python lab/triad_tests.py --platform azure
python lab/triad_tests.py --platform aws --only TC-01 TC-07
```

---

## 7. Licensing, platform notes and vendor claims

* **Entra Agent ID** is available to all Entra customers. Extending Entra security features to agents requires **Microsoft Agent 365**, which is included in Microsoft 365 E7 and sold as an add-on to E5, A5 and Business Premium.
* **Conditional Access for agents** is in preview and requires Entra ID P1 or P2 plus an Agent 365 license per user; Microsoft states that Agent 365 licensing enforcement is coming. **ID Protection for agents** requires P2 during preview.
* **Conditional Access for workload identities** (service principals) requires Workload Identities Premium and doesn't cover managed identities.
* External MCP servers proxied through APIM must conform to MCP version **2025-06-18 or later**.
* The **Sentinel Copilot data connector** is in public preview.
* Independent research has reported **gaps in Copilot Studio admin logging**, where some documented activities did not produce events. Don't rely on Purview alone; correlate with Entra and APIM logs.

### Vendor claims vs documented behaviour

Vendor material describes what a product is for. An assessment has to establish what it actually enforces. Four claims from Microsoft's agent security announcements, read against Microsoft's own documentation:

| Claim | What the documentation shows | What still has to be tested |
| :--- | :--- | :--- |
| Agent 365 enforces least privilege for agents with Conditional Access and blueprints | Conditional Access decides whether a token is issued: which agent, under what risk, from where. It doesn't decide what the agent does with a tool once it has a token, and it has documented gaps (token exchange, API keys, managed identities) | Per-tool authorization and tool credentials (TC-01, TC-07, TC-10) |
| One registry for agents from Microsoft, AWS, Google and others | Registration gives visibility. Entra enforces policy only where Entra issues the token; an agent using AWS IAM to reach AWS resources isn't governed by Conditional Access | Enforcement on each platform separately (the D in TRIAD) |
| Sign-in logs record every authentication attempt, policy hit and failure | True for authentication. Which tool was called, with what arguments and result, isn't in sign-in logs | Gateway records linking user, agent and tool (TC-03) |
| Microsoft's agentic security system keeps every decision "scoped, traceable, and replayable" | The product page (Project Perception, in preview) doesn't describe how its agents are authenticated or authorized, or what high-impact actions need human sign-off | Ask for the agents' identities, permissions, approval thresholds and audit records before granting remediation rights |


---

## 8. Microsoft references

* [About MCP servers in Azure API Management](https://learn.microsoft.com/en-us/azure/api-management/mcp-server-overview)
* [Expose and govern an existing MCP server](https://learn.microsoft.com/en-us/azure/api-management/expose-existing-mcp-server)
* [What is Microsoft Entra Agent ID?](https://learn.microsoft.com/en-us/entra/agent-id/what-is-microsoft-entra-agent-id)
* [What's new in Microsoft Entra Agent ID](https://learn.microsoft.com/en-us/entra/agent-id/whats-new-agent-id)
* [Conditional Access for agent identities](https://learn.microsoft.com/en-us/entra/identity/conditional-access/agent-id)
* [Conditional Access for workload identities](https://learn.microsoft.com/en-us/entra/identity/conditional-access/workload-identity)
* [Managed identities FAQ: token caching](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/managed-identities-faq)
* [Continuous access evaluation for workload identities](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation-workload)
* [Selected permissions in Microsoft Graph](https://learn.microsoft.com/en-us/graph/permissions-selected-overview)
* [RBAC for Applications in Exchange Online](https://learn.microsoft.com/en-us/exchange/permissions-exo/application-rbac)
* [Project Perception (product page)](https://www.microsoft.com/en-us/security/business/ai-powered-cybersecurity/project-perception-agentic-system)
* [Prompt Shields in Azure AI Content Safety](https://learn.microsoft.com/en-us/azure/ai-services/content-safety/concepts/jailbreak-detection)
* [Copilot Studio activity logging](https://learn.microsoft.com/en-us/microsoft-copilot-studio/admin-logging-copilot-studio)
* [Audit logs for Copilot and AI activities](https://learn.microsoft.com/en-us/purview/audit-copilot)
* [Microsoft Copilot data connector for Sentinel (preview)](https://techcommunity.microsoft.com/t5/microsoft-sentinel-blog/the-microsoft-copilot-data-connector-for-microsoft-sentinel-is/ba-p/4491986)
* [Copilot Studio logging gaps (Datadog Security Labs)](https://securitylabs.datadoghq.com/articles/copilot-studio-logging-gaps/)
