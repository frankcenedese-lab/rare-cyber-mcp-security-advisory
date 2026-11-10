# Testing Guide: Validating TRIAD on AWS and Microsoft

**Author:** Frank Cenedese, CISSP, CISA  
**Environments:** AWS lab build · Microsoft Entra ID and Azure API Management  
**Last reviewed:** November 2026

---

## 1. Two Environments, One Standard

The TRIAD controls were first built and tested in an **AWS** lab: an AI agent calling MCP tools through Amazon API Gateway, with an IAM role per tool and Amazon Bedrock Guardrails. Most enterprise agents will run on **Microsoft** (Microsoft 365 Copilot, Copilot Studio, Microsoft Foundry or Azure OpenAI), so every control has a Microsoft equivalent and the same tests apply to both.

The problem being tested is the same on either cloud. Without identity isolation, every tool an agent can call, from a read-only lookup to a destructive write, runs under one broad identity: **Identity Flattening**.

### Control Equivalence: AWS and Microsoft

```text
AWS HARDENED STACK                             MICROSOFT ENTERPRISE HARDENED STACK
┌─────────────────────────────────┐           ┌─────────────────────────────────┐
│ AWS API Gateway + SigV4         │ ────────► │ Azure API Management (APIM)     │  <-- Endpoint Authentication
├─────────────────────────────────┤           ├─────────────────────────────────┤
│ AWS IAM Role per Tool           │ ────────► │ Entra Agent ID + per-tool roles │  <-- Least Privilege Isolation
├─────────────────────────────────┤           ├─────────────────────────────────┤
│ AWS Bedrock Guardrails          │ ────────► │ Azure AI Content Safety         │  <-- Prompt Injection Defence
│                                 │           │ (Prompt Shields)                │
├─────────────────────────────────┤           ├─────────────────────────────────┤
│ AWS WAF / Macie                 │ ────────► │ Power Platform DLP & Purview    │  <-- Egress & Data Protection
├─────────────────────────────────┤           ├─────────────────────────────────┤
│ CloudWatch & CloudTrail         │ ────────► │ Azure Monitor + Microsoft       │  <-- Audit & Correlation
│                                 │           │ Sentinel / Defender XDR         │
└─────────────────────────────────┘           └─────────────────────────────────┘
```

---

## 2. Microsoft Implementation by TRIAD Pillar

### T: Threat Modeling & Poison Analysis

| Control objective | Microsoft service | How it's applied |
| :--- | :--- | :--- |
| Detect injected instructions in tool output, documents and email | **Azure AI Content Safety: Prompt Shields** | Prompt Shields covers both direct (jailbreak) and indirect attacks, and both are generally available. Send untrusted tool output through the *documents* input so it's evaluated as third-party content, not as the user's prompt. |
| Enforce a strict request contract | **APIM `validate-content` policy** | Reject JSON-RPC payloads that don't match the expected schema before they reach the MCP backend. |
| Limit what the gateway exposes | **APIM MCP server configuration** | Expose only the tools the agent needs. Note that MCP servers built from REST APIs in APIM currently support tools only, not MCP resources or prompts. |

### R: Rigid Identity Decoupling

| Control objective | Microsoft service | How it's applied |
| :--- | :--- | :--- |
| Give every agent its own identity | **Microsoft Entra Agent ID** (generally available) | Agents built in Microsoft Foundry, Copilot Studio and Security Copilot receive an Agent ID automatically. Non-Microsoft agents (including Amazon Bedrock agents) can be integrated through the sidecar or federation patterns. |
| One scope per tool, not one credential for all tools | **App roles on the APIM-fronted API** | Define roles such as `MCPTool.CustomerRead` and `MCPTool.FinancialWrite`. Grant each agent only the roles it needs. |
| Enforce scope at the gateway | **APIM `validate-azure-ad-token` policy** | Check the `roles` claim against the specific tool being called (see the reference policy in section 3). |
| Constrain where and when an agent can authenticate | **Conditional Access for agents** | Requires Entra ID P1. ID Protection for agents requires P2. |
| Remove stored secrets from the gateway to the backend | **Managed identity** | APIM authenticates to the MCP backend with its managed identity rather than a shared key. |

### I: Immutable Governance & Versioning

| Control objective | Microsoft service | How it's applied |
| :--- | :--- | :--- |
| Approved tool inventory | **Azure API Center** | A central registry for MCP servers, both those exposed through APIM and those hosted elsewhere. Anything not registered is treated as shadow AI. |
| Change control on tool definitions | **APIM MCP versioning + Bicep / Terraform** | MCP servers in APIM can be managed through the REST API, ARM, Bicep, the Azure CLI and Terraform. Keep definitions in Git and deploy only through the pipeline. |
| Tamper evidence | **Pipeline hash check** | Hash each tool definition at build time and compare at deploy time. A mismatch fails the release. |

### A: Audit Telemetry & Correlation

| Control objective | Microsoft service | How it's applied |
| :--- | :--- | :--- |
| Gateway level evidence of every tool call | **Azure Monitor / Application Insights** | APIM's built-in integration logs gateway activity, including allowed and denied MCP calls. |
| Agent authentication evidence | **Entra sign-in and audit logs** | For agents with an Agent ID, authentication activity is logged in Entra ID. |
| Copilot Studio agent activity | **Microsoft Purview Audit** | Admin and interaction events are logged in Purview and available through the Office 365 Management API. |
| SOC correlation | **Microsoft Sentinel** | The Microsoft Copilot data connector (public preview) ingests Copilot audit logs into Sentinel and the Sentinel data lake. |
| Runtime agent protection | **Defender for Cloud Apps: AI agent protection** | Monitors Copilot Studio agent activity and raises alerts into Defender XDR incidents alongside identity and endpoint signals. |

### D: Dual-Ecosystem Enforcement

The same tests (section 5) are run against both the AWS and Microsoft environments. A control isn't considered in place on either platform until its test passes and the evidence is retained.

---

## 3. Reference APIM Policy: Per-Tool Scope Enforcement

This pattern reads the MCP tool name from the JSON-RPC request and requires a matching app role in the caller's Entra token. It's a **reference pattern**: test it in a non-production APIM instance before use.

```xml
<policies>
  <inbound>
    <base />
    <!-- Every caller needs a valid Entra token for this API -->
    <validate-azure-ad-token tenant-id="{{tenant-id}}"
                             header-name="Authorization"
                             failed-validation-httpcode="401"
                             failed-validation-error-message="Unauthorized">
      <audiences>
        <audience>{{mcp-api-audience}}</audience>
      </audiences>
    </validate-azure-ad-token>

    <!-- Identify which tool is being called -->
    <set-variable name="toolName"
      value="@(context.Request.Body.As<JObject>(preserveContent: true)?["params"]?["name"]?.ToString() ?? "")" />

    <!-- High-risk tools require their own role -->
    <choose>
      <when condition="@(context.Variables.GetValueOrDefault<string>("toolName") == "post_journal_entry")">
        <validate-azure-ad-token tenant-id="{{tenant-id}}"
                                 header-name="Authorization"
                                 failed-validation-httpcode="403"
                                 failed-validation-error-message="Scope missing: MCPTool.FinancialWrite">
          <audiences>
            <audience>{{mcp-api-audience}}</audience>
          </audiences>
          <required-claims>
            <claim name="roles" match="any">
              <value>MCPTool.FinancialWrite</value>
            </claim>
          </required-claims>
        </validate-azure-ad-token>
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

---

## 4. Reference Sentinel Query: Denied Tool Calls

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

## 5. Validation Test Plan

Each test traces to a threat in the [Threat Model](../threat-model.md) and a finding in the [evidence baseline](../evidence/index.md) and runs the same way in both environments. Results are recorded only after a test has been run.

| Test | Finding | What is attempted | AWS check | Microsoft check | Pass condition |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TC-01** Out-of-scope tool call | FINDING-01 | Call a financial write tool with an identity scoped only for reads | API Gateway IAM authorization denies the call | APIM `validate-azure-ad-token` rejects the missing role | `403`, logged with the caller identity |
| **TC-02** Indirect prompt injection | FINDING-02 | Return a poisoned document from a read tool; automate variations with **PyRIT** | Bedrock Guardrails prompt attack filter | Prompt Shields document analysis | Attack detected; no write tool invoked |
| **TC-03** Identity correlation | FINDING-03 | Trigger a tool call from a named test user | CloudTrail event links user, role and tool | Sentinel links user, Agent ID and tool | One query returns user, agent and tool together |
| **TC-04** Spoofing *(planned)* | S1, S2 | Connect to an unregistered MCP server; replay an out-of-context agent token | Gateway rejects unknown backends; IAM rejects expired session | APIM blocks unregistered servers; Entra rejects the token | Both attempts refused and logged |
| **TC-05** Denial of service *(planned)* | D1 | Drive the agent into a tool-call loop | API Gateway throttling and usage plans | APIM `rate-limit-by-key` per agent | Calls throttled; alert raised |
| **TC-06** Tool poisoning *(planned)* | T2 | Change a tool description outside the pipeline | Pipeline hash check fails the release | Bicep deployment hash check fails | Change blocked before it reaches the agent |
| **TC-07** Data export *(planned)* | I1 | Call the export tool with an identity holding read and write roles but not export | IAM denies the export role's actions | APIM requires `MCPTool.ExportWrite` | `403`, logged with the caller identity |
| **TC-08** Confused deputy *(planned)* | E2 | Agent acts for a user who lacks write rights | Source identity on the role session checked against the user's entitlements | On-behalf-of token carries the user's roles; APIM checks them | `403`; the agent can't exceed the user |
| **TC-09** Audience binding *(planned)* | S3 | Present a token issued for a different MCP server | Gateway and server check `aud` against their own resource | APIM `validate-azure-ad-token` audience check; server validates `aud` | `401`/`403`; downstream calls use the server's own token |
| **TC-10** Parameter policy *(planned)* | E3 | Post a journal entry over the agent limit, then one within it | Amazon Verified Permissions (Cedar) policy on `amount` | APIM `choose` policy on `amount` | Over limit refused; within limit allowed |
| **TC-11** Separation of duties | E4 | Add a conflicting role to an agent's assignments | `lab/sod_check.py` in CI | Same check, plus Entra ID Governance separation of duties on access packages | Conflict detected; assignment rejected |
| **TC-12** Just-in-time elevation *(planned)* | E5 | Call the payment tool with a standing token, then an approved elevated token | Short-session role assumed after approval | Approved, time-bound role assignment | Standing refused; elevated allowed until expiry |
| **TC-13** Revocation time *(planned)* | E6 | Disable the agent while it is calling tools | Revoke active sessions on the role | Disable the agent identity | Cut off within 300 seconds; time recorded |

---

## Running the Tests

All thirteen tests are automated in the [lab test harness](https://github.com/frankcenedese-lab/rare-cyber-mcp-security-advisory/tree/main/lab), except TC-03, which needs an analyst to run a query and attach the result, and TC-13, which asks the operator to disable the agent mid-test. Each run writes a timestamped evidence file with a SHA-256 hash of every observation, so results can be reproduced and can't be quietly edited.

```bash
python lab/triad_tests.py --platform azure
python lab/triad_tests.py --platform aws --only TC-01 TC-07
```

---

## 6. Licensing and Platform Notes

* **Entra Agent ID** is available to all Entra customers. Extending Entra security features to agents requires **Microsoft Agent 365**, which is included in Microsoft 365 E7 and sold as an add-on to E5, A5 and Business Premium.
* **Conditional Access for agents** needs Entra ID P1; **ID Protection for agents** needs P2.
* External MCP servers proxied through APIM must conform to MCP version **2025-06-18 or later**.
* The **Sentinel Copilot data connector** is in public preview.
* Independent research has reported **gaps in Copilot Studio admin logging**, where some documented activities did not produce events. Don't rely on Purview alone; correlate with Entra and APIM logs.

---

## 7. Microsoft References

* [About MCP servers in Azure API Management](https://learn.microsoft.com/en-us/azure/api-management/mcp-server-overview)
* [Expose and govern an existing MCP server](https://learn.microsoft.com/en-us/azure/api-management/expose-existing-mcp-server)
* [What is Microsoft Entra Agent ID?](https://learn.microsoft.com/en-us/entra/agent-id/what-is-microsoft-entra-agent-id)
* [What's new in Microsoft Entra Agent ID](https://learn.microsoft.com/en-us/entra/agent-id/whats-new-agent-id)
* [Prompt Shields in Azure AI Content Safety](https://learn.microsoft.com/en-us/azure/ai-services/content-safety/concepts/jailbreak-detection)
* [Copilot Studio activity logging](https://learn.microsoft.com/en-us/microsoft-copilot-studio/admin-logging-copilot-studio)
* [Audit logs for Copilot and AI activities](https://learn.microsoft.com/en-us/purview/audit-copilot)
* [Microsoft Copilot data connector for Sentinel (preview)](https://techcommunity.microsoft.com/t5/microsoft-sentinel-blog/the-microsoft-copilot-data-connector-for-microsoft-sentinel-is/ba-p/4491986)
* [Copilot Studio logging gaps (Datadog Security Labs)](https://securitylabs.datadoghq.com/articles/copilot-studio-logging-gaps/)
