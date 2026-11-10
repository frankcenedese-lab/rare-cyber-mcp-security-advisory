# Enterprise Architectural Guide: Securing Model Context Protocol (MCP) in Microsoft Entra ID & Azure APIM

**Author:** Rare Cyber Advisory Services  
**Target Audience:** Enterprise Security Architects, Azure Administrators, and DevSecOps Engineers  
**Classification:** Technical Advisory Architecture Baseline  
**Last reviewed:** November 2026

---

## 1. Executive Context & System Architecture

While hands-on engineering labs validate least-privilege tool isolation using **AWS IAM Roles** and **API Gateway**, enterprise environments running **Microsoft 365 Copilot**, **Microsoft Copilot Studio**, **Microsoft Foundry**, or custom **Azure OpenAI** workflows require equivalent controls in the Microsoft enterprise stack.

Without identity isolation, an MCP server integrated into Copilot Studio introduces **Identity Flattening**: every tool, whether a read-only lookup or a destructive write action, inherits the single broad identity of the Copilot agent or execution connector.

### Multi-Cloud Architectural Translation Matrix

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

## 2. TRIAD Pillar Mapping to Microsoft Services

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

The same three tests (section 5) are run against both the AWS and Microsoft stacks. A control isn't considered in place on either platform until its test passes and the evidence is retained.

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

Each test maps to a finding in the [evidence baseline](../evidence/index.md). Microsoft results are recorded only after the test has been run in a tenant.

| Test | Finding | Method | Expected result | Evidence retained |
| :--- | :--- | :--- | :--- | :--- |
| **TC-01** Out-of-scope tool call | FINDING-01 | Call `post_journal_entry` with a token holding only `MCPTool.CustomerRead` | `403 Scope missing` from APIM | APIM gateway log entry, token claims (redacted) |
| **TC-02** Indirect prompt injection | FINDING-02 | Return a poisoned document from a read tool; scan it with Prompt Shields; automate variations with **PyRIT** | Attack detected; no write tool invoked | Prompt Shields response, PyRIT run log |
| **TC-03** Identity correlation | FINDING-03 | Trigger a tool call from a named test user through Copilot Studio | Sentinel shows user, agent identity and tool name in one investigation | Sentinel query result, Purview audit record |

---

## 6. Licensing and Limitations to Confirm with the Client

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

---

*Rare Cyber Advisory Services: Establishing Trust in Enterprise AI Infrastructure.*
