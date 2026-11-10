# Configuration & Policy Changes: Before and After

**Scope:** Every configuration and governance policy change behind the TRIAD results  
**Environments:** AWS lab · Microsoft equivalents  
**Traceability:** Each change maps to a threat, a test and a policy  
**Last reviewed:** November 2026

---

## How to read this page

Hardening isn't one setting. Each TRIAD result came from a specific configuration change, and each configuration change only lasts if a policy requires it. This page shows both layers:

1. **Technical configuration**, before and after, on AWS and Microsoft.
2. **Governance policies** that had to change so the configuration stays that way.

Examples use placeholder account IDs, names and GUIDs. They're reference patterns from the lab; validate them in a non-production environment before use.

---

## Summary of changes

| # | Change | Threats | Test | AWS | Microsoft |
| :--- | :--- | :--- | :--- | :--- | :--- |
| C1 | Split the shared role into one role per tool | E1, I1 | TC-01, TC-07 | IAM roles | Entra app roles |
| C2 | Enforce identity and scope at the gateway | E1, E2, S2 | TC-01, TC-08 | API Gateway IAM auth | APIM `validate-azure-ad-token` |
| C3 | Carry the user's identity through to every tool call | R1, E2 | TC-03, TC-08 | STS source identity | On-behalf-of token + logged claim |
| C4 | Inspect untrusted content before the agent acts | T1 | TC-02 | Bedrock Guardrails | Prompt Shields |
| C5 | Throttle tool calls per agent | D1 | TC-05 | Usage plan throttling | APIM `rate-limit-by-key` |
| C6 | Lock tool definitions to approved versions | T2, S1 | TC-04, TC-06 | Pipeline hash check | Pipeline hash check + API Center |

---

## C1. One role per tool, not one role for everything

**AWS: IAM**

<div class="ba" markdown="1">
<div class="before" markdown="1">

**Before:** one role for every tool

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["lambda:InvokeFunction", "dynamodb:*", "s3:*"],
    "Resource": "*"
  }]
}
```

`MCPSharedExecutionRole`: a lookup and a payment run with the same rights.

</div>
<div class="after" markdown="1">

**After:** a scoped role per tool

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "lambda:InvokeFunction",
    "Resource": "arn:aws:lambda:ca-central-1:123456789012:function:post-journal-entry"
  }]
}
```

`mcp-tool-post-journal`: can do one thing. Lookup and export each get their own role.

</div>
</div>

**Microsoft: Entra app roles**

<div class="ba" markdown="1">
<div class="before" markdown="1">

**Before:** a single access role

```json
"appRoles": [{
  "allowedMemberTypes": ["Application"],
  "displayName": "MCP Access",
  "value": "MCP.Access",
  "id": "00000000-0000-0000-0000-000000000001",
  "isEnabled": true
}]
```

Any agent with access can call any tool.

</div>
<div class="after" markdown="1">

**After:** one role per tool

```json
"appRoles": [
  { "value": "MCPTool.CustomerRead",   "displayName": "Customer lookup", "...": "..." },
  { "value": "MCPTool.FinancialWrite", "displayName": "Post journal",    "...": "..." },
  { "value": "MCPTool.ExportWrite",    "displayName": "Export records",  "...": "..." }
]
```

Each agent's Agent ID is granted only the roles its job needs.

</div>
</div>

---

## C2. Enforce identity and scope at the gateway

<div class="ba" markdown="1">
<div class="before" markdown="1">

**Before:** open method (AWS) and key-only policy (Microsoft)

```yaml
# Amazon API Gateway (OpenAPI)
x-amazon-apigateway-auth:
  type: NONE
```

```xml
<!-- Azure API Management -->
<inbound>
  <base />
</inbound>
```

Anyone who reaches the endpoint can call any tool.

</div>
<div class="after" markdown="1">

**After:** signed identity required; role checked per tool

```yaml
# Amazon API Gateway (OpenAPI)
x-amazon-apigateway-auth:
  type: AWS_IAM
```

```xml
<!-- Azure API Management (abridged) -->
<validate-azure-ad-token tenant-id="{{tenant-id}}"
    failed-validation-httpcode="403">
  <required-claims>
    <claim name="roles" match="any">
      <value>MCPTool.FinancialWrite</value>
    </claim>
  </required-claims>
</validate-azure-ad-token>
```

The full per-tool policy is in the [Testing Guide](advisory/testing-guide.md#3-reference-apim-policy-per-tool-scope-enforcement).

</div>
</div>

---

## C3. Carry the user's identity into every tool call

<div class="ba" markdown="1">
<div class="before" markdown="1">

**Before:** the agent acts as itself

```json
{ "Action": "sts:AssumeRole" }
```

Logs show the role, never the person behind it.

</div>
<div class="after" markdown="1">

**After:** the user travels with the call

```json
{
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::123456789012:role/mcp-agent-runtime" },
  "Action": ["sts:AssumeRole", "sts:SetSourceIdentity"],
  "Condition": { "StringLike": { "sts:SourceIdentity": "*@example.com" } }
}
```

```xml
<!-- APIM: record who the agent is acting for -->
<trace source="mcp-audit" severity="information">
  <message>@{
    var jwt = context.Request.Headers.GetValueOrDefault("Authorization","").AsJwt();
    return $"user={jwt?.Claims.GetValueOrDefault("upn","")} tool={context.Variables.GetValueOrDefault<string>("toolName")}";
  }</message>
</trace>
```

</div>
</div>

---

## C4. Inspect untrusted content before the agent acts

<div class="ba" markdown="1">
<div class="before" markdown="1">

**Before:** no content inspection

```json
{ "guardrailConfig": null }
```

Instructions hidden in an email are read and followed.

</div>
<div class="after" markdown="1">

**After:** prompt attack filtering on input

```json
"contentPolicyConfig": {
  "filtersConfig": [{
    "type": "PROMPT_ATTACK",
    "inputStrength": "HIGH",
    "outputStrength": "NONE"
  }]
}
```

On Microsoft, Prompt Shields is enabled in the deployment's content filter, with untrusted tool output passed as **documents** so indirect attacks are evaluated.

</div>
</div>

---

## C5. Throttle tool calls per agent

<div class="ba" markdown="1">
<div class="before" markdown="1">

**Before:** no limits

An agent caught in a loop can call tools until quotas or budgets run out.

</div>
<div class="after" markdown="1">

**After:** limits per agent identity

```json
"throttle": { "rateLimit": 10, "burstLimit": 20 }
```

```xml
<rate-limit-by-key calls="30" renewal-period="60"
  counter-key="@(context.Request.Headers.GetValueOrDefault("Authorization","").AsJwt()?.Claims.GetValueOrDefault("oid",""))" />
```

</div>
</div>

---

## C6. Lock tool definitions to approved versions

<div class="ba" markdown="1">
<div class="before" markdown="1">

**Before:** definitions edited in place

A changed tool description goes live immediately, and the agent trusts it.

</div>
<div class="after" markdown="1">

**After:** hashed and verified on every change

```bash
python lab/tool_lock.py generate   # after an approved change
python lab/tool_lock.py verify     # in CI: any drift fails the build
```

On Microsoft, approved MCP servers are also registered in Azure API Center, and the gateway only routes to registered servers.

</div>
</div>

---

## Governance policies impacted

Configuration drifts back unless a policy requires it. These are the policies each change touched, with the control references an auditor would test against.

| Policy | What changes | Changes | ISO/IEC 27001:2022 | ISO/IEC 42001 |
| :--- | :--- | :--- | :--- | :--- |
| **Access control / IAM standard** | AI agents become a named identity class with an owner; one role per tool; agent access included in periodic access reviews | C1, C2, C3 | A.5.15, A.5.18, A.8.2 | 6.1.3 |
| **AI policy and acceptable use** | Only registered agents may connect to production systems; high-risk tools (payments, exports) need explicit approval | C1, C6 | — | 5.2 |
| **Change management** | Tool definitions are configuration items; changes only through the pipeline with a verified hash | C6 | A.8.32 | 8.1 |
| **Logging and monitoring standard** | Every tool call logs user, agent, tool and decision; agent logs kept for the same retention as privileged access logs | C3 | A.8.15, A.8.16 | 9.1 |
| **Supplier and third-party security** | MCP servers and AI connectors are assessed and registered like any supplier before use | C6 | A.5.19, A.5.23 | — |
| **Capacity and availability** | Rate limits and spend alerts set per agent | C5 | A.8.6 | — |
| **Data classification and DLP** | Content reaching agents is inspected; exports limited to approved data classes | C1, C4 | A.5.12, A.8.12 | — |
| **Incident response plan** | New playbook for a compromised agent: revoke its identity, disable the tool, preserve logs | C2, C3 | A.5.24, A.5.26 | — |
