# Lab Design and Hardening

**Platform:** AWS lab (tested)  
**Standards:** OWASP Top 10 for Agentic Applications (2026) · NIST SP 800-53 · STRIDE · MCP authorization specification  
**Author:** Frank Cenedese, CISSP, CISA

---

## The principle being tested

The OWASP Top 10 for Agentic Applications (2026) sets out the principle of **least agency**: give an agent only the autonomy and access its task needs. It extends the familiar principles of least privilege and excessive agency to systems that act on their own. Its risk **ASI03, Identity and Privilege Abuse**, describes the failure this lab examines: an agent that inherits broader credentials than its task needs, with no separate identity for each action.

The lab asks one practical question. **When an AI agent is connected to business systems through the Model Context Protocol (MCP), what can it actually do, and can anyone prove what it did afterwards?**

---

## The environment

The original AWS lab was developed with Zach Marcy. This report's threat model, hardening analysis, test harness and Azure analysis are the author's own.

The baseline was deployed the way a team building a pilot often would: working, fast and relying on defaults.

- An AI agent connected to an MCP tool server through Amazon API Gateway
- Four tools with different risk levels: `customer_lookup` (read), `post_journal_entry` (financial write), `approve_journal_entry` (approval) and `export_records` (bulk export)
- **One shared IAM role** used by every tool, read and write alike
- No content inspection on what the agent reads
- Standard API logging, with no link between a tool call and the person behind it

The shared role is the core problem. A read-only lookup and a financial write run with the same rights, so anything that steers the agent inherits the rights of its most powerful tool.

<div class="figure-slot" data-figure="decouple"></div>

---

## Threat model

The lab was modelled with STRIDE across five trust boundaries (user to agent, agent to gateway, gateway to tool server, tool server to downstream API, and the logging pipeline), then checked against the OWASP Agentic Top 10 to catch agent-specific threats STRIDE misses.

<div class="figure-slot" data-figure="stride"></div>

| ID | Threat | Standard reference | Status |
| :--- | :--- | :--- | :--- |
| **E1** | All tools share one role, so a read task can perform writes | OWASP ASI03 · NIST AC-6 | TESTED |
| **T1** | Instructions hidden in content steer the agent (indirect prompt injection) | OWASP ASI01 · NIST SI-10 | TESTED |
| **R1** | A harmful action can't be traced to a user, agent or tool | NIST AU-12 | TESTED |
| **T2** | A tool's definition is changed to mislead the agent (tool poisoning) | OWASP ASI04 | VERIFIED |
| **E4** | One agent holds conflicting duties, such as posting and approving | NIST AC-5 | VERIFIED |
| **I1** | Agent exports records beyond what the task needs | OWASP ASI03 | PLANNED |
| **E2** | Confused deputy: the agent uses its own rights for a user who lacks them | OWASP ASI03 | PLANNED |
| **S1, S2, S3** | Unapproved MCP server; stolen or replayed token; token accepted by the wrong server | MCP authorization specification | PLANNED |
| **D1** | Agent loops on tool calls, exhausting quotas | NIST SC-5 | PLANNED |
| **E3, E5, E6** | Limits exceeded within an allowed tool; standing privilege; access kept after disabling | OWASP ASI03 | PLANNED |
| **I2, I3** | Sensitive data leaks into logs, or out through the agent's responses | NIST AC-4 | OPEN |

**TESTED** means run against the deployed lab. **VERIFIED** means the control logic was checked in the repository and CI, not in a deployed environment. **PLANNED** means a test is defined but not yet run. **OPEN** means no test is defined yet.

The threat model mattered. Before it, three tests appeared to cover the lab. Afterwards, they were shown to cover three of sixteen threats, and two important gaps were found: bulk export as its own privilege, and the confused deputy.

---

## Hardening changes, before and after

Four configuration changes produced the tested results. Examples use placeholder account IDs and names.

### 1. One identity per tool, not one for everything

Addresses E1 · OWASP ASI03 · NIST AC-6

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

### 2. Authenticate every caller and check the role for each tool

Addresses E1, E2 · NIST AC-3

<div class="ba" markdown="1">
<div class="before" markdown="1">

**Before:** open method

```yaml
# Amazon API Gateway (OpenAPI)
x-amazon-apigateway-auth:
  type: NONE
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

API Gateway authorizers can't read the request body, where MCP carries the tool name. The gateway authenticates the caller; the MCP server then checks the caller's role against each tool's `required_role` in the [tool definitions](https://github.com/frankcenedese-lab/rare-cyber-mcp-security-advisory/blob/main/lab/tools/tool_definitions.json) and refuses unlisted tools.

</div>
</div>

Both layers matter. The role check decides which tools the agent may call; the per-tool role from change 1 decides what each tool can reach. A call that gets past one still lacks the permission to act.

### 3. Record the user behind every tool call

Addresses R1 · NIST AU-12

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
  "Condition": { "Null": { "sts:SourceIdentity": "false" } }
}
```

The role can't be assumed without a source identity, which is set to the user's immutable ID and appears in CloudTrail on every call.

</div>
</div>

This provides **attribution**: who was behind an action. It doesn't yet cap the agent at the user's own rights (delegation), which test TC-08 is defined to check.

### 4. Inspect untrusted content before the agent acts

Addresses T1 · OWASP ASI01 · NIST SI-10

<div class="ba" markdown="1">
<div class="before" markdown="1">

**Before:** no content inspection

```json
{ "guardrailConfig": null }
```

Instructions hidden in an email are read and followed.

</div>
<div class="after" markdown="1">

**After:** prompt attack filtering

```json
"contentPolicyConfig": {
  "filtersConfig": [{
    "type": "PROMPT_ATTACK",
    "inputStrength": "HIGH",
    "outputStrength": "NONE"
  }]
}
```

Tool output is passed to Amazon Bedrock Guardrails through the `ApplyGuardrail` API before the agent sees it.

</div>
</div>

Detection is probabilistic and can be bypassed, which is why change 1 is the primary control: it limits what a steered agent can do.

Two further controls are verified in the repository: a hash lock on tool definitions that fails the build if a definition changes outside the pipeline (T2), and a separation of duties check that rejects an agent holding both posting and approval roles (E4). Both run in CI.
