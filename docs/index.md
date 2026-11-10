# Rare Cyber: MCP Security Advisory & TRIAD Framework

**Securing Model Context Protocol (MCP) deployments across AWS and Microsoft.**

As enterprise adoption of agentic AI and the **Model Context Protocol (MCP)** accelerates, default deployments expose organizations to two critical risks:

* **Identity Flattening**: every tool shares a single elevated service credential, so a read-only lookup and a destructive write run with the same authority.
* **Indirect Prompt Injection**: unvalidated tool output (a document, ticket or email) hijacks the agent and triggers tool calls nobody approved.

This site is the advisory baseline and proof of concept for **Rare Cyber Advisory Services**, establishing the **TRIAD Framework** for enterprise MCP hardening.

> **What happens when the privileged account isn't a person anymore?**

---

## Start here

<div class="grid cards" markdown>

-   :material-briefcase-outline: **CISO Executive Brief**

    ---

    The business risk, the attack path, and the TRIAD baseline in one read for security leadership.

    [Read the brief](advisory/executive-brief.md)

-   :material-microsoft-azure: **Microsoft Architecture Guide**

    ---

    How the TRIAD controls map to Entra Agent ID, Azure API Management, Prompt Shields, Purview and Sentinel.

    [Read the guide](advisory/azure-copilot-mapping.md)

-   :material-file-check-outline: **Evidence Baseline**

    ---

    Before and after assessment output, mapped to NIST SP 800-53 controls.

    [View the evidence](evidence/index.md)

</div>

---

## The TRIAD Framework

| Pillar | What it enforces | AWS | Microsoft |
| :--- | :--- | :--- | :--- |
| **T**hreat Modeling & Poison Analysis | Sanitize tool output; strict JSON schema validation | Bedrock Guardrails | Prompt Shields, APIM `validate-content` |
| **R**igid Identity Decoupling | One scoped identity per tool function | IAM role per tool | Entra Agent ID + per-tool app roles |
| **I**mmutable Governance & Versioning | Hashed, version-controlled tool definitions | Git + pipeline | API Center, APIM versioning, Bicep |
| **A**udit Telemetry & Correlation | Tool calls linked to the human user | CloudTrail, CloudWatch | Azure Monitor, Purview, Sentinel |
| **D**ual-Ecosystem Enforcement | Same policy, same tests, both clouds | ✓ | ✓ |

---

## Standards alignment

Controls are mapped to **NIST SP 800-53**, the **NIST AI RMF 1.0**, **ISO/IEC 42001** and the **OWASP** guidance for LLM applications. See the mapping table in the [Executive Brief](advisory/executive-brief.md#compliance-standards-mapping).

---

## About Rare Cyber

Rare Cyber Advisory Services helps organizations prove that their AI systems are secure, governed and defensible: that reasonable controls existed, operated and were monitored.

<!-- TODO: add acknowledgement for Zach's original lab work here, e.g. "AWS lab baseline developed with [Name](link)." -->

[rarecyber.ca](https://rarecyber.ca){ .md-button }
[View on GitHub](https://github.com/frankcenedese-lab/rare-cyber-mcp-security-advisory){ .md-button }
