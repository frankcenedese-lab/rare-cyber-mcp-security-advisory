# Scope, Limitations, Residual Risk and Change Log

**Report version:** Version 1.3  
**Status:** Living report, updated as tests are run  
**Last reviewed:** November 2026

---

## Scope

This report covers a single AI agent connected to business tools through the Model Context Protocol (MCP), behind an API gateway, in a lab environment built for this work. Controls were implemented and tested on AWS. Microsoft equivalents are documented for every control; Microsoft results are reported only for tests that have been run in a Microsoft tenant.

## Authorization

All testing described in this report was performed in environments owned and controlled by the author. The test harness should only be run against systems you own or are explicitly authorized to test.

## Limitations

| Area | Limitation | Effect on the findings |
| :--- | :--- | :--- |
| **Environment** | A lab, not production: synthetic data, placeholder account IDs, one agent in the attack scenarios, four tools | Results show the controls work in this configuration; production environments need their own testing |
| **Test coverage** | As of version 1.3, three of sixteen threats are tested in the lab and two are verified in the repository only; nine have defined tests not yet run; two are open | Untested threats are reported as planned, never as mitigated |
| **Prompt injection** | Detection tools such as Prompt Shields and Bedrock Guardrails are probabilistic and can be bypassed by adaptive attacks | A passing TC-02 shows the control catches the tested payloads, not every possible injection. Bedrock's prompt attack filter is designed mainly for user input, so its coverage of injection in documents and tool output must be confirmed on AWS |
| **Agent architectures not covered** | Multi-agent systems, agent-to-agent protocols, persistent agent memory and retrieval (RAG) pipelines | Threats such as memory poisoning and agent-to-agent trust, covered by CSA MAESTRO, are out of scope |
| **Baseline evidence** | The v1.0 assessment files include a qualitative risk rating, not a calculated score, and predate the evidence standard (no operator, expected outcome or hash); the hardened file's environment label overstates its scope (see the erratum on the Results page) | Findings are reported as control pass or fail for the AWS lab only; TC-01 to TC-03 will be re-run with the harness |
| **Framework mappings** | Control mappings to NIST SP 800-53, NIST AI RMF and ISO standards are the author's analysis | They support, but don't replace, a formal compliance assessment |
| **Identity maturity** | The lab is at level 2 with user attribution. Levels 3 to 5 of the agent identity maturity model are designed and specified, not yet implemented | Identity controls beyond per-tool roles are reported as design, not as tested results |
| **Detection** | Only TC-05 checks that an alert is raised. Whether a security operations team would detect an injection or a confused deputy in practice isn't tested | Detection and response capability is assumed, not demonstrated |
| **Platform features** | Some Microsoft features referenced (for example, the Sentinel Copilot data connector) were in preview at the time of writing | Availability and behaviour may change; the Testing Guide notes preview status |

## Residual risk

Hardening reduces risk; it doesn't remove it. After the TRIAD controls, the lab still carries:

- **Novel injection:** payloads that content inspection doesn't recognize. Per-tool identity and parameter limits cap the damage a steered agent can do, which is why identity, not detection, is the primary control.
- **Misuse within granted rights:** an agent acting within its role and limits can still take a wrong action. Separation of duties and human approval for high-risk tools reduce this.
- **Revocation lag:** a disabled agent can keep working until its tokens expire. TC-13 measures this window.
- **Output leakage (I3):** data carried out in the agent's own responses is identified but not yet controlled or tested.

In an organization, residual risk should be accepted formally by a named risk owner, usually the business owner of the process the agent supports, and reviewed when tests or the threat model change.

## Logging and privacy

Control A records every tool call with the user, the agent and the arguments, and threat I2 warns that sensitive data can leak into logs. Both are true, and they pull against each other. The lab resolves the tension this way:

- **Log identifiers and decisions, not content:** user ID, agent ID, tool, decision and a hash of the arguments, rather than the full payload.
- **Redact or tokenize personal information** before it reaches the log store, with full payloads kept only in a restricted store when an investigation requires them.
- **Set retention to purpose:** the same retention as privileged access logs, with access to agent logs itself logged.

For Canadian organizations, this aligns logging with PIPEDA's limits on collection and retention. Collecting less personal information in logs is itself a control.

## Operational considerations

- **Latency:** content inspection and per-call policy checks add time to every tool call. Measure it in pilots and set budgets before production.
- **False positives:** content filters will sometimes block legitimate content. Tune thresholds with real samples, and log blocks for review rather than failing silently.
- **Approval fatigue:** just-in-time approval for every call trains people to approve without reading. Reserve it for genuinely high-risk tools and make approvals specific (amount, record, purpose).
- **Model provider risk:** prompts and tool outputs reach the model provider. Review its data retention, training use and data residency terms, which this report doesn't assess.

## What this report does not claim

- That the hardened lab is immune to prompt injection or any other attack class.
- That results transfer unchanged to another organization's environment.
- That planned tests have passed.

---

## Change log

| Version | Date | Changes |
| :--- | :--- | :--- |
| 1.3 | 2026-11-10 | Critical review corrections. Erratum on the hardened assessment's scope; repository checks reported as VERIFIED rather than lab passes. Clarified that the lab records the user (attribution) but doesn't yet authorize by the user's rights (level 3). Corrected AWS per-tool enforcement (in the MCP server, since API Gateway authorizers can't read the request body), the APIM reference policy (default deny for unlisted tools), the source identity condition, the 15-minute token minimum, the AWS audience and throttling rows, and the Bedrock document-injection caveat. Added threat I3 (output leakage), residual risk, logging and privacy, and operational considerations. Harness: allowed paths now require a successful response within an MCP session. Consistent four-tool description, Canadian spelling and neutral voice. |
| 1.2 | 2026-11-10 | Added the Identity Architecture section: identity flattening vs decoupled identity, mandatory identity standards (tool-scoped identities, ephemeral credentials with 60 and 15 minute token limits, delegation, audience binding), a multi-cloud implementation mapping, four identities, token flow with audience binding and no passthrough, a five-level agent identity maturity model, and tests TC-09 to TC-13. Threat model extended to fifteen threats. Separation of duties check (TC-11) added to the harness and CI. |
| 1.1 | 2026-11-10 | Restructured as a technical report. Added the STRIDE threat model (ten threats, five trust boundaries), configuration and policy changes before and after, the automated test harness, tests TC-04 to TC-08, the evidence standard, and this section. Executive brief moved to an appendix. |
| 1.0 | 2026-11-10 | Initial advisory: TRIAD framework, AWS lab baseline and hardened results, Microsoft control mapping. |
