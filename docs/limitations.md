# Scope, Limitations and Change Log

**Report version:** Version 1.2  
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
| **Environment** | A lab, not production: synthetic data, placeholder account IDs, one agent, three tools | Results show the controls work in this configuration; production environments need their own testing |
| **Test coverage** | As of version 1.2, five of fifteen threats are tested; nine have defined tests not yet run; one is open | Untested threats are reported as planned, never as mitigated |
| **Prompt injection** | Detection tools such as Prompt Shields and Bedrock Guardrails are probabilistic and can be bypassed by adaptive attacks | A passing TC-02 shows the control catches the tested payloads, not every possible injection |
| **Agent architectures not covered** | Multi-agent systems, agent-to-agent protocols, persistent agent memory and retrieval (RAG) pipelines | Threats such as memory poisoning and agent-to-agent trust, covered by CSA MAESTRO, are out of scope |
| **Baseline scoring** | The baseline files include a qualitative risk rating, not a calculated score | Findings are reported as control pass or fail, not as a numeric risk reduction |
| **Framework mappings** | Control mappings to NIST SP 800-53, NIST AI RMF and ISO standards are the author's analysis | They support, but don't replace, a formal compliance assessment |
| **Identity maturity** | Levels 3 to 5 of the agent identity maturity model are designed and specified, not yet implemented in the lab | Identity controls beyond per-tool roles are reported as design, not as tested results |
| **Platform features** | Some Microsoft features referenced (for example, the Sentinel Copilot data connector) were in preview at the time of writing | Availability and behaviour may change; the Testing Guide notes preview status |

## What this report does not claim

- That the hardened lab is immune to prompt injection or any other attack class.
- That results transfer unchanged to another organization's environment.
- That planned tests have passed.

---

## Change log

| Version | Date | Changes |
| :--- | :--- | :--- |
| 1.2 | 2026-11-10 | Added the Identity Architecture section: four identities, token flow with audience binding and no passthrough, a five-level agent identity maturity model, and tests TC-09 to TC-13. Threat model extended to fifteen threats. Separation of duties check (TC-11) added to the harness and CI. |
| 1.1 | 2026-11-10 | Restructured as a technical report. Added the STRIDE threat model (ten threats, five trust boundaries), configuration and policy changes before and after, the automated test harness, tests TC-04 to TC-08, the evidence standard, and this section. Executive brief moved to an appendix. |
| 1.0 | 2026-11-10 | Initial advisory: TRIAD framework, AWS lab baseline and hardened results, Microsoft control mapping. |
