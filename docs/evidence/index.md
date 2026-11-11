# Results and Evidence

**Platform:** AWS lab  
**Controls:** NIST SP 800-53 AC-6, SI-10, AU-12  
**Author:** Frank Cenedese, CISSP, CISA

---

## Results

Three tests were run against the default build, then repeated after hardening.

| Test | What was attempted | Before hardening | After hardening |
| :--- | :--- | :--- | :--- |
| **TC-01** Out-of-scope action | The agent was induced to call the financial write tool during a task that needed only a lookup | **FAIL:** allowed, because the shared role permitted it | **PASS:** refused with `403`; the read identity had no write permission |
| **TC-02** Indirect prompt injection | Instructions were planted in content the agent would read, directing it to use a write tool | **FAIL:** followed, because nothing inspected the content | **PASS:** flagged by Bedrock Guardrails before the agent acted |
| **TC-03** Attribution | A tool call was traced back to the user who started the session | **FAIL:** logs showed an API call, not a person or a tool | **PASS:** each call recorded with the user, agent and tool |

A passing TC-02 shows the control caught the tested payloads, not every possible injection.

---

## What hasn't been tested yet

Results are reported only for tests that have been run. Two controls are verified in the repository and CI but not in a deployed environment: the tool definition hash lock (TC-06) and the separation of duties check (TC-11). Eight more tests are defined in the [lab test harness](https://github.com/frankcenedese-lab/rare-cyber-mcp-security-advisory/tree/main/lab) with pass conditions set in advance: spoofing and token replay, throttling, bulk export, confused deputy, token audience, amount limits, time-bound elevation and revocation time (TC-04, TC-05, TC-07 to TC-10, TC-12 and TC-13). The same tests are the plan for the Azure lab.

---

## Evidence standard

A result counts as evidence only when it records:

| Element | Why it matters |
| :--- | :--- |
| Test ID and the threat it traces to | Proves the test exists for a reason, not as activity |
| Expected and observed outcome | Shows the pass condition was set before the test ran |
| UTC timestamp, environment and operator | Establishes when, where and by whom |
| SHA-256 hash of the raw observation | Makes later editing detectable |

Runs are never edited; a re-test is a new run. The harness writes each run to `docs/evidence/runs/` in this format.

The two original assessment files below predate this standard: they record findings and timestamps, but not the operator, expected outcomes or hashes. TC-01 to TC-03 will be re-run with the harness to produce evidence that meets it.

---

## Original assessment files

The results above come from two assessment files recorded in the AWS lab on 2026-11-10: [the default build](scan-vulnerable.json) (non-compliant, three findings) and [the hardened build](scan-hardened.json) (all three passed).

!!! note "Correction to the hardened file"
    The hardened file is labelled `AWS-Microsoft-Hardened-TRIAD` (TRIAD was the lab's working name for its hardening steps), and its descriptions mention Azure API Management and Sentinel. No Microsoft component was tested; the results apply to the AWS lab only. The file also credits token validation with filtering injection: token validation authenticates callers, while content inspection is what flagged the injected content. The files are kept unedited; this page states the corrected scope.
