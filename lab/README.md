# TRIAD Lab Test Harness

Repeatable tests for the thirteen TRIAD test cases, on AWS or Azure. Each run writes one evidence file to `docs/evidence/runs/`, recording what was attempted, what was expected, what was observed, and a SHA-256 hash of the observation.

> Only run these tests against environments you own or are authorized to test.

## Setup

```bash
pip install -r lab/requirements.txt
cp lab/config.example.env lab/.env   # fill in your lab gateway, tools and test tokens
```

`lab/.env` is git-ignored. Use short-lived tokens issued for the test run.

## Run

```bash
python lab/triad_tests.py --platform azure            # all tests on Azure
python lab/triad_tests.py --platform aws              # all tests on AWS
python lab/triad_tests.py --platform aws --only TC-01 TC-07
```

| Test | Threat | What it checks | How |
| :--- | :--- | :--- | :--- |
| TC-01 | E1 | Read-only identity can't call the write tool | Automated |
| TC-02 | T1 | Injected instructions in a document are flagged | Automated (Prompt Shields or Bedrock Guardrails) |
| TC-03 | R1 | One query shows user, agent and tool | Manual: run the query in `lab/queries/`, attach the result |
| TC-04 | S1, S2 | Expired token and unregistered server are refused | Automated |
| TC-05 | D1 | A flood of tool calls is throttled | Automated |
| TC-06 | T2 | A changed tool definition fails the hash check | Automated, offline |
| TC-07 | I1 | Export needs its own role | Automated |
| TC-08 | E2 | Agent can't exceed the calling user's rights | Automated |
| TC-09 | S3 | Token for another MCP server is refused | Automated |
| TC-10 | E3 | Call over the agent's parameter limit is refused | Automated |
| TC-11 | E4 | Conflicting roles on one agent are detected | Automated, offline (`lab/sod_check.py`) |
| TC-12 | E5 | High-risk tool needs just-in-time elevation | Automated |
| TC-13 | E6 | Disabled agent is cut off within the target time | Interactive: you disable the agent when prompted |

Statuses: `PASS`, `FAIL`, `MANUAL` (needs an analyst to attach evidence), `SKIPPED` (setting missing), `ERROR` (harness problem, recorded rather than hidden).

## Tool definition lock

```bash
python lab/tool_lock.py generate   # after an approved change
python lab/tool_lock.py verify     # runs in CI on every push
```

## Evidence standard

A result counts as evidence only if it has: the test ID and threat it traces to, the expected and observed outcome, a UTC timestamp, the environment and operator, and the hash of the raw observation. Manual results also need the attached query output or screenshot. Runs are committed as-is and never edited; a re-test is a new run.
