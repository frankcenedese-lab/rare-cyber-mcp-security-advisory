# Securing AI Agents with Privileged Tool Access

A threat-modelled lab on AWS and Microsoft. Technical report (version 1.3) by Frank Cenedese, CISSP, CISA.

---

## Overview

AI agents connected to business systems through the Model Context Protocol (MCP) commonly run every tool under one shared credential, can be steered by content they read, and leave logs that can't attribute an action to a person. This repository contains a lab-based technical report on those risks: a STRIDE threat model, the TRIAD controls applied on AWS with Microsoft equivalents, configuration and policy changes before and after, an automated test harness, and the results to date, with limitations stated.

---

## 🌐 Read the Report

**[frankcenedese-lab.github.io/rare-cyber-mcp-security-advisory](https://frankcenedese-lab.github.io/rare-cyber-mcp-security-advisory/)**

| Section | Source |
| :--- | :--- |
| Abstract and key findings | [site home](https://frankcenedese-lab.github.io/rare-cyber-mcp-security-advisory/) |
| 1. Method and Environment | [docs/case-study.md](docs/case-study.md) |
| 2. Threat Model (STRIDE) | [docs/threat-model.md](docs/threat-model.md) |
| 3. Identity Architecture | [docs/identity-architecture.md](docs/identity-architecture.md) |
| 4. Configuration and Policy Changes | [docs/configuration.md](docs/configuration.md) |
| 5. Testing Guide | [docs/advisory/testing-guide.md](docs/advisory/testing-guide.md) |
| 6. Results and Evidence | [docs/evidence/index.md](docs/evidence/index.md) |
| 7. Scope, Limitations, Residual Risk and Change Log | [docs/limitations.md](docs/limitations.md) |
| Appendix: Executive Summary | [docs/advisory/executive-brief.md](docs/advisory/executive-brief.md) |

---

## Repository Structure

```text
.
├── docs/                      # Site content (Markdown)
│   ├── case-study.md
│   ├── threat-model.md
│   ├── identity-architecture.md
│   ├── configuration.md
│   ├── advisory/              # Executive brief and testing guide
│   └── evidence/              # Evidence page, baseline results, harness runs
├── lab/                       # TRIAD test harness
│   ├── triad_tests.py         # Runs TC-01 to TC-13 on AWS or Microsoft
│   ├── tool_lock.py           # Tool definition hash lock (TC-06)
│   ├── sod_check.py           # Separation of duties and ownership check (TC-11)
│   ├── tools/ identity/ payloads/ queries/
│   └── README.md
├── site_builder/              # Builds the website from docs/
└── .github/workflows/         # Site deploy + tool lock and duties checks
```

---

## Run the Lab Tests

```bash
pip install -r lab/requirements.txt
cp lab/config.example.env lab/.env
python lab/triad_tests.py --platform azure
```

See [lab/README.md](lab/README.md). Only test environments you own or are authorized to test.

## Preview the Site Locally

```bash
pip install -r requirements.txt
python site_builder/build.py
python -m http.server -d _site 8000
```

---

