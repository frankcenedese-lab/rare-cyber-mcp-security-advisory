# Securing AI Agents with Privileged Tool Access

A threat-modelled lab on AWS and Microsoft. Technical report by Frank Cenedese, CISSP, CISA.

[![Governance Standard: TRIAD v1.0](https://img.shields.io/badge/Governance-TRIAD%20v1.0-blue.svg)](#the-triad-framework)
[![Compliance Alignment: NIST / ISO / OWASP](https://img.shields.io/badge/Compliance-NIST%20%7C%20ISO%2042001%20%7C%20OWASP-green.svg)](#standards--compliance-mapping)[![Cloud Focus: Multi-Cloud AWS & Azure](https://img.shields.io/badge/Multi--Cloud-AWS%20%26%20Microsoft-orange.svg)](#multi-cloud-architecture)

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
| 3. Configuration and Policy Changes | [docs/configuration.md](docs/configuration.md) |
| 4. Testing Guide | [docs/advisory/testing-guide.md](docs/advisory/testing-guide.md) |
| 5. Results and Evidence | [docs/evidence/index.md](docs/evidence/index.md) |
| 6. Scope, Limitations and Change Log | [docs/limitations.md](docs/limitations.md) |
| Appendix: Executive Summary | [docs/advisory/executive-brief.md](docs/advisory/executive-brief.md) |

--- | :--- |
| [The Build](docs/case-study.md) | The case study: build, threat model, break, fix, prove |
| [Threat Model](docs/threat-model.md) | STRIDE analysis of the lab: ten threats, five trust boundaries |
| [Configuration](docs/configuration.md) | Every configuration and policy change, before and after |
| [Testing Guide](docs/advisory/testing-guide.md) | Eight tests on AWS and Microsoft, with pass conditions |
| [Evidence](docs/evidence/index.md) | Assessment results and the evidence standard |
| [Executive Brief](docs/advisory/executive-brief.md) | The risk, questions and decisions for leaders |

---

## Repository Structure

```text
.
├── docs/                      # Site content (Markdown)
│   ├── case-study.md
│   ├── threat-model.md
│   ├── configuration.md
│   ├── advisory/              # Executive brief and testing guide
│   └── evidence/              # Evidence page, baseline results, harness runs
├── lab/                       # TRIAD test harness
│   ├── triad_tests.py         # Runs TC-01 to TC-08 on AWS or Microsoft
│   ├── tool_lock.py           # Tool definition hash lock (TC-06)
│   ├── tools/ payloads/ queries/
│   └── README.md
├── site_builder/              # Builds the website from docs/
└── .github/workflows/         # Site deploy + tool lock verification
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

