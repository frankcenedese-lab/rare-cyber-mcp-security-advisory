# Rare Cyber AI Security Lab: Securing AI Agents on AWS and Microsoft

[![Governance Standard: TRIAD v1.0](https://img.shields.io/badge/Governance-TRIAD%20v1.0-blue.svg)](#the-triad-framework)
[![Compliance Alignment: NIST / ISO / OWASP](https://img.shields.io/badge/Compliance-NIST%20%7C%20ISO%2042001%20%7C%20OWASP-green.svg)](#standards--compliance-mapping)[![Cloud Focus: Multi-Cloud AWS & Azure](https://img.shields.io/badge/Multi--Cloud-AWS%20%26%20Microsoft-orange.svg)](#multi-cloud-architecture)

---

## Overview

As enterprise adoption of Agentic AI and the **Model Context Protocol (MCP)** rapidly accelerates, default unhardened deployments expose organizations to critical risk vectors—most notably **Identity Flattening** (where all tools share a single elevated service credential) and **Indirect Prompt Injection** (where unvalidated tool outputs hijack model execution).

This repository serves as the official advisory baseline and proof-of-concept repository for **Rare Cyber Advisory Services**, establishing the **TRIAD Framework** for enterprise MCP hardening.

---

## 🌐 Visit the Site

**[frankcenedese-lab.github.io/rare-cyber-mcp-security-advisory](https://frankcenedese-lab.github.io/rare-cyber-mcp-security-advisory/)**

| Page | What it shows |
| :--- | :--- |
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

*Rare Cyber Advisory Services: Establishing Trust in Enterprise AI Infrastructure.*
