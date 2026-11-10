# Rare Cyber: Model Context Protocol (MCP) Security Advisory & TRIAD Framework

[![Governance Standard: TRIAD v1.0](https://img.shields.io/badge/Governance-TRIAD%20v1.0-blue.svg)](#the-triad-framework)
[![Compliance Alignment: NIST / ISO / OWASP](https://img.shields.io/badge/Compliance-NIST%20%7C%20ISO%2042001%20%7C%20OWASP-green.svg)](#standards--compliance-mapping)[![Cloud Focus: Multi-Cloud AWS & Azure](https://img.shields.io/badge/Multi--Cloud-AWS%20%26%20Microsoft-orange.svg)](#multi-cloud-architecture)

---

## Overview

As enterprise adoption of Agentic AI and the **Model Context Protocol (MCP)** rapidly accelerates, default unhardened deployments expose organizations to critical risk vectors—most notably **Identity Flattening** (where all tools share a single elevated service credential) and **Indirect Prompt Injection** (where unvalidated tool outputs hijack model execution).

This repository serves as the official advisory baseline and proof-of-concept repository for **Rare Cyber Advisory Services**, establishing the **TRIAD Framework** for enterprise MCP hardening.

---

## 🌐 Read the Advisory Online

**[frankcenedese-lab.github.io/rare-cyber-mcp-security-advisory](https://frankcenedese-lab.github.io/rare-cyber-mcp-security-advisory/)**

| Document | Audience |
| :--- | :--- |
| [CISO Executive Brief](docs/advisory/executive-brief.md) | Security leadership |
| [Microsoft Architecture Guide](docs/advisory/azure-copilot-mapping.md) | Architects, Azure admins, DevSecOps |
| [Evidence Baseline](docs/evidence/index.md) | Auditors, assessors |

---

## Repository Structure

```text
.
├── docs/
│   ├── index.md                        # Site home page
│   ├── advisory/
│   │   ├── executive-brief.md          # CISO Executive Advisory Brief & Business Context
│   │   └── azure-copilot-mapping.md    # Microsoft Architecture Guide (Entra Agent ID, APIM, Prompt Shields, Sentinel)
│   └── evidence/
│       ├── index.md                    # Evidence baseline summary
│       ├── scan-vulnerable.json        # Pre-hardening assessment output (sample)
│       └── scan-hardened.json          # Post-hardening assessment output (sample)
├── .github/workflows/deploy-pages.yml  # Publishes the site to GitHub Pages on every push to main
├── mkdocs.yml                          # Site configuration
├── requirements.txt                    # Site build dependency
└── README.md                           # This file
```

---

## Preview the Site Locally

```bash
pip install -r requirements.txt
mkdocs serve
```

Then open http://127.0.0.1:8000.

---

*Rare Cyber Advisory Services: Establishing Trust in Enterprise AI Infrastructure.*
