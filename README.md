# Securing AI Agents with Privileged Tool Access

Least agency, tested in an AWS lab. Technical report (version 2.3) by Frank Cenedese, CISSP, CISA.

The original AWS lab was developed with Zach Marcy. The threat model, hardening analysis, test harness and Azure analysis in this report are the author's own.

---

## Overview

The OWASP Top 10 for Agentic Applications (2026) sets out the principle of least agency: an AI agent should get only the access and autonomy its task needs. This repository tests that principle. An AI agent with four MCP tools was deployed on AWS with one shared credential, threat modelled with STRIDE, hardened with four configuration changes, and re-tested against NIST SP 800-53 AC-6, SI-10 and AU-12. It also documents how the same problem appears on Azure and where Azure differs.

---

## Read the Report

**[frankcenedese-lab.github.io/rare-cyber-mcp-security-advisory](https://frankcenedese-lab.github.io/rare-cyber-mcp-security-advisory/)**

| Section | Source |
| :--- | :--- |
| Abstract and key findings | [site home](https://frankcenedese-lab.github.io/rare-cyber-mcp-security-advisory/) |
| 1. Lab Design and Hardening | [docs/lab.md](docs/lab.md) |
| 2. Results and Evidence | [docs/evidence/index.md](docs/evidence/index.md) |
| 3. Applying It on Azure, and Limitations | [docs/azure.md](docs/azure.md) |

Earlier, longer versions of the report are kept in [docs/archive/](docs/archive/).

---

## Repository Structure

```text
.
├── docs/                      # Site content (Markdown)
│   ├── lab.md
│   ├── azure.md
│   ├── evidence/              # Results page, original assessment files, harness runs
│   └── archive/               # Version 1.4 pages, kept for reference
├── lab/                       # Test harness
│   ├── triad_tests.py         # Runs TC-01 to TC-13 on AWS or Azure
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
python lab/triad_tests.py --platform aws
```

See [lab/README.md](lab/README.md). Only test environments you own or are authorized to test.

## Preview the Site Locally

```bash
pip install -r requirements.txt
python site_builder/build.py
python -m http.server -d _site 8000
```

---

