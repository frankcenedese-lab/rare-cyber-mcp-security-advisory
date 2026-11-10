# Rare Cyber: Model Context Protocol (MCP) Security Advisory & TRIAD Framework

[![Governance Standard: TRIAD v1.0](https://img.shields.io/badge/Governance-TRIAD%20v1.0-blue.svg)](#the-triad-framework)
[![Compliance Alignment: NIST / ISO / OWASP](https://img.shields.io/badge/Compliance-NIST%20%7C%20ISO%2042001%20%7C%20OWASP-green.svg)](#standards--compliance-mapping)
[![Cloud Focus: Multi-Cloud AWS & Azure](https://img.shields.io/badge/Multi--Cloud-AWS%20%26%20Microsoft-orange.svg)](#multi-cloud-architecture)
graph TD
    subgraph AWS_Hardened_Stack["AWS Engineering Baseline"]
        A1[AWS API Gateway + SigV4] --> A2[AWS IAM Role per Tool]
        A2 --> A3[Bedrock Guardrails & WAF]
        A3 --> A4[CloudWatch & CloudTrail]
    end

    subgraph Microsoft_Enterprise_Stack["Microsoft Enterprise Stack"]
        M1[Azure APIM + JWT Validation] --> M2[Entra ID Workload Identity]
        M2 --> M3[Power Platform DLP & Purview]
        M3 --> M4[Microsoft Sentinel]
    end

    A1 -. "1:1 Architectural Mapping" .-> M1
    A2 -. "Least-Privilege Isolation" .-> M2
    A3 -. "Egress & Data Protection" .-> M3
    A4 -. "Audit Correlation" .-> M4

    style AWS_Hardened_Stack fill:#fff3e0,stroke:#ff9800,stroke-width:2px
    style Microsoft_Enterprise_Stack fill:#e3f2fd,stroke:#2196f3,stroke-width:2px

---

## Overview

As enterprise adoption of Agentic AI and the **Model Context Protocol (MCP)** rapidly accelerates, default unhardened deployments expose organizations to critical risk vectors—most notably **Identity Flattening** (where all tools share a single elevated service credential) and **Indirect Prompt Injection** (where unvalidated tool outputs hijack model execution).

This repository serves as the official advisory baseline and proof-of-concept repository for **Rare Cyber Advisory Services**, establishing the **TRIAD Framework** for enterprise MCP hardening.

---

## Repository Structure

```text
.
├── advisory/
│   ├── executive-brief.md          # CISO Executive Advisory Brief & Business Context
│   └── azure-copilot-mapping.md    # Multi-Cloud Architectural Translation (AWS ➔ Entra ID/APIM)
├── evidence/
│   ├── scan-vulnerable.json        # Pre-hardening vulnerability audit baseline
│   └── scan-hardened.json          # Post-hardening compliance validation telemetry
└── README.md                       # Master Repository Architecture
