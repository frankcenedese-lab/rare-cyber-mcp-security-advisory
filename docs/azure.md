# Applying It on Azure, and Limitations

**Platform:** Azure reference design (not yet tested)  
**Sources:** Microsoft Learn documentation for Entra ID, managed identities, Conditional Access and API Management  
**Author:** Frank Cenedese, CISSP, CISA

---

## The same problem, in Azure terms

Least privilege for an agent has two layers on any cloud:

| Layer | Question | AWS lab (tested) | Azure reference design |
| :--- | :--- | :--- | :--- |
| **Caller authorization** | Which tools may this agent call? | MCP server checks each tool's required role | API Management checks a per-tool app role in the agent's Entra token |
| **Tool credential** | What can each tool reach once it runs? | One IAM execution role per tool | One user-assigned managed identity per tool, with Azure RBAC on one resource |

The lab's finding sits in the second layer. On AWS the over-provisioned account was one IAM role shared by every tool. **On Azure it is usually one managed identity shared by every tool**, holding broad roles and often a tenant-wide Microsoft Graph permission. Checking only which tools an agent may call leaves that account in place.

<div class="ba" markdown="1">
<div class="before" markdown="1">

**Before:** one managed identity for every tool

```bash
az role assignment create --assignee "$MCP_MI" \
  --role "Contributor" --scope "$FINANCE_RG_ID"
az role assignment create --assignee "$MCP_MI" \
  --role "Storage Blob Data Contributor" --scope "$STORAGE_ACCOUNT_ID"
# Plus Microsoft Graph application permission Sites.ReadWrite.All
```

The Graph permission reaches every SharePoint site in the tenant.

</div>
<div class="after" markdown="1">

**After:** one identity per tool, scoped to one resource

```bash
az identity create -g rg-mcp -n mi-tool-customer-lookup
az role assignment create --assignee "$MI_LOOKUP" \
  --role "Storage Table Data Reader" \
  --scope "$STORAGE_ACCOUNT_ID/tableServices/default/tables/customers"
# Graph: Sites.Selected on one site; Sites.ReadWrite.All removed
```

Each tool runs in its own Function app with only its own identity attached.

</div>
</div>

---

## Where Azure differs from AWS

These differences change how a control is built or tested, not just which service provides it.

| Topic | AWS | Azure | Consequence |
| :--- | :--- | :--- | :--- |
| **Separating tool identities** | Each Lambda function has one execution role | Any code in an app can request a token for any managed identity attached to it | One identity per tool only works if each tool runs in its own app or container |
| **Scope of permissions** | IAM policies can name individual resources | Microsoft Graph application permissions are tenant wide by default | Narrow Graph access with Sites.Selected or Exchange RBAC for Applications, and remove the broad permission |
| **Token lifetime** | Role sessions can be as short as 15 minutes | Managed identity tokens are cached for around 24 hours and can't be force refreshed | Short-lived credentials can't be enforced on the tool identity; the gateway becomes the short-lived control |
| **Access conditions** | IAM condition keys work on any role | Conditional Access covers agent identities (preview) and single-tenant service principals, not managed identities or API keys | Don't rely on Conditional Access for the tool layer |
| **Revocation** | Revoke the role's active sessions | Disabling an identity stops new tokens; issued tokens run to expiry, and role changes on a managed identity can take hours | Block the agent at API Management first |
| **Attribution downstream** | The user's source identity stays on the role session and appears in CloudTrail | A managed identity call carries no user | The API Management log is the only record linking user, agent and tool |
| **Where per-tool checks run** | In the MCP server, because API Gateway can't read the request body | In API Management, which can read the body | Azure can enforce at the gateway |
| **Agent identity** | IAM role for the agent runtime | Entra Agent ID: agent identities created from a blueprint, each with a sponsor. In delegated calls the user is the token subject and the agent appears in `azp` and `xms_act_fct` | Check those claims at the gateway |

Agents built in Copilot Studio or Microsoft 365 Copilot follow a different model: connectors carry their own credentials, and no customer gateway is in the path by default. They are out of scope here.

**Next step:** build the Azure lab with the same four tools and run TC-01 to TC-03 there, then TC-13 to measure how long access actually continues after a managed identity's role is removed.

---

## Limitations

| Area | Limitation |
| :--- | :--- |
| **Environment** | A lab with synthetic data, one agent and four tools. Production environments need their own testing. |
| **Test coverage** | Three of sixteen threats are tested, two are verified in the repository, nine have defined tests not yet run, and two have none. Untested threats are reported as planned, never as mitigated. |
| **Azure** | The Azure material is a reference design based on Microsoft's documentation. No Azure test has been run. |
| **Prompt injection** | Content inspection is probabilistic and can be bypassed by adaptive attacks. |
| **Delegation** | The lab records the user behind each call but doesn't yet cap the agent at the user's own rights. |
| **Original evidence** | The original assessment files predate the evidence standard; TC-01 to TC-03 will be re-run with the harness. |
| **Framework mappings** | Mappings to OWASP and NIST are the author's analysis and don't replace a formal assessment. |

## Residual risk

- **Novel injection** that content inspection doesn't recognize. Per-tool identities cap the damage, which is why identity, not detection, is the primary control.
- **Misuse within granted rights:** an agent acting within its role can still take a wrong action. Separation of duties and human approval for high-risk tools reduce this.
- **Revocation lag:** a disabled agent can keep working until its tokens expire, and on Azure that window can be much longer.
- **Data leakage through logs or the agent's responses** (I2, I3) is identified but not yet controlled.

Logs record identifiers and decisions (user, agent, tool, outcome and a hash of the arguments), not full payloads, to limit the personal information they hold, consistent with PIPEDA's limits on collection and retention.

## Authorization

All testing was performed in environments owned and controlled by the author. Run the test harness only against systems you own or are authorized to test.

## Change log

| Version | Date | Changes |
| :--- | :--- | :--- |
| 2.0 | 2026-11-11 | Condensed to four pages focused on what was built and tested. Anchored on OWASP least agency and NIST SP 800-53. Removed non-standard terms and the agent identity maturity model. Earlier pages are kept in the repository archive. |
| 1.4 | 2026-11-11 | Azure material corrected against Microsoft's documentation: two layers of least privilege and the platform differences. |
| 1.0 to 1.3 | 2026-11-10 | Initial report, threat model, test harness and critical review corrections. |

## Sources

* [Managed identities FAQ: token caching](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/managed-identities-faq)
* [Conditional Access: users, groups, agents and workload identities](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-users-groups)
* [Continuous access evaluation for workload identities](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation-workload)
* [Selected permissions in Microsoft Graph](https://learn.microsoft.com/en-us/graph/permissions-selected-overview)
* [RBAC for Applications in Exchange Online](https://learn.microsoft.com/en-us/exchange/permissions-exo/application-rbac)
* [What is Microsoft Entra Agent ID?](https://learn.microsoft.com/en-us/entra/agent-id/what-is-microsoft-entra-agent-id)
* [MCP servers in Azure API Management](https://learn.microsoft.com/en-us/azure/api-management/mcp-server-overview)
* [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
