# Security Policy

## Responsible Disclosure

CyberCore is an autonomous defensive cybersecurity platform designed to assist security teams with authorized asset inventory, vulnerability intelligence correlation, and controlled evidence gathering.

If you discover a security vulnerability within CyberCore itself:
1. **Do not create a public GitHub issue.**
2. Report vulnerabilities privately to the maintainers by emailing the repository owner or using [GitHub Private Vulnerability Reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-communicating-vulnerabilities/privately-reporting-a-security-vulnerability).
3. Include detailed steps to reproduce, affected components, and potential impact.

## Security Principles of CyberCore

- **Strict Scope Governance**: CyberCore's `PolicyEngine` validates every target against configured CIDRs (`config/policy.yaml`). Public IPs and unapproved networks are rejected by default.
- **Fail-Closed Design**: If database journals, budget coordinators, or approval stores are unavailable, all tool executions are refused (`503 Service Unavailable`).
- **No Arbitrary Shell Execution**: Language models interacting with CyberCore never receive direct shell access. All actions occur through typed, strictly validated Pydantic contracts via the `ToolBroker`.
- **Durable Cryptographic Audit**: Every request, decision, raw output, and evidence artifact is hashed with SHA-256 and persisted in PostgreSQL.
- **Single-Use Approvals**: Medium and high risk actions mandate cryptographically signed, one-time approval tokens issued by a supervisor.
