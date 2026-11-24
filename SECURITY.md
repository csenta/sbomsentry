# Security Policy

## Security Model

SBOMsentry performs read-only static analysis on software bill of materials and dependency manifests.

### Safe by Design
- **Local Analysis**: Analysis executes offline in isolated environments. No analyzed dependencies or proprietary component metadata are sent to external networks.
- **Deterministic Evaluation**: Graph reachability and vulnerability correlations are computed locally using validated semver logic.

## Reporting a Vulnerability

If you discover a vulnerability in SBOMsentry:
1. Do not create public GitHub issues.
2. Report the vulnerability privately via GitHub Security Advisories to the repository maintainers.
