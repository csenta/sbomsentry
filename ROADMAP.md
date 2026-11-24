# SBOMsentry Roadmap

## Phase 1: Ingestion & Dependency DAG (Completed)
- [x] Multi-format SBOM ingestion: CycloneDX JSON/XML and SPDX JSON.
- [x] Manifest ingestion: Python `requirements.txt` and npm `package-lock.json`.
- [x] Directed Acyclic Graph (DAG) generation with path reachability and transitive depth.

## Phase 2: Threat & Compliance Analyzers (Completed)
- [x] Embedded vulnerability intelligence database with semantic version range comparison.
- [x] Advanced typosquatting and visual homoglyph detection against canonical registries.
- [x] License compliance auditor with copyleft and commercial policy classification.
- [x] Minimal-breaking-change automated remediation synthesizer.

## Phase 3: Reporting, CI/CD, and Verification (Completed)
- [x] CLI interface with `scan`, `graph`, `audit`, and `remediate`.
- [x] Standalone interactive HTML5 visual supply chain risk dashboard.
- [x] CI/CD break-build quality gate (`--fail-on-cvss`).
- [x] Multi-platform containerization and GitHub Actions verification.
