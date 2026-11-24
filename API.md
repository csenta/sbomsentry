# SBOMsentry API Reference

## Python Library Usage

```python
from sbomsentry.core.sbom_parser import SBOMParser
from sbomsentry.core.graph_engine import DependencyGraphEngine
from sbomsentry.analyzers.vulnerability_engine import VulnerabilityEngine
from sbomsentry.analyzers.typosquat_detector import TyposquatDetector
from sbomsentry.analyzers.license_auditor import LicenseAuditor
from sbomsentry.analyzers.remediation_synthesizer import RemediationSynthesizer
from sbomsentry.reporters.cli_reporter import CLIReporter

# 1. Parse SBOM or manifest
target_name, components, edges = SBOMParser.parse_file("examples/cyclonedx_sbom.json")

# 2. Build Dependency Graph
graph = DependencyGraphEngine(target_name, components, edges)

# 3. Scan for Vulnerabilities and Trace Paths
vuln_engine = VulnerabilityEngine()
vulnerabilities = vuln_engine.scan_components(components, graph)

# 4. Detect Typosquats
typosquat_engine = TyposquatDetector()
typosquats = typosquat_engine.analyze(components)

# 5. Audit Licenses
license_engine = LicenseAuditor(proprietary_mode=True)
licenses = license_engine.audit_components(components)

# 6. Synthesize Upgrades
remediations = RemediationSynthesizer.synthesize(vulnerabilities)
```
