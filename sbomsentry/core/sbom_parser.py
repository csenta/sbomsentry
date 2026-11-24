"""
Multi-Format SBOM & Lockfile Parser for SBOMsentry.
Supports CycloneDX (JSON), SPDX (JSON), requirements.txt, and package-lock.json.
"""

import json
import os
import re
from typing import Any

from sbomsentry.core.models import Component, Ecosystem


class SBOMParser:
    """Parses various Software Bill of Materials formats and dependency manifests."""

    @staticmethod
    def parse_file(file_path: str) -> tuple[str, list[Component], dict[str, list[str]]]:
        """
        Returns:
            (target_name, list_of_components, dependency_graph_edges)
        """
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Input file not found: {file_path}")

        filename = os.path.basename(file_path).lower()

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read().strip()

        if filename == "requirements.txt" or filename.endswith(".txt"):
            return SBOMParser._parse_requirements_txt(content, filename)

        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise ValueError(f"File {file_path} is neither valid JSON nor requirements.txt: {e}")

        if "bomFormat" in data and data.get("bomFormat") == "CycloneDX":
            return SBOMParser._parse_cyclonedx(data)
        elif "spdxVersion" in data:
            return SBOMParser._parse_spdx(data)
        elif "packages" in data or "dependencies" in data:
            return SBOMParser._parse_package_lock(data, filename)

        # Fallback generic JSON component array
        if isinstance(data, list):
            return SBOMParser._parse_generic_list(data, filename)

        raise ValueError(f"Unrecognized SBOM format in {file_path}")

    @staticmethod
    def _detect_ecosystem(purl: str, default: Ecosystem = Ecosystem.GENERIC) -> Ecosystem:
        if purl.startswith("pkg:pypi/"):
            return Ecosystem.PYPI
        elif purl.startswith("pkg:npm/"):
            return Ecosystem.NPM
        elif purl.startswith("pkg:golang/") or purl.startswith("pkg:go/"):
            return Ecosystem.GOLANG
        elif purl.startswith("pkg:maven/"):
            return Ecosystem.MAVEN
        return default

    @staticmethod
    def _parse_cyclonedx(data: dict[str, Any]) -> tuple[str, list[Component], dict[str, list[str]]]:
        metadata = data.get("metadata", {})
        target_name = metadata.get("component", {}).get("name", "cyclonedx-project")

        components: list[Component] = []
        edges: dict[str, list[str]] = {}

        # Parse components
        for c in data.get("components", []):
            name = c.get("name", "")
            version = c.get("version", "0.0.0")
            purl = c.get("purl", "")
            eco = SBOMParser._detect_ecosystem(purl, Ecosystem.GENERIC)

            licenses = []
            for lic_entry in c.get("licenses", []):
                if "license" in lic_entry:
                    lic_info = lic_entry["license"]
                    lic_name = lic_info.get("id") or lic_info.get("name")
                    if lic_name:
                        licenses.append(lic_name)
                elif "expression" in lic_entry:
                    licenses.append(lic_entry["expression"])

            hashes = {}
            for h in c.get("hashes", []):
                alg = h.get("alg", "").lower()
                val = h.get("content", "")
                if alg and val:
                    hashes[alg] = val

            components.append(
                Component(
                    name=name,
                    version=version,
                    ecosystem=eco,
                    purl=purl,
                    licenses=licenses,
                    hashes=hashes,
                    description=c.get("description", ""),
                )
            )

        # Parse dependencies graph
        for dep in data.get("dependencies", []):
            src_ref = dep.get("ref", "")
            targets = dep.get("dependsOn", [])
            if src_ref:
                edges[src_ref] = targets

        return target_name, components, edges

    @staticmethod
    def _parse_spdx(data: dict[str, Any]) -> tuple[str, list[Component], dict[str, list[str]]]:
        target_name = data.get("name", "spdx-project")
        components: list[Component] = []
        edges: dict[str, list[str]] = {}

        spdx_id_map: dict[str, str] = {}  # SPDXID -> component_name

        for p in data.get("packages", []):
            name = p.get("name", "")
            version = p.get("versionInfo", "0.0.0")
            spdx_id = p.get("SPDXID", "")
            lic = p.get("licenseDeclared") or p.get("licenseConcluded")
            licenses = [lic] if lic and lic != "NOASSERTION" else []

            purl = ""
            for ref in p.get("externalRefs", []):
                if ref.get("referenceType") == "purl":
                    purl = ref.get("referenceLocator", "")

            eco = SBOMParser._detect_ecosystem(purl, Ecosystem.GENERIC)
            spdx_id_map[spdx_id] = name

            components.append(
                Component(
                    name=name,
                    version=version,
                    ecosystem=eco,
                    purl=purl,
                    licenses=licenses,
                    description=p.get("description", ""),
                )
            )

        for rel in data.get("relationships", []):
            if rel.get("relationshipType") == "DEPENDS_ON":
                elem = rel.get("spdxElementId", "")
                related = rel.get("relatedSpdxElement", "")
                src = spdx_id_map.get(elem, elem)
                tgt = spdx_id_map.get(related, related)
                edges.setdefault(src, []).append(tgt)

        return target_name, components, edges

    @staticmethod
    def _parse_package_lock(data: dict[str, Any], filename: str) -> tuple[str, list[Component], dict[str, list[str]]]:
        target_name = data.get("name", filename.replace(".json", ""))
        components: list[Component] = []
        edges: dict[str, list[str]] = {}

        # npm lockfile v2/v3 has "packages"
        if "packages" in data and isinstance(data["packages"], dict):
            for pkg_path, meta in data["packages"].items():
                if not pkg_path:  # Root app
                    continue
                name = pkg_path.split("node_modules/")[-1]
                version = meta.get("version", "0.0.0")
                lic = meta.get("license")
                licenses = [lic] if lic else []

                # Dependencies of this package
                deps = list(meta.get("dependencies", {}).keys())
                edges[name] = deps

                components.append(
                    Component(
                        name=name,
                        version=version,
                        ecosystem=Ecosystem.NPM,
                        purl=f"pkg:npm/{name}@{version}",
                        licenses=licenses,
                        is_direct=not ("node_modules/" in pkg_path and pkg_path.count("node_modules/") > 1),
                    )
                )
        # npm lockfile v1 has "dependencies"
        elif "dependencies" in data and isinstance(data["dependencies"], dict):
            for name, meta in data["dependencies"].items():
                version = meta.get("version", "0.0.0")
                deps = list(meta.get("requires", {}).keys())
                edges[name] = deps
                components.append(
                    Component(
                        name=name,
                        version=version,
                        ecosystem=Ecosystem.NPM,
                        purl=f"pkg:npm/{name}@{version}",
                        is_direct=True,
                    )
                )

        return target_name, components, edges

    @staticmethod
    def _parse_requirements_txt(content: str, filename: str) -> tuple[str, list[Component], dict[str, list[str]]]:
        target_name = filename.replace(".txt", "")
        components: list[Component] = []
        edges: dict[str, list[str]] = {}

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            match = re.match(r"^([a-zA-Z0-9_\-\.]+)(?:[>=<~^!]=?([a-zA-Z0-9_\-\.]+))?", line)
            if match:
                name = match.group(1).lower()
                version = match.group(2) or "latest"
                components.append(
                    Component(
                        name=name,
                        version=version,
                        ecosystem=Ecosystem.PYPI,
                        purl=f"pkg:pypi/{name}@{version}",
                        is_direct=True,
                    )
                )

        return target_name, components, edges

    @staticmethod
    def _parse_generic_list(data: list[Any], filename: str) -> tuple[str, list[Component], dict[str, list[str]]]:
        target_name = filename
        components = []
        for item in data:
            if isinstance(item, dict):
                components.append(
                    Component(
                        name=item.get("name", "unknown"),
                        version=item.get("version", "0.0.0"),
                        purl=item.get("purl", ""),
                        licenses=item.get("licenses", []),
                    )
                )
        return target_name, components, {}
