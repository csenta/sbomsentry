"""
Typosquatting and Impersonation Analyzer for SBOMsentry.
Evaluates dependency names against canonical open-source package registries to detect supply-chain attacks.
"""

from sbomsentry.core.models import Component, TyposquatFinding

# Curated reference set of top canonical packages frequently targeted by typosquatters
CANONICAL_PACKAGES = [
    # PyPI
    "requests", "urllib3", "numpy", "pandas", "scipy", "flask", "django",
    "fastapi", "pydantic", "boto3", "botocore", "cryptography", "pytest",
    "torch", "tensorflow", "transformers", "scikit-learn", "pyyaml", "pillow",
    "beautifulsoup4", "wheel", "setuptools", "jinja2", "certifi", "six",
    # NPM
    "lodash", "express", "react", "react-dom", "axios", "moment", "chalk",
    "commander", "debug", "webpack", "babel", "next", "vue", "async",
    "typescript", "rxjs", "tslib", "body-parser", "dotenv", "uuid",
]


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculates Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def homoglyph_check(name: str, canonical: str) -> bool:
    """Detects visual homoglyph substitutions (e.g. 0 -> o, 1 -> l)."""
    trans = str.maketrans({"0": "o", "1": "l", "5": "s", "8": "b", "_": "-", "v": "u"})
    norm_name = name.translate(trans)
    norm_canonical = canonical.translate(trans)
    return norm_name == norm_canonical and name != canonical


class TyposquatDetector:
    """Detects malicious typosquatting and dependency confusion attacks."""

    def __init__(self, canonical_list: list[str] | None = None):
        self.canonicals = set(canonical_list or CANONICAL_PACKAGES)

    def analyze(self, components: list[Component]) -> list[TyposquatFinding]:
        findings: list[TyposquatFinding] = []

        for comp in components:
            name = comp.name.lower()
            if name in self.canonicals:
                continue  # Legitimate canonical package

            for can in self.canonicals:
                # 1. Homoglyph check
                if homoglyph_check(name, can):
                    findings.append(
                        TyposquatFinding(
                            component_name=comp.name,
                            suspected_canonical=can,
                            distance=1,
                            similarity=0.95,
                            reason=f"Visual homoglyph / character substitution of canonical package '{can}'",
                            severity="CRITICAL",
                        )
                    )
                    break

                # 2. Levenshtein distance check
                # Only compare if lengths are comparable and longer than 3 chars
                if len(can) >= 4 and abs(len(name) - len(can)) <= 2:
                    dist = levenshtein_distance(name, can)
                    max_len = max(len(name), len(can))
                    sim = 1.0 - (dist / max_len)

                    if dist == 1:
                        findings.append(
                            TyposquatFinding(
                                component_name=comp.name,
                                suspected_canonical=can,
                                distance=dist,
                                similarity=sim,
                                reason=f"Single-character mutation/typo of canonical package '{can}' (edit distance 1)",
                                severity="HIGH",
                            )
                        )
                        break
                    elif dist == 2 and max_len >= 7:
                        findings.append(
                            TyposquatFinding(
                                component_name=comp.name,
                                suspected_canonical=can,
                                distance=dist,
                                similarity=sim,
                                reason=f"Close edit distance ({dist}) to canonical package '{can}'",
                                severity="MEDIUM",
                            )
                        )
                        break

        return findings
