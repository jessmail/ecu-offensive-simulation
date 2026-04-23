"""
Test report generator with ISO 21434 compliance.

Produces structured security assessment reports with CVSS scoring,
risk matrices, and remediation recommendations. Outputs to JSON
and Markdown formats.
"""

from __future__ import annotations

import json
import logging
import math
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class Severity(Enum):
    """Finding severity levels aligned with CVSS v3.1."""

    CRITICAL = auto()  # CVSS 9.0-10.0
    HIGH = auto()      # CVSS 7.0-8.9
    MEDIUM = auto()    # CVSS 4.0-6.9
    LOW = auto()       # CVSS 0.1-3.9
    INFO = auto()      # Informational


class AttackVector(Enum):
    """CVSS v3.1 Attack Vector (adapted for automotive)."""

    NETWORK = "N"      # Remote via DoIP / Ethernet
    ADJACENT = "A"     # CAN bus / local network
    LOCAL = "L"        # OBD-II physical access
    PHYSICAL = "P"     # Direct ECU hardware access


class AttackComplexity(Enum):
    """CVSS v3.1 Attack Complexity."""

    LOW = "L"
    HIGH = "H"


class PrivilegesRequired(Enum):
    """CVSS v3.1 Privileges Required."""

    NONE = "N"
    LOW = "L"
    HIGH = "H"


class UserInteraction(Enum):
    """CVSS v3.1 User Interaction."""

    NONE = "N"
    REQUIRED = "R"


class Impact(Enum):
    """CVSS v3.1 Impact metric values."""

    NONE = "N"
    LOW = "L"
    HIGH = "H"


@dataclass
class CVSSScore:
    """CVSS v3.1 Base Score calculation."""

    attack_vector: AttackVector
    attack_complexity: AttackComplexity
    privileges_required: PrivilegesRequired
    user_interaction: UserInteraction
    scope_changed: bool
    confidentiality_impact: Impact
    integrity_impact: Impact
    availability_impact: Impact

    @property
    def base_score(self) -> float:
        """Calculate CVSS v3.1 base score."""
        iss = self._impact_sub_score()
        if iss <= 0:
            return 0.0

        exploitability = self._exploitability_sub_score()

        if self.scope_changed:
            score = min(
                1.08 * (iss + exploitability),
                10.0,
            )
        else:
            score = min(iss + exploitability, 10.0)

        return math.ceil(score * 10) / 10

    @property
    def severity(self) -> Severity:
        """Map base score to severity."""
        score = self.base_score
        if score >= 9.0:
            return Severity.CRITICAL
        if score >= 7.0:
            return Severity.HIGH
        if score >= 4.0:
            return Severity.MEDIUM
        if score > 0.0:
            return Severity.LOW
        return Severity.INFO

    @property
    def vector_string(self) -> str:
        """Generate CVSS v3.1 vector string."""
        scope = "C" if self.scope_changed else "U"
        return (
            f"CVSS:3.1/AV:{self.attack_vector.value}/AC:{self.attack_complexity.value}/"
            f"PR:{self.privileges_required.value}/UI:{self.user_interaction.value}/"
            f"S:{scope}/C:{self.confidentiality_impact.value}/"
            f"I:{self.integrity_impact.value}/A:{self.availability_impact.value}"
        )

    def _impact_sub_score(self) -> float:
        """Calculate Impact Sub-Score (ISS)."""
        isc_conf = self._impact_value(self.confidentiality_impact)
        isc_integ = self._impact_value(self.integrity_impact)
        isc_avail = self._impact_value(self.availability_impact)

        isc_base = 1 - (1 - isc_conf) * (1 - isc_integ) * (1 - isc_avail)

        if self.scope_changed:
            return 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
        else:
            return 6.42 * isc_base

    def _exploitability_sub_score(self) -> float:
        """Calculate Exploitability Sub-Score."""
        av = {
            AttackVector.NETWORK: 0.85,
            AttackVector.ADJACENT: 0.62,
            AttackVector.LOCAL: 0.55,
            AttackVector.PHYSICAL: 0.20,
        }[self.attack_vector]

        ac = {
            AttackComplexity.LOW: 0.77,
            AttackComplexity.HIGH: 0.44,
        }[self.attack_complexity]

        if self.scope_changed:
            pr = {
                PrivilegesRequired.NONE: 0.85,
                PrivilegesRequired.LOW: 0.68,
                PrivilegesRequired.HIGH: 0.50,
            }
        else:
            pr = {
                PrivilegesRequired.NONE: 0.85,
                PrivilegesRequired.LOW: 0.62,
                PrivilegesRequired.HIGH: 0.27,
            }
        pr_val = pr[self.privileges_required]

        ui = {
            UserInteraction.NONE: 0.85,
            UserInteraction.REQUIRED: 0.62,
        }[self.user_interaction]

        return 8.22 * av * ac * pr_val * ui

    @staticmethod
    def _impact_value(impact: Impact) -> float:
        return {Impact.NONE: 0.0, Impact.LOW: 0.22, Impact.HIGH: 0.56}[impact]


@dataclass
class Finding:
    """A single security finding."""

    finding_id: str
    title: str
    description: str
    category: str
    cvss: CVSSScore
    evidence: str
    remediation: str
    iso_21434_clause: str = ""
    affected_component: str = ""
    references: list[str] = field(default_factory=list)

    @property
    def severity(self) -> Severity:
        return self.cvss.severity

    def to_dict(self) -> dict:
        return {
            "id": self.finding_id,
            "title": self.title,
            "severity": self.severity.name,
            "cvss_score": self.cvss.base_score,
            "cvss_vector": self.cvss.vector_string,
            "description": self.description,
            "category": self.category,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "iso_21434_clause": self.iso_21434_clause,
            "affected_component": self.affected_component,
            "references": self.references,
        }


# Pre-defined finding templates for common automotive vulnerabilities
FINDING_TEMPLATES: dict[str, dict] = {
    "seed_reuse": {
        "title": "SecurityAccess Seed Reuse",
        "description": (
            "The ECU's SecurityAccess implementation reuses seed values across "
            "multiple authentication attempts. An attacker who captures a valid "
            "seed-key pair can replay the key when the same seed is issued again, "
            "bypassing authentication without knowledge of the key derivation algorithm."
        ),
        "category": "Authentication",
        "cvss": CVSSScore(
            attack_vector=AttackVector.ADJACENT,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope_changed=False,
            confidentiality_impact=Impact.HIGH,
            integrity_impact=Impact.HIGH,
            availability_impact=Impact.HIGH,
        ),
        "remediation": (
            "Implement a cryptographically secure random number generator (CSPRNG) "
            "for seed generation. Ensure seeds are never reused across sessions. "
            "Consider implementing a monotonic counter or timestamp component."
        ),
        "iso_21434_clause": "Clause 9 - Cybersecurity validation",
    },
    "weak_key_derivation": {
        "title": "Weak Key Derivation Algorithm",
        "description": (
            "The ECU uses a trivially reversible key derivation algorithm "
            "(e.g., XOR with constant, bitwise complement). An attacker can "
            "reverse-engineer the algorithm from a single captured seed-key pair."
        ),
        "category": "Cryptography",
        "cvss": CVSSScore(
            attack_vector=AttackVector.ADJACENT,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope_changed=True,
            confidentiality_impact=Impact.HIGH,
            integrity_impact=Impact.HIGH,
            availability_impact=Impact.LOW,
        ),
        "remediation": (
            "Replace the key derivation with a standardized algorithm such as "
            "CMAC-AES or HMAC-SHA256 with a per-ECU secret key stored in secure "
            "hardware (HSM/SHE). Implement the security access as defined in "
            "ISO 14229-1 Annex I."
        ),
        "iso_21434_clause": "Clause 8 - Threat analysis and risk assessment",
    },
    "ecu_crash": {
        "title": "ECU Denial of Service via Malformed Input",
        "description": (
            "The ECU becomes unresponsive when receiving specific malformed "
            "diagnostic messages, indicating insufficient input validation. "
            "This can lead to a denial-of-service condition requiring a power "
            "cycle to recover."
        ),
        "category": "Input Validation",
        "cvss": CVSSScore(
            attack_vector=AttackVector.ADJACENT,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope_changed=False,
            confidentiality_impact=Impact.NONE,
            integrity_impact=Impact.NONE,
            availability_impact=Impact.HIGH,
        ),
        "remediation": (
            "Implement robust input validation for all diagnostic services. "
            "Use a watchdog timer to recover from unexpected states. "
            "Apply fuzz testing as part of the verification process."
        ),
        "iso_21434_clause": "Clause 9 - Cybersecurity validation",
    },
    "unauthorized_write": {
        "title": "Unauthorized Write Access Without Authentication",
        "description": (
            "The ECU accepts WriteDataByIdentifier or RequestDownload requests "
            "without requiring prior SecurityAccess authentication, allowing "
            "modification of ECU data or firmware."
        ),
        "category": "Authorization",
        "cvss": CVSSScore(
            attack_vector=AttackVector.ADJACENT,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope_changed=True,
            confidentiality_impact=Impact.HIGH,
            integrity_impact=Impact.HIGH,
            availability_impact=Impact.HIGH,
        ),
        "remediation": (
            "Enforce SecurityAccess authentication for all write operations. "
            "Implement defense-in-depth with additional integrity checks "
            "(e.g., signature verification for firmware updates)."
        ),
        "iso_21434_clause": "Clause 15 - Vulnerability analysis",
    },
    "session_timeout_missing": {
        "title": "Missing Diagnostic Session Timeout",
        "description": (
            "The ECU does not enforce a session timeout for extended or "
            "programming diagnostic sessions. Once a session is established, "
            "it remains active indefinitely without TesterPresent messages."
        ),
        "category": "Session Management",
        "cvss": CVSSScore(
            attack_vector=AttackVector.ADJACENT,
            attack_complexity=AttackComplexity.HIGH,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope_changed=False,
            confidentiality_impact=Impact.LOW,
            integrity_impact=Impact.LOW,
            availability_impact=Impact.NONE,
        ),
        "remediation": (
            "Implement P3 server timeout (typically 5 seconds) to automatically "
            "return to the default session when no TesterPresent is received. "
            "Ensure SecurityAccess state is cleared on session timeout."
        ),
        "iso_21434_clause": "Clause 9 - Cybersecurity validation",
    },
}


class ReportGenerator:
    """Generates ISO 21434 compliant security assessment reports."""

    def __init__(
        self,
        project_name: str = "ECU Security Assessment",
        assessor: str = "Security Engineering Team",
        target_ecu: str = "Target ECU",
    ) -> None:
        """Initialize report generator.

        Args:
            project_name: Name of the assessment project.
            assessor: Name of the assessor / team.
            target_ecu: Name or identifier of the target ECU.
        """
        self._project_name = project_name
        self._assessor = assessor
        self._target_ecu = target_ecu
        self._findings: list[Finding] = []
        self._finding_counter = 0
        self._start_time = time.time()
        self._metadata: dict = {}

    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the report."""
        self._findings.append(finding)
        logger.info("Finding added: [%s] %s (%s)",
                     finding.finding_id, finding.title, finding.severity.name)

    def add_finding_from_template(
        self,
        template_key: str,
        evidence: str,
        affected_component: str = "",
        **overrides,
    ) -> Finding:
        """Create and add a finding from a predefined template.

        Args:
            template_key: Key from FINDING_TEMPLATES.
            evidence: Specific evidence for this finding.
            affected_component: Affected ECU component.
            **overrides: Override any template field.

        Returns:
            The created Finding object.
        """
        if template_key not in FINDING_TEMPLATES:
            raise ValueError(f"Unknown template: {template_key}")

        template = FINDING_TEMPLATES[template_key].copy()
        template.update(overrides)

        self._finding_counter += 1
        finding_id = f"FIND-{self._finding_counter:03d}"

        finding = Finding(
            finding_id=finding_id,
            title=template["title"],
            description=template["description"],
            category=template["category"],
            cvss=template["cvss"],
            evidence=evidence,
            remediation=template["remediation"],
            iso_21434_clause=template.get("iso_21434_clause", ""),
            affected_component=affected_component,
        )

        self.add_finding(finding)
        return finding

    def set_metadata(self, **kwargs) -> None:
        """Set additional report metadata."""
        self._metadata.update(kwargs)

    def generate_risk_matrix(self) -> str:
        """Generate a text-based risk matrix visualization.

        Returns:
            ASCII risk matrix showing finding distribution.
        """
        # Impact (Y-axis) vs Likelihood (X-axis)
        matrix = {
            "CRITICAL": {"High": 0, "Medium": 0, "Low": 0},
            "HIGH": {"High": 0, "Medium": 0, "Low": 0},
            "MEDIUM": {"High": 0, "Medium": 0, "Low": 0},
            "LOW": {"High": 0, "Medium": 0, "Low": 0},
        }

        for f in self._findings:
            severity = f.severity.name
            if severity not in matrix:
                continue
            # Map attack complexity to likelihood
            if f.cvss.attack_complexity == AttackComplexity.LOW:
                likelihood = "High"
            else:
                likelihood = "Medium" if f.cvss.attack_vector in (AttackVector.ADJACENT, AttackVector.LOCAL) else "Low"
            matrix[severity][likelihood] += 1

        lines = [
            "Risk Matrix (Findings Distribution)",
            "=" * 50,
            "",
            "Impact       | Likelihood                    ",
            "             | High     | Medium   | Low     ",
            "-------------|----------|----------|----------",
        ]

        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            row = matrix[severity]
            lines.append(
                f" {severity:<12}|  {row['High']:<8}|  {row['Medium']:<8}|  {row['Low']:<8}"
            )

        lines.append("-" * 50)
        return "\n".join(lines)

    def generate_json(self) -> dict:
        """Generate the complete report as a JSON-serializable dict.

        Returns:
            Report data dictionary.
        """
        severity_counts = {}
        for f in self._findings:
            name = f.severity.name
            severity_counts[name] = severity_counts.get(name, 0) + 1

        return {
            "report": {
                "title": self._project_name,
                "target_ecu": self._target_ecu,
                "assessor": self._assessor,
                "date": datetime.now().isoformat(),
                "framework_version": "1.0.0",
                "iso_21434_compliant": True,
                "metadata": self._metadata,
            },
            "executive_summary": {
                "total_findings": len(self._findings),
                "severity_distribution": severity_counts,
                "highest_severity": max(
                    (f.severity for f in self._findings),
                    key=lambda s: list(Severity).index(s),
                    default=Severity.INFO,
                ).name if self._findings else "NONE",
                "overall_risk": self._calculate_overall_risk(),
            },
            "findings": [f.to_dict() for f in self._findings],
            "risk_matrix": self.generate_risk_matrix(),
        }

    def generate_markdown(self) -> str:
        """Generate the complete report in Markdown format.

        Returns:
            Markdown report string.
        """
        report_data = self.generate_json()
        lines: list[str] = []

        # Header
        lines.append(f"# {self._project_name}")
        lines.append("")
        lines.append(f"**Target:** {self._target_ecu}")
        lines.append(f"**Assessor:** {self._assessor}")
        lines.append(f"**Date:** {datetime.now().strftime('%Y-%m-%d')}")
        lines.append(f"**Standard:** ISO 21434:2021 - Road vehicles - Cybersecurity engineering")
        lines.append("")

        # Executive Summary
        lines.append("## Executive Summary")
        lines.append("")
        summary = report_data["executive_summary"]
        lines.append(f"This assessment identified **{summary['total_findings']} findings** "
                      f"across the target ECU's diagnostic interface.")
        lines.append("")
        lines.append("### Severity Distribution")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = summary["severity_distribution"].get(sev, 0)
            if count > 0:
                lines.append(f"| {sev} | {count} |")
        lines.append("")

        lines.append(f"**Overall Risk Rating:** {summary['overall_risk']}")
        lines.append("")

        # Risk Matrix
        lines.append("### Risk Matrix")
        lines.append("")
        lines.append("```")
        lines.append(self.generate_risk_matrix())
        lines.append("```")
        lines.append("")

        # Findings
        lines.append("## Findings")
        lines.append("")

        for finding in sorted(self._findings, key=lambda f: list(Severity).index(f.severity)):
            lines.append(f"### {finding.finding_id}: {finding.title}")
            lines.append("")
            lines.append(f"**Severity:** {finding.severity.name} "
                          f"(CVSS {finding.cvss.base_score})")
            lines.append(f"**Vector:** `{finding.cvss.vector_string}`")
            lines.append(f"**Category:** {finding.category}")
            if finding.affected_component:
                lines.append(f"**Affected Component:** {finding.affected_component}")
            if finding.iso_21434_clause:
                lines.append(f"**ISO 21434:** {finding.iso_21434_clause}")
            lines.append("")

            lines.append("**Description:**")
            lines.append("")
            lines.append(finding.description)
            lines.append("")

            lines.append("**Evidence:**")
            lines.append("")
            lines.append(f"```\n{finding.evidence}\n```")
            lines.append("")

            lines.append("**Remediation:**")
            lines.append("")
            lines.append(finding.remediation)
            lines.append("")
            lines.append("---")
            lines.append("")

        # ISO 21434 Compliance
        lines.append("## ISO 21434 Compliance Notes")
        lines.append("")
        lines.append("This assessment addresses the following ISO 21434 clauses:")
        lines.append("")
        clauses = set(f.iso_21434_clause for f in self._findings if f.iso_21434_clause)
        for clause in sorted(clauses):
            lines.append(f"- {clause}")
        lines.append("")

        # Disclaimer
        lines.append("## Disclaimer")
        lines.append("")
        lines.append(
            "This report is provided for authorized security assessment purposes only. "
            "Findings are based on the specific test conditions and ECU firmware version "
            "at the time of testing. Results may vary with different configurations "
            "or software versions."
        )
        lines.append("")

        return "\n".join(lines)

    def save(self, filepath: str, fmt: str = "markdown") -> None:
        """Save the report to a file.

        Args:
            filepath: Output file path.
            fmt: Format ('markdown' or 'json').
        """
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)

        if fmt == "json":
            with open(path, "w") as f:
                json.dump(self.generate_json(), f, indent=2)
        elif fmt == "markdown":
            with open(path, "w") as f:
                f.write(self.generate_markdown())
        else:
            raise ValueError(f"Unsupported format: {fmt}")

        logger.info("Report saved to %s (%s)", filepath, fmt)

    def _calculate_overall_risk(self) -> str:
        """Calculate overall risk rating based on all findings."""
        if not self._findings:
            return "NONE"

        max_score = max(f.cvss.base_score for f in self._findings)
        critical_count = sum(1 for f in self._findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in self._findings if f.severity == Severity.HIGH)

        if critical_count >= 2 or max_score >= 9.5:
            return "CRITICAL"
        if critical_count >= 1 or max_score >= 9.0:
            return "HIGH"
        if high_count >= 2 or max_score >= 7.0:
            return "HIGH"
        if max_score >= 4.0:
            return "MEDIUM"
        if max_score > 0:
            return "LOW"
        return "NONE"
