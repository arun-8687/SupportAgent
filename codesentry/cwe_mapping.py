"""CWE → OWASP 2025 mapping engine."""

from __future__ import annotations

from typing import Dict, Optional, Tuple

from codesentry.models import CWEEntry, Finding, OWASPCategory

# ---------------------------------------------------------------------------
# CWE name lookup
# ---------------------------------------------------------------------------
CWE_NAMES: Dict[str, str] = {
    "CWE-16": "Configuration",
    "CWE-17": "DEPRECATED: Code",
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Path Traversal",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-site Scripting (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-94": "Code Injection",
    "CWE-200": "Exposure of Sensitive Information",
    "CWE-250": "Execution with Unnecessary Privileges",
    "CWE-284": "Improper Access Control",
    "CWE-287": "Improper Authentication",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-311": "Missing Encryption of Sensitive Data",
    "CWE-321": "Use of Hard-coded Cryptographic Key",
    "CWE-327": "Use of Broken Crypto Algorithm",
    "CWE-330": "Use of Insufficiently Random Values",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-732": "Incorrect Permission Assignment",
    "CWE-754": "Improper Check for Unusual Conditions",
    "CWE-755": "Improper Handling of Exceptional Conditions",
    "CWE-770": "Allocation of Resources Without Limits",
    "CWE-778": "Insufficient Logging",
    "CWE-787": "Out-of-bounds Write",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-829": "Inclusion of Functionality from Untrusted Control Sphere",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
}

# ---------------------------------------------------------------------------
# CWE → OWASP 2025 Top-10 mapping
# Each value is (owasp_id, owasp_name)
# ---------------------------------------------------------------------------
CWE_TO_OWASP_2025: Dict[str, Tuple[str, str]] = {
    # A01 – Broken Access Control
    "CWE-22": ("A01", "Broken Access Control"),
    "CWE-200": ("A01", "Broken Access Control"),
    "CWE-284": ("A01", "Broken Access Control"),
    "CWE-352": ("A01", "Broken Access Control"),
    "CWE-732": ("A01", "Broken Access Control"),
    "CWE-862": ("A01", "Broken Access Control"),
    "CWE-863": ("A01", "Broken Access Control"),
    "CWE-918": ("A01", "Broken Access Control"),
    # A02 – Security Misconfiguration
    "CWE-17": ("A02", "Security Misconfiguration"),
    "CWE-16": ("A02", "Security Misconfiguration"),
    "CWE-250": ("A02", "Security Misconfiguration"),
    "CWE-770": ("A02", "Security Misconfiguration"),
    # A04 – Cryptographic Failures
    "CWE-311": ("A04", "Cryptographic Failures"),
    "CWE-321": ("A04", "Cryptographic Failures"),
    "CWE-327": ("A04", "Cryptographic Failures"),
    "CWE-330": ("A04", "Cryptographic Failures"),
    # A05 – Injection
    "CWE-20": ("A05", "Injection"),
    "CWE-78": ("A05", "Injection"),
    "CWE-79": ("A05", "Injection"),
    "CWE-89": ("A05", "Injection"),
    "CWE-94": ("A05", "Injection"),
    "CWE-787": ("A05", "Injection"),
    # A07 – Authentication Failures
    "CWE-287": ("A07", "Authentication Failures"),
    "CWE-306": ("A07", "Authentication Failures"),
    "CWE-798": ("A07", "Authentication Failures"),
    # A08 – Software and Data Integrity Failures
    "CWE-502": ("A08", "Software and Data Integrity Failures"),
    "CWE-829": ("A08", "Software and Data Integrity Failures"),
    # A09 – Security Logging and Monitoring Failures
    "CWE-778": ("A09", "Security Logging and Monitoring Failures"),
    # A10 – Mishandling Exceptional Conditions
    "CWE-754": ("A10", "Mishandling Exceptional Conditions"),
    "CWE-755": ("A10", "Mishandling Exceptional Conditions"),
}


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def get_cwe_entry(cwe_id: str) -> CWEEntry:
    """Return a :class:`CWEEntry` for the given CWE identifier.

    If the CWE is not in the local name table the entry is still returned
    with a generic name so callers always get a valid object.
    """
    name = CWE_NAMES.get(cwe_id, cwe_id)
    return CWEEntry(id=cwe_id, name=name)


def get_owasp_for_cwe(cwe_id: str) -> Optional[OWASPCategory]:
    """Look up the OWASP 2025 Top-10 category for a CWE identifier."""
    mapping = CWE_TO_OWASP_2025.get(cwe_id)
    if mapping is None:
        return None
    owasp_id, owasp_name = mapping
    return OWASPCategory(id=owasp_id, year=2025, name=owasp_name)


def enrich_finding(finding: Finding) -> Finding:
    """Add OWASP category to a finding that has a CWE but no OWASP mapping.

    Returns a **new** :class:`Finding` instance with the enriched data so
    the original object is not mutated.
    """
    if finding.cwe is None or finding.owasp is not None:
        return finding

    owasp = get_owasp_for_cwe(finding.cwe.id)
    if owasp is None:
        return finding

    return finding.model_copy(update={"owasp": owasp})
