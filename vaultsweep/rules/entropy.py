import math
import re
from collections import Counter

from vaultsweep.models import Finding, Severity
from vaultsweep.rules.base import Rule, RuleMeta

# Matches assignment expressions with a 32+ char token:
# e.g. SECRET_TOKEN = "a9F3kL8mQ2pR7vX1zB5nM4cW6yT0jH8dG2sE"
_ASSIGNMENT_RE = re.compile(
    r"""(?ix)
    (?:^|[\s,;{(])
    (?P<key>[a-z0-9_.-]*(?:secret|token|key|password|passwd|pwd|private|seed|credential|auth)[a-z0-9_.-]*)
    \s*(?:=|:|:=)\s*
    ['"]?(?P<val>[A-Za-z0-9+/=_-]{32,})['"]?
    """
)

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_STELLAR_PUBLIC_OR_SECRET_RE = re.compile(r"^[GSM][A-Z2-7]{55,68}$")
_KNOWN_PREFIXES = ("sk-ant-", "ghp_", "gho_", "AKIA", "ASIA", "http://", "https://")


def shannon_entropy(value: str) -> float:
    """Compute Shannon entropy in bits per character."""
    if not value:
        return 0.0
    length = len(value)
    counts = Counter(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _has_character_diversity(value: str) -> bool:
    has_lower = any(c.islower() for c in value)
    has_upper = any(c.isupper() for c in value)
    has_digit = any(c.isdigit() for c in value)
    classes = sum((has_lower, has_upper, has_digit))
    # Accept either >=2 character classes (e.g. hex with digits+letters or mixed case/digits)
    return classes >= 2


class HighEntropySecretRule(Rule):
    meta = RuleMeta(
        rule_id="ENTROPY-001",
        name="High-Entropy Secret Assignment",
        severity=Severity.HIGH,
        description="High-entropy 32+ character string assigned to a secret/key/token variable.",
        remediation="Move high-entropy credentials to environment variables or a secret manager.",
    )

    min_length: int = 32
    entropy_threshold: float = 4.0

    def scan_line(self, file_path: str, line_no: int, line: str) -> list[Finding]:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            return []
        lower_line = line.lower()
        if "example" in lower_line or "placeholder" in lower_line or "fixture" in lower_line:
            return []
        if "${" in line:
            return []

        findings: list[Finding] = []
        for m in _ASSIGNMENT_RE.finditer(line):
            candidate = m.group("val")
            if len(candidate) < self.min_length:
                continue
            if candidate.startswith(_KNOWN_PREFIXES):
                continue
            if _UUID_RE.match(candidate) or _STELLAR_PUBLIC_OR_SECRET_RE.match(candidate):
                continue
            if not _has_character_diversity(candidate):
                continue
            if shannon_entropy(candidate) < self.entropy_threshold:
                continue
            findings.append(
                self._finding(
                    file_path,
                    line_no,
                    m.start("val") + 1,
                    candidate,
                )
            )
        return findings
