import re

from vaultsweep.models import Severity
from vaultsweep.rules.base import RegexRule, RuleMeta

# Stellar Muxed Account (M-address): M + 68 base32 chars (A-Z, 2-7), 69 chars total
_STELLAR_MUXED_ACCOUNT = re.compile(r"\bM[A-Z2-7]{68}\b")

# Stellar Federation address (e.g., alice*stellar.org) assigned in config/source
_STELLAR_FEDERATION_ADDRESS = re.compile(
    r"\b[a-zA-Z0-9_.+-]{1,64}\*(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,24}\b"
)


class StellarMuxedAccountRule(RegexRule):
    meta = RuleMeta(
        rule_id="STELLAR-002",
        name="Stellar Muxed Account Identifier",
        severity=Severity.LOW,
        description="Hardcoded Stellar muxed account (M-address, 69 chars) detected in source.",
        remediation=(
            "Verify whether the embedded muxed account ID leaks customer sub-account "
            "routing metadata; externalize to configuration if sensitive."
        ),
    )
    pattern = _STELLAR_MUXED_ACCOUNT
    min_length = 69

    def _is_false_positive(self, line: str, matched: str) -> bool:
        if super()._is_false_positive(line, matched):
            return True
        if matched == "M" + "A" * 68 or "MXXXXXXXX" in matched:
            return True
        return False


class StellarFederationAddressRule(RegexRule):
    meta = RuleMeta(
        rule_id="STELLAR-003",
        name="Stellar Federation Address Pattern",
        severity=Severity.LOW,
        description="Stellar federation address (name*domain.tld) detected in source.",
        remediation=(
            "Ensure hardcoded federation addresses do not expose private payment "
            "identities or internal federation endpoints."
        ),
    )
    pattern = _STELLAR_FEDERATION_ADDRESS
    min_length = 6

    def _is_false_positive(self, line: str, matched: str) -> bool:
        if super()._is_false_positive(line, matched):
            return True
        # Ignore markdown bold/italics or glob patterns or multiplication expressions
        if "/" in matched or " " in matched:
            return True
        return False
