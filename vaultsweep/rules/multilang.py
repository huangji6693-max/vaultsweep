import re

from vaultsweep.models import Severity
from vaultsweep.rules.base import RegexRule, Rule, RuleMeta

# Solidity / EVM 32-byte private key assignment (0x + 64 hex chars in key/secret/privateKey context)
_SOLIDITY_PRIVATE_KEY = re.compile(
    r"""(?ix)
    (?:private_?key|deployer_?key|signer_?key|secret_?key|vm\.rememberKey)
    \s*(?:=|:|\()\s*
    ['"]?(0x[0-9a-fA-F]{64})['"]?
    """
)

# Go hardcoded DSN or secret constant assignment
_GO_DSN_OR_SECRET = re.compile(
    r"""(?ix)
    (?:
        (?:postgres|mysql|mongodb|redis)://[^/\s:'"]+:[^@\s'"]+@[^\s'"]+
        |
        (?:const|var)\s+[A-Za-z0-9_]*(?:Secret|PrivateKey|ApiKey|Password|Seed)\s*(?:string)?\s*=\s*"([^"\n]{12,})"
    )
    """
)

# Java .properties / Spring Boot plaintext credential properties
_JAVA_PROPERTIES_SECRET = re.compile(
    r"""(?ix)
    ^\s*
    (?:
        spring\.(?:datasource|data\.redis|rabbitmq|mail)\.password
        |stellar\.(?:secret|signer|account)\.(?:seed|key|secret)
        |javax\.net\.ssl\.(?:keyStorePassword|trustStorePassword)
        |(?:keystore|truststore|db|database|jwt|api)\.password
    )
    \s*[:=]\s*
    ([^\s#${][^\r\n]{5,})
    """
)


class SolidityPrivateKeyRule(RegexRule):
    meta = RuleMeta(
        rule_id="SOLIDITY-001",
        name="Solidity / EVM Private Key Exposed",
        severity=Severity.CRITICAL,
        description="A 32-byte hexadecimal private key (0x + 64 hex chars) was found in source.",
        remediation=(
            "Use Foundry keystore / environment variables (`vm.envUint`) "
            "instead of hardcoded keys."
        ),
    )
    pattern = _SOLIDITY_PRIVATE_KEY
    min_length = 66

    def _is_false_positive(self, line: str, matched: str) -> bool:
        if super()._is_false_positive(line, matched):
            return True
        lower = matched.lower()
        # Ignore all-zero or trivial repeating hex placeholders
        if "0x" + "0" * 64 in lower or "0x" + "1" * 64 in lower:
            return True
        return False


class GoCredentialRule(RegexRule):
    meta = RuleMeta(
        rule_id="GO-001",
        name="Go Hardcoded DSN or Secret Constant",
        severity=Severity.HIGH,
        description="Hardcoded Go database DSN credential or secret constant detected.",
        remediation="Load Go credentials at runtime via `os.Getenv` or a secret manager.",
    )
    pattern = _GO_DSN_OR_SECRET
    min_length = 12


class JavaPropertiesSecretRule(RegexRule):
    meta = RuleMeta(
        rule_id="JAVA-001",
        name="Java .properties Plaintext Credential",
        severity=Severity.HIGH,
        description="Plaintext password or Stellar seed found in Java .properties configuration.",
        remediation="Externalize sensitive properties using `${ENV_VAR}` placeholders.",
    )
    pattern = _JAVA_PROPERTIES_SECRET
    min_length = 10


MULTILANG_RULES: list[Rule] = [
    SolidityPrivateKeyRule(),
    GoCredentialRule(),
    JavaPropertiesSecretRule(),
]
