from vaultsweep.rules.api_keys import API_KEY_RULES
from vaultsweep.rules.base import Rule, RuleMeta
from vaultsweep.rules.default_credentials import DefaultCredentialRule
from vaultsweep.rules.mnemonic import MnemonicPhraseRule
from vaultsweep.rules.multilang import MULTILANG_RULES
from vaultsweep.rules.rpc_creds import RpcEmbeddedCredentialRule
from vaultsweep.rules.stellar_secret_key import StellarSecretKeyRule

ALL_RULES: list[Rule] = [
    StellarSecretKeyRule(),
    MnemonicPhraseRule(),
    DefaultCredentialRule(),
    RpcEmbeddedCredentialRule(),
    *API_KEY_RULES,
    *MULTILANG_RULES,
]


def list_rules() -> list[RuleMeta]:
    return [r.meta for r in ALL_RULES]
