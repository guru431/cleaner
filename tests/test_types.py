from cleaner.core.detect.base import load_builtin
from cleaner.core.types import EntityType, Policy, default_policies


def test_secret_is_hidden_by_default_and_everything_else_is_masked():
    policies = default_policies()
    assert policies[EntityType.SECRET] is Policy.HIDE
    assert {p for t, p in policies.items() if t is not EntityType.SECRET} == {Policy.MASK}


def test_builtin_lists_are_lowercase_and_skip_comments():
    builtin = load_builtin()
    assert "microsoft.com" in builtin.well_known_domains
    assert "www" in builtin.generic_labels
    assert "администратор" in builtin.builtin_accounts
    assert "py" in builtin.ambiguous_suffixes
    assert not any(item.startswith("#") for item in builtin.well_known_domains)
