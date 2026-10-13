"""Проверки окружения этапа 1: библиотеки работают на установленном Python и без сети."""
import pytest
import regex
import tldextract


def test_tldextract_works_offline_with_bundled_list():
    extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, extra_suffixes=("local",))
    public = extract("srv-dc01.msk.corp.contoso.ru")
    assert (public.subdomain, public.domain, public.suffix) == ("srv-dc01.msk.corp", "contoso", "ru")
    internal = extract("srv1.corp.local")
    assert (internal.subdomain, internal.domain, internal.suffix) == ("srv1", "corp", "local")
    assert extract("setup.unknownext").suffix == ""


def test_regex_module_interrupts_a_slow_pattern():
    with pytest.raises(TimeoutError):
        regex.search(r"^(a|aa)+$", "a" * 40 + "!", timeout=0.2)


def test_detect_secrets_scans_a_plain_string():
    from detect_secrets.core.plugins.util import get_mapping_from_secret_type_to_class
    from detect_secrets.core.scan import scan_line
    from detect_secrets.settings import transient_settings

    names = sorted(cls.__name__ for cls in get_mapping_from_secret_type_to_class().values())
    assert "AWSKeyDetector" in names
    with transient_settings({"plugins_used": [{"name": n} for n in names]}):
        found = [secret.secret_value for secret in scan_line("aws_access_key_id = REDACTED_AWS_ACCESS_KEY")]
    assert "REDACTED_AWS_ACCESS_KEY" in found
