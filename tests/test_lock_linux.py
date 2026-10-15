"""deploy/lock_linux.py: отказ от версий моложе MIN_AGE_DAYS (сеть подменена, время — подставное)."""
from datetime import datetime, timedelta, timezone

from deploy import lock_linux

NOW = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)


def test_versions_published_less_than_two_weeks_ago_are_refused():
    published = {
        ("truststore", "0.10.5"): NOW - timedelta(days=3),
        ("httpx2", "2.13.1"): NOW - timedelta(days=22),
        ("torch", "2.14.1"): NOW - timedelta(days=13, hours=23),
        ("local-only", "1.0"): None,                     # нет на PyPI — проверять нечего
    }
    pins = {name: (version + ("+cpu" if name == "torch" else ""), []) for name, version in published}
    young = lock_linux.too_young(pins, sorted(pins), NOW, lambda name, version: published[(name, version)])
    assert young == ["torch==2.14.1 (01.10.2026)", "truststore==0.10.5 (12.10.2026)"]


def test_a_version_exactly_two_weeks_old_is_taken():
    pins = {"pytest": ("9.1.1", [])}
    assert lock_linux.too_young(pins, ["pytest"], NOW, lambda *_: NOW - timedelta(days=14)) == []
