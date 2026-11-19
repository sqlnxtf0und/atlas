"""DNS collector behaviour against a zone-backed fake resolver.

No network. The resolver is a double, the rdata is real dnspython data, and every
assertion is about normalization, error translation and scope discipline.
"""

from __future__ import annotations

import dns.resolver
import pytest

from atlas.collect.base import CollectionTarget, DnsAnswerObservation, NameStatusObservation
from atlas.collect.dns import DEFAULT_RECORD_TYPES, DnsCollector
from atlas.config import Settings
from atlas.db.enums import DnsRecordType, TargetKind
from atlas.errors import ScopeViolation
from support import FakeResolver, RecordingLimiter, make_context, zone_of


def domain_target(value: str = "example.com") -> CollectionTarget:
    return CollectionTarget(kind=TargetKind.DOMAIN, value=value)


def collector(resolver: FakeResolver, *, follow: bool = True) -> DnsCollector:
    return DnsCollector(settings=Settings(), resolver=resolver, follow_cnames=follow)


def answers(result_observations: object) -> list[DnsAnswerObservation]:
    return [o for o in result_observations if isinstance(o, DnsAnswerObservation)]  # type: ignore[union-attr]


def test_collects_the_standard_record_set() -> None:
    resolver = zone_of(
        {
            "example.com": {
                "A": ["203.0.113.10", "203.0.113.11"],
                "AAAA": ["2001:db8::10"],
                "MX": ["10 mail.example.com.", "20 backup.example.com."],
                "NS": ["ns1.example.net.", "ns2.example.net."],
                "TXT": ['"v=spf1 -all"'],
                "SOA": [
                    "ns1.example.net. hostmaster.example.com. 2024010101 7200 3600 1209600 300"
                ],
                "CAA": ['0 issue "letsencrypt.org"'],
            }
        }
    )
    context = make_context(Settings(), ["example.com"])

    result = collector(resolver).collect(domain_target(), context)

    assert result.ok
    by_type: dict[DnsRecordType, set[str]] = {}
    for observation in answers(result.observations):
        by_type.setdefault(observation.record_type, set()).add(observation.value)

    assert by_type[DnsRecordType.A] == {"203.0.113.10", "203.0.113.11"}
    assert by_type[DnsRecordType.AAAA] == {"2001:db8::10"}
    assert by_type[DnsRecordType.MX] == {"mail.example.com", "backup.example.com"}
    assert by_type[DnsRecordType.NS] == {"ns1.example.net", "ns2.example.net"}
    assert by_type[DnsRecordType.TXT] == {"v=spf1 -all"}
    assert any(
        v.startswith("ns1.example.net hostmaster.example.com") for v in by_type[DnsRecordType.SOA]
    )
    assert by_type[DnsRecordType.CAA] == {'0 issue "letsencrypt.org"'}

    mx = next(o for o in answers(result.observations) if o.record_type is DnsRecordType.MX)
    assert mx.priority in {10, 20}
    assert mx.ttl == 300
    assert result.stats["checked_types"] == sorted(t.value for t in DEFAULT_RECORD_TYPES)


def test_nxdomain_stops_the_run_and_is_recorded() -> None:
    resolver = FakeResolver()  # knows no names at all
    context = make_context(Settings(), ["missing.example.com"])

    result = collector(resolver).collect(domain_target("missing.example.com"), context)

    statuses = [o for o in result.observations if isinstance(o, NameStatusObservation)]
    assert len(statuses) == 1
    assert statuses[0].status == "NXDOMAIN"
    assert statuses[0].exists is False
    assert answers(result.observations) == []
    # NXDOMAIN answers the question for the whole name, so every type counts as checked.
    assert len(result.stats["checked_types"]) == len(DEFAULT_RECORD_TYPES)


def test_no_answer_is_not_an_error() -> None:
    resolver = zone_of({"example.com": {"A": ["203.0.113.10"]}})
    context = make_context(Settings(), ["example.com"])

    result = collector(resolver).collect(domain_target(), context)

    assert result.ok
    assert "AAAA" in result.stats["checked_types"]
    assert not any(o.record_type is DnsRecordType.AAAA for o in answers(result.observations))


def test_timeout_is_recorded_and_not_checked() -> None:
    resolver = zone_of({"example.com": {"A": ["203.0.113.10"]}})
    resolver.failures[("example.com", "MX")] = TimeoutError("no answer in time")
    context = make_context(Settings(), ["example.com"])

    result = collector(resolver).collect(domain_target(), context)

    assert result.partial
    assert [e.operation for e in result.errors] == ["MX"]
    assert "MX" not in result.stats["checked_types"]
    assert any(o.record_type is DnsRecordType.A for o in answers(result.observations))


def test_dangling_cname_is_evidenced_not_inferred() -> None:
    resolver = zone_of(
        {
            "www.example.com": {"CNAME": ["unclaimed.example.net."]},
            "example.com": {"A": ["203.0.113.10"]},
        }
    )
    context = make_context(Settings(), ["example.com", "www.example.com"])

    result = collector(resolver).collect(domain_target("www.example.com"), context)

    statuses = {
        o.query_name: o for o in result.observations if isinstance(o, NameStatusObservation)
    }
    assert statuses["unclaimed.example.net"].exists is False
    assert statuses["unclaimed.example.net"].status == "NXDOMAIN"


def test_resolving_cname_target_is_marked_resolved() -> None:
    resolver = zone_of(
        {
            "www.example.com": {"CNAME": ["app.example.net."]},
            "app.example.net": {"A": ["203.0.113.20"]},
        }
    )
    context = make_context(Settings(), ["example.com", "www.example.com"])

    result = collector(resolver).collect(domain_target("www.example.com"), context)

    statuses = {
        o.query_name: o for o in result.observations if isinstance(o, NameStatusObservation)
    }
    assert statuses["app.example.net"].exists is True
    assert result.stats["cname_checks"] == 1


def test_cname_following_can_be_disabled() -> None:
    resolver = zone_of({"www.example.com": {"CNAME": ["app.example.net."]}})
    context = make_context(Settings(), ["www.example.com"])

    result = collector(resolver, follow=False).collect(domain_target("www.example.com"), context)

    assert result.stats.get("cname_checks") is None
    assert not any(isinstance(o, NameStatusObservation) for o in result.observations)


def test_scope_violation_aborts_before_any_query() -> None:
    resolver = zone_of({"example.com": {"A": ["203.0.113.10"]}})
    context = make_context(Settings(), ["other.example"])

    with pytest.raises(ScopeViolation):
        collector(resolver).collect(domain_target("example.com"), context)
    assert resolver.queries == []


def test_rate_limiter_is_consulted_per_query() -> None:
    resolver = zone_of({"example.com": {"A": ["203.0.113.10"], "TXT": ['"hello"']}})
    limiter = RecordingLimiter()
    context = make_context(Settings(), ["example.com"], limiter=limiter)

    collector(resolver).collect(domain_target(), context)

    assert limiter.keys.count("dns:example.com") == len(DEFAULT_RECORD_TYPES)


def test_deadline_stops_further_types() -> None:
    resolver = zone_of({"example.com": {"A": ["203.0.113.10"]}})
    context = make_context(Settings(), ["example.com"], deadline_seconds=-1)

    result = collector(resolver).collect(domain_target(), context)

    assert result.errors
    assert result.errors[0].error_type == "deadline"
    assert resolver.queries == []


def test_ptr_for_address_target() -> None:
    resolver = zone_of({"10.113.0.203.in-addr.arpa": {"PTR": ["host.example.com."]}})
    context = make_context(Settings(), ["203.0.113.0/24"])

    target = CollectionTarget(kind=TargetKind.IP, value="203.0.113.10")
    result = collector(resolver).collect(target, context)

    assert result.ok
    ptr = [o for o in answers(result.observations) if o.record_type is DnsRecordType.PTR]
    assert [o.value for o in ptr] == ["host.example.com"]


def test_cidr_target_is_rejected_with_a_clear_error() -> None:
    resolver = FakeResolver()
    context = make_context(Settings(), ["203.0.113.0/24"])
    target = CollectionTarget(kind=TargetKind.CIDR, value="203.0.113.0/24")

    result = collector(resolver).collect(target, context)

    assert result.errors[0].error_type == "unsupported_target"


def test_nameserver_failure_is_translated_to_connection_error() -> None:
    resolver = FakeResolver()
    resolver.names.add("example.com")
    resolver.failures[("example.com", "A")] = dns.resolver.NoNameservers()
    context = make_context(Settings(), ["example.com"])

    result = collector(resolver).collect(domain_target(), context)

    error = next(e for e in result.errors if e.operation == "A")
    assert error.error_type == "ConnectionError"
    assert error.retryable is True
