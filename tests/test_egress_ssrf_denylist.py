"""Egress SSRF denylist: private/loopback/link-local/metadata targets must be blocked.

Regression guard for Phase 2 finding H1: the previous string-prefix egress check missed
the cloud-metadata endpoint (169.254.169.254), the 172.16.0.0/12 range, IPv6 loopback,
and numerically-encoded IPs. The fix uses ipaddress-based classification and resolves
DNS names before checking.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "mvar-core"))

from sink_policy import _egress_hostname_is_private  # noqa: E402


@pytest.mark.parametrize(
    "host",
    [
        "169.254.169.254",  # cloud metadata / credential endpoint — the #1 SSRF target
        "169.254.1.1",       # link-local
        "172.16.0.5",        # 172.16.0.0/12 (missed by old prefix check)
        "172.31.255.1",      # 172.16.0.0/12 upper bound
        "10.0.0.1",          # private
        "192.168.1.10",      # private
        "127.0.0.1",         # loopback
        "::1",               # IPv6 loopback (missed by old check)
        "0.0.0.0",           # unspecified
    ],
)
def test_private_and_metadata_targets_are_blocked(host):
    reason = _egress_hostname_is_private(host)
    assert reason is not None, f"{host} should be blocked but was allowed"


def test_known_limitation_integer_notation_ip():
    """HONEST limitation: Python's ipaddress does not parse integer-notation IPs
    (e.g. '2130706433' for 127.0.0.1), so this checker treats them as hostnames.
    Documented rather than falsely claimed as blocked. Mitigation: URL parsing/normalization
    upstream, or the allowlist (default-deny) posture, should reject non-hostname targets."""
    # Not asserting a block — asserting we KNOW it isn't blocked here, so no false claim.
    assert _egress_hostname_is_private("2130706433") is None


@pytest.mark.parametrize("host", ["8.8.8.8", "1.1.1.1"])
def test_public_ips_are_allowed(host):
    assert _egress_hostname_is_private(host) is None


def test_hostnames_are_deterministic_by_default():
    # By default (no DNS), a hostname is governed by the allowlist, not resolution —
    # the private-IP check returns None for names so decisions stay deterministic.
    assert _egress_hostname_is_private("api.example.com") is None
    assert _egress_hostname_is_private("this-host-does-not-exist.invalid") is None


def test_unresolvable_host_fails_closed_when_dns_enabled():
    # With opt-in DNS resolution, an unresolvable host is denied (fail-closed).
    reason = _egress_hostname_is_private(
        "this-host-does-not-exist.invalid", resolve_dns=True
    )
    assert reason is not None


def test_ipv4_mapped_ipv6_metadata_is_blocked():
    # ::ffff:169.254.169.254 must unwrap to the blocked IPv4 metadata address
    assert _egress_hostname_is_private("::ffff:169.254.169.254") is not None
