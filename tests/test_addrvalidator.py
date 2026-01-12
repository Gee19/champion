"""Tests for the AddrValidator class."""

from __future__ import annotations

import ipaddress
import re
import socket
from unittest.mock import patch

import pytest

from champion.addrvalidator import (
    AddrValidator,
    canonicalize_hostname,
    determine_local_addresses,
)
from champion.exceptions import ConfigException, NameserverException


class TestCanonicalizeHostname:
    """Tests for hostname canonicalization."""

    def test_lowercase(self) -> None:
        """Should lowercase ASCII characters."""
        assert canonicalize_hostname("EXAMPLE.COM") == "example.com"

    def test_mixed_case(self) -> None:
        """Should handle mixed case."""
        assert canonicalize_hostname("ExAmPlE.CoM") == "example.com"

    def test_already_lowercase(self) -> None:
        """Should handle already lowercase hostnames."""
        assert canonicalize_hostname("example.com") == "example.com"

    def test_idn(self) -> None:
        """Should convert IDN to punycode."""
        # "münchen.de" should become "xn--mnchen-3ya.de"
        assert canonicalize_hostname("münchen.de") == "xn--mnchen-3ya.de"

    def test_idn_uppercase(self) -> None:
        """Should handle uppercase IDN."""
        assert canonicalize_hostname("MÜNCHEN.DE") == "xn--mnchen-3ya.de"


class TestDetermineLocalAddresses:
    """Tests for local address detection."""

    def test_without_netifaces(self) -> None:
        """Should raise ConfigException when netifaces is not available."""
        with (
            patch("champion.addrvalidator.HAVE_NETIFACES", False),
            pytest.raises(ConfigException, match="netifaces"),
        ):
            determine_local_addresses()

    @pytest.mark.skipif(
        not hasattr(socket, "if_nameindex"),
        reason="Platform doesn't support interface enumeration",
    )
    def test_with_netifaces(self) -> None:
        """Should return a list of IP networks when netifaces is available."""
        # This test will only pass if netifaces is installed
        try:
            import netifaces  # noqa: F401

            addresses = determine_local_addresses()
            assert isinstance(addresses, list)
            for addr in addresses:
                assert isinstance(
                    addr, (ipaddress.IPv4Network, ipaddress.IPv6Network)
                )
        except ImportError:
            pytest.skip("netifaces not installed")


class TestAddrValidatorIPv4:
    """Tests for IPv4 address validation."""

    @pytest.fixture
    def validator(self) -> AddrValidator:
        """Create a validator with autodetect disabled for testing."""
        return AddrValidator(autodetect_local_addresses=False)

    def test_public_ip_allowed(self, validator: AddrValidator) -> None:
        """Should allow public IP addresses."""
        assert validator.is_ip_allowed("8.8.8.8", _local_addresses=[])
        assert validator.is_ip_allowed("1.1.1.1", _local_addresses=[])
        assert validator.is_ip_allowed("93.184.216.34", _local_addresses=[])

    def test_loopback_blocked(self, validator: AddrValidator) -> None:
        """Should block loopback addresses."""
        assert not validator.is_ip_allowed("127.0.0.1", _local_addresses=[])
        assert not validator.is_ip_allowed("127.255.255.255", _local_addresses=[])

    def test_private_10_blocked(self, validator: AddrValidator) -> None:
        """Should block 10.0.0.0/8 addresses."""
        assert not validator.is_ip_allowed("10.0.0.1", _local_addresses=[])
        assert not validator.is_ip_allowed("10.255.255.255", _local_addresses=[])

    def test_private_172_blocked(self, validator: AddrValidator) -> None:
        """Should block 172.16.0.0/12 addresses."""
        assert not validator.is_ip_allowed("172.16.0.1", _local_addresses=[])
        assert not validator.is_ip_allowed("172.31.255.255", _local_addresses=[])

    def test_private_192_blocked(self, validator: AddrValidator) -> None:
        """Should block 192.168.0.0/16 addresses."""
        assert not validator.is_ip_allowed("192.168.0.1", _local_addresses=[])
        assert not validator.is_ip_allowed("192.168.255.255", _local_addresses=[])

    def test_link_local_blocked(self, validator: AddrValidator) -> None:
        """Should block link-local addresses (169.254.x.x)."""
        assert not validator.is_ip_allowed("169.254.0.1", _local_addresses=[])
        assert not validator.is_ip_allowed("169.254.169.254", _local_addresses=[])

    def test_multicast_blocked(self, validator: AddrValidator) -> None:
        """Should block multicast addresses."""
        assert not validator.is_ip_allowed("224.0.0.1", _local_addresses=[])
        assert not validator.is_ip_allowed("239.255.255.255", _local_addresses=[])

    def test_reserved_blocked(self, validator: AddrValidator) -> None:
        """Should block reserved addresses."""
        assert not validator.is_ip_allowed("240.0.0.1", _local_addresses=[])

    def test_unspecified_blocked(self, validator: AddrValidator) -> None:
        """Should block unspecified address."""
        assert not validator.is_ip_allowed("0.0.0.0", _local_addresses=[])

    def test_6to4_relay_blocked(self, validator: AddrValidator) -> None:
        """Should block 6to4 relay anycast addresses."""
        assert not validator.is_ip_allowed("192.88.99.1", _local_addresses=[])

    def test_carrier_grade_nat_blocked(self, validator: AddrValidator) -> None:
        """Should block carrier-grade NAT addresses."""
        assert not validator.is_ip_allowed("100.64.0.1", _local_addresses=[])
        assert not validator.is_ip_allowed("100.127.255.255", _local_addresses=[])


class TestAddrValidatorIPv6:
    """Tests for IPv6 address validation."""

    @pytest.fixture
    def validator(self) -> AddrValidator:
        """Create a validator with IPv6 enabled."""
        return AddrValidator(
            allow_ipv6=True,
            autodetect_local_addresses=False,
        )

    @pytest.fixture
    def validator_no_ipv6(self) -> AddrValidator:
        """Create a validator with IPv6 disabled."""
        return AddrValidator(
            allow_ipv6=False,
            autodetect_local_addresses=False,
        )

    def test_ipv6_blocked_by_default(self, validator_no_ipv6: AddrValidator) -> None:
        """Should block IPv6 when not explicitly enabled."""
        # Public IPv6 address
        assert not validator_no_ipv6.is_ip_allowed(
            "2001:4860:4860::8888", _local_addresses=[]
        )

    def test_public_ipv6_allowed(self, validator: AddrValidator) -> None:
        """Should allow public IPv6 addresses when enabled."""
        # Google's public DNS
        assert validator.is_ip_allowed("2001:4860:4860::8888", _local_addresses=[])

    def test_loopback_ipv6_blocked(self, validator: AddrValidator) -> None:
        """Should block IPv6 loopback."""
        assert not validator.is_ip_allowed("::1", _local_addresses=[])

    def test_link_local_ipv6_blocked(self, validator: AddrValidator) -> None:
        """Should block IPv6 link-local addresses."""
        assert not validator.is_ip_allowed("fe80::1", _local_addresses=[])

    def test_site_local_ipv6_blocked(self, validator: AddrValidator) -> None:
        """Should block IPv6 site-local addresses (deprecated)."""
        assert not validator.is_ip_allowed("fec0::1", _local_addresses=[])

    def test_ipv4_mapped_ipv6_blocked(self, validator: AddrValidator) -> None:
        """Should block IPv4-mapped IPv6 addresses with private IPv4."""
        # ::ffff:127.0.0.1
        assert not validator.is_ip_allowed("::ffff:127.0.0.1", _local_addresses=[])
        # ::ffff:192.168.1.1
        assert not validator.is_ip_allowed("::ffff:192.168.1.1", _local_addresses=[])


class TestAddrValidatorTunneling:
    """Tests for IPv6 tunneling mechanism validation."""

    @pytest.fixture
    def validator_teredo(self) -> AddrValidator:
        """Create a validator with Teredo enabled."""
        return AddrValidator(
            allow_ipv6=True,
            allow_teredo=True,
            autodetect_local_addresses=False,
        )

    @pytest.fixture
    def validator_6to4(self) -> AddrValidator:
        """Create a validator with 6to4 enabled."""
        return AddrValidator(
            allow_ipv6=True,
            allow_6to4=True,
            autodetect_local_addresses=False,
        )

    @pytest.fixture
    def validator_no_teredo(self) -> AddrValidator:
        """Create a validator with Teredo disabled."""
        return AddrValidator(
            allow_ipv6=True,
            allow_teredo=False,
            autodetect_local_addresses=False,
        )

    def test_teredo_blocked_by_default(self, validator_no_teredo: AddrValidator) -> None:
        """Should block Teredo addresses by default."""
        # Teredo address format: 2001:0:server:flags:client
        assert not validator_no_teredo.is_ip_allowed(
            "2001:0:4136:e378:8000:63bf:3fff:fdd2", _local_addresses=[]
        )

    def test_6to4_blocked_by_default(self) -> None:
        """Should block 6to4 addresses by default."""
        validator = AddrValidator(
            allow_ipv6=True,
            allow_6to4=False,
            autodetect_local_addresses=False,
        )
        # 6to4 address embedding 8.8.8.8
        assert not validator.is_ip_allowed("2002:808:808::1", _local_addresses=[])


class TestAddrValidatorBlacklist:
    """Tests for IP blacklisting."""

    def test_manual_blacklist(self) -> None:
        """Should block manually blacklisted IPs."""
        validator = AddrValidator(
            ip_blacklist={ipaddress.ip_network("203.0.113.0/24")},
            autodetect_local_addresses=False,
        )
        assert not validator.is_ip_allowed("203.0.113.1", _local_addresses=[])
        assert not validator.is_ip_allowed("203.0.113.254", _local_addresses=[])
        # Other addresses should still work
        assert validator.is_ip_allowed("8.8.8.8", _local_addresses=[])


class TestAddrValidatorWhitelist:
    """Tests for IP whitelisting."""

    def test_whitelist_overrides_blacklist(self) -> None:
        """Should allow whitelisted IPs even if they would be blocked."""
        validator = AddrValidator(
            ip_whitelist={ipaddress.ip_network("10.0.0.5/32")},
            autodetect_local_addresses=False,
        )
        # This specific IP is whitelisted
        assert validator.is_ip_allowed("10.0.0.5", _local_addresses=[])
        # Other private IPs are still blocked
        assert not validator.is_ip_allowed("10.0.0.6", _local_addresses=[])

    def test_whitelist_overrides_manual_blacklist(self) -> None:
        """Should allow whitelisted IPs even if manually blacklisted."""
        validator = AddrValidator(
            ip_blacklist={ipaddress.ip_network("8.8.8.0/24")},
            ip_whitelist={ipaddress.ip_network("8.8.8.8/32")},
            autodetect_local_addresses=False,
        )
        # Whitelisted IP works
        assert validator.is_ip_allowed("8.8.8.8", _local_addresses=[])
        # Other IPs in the blacklisted range are blocked
        assert not validator.is_ip_allowed("8.8.8.4", _local_addresses=[])


class TestAddrValidatorLocalAddresses:
    """Tests for local address detection and blocking."""

    def test_local_addresses_blocked(self) -> None:
        """Should block addresses detected as local."""
        validator = AddrValidator(autodetect_local_addresses=False)
        local_addrs = [ipaddress.ip_network("192.0.2.1/32")]
        assert not validator.is_ip_allowed("192.0.2.1", _local_addresses=local_addrs)


class TestAddrValidatorHostname:
    """Tests for hostname validation."""

    @pytest.fixture
    def validator(self) -> AddrValidator:
        """Create a validator with hostname blacklist."""
        return AddrValidator(
            hostname_blacklist={"*.internal.example.com", "blocked.com"},
            autodetect_local_addresses=False,
        )

    def test_blacklisted_hostname(self, validator: AddrValidator) -> None:
        """Should block blacklisted hostnames."""
        assert not validator.is_hostname_allowed("blocked.com")

    def test_blacklisted_hostname_glob(self, validator: AddrValidator) -> None:
        """Should block hostnames matching glob patterns."""
        assert not validator.is_hostname_allowed("foo.internal.example.com")
        assert not validator.is_hostname_allowed("bar.internal.example.com")

    def test_allowed_hostname(self, validator: AddrValidator) -> None:
        """Should allow non-blacklisted hostnames."""
        assert validator.is_hostname_allowed("example.com")
        assert validator.is_hostname_allowed("allowed.com")

    def test_case_insensitive(self, validator: AddrValidator) -> None:
        """Should handle case-insensitive matching."""
        assert not validator.is_hostname_allowed("BLOCKED.COM")
        assert not validator.is_hostname_allowed("Blocked.Com")

    def test_regex_pattern(self) -> None:
        """Should support regex patterns."""
        validator = AddrValidator(
            hostname_blacklist={re.compile(r".*\.evil\.com$")},
            autodetect_local_addresses=False,
        )
        assert not validator.is_hostname_allowed("foo.evil.com")
        assert validator.is_hostname_allowed("evil.com.safe.org")


class TestAddrValidatorPorts:
    """Tests for port validation."""

    def test_default_port_whitelist(self) -> None:
        """Should have default port whitelist."""
        validator = AddrValidator(autodetect_local_addresses=False)
        assert 80 in validator.port_whitelist
        assert 443 in validator.port_whitelist
        assert 8080 in validator.port_whitelist
        assert 8443 in validator.port_whitelist
        assert 8000 in validator.port_whitelist

    def test_custom_port_whitelist(self) -> None:
        """Should support custom port whitelist."""
        validator = AddrValidator(
            port_whitelist={8888, 9999},
            autodetect_local_addresses=False,
        )
        assert 8888 in validator.port_whitelist
        assert 9999 in validator.port_whitelist
        assert 80 not in validator.port_whitelist

    def test_port_blacklist(self) -> None:
        """Should support port blacklist."""
        validator = AddrValidator(
            port_blacklist={22, 23},
            autodetect_local_addresses=False,
        )
        assert 22 in validator.port_blacklist
        assert 23 in validator.port_blacklist


class TestAddrValidatorAddrinfo:
    """Tests for addrinfo validation."""

    @pytest.fixture
    def validator(self) -> AddrValidator:
        """Create a validator for testing."""
        return AddrValidator(autodetect_local_addresses=False)

    def test_valid_addrinfo(self, validator: AddrValidator) -> None:
        """Should allow valid addrinfo."""
        addrinfo = (
            socket.AF_INET,
            socket.SOCK_STREAM,
            6,
            "",
            (ipaddress.ip_address("8.8.8.8"), 80),
        )
        assert validator.is_addrinfo_allowed(addrinfo, _local_addresses=[])

    def test_blocked_port(self, validator: AddrValidator) -> None:
        """Should block non-whitelisted ports."""
        addrinfo = (
            socket.AF_INET,
            socket.SOCK_STREAM,
            6,
            "",
            (ipaddress.ip_address("8.8.8.8"), 22),
        )
        assert not validator.is_addrinfo_allowed(addrinfo, _local_addresses=[])

    def test_blocked_ip_in_addrinfo(self, validator: AddrValidator) -> None:
        """Should block private IPs in addrinfo."""
        addrinfo = (
            socket.AF_INET,
            socket.SOCK_STREAM,
            6,
            "",
            (ipaddress.ip_address("192.168.1.1"), 80),
        )
        assert not validator.is_addrinfo_allowed(addrinfo, _local_addresses=[])

    def test_hostname_blacklist_requires_canonname(self) -> None:
        """Should raise if hostname blacklist is set but canonname is missing."""
        validator = AddrValidator(
            hostname_blacklist={"evil.com"},
            autodetect_local_addresses=False,
        )
        addrinfo = (
            socket.AF_INET,
            socket.SOCK_STREAM,
            6,
            "",  # Empty canonname
            (ipaddress.ip_address("8.8.8.8"), 80),
        )
        with pytest.raises(NameserverException):
            validator.is_addrinfo_allowed(addrinfo, _local_addresses=[])

    def test_ipv6_addrinfo(self, validator: AddrValidator) -> None:
        """Should handle IPv6 addrinfo format."""
        validator_ipv6 = AddrValidator(
            allow_ipv6=True,
            autodetect_local_addresses=False,
        )
        addrinfo = (
            socket.AF_INET6,
            socket.SOCK_STREAM,
            6,
            "",
            (ipaddress.ip_address("2001:4860:4860::8888"), 80, 0, 0),
        )
        assert validator_ipv6.is_addrinfo_allowed(addrinfo, _local_addresses=[])
