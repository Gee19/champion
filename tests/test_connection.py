"""Tests for the connection layer."""

from __future__ import annotations

import ipaddress
import socket
from unittest.mock import patch

import pytest

from champion.addrvalidator import AddrValidator
from champion.connection import (
    ValidatingHTTPConnection,
    ValidatingHTTPSConnection,
    champion_getaddrinfo,
    fix_addrinfo,
    validating_create_connection,
)
from champion.exceptions import UnacceptableAddressException


class TestChampionGetaddrinfo:
    """Tests for the champion_getaddrinfo function."""

    def test_returns_tuple(self) -> None:
        """Should return a tuple of address info."""
        # Use a well-known public DNS that should always resolve
        result = champion_getaddrinfo("dns.google", 80)
        assert isinstance(result, tuple)
        assert len(result) > 0

    def test_with_canonname(self) -> None:
        """Should include canonical name when requested."""
        result = champion_getaddrinfo("dns.google", 80, get_canonname=True)
        assert isinstance(result, tuple)
        # First record should have canonname
        if result:
            assert result[0][3]  # canonname field


class TestFixAddrinfo:
    """Tests for the fix_addrinfo function."""

    def test_empty_records(self) -> None:
        """Should handle empty records."""
        result = fix_addrinfo([])
        assert result == ()

    def test_propagates_canonname(self) -> None:
        """Should propagate canonname to all records."""
        records = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "canonical.example.com", ("1.2.3.4", 80)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("5.6.7.8", 80)),
        ]
        result = fix_addrinfo(records)
        assert result[0][3] == "canonical.example.com"
        assert result[1][3] == "canonical.example.com"

    def test_parses_ip_addresses(self) -> None:
        """Should parse IP addresses into ipaddress objects."""
        records = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 80)),
        ]
        result = fix_addrinfo(records)
        ip = result[0][4][0]
        assert isinstance(ip, ipaddress.IPv4Address)
        assert str(ip) == "8.8.8.8"


class TestValidatingCreateConnection:
    """Tests for the validating_create_connection function."""

    @pytest.fixture
    def validator(self) -> AddrValidator:
        """Create a validator for testing."""
        return AddrValidator(autodetect_local_addresses=False)

    def test_blocks_localhost(self, validator: AddrValidator) -> None:
        """Should block connections to localhost."""
        with pytest.raises(UnacceptableAddressException):
            validating_create_connection(
                ("127.0.0.1", 80),
                validator=validator,
            )

    def test_blocks_private_ip(self, validator: AddrValidator) -> None:
        """Should block connections to private IPs."""
        with pytest.raises(UnacceptableAddressException):
            validating_create_connection(
                ("192.168.1.1", 80),
                validator=validator,
            )

    def test_blocks_link_local(self, validator: AddrValidator) -> None:
        """Should block connections to link-local addresses."""
        with pytest.raises(UnacceptableAddressException):
            validating_create_connection(
                ("169.254.169.254", 80),
                validator=validator,
            )

    def test_blocks_hostname_resolving_to_private(self, validator: AddrValidator) -> None:
        """Should block hostnames that resolve to private IPs."""
        with patch("socket.getaddrinfo") as mock_getaddrinfo:
            mock_getaddrinfo.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.1", 80)),
            ]
            with pytest.raises(UnacceptableAddressException):
                validating_create_connection(
                    ("evil.example.com", 80),
                    validator=validator,
                )

    def test_blocks_blacklisted_hostname(self) -> None:
        """Should block blacklisted hostnames."""
        validator = AddrValidator(
            hostname_blacklist={"evil.com"},
            autodetect_local_addresses=False,
        )
        with pytest.raises(UnacceptableAddressException):
            validating_create_connection(
                ("evil.com", 80),
                validator=validator,
            )


class TestValidatingHTTPConnection:
    """Tests for the ValidatingHTTPConnection class."""

    @pytest.fixture
    def validator(self) -> AddrValidator:
        """Create a validator for testing."""
        return AddrValidator(autodetect_local_addresses=False)

    def test_requires_validator(self) -> None:
        """Should require a validator parameter."""
        with pytest.raises(TypeError):
            ValidatingHTTPConnection("example.com")  # type: ignore[call-arg]

    def test_stores_validator(self, validator: AddrValidator) -> None:
        """Should store the validator."""
        conn = ValidatingHTTPConnection("example.com", validator=validator)
        assert conn._validator is validator

    def test_has_new_conn(self, validator: AddrValidator) -> None:
        """Should have _new_conn method."""
        conn = ValidatingHTTPConnection("example.com", validator=validator)
        assert hasattr(conn, "_new_conn")
        assert callable(conn._new_conn)


class TestValidatingHTTPSConnection:
    """Tests for the ValidatingHTTPSConnection class."""

    @pytest.fixture
    def validator(self) -> AddrValidator:
        """Create a validator for testing."""
        return AddrValidator(autodetect_local_addresses=False)

    def test_requires_validator(self) -> None:
        """Should require a validator parameter."""
        with pytest.raises(TypeError):
            ValidatingHTTPSConnection("example.com")  # type: ignore[call-arg]

    def test_stores_validator(self, validator: AddrValidator) -> None:
        """Should store the validator."""
        conn = ValidatingHTTPSConnection("example.com", validator=validator)
        assert conn._validator is validator

    def test_has_new_conn(self, validator: AddrValidator) -> None:
        """Should have _new_conn method."""
        conn = ValidatingHTTPSConnection("example.com", validator=validator)
        assert hasattr(conn, "_new_conn")
        assert callable(conn._new_conn)
