"""Pytest configuration and shared fixtures."""

from __future__ import annotations

import pytest

from champion import AddrValidator


@pytest.fixture
def validator() -> AddrValidator:
    """Create a standard validator with local address detection disabled."""
    return AddrValidator(autodetect_local_addresses=False)


@pytest.fixture
def validator_ipv6() -> AddrValidator:
    """Create a validator with IPv6 enabled."""
    return AddrValidator(
        allow_ipv6=True,
        autodetect_local_addresses=False,
    )


@pytest.fixture
def validator_all_tunneling() -> AddrValidator:
    """Create a validator with all tunneling mechanisms enabled."""
    return AddrValidator(
        allow_ipv6=True,
        allow_teredo=True,
        allow_6to4=True,
        allow_dns64=True,
        autodetect_local_addresses=False,
    )
