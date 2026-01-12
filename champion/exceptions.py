"""
Champion exception classes.

This module defines all custom exceptions used by Champion for SSRF protection.
"""

from __future__ import annotations


class ChampionException(Exception):
    """Base exception for all Champion-related errors."""

    pass


class UnacceptableAddressException(ChampionException):
    """Raised when a request targets an address that is not allowed.

    This is the primary exception raised when SSRF protection blocks a request.
    """

    pass


class NameserverException(ChampionException):
    """Raised when DNS resolution provides insufficient information.

    This typically occurs when hostname blacklisting is enabled but the DNS
    server doesn't return canonical names needed for validation.
    """

    pass


class MountDisabledException(ChampionException):
    """Raised when attempting to mount a custom adapter on a Champion session.

    Mounting custom adapters is disabled to prevent bypassing SSRF protections.
    """

    pass


class ProxyDisabledException(NotImplementedError, ChampionException):
    """Raised when attempting to use a proxy with Champion.

    Proxies are disabled because they would bypass SSRF protections by
    allowing the proxy server to connect to restricted addresses.
    """

    pass


class ConfigException(ChampionException):
    """Raised when Champion is misconfigured.

    For example, when local address detection is enabled but the netifaces
    module is not installed.
    """

    pass
