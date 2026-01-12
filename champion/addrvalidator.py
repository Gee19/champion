"""
Address validation for SSRF protection.

This module provides the core validation logic that determines whether a
network address is safe to connect to.
"""

from __future__ import annotations

import fnmatch
import functools
import ipaddress
import re
from collections.abc import Callable, Iterable
from re import Pattern
from typing import TYPE_CHECKING, Any, TypeVar

from .exceptions import ConfigException, NameserverException

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

# Try to import netifaces for local address detection
try:
    import netifaces

    HAVE_NETIFACES = True
except ImportError:
    netifaces = None  # type: ignore[assignment]
    HAVE_NETIFACES = False


F = TypeVar("F", bound=Callable[..., Any])


def canonicalize_hostname(hostname: str) -> str:
    """Lowercase and convert a hostname to punycode.

    We do the lowercasing after IDNA encoding because we only want to
    lowercase the ASCII characters.

    Args:
        hostname: The hostname to canonicalize.

    Returns:
        The canonicalized hostname in lowercase punycode.
    """
    return hostname.encode("idna").lower().decode("utf-8")


def determine_local_addresses() -> list[IPv4Network | IPv6Network]:
    """Get all IP addresses that refer to this machine using netifaces.

    Returns:
        List of IP networks representing local addresses.

    Raises:
        ConfigException: If netifaces module is not available.
    """
    if not HAVE_NETIFACES:
        raise ConfigException(
            "Tried to determine local addresses, but netifaces module was not importable"
        )

    ips: list[IPv4Network | IPv6Network] = []
    for interface in netifaces.interfaces():
        if_families = netifaces.ifaddresses(interface)
        for family_kind in {netifaces.AF_INET, netifaces.AF_INET6}:
            addrs = if_families.get(family_kind, [])
            for addr_info in addrs:
                addr = addr_info.get("addr", "")
                if not addr:
                    continue
                if family_kind == netifaces.AF_INET6:
                    # Remove scope ID for IPv6 addresses
                    addr = addr.split("%")[0]
                try:
                    ips.append(ipaddress.ip_network(addr))
                except ValueError:
                    # Skip malformed addresses
                    continue
    return ips


def add_local_address_arg(func: F) -> F:
    """Decorator to add the _local_addresses kwarg if missing.

    This information shouldn't be cached between calls (what if one of the
    adapters got a new IP at runtime?), and we don't want each function to
    recalculate it. Just recalculate it if the caller didn't provide it for us.
    """

    @functools.wraps(func)
    def wrapper(self: AddrValidator, *args: Any, **kwargs: Any) -> Any:
        if "_local_addresses" not in kwargs:
            if self.autodetect_local_addresses:
                kwargs["_local_addresses"] = determine_local_addresses()
            else:
                kwargs["_local_addresses"] = []
        return func(self, *args, **kwargs)

    return wrapper  # type: ignore[return-value]


class AddrValidator:
    """Validator for network addresses to prevent SSRF attacks.

    This class provides configurable rules for determining whether a network
    address is safe to connect to. By default, it blocks connections to:

    - Private IP ranges (192.168.x.x, 10.x.x.x, etc.)
    - Loopback addresses (127.0.0.1, ::1)
    - Link-local addresses (169.254.x.x)
    - IPv6 addresses (unless explicitly enabled)
    - Non-standard ports

    Example:
        >>> validator = AddrValidator()
        >>> validator.is_ip_allowed("8.8.8.8")
        True
        >>> validator.is_ip_allowed("127.0.0.1")
        False
        >>> validator.is_ip_allowed("192.168.1.1")
        False
    """

    # 6to4 relay anycast address range
    _6TO4_RELAY_NET = ipaddress.ip_network("192.88.99.0/24")
    # DNS64 well-known prefix
    _DNS64_WK_PREFIX = ipaddress.ip_network("64:ff9b::/96")
    # Default allowed ports (common HTTP/HTTPS ports)
    DEFAULT_PORT_WHITELIST: frozenset[int] = frozenset({80, 8080, 443, 8443, 8000})

    def __init__(
        self,
        ip_blacklist: Iterable[IPv4Network | IPv6Network] | None = None,
        ip_whitelist: Iterable[IPv4Network | IPv6Network] | None = None,
        port_whitelist: Iterable[int] | None = None,
        port_blacklist: Iterable[int] | None = None,
        hostname_blacklist: Iterable[str | Pattern[str]] | None = None,
        allow_ipv6: bool = False,
        allow_teredo: bool = False,
        allow_6to4: bool = False,
        allow_dns64: bool = False,
        autodetect_local_addresses: bool = True,
    ) -> None:
        """Initialize the address validator.

        Args:
            ip_blacklist: IP networks to explicitly block.
            ip_whitelist: IP networks to explicitly allow (overrides blacklist).
            port_whitelist: Ports to allow. If neither port_whitelist nor
                port_blacklist is provided, defaults to common HTTP ports.
            port_blacklist: Ports to explicitly block.
            hostname_blacklist: Hostnames or patterns to block. Can be glob
                patterns (strings) or compiled regex patterns.
            allow_ipv6: Whether to allow IPv6 addresses. Disabled by default
                because IPv6 bypasses NAT-based protections.
            allow_teredo: Whether to allow Teredo tunneling addresses.
            allow_6to4: Whether to allow 6to4 tunneling addresses.
            allow_dns64: Whether to allow DNS64 translated addresses.
            autodetect_local_addresses: Whether to detect and block local
                interface addresses. Requires netifaces to be installed.
        """
        if not port_blacklist and not port_whitelist:
            port_whitelist = self.DEFAULT_PORT_WHITELIST

        self.ip_blacklist: set[IPv4Network | IPv6Network] = set(ip_blacklist or [])
        self.ip_whitelist: set[IPv4Network | IPv6Network] = set(ip_whitelist or [])
        self.port_blacklist: set[int] = set(port_blacklist or [])
        self.port_whitelist: set[int] = set(port_whitelist or [])
        self.hostname_blacklist: set[str | Pattern[str]] = set(hostname_blacklist or [])
        self.allow_ipv6 = allow_ipv6
        self.allow_teredo = allow_teredo
        self.allow_6to4 = allow_6to4
        self.allow_dns64 = allow_dns64
        self.autodetect_local_addresses = autodetect_local_addresses

    @add_local_address_arg
    def is_ip_allowed(
        self,
        addr_ip: str | IPv4Address | IPv6Address,
        _local_addresses: list[IPv4Network | IPv6Network] | None = None,
    ) -> bool:
        """Check if an IP address is allowed.

        Args:
            addr_ip: The IP address to check (string or ipaddress object).
            _local_addresses: Internal parameter for local address list.

        Returns:
            True if the address is allowed, False otherwise.
        """
        if _local_addresses is None:
            _local_addresses = []

        if not isinstance(addr_ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            addr_ip = ipaddress.ip_address(addr_ip)

        # Whitelist takes precedence over blacklist to allow punching holes
        if any(addr_ip in net for net in self.ip_whitelist):
            return True

        if any(addr_ip in net for net in self.ip_blacklist):
            return False

        if any(addr_ip in net for net in _local_addresses):
            return False

        if addr_ip.version == 4:
            # Check for carrier-grade NAT addresses
            if not addr_ip.is_private and not ipaddress.ip_network(addr_ip).is_global:
                return False
        elif addr_ip.version == 6:
            # IPv6 bypasses NAT protections - disabled by default
            if not self.allow_ipv6:
                return False

            # Check for IPv4 addresses embedded in IPv6
            v4_nested: list[IPv4Address] = []

            if addr_ip.ipv4_mapped:
                v4_nested.append(addr_ip.ipv4_mapped)

            if addr_ip.sixtofour:
                if not self.allow_6to4:
                    return False
                v4_nested.append(addr_ip.sixtofour)

            if addr_ip.teredo:
                if not self.allow_teredo:
                    return False
                # Check both client and server IPs
                v4_nested.extend(addr_ip.teredo)

            if addr_ip in self._DNS64_WK_PREFIX:
                if not self.allow_dns64:
                    return False
                # Last 4 bytes are the IPv4 address
                v4_nested.append(ipaddress.IPv4Address(addr_ip.packed[-4:]))

            # Recursively validate nested IPv4 addresses
            if not all(self.is_ip_allowed(addr_v4) for addr_v4 in v4_nested):
                return False

            # Site-local addresses (fec0::/10, deprecated)
            if addr_ip.is_site_local:
                return False
        else:
            raise ValueError(f"Unsupported IP version: {addr_ip!r}")

        # Common checks for both IPv4 and IPv6
        if addr_ip.is_link_local:
            return False
        if addr_ip.is_loopback:
            return False
        if addr_ip.is_multicast:
            return False
        if addr_ip.is_private:
            return False
        if addr_ip.is_reserved:
            return False
        if addr_ip in self._6TO4_RELAY_NET:
            return False

        return not addr_ip.is_unspecified

    def _hostname_matches_pattern(self, hostname: str, pattern: str | Pattern[str]) -> bool:
        """Check if a hostname matches a blacklist pattern.

        Args:
            hostname: The hostname to check.
            pattern: A glob pattern (string) or compiled regex.

        Returns:
            True if the hostname matches the pattern.
        """
        # Convert glob patterns to regex on the fly
        if isinstance(pattern, str):
            pattern = fnmatch.translate(canonicalize_hostname(pattern))

        hostname = canonicalize_hostname(hostname)
        # Handle null bytes that could be used for bypasses
        no_null_hostname = hostname.split("\x00")[0]

        return any(re.match(pattern, x.strip(".")) for x in (no_null_hostname, hostname))

    def is_hostname_allowed(self, hostname: str) -> bool:
        """Check if a hostname is allowed.

        Args:
            hostname: The hostname to check.

        Returns:
            True if the hostname is allowed, False if it matches a blacklist pattern.
        """
        for pattern in self.hostname_blacklist:
            if self._hostname_matches_pattern(hostname, pattern):
                return False
        return True

    @add_local_address_arg
    def is_addrinfo_allowed(
        self,
        addrinfo: tuple[int, int, int, str, tuple[Any, ...]],
        _local_addresses: list[IPv4Network | IPv6Network] | None = None,
    ) -> bool:
        """Check if socket address info is allowed.

        This validates the full address info tuple returned by socket.getaddrinfo(),
        including port and hostname checks.

        Args:
            addrinfo: A 5-tuple from socket.getaddrinfo().
            _local_addresses: Internal parameter for local address list.

        Returns:
            True if the address info is allowed.

        Raises:
            NameserverException: If hostname blacklisting is enabled but
                canonname is not available in the addrinfo.
            ValueError: If addrinfo has unexpected format.
        """
        if _local_addresses is None:
            _local_addresses = []

        assert len(addrinfo) == 5
        family, socktype, proto, canonname, sockaddr = addrinfo

        # Extract IP and port from sockaddr
        if len(sockaddr) == 2:
            # IPv4: (ip, port)
            ip, port = sockaddr
        elif len(sockaddr) == 4:
            # IPv6: (ip, port, flow_info, scope_id)
            ip, port, flow_info, scope_id = sockaddr
        else:
            raise ValueError(f"Unexpected addrinfo format: {sockaddr!r}")

        # Validate port
        if self.port_whitelist and port not in self.port_whitelist:
            return False
        if port in self.port_blacklist:
            return False

        # Validate hostname if blacklist is configured
        if self.hostname_blacklist:
            if not canonname:
                raise NameserverException(
                    "addrinfo must contain the canon name to do blacklisting "
                    "based on hostname. Make sure you use the "
                    "`socket.AI_CANONNAME` flag, and that each record contains "
                    "the canon name. Your DNS server might also be garbage."
                )

            if not self.is_hostname_allowed(canonname):
                return False

        return self.is_ip_allowed(ip, _local_addresses=_local_addresses)
