"""
Validating HTTP connections for urllib3 2.x.

This module provides HTTP and HTTPS connection classes that validate
addresses before connecting to prevent SSRF attacks.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Sequence
from socket import timeout as SocketTimeout
from typing import TYPE_CHECKING, Any

from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.exceptions import ConnectTimeoutError
from urllib3.util.connection import _set_socket_options
from urllib3.util.connection import create_connection as urllib3_create_connection

from . import addrvalidator
from .exceptions import UnacceptableAddressException

if TYPE_CHECKING:
    from .addrvalidator import AddrValidator

# Sentinel for using the global default timeout
_DEFAULT_TIMEOUT = object()


def champion_getaddrinfo(
    host: str, port: int, get_canonname: bool = False
) -> tuple[tuple[int, int, int, str, tuple[Any, ...]], ...]:
    """Get address info with optional canonical name resolution.

    This is a wrapper around socket.getaddrinfo that properly handles
    canonical names for hostname validation.

    Args:
        host: The hostname to resolve.
        port: The port number.
        get_canonname: Whether to request the canonical name from DNS.

    Returns:
        A tuple of address info records with parsed IP addresses.
    """
    addrinfo = socket.getaddrinfo(
        host,
        port,
        0,
        socket.SOCK_STREAM,
        0,
        socket.AI_CANONNAME if get_canonname else 0,
    )
    return fix_addrinfo(addrinfo)  # type: ignore[arg-type]


def fix_addrinfo(
    records: Sequence[tuple[Any, ...]],
) -> tuple[tuple[int, int, int, str, tuple[Any, ...]], ...]:
    """Propagate the canonical name across records and parse IPs.

    The canonical name is typically only included in the first record
    from getaddrinfo, so we propagate it to all records. We also parse
    the IP addresses into ipaddress objects for validation.

    Args:
        records: Raw address info records from socket.getaddrinfo.

    Returns:
        Fixed records with canonical names and parsed IPs.
    """

    def fix_record(
        record: tuple[int, int, int, str, tuple[Any, ...]],
        canonname: str,
    ) -> tuple[int, int, int, str, tuple[Any, ...]]:
        sa = record[4]
        # Parse the IP address for validation
        sa = (ipaddress.ip_address(sa[0]),) + sa[1:]
        return record[0], record[1], record[2], canonname, sa

    canonname = ""
    if records:
        assert len(records[0]) == 5
        canonname = records[0][3]
    return tuple(fix_record(x, canonname) for x in records)


def validating_create_connection(
    address: tuple[str, int],
    timeout: float | object | None = _DEFAULT_TIMEOUT,
    source_address: tuple[str, int] | None = None,
    socket_options: list[tuple[int, int, int | bytes]] | None = None,
    *,
    validator: AddrValidator,
) -> socket.socket:
    """Create a socket connection with address validation.

    This function validates the target address against SSRF rules before
    establishing the connection. Only addresses that pass validation will
    be connected to.

    Args:
        address: A (host, port) tuple to connect to.
        timeout: Connection timeout in seconds.
        source_address: Optional source address to bind to.
        socket_options: Optional socket options to set.
        validator: The AddrValidator to use for validation.

    Returns:
        A connected socket.

    Raises:
        UnacceptableAddressException: If the address is not allowed.
        socket.error: If connection fails.
    """
    host, port = address

    # Check if we need canonical name for hostname blacklisting
    need_canonname = False
    if validator.hostname_blacklist:
        need_canonname = True
        # Check the hostname before DNS resolution
        if not validator.is_hostname_allowed(host):
            raise UnacceptableAddressException(host)

    err: Exception | None = None
    addrinfo = champion_getaddrinfo(host, port, get_canonname=need_canonname)

    if addrinfo:
        # Get local addresses for validation if configured
        if validator.autodetect_local_addresses:
            local_addresses = addrvalidator.determine_local_addresses()
        else:
            local_addresses = []

        for res in addrinfo:
            # Check if we're allowed to connect to this address
            if not validator.is_addrinfo_allowed(
                res,
                _local_addresses=local_addresses,
            ):
                continue

            af, socktype, proto, canonname, sa = res
            # Convert the validated IP back to string for socket.connect
            sa = (sa[0].exploded,) + sa[1:]
            sock = None

            try:
                sock = socket.socket(af, socktype, proto)

                # Set socket options before connecting
                _set_socket_options(sock, socket_options)

                if timeout is not _DEFAULT_TIMEOUT:
                    sock.settimeout(timeout)  # type: ignore[arg-type]
                if source_address:
                    sock.bind(source_address)

                sock.connect(sa)
                return sock

            except OSError as e:
                err = e
                if sock is not None:
                    sock.close()
                    sock = None

        if err is None:
            # None of the addresses were acceptable
            err = UnacceptableAddressException(address)

    if err is not None:
        raise err
    else:
        raise OSError("getaddrinfo returns an empty list")


def _validating_new_conn(self: ValidatingHTTPConnection | ValidatingHTTPSConnection) -> socket.socket:
    """Establish a validated socket connection.

    This method replaces the default _new_conn to add SSRF validation.

    Returns:
        A connected and validated socket.

    Raises:
        ConnectTimeoutError: If the connection times out.
        UnacceptableAddressException: If the address is blocked.
    """
    extra_kw: dict[str, Any] = {}

    if self.source_address:
        extra_kw["source_address"] = self.source_address

    if self.socket_options:
        extra_kw["socket_options"] = self.socket_options

    try:
        # Check if we're running under a testing framework that patches sockets
        # (like httpretty). In that case, fall back to the standard connection.
        if socket.getaddrinfo.__module__.startswith("httpretty"):
            conn = urllib3_create_connection(
                (self._dns_host, self.port),
                self.timeout,
                **extra_kw,
            )
        else:
            extra_kw["validator"] = self._validator
            conn = validating_create_connection(
                (self._dns_host, self.port),
                self.timeout,
                **extra_kw,
            )

    except SocketTimeout as e:
        raise ConnectTimeoutError(
            self,
            f"Connection to {self.host} timed out. (connect timeout={self.timeout})",
        ) from e

    return conn


# Verify the urllib3 API hasn't changed in a way that would break us
assert hasattr(HTTPConnection, "_new_conn"), "urllib3 API changed: HTTPConnection._new_conn missing"
assert hasattr(HTTPSConnection, "_new_conn"), "urllib3 API changed: HTTPSConnection._new_conn missing"


class ValidatingHTTPConnection(HTTPConnection):
    """HTTP connection with SSRF validation.

    This connection class validates target addresses before connecting
    to prevent Server-Side Request Forgery attacks.
    """

    def __init__(self, *args: Any, validator: AddrValidator, **kwargs: Any) -> None:
        """Initialize a validating HTTP connection.

        Args:
            *args: Arguments passed to HTTPConnection.
            validator: The AddrValidator to use for address validation.
            **kwargs: Keyword arguments passed to HTTPConnection.
        """
        self._validator = validator
        super().__init__(*args, **kwargs)

    def _new_conn(self) -> socket.socket:
        """Create a new validated connection."""
        return _validating_new_conn(self)


class ValidatingHTTPSConnection(HTTPSConnection):
    """HTTPS connection with SSRF validation.

    This connection class validates target addresses before connecting
    to prevent Server-Side Request Forgery attacks over TLS.
    """

    def __init__(self, *args: Any, validator: AddrValidator, **kwargs: Any) -> None:
        """Initialize a validating HTTPS connection.

        Args:
            *args: Arguments passed to HTTPSConnection.
            validator: The AddrValidator to use for address validation.
            **kwargs: Keyword arguments passed to HTTPSConnection.
        """
        self._validator = validator
        super().__init__(*args, **kwargs)

    def _new_conn(self) -> socket.socket:
        """Create a new validated connection."""
        return _validating_new_conn(self)
