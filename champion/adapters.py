"""
HTTP adapters with SSRF protection for requests.

This module provides an HTTPAdapter that validates addresses before connecting,
preventing Server-Side Request Forgery attacks.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from requests.adapters import DEFAULT_POOLBLOCK, HTTPAdapter

from .addrvalidator import AddrValidator
from .exceptions import ProxyDisabledException
from .poolmanager import ValidatingPoolManager

if TYPE_CHECKING:
    pass


class ValidatingHTTPAdapter(HTTPAdapter):
    """HTTP adapter that validates addresses before connecting.

    This adapter uses a ValidatingPoolManager to ensure all connections
    are checked against SSRF rules before being established.

    Example:
        >>> from champion import AddrValidator
        >>> from champion.adapters import ValidatingHTTPAdapter
        >>> import requests
        >>>
        >>> session = requests.Session()
        >>> adapter = ValidatingHTTPAdapter(validator=AddrValidator())
        >>> session.mount("http://", adapter)
        >>> session.mount("https://", adapter)
    """

    # Include validator in pickled state
    __attrs__ = HTTPAdapter.__attrs__ + ["_validator"]

    def __init__(self, *args: Any, validator: AddrValidator | None = None, **kwargs: Any) -> None:
        """Initialize the validating HTTP adapter.

        Args:
            *args: Arguments passed to HTTPAdapter.
            validator: The AddrValidator to use. If not provided, a default
                validator with standard SSRF protections is used.
            **kwargs: Keyword arguments passed to HTTPAdapter.
        """
        self._validator = validator or AddrValidator()
        super().__init__(*args, **kwargs)

    def init_poolmanager(
        self,
        connections: int,
        maxsize: int,
        block: bool = DEFAULT_POOLBLOCK,
        **pool_kwargs: Any,
    ) -> None:
        """Initialize the pool manager with SSRF validation.

        Args:
            connections: Number of connection pools to cache.
            maxsize: Maximum number of connections per pool.
            block: Whether to block when pool is full.
            **pool_kwargs: Additional keyword arguments for the pool manager.
        """
        self._pool_connections = connections
        self._pool_maxsize = maxsize
        self._pool_block = block
        self.poolmanager = ValidatingPoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            validator=self._validator,
            **pool_kwargs,
        )

    def proxy_manager_for(self, proxy: str, **proxy_kwargs: Any) -> None:
        """Raise an error because proxies bypass SSRF protection.

        Proxies are disabled because they would allow connections to
        arbitrary addresses through the proxy server, bypassing our
        address validation.

        Args:
            proxy: The proxy URL (ignored).
            **proxy_kwargs: Proxy keyword arguments (ignored).

        Raises:
            ProxyDisabledException: Always raised.
        """
        raise ProxyDisabledException("Proxies cannot be used with Champion")
