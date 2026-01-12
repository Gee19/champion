"""
Validating pool manager for urllib3 2.x.

This module provides a PoolManager that uses validating connection pools
to prevent SSRF attacks.
"""

from __future__ import annotations

import functools
from typing import TYPE_CHECKING, Any, NamedTuple

from urllib3 import PoolManager
from urllib3.poolmanager import _default_key_normalizer

from .connectionpool import ValidatingHTTPConnectionPool, ValidatingHTTPSConnectionPool

if TYPE_CHECKING:
    from .addrvalidator import AddrValidator


# Pool classes indexed by scheme
pool_classes_by_scheme: dict[str, type] = {
    "http": ValidatingHTTPConnectionPool,
    "https": ValidatingHTTPSConnectionPool,
}


class ChampionPoolKey(NamedTuple):
    """Extended pool key that includes the validator.

    This allows different validators to use different connection pools,
    preventing cross-contamination of security policies.
    """

    # Include all fields from the base PoolKey
    key_scheme: str
    key_host: str
    key_port: int | None
    key_timeout: Any
    key_retries: Any
    key_block: bool
    key_source_address: tuple[str, int] | None
    key_key_file: str | None
    key_key_password: str | None
    key_cert_file: str | None
    key_cert_reqs: str | int | None
    key_ca_certs: str | None
    key_ssl_version: int | str | None
    key_ssl_minimum_version: int | None
    key_ssl_maximum_version: int | None
    key_ca_cert_dir: str | None
    key_ssl_context: Any
    key_maxsize: int
    key_headers: frozenset[tuple[str, str]] | None
    key__proxy: Any
    key__proxy_headers: frozenset[tuple[str, str]] | None
    key__proxy_config: Any
    key_socket_options: tuple[tuple[int, int, int | bytes], ...] | None
    key__socks_options: frozenset[tuple[str, Any]] | None
    key_assert_hostname: str | bool | None
    key_assert_fingerprint: str | None
    key_server_hostname: str | None
    key_blocksize: int
    key_ca_cert_data: str | bytes | None
    # Additional field for validator identity
    key_validator: int


def key_normalizer(
    key_class: type[ChampionPoolKey], request_context: dict[str, Any]
) -> ChampionPoolKey:
    """Normalize request context into a pool key.

    This function creates a unique key for each combination of connection
    parameters and validator, ensuring that different security policies
    don't share connection pools.

    Args:
        key_class: The PoolKey class to instantiate.
        request_context: The request context dictionary.

    Returns:
        A ChampionPoolKey instance.
    """
    request_context = request_context.copy()
    # Use validator's id to distinguish different validators
    # TODO: Add ability to serialize validator rules to dict, allowing
    # pools to be shared between sessions with the same rules.
    request_context["validator"] = id(request_context.get("validator"))
    return _default_key_normalizer(key_class, request_context)  # type: ignore[arg-type, return-value]


key_fn_by_scheme: dict[str, functools.partial[Any]] = {
    "http": functools.partial(key_normalizer, ChampionPoolKey),
    "https": functools.partial(key_normalizer, ChampionPoolKey),
}


class ValidatingPoolManager(PoolManager):
    """Pool manager that validates addresses before connecting.

    This manager uses ValidatingHTTPConnectionPool and ValidatingHTTPSConnectionPool
    to ensure all connections are validated against SSRF rules.
    """

    def __init__(
        self,
        *args: Any,
        validator: AddrValidator | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize the validating pool manager.

        Args:
            *args: Arguments passed to PoolManager.
            validator: The AddrValidator to use for all connections.
            **kwargs: Keyword arguments passed to PoolManager.
        """
        # Store validator in connection pool kwargs
        if validator is not None:
            kwargs.setdefault("validator", validator)

        super().__init__(*args, **kwargs)

        # Verify the API hasn't changed
        assert hasattr(self, "pool_classes_by_scheme"), "urllib3 API changed"

        # Override pool classes with our validating versions
        self.pool_classes_by_scheme = pool_classes_by_scheme
        self.key_fn_by_scheme = key_fn_by_scheme.copy()  # type: ignore[assignment]
