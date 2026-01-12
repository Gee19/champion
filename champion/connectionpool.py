"""
Validating connection pools for urllib3 2.x.

This module provides connection pool classes that use validating connections
to prevent SSRF attacks.
"""

from __future__ import annotations

from urllib3 import HTTPConnectionPool, HTTPSConnectionPool

from .connection import ValidatingHTTPConnection, ValidatingHTTPSConnection

# Verify the urllib3 API hasn't changed
assert hasattr(HTTPConnectionPool, "ConnectionCls"), "urllib3 API changed: ConnectionCls missing"
assert hasattr(HTTPSConnectionPool, "ConnectionCls"), "urllib3 API changed: ConnectionCls missing"
assert hasattr(HTTPConnectionPool, "scheme"), "urllib3 API changed: scheme missing"
assert hasattr(HTTPSConnectionPool, "scheme"), "urllib3 API changed: scheme missing"


class ValidatingHTTPConnectionPool(HTTPConnectionPool):
    """HTTP connection pool using validating connections.

    This pool creates ValidatingHTTPConnection instances that check
    addresses against SSRF rules before connecting.
    """

    scheme = "http"
    ConnectionCls = ValidatingHTTPConnection


class ValidatingHTTPSConnectionPool(HTTPSConnectionPool):
    """HTTPS connection pool using validating connections.

    This pool creates ValidatingHTTPSConnection instances that check
    addresses against SSRF rules before connecting.
    """

    scheme = "https"
    ConnectionCls = ValidatingHTTPSConnection
