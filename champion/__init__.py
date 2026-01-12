"""
Champion - SSRF protection for Python requests.

Champion is a drop-in replacement for the requests library that prevents
Server-Side Request Forgery (SSRF) attacks by validating all connection
targets before establishing connections.

Example:
    >>> import champion
    >>>
    >>> # Safe requests to public addresses work normally
    >>> response = champion.get("https://httpbin.org/get")
    >>> response.status_code
    200
    >>>
    >>> # Attempts to access internal addresses are blocked
    >>> champion.get("http://localhost/")  # Raises UnacceptableAddressException
    >>> champion.get("http://192.168.1.1/")  # Raises UnacceptableAddressException
    >>> champion.get("http://169.254.169.254/")  # Blocks AWS metadata endpoint

For more control, use AddrValidator to customize the protection rules:

    >>> from champion import AddrValidator, Session
    >>> import ipaddress
    >>>
    >>> # Allow connections to a specific internal host
    >>> validator = AddrValidator(
    ...     ip_whitelist={ipaddress.ip_network("10.0.0.5/32")}
    ... )
    >>> with Session(validator=validator) as session:
    ...     response = session.get("http://10.0.0.5/api")
"""

from __future__ import annotations

__version__ = "1.0.0"

# Re-export useful items from requests for convenience
from requests import utils
from requests.exceptions import (
    ConnectionError,
    HTTPError,
    RequestException,
    Timeout,
    TooManyRedirects,
    URLRequired,
)
from requests.models import PreparedRequest, Request, Response
from requests.status_codes import codes

# Export our adapters
from .adapters import ValidatingHTTPAdapter

# Export the validator
from .addrvalidator import AddrValidator

# Export the high-level API
from .api import (
    RequestsAPIWrapper,
    Session,
    delete,
    get,
    head,
    options,
    patch,
    post,
    put,
    request,
    session,
)

# Export exceptions
from .exceptions import (
    ChampionException,
    ConfigException,
    MountDisabledException,
    NameserverException,
    ProxyDisabledException,
    UnacceptableAddressException,
)

__all__ = [
    # Version
    "__version__",
    # API functions
    "delete",
    "get",
    "head",
    "options",
    "patch",
    "post",
    "put",
    "request",
    "session",
    # Classes
    "Session",
    "AddrValidator",
    "RequestsAPIWrapper",
    "ValidatingHTTPAdapter",
    # Exceptions
    "ChampionException",
    "ConfigException",
    "MountDisabledException",
    "NameserverException",
    "ProxyDisabledException",
    "UnacceptableAddressException",
    # Re-exports from requests
    "codes",
    "ConnectionError",
    "HTTPError",
    "PreparedRequest",
    "Request",
    "RequestException",
    "Response",
    "Timeout",
    "TooManyRedirects",
    "URLRequired",
    "utils",
]
