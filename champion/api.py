"""
Champion API - Drop-in replacement for requests with SSRF protection.

This module provides a requests-compatible API that validates all
connections to prevent Server-Side Request Forgery attacks.

Example:
    >>> import champion
    >>> response = champion.get("https://httpbin.org/get")
    >>> response.status_code
    200
    >>> champion.get("http://localhost/")  # Blocked!
    Traceback (most recent call last):
        ...
    champion.exceptions.UnacceptableAddressException: ...
"""

from __future__ import annotations

import hashlib
import pickle
from collections import OrderedDict
from typing import TYPE_CHECKING, Any

from requests import Response
from requests import Session as RequestsSession

import champion

from .adapters import ValidatingHTTPAdapter
from .exceptions import MountDisabledException

if TYPE_CHECKING:
    from .addrvalidator import AddrValidator


class Session(RequestsSession):
    """SSRF-protected requests Session.

    This is a drop-in replacement for requests.Session that validates
    all connections to prevent Server-Side Request Forgery attacks.

    Example:
        >>> import champion
        >>> with champion.Session() as session:
        ...     response = session.get("https://httpbin.org/get")
        ...     print(response.status_code)
        200
    """

    __attrs__ = RequestsSession.__attrs__ + ["validator"]
    DEFAULT_VALIDATOR: AddrValidator | None = None

    def __init__(
        self,
        *args: Any,
        validator: AddrValidator | None = None,
        _adapter_kwargs: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize an SSRF-protected session.

        Args:
            *args: Arguments passed to requests.Session.
            validator: Custom AddrValidator for this session. If not provided,
                uses the class DEFAULT_VALIDATOR or creates a new one.
            _adapter_kwargs: Internal parameter for adapter configuration.
            **kwargs: Keyword arguments passed to requests.Session.
        """
        self.validator = validator or self.DEFAULT_VALIDATOR
        adapter_kwargs = _adapter_kwargs or {}

        # Session.__init__() calls mount() internally, so we need to allow
        # it temporarily
        self._mount_allowed = True
        super().__init__(*args, **kwargs)

        # Drop any existing adapters and replace with validating ones
        self.adapters: OrderedDict[str, Any] = OrderedDict()
        self.mount(
            "http://",
            ValidatingHTTPAdapter(validator=self.validator, **adapter_kwargs),
        )
        self.mount(
            "https://",
            ValidatingHTTPAdapter(validator=self.validator, **adapter_kwargs),
        )
        self._mount_allowed = False

    def mount(self, prefix: str | bytes, adapter: Any) -> None:
        """Mount an adapter - disabled to prevent protection bypass.

        After initialization, mounting custom adapters is disabled to
        prevent bypassing SSRF protections.

        Args:
            prefix: URL prefix for the adapter.
            adapter: The adapter to mount.

        Raises:
            MountDisabledException: If called after initialization.
        """
        if self._mount_allowed:
            super().mount(prefix, adapter)
        else:
            raise MountDisabledException(
                "mount() is disabled to prevent protection bypasses"
            )


def session(*args: Any, **kwargs: Any) -> Session:
    """Create a new SSRF-protected session.

    Returns:
        A new Session instance.
    """
    return Session(*args, **kwargs)


def request(method: str, url: str, **kwargs: Any) -> Response:
    """Send an SSRF-protected HTTP request.

    This is equivalent to requests.request() but with SSRF protection.

    Args:
        method: HTTP method (GET, POST, etc.).
        url: URL to request.
        **kwargs: Additional arguments passed to requests.

    Returns:
        The Response object.

    Raises:
        UnacceptableAddressException: If the URL resolves to a blocked address.
    """
    validator = kwargs.pop("validator", None)
    with Session(validator=validator) as sess:
        response = sess.request(method=method, url=url, **kwargs)
    return response


def get(url: str, **kwargs: Any) -> Response:
    """Send an SSRF-protected GET request.

    Args:
        url: URL to request.
        **kwargs: Additional arguments passed to requests.

    Returns:
        The Response object.
    """
    kwargs.setdefault("allow_redirects", True)
    return request("get", url, **kwargs)


def options(url: str, **kwargs: Any) -> Response:
    """Send an SSRF-protected OPTIONS request.

    Args:
        url: URL to request.
        **kwargs: Additional arguments passed to requests.

    Returns:
        The Response object.
    """
    kwargs.setdefault("allow_redirects", True)
    return request("options", url, **kwargs)


def head(url: str, **kwargs: Any) -> Response:
    """Send an SSRF-protected HEAD request.

    Args:
        url: URL to request.
        **kwargs: Additional arguments passed to requests.

    Returns:
        The Response object.
    """
    kwargs.setdefault("allow_redirects", False)
    return request("head", url, **kwargs)


def post(url: str, data: Any = None, json: Any = None, **kwargs: Any) -> Response:
    """Send an SSRF-protected POST request.

    Args:
        url: URL to request.
        data: Request body data.
        json: JSON data for request body.
        **kwargs: Additional arguments passed to requests.

    Returns:
        The Response object.
    """
    return request("post", url, data=data, json=json, **kwargs)


def put(url: str, data: Any = None, **kwargs: Any) -> Response:
    """Send an SSRF-protected PUT request.

    Args:
        url: URL to request.
        data: Request body data.
        **kwargs: Additional arguments passed to requests.

    Returns:
        The Response object.
    """
    return request("put", url, data=data, **kwargs)


def patch(url: str, data: Any = None, **kwargs: Any) -> Response:
    """Send an SSRF-protected PATCH request.

    Args:
        url: URL to request.
        data: Request body data.
        **kwargs: Additional arguments passed to requests.

    Returns:
        The Response object.
    """
    return request("patch", url, data=data, **kwargs)


def delete(url: str, **kwargs: Any) -> Response:
    """Send an SSRF-protected DELETE request.

    Args:
        url: URL to request.
        **kwargs: Additional arguments passed to requests.

    Returns:
        The Response object.
    """
    return request("delete", url, **kwargs)


class RequestsAPIWrapper:
    """Wrapper that provides a requests-like API with a specific validator.

    This class allows creating a module-like object with a pre-configured
    validator, useful for application-wide security policies.

    Example:
        >>> from champion import AddrValidator, RequestsAPIWrapper
        >>> import ipaddress
        >>>
        >>> # Create a wrapper that also blocks a specific IP range
        >>> validator = AddrValidator(
        ...     ip_blacklist={ipaddress.ip_network("203.0.113.0/24")}
        ... )
        >>> safe_requests = RequestsAPIWrapper(validator)
        >>>
        >>> # Use like the requests module
        >>> response = safe_requests.get("https://httpbin.org/get")
    """

    # Pickling may not work correctly unless loaded within the same
    # interpreter instance. Enable at your peril.
    SUPPORT_WRAPPER_PICKLING: bool = False

    def __init__(self, validator: AddrValidator) -> None:
        """Initialize the API wrapper.

        Args:
            validator: The AddrValidator to use for all requests.
        """
        self.validator = validator
        outer_self = self

        class _WrappedSession(Session):
            """Session that uses the wrapper's validator by default."""

            DEFAULT_VALIDATOR = outer_self.validator

        self._make_wrapper_cls_global(_WrappedSession)

        # Try to set up FuturesSession if available
        try:
            from .futures import FuturesSession

            class _WrappedFuturesSession(FuturesSession):
                """FuturesSession that uses the wrapper's validator by default."""

                DEFAULT_VALIDATOR = outer_self.validator

            self._make_wrapper_cls_global(_WrappedFuturesSession)
            self.FuturesSession = _WrappedFuturesSession
        except ImportError:
            pass

        # Wrap all the API functions
        self.request = self._default_arg_wrapper(request)
        self.get = self._default_arg_wrapper(get)
        self.options = self._default_arg_wrapper(options)
        self.head = self._default_arg_wrapper(head)
        self.post = self._default_arg_wrapper(post)
        self.put = self._default_arg_wrapper(put)
        self.patch = self._default_arg_wrapper(patch)
        self.delete = self._default_arg_wrapper(delete)
        self.session = self._default_arg_wrapper(session)
        self.Session = _WrappedSession

    def __getattr__(self, item: str) -> Any:
        """Fall back to the champion module for missing attributes.

        This allows the wrapper to act like the champion module for
        things like exception classes, Request, Response, etc.
        """
        try:
            return object.__getattribute__(self, item)
        except AttributeError:
            return getattr(champion, item)

    def _default_arg_wrapper(self, fun: Any) -> Any:
        """Wrap a function to use the configured validator by default."""

        def wrapped_func(*args: Any, **kwargs: Any) -> Any:
            kwargs.setdefault("validator", self.validator)
            return fun(*args, **kwargs)

        return wrapped_func

    def _make_wrapper_cls_global(self, cls: type) -> None:
        """Make a wrapper class global for pickle support."""
        if not self.SUPPORT_WRAPPER_PICKLING:
            return
        # Create a unique name based on the wrapper's configuration
        wrapper_hash = hashlib.sha256(pickle.dumps(self)).hexdigest()
        cls.__name__ = f"{cls.__name__}_{wrapper_hash}"
        cls.__qualname__ = f"{__name__}.{cls.__name__}"
        if not globals().get(cls.__name__):
            globals()[cls.__name__] = cls


__all__ = (
    "delete",
    "get",
    "head",
    "options",
    "patch",
    "post",
    "put",
    "request",
    "session",
    "Session",
    "RequestsAPIWrapper",
)
