"""
Asynchronous requests support with SSRF protection.

This module provides a FuturesSession that allows making asynchronous
HTTP requests while maintaining SSRF protections.

Requires the requests-futures package to be installed.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Any

from requests.adapters import DEFAULT_POOLSIZE

from .api import Session

if TYPE_CHECKING:
    pass

try:
    import requests_futures.sessions as rf_sessions

    HAVE_REQUESTS_FUTURES = True
except ImportError:
    rf_sessions = None  # type: ignore[assignment]
    HAVE_REQUESTS_FUTURES = False


if HAVE_REQUESTS_FUTURES:

    class FuturesSession(rf_sessions.FuturesSession, Session):  # type: ignore[misc]
        """Asynchronous session with SSRF protection.

        This combines requests-futures' asynchronous capabilities with
        Champion's SSRF protection.

        Example:
            >>> from champion.futures import FuturesSession
            >>> with FuturesSession() as session:
            ...     future = session.get("https://httpbin.org/get")
            ...     response = future.result()
            ...     print(response.status_code)
            200
        """

        def __init__(
            self,
            executor: ThreadPoolExecutor | None = None,
            max_workers: int = 2,
            session: Session | None = None,
            *args: Any,
            **kwargs: Any,
        ) -> None:
            """Initialize an asynchronous SSRF-protected session.

            Args:
                executor: ThreadPoolExecutor to use. If not provided, one
                    will be created with max_workers threads.
                max_workers: Number of worker threads if executor is not provided.
                session: Session to wrap. Must be a Champion Session or None.
                *args: Arguments passed to Session.
                **kwargs: Keyword arguments passed to Session.
            """
            adapter_kwargs: dict[str, Any] = {}

            if executor is None:
                executor = ThreadPoolExecutor(max_workers=max_workers)
                # Set connection pool size equal to max_workers if needed
                if max_workers > DEFAULT_POOLSIZE:
                    adapter_kwargs = {
                        "pool_connections": max_workers,
                        "pool_maxsize": max_workers,
                    }

            kwargs["_adapter_kwargs"] = adapter_kwargs
            Session.__init__(self, *args, **kwargs)
            self.executor = executor
            self.session = session

        @property
        def session(self) -> None:
            """Return None - session wrapping is not supported."""
            return None

        @session.setter
        def session(self, value: Any) -> None:
            """Prevent setting the session property to bypass protections.

            Args:
                value: The value to set (must be None or a Champion Session).

            Raises:
                NotImplementedError: If value is not None or a Champion Session.
            """
            if value is not None and not isinstance(value, Session):
                raise NotImplementedError(
                    "Setting the .session property to non-Champion values is "
                    "disabled to prevent whitelist bypasses"
                )

else:
    # Provide a stub if requests-futures is not installed
    class FuturesSession:  # type: ignore[no-redef]
        """Stub class when requests-futures is not installed."""

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            raise ImportError(
                "FuturesSession requires the requests-futures package. "
                "Install it with: pip install champion[futures]"
            )


__all__ = ("FuturesSession",)
