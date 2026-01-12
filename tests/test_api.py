"""Tests for the Champion API."""

from __future__ import annotations

import ipaddress
from unittest.mock import MagicMock

import pytest
import responses

import champion
from champion import AddrValidator, RequestsAPIWrapper, Session
from champion.exceptions import (
    MountDisabledException,
    ProxyDisabledException,
    UnacceptableAddressException,
)


class TestSession:
    """Tests for the Champion Session class."""

    def test_session_creation(self) -> None:
        """Should create a session successfully."""
        with Session() as session:
            assert session is not None
            assert hasattr(session, "validator")

    def test_session_with_custom_validator(self) -> None:
        """Should accept a custom validator."""
        validator = AddrValidator(
            ip_whitelist={ipaddress.ip_network("10.0.0.5/32")},
            autodetect_local_addresses=False,
        )
        with Session(validator=validator) as session:
            assert session.validator is validator

    def test_mount_disabled(self) -> None:
        """Should prevent mounting custom adapters."""
        session = Session()
        with pytest.raises(MountDisabledException):
            session.mount("http://", MagicMock())

    def test_mount_disabled_https(self) -> None:
        """Should prevent mounting custom HTTPS adapters."""
        session = Session()
        with pytest.raises(MountDisabledException):
            session.mount("https://", MagicMock())


class TestSessionRequests:
    """Tests for making requests with Champion sessions."""

    @responses.activate
    def test_get_public_url(self) -> None:
        """Should allow GET to public URLs."""
        responses.add(
            responses.GET,
            "http://93.184.216.34/",
            json={"status": "ok"},
            status=200,
        )

        # Use IP address directly to avoid DNS lookup
        validator = AddrValidator(autodetect_local_addresses=False)
        response = champion.get("http://93.184.216.34/", validator=validator)
        assert response.status_code == 200

    def test_block_localhost(self) -> None:
        """Should block requests to localhost."""
        validator = AddrValidator(autodetect_local_addresses=False)
        with pytest.raises(UnacceptableAddressException):
            champion.get("http://127.0.0.1/", validator=validator)

    def test_block_private_ip(self) -> None:
        """Should block requests to private IPs."""
        validator = AddrValidator(autodetect_local_addresses=False)
        with pytest.raises(UnacceptableAddressException):
            champion.get("http://192.168.1.1/", validator=validator)

    def test_block_link_local(self) -> None:
        """Should block requests to link-local addresses (AWS metadata)."""
        validator = AddrValidator(autodetect_local_addresses=False)
        with pytest.raises(UnacceptableAddressException):
            champion.get("http://169.254.169.254/", validator=validator)


class TestAPIFunctions:
    """Tests for the module-level API functions."""

    def test_get_function(self) -> None:
        """Should have a get function."""
        assert callable(champion.get)

    def test_post_function(self) -> None:
        """Should have a post function."""
        assert callable(champion.post)

    def test_put_function(self) -> None:
        """Should have a put function."""
        assert callable(champion.put)

    def test_patch_function(self) -> None:
        """Should have a patch function."""
        assert callable(champion.patch)

    def test_delete_function(self) -> None:
        """Should have a delete function."""
        assert callable(champion.delete)

    def test_head_function(self) -> None:
        """Should have a head function."""
        assert callable(champion.head)

    def test_options_function(self) -> None:
        """Should have an options function."""
        assert callable(champion.options)

    def test_request_function(self) -> None:
        """Should have a request function."""
        assert callable(champion.request)

    def test_session_function(self) -> None:
        """Should have a session function."""
        assert callable(champion.session)


class TestRequestsAPIWrapper:
    """Tests for the RequestsAPIWrapper class."""

    @pytest.fixture
    def wrapper(self) -> RequestsAPIWrapper:
        """Create a wrapper for testing."""
        validator = AddrValidator(autodetect_local_addresses=False)
        return RequestsAPIWrapper(validator)

    def test_wrapper_has_get(self, wrapper: RequestsAPIWrapper) -> None:
        """Should have get method."""
        assert callable(wrapper.get)

    def test_wrapper_has_post(self, wrapper: RequestsAPIWrapper) -> None:
        """Should have post method."""
        assert callable(wrapper.post)

    def test_wrapper_has_session(self, wrapper: RequestsAPIWrapper) -> None:
        """Should have Session class."""
        assert wrapper.Session is not None

    def test_wrapper_uses_validator(self, wrapper: RequestsAPIWrapper) -> None:
        """Wrapper Session should use the wrapper's validator."""
        session = wrapper.Session()
        assert session.validator is wrapper.validator

    def test_wrapper_getattr_fallback(self, wrapper: RequestsAPIWrapper) -> None:
        """Should fall back to champion module for missing attributes."""
        # Should be able to access champion.codes through the wrapper
        assert wrapper.codes is not None

    def test_wrapper_blocks_private_ips(self, wrapper: RequestsAPIWrapper) -> None:
        """Wrapper should block private IPs."""
        with pytest.raises(UnacceptableAddressException):
            wrapper.get("http://192.168.1.1/")


class TestProxyBlocking:
    """Tests for proxy blocking functionality."""

    def test_proxies_blocked_in_session(self) -> None:
        """Should raise error when using proxies."""
        validator = AddrValidator(autodetect_local_addresses=False)
        with pytest.raises(ProxyDisabledException):
            champion.get(
                "http://93.184.216.34/",
                proxies={"http": "http://proxy.example.com:8080"},
                validator=validator,
            )


class TestExceptionReexports:
    """Tests for exception re-exports."""

    def test_champion_exception(self) -> None:
        """Should export ChampionException."""
        assert champion.ChampionException is not None

    def test_unacceptable_address_exception(self) -> None:
        """Should export UnacceptableAddressException."""
        assert champion.UnacceptableAddressException is not None

    def test_mount_disabled_exception(self) -> None:
        """Should export MountDisabledException."""
        assert champion.MountDisabledException is not None

    def test_proxy_disabled_exception(self) -> None:
        """Should export ProxyDisabledException."""
        assert champion.ProxyDisabledException is not None

    def test_config_exception(self) -> None:
        """Should export ConfigException."""
        assert champion.ConfigException is not None


class TestRequestsReexports:
    """Tests for requests module re-exports."""

    def test_response(self) -> None:
        """Should export Response."""
        assert champion.Response is not None

    def test_request(self) -> None:
        """Should export Request."""
        assert champion.Request is not None

    def test_prepared_request(self) -> None:
        """Should export PreparedRequest."""
        assert champion.PreparedRequest is not None

    def test_request_exception(self) -> None:
        """Should export RequestException."""
        assert champion.RequestException is not None

    def test_timeout(self) -> None:
        """Should export Timeout."""
        assert champion.Timeout is not None

    def test_http_error(self) -> None:
        """Should export HTTPError."""
        assert champion.HTTPError is not None

    def test_connection_error(self) -> None:
        """Should export ConnectionError."""
        assert champion.ConnectionError is not None

    def test_status_codes(self) -> None:
        """Should export status codes."""
        assert champion.codes is not None
        assert champion.codes.ok == 200
