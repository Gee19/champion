"""Integration tests for Champion."""

from __future__ import annotations

import ipaddress

import pytest
import responses

import champion
from champion import AddrValidator, Session
from champion.exceptions import UnacceptableAddressException


class TestSSRFProtection:
    """Integration tests for SSRF protection."""

    @pytest.fixture
    def validator(self) -> AddrValidator:
        """Create a validator for testing."""
        return AddrValidator(autodetect_local_addresses=False)

    def test_blocks_localhost_127(self, validator: AddrValidator) -> None:
        """Should block 127.0.0.1."""
        with pytest.raises(UnacceptableAddressException):
            champion.get("http://127.0.0.1/", validator=validator)

    def test_blocks_localhost_any_127(self, validator: AddrValidator) -> None:
        """Should block any 127.x.x.x address."""
        with pytest.raises(UnacceptableAddressException):
            champion.get("http://127.0.0.2/", validator=validator)

    def test_blocks_localhost_max(self, validator: AddrValidator) -> None:
        """Should block 127.255.255.255."""
        with pytest.raises(UnacceptableAddressException):
            champion.get("http://127.255.255.255/", validator=validator)

    def test_blocks_10_network(self, validator: AddrValidator) -> None:
        """Should block 10.0.0.0/8 network."""
        with pytest.raises(UnacceptableAddressException):
            champion.get("http://10.0.0.1/", validator=validator)

    def test_blocks_172_16_network(self, validator: AddrValidator) -> None:
        """Should block 172.16.0.0/12 network."""
        with pytest.raises(UnacceptableAddressException):
            champion.get("http://172.16.0.1/", validator=validator)
        with pytest.raises(UnacceptableAddressException):
            champion.get("http://172.31.255.255/", validator=validator)

    def test_blocks_192_168_network(self, validator: AddrValidator) -> None:
        """Should block 192.168.0.0/16 network."""
        with pytest.raises(UnacceptableAddressException):
            champion.get("http://192.168.0.1/", validator=validator)

    def test_blocks_aws_metadata(self, validator: AddrValidator) -> None:
        """Should block AWS metadata endpoint."""
        with pytest.raises(UnacceptableAddressException):
            champion.get("http://169.254.169.254/", validator=validator)

    def test_blocks_azure_metadata(self, validator: AddrValidator) -> None:
        """Should block Azure metadata endpoint."""
        with pytest.raises(UnacceptableAddressException):
            champion.get("http://169.254.169.254/metadata/", validator=validator)

    def test_blocks_gcp_metadata(self, validator: AddrValidator) -> None:
        """Should block GCP metadata endpoint."""
        with pytest.raises(UnacceptableAddressException):
            champion.get("http://169.254.169.254/computeMetadata/", validator=validator)


class TestWhitelistOverride:
    """Integration tests for whitelist functionality."""

    def test_whitelist_allows_private_ip(self) -> None:
        """Should allow whitelisted private IPs."""
        validator = AddrValidator(
            ip_whitelist={ipaddress.ip_network("10.0.0.5/32")},
            autodetect_local_addresses=False,
        )

        # This should not raise an exception for the address validation
        # (it will fail to connect, but that's expected)
        try:
            champion.get("http://10.0.0.5/", validator=validator, timeout=0.1)
        except UnacceptableAddressException:
            pytest.fail("Should not block whitelisted IP")
        except Exception:
            # Connection errors are expected since there's no server
            pass


class TestSessionContextManager:
    """Integration tests for session context manager."""

    def test_session_as_context_manager(self) -> None:
        """Should work as a context manager."""
        validator = AddrValidator(autodetect_local_addresses=False)
        with Session(validator=validator) as session:
            assert session is not None
            # Session should be usable
            with pytest.raises(UnacceptableAddressException):
                session.get("http://127.0.0.1/")


class TestHTTPMethods:
    """Integration tests for different HTTP methods."""

    @responses.activate
    def test_get_method(self) -> None:
        """Should support GET requests."""
        responses.add(
            responses.GET,
            "http://93.184.216.34/",
            json={"method": "GET"},
            status=200,
        )
        validator = AddrValidator(autodetect_local_addresses=False)
        response = champion.get("http://93.184.216.34/", validator=validator)
        assert response.status_code == 200

    @responses.activate
    def test_post_method(self) -> None:
        """Should support POST requests."""
        responses.add(
            responses.POST,
            "http://93.184.216.34/",
            json={"method": "POST"},
            status=200,
        )
        validator = AddrValidator(autodetect_local_addresses=False)
        response = champion.post("http://93.184.216.34/", validator=validator)
        assert response.status_code == 200

    @responses.activate
    def test_put_method(self) -> None:
        """Should support PUT requests."""
        responses.add(
            responses.PUT,
            "http://93.184.216.34/",
            json={"method": "PUT"},
            status=200,
        )
        validator = AddrValidator(autodetect_local_addresses=False)
        response = champion.put("http://93.184.216.34/", validator=validator)
        assert response.status_code == 200

    @responses.activate
    def test_patch_method(self) -> None:
        """Should support PATCH requests."""
        responses.add(
            responses.PATCH,
            "http://93.184.216.34/",
            json={"method": "PATCH"},
            status=200,
        )
        validator = AddrValidator(autodetect_local_addresses=False)
        response = champion.patch("http://93.184.216.34/", validator=validator)
        assert response.status_code == 200

    @responses.activate
    def test_delete_method(self) -> None:
        """Should support DELETE requests."""
        responses.add(
            responses.DELETE,
            "http://93.184.216.34/",
            json={"method": "DELETE"},
            status=200,
        )
        validator = AddrValidator(autodetect_local_addresses=False)
        response = champion.delete("http://93.184.216.34/", validator=validator)
        assert response.status_code == 200

    @responses.activate
    def test_head_method(self) -> None:
        """Should support HEAD requests."""
        responses.add(
            responses.HEAD,
            "http://93.184.216.34/",
            status=200,
        )
        validator = AddrValidator(autodetect_local_addresses=False)
        response = champion.head("http://93.184.216.34/", validator=validator)
        assert response.status_code == 200

    @responses.activate
    def test_options_method(self) -> None:
        """Should support OPTIONS requests."""
        responses.add(
            responses.OPTIONS,
            "http://93.184.216.34/",
            status=200,
        )
        validator = AddrValidator(autodetect_local_addresses=False)
        response = champion.options("http://93.184.216.34/", validator=validator)
        assert response.status_code == 200


@pytest.mark.network
class TestRealNetworkRequests:
    """Integration tests that make real network requests.

    These tests are marked with @pytest.mark.network and can be skipped
    by running: pytest -m "not network"
    """

    def test_real_public_request(self) -> None:
        """Should successfully make a request to a public API."""
        validator = AddrValidator(autodetect_local_addresses=False)
        response = champion.get(
            "https://httpbin.org/get",
            validator=validator,
            timeout=10,
        )
        assert response.status_code == 200
        data = response.json()
        assert "url" in data

    def test_real_https_request(self) -> None:
        """Should successfully make HTTPS requests."""
        validator = AddrValidator(autodetect_local_addresses=False)
        response = champion.get(
            "https://httpbin.org/get",
            validator=validator,
            timeout=10,
        )
        assert response.status_code == 200

    def test_real_post_with_data(self) -> None:
        """Should successfully POST data."""
        validator = AddrValidator(autodetect_local_addresses=False)
        response = champion.post(
            "https://httpbin.org/post",
            json={"test": "data"},
            validator=validator,
            timeout=10,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["json"] == {"test": "data"}
