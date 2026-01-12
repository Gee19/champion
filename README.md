# Champion

[![PyPI version](https://badge.fury.io/py/champion.svg)](https://badge.fury.io/py/champion)
[![Python versions](https://img.shields.io/pypi/pyversions/champion.svg)](https://pypi.org/project/champion/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![CI](https://github.com/champion-ssrf/champion/actions/workflows/ci.yml/badge.svg)](https://github.com/champion-ssrf/champion/actions/workflows/ci.yml)

**Champion** is a Python library that wraps the popular [requests](https://requests.readthedocs.io/) library to prevent Server-Side Request Forgery (SSRF) attacks.

Champion is a modernized fork of [Advocate](https://github.com/JordanMilne/Advocate), updated to support modern Python versions and the latest versions of requests and urllib3.

## Features

- **Drop-in replacement** for the `requests` library
- **Blocks private IP ranges** (10.x.x.x, 192.168.x.x, 172.16-31.x.x)
- **Blocks localhost** (127.0.0.1, ::1)
- **Blocks cloud metadata endpoints** (169.254.169.254)
- **Blocks IPv6** by default (configurable)
- **DNS rebinding protection** - validates addresses at connection time
- **Redirect validation** - every hop is validated
- **Customizable** - whitelist specific IPs, configure allowed ports, etc.

## Installation

```bash
pip install champion
```

With optional dependencies:

```bash
# For local network interface detection
pip install champion[netifaces]

# For async support via requests-futures
pip install champion[futures]

# For development
pip install champion[dev]
```

## Requirements

- Python 3.9+
- requests >= 2.30.0
- urllib3 >= 2.2.0

## Quick Start

Champion is designed to be a drop-in replacement for requests:

```python
import champion

# This works - public IP
response = champion.get("https://httpbin.org/get")
print(response.json())

# These are blocked - private/internal IPs
champion.get("http://localhost/")  # UnacceptableAddressException
champion.get("http://192.168.1.1/")  # UnacceptableAddressException
champion.get("http://169.254.169.254/")  # AWS metadata blocked
```

## Usage

### Basic Usage

```python
import champion

# All standard requests methods are available
response = champion.get("https://api.example.com/data")
response = champion.post("https://api.example.com/data", json={"key": "value"})
response = champion.put("https://api.example.com/data/1", data="content")
response = champion.delete("https://api.example.com/data/1")
```

### Using Sessions

```python
import champion

with champion.Session() as session:
    response = session.get("https://api.example.com/data")
    # Session maintains cookies, auth, etc.
```

### Custom Validation Rules

```python
import ipaddress
from champion import AddrValidator, Session

# Allow connections to a specific internal host
validator = AddrValidator(
    ip_whitelist={ipaddress.ip_network("10.0.0.5/32")},
)

with Session(validator=validator) as session:
    # This specific IP is now allowed
    response = session.get("http://10.0.0.5/api/internal")
```

### Block Specific Hosts

```python
from champion import AddrValidator, Session

validator = AddrValidator(
    hostname_blacklist={"*.internal.company.com", "secret.example.com"},
)

with Session(validator=validator) as session:
    session.get("https://public.example.com")  # OK
    session.get("https://secret.example.com")  # Blocked
    session.get("https://foo.internal.company.com")  # Blocked
```

### Custom Port Restrictions

```python
from champion import AddrValidator, Session

# Only allow standard HTTPS
validator = AddrValidator(
    port_whitelist={443},
)

with Session(validator=validator) as session:
    session.get("https://example.com/")  # OK (port 443)
    session.get("http://example.com/")   # Blocked (port 80)
```

### Application-Wide Protection

```python
from champion import AddrValidator, RequestsAPIWrapper

# Create a wrapper with your security policy
validator = AddrValidator(
    allow_ipv6=False,
    port_whitelist={80, 443, 8080},
)
safe_requests = RequestsAPIWrapper(validator)

# Use it like the requests module
response = safe_requests.get("https://api.example.com/")
```

### Async Requests (with requests-futures)

```python
from champion.futures import FuturesSession

with FuturesSession() as session:
    future = session.get("https://httpbin.org/get")
    # Do other work...
    response = future.result()
    print(response.json())
```

## Configuration Options

The `AddrValidator` class accepts the following parameters:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `ip_blacklist` | Set[IPNetwork] | `set()` | IP networks to explicitly block |
| `ip_whitelist` | Set[IPNetwork] | `set()` | IP networks to allow (overrides blacklist) |
| `port_whitelist` | Set[int] | `{80, 443, 8080, 8443, 8000}` | Allowed ports |
| `port_blacklist` | Set[int] | `set()` | Explicitly blocked ports |
| `hostname_blacklist` | Set[str\|Pattern] | `set()` | Blocked hostnames (glob or regex) |
| `allow_ipv6` | bool | `False` | Allow IPv6 addresses |
| `allow_teredo` | bool | `False` | Allow Teredo tunneling |
| `allow_6to4` | bool | `False` | Allow 6to4 tunneling |
| `allow_dns64` | bool | `False` | Allow DNS64 addresses |
| `autodetect_local_addresses` | bool | `True` | Detect and block local interfaces |

## What Champion Blocks

By default, Champion blocks:

- **Loopback addresses**: 127.0.0.0/8, ::1
- **Private networks**: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
- **Link-local addresses**: 169.254.0.0/16, fe80::/10
- **Cloud metadata endpoints**: 169.254.169.254 (AWS, GCP, Azure)
- **Multicast addresses**: 224.0.0.0/4, ff00::/8
- **IPv6 addresses** (by default)
- **Non-standard ports** (configurable)

## Security Considerations

### Why Not Just Validate the URL?

Many SSRF protections only validate the URL before making the request. This approach has several vulnerabilities:

1. **DNS rebinding**: An attacker controls DNS and can return different IPs for validation vs. connection
2. **Parser inconsistencies**: The validator and HTTP library may parse URLs differently
3. **Redirects**: The initial URL may be safe, but redirect to an internal address

Champion addresses these by:

1. **Validating at connection time**: We check the actual IP address being connected to
2. **Using the HTTP library's resolution**: We hook into urllib3's connection layer
3. **Validating every redirect**: Each hop is validated, not just the initial URL

### Proxies Are Disabled

Champion intentionally blocks the use of HTTP proxies because they bypass SSRF protections. The proxy server would make the actual connection, not your application.

### IPv6 Concerns

IPv6 is disabled by default because:

1. IPv6 can embed IPv4 addresses in various formats
2. Many IPv6 features (Teredo, 6to4) can tunnel to internal IPv4 addresses
3. NAT-based protections don't apply to IPv6

If you need IPv6 support, enable it explicitly and be aware of the additional attack surface.

## Migrating from Advocate

Champion is a modernized fork of Advocate with the following changes:

1. **Renamed**: `advocate` → `champion`
2. **Exception renamed**: `AdvocateException` → `ChampionException`
3. **Modern Python**: Requires Python 3.9+
4. **Modern dependencies**: requests >= 2.30.0, urllib3 >= 2.2.0
5. **Type hints**: Full type annotation coverage
6. **Modern packaging**: Uses pyproject.toml (PEP 517/518)

### Migration Example

```python
# Before (Advocate)
import advocate
response = advocate.get("https://example.com")

# After (Champion)
import champion
response = champion.get("https://example.com")
```

## Development

```bash
# Clone the repository
git clone https://github.com/champion-ssrf/champion.git
cd champion

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=champion --cov-report=term-missing

# Skip network tests
pytest -m "not network"

# Type checking
mypy champion

# Linting
ruff check champion
```

## License

Champion is released under the Apache 2.0 License. See [LICENSE](LICENSE) for details.

## Credits

Champion is based on [Advocate](https://github.com/JordanMilne/Advocate) by Jordan Milne. Original Advocate copyright (c) 2015 Jordan Milne.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## See Also

- [requests](https://requests.readthedocs.io/) - The HTTP library Champion wraps
- [urllib3](https://urllib3.readthedocs.io/) - The HTTP client library used internally
- [OWASP SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) - SSRF prevention guidance
