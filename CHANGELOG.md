# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-01-12

### Added

- Initial release of Champion as a modernized fork of Advocate
- Full SSRF protection with the same security guarantees as Advocate
- Drop-in replacement API for the `requests` library
- `AddrValidator` class for customizable validation rules
- `Session` class with SSRF protection built-in
- `RequestsAPIWrapper` for application-wide security policies
- `FuturesSession` for async requests (requires `requests-futures`)
- Comprehensive test suite with pytest
- Type hints throughout the codebase
- GitHub Actions CI/CD workflow
- Modern Python packaging with `pyproject.toml` (PEP 517/518)

### Changed (from Advocate)

- **Renamed package**: `advocate` → `champion`
- **Renamed exceptions**: `AdvocateException` → `ChampionException`
- **Python version**: Now requires Python 3.9+ (was 3.6+)
- **Dependencies updated**:
  - `requests` >= 2.30.0 (was >= 2.18.0, < 3.0)
  - `urllib3` >= 2.2.0 (was >= 1.22, < 2.0)
  - `netifaces` is now optional (install with `champion[netifaces]`)
- **Connection layer**: Completely rewritten for urllib3 2.x compatibility
- **Pool manager**: Updated `ChampionPoolKey` for urllib3 2.x API
- **Type safety**: Full type annotations added
- **Code style**: Modernized with ruff, black formatting conventions

### Fixed

- Compatibility with urllib3 2.x API changes
- Compatibility with requests 2.30+ internal changes
- Modern Python syntax (f-strings, type unions, etc.)

### Security

- Maintains all SSRF protections from Advocate:
  - Blocks private IP ranges (10.x, 172.16-31.x, 192.168.x)
  - Blocks localhost (127.0.0.1, ::1)
  - Blocks link-local addresses (169.254.x.x)
  - Blocks cloud metadata endpoints
  - DNS rebinding protection
  - Redirect validation
  - IPv6 tunneling detection (Teredo, 6to4, DNS64)

## [Unreleased]

### Planned

- Python 3.13 official support (when released)
- AsyncIO native support (without requests-futures)
- Additional cloud provider metadata endpoint patterns

---

## Migration from Advocate

Champion is designed to be a drop-in replacement for Advocate. The main changes:

```python
# Before (Advocate)
import advocate
from advocate.exceptions import AdvocateException

try:
    response = advocate.get("https://example.com")
except AdvocateException as e:
    print(f"Blocked: {e}")

# After (Champion)
import champion
from champion.exceptions import ChampionException

try:
    response = champion.get("https://example.com")
except ChampionException as e:
    print(f"Blocked: {e}")
```

All validator options remain the same. See the README for full documentation.
