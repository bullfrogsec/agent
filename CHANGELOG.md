# Changelog

## [Unreleased]

## [0.11.1] - 2026-08-24

### Fixed

- `docker cp` and `docker exec` are no longer refused for every container while `--enable-sudo=false`.

## [0.11.0] - 2026-08-23

### Changed

- A connection denied in `--egress-policy=block` is now refused with a TCP reset instead of dropped in silence, so clients fail immediately rather than retransmitting until their own timeout (~20ms rather than 8s). Audit mode never resets anything.

### Fixed

- IPv6 addresses from AAAA records are now added to the allow-list, so a domain in `--allowed-domains` is reachable over IPv6.
- A container's IPv6 egress is now filtered. The DOCKER-USER rules are IPv4 only, so container IPv6 traffic previously reached any address unjudged and unlogged.
- `--enable-sudo=false` now filters the Docker daemon's API to prevent privilege escalation via the `docker` group.

## [0.10.2] - 2026-03-24

### Added

- ARM64 support for Linux builds

## [0.10.0] - 2026-02-15

### Changed

- Initial release as a standalone repository
- Extracted from [bullfrogsec/bullfrog](https://github.com/bullfrogsec/bullfrog)
