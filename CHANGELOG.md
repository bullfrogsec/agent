# Changelog

## [Unreleased]

### Changed

- A connection denied in `--egress-policy=block` is now refused rather than
  dropped in silence: the agent answers the denied SYN with a TCP reset, so the
  client fails immediately with a connection-refused error instead of
  retransmitting until its own timeout (~20ms rather than 8s, measured in the
  e2e harness). Enforcement is unchanged: the denied traffic never reaches the
  destination either way, and audit mode never resets anything.

### Fixed

- IPv6 addresses from AAAA records are now added to the allow-list, so a domain
  in `--allowed-domains` is reachable over IPv6. Only A records were recorded
  before, which left an allowed domain unreachable on a dual-stack runner.

- A container's IPv6 egress is now filtered. The rules the agent writes into
  Docker's DOCKER-USER chain are in nftables' `ip` family, which cannot match
  IPv6, so container IPv6 traffic reached any address unjudged and unlogged.
  A forward chain in the agent's own `inet` table now covers it, which also
  means the coverage does not depend on Docker's own IPv6 configuration.

### Security

- The nftables rule that lets the agent's own resets through is now narrow
  enough that nothing else fits. It requires a mark drawn at random on every
  start, rather than a fixed one written in this repository, and it also
  requires the packet to look like a reset: TCP, 40 bytes, RST set with
  fin/syn/psh/urg clear. A packet carrying any payload no longer matches.
  Setting a mark needs CAP_NET_RAW or CAP_NET_ADMIN, so this is not reachable
  from an ordinary build step, but it is reachable from root and from
  `docker run --network=host`, and this is the one rule whose job is to let a
  packet past the allow-list.

- The rendered ruleset is removed from /tmp once nft has loaded it, since it
  contains the run's mark.

- The raw socket used for reset injection is opened with `SOCK_CLOEXEC`, so the
  processes the agent starts no longer inherit it. It carries the injection
  mark, which would let its holder send packets the ruleset allows through.

## [0.10.2] - 2026-03-24

### Added

- ARM64 support for Linux builds

## [0.10.0] - 2026-02-15

### Changed

- Initial release as a standalone repository
- Extracted from [bullfrogsec/bullfrog](https://github.com/bullfrogsec/bullfrog)
