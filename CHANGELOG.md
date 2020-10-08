# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## Unreleased
### Added
- Make the HTTP client follow redirects when interacting with Pairing API

### Changed
- Increase the max certificate chain length to 10.
- Breaking API change: `pairing_url` now MUST NOT include the `/v1` suffix.

### Fixed
- Use a custom check for the hostname so that wildcard SSL certificates are supported.

## [0.11.1] - 2020-05-18

## [0.11.0] - 2020-04-13

## [0.11.0-rc.1] - 2020-03-26

## [0.11.0-rc.0] - 2020-02-27
### Added
- Initial release.
