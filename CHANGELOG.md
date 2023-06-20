# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2023-06-20
### Added
- Add `unregister_device` to unregister a device, allowing to register it again. 

### Changed
- Request backoff time for info and certificate request is exponential instead of fixed.

## [1.0.3] - 2022-07-04

## [1.0.2] - 2022-03-29

## [1.0.1] - 2021-12-16

## [1.0.0] - 2021-06-29

## [1.0.0-rc.0] - 2021-05-05
### Changed
- Standardize subscriptions (see
  [astarte-platform/astarte#568](https://github.com/astarte-platform/astarte/issues/568)). This
  reduces the network bandwidth usage.

## [1.0.0-beta.2] - 2021-03-23
### Added
- Add validation when publishing on object aggregate interfaces.

### Fixed
- Correctly use a BSON binary instead of a string when publishing binaryblob values.

## [1.0.0-beta.1] - 2020-02-15
### Added
- Make the HTTP client follow redirects when interacting with Pairing API
- Add `unset_property` function to unset a path on a property interface.

### Changed
- Increase the max certificate chain length to 10.
- Breaking API change: `pairing_url` now MUST NOT include the `/v1` suffix.

### Fixed
- Use a custom check for the hostname so that wildcard SSL certificates are supported.

## [0.11.4] - 2021-01-27
### Fixed
- Lock gpb to 4.12.0 to fix exprotobuf compilation issue

## [0.11.3] - 2020-09-24

## [0.11.2] - 2020-08-31

## [0.11.1] - 2020-05-18

## [0.11.0] - 2020-04-13

## [0.11.0-rc.1] - 2020-03-26

## [0.11.0-rc.0] - 2020-02-27
### Added
- Initial release.
