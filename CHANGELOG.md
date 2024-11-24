# Changelog

All notable changes to this project will be documented in this file.

## [3.0.1] - 2024-11-24

### Breaking changes

- Support for BlastRadius and fixed handling of Message-Authenticators in Access\* packets
- Modernized some parts of the public API
- Dropped explicit .NET Framework support and bumped NETStandard to 2.1
- Support for nullable reference types and updated type and method definitions to reflect this
- Set IsAotCompatible to true

## [1.4.2] - 2018-07-24

### Fixed

- Remove side effect where message-authenticator would be set to zeroes in the original packet after parsing. Now message-authenticator is correctly dumped

## [1.4.1] - 2018-06-11

### Added

- Support for Change of Authorization packets ([henriqueof](https://github.com/henriqueof))

## [1.4.0] - 2018-05-18

### Added

- IRadiusDictionary interface for custom radiusdictionary implementations

### Possible Breaking Changes

- Attribute and vendor attribute dictionaries now internal. Use new get wrapper methods instead.
- Removed RadiusDictionary constructor for creating dictionary from custom attribute lists. Implement IRadiusDictionary instead
