# Changelog
All notable changes to this project will be documented in this file.

## [1.4.1] - 2018-06-11
### Added
- Support for Change of Authorization packets ([henriqueof](https://github.com/henriqueof))

## [1.4.0] - 2018-05-18
### Added
- IRadiusDictionary interface for custom radiusdictionary implementations

### Possible Breaking Changes
- Attribute and vendor attribute dictionaries now internal. Use new get wrapper methods instead.
- Removed RadiusDictionary constructor for creating dictionary from custom attribute lists. Implement IRadiusDictionary instead
