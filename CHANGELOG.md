# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-05-23
### Added
- add info regarding current connections per client certificate

### Changed
- build project using hatchling
- dependencies updates

## [0.8.0] - 2021-11-26
### Changed
- migrate network config from old OpenWrt 19.07 syntax to new OpenWrt 21.02 syntax 

## [0.7.0] - 2021-08-05
### Added
- add hook to reload openvpn server settings

## [0.6.4] - 2021-04-01
### Changed
- speed up generating of dhparam file
- set topology "subnet" instead of "net30" (default, but for legacy clients only)
- cleanup in tests fixtures
- migrate changelog to Keep a Changelog style

## [0.6.3] - 2020-11-11
- return certificate name within get_client_config api call
- generate dhparam with turris-cagen instead of using separate dhparam
- python2 code cleanup

## [0.6.2] - 2019-10-10
- fix router ip address autodetection
- tests: refactoring

## [0.6.1] - 2019-08-12
- use ipaddress module instead of foris_controller_utils.IPv4 and remove IPv4

## [0.6] - 2019-02-11
- compress logic update
- setup.py: making dependencies paho-mqtt and ubus optional
- python2 deprecation
- ca ready fix

## [0.5.1] - 2018-11-30
- setup.py: cleanup + PEP508 updated

## [0.5] - 2018-09-20
- restarting network in a more propper way

## [0.4] - 2018-08-13
- python3 compatibility
- reflect api changes
- test updates
- restart entire network to ensure that new settings are used
- more robust ipv4 wan detection in client configs
- comp-lzo -> compress lzo option updated

## [0.3] - 2018-05-24
- listening on IPv6 address
- protocol support extended

## [0.2] - 2018-04-26
- update_settings: initial state fix

## [0.1] - 2018-04-19
- initial version
