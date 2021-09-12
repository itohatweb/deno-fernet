# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2021-09-12

### Changed

- AES.decrypt to return a Uint8Array instead of a string (so fernet.decode now returns an Uint8Array).
- encodeFernet now requires the data to be a Uint8Array instead of a string.
- ferne.encode now accepts an Uint8Array.

## [0.1.1] - 2021-09-03

### Fixed

- hex2urlsave padEnd calculation adding 4 "=" when it is a multiple of 4.

## [0.1.1] - 2021-09-03

### Fixed

- Fix base64url invalid character decode error.
- Do not decode too short tokens.

## [0.1.0] - 2021-09-03

- First release.

[0.1.2]: https://github.com/itohatweb/deno-fernet/compare/0.1.1...0.1.2
[0.1.1]: https://github.com/itohatweb/deno-fernet/compare/0.1.0...0.1.1
[0.1.0]: https://github.com/itohatweb/deno-fernet/compare/516a0e07c77ae36f3e7a06b6f4bef8d4de77674c...0.1.0
