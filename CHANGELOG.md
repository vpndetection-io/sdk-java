# Changelog

What each release changed for you, newest first. Each line is a commit's summary, linked to its full description and diff. Releases before 6.2.2 are described by their release commits.

## 6.3.3 - 2026-10-01

### Fixes

- Raise jackson to 2.22.3, past two denial-of-service advisories ([`ed2bf78`](https://github.com/vpndetection-io/sdk-java/commit/ed2bf78c83367e0292241c4b74e326d7b4d25020))

## 6.3.2 - 2026-09-30

### Fixes

- Share one request per address among concurrent lookups and batches ([`9c5ac04`](https://github.com/vpndetection-io/sdk-java/commit/9c5ac04f6591cb7a7b2a97653409742fac25bcee))

## 6.3.1 - 2026-09-30

### Fixes

- Judge an IPv4-mapped address as the IPv4 address it carries ([`5d8920f`](https://github.com/vpndetection-io/sdk-java/commit/5d8920f104f19dae44e85d0ec3decf8cb0d87edb))
- Recognize 26 more reserved ranges as bogons, as the API does ([`f6de374`](https://github.com/vpndetection-io/sdk-java/commit/f6de37426c1fdc336919eb1c64a038da39bf0ba3))

## 6.3.0 - 2026-09-27

### Features

- Re-pin the spec to 2026.09.26, adding clientIdMetadataDocumentSupported ([`7b8dd55`](https://github.com/vpndetection-io/sdk-java/commit/7b8dd555dc09ecc6c75a42e05c7a58a9c995caa7))

## 6.2.2 - 2026-09-22

### Fixes

- Re-pin the spec to 2026.09.21, and regenerate ([`784e836`](https://github.com/vpndetection-io/sdk-java/commit/784e83681098671c013325d25f8cc5eeaaee0da0))
