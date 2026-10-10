# Changelog

What each release changed for you, newest first. Each line is a commit's summary, linked to its full description and diff. Releases before 6.2.2 are described by their release commits.

## 6.4.1 - 2026-10-10

### Fixes

- Re-pin the spec to 2026.10.09: rotating a key needs apikeys.reveal ([`f2543a8`](https://github.com/vpndetection-io/sdk-java/commit/f2543a8675a17366040fc2985e6a7ef3a03a5d1b))

## 6.4.0 - 2026-10-04

### Features

- Add the authorization code sign-in, with PKCE ([`4f7d4f8`](https://github.com/vpndetection-io/sdk-java/commit/4f7d4f8d6933221060964696c1191decf3ac33cb))

### Fixes

- Wait out a Retry-After too long to count on the backoff ([`ac7e58c`](https://github.com/vpndetection-io/sdk-java/commit/ac7e58c6bb96346840684651be0f1865011a4560))
- Never sleep the device poll past its deadline ([`df6f999`](https://github.com/vpndetection-io/sdk-java/commit/df6f999a1b6489c5ffdb018d9a2c731dccabb6da))
- Re-pin the spec to 2026.10.03: metadata needs no license ([`7480966`](https://github.com/vpndetection-io/sdk-java/commit/7480966c0ff233cfdd48510f8e254717ccdc805f))

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
