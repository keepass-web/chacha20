# @keepass-web/chacha20

ChaCha20 and Salsa20 stream cipher implementation for the [keepass-web](https://github.com/keepass-web) project.

This package implements the raw stream ciphers only:
- ChaCha20 (RFC 8439 IETF variant: 256-bit key, 96-bit nonce, 32-bit counter), used by KDBX 4.
- Salsa20 (Bernstein: 256-bit key, 64-bit nonce, 64-bit counter), used by the KDBX 3.1 inner random stream.

Poly1305 and the ChaCha20-Poly1305 AEAD construction from RFC 8439 are not implemented, because they are not needed for KDBX.

## Specification

See [SPEC.md](./SPEC.md).

## Usage

Published to npm under the `@keepass-web` scope with provenance signing.

## Development

```sh
npm ci
npm run typecheck
npm run lint
npm test
```
