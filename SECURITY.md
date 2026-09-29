# Security Policy

## Security status

`webcrypto-ratchet` is a cryptographic protocol implementation intended for
experimentation, research, and applications that specifically require a
pure-JavaScript/WebCrypto implementation of a PQXDH-style handshake and
post-quantum Triple Ratchet.

**This project has not undergone an independent cryptographic security audit.**

It should not be considered equivalent in assurance to an independently audited
and established messaging implementation such as Signal's `libsignal`.

The project intentionally documents its security assumptions, design choices,
and known limitations in the [README security notes](./README.md#security-notes).

## Reporting a vulnerability

Please do **not** open a public GitHub issue for a suspected security
vulnerability.

Instead, report security issues privately through GitHub's
**Security Advisories → Report a vulnerability** feature:

https://github.com/sabrigo/webcrypto-ratchet/security/advisories/new

Please include, where possible:

- A description of the vulnerability
- The affected version(s)
- Steps to reproduce the issue
- A minimal proof of concept
- The expected behaviour
- The observed behaviour
- Any potential security impact
- A suggested mitigation, if known

For cryptographic issues, please include enough technical detail to make the
issue independently reproducible.

## What should be reported privately?

Examples include:

- Authentication or key-agreement failures
- Key compromise or unintended key disclosure
- Incorrect cryptographic state transitions
- Ratchet state desynchronisation with security consequences
- Replay or message-reordering vulnerabilities beyond documented limitations
- Authentication bypasses
- Failures that expose plaintext or key material
- Weaknesses that allow an attacker to recover message keys
- Randomness or nonce-generation failures
- Vulnerabilities in the ML-KEM integration
- Vulnerabilities in the WebCrypto primitives or their use
- Dependency vulnerabilities with a meaningful security impact

If you are unsure whether an issue qualifies as a security vulnerability,
please report it privately rather than opening a public issue.

## Supported versions

Security fixes are applied to the latest published version.

| Version | Security support |
|---|---|
| Latest release | Supported |
| Older releases | Best effort |
| Unreleased development versions | Not guaranteed |

Users should generally upgrade to the latest release before reporting an issue
that may already have been fixed.

## Security architecture

The library provides cryptographic session establishment and message
encryption/decryption. It does **not** provide a complete messaging system.

In particular, applications using this library are responsible for:

- Transport
- Public-key distribution
- Identity verification
- Identity persistence
- Private-key storage
- Session persistence
- Authentication of application-level identities
- One-time prekey management
- Replay/session management
- Access control
- Application-level abuse protection

The library should therefore be treated as one component of a larger secure
messaging system rather than a complete messaging product.

## Cryptographic implementation

The implementation uses:

- X25519 for elliptic-curve Diffie-Hellman operations
- Ed25519 for signatures
- ML-KEM-768 for post-quantum key encapsulation
- HKDF-SHA256 for key derivation
- HMAC-SHA256 for symmetric ratchet advancement
- AES-256-GCM for authenticated encryption
- WebCrypto for browser/runtime cryptographic primitives

ML-KEM functionality is provided by
[`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum).

The implementation is deliberately designed to use standard WebCrypto
primitives wherever possible so that the same protocol can run in browsers,
Node.js, Deno, and Cloudflare Workers.

## Known limitations

The README contains the authoritative technical security notes and should be
read before using this library for security-sensitive applications.

Known limitations include:

- No independent cryptographic audit
- No Signal wire compatibility
- No Matrix wire compatibility
- No group messaging protocol
- Application-controlled identity verification
- Application-controlled key persistence
- Extractable key material in the default key-generation helpers
- JavaScript memory does not provide reliable secret zeroisation
- Handshake replay considerations when one-time prekeys are not used
- Significant per-message overhead from ML-KEM material
- The protocol's KDF encoding is not byte-for-byte compatible with Signal's
  implementation

These limitations are intentional or documented design constraints unless
otherwise stated.

## Browser security

When used in a browser, the security of the application also depends on the
browser environment.

Applications should:

- Serve the application over HTTPS
- Protect against cross-site scripting (XSS)
- Avoid injecting untrusted HTML into messaging interfaces
- Use an appropriate Content Security Policy
- Protect long-term keys from application-level compromise
- Avoid exposing `CryptoKey` or session state to untrusted code
- Keep dependencies pinned and regularly reviewed

Cryptography cannot protect plaintext after an attacker has compromised the
JavaScript environment that is executing the cryptographic code.

## Dependency security

The project intentionally keeps its cryptographic dependency footprint small.

Dependencies should be regularly updated and reviewed for security advisories.

A dependency update should not automatically be assumed to preserve the
security properties of the protocol; changes to cryptographic dependencies
should be tested against the project's existing test suite.

## Disclosure process

Security reports will be reviewed on a best-effort basis.

When a vulnerability is confirmed, the project may:

1. Investigate and reproduce the issue.
2. Determine affected versions and security impact.
3. Develop and test a fix.
4. Publish a patched release where appropriate.
5. Publish a GitHub Security Advisory when appropriate.
6. Credit the reporter when they wish to be credited.

The project may coordinate disclosure timing with the reporter when a fix
requires users to upgrade.

## Responsible use

This software is provided for legitimate security, privacy, research, and
software-development purposes.

Users are responsible for evaluating whether the protocol and implementation
are appropriate for their particular threat model.

**Do not rely on this implementation for high-stakes security applications
without obtaining an appropriate independent security review.**