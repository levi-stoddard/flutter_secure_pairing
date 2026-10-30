# Changelog

## 0.1.0 — 2026-10-30

First release.

- `SecureKeyMaterial`: on-device NIST P-256 keypair, private key persisted only in platform secure storage and never exposed. Public key as PEM, SHA-256 fingerprint, and a PKCS#10 CSR.
- `PairingTarget`: QR payload parser and encoder for an example `securepair://pair?d=…&h=…&f=…` format that carries no credential.
- `PairingService`: pairing flow that sends only the public key, persists the issued credential on success, and fails closed to the least-privileged role.
- `PairingTransport` interface with `FakePairingTransport` (in memory) and `HttpPairingTransport` (reference HTTPS implementation of an example protocol).
- `PairingCredential` with a log-safe JSON view that never includes the token, and `SecureCredentialStore` / `InMemoryCredentialStore`.
- Example app and CI (analyze + test).
