# Fake Data Prevention with Conventional Cryptographic Protocols

This is a self-contained demo for a System Security exam project. It shows how
fake or modified data can be detected with conventional cryptographic tools:

- A trusted authority creates a root signing key.
- A data producer receives a signed certificate from that authority.
- The producer signs a JSON Web Token (JWT) containing sensor data.
- A verifier checks the producer certificate and the signed data.
- Tampered payloads and untrusted producers are rejected.

## Run

Start a local static server:

```bash
python3 -m http.server 8000
```

Then open:

```text
http://localhost:8000
```

The app uses the browser Web Crypto API, so it should be served from
`localhost` instead of opened directly from the filesystem.

## What To Demonstrate

1. Click `Issue Keys` to create a trusted authority and producer certificate.
2. Click `Sign Data` to produce a signed JWT.
3. Click `Verify` to validate the certificate and payload signature.
4. Click `Tamper Payload` and verify again to see modification detection.
5. Click `Use Untrusted Producer` and verify again to see trust failure.

## Security Model

The demo uses ECDSA P-256 signatures with SHA-256. The authority signs a compact
producer certificate that binds the producer identity to its public key. The
producer signs the data token. A verifier trusts only certificates signed by the
known authority key and accepts only payloads whose signature matches the
certified producer public key.

This prevents fake data in two common cases:

- An attacker modifies legitimate data in transit.
- An attacker creates new data without a trusted certificate.

