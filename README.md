# Fake Data Prevention with Conventional Cryptographic Protocols

This project demonstrates how fake or modified data can be detected before it
is accepted by a verifier.

The example scenario is simple: a producer sends sensor data, and a verifier
accepts it only if the data is authentic, unchanged, fresh, and linked to a
trusted certificate.

## Implemented Concepts

### Integrity

The verifier checks that the data was not changed after it was signed. If the
payload is modified, the signature verification fails and the data is rejected.

### Authentication

The producer must prove that it is a trusted producer. This is done with a
public/private key pair and a certificate signed by a trusted authority.

### Digital Signatures

The project uses ECDSA signatures with SHA-256 through the browser Web Crypto
API.

Two signatures are checked:

- the trusted authority signs the producer certificate
- the producer signs the data token

### Certificate-Based Trust

The producer certificate binds the producer identity to its public key. The
verifier trusts the producer only if the certificate was signed by the trusted
authority.

The certificate contains:

- issuer
- subject
- producer public key
- validity period
- authority signature

### Replay Protection

Each signed token contains a unique `messageId`. When a token is accepted, its
`messageId` is stored by the verifier.

If the same token is verified again, it is rejected as a replay attack.

### Certificate Expiration

The verifier checks the validity period of the certificate. If the certificate
is expired, the data is rejected even if the cryptographic signature is valid.

### Audit Log

Security-relevant actions are recorded in an audit log:

- key issuing
- data signing
- payload tampering
- fake producer test
- certificate expiration
- verification result

### Data Minimization

The signed payload contains only the data needed for the demonstration:

- message ID
- device ID
- location
- reading
- unit
- timestamp

No personal user data is included.

## How It Works

```text
Trusted Authority
  creates a root key pair
  signs the producer certificate
        |
        v
Producer
  creates a payload
  signs the payload as a JWT-like token
        |
        v
Verifier
  checks the certificate signature
  checks the certificate validity period
  checks the payload signature
  checks that the messageId was not already used
  accepts or rejects the data
```

## Demo Steps

1. Click `Issue Keys`.
2. Click `Sign Data`.
3. Click `Verify`.

The first verification should be accepted.

To test attacks:

1. Click `Verify` again to test replay detection.
2. Click `Sign Data`, then `Tamper Payload`, then `Verify`.
3. Click `Sign Data`, then `Use Untrusted Producer`, then `Verify`.
4. Click `Sign Data`, then `Expire Certificate`, then `Verify`.

Each attack should be rejected.

## Run

Start a local static server:

```bash
python3 -m http.server 8000
```

Then open:

```text
http://localhost:8000
```

The project should be served from `localhost` because it uses the browser Web
Crypto API.

## Files

- `index.html`: page structure
- `styles.css`: visual styling
- `app.js`: cryptographic workflow and verification logic
- `README.md`: project description

## Scope

This project is intentionally a small browser-only prototype. The goal is to
show the security logic clearly, not to build a production platform.

Implemented in this prototype:

- certificate-based trust
- digital signature verification
- tamper detection
- fake producer detection
- replay attack detection
- certificate expiration checking
- audit logging inside the page
