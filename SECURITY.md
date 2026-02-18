# Security Policy

## Scope

PAM is a **specification and schema project**, not a runtime application. Security concerns primarily relate to:

- Cryptographic signature validation (spec section 18)
- Content integrity checksums (spec section 6, 15)
- Decentralized identity integration (spec section 17)
- Schema validation bypass

## Reporting a Vulnerability

If you discover a security issue in the specification or schemas, please report it privately:

- **Email**: dangines@gmail.com
- **Subject**: `[PAM Security] <brief description>`

Please include:

1. Which section of the spec or schema is affected
2. Description of the vulnerability
3. Potential impact on implementations
4. Suggested fix if you have one

You will receive an acknowledgment within 48 hours. We will work with you to understand the issue and coordinate
disclosure.

## Disclosure Policy

- We follow coordinated disclosure — please do not publicly disclose issues before a fix is available
- Credit will be given to reporters in the CHANGELOG unless anonymity is requested

## Known Security Considerations

The spec documents these security considerations:

- **RFC 8785 canonicalization** is required for integrity checksums. Using `json.dumps()` produces different output and
  breaks verification.
- **Signature payload** includes export metadata (export_id, export_date, owner_id), not just the checksum, to prevent
  replay attacks.
- **`spec_uri` must not be fetched** over the network by implementations to avoid SSRF.
- **Embeddings are optional** and should not be required for import, as they may leak information about content.
