# Contributing to Portable AI Memory

Thank you for your interest in contributing to PAM. This project is a **specification**, so contributions involve
documentation, schemas, and mappings rather than application code.

## How to Contribute

### Reporting Issues

- **Schema bugs**: Use the [Schema Bug Report](.github/ISSUE_TEMPLATE/schema-bug-report.yml) template
- **Spec changes**: Use the [Spec Change Proposal](.github/ISSUE_TEMPLATE/spec-change-proposal.yml) template

### Proposing Changes

1. Open an issue first to discuss the change
2. Fork the repository and create a branch
3. Make your changes following the guidelines below
4. Submit a pull request using the [PR template](.github/PULL_REQUEST_TEMPLATE.md)

## Guidelines

### Specification Changes (`spec.md`)

- Use RFC 2119 language: MUST, MUST NOT, SHOULD, SHOULD NOT, MAY
- Keep schemas and spec in sync — a normative change in one requires updating the other
- Appendix implementations must match their normative sections
- Revalidate all examples after every change

### Schema Changes (`schemas/`)

- Schemas use JSON Schema Draft 2020-12
- All examples must validate with 0 errors after changes
- Platform identifiers use product names (`chatgpt`, `claude`, `gemini`), not company names

### Provider Mappings (`importer-mappings.md`)

- Mappings are observational — document what providers actually export
- Mark all mappings as best-effort compatibility guidance
- Include detection heuristics for auto-identification
- Version your importer implementations

### Validation Checklist

Before submitting a PR, verify:

1. All 3 schemas are valid Draft 2020-12
2. All 3 example files validate with 0 errors
3. Content hashes in examples are correct
4. Integrity checksum uses RFC 8785 (not `json.dumps`)
5. Cross-references between example files are consistent
6. Platform identifiers are consistent across all schemas

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).
