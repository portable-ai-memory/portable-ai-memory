# Portable AI Memory (PAM)

**A universal interchange format for AI user memories.**

PAM is to AI memory what vCard is to contacts and iCalendar is to events — a standardized, vendor-neutral format that
lets users own, migrate, and control the knowledge AI assistants accumulate about them.

[![Spec Version](https://img.shields.io/badge/spec-v1.0-blue)](spec.md)
[![License: CC BY 4.0](https://img.shields.io/badge/spec_license-CC_BY_4.0-lightgrey)](LICENSE-SPEC)
[![License: Apache 2.0](https://img.shields.io/badge/code_license-Apache_2.0-green)](LICENSE-CODE)

---

## The Problem

AI assistants — ChatGPT, Claude, Gemini, Grok, Copilot — accumulate knowledge about you over time: your preferences,
expertise, projects, goals, and behavioral patterns. This knowledge is stored in proprietary, undocumented formats with
zero interoperability. You cannot migrate your AI context when switching providers, maintain a unified identity across
multiple assistants, or audit and correct what these systems believe about you.

## The Solution

PAM defines a standardized JSON format covering:

- **11 memory types** — facts, preferences, skills, goals, relationships, instructions, context, identity, environment,
  projects, and custom
- **Full provenance** — which platform, conversation, and method produced each memory
- **Temporal lifecycle** — creation, validity periods, supersession chains, archival
- **Confidence scoring** — with configurable decay models
- **Content hashing** — deterministic SHA-256 deduplication
- **Semantic relations** — typed graph between memories
- **Conversation history** — normalized format across all providers
- **Cryptographic signatures** — Ed25519/ECDSA for tamper detection
- **Decentralized identity** — W3C DID support for cross-platform identity
- **Access control** — fine-grained permissions for multi-agent scenarios

## Quick Example

```json
{
  "schema": "portable-ai-memory",
  "schema_version": "1.0",
  "export_id": "exp-001",
  "export_date": "2026-02-15T22:00:00Z",
  "export_type": "full",
  "owner": {
    "id": "user-daniel",
    "did": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
  },
  "memories": [
    {
      "id": "mem-001",
      "type": "skill",
      "content": "User is proficient in Python, Go, and SQL with 15+ years of experience in backend systems and infrastructure.",
      "content_hash": "sha256:7754ba0ba59361bd164c64da9885d18e8c0b2db0ccc4abf5ff27f7189a1c1152",
      "temporal": {
        "created_at": "2026-01-10T14:30:00Z"
      },
      "confidence": {
        "initial": 0.95
      },
      "provenance": {
        "platform": "claude",
        "extraction_method": "explicit_user_input"
      }
    }
  ]
}
```

## Repository Contents

| File                                                                                                         | Description                                     |
|--------------------------------------------------------------------------------------------------------------|-------------------------------------------------|
| [`spec.md`](spec.md)                                                                                         | Full specification (26 sections + 6 appendices) |
| [`importer-mappings.md`](importer-mappings.md)                                                               | Field-by-field mappings from 5 providers to PAM |
| [`schemas/portable-ai-memory.schema.json`](schemas/portable-ai-memory.schema.json)                           | Main JSON Schema (Draft 2020-12)                |
| [`schemas/portable-ai-memory-embeddings.schema.json`](schemas/portable-ai-memory-embeddings.schema.json)     | Embeddings companion schema                     |
| [`schemas/portable-ai-memory-conversation.schema.json`](schemas/portable-ai-memory-conversation.schema.json) | Normalized conversation schema                  |
| [`examples/`](examples/)                                                                                     | Validated example files                         |

## Supported Providers

PAM documents verified export formats and field mappings for:

| Provider                | Export Method                        | Coverage |
|-------------------------|--------------------------------------|----------|
| **OpenAI** (ChatGPT)    | `conversations.json` + memory prompt | Full     |
| **Anthropic** (Claude)  | JSON export + memory edits           | Full     |
| **Google** (Gemini)     | Google Takeout                       | Partial  |
| **Microsoft** (Copilot) | Privacy Dashboard CSV                | Partial  |
| **xAI** (Grok)          | Data export via grok.com             | Full     |

See [`importer-mappings.md`](importer-mappings.md) for detailed field-by-field mappings, timestamp normalization rules,
role normalization tables, and auto-detection heuristics.

## SDKs & Tools

| Package              | Language | Repository                                                                          | Status      |
|----------------------|----------|-------------------------------------------------------------------------------------|-------------|
| `portable-ai-memory` | Python   | [`portable-ai-memory/python-sdk`](https://github.com/portable-ai-memory/python-sdk) | Stable (v1.0.0) |

The Python SDK provides:

- **`pam validate`** — validate any file against PAM schemas (schema + deep checks)
- **`pam convert`** — convert provider exports to PAM format (auto-detects provider)
- **`pam inspect`** — summarize PAM file contents (types, counts, metadata)
- **Programmatic API** — `from portable_ai_memory import load, save, validate, convert`

## Schema Validation

The recommended way to validate PAM files is using the [Python SDK](https://github.com/portable-ai-memory/python-sdk):

```bash
pip install 'portable-ai-memory[cli]'
pam validate my-export.json
```

Or programmatically:

```python
from portable_ai_memory import load, validate

store = load("my-export.json")
result = validate(store)

if result.is_valid:
    print("Valid PAM file")
else:
    for issue in result.errors:
        print(f"✗ {issue}")
```

The SDK performs both schema validation and deep checks (content hashes, integrity checksums, cross-references, temporal ordering).

You can also validate directly against the JSON Schema using any Draft 2020-12 compliant validator:

```python
from jsonschema import Draft202012Validator
import json

with open("schemas/portable-ai-memory.schema.json") as f:
    schema = json.load(f)

with open("my-export.json") as f:
    data = json.load(f)

validator = Draft202012Validator(schema)
errors = list(validator.iter_errors(data))

if errors:
    for e in errors:
        print(f"{e.json_path}: {e.message}")
else:
    print("Valid PAM file")
```

## Design Principles

1. **Interchange, not storage** — PAM defines how data is exchanged between systems, not how implementations store it
   internally
2. **Zero runtime dependencies** — the spec is pure documentation and JSON schemas, no code required
3. **Provider-agnostic** — works with any AI assistant, current or future
4. **User-owned** — the user controls their data, not the provider
5. **Incrementally adoptable** — only `schema`, `schema_version`, `owner.id`, and `memories[]` are required

## License

- **Specification** (`spec.md`, `importer-mappings.md`): [CC BY 4.0](LICENSE-SPEC)
- **Schemas and code**: [Apache License 2.0](LICENSE-CODE)

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for how to propose changes to the specification.

## Security

See [`SECURITY.md`](SECURITY.md) for how to report vulnerabilities.

## Author

Daniel
Gines — [dangines@gmail.com](mailto:dangines@gmail.com) — [github.com/danielgines](https://github.com/danielgines)
