# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Portable AI Memory (PAM) is a **specification** (not a codebase) defining a universal JSON interchange format for AI
user memories across providers. Think vCard for AI memories, iCalendar for events, or OpenAPI for APIs — but for the
knowledge AI assistants accumulate about their users.

PAM enables users to export their memories from one AI assistant (ChatGPT, Claude, Gemini, Copilot, Grok) and import
them into
another without vendor lock-in. It is an **interchange format, NOT a storage format** — implementations use databases
internally (SQLite, PostgreSQL, LanceDB, etc.) and export/import via PAM.

**Status:** v1.0 specification complete. Ready for publication and reference implementation.

## Repository Structure

```text
portable-ai-memory/
├── spec.md                                      # Full PAM v1.0 spec (26 sections + 6 appendices, RFC-style)
├── schemas/
│   ├── portable-ai-memory.schema.json           # Main schema — memory store (Draft 2020-12)
│   ├── portable-ai-memory-embeddings.schema.json    # Embeddings companion schema (optional file)
│   └── portable-ai-memory-conversation.schema.json  # Normalized conversation schema
├── importer-mappings.md                          # Field-by-field mappings: provider exports → PAM
├── scripts/
│   └── validate_pam.py                          # Validator script (22 checks: schemas, hashes, integrity, cross-refs)
└── examples/
    ├── example-memory-store.json                 # Valid example with 5 memories, computed hashes, DID, signature
    ├── example-conversation.json                 # Conversation aligned with conv-001 from memory store
    └── example-embeddings.json                   # Embeddings for the 5 memories (fictional 8D vectors)
```

## Spec Architecture (26 Sections)

The spec is organized as an RFC-style document with these major components:

### Core Memory Model (§1–§11)

- **Root structure**: schema, schema_version, spec_uri, export_id, owner, memories[], relations[],
  conversations_index[], integrity, signature
- **Memory object**: id, type, content, content_hash, temporal, provenance, confidence, access, metadata, tags, summary,
  embedding_ref
- **Type taxonomy** (closed): `fact`, `preference`, `skill`, `context`, `relationship`, `goal`, `instruction`,
  `identity`, `environment`, `project`, `custom`
- **Lifecycle states**: `active` → `superseded` | `deprecated` | `retracted` | `archived`
- **Provenance tracking**: platform, extraction_method (
  llm_inference|explicit_user_input|api_export|browser_extraction|manual)

### Content Integrity (§6, §15)

- **Content hash**: trim → lowercase → Unicode NFC → collapse spaces → SHA-256 → `sha256:<hex>`
- **Integrity checksum**: sort memories by id → canonicalize with **RFC 8785 (JCS)** → SHA-256
- **CRITICAL**: `json.dumps()` is NOT RFC 8785 compliant (float serialization: `1.0` vs `1`). Must use `rfc8785`
  library.
- **Canonicalization field**: `integrity.canonicalization` defaults to `"RFC8785"`

### Extensions (§16–§19)

- **Incremental exports** (§16): `export_type: "full"|"incremental"`, delta fields `base_export_id` and `since`.
  Retracted memories MUST NOT be physically deleted during merge.
- **Decentralized Identity** (§17): `owner.did` supports did:key, did:web, did:ion, did:pkh
- **Cryptographic Signatures** (§18): Ed25519 recommended. Payload is `{checksum, export_id, export_date, owner_id}`
  canonicalized with RFC 8785 — NOT just the checksum.
- **Type Registry** (§19): Community-managed registry at configurable URI

### Conversation Format (§25)

- Companion schema for full dialogue data referenced by `conversations_index`
- Supports DAG (parent_id/children_ids) for OpenAI branching conversations
- Role normalization: human→user, Request→user, AI→assistant, ASSISTANT→assistant (see importer-mappings.md §6)
- Content: simple text or multipart (text, image, code, file, audio, video)
- Import metadata with importer versioning

### Interoperability (§20)

- Observed export sources, NOT officially supported by providers
- Best-effort compatibility guidance; formats may change without notice
- Importers MUST be versioned

## Key Design Decisions and Constraints

### Normative Conventions

- Spec uses RFC 2119 terminology: MUST, MUST NOT, SHOULD, SHOULD NOT, MAY
- Schema files and spec.md MUST stay in sync — any change to one likely requires the other
- All examples MUST validate against their schemas with 0 errors

### Platform Identifier Namespace

- Pattern: `^[a-z0-9_-]{2,32}$`
- Uses **product names** not company names: `chatgpt`, `claude`, `gemini`, `copilot`, `grok` (not openai, anthropic,
  google, microsoft, xai)
- Same namespace across ALL schemas: `provenance.platform`, `conversations_index[].platform`, `provider.name`

### Content Hash Pipeline

```python
import hashlib, unicodedata


def compute_content_hash(content: str) -> str:
    text = content.strip().lower()
    text = unicodedata.normalize("NFC", text)
    text = " ".join(text.split())
    return f"sha256:{hashlib.sha256(text.encode('utf-8')).hexdigest()}"
```

### Integrity Checksum (RFC 8785 REQUIRED)

```python
import rfc8785, hashlib


def compute_integrity_checksum(memories: list) -> str:
    sorted_memories = sorted(memories, key=lambda m: m["id"])
    canonical_bytes = rfc8785.dumps(sorted_memories)
    return f"sha256:{hashlib.sha256(canonical_bytes).hexdigest()}"
```

**WARNING**: `json.dumps(..., sort_keys=True, separators=(",", ":"))` produces DIFFERENT output than RFC 8785 for
floats (`1.0` vs `1`). Never use it for checksums.

### Signature Payload (§18.3)

```python
import rfc8785


def build_signature_payload(export: dict) -> bytes:
    payload = {
        "checksum": export["integrity"]["checksum"],
        "export_id": export["export_id"],
        "export_date": export["export_date"],
        "owner_id": export["owner"]["id"]
    }
    return rfc8785.dumps(payload)
```

The signature covers identity and export metadata — not just memories. This prevents replay attacks and export spoofing.

### spec_uri

- Implementations MUST NOT require `spec_uri` to resolve over network
- It is a version identifier, not a fetchable resource

### Embeddings

- Always optional, stored in separate file
- `embedding_ref` MUST be null when embeddings file not included
- Consumers MUST NOT fail if embeddings are missing; MAY regenerate from content

### Incremental Exports

- Importers MUST NOT physically delete memories marked as `"retracted"` — preserve and update status
- Ensures auditability and undo capability

## Provider Import Mappings (importer-mappings.md)

Field-by-field mappings from real observed exports. Key facts:

| Provider    | Source                           | Format                           | Key Gotcha                                                                                         |
|-------------|----------------------------------|----------------------------------|----------------------------------------------------------------------------------------------------|
| **ChatGPT** | `conversations.json`             | DAG in `mapping`                 | Messages linked by parent/children UUIDs, not a flat array. Timestamps are Unix epoch floats.      |
| **Claude**  | `conversations.json`             | Flat array `chat_messages`       | Field is `chat_messages` NOT `messages`. Sender values: `human`/`assistant`.                       |
| **Gemini**  | Google Takeout `MyActivity.json` | Single JSON array (activity log) | NOT individual conversations. Two variants: `details` and `userInteractions`.                      |
| **Copilot** | Privacy Dashboard                | CSV                              | Two CSV column layouts. No message IDs. JSON format no longer available.                           |
| **Grok**    | Data export via grok.com         | BSON wrapper with nested objects | Timestamps are BSON `$date` format. Sender values inconsistent (4 variants including model names). |

### Detection Heuristics

```python
def detect_provider(data):
    if isinstance(data, list):
        sample = data[0] if data else {}
        if "mapping" in sample: return "chatgpt"
        if "chat_messages" in sample: return "claude"
        if "header" in sample and ("details" in sample or "userInteractions" in sample): return "gemini"
    if isinstance(data, dict):
        if "conversations" in data and isinstance(data["conversations"], list):
            sample = data["conversations"][0] if data["conversations"] else {}
            if "conversation" in sample and "responses" in sample:
                return "grok"
        # Copilot exports are CSV, not JSON — detect by file extension/header
    return "unknown"
```

## Validation

Schemas are JSON Schema Draft 2020-12. Validate with any compliant validator:

```bash
# Python
pip install jsonschema rfc8785
python -c "
from jsonschema import Draft202012Validator
import json
schema = json.load(open('schemas/portable-ai-memory.schema.json'))
example = json.load(open('examples/example-memory-store.json'))
Draft202012Validator.check_schema(schema)
errors = list(Draft202012Validator(schema).iter_errors(example))
print(f'{len(errors)} validation errors')
"

# Node.js with ajv
ajv validate -s schemas/portable-ai-memory.schema.json -d examples/example-memory-store.json --spec=draft2020
```

### Full Validation Checklist

When modifying any file, verify ALL of these:

1. All 3 schemas valid Draft 2020-12
2. All 3 examples validate with 0 errors
3. All 5 content hashes in example-memory-store.json are correct
4. Integrity checksum computed with RFC 8785 matches
5. example-conversation.json is consistent with conversations_index conv-001 (title, platform, dates, tags)
6. Platform identifiers use product names across all schemas
7. Appendix implementations match normative sections (especially signatures §18.3 ↔ Appendix D)

## Licensing

- **Specification** (`spec.md`): CC BY 4.0
- **Schemas + reference implementations**: Apache 2.0

## Reference Implementation

The **GINES** project (separate repository) is the planned reference implementation providing:

- Platform extractors (ChatGPT, Claude, Gemini, Copilot, Grok)
- CLI tools: `pam validate`, `pam export`, `pam import`, `pam sign`, `pam verify`
- Internal storage: SQLite (metadata) + LanceDB (vectors)
- Export/import via PAM JSON format

## Namespace Reservations (Checked Feb 2026)

All available and should be reserved:

- **Domains**: portable-ai-memory.org / .com / .io
- **GitHub**: org `portable-ai-memory` and `portableaimemory`
- **PyPI**: `portable-ai-memory`, `pam-validator`, `pam-spec`
- **npm**: `portable-ai-memory`, `@portable-ai-memory/*`
- **Crates.io**: `portable-ai-memory`

Priority: GitHub org first (free), then `.org` domain (hardcoded in schema `$id` and `spec_uri`).

## Academic and Regulatory Context

- **EU Digital Markets Act (DMA)**: May 2026 review likely to mandate AI memory portability if assistants are designated
  gatekeepers. PAM provides early standardization.
- **University of Stavanger PKG research**: Personal Knowledge Graphs — Krisztian Balog (Google DeepMind), Martin G.
  Skjæveland (RDF)
- **W3C DID Core**: Decentralized identity standard used in §17
- **Samsung Personal Data Engine**: Production PKG deployment on Galaxy S25 using RDFox

## When Editing the Spec

1. **Always keep schemas and spec in sync.** A normative change in spec.md requires the corresponding schema update and
   vice versa.
2. **Revalidate after every change.** Run the full validation checklist above.
3. **Appendix implementations must match normative sections.** The Appendix D signature bug (signing only checksum
   instead of full payload) was caught by cross-referencing §18.3.
4. **Examples must be cross-consistent.** The example-conversation.json must match conversations_index conv-001 in
   title, platform, dates, and tags.
5. **Use RFC 2119 language consistently.** MUST for requirements, SHOULD for recommendations, MAY for optional.
6. **Provider mappings are observational.** Mark them as best-effort compatibility guidance, never as officially
   supported.
7. **RFC 8785 is non-negotiable for checksums.** Never use json.dumps for integrity computation.
