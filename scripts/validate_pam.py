#!/usr/bin/env python3
"""
PAM Repository Validator — Pre-commit hook & standalone CLI.

Validates the Portable AI Memory specification repository ensuring:
  1.  All JSON schemas are valid JSON Schema Draft 2020-12
  2.  All example files validate against their respective schemas
  3.  Content hashes (SHA-256) match actual content
  4.  Integrity block is consistent (total_memories, checksum)
  5.  Cross-references are valid (relations → memories, conversation_ref → conversations_index, etc.)
  6.  Temporal consistency (created_at ≤ updated_at, valid_from ≤ valid_until)
  7.  ID uniqueness (memories, relations, conversations_index, conversation messages, embeddings)
  8.  Custom type rules (custom_type required iff type == 'custom')
  9.  DAG consistency in conversation messages (parent_id/children_ids)
  10. Embeddings cross-references (embedding_ref ↔ embeddings file)
  11. Status ↔ superseded_by consistency
  12. Signature payload verification (§18.3) + Base64url validation + signed_at ≥ export_date
  13. Signature conditional dependency (export_id + export_date required when signed)
  14. Platform identifier consistency across schemas and files
  15. Conversation cross-file consistency (conversations_index ↔ conversation files)
  16. Content hash completeness (content present → content_hash should exist)
  17. Conversation message temporal ordering
  18. BCP 47 language tag validation
  19. Incremental export rules (base_export_id + since when export_type="incremental")
  20. Schema version consistency across files

Usage:
  Standalone:   python validate_pam.py [--repo-root /path/to/repo]
  Pre-commit:   ln -s ../../scripts/validate_pam.py .git/hooks/pre-commit

Exit codes:
  0 — All checks passed
  1 — Validation errors found
  2 — Configuration/setup error

Requires: jsonschema >= 4.21.0 (for Draft 2020-12 support)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

try:
    from jsonschema import Draft202012Validator, ValidationError
except ImportError:
    print("ERROR: jsonschema is required. Install with: pip install 'jsonschema>=4.21.0'", file=sys.stderr)
    sys.exit(2)

try:
    import rfc8785
except ImportError:
    print("ERROR: rfc8785 is required for integrity checksum validation. Install with: pip install rfc8785",
          file=sys.stderr)
    sys.exit(2)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Paths relative to repository root
SCHEMA_DIR = "schemas"
EXAMPLES_DIR = "examples"

SCHEMAS = {
    "portable-ai-memory": f"{SCHEMA_DIR}/portable-ai-memory.schema.json",
    "portable-ai-memory-conversation": f"{SCHEMA_DIR}/portable-ai-memory-conversation.schema.json",
    "portable-ai-memory-embeddings": f"{SCHEMA_DIR}/portable-ai-memory-embeddings.schema.json",
}

# Map schema identifier → schema file for auto-detection
SCHEMA_DETECT_FIELD = "schema"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOG_FORMAT = "%(message)s"
logging.basicConfig(format=LOG_FORMAT, level=logging.INFO)
log = logging.getLogger("pam-validate")


# ---------------------------------------------------------------------------
# Result tracking
# ---------------------------------------------------------------------------

@dataclass
class CheckResult:
    """Single validation check result."""
    level: str  # "error", "warning"
    file: str
    check: str
    message: str

    def __str__(self) -> str:
        icon = "✗" if self.level == "error" else "⚠"
        return f"  {icon} [{self.check}] {self.file}: {self.message}"


@dataclass
class ValidationReport:
    """Aggregated validation results."""
    results: list[CheckResult] = field(default_factory=list)
    _checks_run: set[str] = field(default_factory=set)

    def error(self, file: str, check: str, message: str) -> None:
        self.results.append(CheckResult("error", file, check, message))
        self._checks_run.add(check)

    def warning(self, file: str, check: str, message: str) -> None:
        self.results.append(CheckResult("warning", file, check, message))
        self._checks_run.add(check)

    def check_ran(self, check: str) -> None:
        """Record that a check was executed (regardless of pass/fail)."""
        self._checks_run.add(check)

    @property
    def checks_run(self) -> int:
        return len(self._checks_run)

    @property
    def errors(self) -> list[CheckResult]:
        return [r for r in self.results if r.level == "error"]

    @property
    def warnings(self) -> list[CheckResult]:
        return [r for r in self.results if r.level == "warning"]

    @property
    def ok(self) -> bool:
        return len(self.errors) == 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_json(path: Path) -> dict | list | None:
    """Load and parse a JSON file."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return None
    except FileNotFoundError:
        return None


def normalize_content(content: str) -> str:
    """
    Normalize content for hash computation as specified in the PAM spec.
    Normalization: trim whitespace, lowercase, normalize unicode (NFC), collapse multiple spaces.
    """
    text = content.strip()
    text = text.lower()
    text = unicodedata.normalize("NFC", text)
    text = " ".join(text.split())
    return text


def compute_content_hash(content: str) -> str:
    """Compute SHA-256 hash of normalized content."""
    normalized = normalize_content(content)
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def canonicalize_jcs(obj: object) -> bytes:
    """
    RFC 8785 (JCS) canonicalization — deterministic JSON serialization.
    Uses the rfc8785 library for correct IEEE 754 float serialization.
    CRITICAL: json.dumps() is NOT RFC 8785 compliant (e.g., 1.0 vs 1).
    """
    return rfc8785.dumps(obj)


def compute_integrity_checksum(memories: list[dict]) -> str:
    """
    Compute the integrity checksum for a memories array.
    Per spec: objects sorted by id ascending, then canonicalized per RFC 8785.
    """
    sorted_memories = sorted(memories, key=lambda m: m.get("id", ""))
    canonical = canonicalize_jcs(sorted_memories)
    digest = hashlib.sha256(canonical).hexdigest()
    return f"sha256:{digest}"


def _is_base64url(value: str) -> bool:
    """Check if a string contains only valid Base64url characters (RFC 4648 §5)."""
    import re
    return bool(re.fullmatch(r'[A-Za-z0-9_-]+', value))


def parse_datetime(dt_str: str | None) -> datetime | None:
    """Parse ISO 8601 datetime string."""
    if dt_str is None:
        return None
    try:
        # Handle both 'Z' suffix and '+00:00'
        if dt_str.endswith("Z"):
            dt_str = dt_str[:-1] + "+00:00"
        return datetime.fromisoformat(dt_str)
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Check 1: Schema validity
# ---------------------------------------------------------------------------

def check_schemas_valid(repo: Path, report: ValidationReport) -> dict[str, dict]:
    """Verify all schema files are valid JSON Schema Draft 2020-12."""
    loaded_schemas = {}

    for name, rel_path in SCHEMAS.items():
        schema_path = repo / rel_path
        fname = str(rel_path)

        if not schema_path.exists():
            report.error(fname, "schema-exists", f"Schema file not found: {schema_path}")
            continue

        data = load_json(schema_path)
        if data is None:
            report.error(fname, "schema-json", "Invalid JSON")
            continue

        # Check it declares Draft 2020-12
        declared_schema = data.get("$schema", "")
        if "2020-12" not in declared_schema:
            report.warning(fname, "schema-draft", f"Expected Draft 2020-12, found: {declared_schema}")

        # Try to construct a validator (checks meta-schema validity)
        try:
            Draft202012Validator.check_schema(data)
        except Exception as e:
            report.error(fname, "schema-valid", f"Invalid JSON Schema: {e}")
            continue

        loaded_schemas[name] = data
        report.check_ran("schema-valid")
        log.info(f"  ✓ Schema valid: {fname}")

    return loaded_schemas


# ---------------------------------------------------------------------------
# Check 2: Example files validate against schemas
# ---------------------------------------------------------------------------

def check_examples_validate(repo: Path, schemas: dict[str, dict], report: ValidationReport) -> list[tuple[Path, dict]]:
    """Validate all example files against their detected schema."""
    examples_dir = repo / EXAMPLES_DIR
    validated_examples = []

    if not examples_dir.exists():
        report.warning(EXAMPLES_DIR, "examples-dir", "Examples directory not found")
        return validated_examples

    json_files = sorted(examples_dir.rglob("*.json"))
    if not json_files:
        report.warning(EXAMPLES_DIR, "examples-empty", "No JSON files found in examples/")
        return validated_examples

    for json_file in json_files:
        rel = json_file.relative_to(repo)
        fname = str(rel)

        data = load_json(json_file)
        if data is None:
            report.error(fname, "example-json", "Invalid JSON")
            continue

        # Auto-detect schema from the 'schema' field
        schema_id = data.get(SCHEMA_DETECT_FIELD)
        if schema_id is None:
            report.error(fname, "example-schema-detect",
                         "Missing 'schema' field — cannot determine which schema to validate against")
            continue

        if schema_id not in schemas:
            report.error(fname, "example-schema-detect",
                         f"Unknown schema identifier: '{schema_id}'. Known: {list(schemas.keys())}")
            continue

        schema = schemas[schema_id]
        validator = Draft202012Validator(schema)
        errors = sorted(validator.iter_errors(data), key=lambda e: list(e.path))

        if errors:
            for err in errors[:10]:  # Limit output
                path = ".".join(str(p) for p in err.absolute_path) or "(root)"
                report.error(fname, "schema-validation", f"{path}: {err.message}")
            if len(errors) > 10:
                report.error(fname, "schema-validation", f"... and {len(errors) - 10} more errors")
        else:
            report.check_ran("schema-validation")
            log.info(f"  ✓ Schema valid: {fname}")
            validated_examples.append((json_file, data))

    return validated_examples


# ---------------------------------------------------------------------------
# Check 3: Content hash integrity
# ---------------------------------------------------------------------------

def check_content_hashes(fname: str, data: dict, report: ValidationReport) -> None:
    """Verify content_hash matches SHA-256 of normalized content for each memory."""
    memories = data.get("memories", [])

    for mem in memories:
        mem_id = mem.get("id", "?")
        content = mem.get("content")
        declared_hash = mem.get("content_hash")

        if content is None or declared_hash is None:
            continue

        computed = compute_content_hash(content)
        if computed != declared_hash:
            report.error(
                fname,
                "content-hash",
                f"Memory '{mem_id}': content_hash mismatch. "
                f"Declared: {declared_hash}, computed: {computed}"
            )
        else:
            report.check_ran("content-hash")
            log.debug(f"  ✓ Content hash OK: {mem_id}")


# ---------------------------------------------------------------------------
# Check 4: Integrity block
# ---------------------------------------------------------------------------

def check_integrity_block(fname: str, data: dict, report: ValidationReport) -> None:
    """Verify integrity.total_memories and integrity.checksum."""
    integrity = data.get("integrity")
    memories = data.get("memories", [])

    if integrity is None:
        return  # integrity block is optional

    # total_memories
    declared_total = integrity.get("total_memories")
    if declared_total is not None and declared_total != len(memories):
        report.error(
            fname,
            "integrity-total",
            f"integrity.total_memories={declared_total} but memories array has {len(memories)} items"
        )

    # checksum
    declared_checksum = integrity.get("checksum")
    if declared_checksum is not None:
        computed = compute_integrity_checksum(memories)
        if computed != declared_checksum:
            report.error(
                fname,
                "integrity-checksum",
                f"integrity.checksum mismatch. Declared: {declared_checksum}, computed: {computed}"
            )
        else:
            report.check_ran("integrity-checksum")
            log.info(f"  ✓ Integrity checksum OK: {fname}")


# ---------------------------------------------------------------------------
# Check 5: Cross-references
# ---------------------------------------------------------------------------

def check_cross_references(fname: str, data: dict, report: ValidationReport) -> None:
    """Verify all internal cross-references are valid."""
    memories = data.get("memories", [])
    relations = data.get("relations", [])
    conversations = data.get("conversations_index", [])

    memory_ids = {m["id"] for m in memories if "id" in m}
    conversation_ids = {c["id"] for c in conversations if "id" in c}

    # Relations → memories
    for rel in relations:
        rel_id = rel.get("id", "?")
        from_id = rel.get("from")
        to_id = rel.get("to")

        if from_id and from_id not in memory_ids:
            report.error(fname, "xref-relation", f"Relation '{rel_id}': 'from' references unknown memory '{from_id}'")
        if to_id and to_id not in memory_ids:
            report.error(fname, "xref-relation", f"Relation '{rel_id}': 'to' references unknown memory '{to_id}'")
        if from_id and to_id and from_id == to_id:
            report.warning(fname, "xref-relation", f"Relation '{rel_id}': self-referencing (from == to == '{from_id}')")

    # Memory provenance.conversation_ref → conversations_index
    for mem in memories:
        mem_id = mem.get("id", "?")
        prov = mem.get("provenance", {})
        conv_ref = prov.get("conversation_ref")

        if conv_ref and conversation_ids and conv_ref not in conversation_ids:
            report.error(
                fname,
                "xref-conversation",
                f"Memory '{mem_id}': provenance.conversation_ref='{conv_ref}' not found in conversations_index"
            )

        # superseded_by → memory
        temporal = mem.get("temporal", {})
        superseded = temporal.get("superseded_by")
        if superseded and superseded not in memory_ids:
            report.error(fname, "xref-superseded",
                         f"Memory '{mem_id}': temporal.superseded_by='{superseded}' not found in memories")

    # conversations_index.derived_memories → memories
    for conv in conversations:
        conv_id = conv.get("id", "?")
        derived = conv.get("derived_memories", [])
        for dm_id in derived:
            if dm_id not in memory_ids:
                report.error(
                    fname,
                    "xref-derived",
                    f"Conversation '{conv_id}': derived_memories references unknown memory '{dm_id}'"
                )

    # Bidirectional consistency: conversation_ref ↔ derived_memories
    conv_derived_map: dict[str, set[str]] = {}
    for conv in conversations:
        conv_id = conv.get("id", "?")
        conv_derived_map[conv_id] = set(conv.get("derived_memories", []))

    for mem in memories:
        mem_id = mem.get("id", "?")
        prov = mem.get("provenance", {})
        conv_ref = prov.get("conversation_ref")
        if conv_ref and conv_ref in conv_derived_map:
            if mem_id not in conv_derived_map[conv_ref]:
                report.warning(
                    fname,
                    "xref-bidirectional",
                    f"Memory '{mem_id}' references conversation '{conv_ref}' via provenance, "
                    f"but '{conv_ref}'.derived_memories does not include '{mem_id}'"
                )


# ---------------------------------------------------------------------------
# Check 6: Temporal consistency
# ---------------------------------------------------------------------------

def check_temporal_consistency(fname: str, data: dict, report: ValidationReport) -> None:
    """Verify temporal ordering constraints."""
    memories = data.get("memories", [])

    for mem in memories:
        mem_id = mem.get("id", "?")
        temporal = mem.get("temporal", {})

        created = parse_datetime(temporal.get("created_at"))
        updated = parse_datetime(temporal.get("updated_at"))
        valid_from = parse_datetime(temporal.get("valid_from"))
        valid_until = parse_datetime(temporal.get("valid_until"))

        if created and updated and updated < created:
            report.error(fname, "temporal",
                         f"Memory '{mem_id}': updated_at ({temporal['updated_at']}) < created_at ({temporal['created_at']})")

        if valid_from and valid_until and valid_until < valid_from:
            report.error(fname, "temporal",
                         f"Memory '{mem_id}': valid_until ({temporal['valid_until']}) < valid_from ({temporal['valid_from']})")

        # Confidence: last_reinforced should not precede created_at
        confidence = mem.get("confidence", {})
        if confidence:
            reinforced = parse_datetime(confidence.get("last_reinforced"))
            if created and reinforced and reinforced < created:
                report.warning(fname, "temporal", f"Memory '{mem_id}': confidence.last_reinforced precedes created_at")

    # Conversations temporal
    for conv in data.get("conversations_index", []):
        conv_id = conv.get("id", "?")
        temporal = conv.get("temporal", {})
        created = parse_datetime(temporal.get("created_at"))
        updated = parse_datetime(temporal.get("updated_at"))

        if created and updated and updated < created:
            report.error(fname, "temporal", f"Conversation '{conv_id}': updated_at < created_at")


# ---------------------------------------------------------------------------
# Check 7: ID uniqueness
# ---------------------------------------------------------------------------

def check_id_uniqueness(fname: str, data: dict, report: ValidationReport) -> None:
    """Verify all IDs are unique within their scope."""

    def check_scope(items: list[dict], scope: str) -> None:
        seen: dict[str, int] = {}
        for item in items:
            item_id = item.get("id")
            if item_id is None:
                continue
            if item_id in seen:
                report.error(fname, "id-unique", f"Duplicate {scope} ID: '{item_id}'")
            seen[item_id] = seen.get(item_id, 0) + 1

    check_scope(data.get("memories", []), "memory")
    check_scope(data.get("relations", []), "relation")
    check_scope(data.get("conversations_index", []), "conversation")


def check_id_uniqueness_conversation(fname: str, data: dict, report: ValidationReport) -> None:
    """Verify all message IDs are unique within a conversation."""
    seen: dict[str, int] = {}
    for msg in data.get("messages", []):
        msg_id = msg.get("id")
        if msg_id is None:
            continue
        if msg_id in seen:
            report.error(fname, "id-unique-conversation", f"Duplicate message ID: '{msg_id}'")
        seen[msg_id] = seen.get(msg_id, 0) + 1


def check_id_uniqueness_embeddings(fname: str, data: dict, report: ValidationReport) -> None:
    """Verify all embedding IDs and memory_id references are unique."""
    seen_ids: dict[str, int] = {}
    seen_memory_ids: dict[str, int] = {}
    for emb in data.get("embeddings", []):
        emb_id = emb.get("id")
        if emb_id is not None:
            if emb_id in seen_ids:
                report.error(fname, "id-unique-embeddings", f"Duplicate embedding id: '{emb_id}'")
            seen_ids[emb_id] = seen_ids.get(emb_id, 0) + 1
        mem_id = emb.get("memory_id")
        if mem_id is not None:
            if mem_id in seen_memory_ids:
                report.error(fname, "id-unique-embeddings", f"Duplicate embedding memory_id: '{mem_id}'")
            seen_memory_ids[mem_id] = seen_memory_ids.get(mem_id, 0) + 1


# ---------------------------------------------------------------------------
# Check 8: Custom type rules
# ---------------------------------------------------------------------------

def check_custom_type_rules(fname: str, data: dict, report: ValidationReport) -> None:
    """Verify custom_type is set iff type == 'custom'."""
    for mem in data.get("memories", []):
        mem_id = mem.get("id", "?")
        mem_type = mem.get("type")
        custom_type = mem.get("custom_type")

        if mem_type == "custom" and not custom_type:
            report.error(fname, "custom-type", f"Memory '{mem_id}': type='custom' but custom_type is missing/null")
        elif mem_type != "custom" and custom_type is not None:
            report.error(fname, "custom-type",
                         f"Memory '{mem_id}': type='{mem_type}' but custom_type is set to '{custom_type}' (must be null)")


# ---------------------------------------------------------------------------
# Check 9: Conversation message DAG consistency
# ---------------------------------------------------------------------------

def check_conversation_dag(fname: str, data: dict, report: ValidationReport) -> None:
    """Verify parent_id/children_ids consistency in conversation messages."""
    if data.get("schema") != "portable-ai-memory-conversation":
        return

    messages = data.get("messages", [])
    msg_ids = {m["id"] for m in messages if "id" in m}

    for msg in messages:
        msg_id = msg.get("id", "?")
        parent_id = msg.get("parent_id")
        children_ids = msg.get("children_ids", [])

        # parent_id references valid message
        if parent_id and parent_id not in msg_ids:
            report.error(fname, "dag", f"Message '{msg_id}': parent_id='{parent_id}' not found in messages")

        # children_ids reference valid messages
        for child_id in children_ids:
            if child_id not in msg_ids:
                report.error(fname, "dag", f"Message '{msg_id}': children_ids contains unknown message '{child_id}'")

        # Bidirectional: if A lists B as child, B should list A as parent
        for child_id in children_ids:
            child_msg = next((m for m in messages if m.get("id") == child_id), None)
            if child_msg and child_msg.get("parent_id") != msg_id:
                report.warning(
                    fname,
                    "dag-bidirectional",
                    f"Message '{msg_id}' lists '{child_id}' as child, but '{child_id}'.parent_id='{child_msg.get('parent_id')}'"
                )


# ---------------------------------------------------------------------------
# Check 10: Embeddings cross-references
# ---------------------------------------------------------------------------

def check_embeddings_xref(
        examples: list[tuple[Path, dict]],
        repo: Path,
        report: ValidationReport,
) -> None:
    """Verify embedding_ref → embeddings file and embeddings.memory_id → memories."""
    # Collect all memory stores and embeddings files
    memory_stores: list[tuple[str, dict]] = []
    embeddings_files: list[tuple[str, dict]] = []

    for path, data in examples:
        rel = str(path.relative_to(repo))
        schema_id = data.get("schema")
        if schema_id == "portable-ai-memory":
            memory_stores.append((rel, data))
        elif schema_id == "portable-ai-memory-embeddings":
            embeddings_files.append((rel, data))

    # Build global embedding ID set
    embedding_ids: set[str] = set()
    embedding_memory_refs: dict[str, str] = {}  # embedding_id → memory_id

    for fname, emb_data in embeddings_files:
        for emb in emb_data.get("embeddings", []):
            emb_id = emb.get("id")
            if emb_id:
                embedding_ids.add(emb_id)
                embedding_memory_refs[emb_id] = emb.get("memory_id", "")

    # Check memory.embedding_ref → embedding exists
    all_memory_ids: set[str] = set()
    for fname, store in memory_stores:
        for mem in store.get("memories", []):
            mem_id = mem.get("id", "?")
            all_memory_ids.add(mem_id)
            emb_ref = mem.get("embedding_ref")

            if emb_ref and emb_ref not in embedding_ids:
                report.error(
                    fname,
                    "xref-embedding",
                    f"Memory '{mem_id}': embedding_ref='{emb_ref}' not found in any embeddings file"
                )

    # Check embedding.memory_id → memory exists
    for fname, emb_data in embeddings_files:
        for emb in emb_data.get("embeddings", []):
            emb_id = emb.get("id", "?")
            mem_id = emb.get("memory_id")
            if mem_id and all_memory_ids and mem_id not in all_memory_ids:
                report.error(
                    fname,
                    "xref-embedding-memory",
                    f"Embedding '{emb_id}': memory_id='{mem_id}' not found in any memory store"
                )


# ---------------------------------------------------------------------------
# Check 11: Status ↔ superseded_by consistency
# ---------------------------------------------------------------------------

def check_status_consistency(fname: str, data: dict, report: ValidationReport) -> None:
    """Verify status and superseded_by are consistent."""
    for mem in data.get("memories", []):
        mem_id = mem.get("id", "?")
        status = mem.get("status", "active")
        temporal = mem.get("temporal", {})
        superseded_by = temporal.get("superseded_by")

        if status == "superseded" and not superseded_by:
            report.warning(
                fname,
                "status-consistency",
                f"Memory '{mem_id}': status='superseded' but temporal.superseded_by is not set"
            )
        if superseded_by and status != "superseded":
            report.warning(
                fname,
                "status-consistency",
                f"Memory '{mem_id}': temporal.superseded_by is set but status='{status}' (expected 'superseded')"
            )


# ---------------------------------------------------------------------------
# Check 12: Signature payload verification (§18.3)
# ---------------------------------------------------------------------------

def check_signature_payload(fname: str, data: dict, report: ValidationReport) -> None:
    """Verify signature payload structure and consistency per spec §18.3."""
    signature = data.get("signature")
    if signature is None:
        return

    # Check required payload fields are present in the export
    export_id = data.get("export_id")
    export_date = data.get("export_date")
    owner = data.get("owner", {})
    owner_id = owner.get("id")
    integrity = data.get("integrity", {})
    checksum = integrity.get("checksum")

    if not checksum:
        report.error(fname, "signature-payload",
                     "Signature present but integrity.checksum is missing — cannot verify signature payload")
        return

    # Verify the payload fields exist (the signature covers these)
    if not export_id:
        report.error(fname, "signature-payload",
                     "Signature present but export_id is missing/null — required for signature payload")
    if not export_date:
        report.error(fname, "signature-payload",
                     "Signature present but export_date is missing/null — required for signature payload")
    if not owner_id:
        report.error(fname, "signature-payload",
                     "Signature present but owner.id is missing — required for signature payload")

    # Verify the canonical payload can be constructed
    if export_id and export_date and owner_id and checksum:
        payload = {
            "checksum": checksum,
            "export_id": export_id,
            "export_date": export_date,
            "owner_id": owner_id,
        }
        try:
            canonical = canonicalize_jcs(payload)
            log.debug(f"  ✓ Signature payload canonical form: {len(canonical)} bytes")
        except Exception as e:
            report.error(fname, "signature-payload", f"Failed to canonicalize signature payload: {e}")

    # Check signed_at >= export_date (spec §18.5 rule 3)
    signed_at = signature.get("signed_at")
    if signed_at and export_date:
        try:
            from datetime import datetime, timezone
            sa = datetime.fromisoformat(signed_at.replace("Z", "+00:00"))
            ed = datetime.fromisoformat(export_date.replace("Z", "+00:00"))
            if sa < ed:
                report.error(fname, "signature-payload",
                             f"signature.signed_at ({signed_at}) is before export_date ({export_date}) — spec §18.5 requires signed_at >= export_date")
        except (ValueError, TypeError):
            pass  # malformed dates caught by schema validation

    # Check signature block fields
    algo = signature.get("algorithm")
    value = signature.get("value")
    if not algo:
        report.error(fname, "signature-fields", "signature.algorithm is missing")
    if not value:
        report.error(fname, "signature-fields", "signature.value is missing")
    elif not _is_base64url(value):
        report.error(fname, "signature-fields",
                     f"signature.value contains invalid Base64url characters — must match RFC 4648 §5 alphabet [A-Za-z0-9_-]")


# ---------------------------------------------------------------------------
# Check 13: Signature conditional dependency
# ---------------------------------------------------------------------------

def check_signature_dependencies(fname: str, data: dict, report: ValidationReport) -> None:
    """When signature is present (not null), export_id and export_date MUST be non-null strings."""
    signature = data.get("signature")
    if signature is None:
        return

    export_id = data.get("export_id")
    export_date = data.get("export_date")

    if export_id is None:
        report.error(fname, "signature-dep", "Signed export requires export_id to be a non-null string")
    if export_date is None:
        report.error(fname, "signature-dep", "Signed export requires export_date to be a non-null string")


# ---------------------------------------------------------------------------
# Check 14: Platform identifier consistency
# ---------------------------------------------------------------------------

def check_platform_consistency(
        examples: list[tuple[Path, dict]],
        repo: Path,
        report: ValidationReport,
) -> None:
    """Verify platform identifiers use the same namespace across all files."""
    import re
    platform_pattern = re.compile(r"^[a-z0-9_-]{2,32}$")

    # Collect all platforms from all files
    platforms_by_source: dict[str, set[str]] = {}

    for path, data in examples:
        fname = str(path.relative_to(repo))
        schema_id = data.get("schema")

        if schema_id == "portable-ai-memory":
            # provenance.platform
            for mem in data.get("memories", []):
                prov = mem.get("provenance", {})
                platform = prov.get("platform")
                if platform:
                    platforms_by_source.setdefault(f"{fname}:provenance.platform", set()).add(platform)
                    if not platform_pattern.match(platform):
                        report.error(fname, "platform-format",
                                     f"Invalid platform identifier '{platform}' — must match ^[a-z0-9_-]{{2,32}}$")

            # conversations_index[].platform
            for conv in data.get("conversations_index", []):
                platform = conv.get("platform")
                if platform:
                    platforms_by_source.setdefault(f"{fname}:conversations_index.platform", set()).add(platform)
                    if not platform_pattern.match(platform):
                        report.error(fname, "platform-format",
                                     f"Invalid platform identifier '{platform}' in conversations_index — must match ^[a-z0-9_-]{{2,32}}$")

        elif schema_id == "portable-ai-memory-conversation":
            provider = data.get("provider", {})
            name = provider.get("name")
            if name:
                platforms_by_source.setdefault(f"{fname}:provider.name", set()).add(name)
                if not platform_pattern.match(name):
                    report.error(fname, "platform-format",
                                 f"Invalid provider.name '{name}' — must match ^[a-z0-9_-]{{2,32}}$")

    # Check for company names instead of product names
    company_to_product = {
        "openai": "chatgpt",
        "anthropic": "claude",
        "google": "gemini",
        "microsoft": "copilot",
        "xai": "grok",
    }
    all_platforms: set[str] = set()
    for platforms in platforms_by_source.values():
        all_platforms.update(platforms)

    for platform in all_platforms:
        if platform in company_to_product:
            report.warning(
                "(cross-file)",
                "platform-naming",
                f"Platform '{platform}' uses company name — spec requires product name '{company_to_product[platform]}'"
            )


# ---------------------------------------------------------------------------
# Check 15: Conversation cross-file consistency
# ---------------------------------------------------------------------------

def check_conversation_crossfile(
        examples: list[tuple[Path, dict]],
        repo: Path,
        report: ValidationReport,
) -> None:
    """Verify conversations_index entries are consistent with conversation files."""
    # Collect conversations_index entries from memory stores
    index_entries: dict[str, dict] = {}  # conv_id → index entry
    index_source: dict[str, str] = {}  # conv_id → source file

    # Collect conversation files
    conv_files: dict[str, tuple[str, dict]] = {}  # conv_id → (fname, data)

    for path, data in examples:
        fname = str(path.relative_to(repo))
        schema_id = data.get("schema")

        if schema_id == "portable-ai-memory":
            for entry in data.get("conversations_index", []):
                conv_id = entry.get("id")
                if conv_id:
                    index_entries[conv_id] = entry
                    index_source[conv_id] = fname

        elif schema_id == "portable-ai-memory-conversation":
            conv_id = data.get("id")
            if conv_id:
                conv_files[conv_id] = (fname, data)

    # Cross-check matching IDs
    for conv_id, entry in index_entries.items():
        if conv_id not in conv_files:
            continue  # external reference, can't validate

        conv_fname, conv_data = conv_files[conv_id]
        idx_fname = index_source[conv_id]

        # Title consistency
        idx_title = entry.get("title")
        conv_title = conv_data.get("title")
        if idx_title and conv_title and idx_title != conv_title:
            report.error(
                f"{idx_fname}↔{conv_fname}",
                "conv-crossfile",
                f"Conversation '{conv_id}': title mismatch — index has '{idx_title}', file has '{conv_title}'"
            )

        # Platform consistency
        idx_platform = entry.get("platform")
        conv_provider = conv_data.get("provider", {}).get("name")
        if idx_platform and conv_provider and idx_platform != conv_provider:
            report.error(
                f"{idx_fname}↔{conv_fname}",
                "conv-crossfile",
                f"Conversation '{conv_id}': platform mismatch — index has '{idx_platform}', file has provider.name='{conv_provider}'"
            )

        # Temporal consistency (created_at)
        idx_created = entry.get("temporal", {}).get("created_at")
        conv_created = conv_data.get("temporal", {}).get("created_at")
        if idx_created and conv_created and idx_created != conv_created:
            report.warning(
                f"{idx_fname}↔{conv_fname}",
                "conv-crossfile",
                f"Conversation '{conv_id}': created_at mismatch — index has '{idx_created}', file has '{conv_created}'"
            )

        # Message count
        idx_count = entry.get("message_count")
        actual_count = len(conv_data.get("messages", []))
        if idx_count is not None and idx_count != actual_count:
            report.error(
                f"{idx_fname}↔{conv_fname}",
                "conv-crossfile",
                f"Conversation '{conv_id}': message_count mismatch — index has {idx_count}, file has {actual_count} messages"
            )

        # Tags consistency
        idx_tags = set(entry.get("tags", []))
        conv_tags = set(conv_data.get("tags", []))
        if idx_tags and conv_tags and idx_tags != conv_tags:
            report.warning(
                f"{idx_fname}↔{conv_fname}",
                "conv-crossfile",
                f"Conversation '{conv_id}': tags mismatch — index has {sorted(idx_tags)}, file has {sorted(conv_tags)}"
            )


# ---------------------------------------------------------------------------
# Check 16: Content hash completeness
# ---------------------------------------------------------------------------

def check_content_hash_completeness(fname: str, data: dict, report: ValidationReport) -> None:
    """Warn when content exists but content_hash is missing."""
    for mem in data.get("memories", []):
        mem_id = mem.get("id", "?")
        content = mem.get("content")
        content_hash = mem.get("content_hash")

        if content and not content_hash:
            report.warning(
                fname,
                "content-hash-completeness",
                f"Memory '{mem_id}': has content but content_hash is missing"
            )


# ---------------------------------------------------------------------------
# Check 17: Conversation message temporal ordering
# ---------------------------------------------------------------------------

def check_conversation_temporal(fname: str, data: dict, report: ValidationReport) -> None:
    """Verify message timestamps are in reasonable order for linear conversations."""
    if data.get("schema") != "portable-ai-memory-conversation":
        return

    messages = data.get("messages", [])
    if len(messages) < 2:
        return

    # Only check linear conversations (no branching)
    has_branching = any(
        len(m.get("children_ids", [])) > 1 for m in messages
    )
    if has_branching:
        return  # DAG conversations don't have linear ordering

    prev_dt = None
    prev_id = None
    for msg in messages:
        msg_id = msg.get("id", "?")
        dt = parse_datetime(msg.get("created_at"))
        if dt and prev_dt and dt < prev_dt:
            report.warning(
                fname,
                "conv-temporal-order",
                f"Message '{msg_id}' timestamp ({msg.get('created_at')}) precedes previous message '{prev_id}' ({messages[messages.index(msg) - 1].get('created_at')})"
            )
        if dt:
            prev_dt = dt
            prev_id = msg_id


# ---------------------------------------------------------------------------
# Check 18: BCP 47 language tag validation
# ---------------------------------------------------------------------------

def check_bcp47_language(fname: str, data: dict, report: ValidationReport) -> None:
    """Verify metadata.language fields match the BCP 47 pattern from the spec."""
    import re
    bcp47_pattern = re.compile(r"^[a-z]{2,3}(-[A-Z][a-z]{3})?(-[A-Z]{2})?$")

    for mem in data.get("memories", []):
        mem_id = mem.get("id", "?")
        metadata = mem.get("metadata", {})
        if metadata is None:
            continue
        language = metadata.get("language")
        if language and not bcp47_pattern.match(language):
            report.warning(
                fname,
                "bcp47-language",
                f"Memory '{mem_id}': metadata.language='{language}' does not match BCP 47 pattern ^[a-z]{{2,3}}(-[A-Z][a-z]{{3}})?(-[A-Z]{{2}})?$"
            )


# ---------------------------------------------------------------------------
# Check 19: Incremental export rules
# ---------------------------------------------------------------------------

def check_incremental_export(fname: str, data: dict, report: ValidationReport) -> None:
    """When export_type is 'incremental', base_export_id and since SHOULD be present."""
    export_type = data.get("export_type", "full")
    if export_type != "incremental":
        return

    base_export_id = data.get("base_export_id")
    since = data.get("since")

    if not base_export_id:
        report.warning(
            fname,
            "incremental-fields",
            "export_type='incremental' but base_export_id is missing — SHOULD be provided per §16.2"
        )
    if not since:
        report.warning(
            fname,
            "incremental-fields",
            "export_type='incremental' but since is missing — SHOULD be provided per §16.2"
        )


# ---------------------------------------------------------------------------
# Check 20: Schema version consistency across files
# ---------------------------------------------------------------------------

def check_schema_version_consistency(
        examples: list[tuple[Path, dict]],
        repo: Path,
        report: ValidationReport,
) -> None:
    """Verify schema_version matches across memory store, conversation, and embeddings files."""
    versions: dict[str, list[str]] = {}  # version → list of source files
    for path, data in examples:
        fname = str(path.relative_to(repo))
        sv = data.get("schema_version")
        if sv:
            versions.setdefault(sv, []).append(fname)

    if len(versions) > 1:
        details = "; ".join(f"{v} in {', '.join(fs)}" for v, fs in sorted(versions.items()))
        report.error(
            "(cross-file)",
            "schema-version-consistency",
            f"Mismatched schema_version across files: {details}",
        )


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run_validation(repo: Path) -> ValidationReport:
    """Run all validation checks."""
    report = ValidationReport()

    log.info("=" * 60)
    log.info("PAM Repository Validator")
    log.info(f"Repository: {repo}")
    log.info("=" * 60)

    # Phase 1: Schema validity
    log.info("\n— Phase 1: Schema files")
    schemas = check_schemas_valid(repo, report)

    if not schemas:
        log.info("\n⛔ No valid schemas loaded. Cannot proceed with example validation.")
        return report

    # Phase 2: Example validation against schemas
    log.info("\n— Phase 2: Example files vs schemas")
    validated = check_examples_validate(repo, schemas, report)

    # Phase 3: Deep validation on validated examples
    log.info("\n— Phase 3: Deep validation")
    for path, data in validated:
        fname = str(path.relative_to(repo))
        schema_id = data.get("schema")

        if schema_id == "portable-ai-memory":
            log.info(f"\n  Checking memory store: {fname}")
            for check_fn, check_name in [
                (check_content_hashes, "content-hash"),
                (check_content_hash_completeness, "content-hash-completeness"),
                (check_integrity_block, "integrity-checksum"),
                (check_cross_references, "xref"),
                (check_temporal_consistency, "temporal"),
                (check_id_uniqueness, "id-unique"),
                (check_custom_type_rules, "custom-type"),
                (check_status_consistency, "status-consistency"),
                (check_signature_payload, "signature-payload"),
                (check_signature_dependencies, "signature-dep"),
                (check_incremental_export, "incremental-fields"),
                (check_bcp47_language, "bcp47-language"),
            ]:
                check_fn(fname, data, report)
                report.check_ran(check_name)

        elif schema_id == "portable-ai-memory-conversation":
            log.info(f"\n  Checking conversation: {fname}")
            for check_fn, check_name in [
                (check_conversation_dag, "dag"),
                (check_conversation_temporal, "conv-temporal-order"),
                (check_id_uniqueness_conversation, "id-unique-conversation"),
            ]:
                check_fn(fname, data, report)
                report.check_ran(check_name)

        elif schema_id == "portable-ai-memory-embeddings":
            log.info(f"\n  Checking embeddings: {fname}")
            check_id_uniqueness_embeddings(fname, data, report)
            report.check_ran("id-unique-embeddings")

    # Phase 4: Cross-file references (embeddings ↔ memories, conversations, platforms)
    log.info("\n— Phase 4: Cross-file references")
    check_embeddings_xref(validated, repo, report)
    report.check_ran("xref-embedding")
    check_platform_consistency(validated, repo, report)
    report.check_ran("platform-consistency")
    check_conversation_crossfile(validated, repo, report)
    report.check_ran("conv-crossfile")
    check_schema_version_consistency(validated, repo, report)
    report.check_ran("schema-version-consistency")

    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="PAM Repository Validator — validates schemas, examples, integrity, and cross-references.",
        epilog="Exit code 0 = all checks passed, 1 = errors found, 2 = setup error.",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help="Path to the PAM repository root. Default: auto-detect from script location or cwd.",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable debug logging.",
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Resolve repo root
    if args.repo_root:
        repo = args.repo_root.resolve()
    else:
        # Try to find repo root: look for schemas/ directory
        candidates = [
            Path.cwd(),
            Path(__file__).resolve().parent,
            Path(__file__).resolve().parent.parent,  # if script is in scripts/
        ]
        repo = None
        for candidate in candidates:
            if (candidate / SCHEMA_DIR).is_dir():
                repo = candidate
                break

        if repo is None:
            log.error(f"Cannot find repository root (looked for '{SCHEMA_DIR}/' directory).")
            log.error("Use --repo-root to specify the path explicitly.")
            return 2

    # Verify structure
    if not (repo / SCHEMA_DIR).is_dir():
        log.error(f"'{SCHEMA_DIR}/' directory not found in {repo}")
        return 2

    # Run
    report = run_validation(repo)

    # Summary
    log.info("\n" + "=" * 60)
    if report.warnings:
        log.info(f"\n⚠ Warnings ({len(report.warnings)}):")
        for w in report.warnings:
            log.info(str(w))

    if report.errors:
        log.info(f"\n✗ Errors ({len(report.errors)}):")
        for e in report.errors:
            log.info(str(e))

    log.info("")
    if report.ok:
        log.info(f"✓ All checks passed ({report.checks_run} checks, {len(report.warnings)} warnings)")
        return 0
    else:
        log.info(
            f"✗ Validation failed: {len(report.errors)} error(s), {len(report.warnings)} warning(s) ({report.checks_run} checks)")
        return 1


if __name__ == "__main__":
    sys.exit(main())
