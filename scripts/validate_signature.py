#!/usr/bin/env python3
"""Validate bloatware signature files.

Usage:
    python scripts/validate_signature.py data/signatures/default.json
    python scripts/validate_signature.py path/to/new_signature.json
"""

import json
import re
import sys
from pathlib import Path

VALID_TYPES = {"program", "service", "task", "startup", "driver", "uwp", "telemetry"}
VALID_CLASSIFICATIONS = {"CORE", "ESSENTIAL", "OPTIONAL", "BLOAT", "AGGRESSIVE", "UNKNOWN"}
VALID_ACTIONS = {"DISABLE", "REMOVE", "CONTAIN", "IGNORE"}
VALID_REINSTALL = {"none", "self_healing", "update_restored"}

REQUIRED_FIELDS = [
    "signature_id",
    "publisher",
    "component_name",
    "component_type",
    "match_rules",
    "classification",
    "safe_actions",
    "breakage_notes",
]


def validate_signature(sig: dict, index: int) -> list[str]:
    """Validate a single signature entry. Returns list of errors."""
    errors = []
    prefix = f"signatures[{index}] ({sig.get('signature_id', 'UNKNOWN')})"

    # Required fields
    for field in REQUIRED_FIELDS:
        if field not in sig or not sig[field]:
            errors.append(f"{prefix}: missing required field '{field}'")

    # Signature ID format
    sid = sig.get("signature_id", "")
    if sid and not re.match(r"^[a-z0-9-]+-\d{3}$", sid):
        errors.append(f"{prefix}: signature_id should match 'publisher-component-NNN' format")

    # Component type
    ctype = sig.get("component_type", "")
    if ctype and ctype.lower() not in VALID_TYPES:
        errors.append(f"{prefix}: invalid component_type '{ctype}', must be one of {VALID_TYPES}")

    # Classification
    cls = sig.get("classification", "")
    if cls and cls not in VALID_CLASSIFICATIONS:
        errors.append(
            f"{prefix}: invalid classification '{cls}', must be one of {VALID_CLASSIFICATIONS}"
        )

    # Match rules
    rules = sig.get("match_rules", {})
    if isinstance(rules, dict):
        has_pattern = any(
            rules.get(k)
            for k in ["name_pattern", "publisher_pattern", "path_pattern", "hash_sha256"]
        )
        if not has_pattern:
            errors.append(f"{prefix}: match_rules must have at least one pattern")

        # Validate regex patterns compile
        for key in ["name_pattern", "publisher_pattern", "path_pattern"]:
            pattern = rules.get(key)
            if pattern:
                try:
                    re.compile(pattern)
                except re.error as e:
                    errors.append(f"{prefix}: invalid regex in {key}: {e}")

    # Actions
    for action in sig.get("safe_actions", []):
        if action.upper() not in VALID_ACTIONS:
            errors.append(f"{prefix}: invalid safe_action '{action}'")
    for action in sig.get("unsafe_actions", []):
        if action.upper() not in VALID_ACTIONS:
            errors.append(f"{prefix}: invalid unsafe_action '{action}'")

    # Reinstall behavior
    rb = sig.get("reinstall_behavior", "")
    if rb and rb.lower() not in VALID_REINSTALL:
        errors.append(f"{prefix}: invalid reinstall_behavior '{rb}'")

    # Breakage notes should be non-trivial
    notes = sig.get("breakage_notes", "")
    if notes and len(notes) < 10:
        errors.append(f"{prefix}: breakage_notes too short (minimum 10 chars)")

    return errors


def validate_file(path: Path) -> tuple[int, list[str]]:
    """Validate a signature file. Returns (signature_count, errors)."""
    errors = []

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return 0, [f"Invalid JSON: {e}"]

    # Handle both formats
    if isinstance(data, list):
        signatures = data
    elif isinstance(data, dict):
        signatures = data.get("signatures", [])
        # Check metadata
        if "version" not in data:
            errors.append("Missing 'version' field in file metadata")
    else:
        return 0, ["File must contain a JSON array or object with 'signatures' key"]

    # Check for duplicate IDs
    seen_ids: set[str] = set()
    for sig in signatures:
        sid = sig.get("signature_id", "")
        if sid in seen_ids:
            errors.append(f"Duplicate signature_id: '{sid}'")
        seen_ids.add(sid)

    # Validate each signature
    for i, sig in enumerate(signatures):
        # Skip template entries
        if sig.get("signature_id", "").startswith("_"):
            continue
        errors.extend(validate_signature(sig, i))

    return len(signatures), errors


def main() -> int:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <signature_file.json> [...]")
        return 1

    total_errors = 0
    for filepath in sys.argv[1:]:
        path = Path(filepath)
        if not path.exists():
            print(f"ERROR: File not found: {path}")
            total_errors += 1
            continue

        count, errors = validate_file(path)

        if errors:
            print(f"\n{path}: {count} signatures, {len(errors)} error(s)")
            for err in errors:
                print(f"  - {err}")
            total_errors += len(errors)
        else:
            print(f"{path}: {count} signatures, all valid")

    if total_errors > 0:
        print(f"\nTotal errors: {total_errors}")
        return 1

    print("\nAll signatures valid.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
