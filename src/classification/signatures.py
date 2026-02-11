"""Signature Database - Deterministic bloatware signatures.

This module handles loading, validating, and matching bloatware signatures
for deterministic classification of system components.
"""

import hashlib
import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from src.core.models import (
    ActionType,
    Classification,
    Component,
    ComponentType,
    ReinstallBehavior,
    Signature,
    SignatureMatchRule,
)

logger = logging.getLogger("debloatr.classification.signatures")


@dataclass
class SignatureMatch:
    """Result of matching a component against a signature."""

    signature: Signature
    match_type: str  # "name", "publisher", "path", "hash"
    match_score: float  # 0.0 to 1.0
    matched_value: str  # The value that matched


class SignatureDatabase:
    """Database of bloatware signatures for classification.

    Loads signatures from JSON files and provides matching functionality
    to classify discovered components.

    Example:
        db = SignatureDatabase()
        db.load_from_file(Path("data/signatures/default.json"))
        match = db.match_component(component)
        if match:
            print(f"Matched: {match.signature.component_name}")
    """

    def __init__(self) -> None:
        """Initialize an empty signature database."""
        self.signatures: dict[str, Signature] = {}
        self._by_type: dict[ComponentType, list[Signature]] = {}
        self._by_publisher: dict[str, list[Signature]] = {}
        self._loaded_files: list[Path] = []
        self._file_hashes: dict[str, str] = {}
        self._versions: dict[str, str] = {}  # file path -> version
        self._last_updated: dict[str, str] = {}  # file path -> last_updated date

    def load_from_file(
        self,
        file_path: Path,
        verify_hash: bool = False,
        expected_hash: str | None = None,
    ) -> int:
        """Load signatures from a JSON file.

        Args:
            file_path: Path to the signature JSON file.
            verify_hash: Whether to verify file hash.
            expected_hash: Expected SHA256 hash of the file.

        Returns:
            Number of signatures loaded.

        Raises:
            FileNotFoundError: If file doesn't exist.
            ValueError: If hash verification fails or JSON is invalid.
        """
        if not file_path.exists():
            raise FileNotFoundError(f"Signature file not found: {file_path}")

        # Read file content
        content = file_path.read_text(encoding="utf-8")

        # Verify hash if requested
        if verify_hash:
            file_hash = hashlib.sha256(content.encode()).hexdigest()
            self._file_hashes[str(file_path)] = file_hash

            if expected_hash and file_hash != expected_hash:
                raise ValueError(
                    f"Signature file hash mismatch. " f"Expected: {expected_hash}, Got: {file_hash}"
                )

        # Parse JSON
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in signature file: {e}") from e

        # Handle both array and object with signatures key
        if isinstance(data, list):
            signatures_data = data
            version = "unknown"
            last_updated = "unknown"
        elif isinstance(data, dict):
            signatures_data = data.get("signatures", [])
            version = data.get("version", "unknown")
            last_updated = data.get("last_updated", "unknown")
        else:
            raise ValueError("Invalid signature file format")

        # Track version metadata
        file_key = str(file_path)
        self._versions[file_key] = version
        self._last_updated[file_key] = last_updated

        # Load each signature
        count = 0
        for sig_data in signatures_data:
            try:
                signature = self._parse_signature(sig_data)
                self._add_signature(signature)
                count += 1
            except Exception as e:
                logger.warning(f"Failed to parse signature: {e}")

        self._loaded_files.append(file_path)
        logger.info(f"Loaded {count} signatures from {file_path} (version: {version})")

        return count

    def load_from_directory(
        self,
        directory: Path,
        pattern: str = "*.json",
    ) -> int:
        """Load all signature files from a directory.

        Args:
            directory: Directory containing signature files.
            pattern: Glob pattern for files to load.

        Returns:
            Total number of signatures loaded.
        """
        total = 0
        for file_path in sorted(directory.glob(pattern)):
            try:
                total += self.load_from_file(file_path)
            except Exception as e:
                logger.error(f"Failed to load {file_path}: {e}")

        return total

    def _parse_signature(self, data: dict[str, Any]) -> Signature:
        """Parse a signature dictionary into a Signature object.

        Args:
            data: Raw signature data.

        Returns:
            Parsed Signature object.
        """
        # Parse match rules
        match_rules_data = data.get("match_rules", {})
        match_rules = SignatureMatchRule(
            name_pattern=match_rules_data.get("name_pattern"),
            publisher_pattern=match_rules_data.get("publisher_pattern"),
            path_pattern=match_rules_data.get("path_pattern"),
            hash_sha256=match_rules_data.get("hash_sha256", []),
        )

        # Parse component type
        type_str = data.get("component_type", "program").lower()
        component_type = {
            "program": ComponentType.PROGRAM,
            "service": ComponentType.SERVICE,
            "task": ComponentType.TASK,
            "startup": ComponentType.STARTUP,
            "driver": ComponentType.DRIVER,
            "uwp": ComponentType.UWP,
            "telemetry": ComponentType.TELEMETRY,
        }.get(type_str, ComponentType.PROGRAM)

        # Parse classification
        class_str = data.get("classification", "UNKNOWN").upper()
        classification = (
            Classification[class_str]
            if class_str in Classification.__members__
            else Classification.UNKNOWN
        )

        # Parse safe/unsafe actions
        safe_actions = [
            ActionType[a.upper()]
            for a in data.get("safe_actions", [])
            if a.upper() in ActionType.__members__
        ]
        unsafe_actions = [
            ActionType[a.upper()]
            for a in data.get("unsafe_actions", [])
            if a.upper() in ActionType.__members__
        ]

        # Parse reinstall behavior
        reinstall_str = data.get("reinstall_behavior", "none").lower()
        reinstall_behavior = {
            "none": ReinstallBehavior.NONE,
            "self_healing": ReinstallBehavior.SELF_HEALING,
            "update_restored": ReinstallBehavior.UPDATE_RESTORED,
        }.get(reinstall_str, ReinstallBehavior.NONE)

        # Parse date
        last_updated = datetime.now()
        if data.get("last_updated"):
            try:
                last_updated = datetime.fromisoformat(data["last_updated"])
            except ValueError:
                pass

        return Signature(
            signature_id=data.get("signature_id", ""),
            publisher=data.get("publisher", ""),
            component_name=data.get("component_name", ""),
            component_type=component_type,
            match_rules=match_rules,
            classification=classification,
            related_components=data.get("related_components", []),
            safe_actions=safe_actions,
            unsafe_actions=unsafe_actions,
            reinstall_behavior=reinstall_behavior,
            breakage_notes=data.get("breakage_notes", ""),
            evidence_url=data.get("evidence_url", ""),
            last_updated=last_updated,
        )

    def _add_signature(self, signature: Signature) -> None:
        """Add a signature to the database.

        Args:
            signature: Signature to add.
        """
        # Add to main dict
        self.signatures[signature.signature_id] = signature

        # Index by component type
        if signature.component_type not in self._by_type:
            self._by_type[signature.component_type] = []
        self._by_type[signature.component_type].append(signature)

        # Index by publisher
        publisher_key = signature.publisher.lower()
        if publisher_key not in self._by_publisher:
            self._by_publisher[publisher_key] = []
        self._by_publisher[publisher_key].append(signature)

    def match_component(self, component: Component) -> SignatureMatch | None:
        """Find the best matching signature for a component.

        Args:
            component: Component to match.

        Returns:
            SignatureMatch if found, None otherwise.
        """
        best_match: SignatureMatch | None = None
        best_score = 0.0

        # Get signatures for this component type
        type_signatures = self._by_type.get(component.component_type, [])

        # Also check signatures that match any type
        all_signatures = list(type_signatures)

        for signature in all_signatures:
            match = self._try_match(component, signature)
            if match and match.match_score > best_score:
                best_match = match
                best_score = match.match_score

        return best_match

    def _try_match(
        self,
        component: Component,
        signature: Signature,
    ) -> SignatureMatch | None:
        """Try to match a component against a signature.

        Args:
            component: Component to match.
            signature: Signature to check.

        Returns:
            SignatureMatch if matched, None otherwise.
        """
        rules = signature.match_rules

        # Try hash match first (highest confidence)
        if rules.hash_sha256 and component.install_path:
            file_hash = self._get_file_hash(component.install_path)
            if file_hash and file_hash in rules.hash_sha256:
                return SignatureMatch(
                    signature=signature,
                    match_type="hash",
                    match_score=1.0,
                    matched_value=file_hash,
                )

        # Try name pattern match
        if rules.name_pattern:
            name_to_check = component.name or component.display_name
            if self._pattern_matches(rules.name_pattern, name_to_check):
                return SignatureMatch(
                    signature=signature,
                    match_type="name",
                    match_score=0.9,
                    matched_value=name_to_check,
                )

        # Try publisher pattern match
        if rules.publisher_pattern:
            if self._pattern_matches(rules.publisher_pattern, component.publisher):
                # Publisher match alone is weaker
                return SignatureMatch(
                    signature=signature,
                    match_type="publisher",
                    match_score=0.7,
                    matched_value=component.publisher,
                )

        # Try path pattern match
        if rules.path_pattern and component.install_path:
            path_str = str(component.install_path)
            if self._pattern_matches(rules.path_pattern, path_str):
                return SignatureMatch(
                    signature=signature,
                    match_type="path",
                    match_score=0.8,
                    matched_value=path_str,
                )

        return None

    def _pattern_matches(self, pattern: str, value: str) -> bool:
        """Check if a regex pattern matches a value.

        Args:
            pattern: Regex pattern.
            value: Value to check.

        Returns:
            True if matches, False otherwise.
        """
        try:
            return bool(re.match(pattern, value, re.IGNORECASE))
        except re.error:
            logger.warning(f"Invalid regex pattern: {pattern}")
            return False

    def _get_file_hash(self, path: Path) -> str | None:
        """Get SHA256 hash of a file.

        Args:
            path: Path to file.

        Returns:
            Hash string if successful, None otherwise.
        """
        try:
            if path.exists() and path.is_file():
                return hashlib.sha256(path.read_bytes()).hexdigest()
        except (OSError, PermissionError):
            pass
        return None

    def get_signature(self, signature_id: str) -> Signature | None:
        """Get a signature by ID.

        Args:
            signature_id: Signature ID.

        Returns:
            Signature if found, None otherwise.
        """
        return self.signatures.get(signature_id)

    def get_related_signatures(self, signature: Signature) -> list[Signature]:
        """Get all signatures related to a given signature.

        Args:
            signature: Signature to find related ones for.

        Returns:
            List of related signatures.
        """
        related = []
        for related_id in signature.related_components:
            related_sig = self.signatures.get(related_id)
            if related_sig:
                related.append(related_sig)
        return related

    def get_signatures_by_publisher(self, publisher: str) -> list[Signature]:
        """Get all signatures for a publisher.

        Args:
            publisher: Publisher name.

        Returns:
            List of signatures for that publisher.
        """
        return self._by_publisher.get(publisher.lower(), [])

    def get_signatures_by_type(self, component_type: ComponentType) -> list[Signature]:
        """Get all signatures for a component type.

        Args:
            component_type: Component type.

        Returns:
            List of signatures for that type.
        """
        return self._by_type.get(component_type, [])

    def get_signatures_by_classification(
        self,
        classification: Classification,
    ) -> list[Signature]:
        """Get all signatures with a specific classification.

        Args:
            classification: Classification to filter by.

        Returns:
            List of matching signatures.
        """
        return [sig for sig in self.signatures.values() if sig.classification == classification]

    def export_to_file(self, file_path: Path) -> None:
        """Export all signatures to a JSON file.

        Args:
            file_path: Path to write to.
        """
        signatures_data = []

        for sig in self.signatures.values():
            sig_data = {
                "signature_id": sig.signature_id,
                "publisher": sig.publisher,
                "component_name": sig.component_name,
                "component_type": sig.component_type.name.lower(),
                "match_rules": {
                    "name_pattern": sig.match_rules.name_pattern,
                    "publisher_pattern": sig.match_rules.publisher_pattern,
                    "path_pattern": sig.match_rules.path_pattern,
                    "hash_sha256": sig.match_rules.hash_sha256,
                },
                "classification": sig.classification.value,
                "related_components": sig.related_components,
                "safe_actions": [a.value for a in sig.safe_actions],
                "unsafe_actions": [a.value for a in sig.unsafe_actions],
                "reinstall_behavior": sig.reinstall_behavior.value,
                "breakage_notes": sig.breakage_notes,
                "evidence_url": sig.evidence_url,
                "last_updated": sig.last_updated.isoformat(),
            }
            signatures_data.append(sig_data)

        output = {
            "version": "0.1.0",
            "generated": datetime.now().isoformat(),
            "signature_count": len(signatures_data),
            "signatures": signatures_data,
        }

        file_path.write_text(
            json.dumps(output, indent=2),
            encoding="utf-8",
        )

    @property
    def count(self) -> int:
        """Get total number of signatures."""
        return len(self.signatures)

    @property
    def versions(self) -> dict[str, str]:
        """Get version information for all loaded signature files.

        Returns:
            Dictionary mapping file path to version string.
        """
        return self._versions.copy()

    @property
    def primary_version(self) -> str:
        """Get the version of the primary (first loaded) signature file.

        Returns:
            Version string, or 'unknown' if no files loaded.
        """
        if self._loaded_files:
            return self._versions.get(str(self._loaded_files[0]), "unknown")
        return "unknown"

    def get_version_info(self) -> dict[str, Any]:
        """Get comprehensive version information for all loaded signatures.

        Returns:
            Dictionary with version metadata for all loaded files.
        """
        info: dict[str, Any] = {
            "total_signatures": self.count,
            "files_loaded": len(self._loaded_files),
            "files": [],
        }

        for file_path in self._loaded_files:
            file_key = str(file_path)
            info["files"].append(
                {
                    "path": file_key,
                    "version": self._versions.get(file_key, "unknown"),
                    "last_updated": self._last_updated.get(file_key, "unknown"),
                    "hash": self._file_hashes.get(file_key),
                }
            )

        return info

    def clear(self) -> None:
        """Clear all loaded signatures."""
        self.signatures.clear()
        self._by_type.clear()
        self._by_publisher.clear()
        self._loaded_files.clear()
        self._file_hashes.clear()
        self._versions.clear()
        self._last_updated.clear()
