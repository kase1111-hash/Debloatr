"""Unit tests for signature database module."""

import json
from pathlib import Path

import pytest

from src.classification.signatures import SignatureDatabase, SignatureMatch
from src.core.models import (
    ActionType,
    Classification,
    Component,
    ComponentType,
    ReinstallBehavior,
    Signature,
    SignatureMatchRule,
)


class TestSignatureDatabase:
    """Tests for SignatureDatabase class."""

    def test_init_empty_database(self) -> None:
        """Test creating an empty signature database."""
        db = SignatureDatabase()
        assert db.count == 0
        assert len(db.signatures) == 0

    def test_load_from_file_array_format(self, tmp_path: Path) -> None:
        """Test loading signatures from array format JSON."""
        sig_file = tmp_path / "sigs.json"
        sig_data = [
            {
                "signature_id": "test-sig-001",
                "publisher": "Test Publisher",
                "component_name": "Test App",
                "component_type": "program",
                "match_rules": {"name_pattern": "^Test.*App$"},
                "classification": "BLOAT",
                "safe_actions": ["disable"],
                "unsafe_actions": ["remove"],
            }
        ]
        sig_file.write_text(json.dumps(sig_data))

        db = SignatureDatabase()
        count = db.load_from_file(sig_file)

        assert count == 1
        assert db.count == 1
        assert "test-sig-001" in db.signatures

    def test_load_from_file_object_format(self, tmp_path: Path) -> None:
        """Test loading signatures from object format JSON with signatures key."""
        sig_file = tmp_path / "sigs.json"
        sig_data = {
            "version": "1.0",
            "signatures": [
                {
                    "signature_id": "test-sig-002",
                    "publisher": "Another Publisher",
                    "component_name": "Another App",
                    "component_type": "service",
                    "match_rules": {"name_pattern": "^Another.*$"},
                    "classification": "AGGRESSIVE",
                }
            ],
        }
        sig_file.write_text(json.dumps(sig_data))

        db = SignatureDatabase()
        count = db.load_from_file(sig_file)

        assert count == 1
        assert "test-sig-002" in db.signatures
        sig = db.signatures["test-sig-002"]
        assert sig.classification == Classification.AGGRESSIVE

    def test_load_from_file_not_found(self) -> None:
        """Test loading from non-existent file raises error."""
        db = SignatureDatabase()
        with pytest.raises(FileNotFoundError):
            db.load_from_file(Path("/nonexistent/file.json"))

    def test_load_from_file_invalid_json(self, tmp_path: Path) -> None:
        """Test loading invalid JSON raises error."""
        sig_file = tmp_path / "invalid.json"
        sig_file.write_text("not valid json {{{")

        db = SignatureDatabase()
        with pytest.raises(ValueError, match="Invalid JSON"):
            db.load_from_file(sig_file)

    def test_load_from_file_with_hash_verification(self, tmp_path: Path) -> None:
        """Test loading with hash verification."""
        sig_file = tmp_path / "sigs.json"
        sig_data = [{"signature_id": "test-001", "component_name": "Test"}]
        content = json.dumps(sig_data)
        sig_file.write_text(content)

        import hashlib

        expected_hash = hashlib.sha256(content.encode()).hexdigest()

        db = SignatureDatabase()
        count = db.load_from_file(sig_file, verify_hash=True, expected_hash=expected_hash)
        assert count == 1

    def test_load_from_file_hash_mismatch(self, tmp_path: Path) -> None:
        """Test loading with incorrect hash raises error."""
        sig_file = tmp_path / "sigs.json"
        sig_file.write_text('[{"signature_id": "test"}]')

        db = SignatureDatabase()
        with pytest.raises(ValueError, match="hash mismatch"):
            db.load_from_file(sig_file, verify_hash=True, expected_hash="wronghash")

    def test_load_from_directory(self, tmp_path: Path) -> None:
        """Test loading all signature files from directory."""
        # Create multiple signature files
        sig1 = tmp_path / "sigs1.json"
        sig1.write_text(json.dumps([{"signature_id": "sig-1", "component_name": "App1"}]))

        sig2 = tmp_path / "sigs2.json"
        sig2.write_text(json.dumps([{"signature_id": "sig-2", "component_name": "App2"}]))

        db = SignatureDatabase()
        count = db.load_from_directory(tmp_path)

        assert count == 2
        assert db.count == 2
        assert "sig-1" in db.signatures
        assert "sig-2" in db.signatures

    def test_match_component_by_name(self, tmp_path: Path) -> None:
        """Test matching component by name pattern."""
        sig_file = tmp_path / "sigs.json"
        sig_data = [
            {
                "signature_id": "cortana-001",
                "component_name": "Cortana",
                "component_type": "program",
                "match_rules": {"name_pattern": ".*[Cc]ortana.*"},
                "classification": "BLOAT",
            }
        ]
        sig_file.write_text(json.dumps(sig_data))

        db = SignatureDatabase()
        db.load_from_file(sig_file)

        component = Component(
            component_type=ComponentType.PROGRAM,
            name="Microsoft.Windows.Cortana",
            display_name="Cortana",
            publisher="Microsoft",
        )

        match = db.match_component(component)
        assert match is not None
        assert match.match_type == "name"
        assert match.match_score == 0.9
        assert match.signature.signature_id == "cortana-001"

    def test_match_component_by_publisher(self, tmp_path: Path) -> None:
        """Test matching component by publisher pattern."""
        sig_file = tmp_path / "sigs.json"
        sig_data = [
            {
                "signature_id": "mcafee-001",
                "component_name": "McAfee Security",
                "component_type": "program",
                "match_rules": {"publisher_pattern": ".*McAfee.*"},
                "classification": "AGGRESSIVE",
            }
        ]
        sig_file.write_text(json.dumps(sig_data))

        db = SignatureDatabase()
        db.load_from_file(sig_file)

        component = Component(
            component_type=ComponentType.PROGRAM,
            name="security-scan",
            display_name="Security Scanner",
            publisher="McAfee, LLC",
        )

        match = db.match_component(component)
        assert match is not None
        assert match.match_type == "publisher"
        assert match.match_score == 0.7

    def test_match_component_by_path(self, tmp_path: Path) -> None:
        """Test matching component by path pattern."""
        sig_file = tmp_path / "sigs.json"
        sig_data = [
            {
                "signature_id": "nvidia-telem-001",
                "component_name": "NVIDIA Telemetry",
                "component_type": "service",
                "match_rules": {"path_pattern": ".*NVIDIA.*NvTelemetry.*"},
                "classification": "BLOAT",
            }
        ]
        sig_file.write_text(json.dumps(sig_data))

        db = SignatureDatabase()
        db.load_from_file(sig_file)

        component = Component(
            component_type=ComponentType.SERVICE,
            name="NvTelemetryContainer",
            display_name="NVIDIA Telemetry Container",
            publisher="NVIDIA",
            install_path=Path(
                "C:/Program Files/NVIDIA Corporation/NvTelemetry/NvTelemetryContainer.exe"
            ),
        )

        match = db.match_component(component)
        assert match is not None
        assert match.match_type == "path"
        assert match.match_score == 0.8

    def test_match_component_no_match(self, tmp_path: Path) -> None:
        """Test no match returns None."""
        sig_file = tmp_path / "sigs.json"
        sig_data = [
            {
                "signature_id": "specific-001",
                "component_name": "Specific App",
                "component_type": "program",
                "match_rules": {"name_pattern": "^VerySpecificAppName$"},
                "classification": "BLOAT",
            }
        ]
        sig_file.write_text(json.dumps(sig_data))

        db = SignatureDatabase()
        db.load_from_file(sig_file)

        component = Component(
            component_type=ComponentType.PROGRAM,
            name="completely-different-app",
            display_name="Different App",
            publisher="Unknown",
        )

        match = db.match_component(component)
        assert match is None

    def test_match_component_type_mismatch(self, tmp_path: Path) -> None:
        """Test that component type must match for signature to apply."""
        sig_file = tmp_path / "sigs.json"
        sig_data = [
            {
                "signature_id": "service-only-001",
                "component_name": "Service Only",
                "component_type": "service",
                "match_rules": {"name_pattern": ".*TestService.*"},
                "classification": "BLOAT",
            }
        ]
        sig_file.write_text(json.dumps(sig_data))

        db = SignatureDatabase()
        db.load_from_file(sig_file)

        # Try to match a PROGRAM with service signature
        component = Component(
            component_type=ComponentType.PROGRAM,
            name="TestServiceApp",
            display_name="Test Service App",
            publisher="Test",
        )

        match = db.match_component(component)
        assert match is None  # Should not match different type

    def test_get_signature(self, tmp_path: Path) -> None:
        """Test getting a signature by ID."""
        sig_file = tmp_path / "sigs.json"
        sig_data = [{"signature_id": "fetch-001", "component_name": "Fetchable"}]
        sig_file.write_text(json.dumps(sig_data))

        db = SignatureDatabase()
        db.load_from_file(sig_file)

        sig = db.get_signature("fetch-001")
        assert sig is not None
        assert sig.component_name == "Fetchable"

        missing = db.get_signature("nonexistent")
        assert missing is None

    def test_get_signatures_by_classification(self, tmp_path: Path) -> None:
        """Test filtering signatures by classification."""
        sig_file = tmp_path / "sigs.json"
        sig_data = [
            {"signature_id": "bloat-1", "classification": "BLOAT"},
            {"signature_id": "bloat-2", "classification": "BLOAT"},
            {"signature_id": "aggro-1", "classification": "AGGRESSIVE"},
        ]
        sig_file.write_text(json.dumps(sig_data))

        db = SignatureDatabase()
        db.load_from_file(sig_file)

        bloat_sigs = db.get_signatures_by_classification(Classification.BLOAT)
        assert len(bloat_sigs) == 2

        aggro_sigs = db.get_signatures_by_classification(Classification.AGGRESSIVE)
        assert len(aggro_sigs) == 1

    def test_get_signatures_by_publisher(self, tmp_path: Path) -> None:
        """Test filtering signatures by publisher."""
        sig_file = tmp_path / "sigs.json"
        sig_data = [
            {"signature_id": "ms-1", "publisher": "Microsoft", "component_name": "App1"},
            {"signature_id": "ms-2", "publisher": "Microsoft", "component_name": "App2"},
            {"signature_id": "other-1", "publisher": "Other", "component_name": "App3"},
        ]
        sig_file.write_text(json.dumps(sig_data))

        db = SignatureDatabase()
        db.load_from_file(sig_file)

        ms_sigs = db.get_signatures_by_publisher("Microsoft")
        assert len(ms_sigs) == 2

        ms_sigs_lower = db.get_signatures_by_publisher("microsoft")
        assert len(ms_sigs_lower) == 2  # Case insensitive

    def test_get_signatures_by_type(self, tmp_path: Path) -> None:
        """Test filtering signatures by component type."""
        sig_file = tmp_path / "sigs.json"
        sig_data = [
            {"signature_id": "prog-1", "component_type": "program"},
            {"signature_id": "svc-1", "component_type": "service"},
            {"signature_id": "svc-2", "component_type": "service"},
        ]
        sig_file.write_text(json.dumps(sig_data))

        db = SignatureDatabase()
        db.load_from_file(sig_file)

        prog_sigs = db.get_signatures_by_type(ComponentType.PROGRAM)
        assert len(prog_sigs) == 1

        svc_sigs = db.get_signatures_by_type(ComponentType.SERVICE)
        assert len(svc_sigs) == 2

    def test_get_related_signatures(self, tmp_path: Path) -> None:
        """Test getting related signatures."""
        sig_file = tmp_path / "sigs.json"
        sig_data = [
            {
                "signature_id": "main-001",
                "component_name": "Main App",
                "related_components": ["helper-001", "helper-002"],
            },
            {"signature_id": "helper-001", "component_name": "Helper 1"},
            {"signature_id": "helper-002", "component_name": "Helper 2"},
        ]
        sig_file.write_text(json.dumps(sig_data))

        db = SignatureDatabase()
        db.load_from_file(sig_file)

        main_sig = db.get_signature("main-001")
        related = db.get_related_signatures(main_sig)

        assert len(related) == 2
        related_ids = [s.signature_id for s in related]
        assert "helper-001" in related_ids
        assert "helper-002" in related_ids

    def test_export_to_file(self, tmp_path: Path) -> None:
        """Test exporting signatures to JSON file."""
        sig_file = tmp_path / "sigs.json"
        sig_data = [
            {
                "signature_id": "export-001",
                "publisher": "Export Test",
                "component_name": "Exportable App",
                "component_type": "program",
                "classification": "OPTIONAL",
                "safe_actions": ["disable"],
            }
        ]
        sig_file.write_text(json.dumps(sig_data))

        db = SignatureDatabase()
        db.load_from_file(sig_file)

        export_file = tmp_path / "exported.json"
        db.export_to_file(export_file)

        assert export_file.exists()
        exported_data = json.loads(export_file.read_text())

        assert "version" in exported_data
        assert "signature_count" in exported_data
        assert exported_data["signature_count"] == 1
        assert len(exported_data["signatures"]) == 1
        assert exported_data["signatures"][0]["signature_id"] == "export-001"

    def test_clear(self, tmp_path: Path) -> None:
        """Test clearing all signatures."""
        sig_file = tmp_path / "sigs.json"
        sig_file.write_text('[{"signature_id": "clear-001"}]')

        db = SignatureDatabase()
        db.load_from_file(sig_file)
        assert db.count == 1

        db.clear()
        assert db.count == 0
        assert len(db.signatures) == 0

    def test_parse_safe_unsafe_actions(self, tmp_path: Path) -> None:
        """Test parsing safe and unsafe action types."""
        sig_file = tmp_path / "sigs.json"
        sig_data = [
            {
                "signature_id": "actions-001",
                "component_name": "Actions Test",
                "safe_actions": ["disable", "contain"],
                "unsafe_actions": ["remove"],
            }
        ]
        sig_file.write_text(json.dumps(sig_data))

        db = SignatureDatabase()
        db.load_from_file(sig_file)

        sig = db.get_signature("actions-001")
        assert ActionType.DISABLE in sig.safe_actions
        assert ActionType.CONTAIN in sig.safe_actions
        assert ActionType.REMOVE in sig.unsafe_actions

    def test_parse_reinstall_behavior(self, tmp_path: Path) -> None:
        """Test parsing reinstall behavior."""
        sig_file = tmp_path / "sigs.json"
        sig_data = [
            {
                "signature_id": "reinstall-001",
                "component_name": "Self Healing App",
                "reinstall_behavior": "self_healing",
            }
        ]
        sig_file.write_text(json.dumps(sig_data))

        db = SignatureDatabase()
        db.load_from_file(sig_file)

        sig = db.get_signature("reinstall-001")
        assert sig.reinstall_behavior == ReinstallBehavior.SELF_HEALING

    def test_invalid_regex_pattern(self, tmp_path: Path) -> None:
        """Test handling of invalid regex patterns."""
        sig_file = tmp_path / "sigs.json"
        sig_data = [
            {
                "signature_id": "bad-regex-001",
                "component_type": "program",
                "match_rules": {"name_pattern": "[invalid(regex"},
                "classification": "BLOAT",
            }
        ]
        sig_file.write_text(json.dumps(sig_data))

        db = SignatureDatabase()
        db.load_from_file(sig_file)

        component = Component(
            component_type=ComponentType.PROGRAM,
            name="test-app",
            display_name="Test App",
            publisher="Test",
        )

        # Should not crash, just return no match
        match = db.match_component(component)
        assert match is None


class TestSignatureMatch:
    """Tests for SignatureMatch dataclass."""

    def test_signature_match_creation(self) -> None:
        """Test creating a SignatureMatch."""
        sig = Signature(
            signature_id="test-001",
            publisher="Test",
            component_name="Test App",
            component_type=ComponentType.PROGRAM,
            match_rules=SignatureMatchRule(),
            classification=Classification.BLOAT,
        )

        match = SignatureMatch(
            signature=sig,
            match_type="name",
            match_score=0.9,
            matched_value="Test App",
        )

        assert match.signature == sig
        assert match.match_type == "name"
        assert match.match_score == 0.9
        assert match.matched_value == "Test App"
