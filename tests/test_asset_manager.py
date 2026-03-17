"""
Tests for Asset Manager module
"""

import pytest
from openclaw_shield.asset_manager import (
    AssetManager,
    AssetDiscovery,
    AssetInventory,
    AssetType,
    AssetRiskLevel,
    Asset
)


class TestAssetDiscovery:
    """Test asset discovery functionality."""

    def test_classify_asset_by_extension(self, sample_config, temp_dir):
        """Test asset classification by file extension."""
        discovery = AssetDiscovery(sample_config)

        # Create test files with different extensions
        (temp_dir / "test.py").touch()
        (temp_dir / "test.js").touch()
        (temp_dir / "config.yaml").touch()
        (temp_dir / "data.json").touch()
        (temp_dir / "readme.md").touch()

        # Test classification
        assert discovery._classify_asset(
            temp_dir / "test.py", None
        ) == AssetType.CODE

        assert discovery._classify_asset(
            temp_dir / "config.yaml", None
        ) == AssetType.CONFIG

        assert discovery._classify_asset(
            temp_dir / "readme.md", None
        ) == AssetType.DOCUMENT

    def test_assess_risk(self, sample_config):
        """Test risk assessment."""
        discovery = AssetDiscovery(sample_config)

        # High risk: password in filename
        from pathlib import Path
        risk = discovery._assess_risk(
            Path("/path/to/password.txt"),
            AssetType.DOCUMENT,
            None
        )
        assert risk == AssetRiskLevel.HIGH

        # Safe: readme in filename
        risk = discovery._assess_risk(
            Path("/path/to/readme.txt"),
            AssetType.DOCUMENT,
            None
        )
        assert risk == AssetRiskLevel.SAFE

    def test_create_fingerprint(self, sample_config, temp_dir):
        """Test asset fingerprint creation."""
        discovery = AssetDiscovery(sample_config)

        # Create test file
        test_file = temp_dir / "fingerprint_test.txt"
        test_file.write_text("test content for fingerprinting")

        stat = test_file.stat()
        fingerprint = discovery._create_fingerprint(test_file, stat)

        assert fingerprint.md5 is not None
        assert fingerprint.sha256 is not None
        assert fingerprint.size == len("test content for fingerprinting")
        assert len(fingerprint.md5) == 32
        assert len(fingerprint.sha256) == 64

    def test_discover_directory(self, sample_config, temp_dir):
        """Test directory discovery."""
        discovery = AssetDiscovery(sample_config)

        # Create test files
        (temp_dir / "test.py").write_text("print('hello')")
        (temp_dir / "config.yaml").write_text("key: value")

        assets = discovery.discover(str(temp_dir), recursive=False)

        assert len(assets) >= 2
        assert any(a.path.endswith('test.py') for a in assets)
        assert any(a.path.endswith('config.yaml') for a in assets)


class TestAssetInventory:
    """Test asset inventory functionality."""

    def test_add_retrieve_asset(self, sample_config):
        """Test adding and retrieving assets."""
        inventory = AssetInventory(sample_config)

        asset = Asset(
            path="/test/file.py",
            asset_type=AssetType.CODE,
            fingerprint=None,
            metadata={},
            risk_level=AssetRiskLevel.SAFE
        )

        inventory.add_asset(asset)

        retrieved = inventory.get_asset("/test/file.py")
        assert retrieved is not None
        assert retrieved.path == "/test/file.py"

    def test_query_assets(self, sample_config):
        """Test asset querying."""
        inventory = AssetInventory(sample_config)

        # Add test assets
        inventory.add_asset(Asset(
            path="/test/file.py",
            asset_type=AssetType.CODE,
            fingerprint=None,
            metadata={},
            risk_level=AssetRiskLevel.HIGH
        ))

        inventory.add_asset(Asset(
            path="/test/file.yaml",
            asset_type=AssetType.CONFIG,
            fingerprint=None,
            metadata={},
            risk_level=AssetRiskLevel.SAFE
        ))

        # Query by type
        code_assets = inventory.query(asset_type="code")
        assert len(code_assets) == 1
        assert code_assets[0].asset_type == AssetType.CODE

        # Query by risk
        high_risk = inventory.query(risk_level="high")
        assert len(high_risk) == 1

    def test_get_statistics(self, sample_config):
        """Test statistics generation."""
        inventory = AssetInventory(sample_config)

        stats = inventory.get_statistics()

        assert 'total_assets' in stats
        assert 'by_type' in stats
        assert 'by_risk' in stats


class TestAssetManager:
    """Test asset manager functionality."""

    def test_scan_directory(self, sample_config, temp_dir):
        """Test scanning a directory."""
        manager = AssetManager(sample_config)

        # Create test files
        (temp_dir / "test.py").write_text("print('test')")

        result = manager.scan_directory(str(temp_dir), recursive=False)

        assert 'assets_discovered' in result
        assert result['assets_discovered'] >= 1

    def test_get_risk_report(self, sample_config, temp_dir):
        """Test risk report generation."""
        manager = AssetManager(sample_config)

        # Create test file with high risk indicator
        (temp_dir / "password.txt").write_text("secret123")

        manager.scan_directory(str(temp_dir), recursive=False)
        report = manager.get_risk_report()

        assert 'total_assets' in report
        assert 'risk_distribution' in report
