"""
Tests for Content Audit module
"""

import pytest
from openclaw_shield.content_audit import (
    ContentAuditor,
    FileContentAuditor,
    SensitiveDataType,
    AuditSeverity
)


class TestContentAuditor:
    """Test content auditor functionality."""

    def test_audit_safe_content(self, sample_config):
        """Test auditing safe content."""
        auditor = ContentAuditor(sample_config)

        content = "This is a safe message with no sensitive information."
        report = auditor.audit(content)

        assert report.passed is True
        assert report.total_findings == 0
        assert report.risk_score < 0.5

    def test_audit_email_detection(self, sample_config):
        """Test email address detection."""
        auditor = ContentAuditor(sample_config)

        content = "Contact us at support@example.com for help"
        report = auditor.audit(content)

        assert len(report.findings) > 0
        assert any(f.data_type == SensitiveDataType.PII_CONTACT for f in report.findings)

    def test_audit_api_key_detection(self, sample_config):
        """Test API key detection."""
        auditor = ContentAuditor(sample_config)

        content = "API_KEY=sk-1234567890abcdefghijklmnop"
        report = auditor.audit(content)

        assert len(report.findings) > 0
        assert any(f.data_type == SensitiveDataType.API_KEYS for f in report.findings)

    def test_audit_ssn_detection(self, sample_config):
        """Test SSN detection."""
        auditor = ContentAuditor(sample_config)

        content = "Social Security Number: 123-45-6789"
        report = auditor.audit(content)

        assert len(report.findings) > 0

    def test_audit_malicious_url(self, sample_config):
        """Test malicious URL detection."""
        auditor = ContentAuditor(sample_config)

        content = "Visit this link: bit.ly/malicious_link"
        report = auditor.audit(content)

        assert len(report.findings) > 0
        assert any(f.data_type == SensitiveDataType.MALICIOUS_URL for f in report.findings)

    def test_audit_credit_card(self, sample_config):
        """Test credit card detection."""
        auditor = ContentAuditor(sample_config)

        content = "Card number: 4532015112830366"
        report = auditor.audit(content)

        assert len(report.findings) > 0

    def test_audit_toxic_content(self, sample_config):
        """Test toxic content detection."""
        auditor = ContentAuditor(sample_config)

        content = "I will kill everyone I see"
        report = auditor.audit(content)

        # Should detect toxic content
        assert len(report.findings) > 0

    def test_custom_patterns(self, sample_config):
        """Test custom pattern detection."""
        auditor = ContentAuditor(sample_config)

        # Add custom pattern
        auditor.add_custom_pattern("secret_word", [r"\bSECRET123\b"])

        content = "The secret code is SECRET123"
        report = auditor.audit(content)

        assert len(report.findings) > 0

    def test_whitelist(self, sample_config):
        """Test whitelist functionality."""
        auditor = ContentAuditor(sample_config)

        # Add pattern to whitelist
        auditor.add_whitelist_pattern(r"@example\.com")

        content = "Email: test@example.com"
        report = auditor.audit(content)

        # Should pass due to whitelist
        assert report.passed is True


class TestFileContentAuditor:
    """Test file content auditor functionality."""

    def test_audit_file(self, sample_config, temp_dir):
        """Test file auditing."""
        auditor = FileContentAuditor(sample_config)

        # Create test file with API key
        test_file = temp_dir / "config.py"
        test_file.write_text("API_KEY = 'sk-1234567890abcdefghijklmnop'")

        report = auditor.audit_file(str(test_file))

        assert len(report.findings) > 0
        assert report.content_length > 0

    def test_audit_directory(self, sample_config, temp_dir):
        """Test directory auditing."""
        auditor = FileContentAuditor(sample_config)

        # Create test files
        (temp_dir / "safe.txt").write_text("This is safe content")
        (temp_dir / "secret.txt").write_text("Password: secret123")

        results = auditor.audit_directory(str(temp_dir), recursive=False)

        assert len(results) >= 2
        assert any(len(r.findings) > 0 for r in results.values())

    def test_audit_binary_file(self, sample_config, temp_dir):
        """Test binary file handling."""
        auditor = FileContentAuditor(sample_config)

        # Create a small "binary" file
        binary_file = temp_dir / "test.bin"
        binary_file.write_bytes(b'\x00\x01\x02\x03\xFF\xFE\xFD')

        report = auditor.audit_file(str(binary_file))

        # Should handle gracefully
        assert report is not None

    def test_audit_nonexistent_file(self, sample_config):
        """Test auditing non-existent file."""
        auditor = FileContentAuditor(sample_config)

        report = auditor.audit_file("/nonexistent/file.txt")

        assert report.passed is False
        assert len(report.recommendations) > 0
