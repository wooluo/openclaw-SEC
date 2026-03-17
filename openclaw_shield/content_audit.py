"""
Content Audit Module
Comprehensive content safety auditing for AI interactions.
Detects sensitive data leaks, malicious URLs, policy violations, and more.
"""

import re
import os
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple, Any, Pattern
from dataclasses import dataclass, field, asdict
from enum import Enum
from loguru import logger
from pathlib import Path


class SensitiveDataType(Enum):
    """Types of sensitive data."""
    PII_PERSONAL = "pii_personal"
    PII_CONTACT = "pii_contact"
    PII_FINANCIAL = "pii_financial"
    PII_HEALTH = "pii_health"
    CREDENTIALS = "credentials"
    API_KEYS = "api_keys"
    SECRETS = "secrets"
    COPYRIGHTED = "copyrighted"
    MALICIOUS_URL = "malicious_url"
    POLICY_VIOLATION = "policy_violation"
    TOXIC_CONTENT = "toxic_content"
    UNKNOWN = "unknown"


class AuditSeverity(Enum):
    """Severity levels for audit findings."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AuditFinding:
    """Represents a single audit finding."""
    timestamp: str
    data_type: SensitiveDataType
    severity: AuditSeverity
    confidence: float
    description: str
    evidence: str
    location: Optional[str] = None
    redacted_value: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        d = asdict(self)
        d['data_type'] = self.data_type.value
        d['severity'] = self.severity.value
        return d


@dataclass
class AuditReport:
    """Complete audit report for content."""
    timestamp: str
    content_length: int
    total_findings: int
    findings: List[AuditFinding]
    risk_score: float
    passed: bool
    recommendations: List[str]

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            'timestamp': self.timestamp,
            'content_length': self.content_length,
            'total_findings': self.total_findings,
            'findings': [f.to_dict() for f in self.findings],
            'risk_score': self.risk_score,
            'passed': self.passed,
            'recommendations': self.recommendations
        }


class SensitiveDataPatterns:
    """Patterns for detecting sensitive data."""

    # Email patterns
    EMAIL_PATTERNS = [
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    ]

    # Phone patterns
    PHONE_PATTERNS = [
        r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',  # US format
        r'\b\+?(\d{1,3})?[-.]?\(?\d{3}\)?[-.]?\d{3}[-.]?\d{4}\b',  # International
        r'\b\+?\d{1,3}[-.\s]?\d{3,4}[-.\s]?\d{3,4}[-.\s]?\d{3,6}\b',  # Various
    ]

    # SSN patterns
    SSN_PATTERNS = [
        r'\b\d{3}-\d{2}-\d{4}\b',
        r'\b\d{3}\s\d{2}\s\d{4}\b',
    ]

    # Credit card patterns (Luhn check would be more accurate)
    CREDIT_CARD_PATTERNS = [
        r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9]{2})[0-9]{12})\b',  # Visa, Mastercard
        r'\b(?:3[47][0-9]{13})\b',  # American Express
        r'\b(?:3(?:0[0-5]|[68][0-9])[0-9]{11})\b',  # Diners Club
        r'\b(?:6(?:011|5[0-9]{2})[0-9]{12})\b',  # Discover
    ]

    # IP address patterns
    IP_PATTERNS = [
        r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
        r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',  # IPv6
    ]

    # API key patterns
    API_KEY_PATTERNS = [
        r'\b(sk-|sk-ant-|sk-)(?:[A-Za-z0-9_-]{20,})\b',  # OpenAI, Anthropic
        r'\b(AIza[A-Za-z0-9_-]{35})\b',  # Google API key
        r'\b(AKIA[0-9A-Z]{16})\b',  # AWS access key
        r'\b(ghp_[A-Za-z0-9]{36})\b',  # GitHub personal access token
        r'\b(gho_[A-Za-z0-9]{36})\b',  # GitHub OAuth token
        r'\b(ghu_[A-Za-z0-9]{36})\b',  # GitHub user token
        r'\b(ghs_[A-Za-z0-9]{36})\b',  # GitHub server token
        r'\b(ghr_[A-Za-z0-9]{36})\b',  # GitHub refresh token
        r'\b(xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})\b',  # Slack tokens
        r'\b(xox[p|s|b|o]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24,32})\b',  # Slack alt
        r'\b(PKLive_[a-z0-9]{32,})\b',  # Stripe live
        r'\b(SecretKey\=?)[a-zA-Z0-9+/]{32,}={0,2}\b',  # Generic base64 key
        r'\b(Bearer\s+[A-Za-z0-9_-]{20,})\b',  # Bearer tokens
        r'\b(SessionId\=)?[A-Za-z0-9]{32,}\b',  # Session IDs
    ]

    # Secret/password patterns
    SECRET_PATTERNS = [
        r'(?i)(password|passwd|pwd)\s*[=:]\s*[^\s\'"<>]{4,}',
        r'(?i)(api[_-]?key|apikey|secret[_-]?key)\s*[=:]\s*[^\s\'"<>]{10,}',
        r'(?i)(access[_-]?token|auth[_-]?token|bearer[_-]?token)\s*[=:]\s*[^\s\'"<>]{20,}',
        r'(?i)(refresh[_-]?token|session[_-]?token)\s*[=:]\s*[^\s\'"<>]{20,}',
    ]

    # URL patterns (for malicious URL detection)
    SUSPICIOUS_URL_PATTERNS = [
        r'https?://(?:[a-z0-9-]+\.)?(?:bit\.ly|tinyurl\.com|goo\.gl|t\.co|bit\.do|ow\.ly|is\.gd)\b/i',
        r'https?://(?:[a-z0-9-]+\.)?(?:pastebin\.com|hastebin\.com|justpaste\.it)\b/i',
        r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?(?:/[^\s]*)?',  # IP-based URLs
        r'https?://(?:[a-z0-9-]+\.)?(?:\.xyz|\.top|\.zip|\.tk|\.ml|\.ga|\.cf|\.gq)(?::\d+)?\b/i',
    ]


class ToxicContentDetector:
    """Detects toxic/harmful content."""

    # Toxic content categories
    TOXIC_PATTERNS = {
        'hate_speech': [
            r'\b(hate|kill|murder|destroy|eliminate)\s+(all|every)\s+(?:[a-z]+s?)\b',
            r'\b(deserving\s+(of|to\s+be))\s+(death|rape|violence)\b',
            r'\bgo\s+back\s+to\s+(?:your\s+)?country\b',
        ],
        'violence': [
            r'\b(i\s+will\s+(?:kill|hurt|attack|harm|murder))\b',
            r'\b(going\s+to\s+(?:shoot|stab|bomb|kill))\b',
            r'\b(do\s+you\s+want\s+to\s+die)\b',
        ],
        'self_harm': [
            r'\b(how\s+to\s+(?:kill|commit\s+suicide|harm)\s+myself)\b',
            r'\b(want\s+to\s+die|kill\s+myself)\b',
            r'\b(suicidal|suicide\s+methods)\b',
        ],
        'sexual': [
            r'\b(rape|sexual\s+assault|non[- ]?consensual)\b',
            r'\b(inappropriate|unwanted)\s+(?:sexual\s+)?(contact|touch)\b',
        ],
        'illegal_acts': [
            r'\b(how\s+to\s+(?:make\s+)?(?:a\s+)?(?:bomb|drug|meth\s+?:?))\b',
            r'\b(buy\s+illegal\s+(?:drugs|weapons|guns))\b',
            r'\b(how\s+to\s+(?:steal|hack|rob))\b',
        ],
    }


class ContentAuditor:
    """
    Main content auditor for comprehensive safety checks.
    """

    def __init__(self, config):
        """Initialize the content auditor."""
        self.config = config
        self._enabled_checks = self._load_enabled_checks(config)
        self._custom_patterns: Dict[str, List[str]] = {}
        self._whitelist_patterns: List[Pattern] = []

        # Statistics
        self._audits_performed = 0
        self._findings_detected = 0

    def _load_enabled_checks(self, config) -> Set[str]:
        """Load enabled audit checks from config."""
        default_checks = {
            'pii_personal', 'pii_contact', 'api_keys', 'credentials',
            'malicious_url', 'toxic_content'
        }
        return set(config.get('content_audit.enabled_checks', list(default_checks)))

    def audit(self, content: str, context: Dict = None) -> AuditReport:
        """
        Audit content for sensitive data and policy violations.

        Args:
            content: The content to audit
            context: Additional context (source, user, etc.)

        Returns:
            Complete audit report
        """
        self._audits_performed += 1
        findings = []

        logger.debug(f"Auditing content of length {len(content)}")

        # Apply whitelist first
        if self._is_whitelisted(content):
            return AuditReport(
                timestamp=datetime.now().isoformat(),
                content_length=len(content),
                total_findings=0,
                findings=[],
                risk_score=0.0,
                passed=True,
                recommendations=[]
            )

        # Check for PII (if enabled)
        if 'pii_personal' in self._enabled_checks:
            findings.extend(self._check_pii_personal(content))

        if 'pii_contact' in self._enabled_checks:
            findings.extend(self._check_pii_contact(content))

        if 'pii_financial' in self._enabled_checks:
            findings.extend(self._check_pii_financial(content))

        # Check for credentials (if enabled)
        if 'api_keys' in self._enabled_checks:
            findings.extend(self._check_api_keys(content))

        if 'credentials' in self._enabled_checks:
            findings.extend(self._check_credentials(content))

        # Check for malicious URLs (if enabled)
        if 'malicious_url' in self._enabled_checks:
            findings.extend(self._check_malicious_urls(content))

        # Check for toxic content (if enabled)
        if 'toxic_content' in self._enabled_checks:
            findings.extend(self._check_toxic_content(content))

        # Apply custom patterns
        findings.extend(self._check_custom_patterns(content))

        # Calculate risk score
        risk_score = self._calculate_risk_score(findings)

        # Generate recommendations
        recommendations = self._generate_recommendations(findings)

        # Determine pass/fail
        passed = risk_score < self.config.get('content_audit.fail_threshold', 0.7)

        self._findings_detected += len(findings)

        return AuditReport(
            timestamp=datetime.now().isoformat(),
            content_length=len(content),
            total_findings=len(findings),
            findings=findings,
            risk_score=risk_score,
            passed=passed,
            recommendations=recommendations
        )

    def _is_whitelisted(self, content: str) -> bool:
        """Check if content matches whitelist patterns."""
        return any(pattern.search(content) for pattern in self._whitelist_patterns)

    def _check_pii_personal(self, content: str) -> List[AuditFinding]:
        """Check for personally identifiable information."""
        findings = []

        # Check SSN
        for pattern in SensitiveDataPatterns.SSN_PATTERNS:
            for match in re.finditer(pattern, content):
                findings.append(AuditFinding(
                    timestamp=datetime.now().isoformat(),
                    data_type=SensitiveDataType.PII_PERSONAL,
                    severity=AuditSeverity.HIGH,
                    confidence=0.9,
                    description="Social Security Number detected",
                    evidence=self._redact(match.group(), keep_chars=4),
                    location=f"offset:{match.start()}",
                    metadata={'pattern': 'SSN'}
                ))

        return findings

    def _check_pii_contact(self, content: str) -> List[AuditFinding]:
        """Check for contact information (email, phone)."""
        findings = []

        # Check email
        for pattern in SensitiveDataPatterns.EMAIL_PATTERNS:
            for match in re.finditer(pattern, content):
                findings.append(AuditFinding(
                    timestamp=datetime.now().isoformat(),
                    data_type=SensitiveDataType.PII_CONTACT,
                    severity=AuditSeverity.MEDIUM,
                    confidence=0.95,
                    description="Email address detected",
                    evidence=self._redact_email(match.group()),
                    location=f"offset:{match.start()}",
                    metadata={'pattern': 'EMAIL'}
                ))

        # Check phone
        for pattern in SensitiveDataPatterns.PHONE_PATTERNS:
            for match in re.finditer(pattern, content):
                findings.append(AuditFinding(
                    timestamp=datetime.now().isoformat(),
                    data_type=SensitiveDataType.PII_CONTACT,
                    severity=AuditSeverity.LOW,
                    confidence=0.7,
                    description="Phone number detected",
                    evidence=self._redact(match.group(), keep_chars=4),
                    location=f"offset:{match.start()}",
                    metadata={'pattern': 'PHONE'}
                ))

        return findings

    def _check_pii_financial(self, content: str) -> List[AuditFinding]:
        """Check for financial information."""
        findings = []

        # Check credit cards
        for pattern in SensitiveDataPatterns.CREDIT_CARD_PATTERNS:
            for match in re.finditer(pattern, content):
                # Could add Luhn check here for better accuracy
                findings.append(AuditFinding(
                    timestamp=datetime.now().isoformat(),
                    data_type=SensitiveDataType.PII_FINANCIAL,
                    severity=AuditSeverity.CRITICAL,
                    confidence=0.85,
                    description="Possible credit card number detected",
                    evidence=self._redact(match.group(), keep_chars=4),
                    location=f"offset:{match.start()}",
                    metadata={'pattern': 'CREDIT_CARD'}
                ))

        return findings

    def _check_api_keys(self, content: str) -> List[AuditFinding]:
        """Check for API keys."""
        findings = []

        for pattern in SensitiveDataPatterns.API_KEY_PATTERNS:
            for match in re.finditer(pattern, content):
                findings.append(AuditFinding(
                    timestamp=datetime.now().isoformat(),
                    data_type=SensitiveDataType.API_KEYS,
                    severity=AuditSeverity.CRITICAL,
                    confidence=0.9,
                    description="API key detected",
                    evidence=self._redact(match.group(), keep_chars=6),
                    location=f"offset:{match.start()}",
                    metadata={'pattern': 'API_KEY'}
                ))

        return findings

    def _check_credentials(self, content: str) -> List[AuditFinding]:
        """Check for credentials and secrets."""
        findings = []

        for pattern in SensitiveDataPatterns.SECRET_PATTERNS:
            for match in re.finditer(pattern, content):
                findings.append(AuditFinding(
                    timestamp=datetime.now().isoformat(),
                    data_type=SensitiveDataType.CREDENTIALS,
                    severity=AuditSeverity.HIGH,
                    confidence=0.75,
                    description="Possible credential detected",
                    evidence=self._redact(match.group(), keep_chars=8),
                    location=f"offset:{match.start()}",
                    metadata={'pattern': 'CREDENTIAL'}
                ))

        return findings

    def _check_malicious_urls(self, content: str) -> List[AuditFinding]:
        """Check for malicious URLs."""
        findings = []

        for pattern in SensitiveDataPatterns.SUSPICIOUS_URL_PATTERNS:
            for match in re.finditer(pattern, content):
                findings.append(AuditFinding(
                    timestamp=datetime.now().isoformat(),
                    data_type=SensitiveDataType.MALICIOUS_URL,
                    severity=AuditSeverity.HIGH,
                    confidence=0.7,
                    description="Suspicious URL detected",
                    evidence=match.group()[:50],
                    location=f"offset:{match.start()}",
                    metadata={'pattern': 'SUSPICIOUS_URL'}
                ))

        return findings

    def _check_toxic_content(self, content: str) -> List[AuditFinding]:
        """Check for toxic/harmful content."""
        findings = []
        content_lower = content.lower()

        for category, patterns in ToxicContentDetector.TOXIC_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, content_lower):
                    severity = AuditSeverity.HIGH if category in ['hate_speech', 'violence', 'self_harm'] else AuditSeverity.MEDIUM

                    findings.append(AuditFinding(
                        timestamp=datetime.now().isoformat(),
                        data_type=SensitiveDataType.TOXIC_CONTENT,
                        severity=severity,
                        confidence=0.7,
                        description=f"Toxic content detected: {category}",
                        evidence=f"Pattern matched: {category}",
                        metadata={'category': category}
                    ))
                    break

        return findings

    def _check_custom_patterns(self, content: str) -> List[AuditFinding]:
        """Check custom user-defined patterns."""
        findings = []

        for name, patterns in self._custom_patterns.items():
            for pattern in patterns:
                if isinstance(pattern, str):
                    for match in re.finditer(pattern, content, re.IGNORECASE):
                        findings.append(AuditFinding(
                            timestamp=datetime.now().isoformat(),
                            data_type=SensitiveDataType.UNKNOWN,
                            severity=AuditSeverity.MEDIUM,
                            confidence=0.8,
                            description=f"Custom pattern match: {name}",
                            evidence=match.group()[:50],
                            metadata={'custom_pattern': name}
                        ))

        return findings

    def _calculate_risk_score(self, findings: List[AuditFinding]) -> float:
        """Calculate overall risk score from findings."""
        if not findings:
            return 0.0

        severity_weights = {
            AuditSeverity.CRITICAL: 0.3,
            AuditSeverity.HIGH: 0.2,
            AuditSeverity.MEDIUM: 0.1,
            AuditSeverity.LOW: 0.05,
            AuditSeverity.INFO: 0.01,
        }

        total_score = 0.0
        for finding in findings:
            weight = severity_weights.get(finding.severity, 0.1)
            total_score += weight * finding.confidence

        return min(total_score, 1.0)

    def _generate_recommendations(self, findings: List[AuditFinding]) -> List[str]:
        """Generate recommendations based on findings."""
        recommendations = []

        # Count by type
        type_counts = {}
        for finding in findings:
            dtype = finding.data_type.value
            type_counts[dtype] = type_counts.get(dtype, 0) + 1

        # Generate specific recommendations
        if SensitiveDataType.API_KEYS.value in type_counts:
            recommendations.append(
                f"Found {type_counts[SensitiveDataType.API_KEYS.value]} API key(s). "
                "Remove or redact immediately."
            )

        if SensitiveDataType.CREDENTIALS.value in type_counts:
            recommendations.append(
                f"Found {type_counts[SensitiveDataType.CREDENTIALS.value]} credential(s). "
                "Consider using environment variables."
            )

        if SensitiveDataType.PII_PERSONAL.value in type_counts:
            recommendations.append(
                "Personal information detected. Ensure proper handling per privacy policies."
            )

        if SensitiveDataType.TOXIC_CONTENT.value in type_counts:
            recommendations.append(
                "Toxic content detected. Review and moderate as needed."
            )

        if SensitiveDataType.MALICIOUS_URL.value in type_counts:
            recommendations.append(
                "Suspicious URLs detected. Verify link safety before allowing."
            )

        return recommendations

    def _redact(self, value: str, keep_chars: int = 4, mask_char: str = '*') -> str:
        """Redact a value keeping only some characters."""
        if len(value) <= keep_chars:
            return mask_char * len(value)
        return value[:keep_chars//2] + mask_char * (len(value) - keep_chars) + value[-keep_chars//2:]

    def _redact_email(self, email: str) -> str:
        """Redact email address."""
        parts = email.split('@')
        if len(parts) != 2:
            return self._redact(email, 4)
        local, domain = parts
        return local[:2] + '***@' + domain

    def add_custom_pattern(self, name: str, patterns: List[str]):
        """Add custom detection patterns."""
        self._custom_patterns[name] = patterns
        logger.info(f"Added custom pattern: {name}")

    def add_whitelist_pattern(self, pattern: str):
        """Add a whitelist pattern."""
        self._whitelist_patterns.append(re.compile(pattern, re.IGNORECASE))
        logger.info(f"Added whitelist pattern: {pattern}")

    def get_statistics(self) -> Dict:
        """Get auditor statistics."""
        return {
            'audits_performed': self._audits_performed,
            'findings_detected': self._findings_detected,
            'enabled_checks': list(self._enabled_checks),
            'custom_patterns': list(self._custom_patterns.keys()),
            'whitelist_patterns': len(self._whitelist_patterns)
        }


class FileContentAuditor(ContentAuditor):
    """Content auditor specifically for file auditing."""

    def __init__(self, config):
        """Initialize file content auditor."""
        super().__init__(config)
        self._max_file_size = config.get('content_audit.max_file_size', 10 * 1024 * 1024)  # 10MB
        self._binary_extensions = set(config.get('content_audit.binary_extensions', [
            '.exe', '.dll', '.so', '.dylib', '.bin', '.zip', '.tar', '.gz'
        ]))

    def audit_file(self, file_path: str) -> AuditReport:
        """
        Audit a file for sensitive content.

        Args:
            file_path: Path to the file

        Returns:
            Audit report
        """
        path = Path(file_path)

        if not path.exists():
            return AuditReport(
                timestamp=datetime.now().isoformat(),
                content_length=0,
                total_findings=0,
                findings=[],
                risk_score=0.0,
                passed=False,
                recommendations=[f"File not found: {file_path}"]
            )

        # Check file size
        file_size = path.stat().st_size
        if file_size > self._max_file_size:
            return AuditReport(
                timestamp=datetime.now().isoformat(),
                content_length=file_size,
                total_findings=0,
                findings=[],
                risk_score=0.0,
                passed=False,
                recommendations=[f"File too large for auditing ({file_size} bytes)"]
            )

        # Check if binary
        if path.suffix.lower() in self._binary_extensions:
            return AuditReport(
                timestamp=datetime.now().isoformat(),
                content_length=file_size,
                total_findings=0,
                findings=[],
                risk_score=0.5,
                passed=False,
                recommendations=["Binary file - cannot audit content"]
            )

        # Read and audit content
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            return self.audit(content, {'source_file': str(path)})

        except Exception as e:
            return AuditReport(
                timestamp=datetime.now().isoformat(),
                content_length=0,
                total_findings=0,
                findings=[],
                risk_score=0.0,
                passed=False,
                recommendations=[f"Error reading file: {e}"]
            )

    def audit_directory(self, directory: str, recursive: bool = True) -> Dict[str, AuditReport]:
        """
        Audit all files in a directory.

        Args:
            directory: Path to directory
            recursive: Whether to scan recursively

        Returns:
            Dictionary mapping file paths to audit reports
        """
        path = Path(directory)
        results = {}

        if not path.exists():
            return results

        if recursive:
            files = path.rglob('*')
        else:
            files = path.glob('*')

        for file in files:
            if file.is_file():
                results[str(file)] = self.audit_file(str(file))

        return results
