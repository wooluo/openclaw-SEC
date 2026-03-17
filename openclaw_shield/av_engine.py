"""
Anti-Virus Engine Module
Malicious sample detection using YARA rules, static binary analysis,
behavioral signatures, and quarantine management.
"""

import os
import hashlib
import json
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple, Any, BinaryIO
from dataclasses import dataclass, field, asdict
from enum import Enum
from loguru import logger
from pathlib import Path
import struct


class ThreatCategory(Enum):
    """Categories of threats."""
    VIRUS = "virus"
    TROJAN = "trojan"
    WORM = "worm"
    RANSOMWARE = "ransomware"
    SPYWARE = "spyware"
    ADWARE = "adware"
    ROOTKIT = "rootkit"
    BACKDOOR = "backdoor"
    EXPLOIT = "exploit"
    TOOL = "tool"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"


class ScanAction(Enum):
    """Actions to take on threat detection."""
    QUARANTINE = "quarantine"
    DELETE = "delete"
    DISINFECT = "disinfect"
    IGNORE = "ignore"
    ALERT_ONLY = "alert_only"


@dataclass
class ThreatInfo:
    """Information about a detected threat."""
    name: str
    category: ThreatCategory
    severity: str  # critical, high, medium, low
    description: str
    file_hash: str
    file_path: str
    detected_at: str
    scanner: str
    confidence: float
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        d = asdict(self)
        d['category'] = self.category.value
        return d


@dataclass
class ScanResult:
    """Result of a file scan."""
    file_path: str
    scanned_at: str
    is_clean: bool
    threats: List[ThreatInfo]
    scan_duration_ms: int
    file_size: int
    hashes: Dict[str, str]
    scan_engines: List[str]

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            'file_path': self.file_path,
            'scanned_at': self.scanned_at,
            'is_clean': self.is_clean,
            'threats': [t.to_dict() for t in self.threats],
            'scan_duration_ms': self.scan_duration_ms,
            'file_size': self.file_size,
            'hashes': self.hashes,
            'scan_engines': self.scan_engines
        }


class YARAScanner:
    """YARA rule-based scanner."""

    def __init__(self, config):
        """Initialize YARA scanner."""
        self.config = config
        self._rules_path = config.get('av_engine.yara_rules_path', './config/yara_rules')
        self._rules = []
        self._compiled_rules = None
        self._load_rules()

    def _load_rules(self):
        """Load YARA rules from directory."""
        try:
            import yara
        except ImportError:
            logger.warning("YARA module not available, YARA scanning disabled")
            return

        rules_dir = Path(self._rules_path)
        if not rules_dir.exists():
            logger.warning(f"YARA rules directory not found: {self._rules_path}")
            return

        # Load .yar and .yara files
        rule_files = list(rules_dir.glob('*.yar')) + list(rules_dir.glob('*.yara'))

        if not rule_files:
            logger.warning(f"No YARA rules found in {self._rules_path}")
            return

        try:
            # Compile rules
            filepaths = {str(f): f.name for f in rule_files}
            self._compiled_rules = yara.compile(filepaths=filepaths)
            logger.info(f"Loaded {len(rule_files)} YARA rule files")
        except Exception as e:
            logger.error(f"Failed to load YARA rules: {e}")

    def scan(self, file_path: str) -> List[ThreatInfo]:
        """Scan file with YARA rules."""
        if self._compiled_rules is None:
            return []

        threats = []
        path = Path(file_path)

        if not path.exists():
            logger.warning(f"File not found for YARA scan: {file_path}")
            return []

        try:
            # Get file hash
            file_hash = self._calculate_hash(file_path)

            # Run YARA scan
            matches = self._compiled_rules.match(str(file_path))

            for match in matches:
                # Determine severity based on rule tags
                severity = 'medium'
                if 'critical' in match.tags:
                    severity = 'critical'
                elif 'high' in match.tags:
                    severity = 'high'
                elif 'low' in match.tags:
                    severity = 'low'

                # Map to threat category
                category = self._map_category_from_tags(match.tags)

                threats.append(ThreatInfo(
                    name=match.rule,
                    category=category,
                    severity=severity,
                    description=f"YARA rule match: {match.rule}",
                    file_hash=file_hash,
                    file_path=file_path,
                    detected_at=datetime.now().isoformat(),
                    scanner="yara",
                    confidence=0.9,
                    metadata={
                        'rule': match.rule,
                        'tags': match.tags,
                        'strings': len(match.strings),
                        'meta': match.meta
                    }
                ))

        except Exception as e:
            logger.error(f"YARA scan error: {e}")

        return threats

    def _calculate_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file."""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _map_category_from_tags(self, tags: Set[str]) -> ThreatCategory:
        """Map YARA tags to threat categories."""
        tag_map = {
            'trojan': ThreatCategory.TROJAN,
            'ransomware': ThreatCategory.RANSOMWARE,
            'malware': ThreatCategory.UNKNOWN,
            'backdoor': ThreatCategory.BACKDOOR,
            'exploit': ThreatCategory.EXPLOIT,
            'worm': ThreatCategory.WORM,
        }

        for tag in tags:
            if tag.lower() in tag_map:
                return tag_map[tag.lower()]

        return ThreatCategory.SUSPICIOUS


class StaticBinaryAnalyzer:
    """Static binary analysis for threat detection."""

    # Suspicious strings that may indicate malware
    SUSPICIOUS_STRINGS = {
        # Network-related
        b'socket',
        b'connect',
        b'bind',
        b'listen',

        # Process manipulation
        b'CreateProcess',
        b'VirtualAlloc',
        b'WriteProcessMemory',
        b'CreateRemoteThread',

        # Registry manipulation
        b'RegOpenKey',
        b'RegSetValue',
        b'RegCreateKey',

        # File manipulation
        b'DeleteFile',
        b'CreateFile',
        b'WriteFile',

        # URL download
        b'URLDownloadToFile',
        b'InternetOpen',
        b'HttpSendRequest',

        # Shell access
        b'cmd.exe',
        b'powershell',
        b'sh',
        b'/bin/sh',

        # Persistence
        b'AutoRun',
        b'Startup',
        b'Services',

        # Crypto/Ransomware
        b'encrypt',
        b'decrypt',
        b'ransom',
        b'bitcoin',
        b'wallet',
    }

    # Known malicious section names
    SUSPICIOUS_SECTIONS = {
        b'.upx', b'.packed', b'.themida', b'.vmp',
        b'.force', b'.winlice', b'.nig0',
    }

    def __init__(self, config):
        """Initialize static analyzer."""
        self.config = config
        self._suspicious_threshold = config.get('av_engine.suspicious_threshold', 10)

    def analyze(self, file_path: str) -> List[ThreatInfo]:
        """Analyze binary file statically."""
        threats = []
        path = Path(file_path)

        if not path.exists():
            return threats

        try:
            with open(path, 'rb') as f:
                data = f.read()

            # Check file type
            is_pe, is_elf, is_macho = self._detect_executable_type(data)

            if not any([is_pe, is_elf, is_macho]):
                # Not an executable, skip
                return threats

            # Calculate hash
            file_hash = hashlib.sha256(data).hexdigest()

            # Scan for suspicious strings
            suspicious_count = 0
            found_strings = []

            for string in self.SUSPICIOUS_STRINGS:
                if string in data:
                    suspicious_count += 1
                    found_strings.append(string.decode('utf-8', errors='ignore'))

            if suspicious_count >= self._suspicious_threshold:
                threats.append(ThreatInfo(
                    name="Suspicious Binary",
                    category=ThreatCategory.SUSPICIOUS,
                    severity='high',
                    description=f"Binary contains {suspicious_count} suspicious strings",
                    file_hash=file_hash,
                    file_path=file_path,
                    detected_at=datetime.now().isoformat(),
                    scanner="static_analyzer",
                    confidence=0.7,
                    metadata={
                        'suspicious_strings': found_strings,
                        'string_count': suspicious_count
                    }
                ))

            # Analyze PE structure if applicable
            if is_pe:
                pe_threats = self._analyze_pe(data, file_path, file_hash)
                threats.extend(pe_threats)

        except Exception as e:
            logger.error(f"Static analysis error: {e}")

        return threats

    def _detect_executable_type(self, data: bytes) -> Tuple[bool, bool, bool]:
        """Detect executable type from header."""
        is_pe = data[:2] == b'MZ'
        is_elf = data[:4] == b'\x7fELF'
        is_macho = data[:4] in (b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe',
                               b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe')

        return is_pe, is_elf, is_macho

    def _analyze_pe(self, data: bytes, file_path: str, file_hash: str) -> List[ThreatInfo]:
        """Analyze PE executable structure."""
        threats = []

        try:
            # Parse PE header
            mz_offset = struct.unpack('<I', data[0x3C:0x40])[0]
            pe_sig = data[mz_offset:mz_offset + 4]

            if pe_sig != b'PE\x00\x00':
                return threats

            # Check for packed executables
            # High entropy indicates possible packing
            import math

            # Check entropy of sections
            section_offset = mz_offset + 24  # COFF header offset
            num_sections = struct.unpack('<H', data[section_offset + 2:section_offset + 4])[0]

            section_table_offset = section_offset + 20
            sections = []

            for i in range(min(num_sections, 10)):  # Limit to 10 sections
                section_name = data[section_table_offset:section_table_offset + 8]
                section_name = section_name.split(b'\x00')[0]

                # Check for suspicious section names
                if section_name in self.SUSPICIOUS_SECTIONS:
                    threats.append(ThreatInfo(
                        name="Packed Executable",
                        category=ThreatCategory.SUSPICIOUS,
                        severity='medium',
                        description=f"Suspicious section name: {section_name.decode('utf-8', errors='ignore')}",
                        file_hash=file_hash,
                        file_path=file_path,
                        detected_at=datetime.now().isoformat(),
                        scanner="static_analyzer",
                        confidence=0.8,
                        metadata={'section': section_name.decode('utf-8', errors='ignore')}
                    ))

                section_table_offset += 40  # Section entry size

        except Exception as e:
            logger.debug(f"PE analysis error: {e}")

        return threats


class BehavioralSignatures:
    """Behavioral signature detection."""

    # Behavioral indicators of malware
    INDICATORS = {
        'file_activity': {
            'creates_system_file': ['C:\\Windows\\System32\\*', '/etc/', '/usr/bin/'],
            'deletes_system_file': ['rm -rf /', 'del /F /Q C:\\*'],
            'modifies_critical_files': ['/etc/passwd', '/etc/shadow', 'C:\\Windows\\System32\\drivers\\etc\\hosts'],
        },
        'process_activity': {
            'injects_process': ['WriteProcessMemory', 'CreateRemoteThread', 'ptrace'],
            'hides_process': ['fork + setsid', 'CreateProcess with CREATE_NO_WINDOW'],
            'elevates_privileges': ['sudo', 'su', 'UAC bypass', 'token impersonation'],
        },
        'network_activity': {
            'connects_to_c2': [r'.*\.onion', r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+'],
            'dns_tunneling': ['dns Exfiltrator', 'iodine'],
        },
        'persistence': {
            'adds_autorun': ['HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', '/etc/init.d/', 'systemd service'],
            'creates_scheduled_task': ['schtasks', 'crontab', 'launchd'],
        },
    }

    def __init__(self, config):
        """Initialize behavioral signatures."""
        self.config = config

    def check_behavior(self, behavior: Dict) -> List[ThreatInfo]:
        """
        Check behavior against threat signatures.

        Args:
            behavior: Dictionary describing observed behavior

        Returns:
            List of detected threats
        """
        threats = []
        action_type = behavior.get('type', '')
        details = behavior.get('details', {})

        # Check file activity
        if action_type == 'file_operation':
            threats.extend(self._check_file_behavior(details))

        # Check process activity
        elif action_type == 'process_operation':
            threats.extend(self._check_process_behavior(details))

        # Check network activity
        elif action_type == 'network_operation':
            threats.extend(self._check_network_behavior(details))

        return threats

    def _check_file_behavior(self, details: Dict) -> List[ThreatInfo]:
        """Check file-related behavior."""
        threats = []
        file_path = details.get('path', '')
        operation = details.get('operation', '')

        # Check for system file modification
        for pattern in self.INDICATORS['file_activity']['modifies_critical_files']:
            if pattern in file_path and operation in ['write', 'delete']:
                threats.append(ThreatInfo(
                    name="System File Modification",
                    category=ThreatCategory.TROJAN,
                    severity='high',
                    description=f"Attempt to {operation} critical system file: {file_path}",
                    file_hash="",
                    file_path=file_path,
                    detected_at=datetime.now().isoformat(),
                    scanner="behavioral",
                    confidence=0.8,
                    metadata={'operation': operation, 'pattern': pattern}
                ))

        return threats

    def _check_process_behavior(self, details: Dict) -> List[ThreatInfo]:
        """Check process-related behavior."""
        threats = []
        command = details.get('command', '')

        # Check for privilege escalation
        for indicator in self.INDICATORS['process_activity']['elevates_privileges']:
            if indicator.lower() in command.lower():
                threats.append(ThreatInfo(
                    name="Privilege Escalation",
                    category=ThreatCategory.ROOTKIT,
                    severity='critical',
                    description=f"Privilege escalation attempt detected: {command[:100]}",
                    file_hash="",
                    file_path=details.get('executable', ''),
                    detected_at=datetime.now().isoformat(),
                    scanner="behavioral",
                    confidence=0.75,
                    metadata={'command': command, 'indicator': indicator}
                ))

        return threats

    def _check_network_behavior(self, details: Dict) -> List[ThreatInfo]:
        """Check network-related behavior."""
        threats = []
        remote_host = details.get('remote_host', '')
        remote_port = details.get('remote_port', 0)

        # Check for suspicious ports
        if remote_port in [4444, 5555, 6666, 31337]:
            threats.append(ThreatInfo(
                name="Suspicious Network Activity",
                category=ThreatCategory.BACKDOOR,
                severity='high',
                description=f"Connection to suspicious port: {remote_port}",
                file_hash="",
                file_path="",
                detected_at=datetime.now().isoformat(),
                scanner="behavioral",
                confidence=0.85,
                metadata={'host': remote_host, 'port': remote_port}
            ))

        return threats


class QuarantineManager:
    """Manages quarantined files."""

    def __init__(self, config):
        """Initialize quarantine manager."""
        self.config = config
        self._quarantine_dir = Path(config.get('av_engine.quarantine_dir', './quarantine'))
        self._quarantine_dir.mkdir(parents=True, exist_ok=True)
        self._quarantine_db: Dict[str, Dict] = {}
        self._load_database()

    def quarantine(self, file_path: str, threat_info: ThreatInfo) -> bool:
        """
        Move a file to quarantine.

        Args:
            file_path: Path to file to quarantine
            threat_info: Threat information

        Returns:
            True if successful
        """
        source = Path(file_path)
        if not source.exists():
            logger.error(f"File not found for quarantine: {file_path}")
            return False

        # Generate quarantine filename
        import uuid
        quarantine_id = str(uuid.uuid4())
        quarantine_filename = f"{quarantine_id}_{source.name}"
        quarantine_path = self._quarantine_dir / quarantine_filename

        try:
            # Move file to quarantine
            import shutil
            shutil.move(str(source), str(quarantine_path))

            # Set restrictive permissions
            os.chmod(quarantine_path, 0o400)

            # Record in database
            self._quarantine_db[quarantine_id] = {
                'original_path': str(source.absolute()),
                'quarantine_path': str(quarantine_path),
                'threat': threat_info.to_dict(),
                'quarantined_at': datetime.now().isoformat(),
                'file_size': quarantine_path.stat().st_size
            }

            self._save_database()

            logger.info(f"Quarantined: {file_path} -> {quarantine_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to quarantine {file_path}: {e}")
            return False

    def restore(self, quarantine_id: str, restore_path: str = None) -> bool:
        """
        Restore a quarantined file.

        Args:
            quarantine_id: Quarantine ID
            restore_path: Optional restore path (defaults to original)

        Returns:
            True if successful
        """
        if quarantine_id not in self._quarantine_db:
            logger.error(f"Quarantine ID not found: {quarantine_id}")
            return False

        entry = self._quarantine_db[quarantine_id]
        quarantine_path = Path(entry['quarantine_path'])

        if not quarantine_path.exists():
            logger.error(f"Quarantined file not found: {quarantine_path}")
            return False

        try:
            # Determine restore path
            target_path = Path(restore_path) if restore_path else Path(entry['original_path'])

            # Create parent directory if needed
            target_path.parent.mkdir(parents=True, exist_ok=True)

            # Restore file
            import shutil
            shutil.move(str(quarantine_path), str(target_path))

            # Remove from database
            del self._quarantine_db[quarantine_id]
            self._save_database()

            logger.info(f"Restored: {quarantine_path} -> {target_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to restore {quarantine_id}: {e}")
            return False

    def delete(self, quarantine_id: str) -> bool:
        """Permanently delete a quarantined file."""
        if quarantine_id not in self._quarantine_db:
            return False

        entry = self._quarantine_db[quarantine_id]
        quarantine_path = Path(entry['quarantine_path'])

        try:
            quarantine_path.unlink()
            del self._quarantine_db[quarantine_id]
            self._save_database()

            logger.info(f"Deleted quarantined file: {quarantine_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete {quarantine_id}: {e}")
            return False

    def list_quarantined(self) -> List[Dict]:
        """List all quarantined files."""
        return [
            {
                'id': qid,
                **entry
            }
            for qid, entry in self._quarantine_db.items()
        ]

    def _load_database(self):
        """Load quarantine database from disk."""
        db_path = self._quarantine_dir / 'quarantine.json'
        if db_path.exists():
            try:
                with open(db_path, 'r') as f:
                    self._quarantine_db = json.load(f)
            except Exception as e:
                logger.error(f"Failed to load quarantine database: {e}")

    def _save_database(self):
        """Save quarantine database to disk."""
        db_path = self._quarantine_dir / 'quarantine.json'
        try:
            with open(db_path, 'w') as f:
                json.dump(self._quarantine_db, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save quarantine database: {e}")


class AVEngine:
    """
    Main anti-virus engine coordinating all detection methods.
    """

    def __init__(self, config):
        """Initialize the AV engine."""
        self.config = config
        self.yara_scanner = YARAScanner(config)
        self.static_analyzer = StaticBinaryAnalyzer(config)
        self.behavioral_scanner = BehavioralSignatures(config)
        self.quarantine = QuarantineManager(config)

        # Statistics
        self._scans_performed = 0
        self._threats_detected = 0
        self._files_cleaned = 0

    def scan(self, file_path: str, scan_behavioral: bool = False) -> ScanResult:
        """
        Scan a file for threats.

        Args:
            file_path: Path to file to scan
            scan_behavioral: Whether to include behavioral analysis

        Returns:
            Scan result
        """
        import time
        start_time = time.time()
        path = Path(file_path)

        # Prepare result
        result = ScanResult(
            file_path=str(path.absolute()),
            scanned_at=datetime.now().isoformat(),
            is_clean=True,
            threats=[],
            scan_duration_ms=0,
            file_size=0,
            hashes={},
            scan_engines=['yara', 'static_analyzer']
        )

        if not path.exists():
            result.threats.append(ThreatInfo(
                name="File Not Found",
                category=ThreatCategory.UNKNOWN,
                severity='low',
                description=f"File not found: {file_path}",
                file_hash="",
                file_path=file_path,
                detected_at=datetime.now().isoformat(),
                scanner="av_engine",
                confidence=1.0
            ))
            return result

        try:
            # Get file size
            result.file_size = path.stat().st_size

            # Calculate hashes
            result.hashes = self._calculate_hashes(path)

            # Run YARA scan
            yara_threats = self.yara_scanner.scan(file_path)
            result.threats.extend(yara_threats)

            # Run static analysis
            static_threats = self.static_analyzer.analyze(file_path)
            result.threats.extend(static_threats)

            # Determine if clean
            result.is_clean = len(result.threats) == 0

            # Update statistics
            self._scans_performed += 1
            if not result.is_clean:
                self._threats_detected += len(result.threats)
            else:
                self._files_cleaned += 1

        except Exception as e:
            logger.error(f"Scan error for {file_path}: {e}")
            result.threats.append(ThreatInfo(
                name="Scan Error",
                category=ThreatCategory.UNKNOWN,
                severity='low',
                description=f"Scan error: {str(e)}",
                file_hash="",
                file_path=file_path,
                detected_at=datetime.now().isoformat(),
                scanner="av_engine",
                confidence=0.5
            ))

        result.scan_duration_ms = int((time.time() - start_time) * 1000)

        return result

    def scan_directory(self, directory: str, recursive: bool = True) -> Dict[str, ScanResult]:
        """Scan all files in a directory."""
        results = {}
        path = Path(directory)

        if not path.exists():
            return results

        if recursive:
            files = path.rglob('*')
        else:
            files = path.glob('*')

        for file in files:
            if file.is_file():
                try:
                    result = self.scan(str(file))
                    results[str(file)] = result
                except Exception as e:
                    logger.error(f"Failed to scan {file}: {e}")

        return results

    def _calculate_hashes(self, file_path: Path) -> Dict[str, str]:
        """Calculate multiple hashes of a file."""
        hashes = {}
        hashers = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256(),
        }

        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                for hasher in hashers.values():
                    hasher.update(chunk)

        for name, hasher in hashers.items():
            hashes[name] = hasher.hexdigest()

        return hashes

    def handle_threat(self, scan_result: ScanResult, action: ScanAction) -> bool:
        """
        Handle detected threats with specified action.

        Args:
            scan_result: Scan result containing threats
            action: Action to take

        Returns:
            True if successful
        """
        if scan_result.is_clean:
            return True

        file_path = scan_result.file_path

        if action == ScanAction.QUARANTINE:
            for threat in scan_result.threats:
                return self.quarantine.quarantine(file_path, threat)

        elif action == ScanAction.DELETE:
            try:
                Path(file_path).unlink()
                logger.info(f"Deleted infected file: {file_path}")
                return True
            except Exception as e:
                logger.error(f"Failed to delete {file_path}: {e}")
                return False

        elif action == ScanAction.ALERT_ONLY:
            logger.warning(f"Threat detected in {file_path}: {len(scan_result.threats)} threats")
            return True

        return False

    def get_statistics(self) -> Dict:
        """Get AV engine statistics."""
        return {
            'scans_performed': self._scans_performed,
            'threats_detected': self._threats_detected,
            'files_cleaned': self._files_cleaned,
            'quarantined_files': len(self.quarantine.list_quarantined()),
            'detection_rate': self._threats_detected / max(self._scans_performed, 1)
        }
