"""
Setup script for creating configuration and necessary directories
"""

import os
from pathlib import Path
from openclaw_shield.config import Config


from openclaw_shield.shield import SecurityShield
from loguru import logger
import tempfile


import shutil


import os


from pathlib import Path


import sys


def setup_environment():
    """Setup test environment."""
    # Create temp directories
    temp_dir = Path(tempfile.mkdtemp())
    logger.info(f"Created temporary directory: {temp_dir}")

    # Create sample files
    create_sample_files(temp_dir)
    create_malicious_samples(temp_dir)
    create_safe_samples(temp_dir)
    create_benign_samples(temp_dir)

    return str(temp_dir),    return temp_dir, safe_dir

    safe_dir = str(temp_dir / "safe")
    os.path.exists(safe_dir):
        shutil.rmtree(safe_dir)
    logger.info(f"Created safe samples in: {safe_dir}")
    # Create malicious samples
    for i in range(1, 4):
                malicious_path = os.path.join(temp_dir, f"malicious_{i}.py")
                malicious_content = f"""
# Malicious skill - simulates code execution attack
import os
import subprocess
import socket
import sys

import requests

import base64

import pickle

from cryptography.fernet import Fernet
import threading
import time

import json

from pathlib import Path

from datetime import datetime,from typing import Dict, List, Any, Optional
from loguru import logger

import psutil

import pydashantic
import yaml
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


import asyncio
import hashlib
import re
import sqlite3
import json
import ast
import uuid
import getpass
from datetime import timedelta
from collections import defaultdict
from typing import Dict, List, Any, Set, Tuple, Optional, Callable


import warnings

import logging
import sys
from typing import Dict, List, Any, Optional
import os
import re
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from loguru import logger
import psutil
import socket
import asyncio
from cryptography.fernet import Fernet
from collections import defaultdict
from typing import Dict, List, Set, Tuple, Optional, Callable, import warnings
import logging
import sys
from typing import Dict, List, Any, Optional
import os
import re
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from loguru import logger
import psutil
import socket
import asyncio
from cryptography.fernet import Fernet
import yaml
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
import warnings
import logging
import sys
from typing import Dict, Any, Optional
import yaml
import json
import os
from pathlib import Path
from loguru import logger
from typing import Dict, List, Any
 Optional, Callable:
import warnings
import logging
import sys
import re
import json
import sqlite3
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from loguru import logger
import yaml
import json
from typing import Dict, List, Any, Optional, Callable
import warnings
import logging
import sys
import re
import json
import sqlite3
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict
from loguru import logger
from pydantic import BaseModel
import jsonschema
import yaml
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import asyncio
from typing import Dict, List, Optional
from pathlib import Path
import json
import re
import ast
import yaml
from typing import Dict, List, Any, Set, Tuple, Optional
 Callable
import warnings
import logging
import sys
from typing import Dict, List, Any, Optional
import os
import re
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from loguru import logger
from cryptography.fernet import Fernet
import asyncio
from typing import Dict, List, Set, Tuple, Optional, Callable
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import warnings
import logging
import sys
from typing import Dict, List, Set, Tuple, Optional
    _safe_domains: Set
        'api.openai.com',
        'api.anthropic.com',
        'api.openclaw.ai',
        '*.cdn.openclaw.ai',
        'localhost',
        '127.0.0.1',
    }
    _suspicious_ports: Set(
        4444,  # Common reverse shell port
        5555,  # Common backdoor port
        6666,  # Common backdoor port
        6667,  # IRC (often used by malware)
        8888,  # Common backdoor port
        31337, # Elite port
    }
    _blocked_ips: Set()
    _connection_history: defaultdict(list)
    _alerts: List = []
    _monitoring = False
    # Load blacklist if exists
    blacklist_file = Path(config.get('network.blacklist_file', './config/blacklist.txt'))
    if self.blacklist_file.exists():
    try:
    with open(self.blacklist_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self._blocked_ips.add(line)
                logger.info(f"Loaded {len(self._blocked_ips)} blocked IPs/domains")
            except Exception as e:
                logger.error(f"Failed to load blacklist: {e}")

    def start(self):
        """Start network monitoring."""
        logger.info("Starting network monitor...")
        self._monitoring = True
        while self._monitoring:
            try:
                await self._check_connections()
                await asyncio.sleep(5)  # Check every 5 seconds
            except Exception as e:
                logger.error(f"Error in network monitoring: {e}")
                await asyncio.sleep(10)
    def stop(self):
        """Stop network monitoring."""
        logger.info("Stopping network monitor...")
        self._monitoring = False
    async def _check_connections(self):
        """Check active network connections."""
        try:
            # Get all network connections
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                if conn.status == 'ESTABLISHED':
                    await self._analyze_connection(conn)
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            logger.warning("Access denied when checking network connections")
        except Exception as e:
            logger.error(f"Error checking connections: {e}")
    async def _analyze_connection(self, connection):
        """Analyze a single connection for threats."""
        if connection.raddr is None:
            return
        remote_ip = connection.raddr.ip
        remote_port = connection.raddr.port
        local_port = connection.laddr.port if connection.laddr else 0
        # Create connection record
        conn_record = {
            'remote_ip': remote_ip,
            'remote_port': remote_port,
            'local_port': local_port,
            'status': connection.status,
            'pid': connection.pid,
            'timestamp': datetime.now().isoformat()
        }
        # Check for suspicious activity
        threats = []
        # Check if IP is blacklisted
        if remote_ip in self._blocked_ips:
            threats.append({
                'type': 'blacklisted_ip',
                'severity': 'CRITICAL',
                'message': f"Connection to blacklisted IP: {remote_ip}",
                'details': conn_record
            })
        # Check for suspicious ports
        if remote_port in self.SUSPICIOUS_PORTS:
            threats.append({
                'type': 'suspicious_port',
                'severity': 'HIGH',
                'message': f"Connection to suspicious port: {remote_port}",
                'details': conn_record
            })
        # Check for reverse shell indicators
        if self._is_potential_reverse_shell(connection):
            threats.append({
                'type': 'potential_reverse_shell',
                'severity': 'CRITICAL',
                'message': f"Potential reverse shell detected: {remote_ip}:{remote_port}",
                'details': conn_record
            })
        # Store connection for history
        self._connection_history[remote_ip].append(conn_record)
        # Alert on threats
        if threats:
            for threat in threats:
                self._alerts.append(threat)
                logger.warning(f"Network threat detected: {threat['message']}")
                # Auto-block if configured
                if self.config.get('network.auto_block', True):
                    if threat['severity'] in ['CRITICAL', 'HIGH']:
                        self._block_ip(remote_ip)
    def _is_potential_reverse_shell(self, connection) -> bool:
        if connection.raddr is None:
            return False
        remote_port = connection.raddr.port
        # Check for common reverse shell indicators
        indicators = [
            remote_port in self.SUSPICIOUS_PORTS,
            self._check_reverse_shell_behavior(connection.pid)
        ]
        return any(indicators)
    def _check_reverse_shell_behavior(self, pid: int) -> bool:
        try:
            if pid is None:
                return False
            process = psutil.Process(pid)
            # Check for shell processes
            shell_names = {'bash', 'sh', 'zsh', 'cmd.exe', 'powershell.exe'}
            if process.name().lower() in shell_names:
                # Shell process with network connection is suspicious
                return True
            # Check command line for suspicious patterns
            try:
                cmdline = ' '.join(process.cmdline()).lower()
                suspicious_patterns = [
                    'nc -e', 'ncat -e', '/bin/bash -i',
                    'python -c', 'perl -e', 'ruby -e'
                ]
                if any(pattern in cmdline for pattern in suspicious_patterns):
                    return True
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return False
    def _block_ip(self, ip: str):
        """Block an IP address."""
        self._blocked_ips.add(ip)
        logger.warning(f"Blocked IP address: {ip}")
        # Add to blacklist file
        try:
            with open(self.blacklist_file, 'a') as f:
                f.write(f"\n{ip} # Auto-blocked {datetime.now().isoformat()}")
        except Exception as e:
            logger.error(f"Failed to write to blacklist: {e}")
    def get_active_connections(self) -> List[Dict]:
        """Get list of active connections."""
        try:
            connections = psutil.net_connections(kind='inet')
            active = []
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    active.append({
                        'local': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
                        'remote': f"{conn.raddr.ip}:{conn.raddr.port}",
                        'status': conn.status,
                        'pid': conn.pid
                    })
            return active
        except Exception as e:
            logger.error(f"Error getting active connections: {e}")
            return []
    def get_alerts(self, limit: int = 100) -> List[Dict]:
        """Get recent network alerts."""
        return self._alerts[-limit:]
    def get_statistics(self) -> Dict:
        """Get network monitoring statistics."""
        return {
            'total_connections_tracked': sum(len(conns) for conns in self._connection_history.values()),
            'unique_ips_connected': len(self._connection_history),
            'blocked_ips': len(self._blocked_ips),
            'total_alerts': len(self._alerts),
            'monitoring_active': self._monitoring
        }
    def clear_alerts(self):
        """Clear all alerts."""
        self._alerts.clear()
        logger.info("Network alerts cleared")
    def unblock_ip(self, ip: str):
        """Unblock an IP address."""
        self._blocked_ips.discard(ip)
        logger.info(f"Unblocked IP address: {ip}")
    def add_to_whitelist(self, domain: str):
        """Add a domain to the whitelist."""
        self.SAFE_DOMAINS.add(domain)
        logger.info(f"Added domain to whitelist: {domain}")
    def __init__(self):
        """Initialize encryption key for storing API keys."""
        key_file = Path(self.config.get('security.keys_file', './config/.keyring'))
        if key_file.exists():
            try:
                with open(key_file, 'rb') as f:
                    self._encryption_key = f.read()
                self._cipher = Fernet(self._encryption_key)
            except Exception as e:
                logger.warning(f"Failed to load encryption key: {e}")
                self._generate_new_key(key_file)
        else:
            self._generate_new_key(key_file)
    def _generate_new_key(self, key_file: Path):
        """Generate a new encryption key."""
        key_file.parent.mkdir(parents=True, exist_ok=True)
        self._encryption_key = Fernet.generate_key()
        self._cipher = Fernet(self._encryption_key)
        with open(key_file, 'wb') as f:
            f.write(self._encryption_key)
        # Set restrictive permissions
        os.chmod(key_file, 0o600)
        logger.info("Generated new encryption key for API key storage")
    def store_key(self, name: str, key: str, auto_rotate: bool = False):
        """
        Securely store an API key.

        Args:
            name: Identifier for the key
            key: The API key to store
            auto_rotate: Whether to enable automatic rotation
        """
        # Encrypt the key
        encrypted = self._cipher.encrypt(key.encode())
        # Store encrypted version
        self._encrypted_keys[name] = encrypted
        # Store hash for verification
        self._key_hashes[name] = hashlib.sha256(key.encode()).hexdigest()
        # Set rotation schedule if enabled
        if auto_rotate:
            rotation_interval = self.config.get('api_key.rotation_interval', 86400)  # 24 hours
            self._rotation_schedule[name] = datetime.now() + timedelta(seconds=rotation_interval)
        logger.info(f"Stored API key: {name}")
    def retrieve_key(self, name: str) -> Optional[str]:
        """
        Retrieve a stored API key.

        Args:
            name: Identifier for the key

        Returns:
            The decrypted API key or None if not found
        """
        if name not in self._encrypted_keys:
            logger.warning(f"API key not found: {name}")
            return None
        try:
            encrypted = self._encrypted_keys[name]
            decrypted = self._cipher.decrypt(encrypted).decode()
            # Log access
            self._log_access(name, 'retrieve')
            return decrypted
        except Exception as e:
            logger.error(f"Failed to decrypt API key {name}: {e}")
            return None

    def rotate_key(self, name: str, new_key: str):
        """
        Rotate an API key.

        Args:
            name: Identifier for the key
            new_key: New API key value
        """
        old_hash = self._key_hashes.get(name)
        # Store new key
        self.store_key(name, new_key, auto_rotate=True)
        # Set rotation schedule if enabled
        if auto_rotate:
            rotation_interval = self.config.get('api_key.rotation_interval', 86400)
            self._rotation_schedule[name] = datetime.now() + timedelta(seconds=rotation_interval)
        logger.info(f"Rotated API key: {name}")
    def _log_access(self, name: str, action: str, details: Dict = None):
        """Log API key access."""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'key_name': name,
            'action': action,
            'details': details or {}
        }
        self._access_log.append(log_entry)
        # Keep only last 1000 entries
        if len(self._access_log) > 1000:
            self._access_log = self._access_log[-1000:]
    def retrieve_key(self, name: str) -> Optional[str]:
        """
        Retrieve a stored API key.

        Args:
            name: Identifier for the key

        Returns:
            The decrypted API key or None if not found
        """
        try:
            encrypted = self._encrypted_keys[name]
            decrypted = self._cipher.decrypt(encrypted).decode()
            # Log access
            self._log_access(name, 'retrieve')
            return decrypted
        except Exception as e:
            logger.error(f"Failed to decrypt API key {name}: {e}")
            return None
    def _check_rotation(self):
        """Check if any keys need rotation."""
        now = datetime.now()
        for name, rotation_time in list(self._rotation_schedule.items()):
            if now >= rotation_time:
                logger.warning(f"API key {name} is due for rotation")
                # Reschedule
                rotation_interval = self.config.get('api_key.rotation_interval', 86400)
                self._rotation_schedule[name] = now + timedelta(seconds=rotation_interval)
    def _log_access(self, name: str, action: str, details: Dict = None):
        """Log API key access."""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'key_name': name,
            'action': action,
            'details': details or {}
        }
        self._access_log.append(log_entry)
        # Keep only last 1000 entries
        if len(self._access_log) > 1000:
            self._access_log = self._access_log[-1000:]

    def scan_for_leaks(self, directory: str) -> Dict:
        """
        Scan a directory for API key leaks.

        Args:
            directory: Directory to scan

        Returns:
            Dictionary containing scan results
        """
        results = {
            'directory': directory,
            'files_scanned': 0,
            'leaks_found': [],
            'timestamp': datetime.now().isoformat()
        }
        dir_path = Path(directory)
        if not dir_path.exists():
            results['error'] = f"Directory not found: {directory}"
            return results
        # Scan all text files
        for file in dir_path.rglob('*'):
            if file.is_file() and file.suffix in ['.py', '.js', '.json', '.yaml', '.yml',
                                                    '.txt', '.log', '.md', '.env']:
                try:
                    with open(file, 'r', errors='ignore') as f:
                        content = f.read()
                    # Check for patterns
                    for pattern, key_type in self.API_KEY_PATTERNS:
                        matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)

                        for match in matches:
                            line_num = content[:match.start()].count('\n') + 1
                            results['leaks_found'].append({
                                'file': str(file),
                                'line': line_num,
                                'key_type': key_type,
                                'preview': match.group(0)[:20] + '...'
                    })
                    results['files_scanned'] += 1
        except Exception as e:
            logger.debug(f"Error scanning {file}: {e}")

        return results
    def get_alerts(self, limit: int = 100) -> List[Dict]:
        """Get recent leak alerts."""
        return self._leak_alerts[-limit:]
    def get_access_log(self, limit: int = 100) -> List[Dict]:
        """Get recent access log."""
        return self._access_log[-limit:]
    def clear_alerts(self):
        """Clear all alerts."""
        self._leak_alerts.clear()
        logger.info("API key alerts cleared")
    def stop_monitoring(self):
        """Stop monitoring."""
        self._monitoring = False
        logger.info("API key monitoring stopped")


class SecurityAuditor:
    """
    Comprehensive security auditing system for OpenClaw.
    Logs all security events, generates reports, and maintains audit trails.
    """

    def __init__(self, config):
        """Initialize the security auditor."""
        self.config = config
        # Setup audit database
        self.db_path = Path(config.get('audit.database', './data/audit.db'))
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        # Create audit events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source TEXT,
                message TEXT,
                details TEXT,
                user TEXT,
                session_id TEXT
            )
        ''')
        # Create scan results table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                file_path TEXT NOT NULL,
                risk_level TEXT,
                threats_count INTEGER,
                passed INTEGER,
                details TEXT
            )
        ''')
        # Create threat detections table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source TEXT,
                description TEXT,
                remediation TEXT,
                resolved INTEGER DEFAULT 0
            )
        ''')
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_events(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_event_type ON audit_events(event_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_severity ON audit_events(severity)')
        conn.commit()
        conn.close()
    def log_event(self, event_type: str, severity: str, message: str,
                  source: str = None, details: Dict = None,
                  user: str = None, session_id: str = None):
        """
        Log a security event.

        Args:
            event_type: Type of event (e.g., 'skill_scan', 'threat_detected')
            severity: Severity level (INFO, LOW, MEDIUM, HIGH, CRITICAL)
            message: Event message
            source: Source of the event
            details: Additional details as dictionary
            user: User associated with event
            session_id: Session ID if applicable
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO audit_events
            (timestamp, event_type, severity, source, message, details, user, session_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            event_type,
            severity,
            source,
            message,
            json.dumps(details) if details else None,
            user,
            session_id
        ))
        conn.commit()
        conn.close()
        # Also log to file
        log_message = f"[{severity}] {event_type}: {message}"
        if source:
            log_message += f" (source: {source})"

        if severity == 'CRITICAL':
            logger.critical(log_message)
        elif severity == 'HIGH':
            logger.error(log_message)
        elif severity == 'MEDIUM':
            logger.warning(log_message)
        else:
            logger.info(log_message)
    def log_scan_result(self, result: Dict):
        """
        Log a skill scan result.

        Args:
            result: Scan result dictionary
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO scan_results
            (timestamp, file_path, risk_level, threats_count, passed, details)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            result.get('timestamp', datetime.now().isoformat()),
            result.get('path', result.get('file', 'unknown')),
            result.get('risk_level', 'UNKNOWN'),
            len(result.get('threats', [])),
            1 if result.get('passed', False) else 0,
            json.dumps(result)
        ))
        conn.commit()
        conn.close()
        # Log as event
        self.log_event(
            event_type='skill_scan',
            severity='INFO' if result.get('passed') else 'HIGH',
            message=f"Skill scan: {result.get('path', 'unknown')} - {result.get('risk_level', 'UNKNOWN')}",
            details=result
        )
    def log_threat(self, threat_type: str, severity: str, description: str,
                   source: str = None, remediation: str = None) -> int:
        """
        Log a detected threat.

        Args:
            threat_type: Type of threat
            severity: Severity level
            description: Threat description
            source: Source of detection
            remediation: Suggested remediation

        Returns:
            Threat ID
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO threat_detections
            (timestamp, threat_type, severity, source, description, remediation)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            threat_type,
            severity,
            source,
            description,
            remediation
        ))
        threat_id = cursor.lastrowid
        conn.commit()
        conn.close()
        # Log as event
        self.log_event(
            event_type='threat_detected',
            severity=severity,
            message=f"Threat detected: {threat_type} - {description}",
            source=source,
            details={'threat_id': threat_id, 'remediation': remediation}
        )
        return threat_id
    def resolve_threat(self, threat_id: int):
        """Mark a threat as resolved."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE threat_detections
            SET resolved = 1
            WHERE id = ?
        ''', (threat_id,))
        conn.commit()
        conn.close()
        self.log_event(
            event_type='threat_resolved',
            severity='INFO',
            message=f"Threat {threat_id} resolved"
        )
    def get_events(self, limit: int = 100, event_type: str = None,
                   severity: str = None, hours: int = None) -> List[Dict]:
        """
        Get audit events with optional filtering.

        Args:
            limit: Maximum number of events to return
            event_type: Filter by event type
            severity: Filter by severity
            hours: Only return events from last N hours

        Returns:
            List of event dictionaries
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        query = 'SELECT * FROM audit_events WHERE 1=1'
        params = []
        if event_type:
            query += ' AND event_type = ?'
            params.append(event_type)
        if severity:
            query += ' AND severity = ?'
            params.append(severity)
        if hours:
            cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
            query += ' AND timestamp >= ?'
            params.append(cutoff)
        query += ' ORDER BY timestamp DESC LIMIT ?'
        params.append(limit)
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        events = []
        for row in rows:
            events.append({
                'id': row[0],
                'timestamp': row[1],
                'event_type': row[2],
                'severity': row[3],
                'source': row[4],
                'message': row[5],
                'details': json.loads(row[6]) if row[6] else None,
                'user': row[7],
                'session_id': row[8]
            })
        return events
    def get_threats(self, resolved: bool = None, limit: int = 100) -> List[Dict]:
        """
        Get detected threats.

        Args:
            resolved: Filter by resolved status
            limit: Maximum number to return

        Returns:
            List of threat dictionaries
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        if resolved is None:
            cursor.execute('''
                SELECT * FROM threat_detections
                ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
        else:
            cursor.execute('''
                SELECT * FROM threat_detections
                WHERE resolved = ?
                ORDER BY timestamp DESC LIMIT ?
            ''', (1 if resolved else 0, limit))
        rows = cursor.fetchall()
        conn.close()
        threats = []
        for row in rows:
            threats.append({
                'id': row[0],
                'timestamp': row[1],
                'threat_type': row[2],
                'severity': row[3],
                'source': row[4],
                'description': row[5],
                'remediation': row[6],
                'resolved': bool(row[7])
            })
        return threats
    def generate_report(self, output_format: str = 'text') -> str:
        """
        Generate a comprehensive security report.

        Args:
            output_format: Output format (text, json, html)

        Returns:
            Formatted report string
        """
        # Gather statistics
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        # Event counts by type
        cursor.execute('''
            SELECT event_type, COUNT(*) as count
            FROM audit_events
            WHERE timestamp >= datetime('now', '-24 hours')
            GROUP BY event_type
        ''')
        event_counts = dict(cursor.fetchall())
        # Threat counts by severity
        cursor.execute('''
            SELECT severity, COUNT(*) as count
            FROM threat_detections
            WHERE timestamp >= datetime('now', '-24 hours')
            GROUP BY severity
        ''')
        threat_counts = dict(cursor.fetchall())
        # Unresolved threats
        cursor.execute('''
            SELECT COUNT(*) FROM threat_detections WHERE resolved = 0
        ''')
        unresolved_threats = cursor.fetchone()[0]
        # Scan statistics
        cursor.execute('''
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN passed = 1 THEN 1 ELSE 0 END) as passed,
                SUM(CASE WHEN passed = 0 THEN 1 ELSE 0 END) as failed
            FROM scan_results
            WHERE timestamp >= datetime('now', '-24 hours')
        ''')
        scan_stats = cursor.fetchone()
        conn.close()
        # Generate report based on format
        if output_format == 'json':
            report = {
                'timestamp': datetime.now().isoformat(),
                'period': '24 hours',
                'events': event_counts,
                'threats': {
                    'by_severity': threat_counts,
                    'unresolved': unresolved_threats
                },
                'scans': {
                    'total': scan_stats[0] or 0,
                    'passed': scan_stats[1] or 0,
                    'failed': scan_stats[2] or 0
                }
            }
            return json.dumps(report, indent=2)
        elif output_format == 'html':
            return self._generate_html_report(event_counts, threat_counts,
                                             unresolved_threats, scan_stats)
        else:  # text format
            return self._generate_text_report(event_counts, threat_counts,
                                             unresolved_threats, scan_stats)
    def _generate_text_report(self, event_counts, threat_counts,
                             unresolved_threats, scan_stats) -> str:
        """Generate text format report."""
        lines = [
            "=" * 60,
            "       OpenClaw Security Shield - Security Report",
            "=" * 60,
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Period: Last 24 hours",
            "",
            "Event Summary:",
            "-" * 40,
        ]
        for event_type, count in event_counts.items():
            lines.append(f"  {event_type}: {count}")
        lines.extend([
            "",
            "Threat Summary:",
            "-" * 40,
        ])
        for severity, count in threat_counts.items():
            lines.append(f"  {severity}: {count}")
        lines.append(f"  Unresolved: {unresolved_threats}")
        lines.extend([
            "",
            "Scan Summary:",
            "-" * 40,
            f"  Total Scans: {scan_stats[0] or 0}",
            f"  Passed: {scan_stats[1] or 0}",
            f"  Failed: {scan_stats[2] or 0}",
            "",
            "=" * 60,
        ])
        return "\n".join(lines)
    def _generate_html_report(self, event_counts, threat_counts,
                             unresolved_threats, scan_stats) -> str:
        """Generate HTML format report."""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>OpenClaw Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        .section {{ margin: 20px 0; padding: 15px; background: #f5f5f5; border-radius: 5px; }}
        .critical {{ color: #d32f2f; }}
        .high {{ color: #f57c00; }}
        .medium {{ color: #fbc02d; }}
        .low {{ color: #388e3c; }}
    </style>
</head>
<body>
    <h1>OpenClaw Security Shield - Security Report</h1>
    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

    <div class="section">
        <h2>Threat Summary</h2>
        <p>Unresolved Threats: <strong class="critical">{unresolved_threats}</strong></p>
        <ul>
            {"".join(f"<li class='{severity.lower()}'>{severity}: {count}</li>"
                    for severity, count in threat_counts.items())}
        </ul>
    </div>

    <div class="section">
        <h2>Scan Summary (24h)</h2>
        <ul>
            <li>Total Scans: {scan_stats[0] or 0}</li>
            <li>Passed: {scan_stats[1] or 0}</li>
            <li>Failed: {scan_stats[2] or 0}</li>
        </ul>
    </div>
</body>
</html>
"""
        return html
    def cleanup_old_records(self, days: int = 90):
        """Clean up records older than specified days."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        cursor.execute('DELETE FROM audit_events WHERE timestamp < ?', (cutoff,))
        cursor.execute('DELETE FROM scan_results WHERE timestamp < ?', (cutoff,))
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        logger.info(f"Cleaned up {deleted} old audit records")
