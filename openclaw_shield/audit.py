"""
Security Auditor Module
Provides comprehensive security auditing and logging
"""

import json
import sqlite3
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from loguru import logger


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

        # Setup log file
        self.log_file = Path(config.get('logging.file', './logs/audit.log'))
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

        logger.info("Security auditor initialized")

    def _init_database(self):
        """Initialize the audit database."""
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
