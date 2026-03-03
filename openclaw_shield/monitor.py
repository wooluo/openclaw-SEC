"""
Network Monitor Module
Monitors network connections and detects suspicious activities
"""

import asyncio
import socket
import psutil
from typing import Dict, List, Any, Set
from datetime import datetime
from collections import defaultdict
from loguru import logger
from pathlib import Path


class NetworkMonitor:
    """
    Monitors network connections for OpenClaw processes.
    Detects suspicious outbound connections and data exfiltration attempts.
    """

    # Known safe domains/IPs
    SAFE_DOMAINS = {
        'api.openai.com',
        'api.anthropic.com',
        'api.openclaw.ai',
        '*.cdn.openclaw.ai',
        'localhost',
        '127.0.0.1',
    }

    # Known malicious IP ranges (example - would be updated from threat intel)
    SUSPICIOUS_PORTS = {
        4444,  # Common reverse shell port
        5555,  # Common backdoor port
        6666,  # Common backdoor port
        6667,  # IRC (often used by malware)
        8888,  # Common backdoor port
        31337, # Elite port
    }

    def __init__(self, config):
        """Initialize the network monitor."""
        self.config = config
        self._active_connections = {}
        self._connection_history = defaultdict(list)
        self._blocked_ips = set()
        self._alerts = []
        self._monitoring = False

        # Load blacklist if exists
        self.blacklist_file = Path(config.get('network.blacklist_file', './config/blacklist.txt'))
        self._load_blacklist()

    def _load_blacklist(self):
        """Load IP/domain blacklist from file."""
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

    async def start(self):
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
        """Check if connection looks like a reverse shell."""
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
        """Check if process shows reverse shell behavior."""
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
