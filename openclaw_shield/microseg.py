"""
Micro-Segmentation Module
Network policy enforcement, port-level access control, east-west traffic monitoring,
and firewall rule management for zero-trust security.
"""

import ipaddress
import subprocess
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field, asdict
from enum import Enum
from loguru import logger
from pathlib import Path


class ActionType(Enum):
    """Firewall rule actions."""
    ALLOW = "allow"
    DENY = "deny"
    REJECT = "reject"
    LOG = "log"


class Direction(Enum):
    """Traffic direction."""
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    BIDIRECTIONAL = "bidirectional"


class Protocol(Enum):
    """Network protocols."""
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ANY = "any"


@dataclass
class NetworkEndpoint:
    """Represents a network endpoint."""
    address: str  # IP address or CIDR
    port: Optional[int] = None
    protocol: Optional[Protocol] = None

    def is_match(self, address: str, port: int = None, protocol: str = None) -> bool:
        """Check if this endpoint matches the given address/port/protocol."""
        # Check address
        try:
            ip = ipaddress.ip_address(address)
            if '/' in self.address:
                # CIDR range
                network = ipaddress.ip_network(self.address, strict=False)
                if ip not in network:
                    return False
            else:
                # Exact match
                if str(ip) != self.address:
                    return False
        except ValueError:
            # Hostname match (simplified)
            if self.address != address and not address.endswith(self.address):
                return False

        # Check port
        if self.port is not None and port != self.port:
            return False

        # Check protocol
        if self.protocol is not None and self.protocol != Protocol.ANY:
            if protocol is not None and self.protocol.value != protocol.lower():
                return False

        return True


@dataclass
class FirewallRule:
    """Represents a firewall rule."""
    id: str
    name: str
    description: str
    source: NetworkEndpoint
    destination: NetworkEndpoint
    action: ActionType
    direction: Direction
    protocol: Protocol
    enabled: bool
    created_at: str
    updated_at: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        d = asdict(self)
        d['action'] = self.action.value
        d['direction'] = self.direction.value
        d['protocol'] = self.protocol.value
        return d

    @classmethod
    def from_dict(cls, data: Dict) -> 'FirewallRule':
        """Create from dictionary."""
        source_data = data.pop('source')
        dest_data = data.pop('destination')

        source = NetworkEndpoint(**source_data)
        destination = NetworkEndpoint(**dest_data)

        data['action'] = ActionType(data['action'])
        data['direction'] = Direction(data['direction'])
        data['protocol'] = Protocol(data['protocol'])

        return cls(source=source, destination=destination, **data)


@dataclass
class TrafficEvent:
    """Represents a network traffic event."""
    timestamp: str
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    protocol: str
    direction: Direction
    action_taken: ActionType
    rule_matched: Optional[str]
    bytes_transferred: int
    duration_seconds: Optional[float] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        d = asdict(self)
        d['direction'] = self.direction.value
        d['action_taken'] = self.action_taken.value
        return d


class NetworkPolicy:
    """Network security policy."""

    def __init__(self, config):
        """Initialize network policy."""
        self.config = config
        self._rules: Dict[str, FirewallRule] = {}
        self._default_action = ActionType(config.get('microseg.default_action', 'deny'))
        self._log_denied = config.get('microseg.log_denied', True)

    def add_rule(self, rule: FirewallRule):
        """Add a firewall rule."""
        self._rules[rule.id] = rule
        logger.info(f"Added firewall rule: {rule.name}")

    def remove_rule(self, rule_id: str):
        """Remove a firewall rule."""
        if rule_id in self._rules:
            del self._rules[rule_id]
            logger.info(f"Removed firewall rule: {rule_id}")

    def update_rule(self, rule_id: str, **updates):
        """Update a firewall rule."""
        if rule_id in self._rules:
            rule = self._rules[rule_id]
            for key, value in updates.items():
                if hasattr(rule, key):
                    setattr(rule, key, value)
            rule.updated_at = datetime.now().isoformat()
            logger.info(f"Updated firewall rule: {rule_id}")

    def check_traffic(self, source_ip: str, source_port: int,
                     destination_ip: str, destination_port: int,
                     protocol: str, direction: Direction) -> Tuple[ActionType, Optional[str]]:
        """
        Check if traffic is allowed based on rules.

        Args:
            source_ip: Source IP address
            source_port: Source port
            destination_ip: Destination IP address
            destination_port: Destination port
            protocol: Protocol (tcp, udp, etc.)
            direction: Traffic direction

        Returns:
            Tuple of (action, rule_id)
        """
        # Check rules in order (first match wins)
        for rule_id, rule in self._rules.items():
            if not rule.enabled:
                continue

            # Check direction
            if rule.direction != Direction.BIDIRECTIONAL and rule.direction != direction:
                continue

            # Check protocol
            if rule.protocol != Protocol.ANY and rule.protocol.value != protocol.lower():
                continue

            # Check source
            if not rule.source.is_match(source_ip, source_port, protocol):
                continue

            # Check destination
            if not rule.destination.is_match(destination_ip, destination_port, protocol):
                continue

            # Rule matched
            return rule.action, rule_id

        # No rule matched, use default action
        return self._default_action, None

    def get_rules(self) -> List[FirewallRule]:
        """Get all rules."""
        return list(self._rules.values())


class TrafficMonitor:
    """Monitors network traffic for security analysis."""

    def __init__(self, config):
        """Initialize traffic monitor."""
        self.config = config
        self._events: List[TrafficEvent] = []
        self._max_events = config.get('microseg.max_events', 100000)
        self._connection_tracker: Dict[str, Dict] = {}

    def record_event(self, event: TrafficEvent):
        """Record a traffic event."""
        self._events.append(event)

        # Trim if necessary
        if len(self._events) > self._max_events:
            self._events = self._events[-self._max_events:]

        # Track connection for east-west analysis
        self._track_connection(event)

    def _track_connection(self, event: TrafficEvent):
        """Track connection for analysis."""
        if event.direction == Direction.OUTBOUND:
            key = f"{event.source_ip}:{event.source_port}->{event.destination_ip}:{event.destination_port}"
        else:
            key = f"{event.destination_ip}:{event.destination_port}->{event.source_ip}:{event.source_port}"

        if key not in self._connection_tracker:
            self._connection_tracker[key] = {
                'first_seen': event.timestamp,
                'last_seen': event.timestamp,
                'bytes_sent': event.bytes_transferred,
                'connection_count': 1,
                'source_ip': event.source_ip,
                'destination_ip': event.destination_ip,
                'destination_port': event.destination_port,
            }
        else:
            tracker = self._connection_tracker[key]
            tracker['last_seen'] = event.timestamp
            tracker['bytes_sent'] += event.bytes_transferred
            tracker['connection_count'] += 1

    def get_events(self, limit: int = 1000,
                   start_time: str = None,
                   end_time: str = None) -> List[TrafficEvent]:
        """Get traffic events with optional filtering."""
        events = self._events[-limit:]

        if start_time:
            start = datetime.fromisoformat(start_time)
            events = [e for e in events if datetime.fromisoformat(e.timestamp) >= start]

        if end_time:
            end = datetime.fromisoformat(end_time)
            events = [e for e in events if datetime.fromisoformat(e.timestamp) <= end]

        return events

    def get_east_west_traffic(self) -> Dict[str, Dict]:
        """Get east-west traffic statistics."""
        return dict(self._connection_tracker)

    def detect_anomalies(self) -> List[Dict]:
        """Detect traffic anomalies."""
        anomalies = []

        # Check for data exfiltration (large outbound transfers)
        for key, conn in self._connection_tracker.items():
            if conn['bytes_sent'] > 100 * 1024 * 1024:  # > 100MB
                anomalies.append({
                    'type': 'data_exfiltration',
                    'severity': 'high',
                    'connection': key,
                    'bytes': conn['bytes_sent'],
                    'destination': f"{conn['destination_ip']}:{conn['destination_port']}"
                })

            # Check for port scanning behavior
            if conn['connection_count'] > 100:
                anomalies.append({
                    'type': 'port_scan',
                    'severity': 'medium',
                    'connection': key,
                    'attempts': conn['connection_count'],
                    'source': conn['source_ip']
                })

        return anomalies


class FirewallManager:
    """Manages firewall rules across different platforms."""

    def __init__(self, config):
        """Initialize firewall manager."""
        self.config = config
        self._platform = self._detect_platform()
        self._policy = NetworkPolicy(config)

    def _detect_platform(self) -> str:
        """Detect the current platform."""
        import platform
        system = platform.system().lower()

        if system == 'linux':
            return 'linux'
        elif system == 'darwin':
            return 'macos'
        elif system == 'windows':
            return 'windows'
        else:
            return 'unknown'

    def apply_rule(self, rule: FirewallRule) -> bool:
        """Apply a firewall rule to the system."""
        if self._platform == 'linux':
            return self._apply_linux_rule(rule)
        elif self._platform == 'macos':
            return self._apply_macos_rule(rule)
        elif self._platform == 'windows':
            return self._apply_windows_rule(rule)
        else:
            logger.warning(f"Firewall management not supported on: {self._platform}")
            return False

    def _apply_linux_rule(self, rule: FirewallRule) -> bool:
        """Apply rule using iptables."""
        try:
            cmd = ['sudo', 'iptables']

            # Add rule
            cmd.extend(['-A', 'INPUT' if rule.direction == Direction.INBOUND else 'OUTPUT'])

            # Protocol
            if rule.protocol != Protocol.ANY:
                cmd.extend(['-p', rule.protocol.value])

            # Source
            if '/' in rule.source.address:  # CIDR
                cmd.extend(['-s', rule.source.address])
            else:
                cmd.extend(['-s', rule.source.address])

            if rule.source.port:
                cmd.extend(['--sport', str(rule.source.port)])

            # Destination
            if '/' in rule.destination.address:
                cmd.extend(['-d', rule.destination.address])
            else:
                cmd.extend(['-d', rule.destination.address])

            if rule.destination.port:
                cmd.extend(['--dport', str(rule.destination.port)])

            # Action
            if rule.action == ActionType.ALLOW:
                cmd.append('-j ACCEPT')
            elif rule.action == ActionType.DENY:
                cmd.append('-j DROP')
            elif rule.action == ActionType.REJECT:
                cmd.append('-j REJECT')
            elif rule.action == ActionType.LOG:
                cmd.extend(['-j', 'LOG'])

            # Execute
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                logger.error(f"iptables failed: {result.stderr}")
                return False

            return True

        except Exception as e:
            logger.error(f"Failed to apply Linux firewall rule: {e}")
            return False

    def _apply_macos_rule(self, rule: FirewallRule) -> bool:
        """Apply rule using pfctl (macOS)."""
        try:
            # macOS uses pfctl, which requires a different approach
            # This is a simplified version
            logger.info(f"macOS firewall rule (requires manual configuration): {rule.name}")
            return True
        except Exception as e:
            logger.error(f"Failed to apply macOS firewall rule: {e}")
            return False

    def _apply_windows_rule(self, rule: FirewallRule) -> bool:
        """Apply rule using Windows Firewall."""
        try:
            cmd = [
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule.name}',
                f'dir={rule.direction.value}',
                f'action={rule.action.value}',
                f'protocol={rule.protocol.value}'
            ]

            if rule.source.address:
                cmd.append(f'remoteip={rule.source.address}')

            if rule.destination.port:
                cmd.append(f'localport={rule.destination.port}')

            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                logger.error(f"Windows firewall failed: {result.stderr}")
                return False

            return True

        except Exception as e:
            logger.error(f"Failed to apply Windows firewall rule: {e}")
            return False

    def flush_rules(self):
        """Flush all firewall rules."""
        if self._platform == 'linux':
            subprocess.run(['sudo', 'iptables', '-F'], capture_output=True)
        elif self._platform == 'macos':
            subprocess.run(['sudo', 'pfctl', '-F', 'all'], capture_output=True)
        elif self._platform == 'windows':
            subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name=all'],
                         capture_output=True)

        logger.info("Flushed all firewall rules")


class MicroSegmentation:
    """
    Main micro-segmentation controller.
    Manages network policies, traffic monitoring, and firewall rules.
    """

    def __init__(self, config):
        """Initialize micro-segmentation."""
        self.config = config
        self._policy = NetworkPolicy(config)
        self._monitor = TrafficMonitor(config)
        self._firewall = FirewallManager(config)

        # Load existing rules
        self._load_rules()

    def _load_rules(self):
        """Load rules from configuration file."""
        rules_file = self.config.get('microseg.rules_file', './config/firewall_rules.json')

        if Path(rules_file).exists():
            try:
                with open(rules_file, 'r') as f:
                    rules_data = json.load(f)

                for rule_data in rules_data.get('rules', []):
                    rule = FirewallRule.from_dict(rule_data)
                    self._policy.add_rule(rule)

                logger.info(f"Loaded {len(self._policy.get_rules())} firewall rules")

            except Exception as e:
                logger.error(f"Failed to load firewall rules: {e}")

    def create_segment(self, name: str, cidr: str,
                      allowed_destinations: List[Dict]) -> bool:
        """
        Create a network segment with specific allowed destinations.

        Args:
            name: Segment name
            cidr: CIDR block for the segment
            allowed_destinations: List of allowed destination configs

        Returns:
            True if successful
        """
        import uuid

        # Create default deny rule for the segment
        deny_rule = FirewallRule(
            id=f"seg_deny_{uuid.uuid4().hex[:8]}",
            name=f"{name} - Default Deny",
            description=f"Default deny for segment {name}",
            source=NetworkEndpoint(address=cidr),
            destination=NetworkEndpoint(address="0.0.0.0/0"),
            action=ActionType.DENY,
            direction=Direction.OUTBOUND,
            protocol=Protocol.ANY,
            enabled=True,
            created_at=datetime.now().isoformat(),
            updated_at=datetime.now().isoformat()
        )

        self._policy.add_rule(deny_rule)

        # Create allow rules for each destination
        for dest in allowed_destinations:
            allow_rule = FirewallRule(
                id=f"seg_allow_{uuid.uuid4().hex[:8]}",
                name=f"{name} - Allow {dest.get('name', 'Destination')}",
                description=f"Allow traffic to {dest.get('address')}",
                source=NetworkEndpoint(address=cidr),
                destination=NetworkEndpoint(
                    address=dest['address'],
                    port=dest.get('port'),
                    protocol=Protocol(dest.get('protocol', 'tcp'))
                ),
                action=ActionType.ALLOW,
                direction=Direction.OUTBOUND,
                protocol=Protocol(dest.get('protocol', 'tcp')),
                enabled=True,
                created_at=datetime.now().isoformat(),
                updated_at=datetime.now().isoformat()
            )

            self._policy.add_rule(allow_rule)
            self._firewall.apply_rule(allow_rule)

        logger.info(f"Created network segment: {name} ({cidr})")
        return True

    def check_connection(self, source_ip: str, source_port: int,
                        destination_ip: str, destination_port: int,
                        protocol: str) -> Tuple[bool, Optional[str]]:
        """
        Check if a connection is allowed.

        Args:
            source_ip: Source IP address
            source_port: Source port
            destination_ip: Destination IP address
            destination_port: Destination port
            protocol: Protocol

        Returns:
            Tuple of (allowed, rule_id)
        """
        direction = Direction.OUTBOUND
        action, rule_id = self._policy.check_traffic(
            source_ip, source_port,
            destination_ip, destination_port,
            protocol, direction
        )

        # Create event
        event = TrafficEvent(
            timestamp=datetime.now().isoformat(),
            source_ip=source_ip,
            source_port=source_port,
            destination_ip=destination_ip,
            destination_port=destination_port,
            protocol=protocol,
            direction=direction,
            action_taken=action,
            rule_matched=rule_id,
            bytes_transferred=0
        )

        self._monitor.record_event(event)

        if action == ActionType.DENY or action == ActionType.REJECT:
            logger.warning(f"Connection denied: {source_ip}:{source_port} -> {destination_ip}:{destination_port}")
            return False, rule_id

        return True, rule_id

    def get_traffic_summary(self) -> Dict:
        """Get traffic monitoring summary."""
        events = self._monitor.get_events(limit=10000)

        # Calculate statistics
        total_bytes = sum(e.bytes_transferred for e in events)
        denied_count = sum(1 for e in events if e.action_taken == ActionType.DENY)
        unique_destinations = set(f"{e.destination_ip}:{e.destination_port}" for e in events)

        return {
            'total_events': len(events),
            'total_bytes': total_bytes,
            'denied_connections': denied_count,
            'unique_destinations': len(unique_destinations),
            'active_rules': len(self._policy.get_rules()),
            'anomalies': self._monitor.detect_anomalies()
        }

    def export_rules(self, output_file: str = None) -> str:
        """Export firewall rules to JSON."""
        rules = [r.to_dict() for r in self._policy.get_rules()]

        output = json.dumps({
            'version': '1.0',
            'exported_at': datetime.now().isoformat(),
            'rules': rules
        }, indent=2)

        if output_file:
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, 'w') as f:
                f.write(output)
            logger.info(f"Exported rules to: {output_file}")

        return output

    def import_rules(self, rules_json: str, apply: bool = False) -> int:
        """Import firewall rules from JSON."""
        data = json.loads(rules_json)
        count = 0

        for rule_data in data.get('rules', []):
            rule = FirewallRule.from_dict(rule_data)
            self._policy.add_rule(rule)

            if apply:
                self._firewall.apply_rule(rule)

            count += 1

        logger.info(f"Imported {count} firewall rules")
        return count
