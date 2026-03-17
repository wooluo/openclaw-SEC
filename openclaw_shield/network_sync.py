"""
Network Sync Module
Endpoint-network integration for syncing threat data with network security systems,
receiving threat intelligence feeds, and automated incident response coordination.
"""

import json
import asyncio
import aiohttp
import hashlib
import hmac
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
from loguru import logger
from pathlib import Path


class SyncDirection(Enum):
    """Direction of synchronization."""
    PUSH = "push"  # Send data to external system
    PULL = "pull"  # Receive data from external system
    BIDIRECTIONAL = "bidirectional"


class SyncStatus(Enum):
    """Status of synchronization."""
    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL = "partial"
    PENDING = "pending"


class ThreatIntelFormat(Enum):
    """Threat intelligence feed formats."""
    STIX = "stix"
    TAXII = "taxii"
    MISP = "misp"
    CSV = "csv"
    JSON = "json"
    OPENIOC = "openioc"


@dataclass
class ThreatIntel:
    """Threat intelligence data."""
    id: str
    type: str  # 'ip', 'domain', 'url', 'hash', 'email', etc.
    value: str
    severity: str
    confidence: float
    source: str
    description: str
    tags: List[str]
    first_seen: str
    last_seen: str
    expires_at: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict) -> 'ThreatIntel':
        """Create from dictionary."""
        return cls(**data)

    def is_expired(self) -> bool:
        """Check if threat intel has expired."""
        if not self.expires_at:
            return False

        expires = datetime.fromisoformat(self.expires_at)
        return datetime.now() > expires


@dataclass
class SyncEvent:
    """Represents a synchronization event."""
    id: str
    timestamp: str
    direction: SyncDirection
    target: str  # External system identifier
    status: SyncStatus
    items_synced: int
    error_message: Optional[str] = None
    duration_ms: Optional[int] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        d = asdict(self)
        d['direction'] = self.direction.value
        d['status'] = self.status.value
        return d


@dataclass
class IncidentResponse:
    """Automated incident response action."""
    id: str
    incident_id: str
    action_type: str  # 'block_ip', 'isolate_host', 'block_domain', etc.
    target: str
    status: str  # 'pending', 'executed', 'failed'
    created_at: str
    executed_at: Optional[str] = None
    result: Optional[str] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)


class NetworkSecuritySystem:
    """Base class for network security system integrations."""

    def __init__(self, config: Dict):
        """Initialize the network security system."""
        self.name = config.get('name', 'unknown')
        self.api_endpoint = config.get('api_endpoint')
        self.api_key = config.get('api_key')
        self.verify_ssl = config.get('verify_ssl', True)
        self.timeout = config.get('timeout', 30)

    async def push_threat(self, threat: ThreatIntel) -> bool:
        """Push threat intel to the system."""
        raise NotImplementedError

    async def pull_threats(self) -> List[ThreatIntel]:
        """Pull threat intel from the system."""
        raise NotImplementedError

    async def execute_response(self, response: IncidentResponse) -> bool:
        """Execute an incident response action."""
        raise NotImplementedError


class SIEMIntegration(NetworkSecuritySystem):
    """Integration with SIEM systems (Splunk, QRadar, etc.)."""

    def __init__(self, config):
        """Initialize SIEM integration."""
        super().__init__(config)
        self.siem_type = config.get('siem_type', 'generic')
        self.index = config.get('index', 'security_events')

    async def push_threat(self, threat: ThreatIntel) -> bool:
        """Push threat intel to SIEM."""
        try:
            async with aiohttp.ClientSession() as session:
                # Format for SIEM
                event = {
                    'index': self.index,
                    'sourcetype': 'openclaw:threat',
                    'event': threat.to_dict(),
                    'timestamp': datetime.now().isoformat()
                }

                headers = {
                    'Authorization': f'Bearer {self.api_key}',
                    'Content-Type': 'application/json'
                }

                async with session.post(
                    self.api_endpoint,
                    json=event,
                    headers=headers,
                    verify_ssl=self.verify_ssl,
                    timeout=self.timeout
                ) as response:
                    return response.status == 200

        except Exception as e:
            logger.error(f"Failed to push to SIEM: {e}")
            return False

    async def pull_threats(self) -> List[ThreatIntel]:
        """Pull threat intel from SIEM."""
        # SIEMs typically don't provide threat intel feeds
        return []

    async def execute_response(self, response: IncidentResponse) -> bool:
        """Execute incident response via SIEM."""
        # SIEMs typically trigger responses, not execute them directly
        return True


class FirewallIntegration(NetworkSecuritySystem):
    """Integration with firewall systems (Palo Alto, Cisco, Fortinet, etc.)."""

    def __init__(self, config):
        """Initialize firewall integration."""
        super().__init__(config)
        self.firewall_type = config.get('firewall_type', 'generic')
        self.rule_prefix = config.get('rule_prefix', 'OC-')

    async def push_threat(self, threat: ThreatIntel) -> bool:
        """Push threat intel to firewall."""
        try:
            async with aiohttp.ClientSession() as session:
                if threat.type == 'ip':
                    # Block IP address
                    rule = {
                        'name': f"{self.rule_prefix}{threat.id[:8]}",
                        'source': threat.value,
                        'action': 'deny',
                        'description': f"Block {threat.type} from {threat.source}: {threat.description}"
                    }

                    headers = {
                        'X-API-Key': self.api_key,
                        'Content-Type': 'application/json'
                    }

                    async with session.post(
                        f"{self.api_endpoint}/rules",
                        json=rule,
                        headers=headers,
                        verify_ssl=self.verify_ssl,
                        timeout=self.timeout
                    ) as response:
                        return response.status == 200 or response.status == 201

                elif threat.type == 'domain':
                    # Block domain
                    rule = {
                        'name': f"{self.rule_prefix}{threat.id[:8]}",
                        'destination': threat.value,
                        'action': 'deny',
                        'description': f"Block {threat.type} from {threat.source}: {threat.description}"
                    }

                    headers = {
                        'X-API-Key': self.api_key,
                        'Content-Type': 'application/json'
                    }

                    async with session.post(
                        f"{self.api_endpoint}/rules",
                        json=rule,
                        headers=headers,
                        verify_ssl=self.verify_ssl,
                        timeout=self.timeout
                    ) as response:
                        return response.status == 200 or response.status == 201

            return False

        except Exception as e:
            logger.error(f"Failed to push to firewall: {e}")
            return False

    async def pull_threats(self) -> List[ThreatIntel]:
        """Pull threat intel from firewall."""
        try:
            async with aiohttp.ClientSession() as session:
                headers = {
                    'X-API-Key': self.api_key,
                    'Content-Type': 'application/json'
                }

                async with session.get(
                    f"{self.api_endpoint}/threats",
                    headers=headers,
                    verify_ssl=self.verify_ssl,
                    timeout=self.timeout
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        threats = []
                        for item in data.get('threats', []):
                            threats.append(ThreatIntel.from_dict(item))
                        return threats

        except Exception as e:
            logger.error(f"Failed to pull from firewall: {e}")

        return []

    async def execute_response(self, response: IncidentResponse) -> bool:
        """Execute incident response on firewall."""
        try:
            async with aiohttp.ClientSession() as session:
                headers = {
                    'X-API-Key': self.api_key,
                    'Content-Type': 'application/json'
                }

                action_data = {
                    'action': response.action_type,
                    'target': response.target
                }

                async with session.post(
                    f"{self.api_endpoint}/responses",
                    json=action_data,
                    headers=headers,
                    verify_ssl=self.verify_ssl,
                    timeout=self.timeout
                ) as resp:
                    return resp.status == 200

        except Exception as e:
            logger.error(f"Failed to execute firewall response: {e}")
            return False


class ThreatIntelFeed:
    """Threat intelligence feed integration."""

    def __init__(self, config):
        """Initialize threat intel feed."""
        self.url = config.get('url')
        self.format = ThreatIntelFormat(config.get('format', 'json'))
        self.api_key = config.get('api_key')
        self.update_interval = config.get('update_interval', 3600)  # 1 hour
        self._last_update = None
        self._cache: Dict[str, ThreatIntel] = {}

    async def fetch(self) -> List[ThreatIntel]:
        """Fetch threat intelligence from feed."""
        try:
            async with aiohttp.ClientSession() as session:
                headers = {}
                if self.api_key:
                    headers['Authorization'] = f'Bearer {self.api_key}'

                async with session.get(
                    self.url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=60)
                ) as response:
                    if response.status == 200:
                        content_type = response.headers.get('Content-Type', '')

                        if 'json' in content_type:
                            data = await response.json()
                            return self._parse_json(data)
                        else:
                            text = await response.text()
                            return self._parse_text(text)

        except Exception as e:
            logger.error(f"Failed to fetch threat intel: {e}")

        return []

    def _parse_json(self, data: Any) -> List[ThreatIntel]:
        """Parse JSON threat intel."""
        threats = []

        # Handle different JSON formats
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = data.get('indicators', data.get('threats', []))
        else:
            return []

        for item in items:
            try:
                threat = ThreatIntel(
                    id=item.get('id', hashlib.sha256(item.get('value', '').encode()).hexdigest()[:16]),
                    type=item.get('type', 'unknown'),
                    value=item.get('value', ''),
                    severity=item.get('severity', 'medium'),
                    confidence=item.get('confidence', 0.5),
                    source=item.get('source', 'feed'),
                    description=item.get('description', ''),
                    tags=item.get('tags', []),
                    first_seen=item.get('first_seen', datetime.now().isoformat()),
                    last_seen=item.get('last_seen', datetime.now().isoformat()),
                    expires_at=item.get('expires_at')
                )
                threats.append(threat)
            except Exception as e:
                logger.debug(f"Failed to parse threat item: {e}")

        return threats

    def _parse_text(self, text: str) -> List[ThreatIntel]:
        """Parse text-based threat intel (CSV, etc.)."""
        threats = []

        if self.format == ThreatIntelFormat.CSV:
            lines = text.strip().split('\n')
            for line in lines[1:]:  # Skip header
                parts = line.split(',')
                if len(parts) >= 4:
                    threat = ThreatIntel(
                        id=hashlib.sha256(parts[0].encode()).hexdigest()[:16],
                        type=parts[0],
                        value=parts[1],
                        severity=parts[2],
                        confidence=float(parts[3]) if len(parts) > 3 else 0.5,
                        source='feed',
                        description=parts[4] if len(parts) > 4 else '',
                        tags=[],
                        first_seen=datetime.now().isoformat(),
                        last_seen=datetime.now().isoformat()
                    )
                    threats.append(threat)

        return threats

    def should_update(self) -> bool:
        """Check if feed should be updated."""
        if self._last_update is None:
            return True

        elapsed = (datetime.now() - self._last_update).total_seconds()
        return elapsed >= self.update_interval

    def mark_updated(self):
        """Mark feed as updated."""
        self._last_update = datetime.now()


class NetworkSync:
    """
    Main network sync controller.
    Coordinates sync with external security systems and threat intel feeds.
    """

    def __init__(self, config):
        """Initialize network sync."""
        self.config = config
        self._systems: Dict[str, NetworkSecuritySystem] = {}
        self._feeds: Dict[str, ThreatIntelFeed] = {}
        self._sync_events: List[SyncEvent] = []
        self._intel_cache: Dict[str, ThreatIntel] = {}
        self._response_queue: List[IncidentResponse] = []
        self._callbacks: List[Callable] = []

        # Load configurations
        self._load_systems()
        self._load_feeds()

    def _load_systems(self):
        """Load network security system configurations."""
        systems_config = self.config.get('network_sync.systems', [])

        for sys_config in systems_config:
            sys_type = sys_config.get('type', 'generic')

            if sys_type == 'siem':
                system = SIEMIntegration(sys_config)
            elif sys_type == 'firewall':
                system = FirewallIntegration(sys_config)
            else:
                continue

            self._systems[system.name] = system
            logger.info(f"Loaded network security system: {system.name}")

    def _load_feeds(self):
        """Load threat intelligence feed configurations."""
        feeds_config = self.config.get('network_sync.feeds', [])

        for feed_config in feeds_config:
            feed = ThreatIntelFeed(feed_config)
            self._feeds[feed_config.get('name', f'feed_{len(self._feeds)}')] = feed
            logger.info(f"Loaded threat intel feed: {feed_config.get('name', 'unknown')}")

    async def sync_all(self, direction: SyncDirection = SyncDirection.BIDIRECTIONAL) -> Dict[str, SyncEvent]:
        """Synchronize with all configured systems."""
        events = {}

        for name, system in self._systems.items():
            if direction in [SyncDirection.PUSH, SyncDirection.BIDIRECTIONAL]:
                # Push local threats to system
                event = await self._push_to_system(name, system)
                events[f"{name}_push"] = event

            if direction in [SyncDirection.PULL, SyncDirection.BIDIRECTIONAL]:
                # Pull threats from system
                event = await self._pull_from_system(name, system)
                events[f"{name}_pull"] = event

        # Update feeds
        for name, feed in self._feeds.items():
            if feed.should_update():
                await self._update_feed(name, feed)

        return events

    async def _push_to_system(self, name: str, system: NetworkSecuritySystem) -> SyncEvent:
        """Push threat intel to a system."""
        import uuid
        event_id = str(uuid.uuid4())
        start_time = datetime.now()

        try:
            count = 0
            for threat in self._intel_cache.values():
                if not threat.is_expired():
                    if await system.push_threat(threat):
                        count += 1

            duration = int((datetime.now() - start_time).total_seconds() * 1000)

            event = SyncEvent(
                id=event_id,
                timestamp=datetime.now().isoformat(),
                direction=SyncDirection.PUSH,
                target=name,
                status=SyncStatus.SUCCESS,
                items_synced=count,
                duration_ms=duration
            )

        except Exception as e:
            duration = int((datetime.now() - start_time).total_seconds() * 1000)
            event = SyncEvent(
                id=event_id,
                timestamp=datetime.now().isoformat(),
                direction=SyncDirection.PUSH,
                target=name,
                status=SyncStatus.FAILED,
                items_synced=0,
                error_message=str(e),
                duration_ms=duration
            )

        self._sync_events.append(event)
        return event

    async def _pull_from_system(self, name: str, system: NetworkSecuritySystem) -> SyncEvent:
        """Pull threat intel from a system."""
        import uuid
        event_id = str(uuid.uuid4())
        start_time = datetime.now()

        try:
            threats = await system.pull_threats()

            for threat in threats:
                self._intel_cache[threat.id] = threat

            duration = int((datetime.now() - start_time).total_seconds() * 1000)

            event = SyncEvent(
                id=event_id,
                timestamp=datetime.now().isoformat(),
                direction=SyncDirection.PULL,
                target=name,
                status=SyncStatus.SUCCESS,
                items_synced=len(threats),
                duration_ms=duration
            )

        except Exception as e:
            duration = int((datetime.now() - start_time).total_seconds() * 1000)
            event = SyncEvent(
                id=event_id,
                timestamp=datetime.now().isoformat(),
                direction=SyncDirection.PULL,
                target=name,
                status=SyncStatus.FAILED,
                items_synced=0,
                error_message=str(e),
                duration_ms=duration
            )

        self._sync_events.append(event)
        return event

    async def _update_feed(self, name: str, feed: ThreatIntelFeed):
        """Update threat intelligence from feed."""
        try:
            threats = await feed.fetch()

            for threat in threats:
                self._intel_cache[threat.id] = threat

            feed.mark_updated()
            logger.info(f"Updated threat intel feed {name}: {len(threats)} indicators")

            # Trigger callbacks
            for callback in self._callbacks:
                try:
                    callback(threats)
                except Exception as e:
                    logger.error(f"Feed callback error: {e}")

        except Exception as e:
            logger.error(f"Failed to update feed {name}: {e}")

    def add_threat_intel(self, threat: ThreatIntel):
        """Add threat intel to local cache."""
        self._intel_cache[threat.id] = threat

    def check_threat(self, indicator_type: str, value: str) -> Optional[ThreatIntel]:
        """Check if an indicator is known threat."""
        for threat in self._intel_cache.values():
            if threat.type == indicator_type and threat.value == value:
                if not threat.is_expired():
                    return threat
        return None

    def create_incident_response(self, incident_id: str, action_type: str,
                                target: str) -> IncidentResponse:
        """Create an incident response action."""
        import uuid

        response = IncidentResponse(
            id=str(uuid.uuid4()),
            incident_id=incident_id,
            action_type=action_type,
            target=target,
            status='pending',
            created_at=datetime.now().isoformat()
        )

        self._response_queue.append(response)
        return response

    async def execute_responses(self) -> List[IncidentResponse]:
        """Execute queued incident responses."""
        executed = []

        for response in self._response_queue:
            if response.status == 'pending':
                # Execute on all applicable systems
                success = False

                for system in self._systems.values():
                    if await system.execute_response(response):
                        success = True

                response.status = 'executed' if success else 'failed'
                response.executed_at = datetime.now().isoformat()
                executed.append(response)

        # Clear executed responses
        self._response_queue = [r for r in self._response_queue if r.status == 'pending']

        return executed

    def register_callback(self, callback: Callable):
        """Register callback for new threat intel."""
        self._callbacks.append(callback)

    def get_statistics(self) -> Dict:
        """Get sync statistics."""
        total_events = len(self._sync_events)
        successful = sum(1 for e in self._sync_events if e.status == SyncStatus.SUCCESS)
        failed = sum(1 for e in self._sync_events if e.status == SyncStatus.FAILED)

        return {
            'total_events': total_events,
            'successful_syncs': successful,
            'failed_syncs': failed,
            'intel_cache_size': len(self._intel_cache),
            'pending_responses': len(self._response_queue),
            'systems_count': len(self._systems),
            'feeds_count': len(self._feeds)
        }

    def export_intel(self, format: str = 'json') -> str:
        """Export threat intelligence."""
        threats = list(self._intel_cache.values())

        if format == 'json':
            return json.dumps([t.to_dict() for t in threats], indent=2)
        elif format == 'csv':
            lines = ['id,type,value,severity,confidence,source,description']
            for t in threats:
                lines.append(f"{t.id},{t.type},{t.value},{t.severity},{t.confidence},{t.source},{t.description}")
            return '\n'.join(lines)

        return ''
