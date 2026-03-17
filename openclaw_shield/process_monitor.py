"""
Process Monitor Module
Provides real-time process monitoring for runtime security detection.
Tracks process creation, termination, resource usage, and suspicious behavior.
"""

import os
import signal
import time
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Callable, Any
from dataclasses import dataclass, field, asdict
from enum import Enum
from loguru import logger
import threading
import queue

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    logger.error("psutil is required for process monitoring")


class ProcessEventType(Enum):
    """Types of process events."""
    START = "start"
    EXIT = "exit"
    RESOURCE_HIGH = "resource_high"
    SUSPICIOUS = "suspicious"
    PERMISSION_CHANGE = "permission_change"
    NETWORK_ACTIVITY = "network_activity"


class ThreatLevel(Enum):
    """Threat severity levels."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ProcessEvent:
    """Represents a process-related security event."""
    pid: int
    event_type: ProcessEventType
    threat_level: ThreatLevel
    timestamp: str
    process_name: str
    command_line: str
    parent_pid: Optional[int] = None
    details: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class ProcessInfo:
    """Extended information about a process."""
    pid: int
    name: str
    command_line: str
    parent_pid: int
    user: str
    create_time: float
    exe: Optional[str] = None
    cwd: Optional[str] = None
    connections: List[Dict] = field(default_factory=list)
    open_files: List[str] = field(default_factory=list)
    children: List[int] = field(default_factory=list)

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)


class SuspiciousProcessDetector:
    """
    Detects suspicious process behavior based on various indicators.
    """

    # Suspicious process names
    SUSPICIOUS_NAMES = {
        'nc', 'netcat', 'ncat',
        'bash', 'sh', 'zsh', 'dash',
        'powershell', 'cmd.exe',
        'powershell.exe', 'pwsh',
        'python -c', 'perl -e', 'ruby -e',
        'meterpreter', 'msfvenom',
        'socat', 'cryptcat',
    }

    # Suspicious command line patterns
    SUSPICIOUS_PATTERNS = [
        r'nc\s+-[el]',
        r'netcat\s+-[el]',
        r'bash\s+-i',
        r'sh\s+-i',
        r'powershell.*-enc',
        r'powershell.*hidden',
        r'cmd\.exe.*\/c',
        r'python.*-c.*socket',
        r'perl.*-e.*socket',
        r'eval\s*\(',
        r'exec\s*\(',
        r'reverse.*shell',
        r'bind.*shell',
        r'wget.*\|.*sh',
        r'curl.*\|.*bash',
        r'chmod.*777',
        r'chown.*root',
        r'iptables.*flush',
        r'rm\s+-rf\s+/',
    ]

    # Processes that shouldn't normally have network connections
    NO_NETWORK_PROCESSES = {
        'ls', 'cat', 'grep', 'awk', 'sed',
        'vi', 'vim', 'nano',
        'systemctl', 'service',
    }

    # Legitimate system processes (to reduce false positives)
    LEGITIMATE_SYSTEM_PROCESSES = {
        'systemd', 'init', 'kernel_task',
        'launchd', 'Dock', 'WindowServer',
        'sshd', 'cron', 'atd',
    }

    def __init__(self, config):
        """Initialize the detector."""
        self.config = config
        self._whitelist = set(config.get('process_monitor.whitelist', []))
        self._blacklist = set(config.get('process_monitor.blacklist', []))

    def analyze_process(self, process: psutil.Process) -> List[ProcessEvent]:
        """
        Analyze a process for suspicious behavior.

        Args:
            process: psutil Process object

        Returns:
            List of detected events
        """
        events = []

        if not HAS_PSUTIL:
            return events

        try:
            # Get basic info
            pid = process.pid
            name = process.name()
            cmdline = ' '.join(process.cmdline())

            # Check blacklist
            if name in self._blacklist:
                events.append(ProcessEvent(
                    pid=pid,
                    event_type=ProcessEventType.SUSPICIOUS,
                    threat_level=ThreatLevel.CRITICAL,
                    timestamp=datetime.now().isoformat(),
                    process_name=name,
                    command_line=cmdline,
                    details={'reason': 'blacklisted_process'}
                ))

            # Skip whitelisted processes
            if name in self._whitelist or name in self.LEGITIMATE_SYSTEM_PROCESSES:
                return events

            # Check for suspicious names with network connections
            if self._has_suspicious_network(process):
                events.append(ProcessEvent(
                    pid=pid,
                    event_type=ProcessEventType.NETWORK_ACTIVITY,
                    threat_level=ThreatLevel.HIGH,
                    timestamp=datetime.now().isoformat(),
                    process_name=name,
                    command_line=cmdline,
                    details={'reason': 'suspicious_process_with_network'}
                ))

            # Check command line patterns
            import re
            for pattern in self.SUSPICIOUS_PATTERNS:
                if re.search(pattern, cmdline, re.IGNORECASE):
                    events.append(ProcessEvent(
                        pid=pid,
                        event_type=ProcessEventType.SUSPICIOUS,
                        threat_level=ThreatLevel.HIGH,
                        timestamp=datetime.now().isoformat(),
                        process_name=name,
                        command_line=cmdline,
                        details={'pattern': pattern}
                    ))
                    break

            # Check for process injection indicators
            if self._check_process_injection(process):
                events.append(ProcessEvent(
                    pid=pid,
                    event_type=ProcessEventType.SUSPICIOUS,
                    threat_level=ThreatLevel.CRITICAL,
                    timestamp=datetime.now().isoformat(),
                    process_name=name,
                    command_line=cmdline,
                    details={'reason': 'possible_process_injection'}
                ))

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
        except Exception as e:
            logger.debug(f"Error analyzing process: {e}")

        return events

    def _has_suspicious_network(self, process: psutil.Process) -> bool:
        """Check if process has suspicious network activity."""
        try:
            name = process.name().lower()
            connections = process.connections(kind='inet')

            # Check if shell has network connections
            if name in ['bash', 'sh', 'zsh', 'dash'] and connections:
                return True

            # Check processes that shouldn't have network
            if name in self.NO_NETWORK_PROCESSES and connections:
                return True

            return False
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return False

    def _check_process_injection(self, process: psutil.Process) -> bool:
        """Check for signs of process injection."""
        try:
            # Check for opened handles to other processes
            current_pid = process.pid
            for conn in process.connections():
                # Check for connections from unexpected sources
                if conn.raddr and conn.raddr.port in [4444, 5555, 6666, 31337]:
                    return True
            return False
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return False


class ProcessMonitor:
    """
    Real-time process monitoring system.
    Tracks processes and generates security events.
    """

    def __init__(self, config):
        """Initialize the process monitor."""
        if not HAS_PSUTIL:
            raise RuntimeError("psutil is required for process monitoring")

        self.config = config
        self.detector = SuspiciousProcessDetector(config)
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._event_queue: queue.Queue = queue.Queue()
        self._callbacks: List[Callable[[ProcessEvent], None]] = []

        # Tracking state
        self._known_pids: Set[int] = set()
        self._pid_info: Dict[int, ProcessInfo] = {}
        self._event_history: List[ProcessEvent] = []

        # Configuration
        self._scan_interval = config.get('process_monitor.scan_interval', 5.0)
        self._max_history = config.get('process_monitor.max_history', 10000)
        self._track_children = config.get('process_monitor.track_children', True)

    def start(self):
        """Start process monitoring."""
        if self._running:
            logger.warning("Process monitor is already running")
            return

        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        logger.info("Process monitor started")

    def stop(self):
        """Stop process monitoring."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Process monitor stopped")

    def register_callback(self, callback: Callable[[ProcessEvent], None]):
        """Register a callback for process events."""
        self._callbacks.append(callback)

    def get_events(self, limit: int = 100, threat_level: ThreatLevel = None) -> List[ProcessEvent]:
        """Get recent process events."""
        events = self._event_history[-limit:]
        if threat_level:
            events = [e for e in events if e.threat_level == threat_level]
        return events

    def get_process_info(self, pid: int) -> Optional[ProcessInfo]:
        """Get detailed information about a process."""
        return self._pid_info.get(pid)

    def get_all_processes(self) -> List[ProcessInfo]:
        """Get information about all tracked processes."""
        return list(self._pid_info.values())

    def terminate_process(self, pid: int, force: bool = False) -> bool:
        """
        Terminate a process.

        Args:
            pid: Process ID
            force: Use SIGKILL instead of SIGTERM

        Returns:
            True if successful
        """
        try:
            process = psutil.Process(pid)
            if force:
                process.kill()
            else:
                process.terminate()
            logger.info(f"Terminated process {pid} (force={force})")
            return True
        except psutil.NoSuchProcess:
            logger.warning(f"Process {pid} not found")
            return False
        except psutil.AccessDenied:
            logger.error(f"Access denied to terminate process {pid}")
            return False

    def _monitor_loop(self):
        """Main monitoring loop."""
        logger.info("Starting process monitoring loop")

        # Initial scan
        self._scan_processes()

        while self._running:
            try:
                self._scan_processes()
                self._check_resource_usage()
                time.sleep(self._scan_interval)
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(self._scan_interval)

    def _scan_processes(self):
        """Scan all processes and detect new/terminated ones."""
        if not HAS_PSUTIL:
            return

        current_pids = set()
        current_processes = {}

        # Scan all processes
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'ppid', 'username',
                                          'create_time', 'exe', 'cwd']):
            try:
                pinfo = proc.info
                pid = pinfo['pid']
                current_pids.add(pid)

                # Check for new processes
                if pid not in self._known_pids:
                    self._handle_new_process(proc)

                # Update process info
                process_info = self._get_extended_process_info(proc)
                current_processes[pid] = process_info

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Check for terminated processes
        terminated = self._known_pids - current_pids
        for pid in terminated:
            self._handle_terminated_process(pid)

        # Update state
        self._known_pids = current_pids
        self._pid_info = current_processes

    def _get_extended_process_info(self, proc: psutil.Process) -> ProcessInfo:
        """Get extended information about a process."""
        try:
            with proc.oneshot():
                pinfo = proc.info

                # Get network connections
                connections = []
                for conn in proc.connections(kind='inet'):
                    if conn.raddr:
                        connections.append({
                            'remote_address': conn.raddr.ip,
                            'remote_port': conn.raddr.port,
                            'status': conn.status
                        })

                # Get open files
                open_files = []
                try:
                    for file in proc.open_files():
                        open_files.append(file.path)
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

                # Get children
                children = [child.pid for child in proc.children(recursive=False)]

                return ProcessInfo(
                    pid=pinfo['pid'],
                    name=pinfo.get('name', 'unknown'),
                    command_line=' '.join(pinfo.get('cmdline') or []),
                    parent_pid=pinfo.get('ppid', 0),
                    user=pinfo.get('username', 'unknown'),
                    create_time=pinfo.get('create_time', time.time()),
                    exe=pinfo.get('exe'),
                    cwd=pinfo.get('cwd'),
                    connections=connections,
                    open_files=open_files,
                    children=children
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            # Return minimal info
            return ProcessInfo(
                pid=pinfo['pid'],
                name=pinfo.get('name', 'unknown'),
                command_line=' '.join(pinfo.get('cmdline') or []),
                parent_pid=pinfo.get('ppid', 0),
                user=pinfo.get('username', 'unknown'),
                create_time=pinfo.get('create_time', time.time())
            )

    def _handle_new_process(self, proc: psutil.Process):
        """Handle a new process."""
        try:
            pid = proc.pid
            name = proc.name()
            cmdline = ' '.join(proc.cmdline())

            logger.debug(f"New process detected: {pid} - {name}")

            # Analyze for suspicious behavior
            events = self.detector.analyze_process(proc)

            if not events:
                # Create a benign start event
                events = [ProcessEvent(
                    pid=pid,
                    event_type=ProcessEventType.START,
                    threat_level=ThreatLevel.INFO,
                    timestamp=datetime.now().isoformat(),
                    process_name=name,
                    command_line=cmdline,
                    parent_pid=proc.ppid()
                )]

            # Emit events
            for event in events:
                self._emit_event(event)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    def _handle_terminated_process(self, pid: int):
        """Handle a terminated process."""
        logger.debug(f"Process terminated: {pid}")

        # Check if we have info about this process
        info = self._pid_info.get(pid)
        if info:
            event = ProcessEvent(
                pid=pid,
                event_type=ProcessEventType.EXIT,
                threat_level=ThreatLevel.INFO,
                timestamp=datetime.now().isoformat(),
                process_name=info.name,
                command_line=info.command_line,
                parent_pid=info.parent_pid
            )
            self._emit_event(event)

    def _check_resource_usage(self):
        """Check for processes with high resource usage."""
        if not HAS_PSUTIL:
            return

        cpu_threshold = self.config.get('process_monitor.cpu_threshold', 80.0)
        mem_threshold = self.config.get('process_monitor.memory_threshold', 80.0)

        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cpu_percent = proc.cpu_percent(interval=0.1)
                mem_percent = proc.memory_percent()

                if cpu_percent > cpu_threshold or mem_percent > mem_threshold:
                    event = ProcessEvent(
                        pid=proc.pid,
                        event_type=ProcessEventType.RESOURCE_HIGH,
                        threat_level=ThreatLevel.LOW,
                        timestamp=datetime.now().isoformat(),
                        process_name=proc.name(),
                        command_line=' '.join(proc.cmdline()),
                        details={
                            'cpu_percent': cpu_percent,
                            'memory_percent': mem_percent
                        }
                    )
                    self._emit_event(event)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def _emit_event(self, event: ProcessEvent):
        """Emit a process event to callbacks and history."""
        # Add to history
        self._event_history.append(event)
        if len(self._event_history) > self._max_history:
            self._event_history = self._event_history[-self._max_history:]

        # Call callbacks
        for callback in self._callbacks:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Error in event callback: {e}")

        # Log if not info level
        if event.threat_level != ThreatLevel.INFO:
            level = event.threat_level.value.upper()
            logger.log(level.lower(), f"Process event: {event.process_name} ({event.pid}) - {event.event_type.value}")

    def get_statistics(self) -> Dict:
        """Get monitoring statistics."""
        return {
            'running': self._running,
            'tracked_processes': len(self._known_pids),
            'events_recorded': len(self._event_history),
            'scan_interval': self._scan_interval,
            'threat_breakdown': self._get_threat_breakdown()
        }

    def _get_threat_breakdown(self) -> Dict:
        """Get breakdown of events by threat level."""
        breakdown = {level.value: 0 for level in ThreatLevel}
        for event in self._event_history:
            breakdown[event.threat_level.value] += 1
        return breakdown


class ProcessAuditor:
    """
    Audits process behavior and generates security reports.
    """

    def __init__(self, config):
        """Initialize the process auditor."""
        self.config = config

    def audit_process_tree(self, pid: int) -> Dict:
        """
        Audit a process and all its children.

        Args:
            pid: Root process ID

        Returns:
            Audit report
        """
        if not HAS_PSUTIL:
            return {'error': 'psutil not available'}

        try:
            proc = psutil.Process(pid)
            report = {
                'root_process': self._audit_process(proc),
                'children': []
            }

            for child in proc.children(recursive=True):
                report['children'].append(self._audit_process(child))

            return report

        except psutil.NoSuchProcess:
            return {'error': f'Process {pid} not found'}

    def _audit_process(self, proc: psutil.Process) -> Dict:
        """Audit a single process."""
        try:
            with proc.oneshot():
                return {
                    'pid': proc.pid,
                    'name': proc.name(),
                    'exe': proc.exe(),
                    'cwd': proc.cwd(),
                    'cmdline': proc.cmdline(),
                    'ppid': proc.ppid(),
                    'username': proc.username(),
                    'create_time': datetime.fromtimestamp(proc.create_time()).isoformat(),
                    'connections': len(proc.connections()),
                    'open_files': len(proc.open_files()),
                    'threads': proc.num_threads(),
                    'cpu_percent': proc.cpu_percent(),
                    'memory_percent': proc.memory_percent(),
                    'memory_info': {
                        'rss': proc.memory_info().rss,
                        'vms': proc.memory_info().vms
                    }
                }
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            return {'error': str(e)}

    def detect_anomalies(self, baseline: Dict, current: Dict) -> List[Dict]:
        """
        Detect anomalies by comparing current state to baseline.

        Args:
            baseline: Baseline process data
            current: Current process data

        Returns:
            List of detected anomalies
        """
        anomalies = []

        # Compare process count
        baseline_count = baseline.get('process_count', 0)
        current_count = current.get('process_count', 0)

        if abs(current_count - baseline_count) > baseline_count * 0.2:
            anomalies.append({
                'type': 'process_count_change',
                'baseline': baseline_count,
                'current': current_count,
                'severity': 'medium'
            })

        # Compare suspicious processes
        baseline_suspicious = baseline.get('suspicious_processes', [])
        current_suspicious = current.get('suspicious_processes', [])

        new_suspicious = set(current_suspicious) - set(baseline_suspicious)
        if new_suspicious:
            anomalies.append({
                'type': 'new_suspicious_processes',
                'processes': list(new_suspicious),
                'severity': 'high'
            })

        return anomalies
