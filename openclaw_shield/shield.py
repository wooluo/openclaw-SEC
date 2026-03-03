"""
Main Security Shield Module
Orchestrates all security components
"""

import os
import json
import asyncio
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from loguru import logger

from .scanner import SkillScanner
from .monitor import NetworkMonitor
from .api_protection import APIKeyProtection
from .audit import SecurityAuditor
from .config import Config
from .threats import ThreatDetector


class SecurityShield:
    """
    Main security shield class that orchestrates all security components.
    Provides a unified interface for protecting OpenClaw installations.
    """

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the Security Shield.

        Args:
            config_path: Path to configuration file
        """
        self.console = Console()
        self.config = Config(config_path)

        # Initialize components
        self.scanner = SkillScanner(self.config)
        self.monitor = NetworkMonitor(self.config)
        self.api_protection = APIKeyProtection(self.config)
        self.auditor = SecurityAuditor(self.config)
        self.threat_detector = ThreatDetector(self.config)

        # Setup logging
        self._setup_logging()

        # State tracking
        self._monitoring_active = False
        self._threats_detected = []
        self._quarantine_dir = Path(self.config.get("security.quarantine_dir", "./quarantine"))
        self._quarantine_dir.mkdir(parents=True, exist_ok=True)

        logger.info("OpenClaw Security Shield initialized")

    def _setup_logging(self):
        """Configure logging based on config settings."""
        log_level = self.config.get("logging.level", "INFO")
        log_file = self.config.get("logging.file", "./logs/security.log")

        # Create log directory if needed
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)

        # Configure loguru
        logger.add(
            log_file,
            level=log_level,
            rotation="100 MB",
            retention="90 days",
            compression="zip",
            format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {message}"
        )

    def scan_skill(self, skill_path: str) -> Dict[str, Any]:
        """
        Scan a single skill for security threats.

        Args:
            skill_path: Path to the skill file or directory

        Returns:
            Scan results dictionary
        """
        logger.info(f"Scanning skill: {skill_path}")

        # Perform comprehensive scan
        results = {
            "path": skill_path,
            "timestamp": datetime.now().isoformat(),
            "threats": [],
            "risk_level": "LOW",
            "recommendations": [],
            "passed": True
        }

        try:
            # Static analysis
            static_results = self.scanner.scan_file(skill_path)
            results["static_analysis"] = static_results

            # Threat detection
            threats = self.threat_detector.analyze(skill_path, static_results)
            results["threats"] = threats

            # Calculate risk level
            results["risk_level"] = self._calculate_risk_level(threats)

            # Generate recommendations
            results["recommendations"] = self._generate_recommendations(threats)

            # Determine if passed
            results["passed"] = results["risk_level"] in ["LOW", "MEDIUM"]

            # Log results
            self.auditor.log_scan_result(results)

            if not results["passed"]:
                logger.warning(f"Skill {skill_path} failed security scan: {results['risk_level']}")
                if self.config.get("security.block_malicious", True):
                    self._quarantine_skill(skill_path)

        except Exception as e:
            logger.error(f"Error scanning skill {skill_path}: {e}")
            results["error"] = str(e)
            results["passed"] = False

        return results

    def scan_all_skills(self, skills_dir: str) -> Dict[str, Any]:
        """
        Scan all skills in a directory.

        Args:
            skills_dir: Path to skills directory

        Returns:
            Aggregate scan results
        """
        logger.info(f"Scanning all skills in: {skills_dir}")

        skills_path = Path(skills_dir)
        if not skills_path.exists():
            raise FileNotFoundError(f"Skills directory not found: {skills_dir}")

        results = {
            "directory": skills_dir,
            "timestamp": datetime.now().isoformat(),
            "total_skills": 0,
            "scanned": 0,
            "passed": 0,
            "failed": 0,
            "quarantined": 0,
            "skill_results": [],
            "summary": {}
        }

        # Find all skill files
        skill_files = list(skills_path.rglob("*.py")) + list(skills_path.rglob("*.js"))
        results["total_skills"] = len(skill_files)

        # Scan each skill
        for skill_file in skill_files:
            scan_result = self.scan_skill(str(skill_file))
            results["skill_results"].append(scan_result)
            results["scanned"] += 1

            if scan_result["passed"]:
                results["passed"] += 1
            else:
                results["failed"] += 1
                if scan_result.get("quarantined"):
                    results["quarantined"] += 1

        # Generate summary
        results["summary"] = self._generate_summary(results["skill_results"])

        # Display results
        self._display_scan_report(results)

        return results

    def start_monitoring(self):
        """Start real-time security monitoring."""
        logger.info("Starting security monitoring...")
        self._monitoring_active = True

        try:
            # Start network monitoring
            asyncio.create_task(self.monitor.start())

            # Start file system monitoring
            asyncio.create_task(self._monitor_skills_directory())

            # Start API key monitoring
            asyncio.create_task(self.api_protection.monitor())

            logger.info("Security monitoring active")
            self.console.print("[green]✓ Security monitoring started[/green]")

        except Exception as e:
            logger.error(f"Failed to start monitoring: {e}")
            raise

    def stop_monitoring(self):
        """Stop security monitoring."""
        logger.info("Stopping security monitoring...")
        self._monitoring_active = False
        self.console.print("[yellow]✗ Security monitoring stopped[/yellow]")

    async def _monitor_skills_directory(self):
        """Monitor skills directory for changes."""
        skills_dir = Path(self.config.get("skills.directory", "~/.openclaw/workspace/skills"))
        skills_dir = skills_dir.expanduser()

        if not skills_dir.exists():
            logger.warning(f"Skills directory not found: {skills_dir}")
            return

        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileModifiedEvent

        class SkillEventHandler(FileSystemEventHandler):
            def __init__(self, shield):
                self.shield = shield

            def on_created(self, event):
                if not event.is_directory and event.src_path.endswith(('.py', '.js')):
                    logger.info(f"New skill detected: {event.src_path}")
                    result = self.shield.scan_skill(event.src_path)
                    if not result["passed"]:
                        self.shield.console.print(
                            f"[red]⚠ Malicious skill blocked: {event.src_path}[/red]"
                        )

            def on_modified(self, event):
                if not event.is_directory and event.src_path.endswith(('.py', '.js')):
                    logger.info(f"Skill modified: {event.src_path}")
                    self.shield.scan_skill(event.src_path)

        event_handler = SkillEventHandler(self)
        observer = Observer()
        observer.schedule(event_handler, str(skills_dir), recursive=True)
        observer.start()

        while self._monitoring_active:
            await asyncio.sleep(1)

        observer.stop()
        observer.join()

    def _calculate_risk_level(self, threats: List[Dict]) -> str:
        """Calculate overall risk level from detected threats."""
        if not threats:
            return "LOW"

        severity_weights = {
            "CRITICAL": 100,
            "HIGH": 50,
            "MEDIUM": 20,
            "LOW": 5,
            "INFO": 1
        }

        total_score = sum(severity_weights.get(t.get("severity", "LOW"), 5) for t in threats)

        if total_score >= 100:
            return "CRITICAL"
        elif total_score >= 50:
            return "HIGH"
        elif total_score >= 20:
            return "MEDIUM"
        else:
            return "LOW"

    def _generate_recommendations(self, threats: List[Dict]) -> List[str]:
        """Generate security recommendations based on detected threats."""
        recommendations = []

        for threat in threats:
            if threat.get("type") == "code_execution":
                recommendations.append("Remove or sandbox code execution functions (eval, exec)")
            elif threat.get("type") == "reverse_shell":
                recommendations.append("CRITICAL: Remove network connection code immediately")
            elif threat.get("type") == "data_exfiltration":
                recommendations.append("Review and restrict data collection practices")
            elif threat.get("type") == "api_key_leak":
                recommendations.append("Move API keys to environment variables or secure storage")
            elif threat.get("type") == "unsafe_import":
                recommendations.append(f"Review import: {threat.get('detail', 'unknown')}")

        return list(set(recommendations))  # Remove duplicates

    def _quarantine_skill(self, skill_path: str):
        """Move a malicious skill to quarantine."""
        import shutil

        src = Path(skill_path)
        if not src.exists():
            return

        dest = self._quarantine_dir / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{src.name}"

        try:
            shutil.move(str(src), str(dest))
            logger.warning(f"Skill quarantined: {skill_path} -> {dest}")
            self.console.print(f"[yellow]Skill quarantined: {skill_path}[/yellow]")
        except Exception as e:
            logger.error(f"Failed to quarantine skill: {e}")

    def _generate_summary(self, skill_results: List[Dict]) -> Dict:
        """Generate a summary of scan results."""
        threat_counts = {}
        for result in skill_results:
            for threat in result.get("threats", []):
                threat_type = threat.get("type", "unknown")
                threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1

        return {
            "total_threats": sum(threat_counts.values()),
            "threat_breakdown": threat_counts,
            "risk_distribution": {
                "critical": sum(1 for r in skill_results if r["risk_level"] == "CRITICAL"),
                "high": sum(1 for r in skill_results if r["risk_level"] == "HIGH"),
                "medium": sum(1 for r in skill_results if r["risk_level"] == "MEDIUM"),
                "low": sum(1 for r in skill_results if r["risk_level"] == "LOW"),
            }
        }

    def _display_scan_report(self, results: Dict):
        """Display a formatted scan report."""
        self.console.print("\n")
        self.console.print(Panel.fit(
            "[bold cyan]OpenClaw Security Shield - Scan Report[/bold cyan]",
            border_style="cyan"
        ))

        # Summary table
        table = Table(title="Scan Summary", show_header=True, header_style="bold magenta")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("Total Skills", str(results["total_skills"]))
        table.add_row("Scanned", str(results["scanned"]))
        table.add_row("Passed", str(results["passed"]))
        table.add_row("Failed", str(results["failed"]))
        table.add_row("Quarantined", str(results["quarantined"]))

        self.console.print(table)

        # Threat breakdown
        if results["summary"]["total_threats"] > 0:
            threat_table = Table(title="Threat Breakdown", show_header=True)
            threat_table.add_column("Threat Type", style="red")
            threat_table.add_column("Count", style="yellow")

            for threat_type, count in results["summary"]["threat_breakdown"].items():
                threat_table.add_row(threat_type, str(count))

            self.console.print(threat_table)

        # Failed skills
        failed_skills = [r for r in results["skill_results"] if not r["passed"]]
        if failed_skills:
            self.console.print("\n[bold red]Failed Skills:[/bold red]")
            for skill in failed_skills:
                self.console.print(f"  • {skill['path']} - [{skill['risk_level']}]")

        self.console.print("\n")

    def generate_report(self, output_format: str = "text") -> str:
        """
        Generate a comprehensive security report.

        Args:
            output_format: Output format (text, json, html)

        Returns:
            Formatted report string
        """
        return self.auditor.generate_report(output_format)

    def get_status(self) -> Dict[str, Any]:
        """Get current security status."""
        return {
            "monitoring_active": self._monitoring_active,
            "threats_detected": len(self._threats_detected),
            "quarantine_dir": str(self._quarantine_dir),
            "config": self.config.to_dict(),
            "components": {
                "scanner": "active",
                "monitor": "active" if self._monitoring_active else "inactive",
                "api_protection": "active",
                "auditor": "active"
            }
        }
