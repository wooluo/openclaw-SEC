"""
OpenClaw Security Shield
A comprehensive security protection system for OpenClaw
"""

__version__ = "1.0.0"
__author__ = "OpenClaw Security Team"
__email__ = "security@openclaw.ai"

from .shield import SecurityShield
from .scanner import SkillScanner
from .monitor import NetworkMonitor
from .api_protection import APIKeyProtection
from .audit import SecurityAuditor

__all__ = [
    "SecurityShield",
    "SkillScanner",
    "NetworkMonitor",
    "APIKeyProtection",
    "SecurityAuditor",
]
