"""
OpenClaw Security Shield
A comprehensive security protection system for OpenClaw
"""

__version__ = "1.1.0"
__author__ = "OpenClaw Security Team"
__email__ = "security@openclaw.ai"

# Core modules
from .shield import SecurityShield
from .scanner import SkillScanner
from .monitor import NetworkMonitor
from .api_protection import APIKeyProtection
from .audit import SecurityAuditor

# Phase 1: Basic enhancements
from .asset_manager import AssetManager, AssetDiscovery, AssetInventory
from .process_monitor import ProcessMonitor, ProcessAuditor

# Phase 2: AI traffic analysis (Second防线)
from .ai_analyzer import AIAnalyzer, LLMProviderDetector
from .prompt_guard import PromptGuard, AdaptivePromptGuard
from .content_audit import ContentAuditor, FileContentAuditor
from .llm_adapter import LLMAdapterFactory, UnifiedLLMClient
from .traffic_decrypt import SSLInspector, SSLMITMProxy, CertificateAuthority

# Phase 4: Third防线
from .access_control import AccessController, Capability
from .av_engine import AVEngine, QuarantineManager
from .microseg import MicroSegmentation, FirewallManager
from .network_sync import NetworkSync, ThreatIntel

__all__ = [
    # Core
    "SecurityShield",
    "SkillScanner",
    "NetworkMonitor",
    "APIKeyProtection",
    "SecurityAuditor",
    # Phase 1
    "AssetManager",
    "AssetDiscovery",
    "AssetInventory",
    "ProcessMonitor",
    "ProcessAuditor",
    # Phase 2
    "AIAnalyzer",
    "LLMProviderDetector",
    "PromptGuard",
    "AdaptivePromptGuard",
    "ContentAuditor",
    "FileContentAuditor",
    "LLMAdapterFactory",
    "UnifiedLLMClient",
    "SSLInspector",
    "SSLMITMProxy",
    "CertificateAuthority",
    # Phase 4
    "AccessController",
    "Capability",
    "AVEngine",
    "QuarantineManager",
    "MicroSegmentation",
    "FirewallManager",
    "NetworkSync",
    "ThreatIntel",
]
