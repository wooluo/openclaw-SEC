"""
API Key Protection Module
Protects API keys from leakage and unauthorized access
"""

import os
import re
import hashlib
import asyncio
from typing import Dict, List, Optional, Set
from pathlib import Path
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from loguru import logger


class APIKeyProtection:
    """
    Protects API keys used by OpenClaw from leakage and unauthorized access.
    Provides encryption, rotation, and monitoring capabilities.
    """

    # Common API key patterns
    API_KEY_PATTERNS = [
        # OpenAI
        (r'sk-[a-zA-Z0-9]{20,}', 'OpenAI API Key'),
        (r'sk-proj-[a-zA-Z0-9]{20,}', 'OpenAI Project Key'),

        # Anthropic
        (r'sk-ant-[a-zA-Z0-9]{20,}', 'Anthropic API Key'),

        # Generic patterns
        (r'api[_-]?key[_-]?[a-zA-Z0-9]{16,}', 'Generic API Key'),
        (r'[a-zA-Z0-9]{32,}', 'Possible API Key'),

        # AWS
        (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
        (r'aws[_-]?secret[_-]?access[_-]?key', 'AWS Secret Key'),

        # Other services
        (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Personal Token'),
        (r'gho_[a-zA-Z0-9]{36}', 'GitHub OAuth Token'),
        (r'glpat-[a-zA-Z0-9]{20,}', 'GitLab Personal Token'),
    ]

    def __init__(self, config):
        """Initialize API key protection."""
        self.config = config
        self._encrypted_keys = {}
        self._key_hashes = {}
        self._rotation_schedule = {}
        self._access_log = []
        self._leak_alerts = []
        self._monitoring = False

        # Initialize encryption
        self._init_encryption()

    def _init_encryption(self):
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

        # Log rotation
        self._log_access(name, 'rotate', {'old_hash': old_hash[:16] + '...'})

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

    async def monitor(self):
        """Start monitoring for API key leaks."""
        logger.info("Starting API key leak monitoring...")
        self._monitoring = True

        while self._monitoring:
            try:
                # Check for key rotation
                await self._check_rotation()

                # Check environment for leaked keys
                self._check_environment()

                # Check recent files for leaked keys
                await self._check_recent_files()

                await asyncio.sleep(60)  # Check every minute

            except Exception as e:
                logger.error(f"Error in API key monitoring: {e}")
                await asyncio.sleep(60)

    async def _check_rotation(self):
        """Check if any keys need rotation."""
        now = datetime.now()

        for name, rotation_time in list(self._rotation_schedule.items()):
            if now >= rotation_time:
                logger.warning(f"API key {name} is due for rotation")
                self._leak_alerts.append({
                    'type': 'rotation_due',
                    'severity': 'MEDIUM',
                    'message': f"API key {name} is due for rotation",
                    'timestamp': now.isoformat()
                })

                # Reschedule
                rotation_interval = self.config.get('api_key.rotation_interval', 86400)
                self._rotation_schedule[name] = now + timedelta(seconds=rotation_interval)

    def _check_environment(self):
        """Check environment variables for leaked keys."""
        for env_var, value in os.environ.items():
            self._check_for_leak(value, f"environment:{env_var}")

    async def _check_recent_files(self):
        """Check recent files for leaked keys."""
        # Check common locations where keys might be leaked
        check_paths = [
            Path.home() / '.openclaw',
            Path('./logs'),
            Path('./config'),
        ]

        for path in check_paths:
            if path.exists():
                for file in path.rglob('*'):
                    if file.is_file() and file.suffix in ['.log', '.txt', '.json', '.yaml', '.yml']:
                        try:
                            with open(file, 'r', errors='ignore') as f:
                                content = f.read()
                                self._check_for_leak(content, str(file))
                        except Exception:
                            pass

    def _check_for_leak(self, content: str, location: str):
        """Check content for API key leaks."""
        for pattern, key_type in self.API_KEY_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)

            for match in matches:
                # Check if this matches one of our stored keys
                matched_key = match.group(0)

                for name, key_hash in self._key_hashes.items():
                    if hashlib.sha256(matched_key.encode()).hexdigest() == key_hash:
                        alert = {
                            'type': 'key_leak',
                            'severity': 'CRITICAL',
                            'message': f"API key leak detected: {name}",
                            'location': location,
                            'key_type': key_type,
                            'timestamp': datetime.now().isoformat()
                        }
                        self._leak_alerts.append(alert)
                        logger.critical(f"API KEY LEAK DETECTED: {name} in {location}")

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
                        matches = re.finditer(pattern, content, re.IGNORECASE)

                        for match in matches:
                            results['leaks_found'].append({
                                'file': str(file),
                                'line': content[:match.start()].count('\n') + 1,
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
