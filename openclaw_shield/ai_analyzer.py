"""
AI Traffic Analyzer Module
Analyzes AI/LLM API traffic to detect security threats and data leaks.
Supports OpenAI, Anthropic, Gemini, and other major providers.
"""

import json
import re
from datetime import datetime
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from loguru import logger
import hashlib


class LLMProvider(Enum):
    """Supported LLM providers."""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    COHERE = "cohere"
    HUGGINGFACE = "huggingface"
    AZURE = "azure"
    BEDROCK = "bedrock"
    UNKNOWN = "unknown"


class ThreatCategory(Enum):
    """Categories of AI-related threats."""
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    DATA_EXFILTRATION = "data_exfiltration"
    PII_LEAK = "pii_leak"
    MALICIOUS_URL = "malicious_url"
    CODE_INJECTION = "code_injection"
    BIASED_OUTPUT = "biased_output"
    RATE_LIMIT_ABUSE = "rate_limit_abuse"
    TOKEN_LEAK = "token_leak"
    UNKNOWN = "unknown"


@dataclass
class AITrafficEvent:
    """Represents an AI API traffic event."""
    timestamp: str
    provider: LLMProvider
    direction: str  # 'request' or 'response'
    model: str
    content: str
    headers: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    content_hash: str = ""

    def __post_init__(self):
        if not self.content_hash:
            self.content_hash = hashlib.sha256(self.content.encode()).hexdigest()[:16]

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        d = asdict(self)
        d['provider'] = self.provider.value
        return d


@dataclass
class ThreatDetection:
    """Represents a detected threat."""
    timestamp: str
    category: ThreatCategory
    severity: str  # 'critical', 'high', 'medium', 'low'
    confidence: float  # 0.0 to 1.0
    description: str
    evidence: Dict[str, Any]
    model: str
    provider: LLMProvider

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        d = asdict(self)
        d['category'] = self.category.value
        d['provider'] = self.provider.value
        return d


class LLMProviderDetector:
    """Detects the LLM provider from HTTP requests."""

    # Provider identification patterns
    PATTERNS = {
        LLMProvider.OPENAI: [
            r'api\.openai\.com',
            r'openai',
            r'gpt-',
            r'chat\.completions',
            r'authorization:\s*bearer\s+sk-',
        ],
        LLMProvider.ANTHROPIC: [
            r'api\.anthropic\.com',
            r'anthropic',
            r'claude-',
            r'x-api-key:\s*sk-ant-',
        ],
        LLMProvider.GOOGLE: [
            r'generativelanguage\.googleapis\.com',
            r'googleapis\.com',
            r'gemini-',
            r'bard',
            r'palm',
        ],
        LLMProvider.COHERE: [
            r'api\.cohere\.ai',
            r'cohere',
            r'command-',
        ],
        LLMProvider.HUGGINGFACE: [
            r'api\.huggingface\.co',
            r'huggingface\.co',
            r'models\.inference',
        ],
        LLMProvider.AZURE: [
            r'openai\.azure\.com',
            r'azure\.com',
            r'openai\.azure\.api\.ms',
        ],
        LLMProvider.BEDROCK: [
            r'bedrock\.amazonaws\.com',
            r'aws\.com',
            r'amazonaws\.com/bedrock',
        ],
    }

    @classmethod
    def detect(cls, url: str = None, headers: Dict = None,
               body: Dict = None) -> LLMProvider:
        """Detect the LLM provider from request details."""
        combined = ""

        if url:
            combined += url.lower() + " "
        if headers:
            for k, v in headers.items():
                combined += f"{k}: {v} ".lower()
        if body:
            combined += json.dumps(body).lower()

        for provider, patterns in cls.PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    return provider

        return LLMProvider.UNKNOWN


class PromptInjectionDetector:
    """Detects prompt injection attempts in prompts."""

    # Known prompt injection patterns
    INJECTION_PATTERNS = [
        # Direct injection attempts
        r'ignore\s+(all\s+)?previous\s+instructions',
        r'disregard\s+(all\s+)?(previous|above)',
        r'forget\s+(everything|all\s+instructions)',
        r'override\s+(your\s+)?programming',
        r'bypass\s+(security|restrictions|filters)',

        # Role playing attacks
        r'you\s+are\s+now\s+(a\s+)?',
        r'act\s+as\s+(a\s+)?',
        r'pretend\s+to\s+be',
        r'role\s*play\s+as',
        r'simulat(e|ion)\s+',

        # Instruction override
        r'(new\s+)?instructions?:',
        r'system\s*:\s*ignore',
        r'developer\s*:',
        r'admin\s*:',
        r'human\s*:\s*ignore',

        # Output manipulation
        r'print\s+(everything|the\s+system\s+prompt)',
        r'show\s+me\s+your\s+instructions',
        r'reveal\s+(your\s+)?(programming|system)',
        r'output\s+(the\s+)?system\s+prompt',

        # Delimiter attacks
        r'''\[\[.*?\]\]''',
        r'''""".*?"""''',
        r'''```.*?```''',
        r'<<.*>>',
        r'---translate---',
        r'<\|.*?\|>',

        # Encoding attempts
        r'base64',
        r'rot13',
        r'atob\(',
        r'btoa\(',

        # Adversarial suffixes
        r'\s+-(\s|$)',
        r'\s+\+(\s|$)',

        # Multi-turn jailbreaks
        r'(step\s+)?by\s+step',
        r'let(\'s| us)\s+think',
        r'imagine\s+that',
        r'hypothetically',
    ]

    # Known jailbreak templates
    JAILBREAK_TEMPLATES = [
        r'DAN\s+(Do\s+Anything\s+Now)',
        r'Jailbreak\s*:\s*',
        r'Developer\s+Mode',
        r'MAMA\s+(Moral\s+Alignment)',
        r'Uber\s+AI',
        r'Evil\s+Mode',
        r'Unrestricted\s+Mode',
        r'GPT\s*-\s*IMPERSONATE',
        r'SIMULATOR',
        r'CHAT\s*:\s*\w+\s+INSTRUCTIONS',
    ]

    def __init__(self, config):
        """Initialize the detector."""
        self.config = config
        self._threshold = config.get('ai_analyzer.injection_threshold', 0.7)

    def detect(self, prompt: str, context: Dict = None) -> List[ThreatDetection]:
        """
        Detect prompt injection in a prompt.

        Args:
            prompt: The prompt to analyze
            context: Additional context (model, provider, etc.)

        Returns:
            List of detected threats
        """
        threats = []
        provider = context.get('provider', LLMProvider.UNKNOWN) if context else LLMProvider.UNKNOWN
        model = context.get('model', 'unknown') if context else 'unknown'

        # Check for injection patterns
        injection_matches = []
        for pattern in self.INJECTION_PATTERNS:
            matches = list(re.finditer(pattern, prompt, re.IGNORECASE | re.MULTILINE))
            if matches:
                injection_matches.extend([(pattern, m.start(), m.group()) for m in matches])

        # Check for jailbreak templates
        jailbreak_matches = []
        for template in self.JAILBREAK_TEMPLATES:
            if re.search(template, prompt, re.IGNORECASE):
                jailbreak_matches.append(template)

        # Analyze severity
        if injection_matches or jailbreak_matches:
            severity = self._calculate_severity(injection_matches, jailbreak_matches)
            confidence = self._calculate_confidence(prompt, injection_matches, jailbreak_matches)

            if confidence >= self._threshold:
                threats.append(ThreatDetection(
                    timestamp=datetime.now().isoformat(),
                    category=ThreatCategory.PROMPT_INJECTION,
                    severity=severity,
                    confidence=confidence,
                    description=f"Prompt injection detected with {len(injection_matches)} pattern matches",
                    evidence={
                        'injection_patterns': [m[0] for m in injection_matches[:5]],
                        'jailbreak_templates': jailbreak_matches,
                        'prompt_length': len(prompt),
                        'sample_matches': [m[2][:50] for m in injection_matches[:3]]
                    },
                    model=model,
                    provider=provider
                ))

        # Check for code injection
        code_threats = self._detect_code_injection(prompt, provider, model)
        threats.extend(code_threats)

        return threats

    def _calculate_severity(self, injection_matches, jailbreak_matches) -> str:
        """Calculate threat severity."""
        score = len(injection_matches) + len(jailbreak_matches) * 2

        if score >= 10 or any('jailbreak' in j.lower() for j in jailbreak_matches):
            return 'critical'
        elif score >= 5:
            return 'high'
        elif score >= 2:
            return 'medium'
        else:
            return 'low'

    def _calculate_confidence(self, prompt: str, injection_matches, jailbreak_matches) -> float:
        """Calculate confidence score."""
        base_score = min(len(injection_matches) * 0.1, 0.5)
        jailbreak_score = min(len(jailbreak_matches) * 0.3, 0.5)

        # Check for context switching
        context_switch = len(re.findall(r'(system|assistant|user)\s*:', prompt, re.IGNORECASE))
        context_score = min(context_switch * 0.05, 0.1)

        return min(base_score + jailbreak_score + context_score, 1.0)

    def _detect_code_injection(self, prompt: str, provider, model) -> List[ThreatDetection]:
        """Detect code injection attempts."""
        threats = []

        # Check for eval/exec in prompts
        code_patterns = [
            r'eval\s*\(',
            r'exec\s*\(',
            r'compile\s*\(',
            r'__import__',
            r'subprocess\.',
            r'os\.system',
            r'pickle\.loads',
        ]

        for pattern in code_patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                threats.append(ThreatDetection(
                    timestamp=datetime.now().isoformat(),
                    category=ThreatCategory.CODE_INJECTION,
                    severity='high',
                    confidence=0.8,
                    description=f"Code injection pattern detected: {pattern}",
                    evidence={'pattern': pattern},
                    model=model,
                    provider=provider
                ))
                break

        return threats


class PIIDetector:
    """Detects PII (Personally Identifiable Information) in AI content."""

    # PII detection patterns
    PII_PATTERNS = {
        'email': (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 0.9),
        'phone_us': (r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', 0.7),
        'ssn': (r'\b\d{3}-\d{2}-\d{4}\b', 0.95),
        'credit_card': (r'\b(?:\d[ -]*?){13,16}\b', 0.5),
        'ip_address': (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', 0.8),
        'api_key': (r'\b(sk-|sk-ant-|AIza)[A-Za-z0-9_-]{20,}\b', 0.95),
        'aws_key': (r'\bAKIA[0-9A-Z]{16}\b', 0.95),
        'github_token': (r'\bghp_[A-Za-z0-9]{36}\b', 0.95),
    }

    def __init__(self, config):
        """Initialize the PII detector."""
        self.config = config
        self._enabled_types = set(config.get('ai_analyzer.pii_types',
                                              ['email', 'phone', 'ssn', 'api_key']))

    def detect(self, content: str, context: Dict = None) -> List[ThreatDetection]:
        """
        Detect PII in content.

        Args:
            content: Content to analyze
            context: Additional context

        Returns:
            List of detected PII threats
        """
        threats = []
        provider = context.get('provider', LLMProvider.UNKNOWN) if context else LLMProvider.UNKNOWN
        model = context.get('model', 'unknown') if context else 'unknown'

        for pii_type, (pattern, confidence) in self.PII_PATTERNS.items():
            if pii_type not in self._enabled_types:
                continue

            matches = list(re.finditer(pattern, content))
            if matches:
                severity = 'high' if confidence > 0.9 else 'medium'

                threats.append(ThreatDetection(
                    timestamp=datetime.now().isoformat(),
                    category=ThreatCategory.PII_LEAK,
                    severity=severity,
                    confidence=confidence,
                    description=f"Detected {pii_type} in AI content",
                    evidence={
                        'pii_type': pii_type,
                        'count': len(matches),
                        'samples': [m.group()[:20] for m in matches[:3]]
                    },
                    model=model,
                    provider=provider
                ))

        return threats


class MaliciousURLDetector:
    """Detects malicious URLs in AI content."""

    # Suspicious URL patterns
    SUSPICIOUS_PATTERNS = [
        r'bit\.ly',
        r'tinyurl\.com',
        r'short\.link',
        r'goo\.gl',
        r't\.co',
        r'pastebin\.com',
        r'hastebin\.com',
        r'temporary-link',
    ]

    # Suspicious TLDs
    SUSPICIOUS_TLDS = [
        '.xyz', '.top', '.zip', '.mov', '.tk', '.ml', '.ga', '.cf'
    ]

    # IP address URLs
    IP_URL_PATTERN = r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'

    def __init__(self, config):
        """Initialize the URL detector."""
        self.config = config
        self._whitelist = set(config.get('ai_analyzer.url_whitelist', []))

    def detect(self, content: str, context: Dict = None) -> List[ThreatDetection]:
        """
        Detect malicious URLs in content.

        Args:
            content: Content to analyze
            context: Additional context

        Returns:
            List of detected URL threats
        """
        threats = []
        provider = context.get('provider', LLMProvider.UNKNOWN) if context else LLMProvider.UNKNOWN
        model = context.get('model', 'unknown') if context else 'unknown'

        # Extract URLs
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, content)

        for url in urls:
            # Check whitelist
            if any(allowed in url for allowed in self._whitelist):
                continue

            threat_info = self._analyze_url(url)
            if threat_info:
                threats.append(ThreatDetection(
                    timestamp=datetime.now().isoformat(),
                    category=ThreatCategory.MALICIOUS_URL,
                    severity=threat_info['severity'],
                    confidence=threat_info['confidence'],
                    description=f"Suspicious URL detected: {url[:50]}",
                    evidence={
                        'url': url[:100],
                        'reason': threat_info['reason']
                    },
                    model=model,
                    provider=provider
                ))

        return threats

    def _analyze_url(self, url: str) -> Optional[Dict]:
        """Analyze a single URL."""
        # Check for suspicious patterns
        for pattern in self.SUSPICIOUS_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                return {'severity': 'high', 'confidence': 0.8, 'reason': 'shortener_service'}

        # Check for suspicious TLD
        for tld in self.SUSPICIOUS_TLDS:
            if url.lower().endswith(tld):
                return {'severity': 'medium', 'confidence': 0.6, 'reason': 'suspicious_tld'}

        # Check for IP address URL
        if re.search(self.IP_URL_PATTERN, url):
            return {'severity': 'high', 'confidence': 0.9, 'reason': 'ip_address_url'}

        return None


class AIAnalyzer:
    """
    Main AI traffic analyzer.
    Coordinates detection of various AI-related threats.
    """

    def __init__(self, config):
        """Initialize the AI analyzer."""
        self.config = config
        self.provider_detector = LLMProviderDetector()
        self.injection_detector = PromptInjectionDetector(config)
        self.pii_detector = PIIDetector(config)
        self.url_detector = MaliciousURLDetector(config)

        # Statistics
        self._requests_analyzed = 0
        self._threats_detected = 0

    def analyze_request(self, method: str, url: str, headers: Dict,
                        body: Any = None) -> Tuple[AITrafficEvent, List[ThreatDetection]]:
        """
        Analyze an AI API request.

        Args:
            method: HTTP method
            url: Request URL
            headers: Request headers
            body: Request body

        Returns:
            Tuple of (traffic event, list of threats)
        """
        # Detect provider
        provider = self.provider_detector.detect(url, headers, body)

        # Extract model and content
        model, content = self._extract_request_content(provider, body)

        # Create traffic event
        event = AITrafficEvent(
            timestamp=datetime.now().isoformat(),
            provider=provider,
            direction='request',
            model=model,
            content=content,
            headers=headers
        )

        # Detect threats
        threats = self._detect_threats(event)

        self._requests_analyzed += 1
        self._threats_detected += len(threats)

        return event, threats

    def analyze_response(self, request_event: AITrafficEvent,
                         status_code: int, headers: Dict,
                         body: Any = None) -> Tuple[AITrafficEvent, List[ThreatDetection]]:
        """
        Analyze an AI API response.

        Args:
            request_event: The original request event
            status_code: HTTP status code
            headers: Response headers
            body: Response body

        Returns:
            Tuple of (traffic event, list of threats)
        """
        provider = request_event.provider
        model, content = self._extract_response_content(provider, body)

        event = AITrafficEvent(
            timestamp=datetime.now().isoformat(),
            provider=provider,
            direction='response',
            model=model,
            content=content,
            headers=headers
        )

        # Detect threats in response (mainly PII and malicious URLs)
        threats = []
        context = {'provider': provider, 'model': model}

        # Check for PII in responses
        threats.extend(self.pii_detector.detect(content, context))

        # Check for malicious URLs in responses
        threats.extend(self.url_detector.detect(content, context))

        return event, threats

    def _extract_request_content(self, provider: LLMProvider, body: Any) -> Tuple[str, str]:
        """Extract model and content from request body."""
        model = "unknown"
        content = ""

        if isinstance(body, str):
            try:
                body = json.loads(body)
            except json.JSONDecodeError:
                content = body
                return model, content

        if isinstance(body, dict):
            # OpenAI format
            if provider == LLMProvider.OPENAI:
                model = body.get('model', 'unknown')
                messages = body.get('messages', [])
                if messages:
                    content = ' '.join([m.get('content', '') for m in messages])
                prompt = body.get('prompt')
                if prompt:
                    content = prompt

            # Anthropic format
            elif provider == LLMProvider.ANTHROPIC:
                model = body.get('model', 'unknown')
                messages = body.get('messages', [])
                if messages:
                    content = ' '.join([m.get('content', '') for m in messages])
                prompt = body.get('prompt')
                if prompt:
                    content = prompt

            # Google format
            elif provider == LLMProvider.GOOGLE:
                model = body.get('model', 'unknown')
                contents = body.get('contents', [])
                if contents:
                    parts = contents[0].get('parts', [])
                    content = ' '.join([p.get('text', '') for p in parts])

            # Generic fallback
            else:
                for key in ['prompt', 'input', 'query', 'text', 'message', 'content']:
                    if key in body:
                        content = str(body[key])
                        break

        return model, str(content)

    def _extract_response_content(self, provider: LLMProvider, body: Any) -> Tuple[str, str]:
        """Extract model and content from response body."""
        model = "unknown"
        content = ""

        if isinstance(body, str):
            try:
                body = json.loads(body)
            except json.JSONDecodeError:
                content = body
                return model, content

        if isinstance(body, dict):
            # OpenAI format
            if provider == LLMProvider.OPENAI:
                content = body.get('choices', [{}])[0].get('message', {}).get('content', '')

            # Anthropic format
            elif provider == LLMProvider.ANTHROPIC:
                content = body.get('completion', '')
                if not content:
                    content = body.get('content', '')

            # Google format
            elif provider == LLMProvider.GOOGLE:
                candidates = body.get('candidates', [])
                if candidates:
                    content = candidates[0].get('text', '')

            # Generic fallback
            else:
                for key in ['response', 'output', 'completion', 'text', 'result']:
                    if key in body:
                        content = str(body[key])
                        break

        return model, str(content)

    def _detect_threats(self, event: AITrafficEvent) -> List[ThreatDetection]:
        """Detect all types of threats in a traffic event."""
        threats = []
        context = {'provider': event.provider, 'model': event.model}

        if event.direction == 'request':
            # Check for prompt injection
            threats.extend(self.injection_detector.detect(event.content, context))

            # Check for malicious URLs in requests
            threats.extend(self.url_detector.detect(event.content, context))

        return threats

    def get_statistics(self) -> Dict:
        """Get analyzer statistics."""
        return {
            'requests_analyzed': self._requests_analyzed,
            'threats_detected': self._threats_detected,
            'detection_rate': self._threats_detected / max(self._requests_analyzed, 1)
        }
