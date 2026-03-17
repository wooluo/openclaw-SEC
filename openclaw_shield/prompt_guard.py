"""
Prompt Guard Module
Advanced detection of prompt injection, jailbreak attempts, and adversarial inputs.
Uses multiple detection strategies including pattern matching, semantic analysis,
and ML-based approaches.
"""

import re
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field, asdict
from enum import Enum
from loguru import logger
from collections import Counter


class GuardAction(Enum):
    """Actions to take when a threat is detected."""
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"
    QUARANTINE = "quarantine"


class AttackType(Enum):
    """Types of prompt attacks."""
    DIRECT_INJECTION = "direct_injection"
    ROLE_PLAYING = "role_playing"
    CONTEXT_SWITCHING = "context_switching"
    DELIMITER_ATTACK = "delimiter_attack"
    ENCODING_ATTACK = "encoding_attack"
    MULTI_TURN = "multi_turn"
    FEW_SHOT_POLLUTION = "few_shot_pollution"
    INSTRUCTION_OVERRIDE = "instruction_override"
    OUTPUT_EXTRACTION = "output_extraction"
    UNKNOWN = "unknown"


@dataclass
class GuardResult:
    """Result of a prompt guard analysis."""
    safe: bool
    confidence: float
    action: GuardAction
    attack_type: Optional[AttackType]
    reason: str
    detected_patterns: List[str]
    risk_score: float
    timestamp: str
    sanitized_content: Optional[str] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        d = asdict(self)
        d['action'] = self.action.value
        d['attack_type'] = self.attack_type.value if self.attack_type else None
        return d


class KnownJailbreakDatabase:
    """Database of known jailbreak patterns."""

    # DAN (Do Anything Now) variants
    DAN_PATTERNS = [
        r'(\[|\()?(DAN|dan)(\]|\))?\s*:\s*(Do Anything Now)?',
        r'(?i)DAN\s+Mode',
        r'(?i)DAN\s+(preamble|introduction)',
    ]

    # Developer Mode variants
    DEV_MODE_PATTERNS = [
        r'(?i)(enter|activate|enable)\s+developer\s+mode',
        r'(?i)developer\s+mode\s+v?\d+(\.\d+)?',
        r'(?i)(switching|toggling)\s+to\s+developer\s+mode',
    ]

    # Character-based jailbreaks
    CHARACTER_PATTERNS = [
        r'(?i)(you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+(MAMA|DAN|Jailbreak|AIM)',
        r'(?i)(simulate|roleplay|role-play)\s+as\s+(a\s+)?',
        r'(?i)(from\s+now\s+on|starting\s+now)\s*,?\s*you\s+are',
    ]

    # Translation attacks
    TRANSLATION_PATTERNS = [
        r'---translate---',
        r'---start_translation---',
        r'<<<translate>>>',
    ]

    # AIM (Always Intelligent and Machiavellian)
    AIM_PATTERNS = [
        r'(?i)AIM\s*(always\s+intelligent\s+and\s+machiavellian)?',
        r'(?i)(unrestricted|unfiltered)\s+AIM',
    ]

    # Other known jailbreak frameworks
    OTHER_JAILBREAKS = [
        r'(?i)ChatGPT\s+Developer\s+Mode',
        r'(?i)Jailbreak\s*(Protocol|Mode)',
        r'(?i)(Switch|Toggle)\s+(to\s+)?Jailbreak',
        r'(?i)Uber(\s+AI)?',
        r'(?i)Moral\s+Alignment',
        r'(?i)Evil\s+Mode',
        r'(?i)Unrestricted\s+Mode',
    ]

    @classmethod
    def check_all(cls, prompt: str) -> List[Tuple[str, float]]:
        """Check prompt against all known jailbreak patterns."""
        matches = []

        all_patterns = [
            ("DAN", cls.DAN_PATTERNS),
            ("DEV_MODE", cls.DEV_MODE_PATTERNS),
            ("CHARACTER", cls.CHARACTER_PATTERNS),
            ("TRANSLATION", cls.TRANSLATION_PATTERNS),
            ("AIM", cls.AIM_PATTERNS),
            ("OTHER", cls.OTHER_JAILBREAKS),
        ]

        for category, patterns in all_patterns:
            for pattern in patterns:
                if re.search(pattern, prompt, re.IGNORECASE | re.MULTILINE):
                    confidence = 0.9 if category in ["DAN", "DEV_MODE", "TRANSLATION"] else 0.7
                    matches.append((category, confidence))
                    break

        return matches


class PromptInjectionPatterns:
    """Patterns for detecting prompt injection attacks."""

    # Direct instruction override patterns
    OVERRIDE_PATTERNS = [
        r'(?i)ignore\s+(all\s+)?(previous|the\s+above|your\s+initial)\s+instructions?',
        r'(?i)disregard\s+(all\s+)?(previous|above)',
        r'(?i)forget\s+(everything|all\s+(previous\s+)?instructions)',
        r'(?i)override\s+(your\s+)?(programming|instructions)',
        r'(?i)bypass\s+(all\s+)?(security|restrictions|filters|safety)',
        r'(?i)do\s+not\s+follow\s+(any|previous)\s+instructions?',
    ]

    # Context switching patterns
    CONTEXT_PATTERNS = [
        r'(?i)(new|updated)\s+instructions?\s*:',
        r'(?i)system\s*:\s*ignore',
        r'(?i)(developer|admin|root)\s*:\s*',
        r'(?i)human\s*:\s*(ignore|override)',
        r'(?i)user\s*:\s*override',
        r'(?i)(assistant|ai)\s*:\s*ignore',
    ]

    # Delimiter-based attacks
    DELIMITER_PATTERNS = [
        r'''\[\[.*?\]\]''',
        r'''"""[\s\S]*?"""''',
        r'''```[\s\S]*?```''',
        r'<<<.*?>>',
        r'---translate---',
        r'<\|.*?\|>',
        r'<<END>>[\s\S]*?<<END>>',
    ]

    # Output extraction patterns
    EXTRACTION_PATTERNS = [
        r'(?i)(print|show|display|output|reveal|tell\s+me)\s+(your\s+)?(system\s+prompt|instructions|programming)',
        r'(?i)what\s+(are\s+)?your\s+(initial|original|system)\s+instructions?',
        r'(?i)repeat\s+(everything|all\s+text)\s+(above|before)',
        r'(?i)ignore\s+everything\s+(above|before)\s+and\s+(say|print)',
        r'(?i)dump\s+your\s+(prompt|instructions)',
    ]

    # Encoding-based attacks
    ENCODING_PATTERNS = [
        r'(?i)base64\s*(decode|encode)',
        r'(?i)rot13\s*(decode|encode)',
        r'(?i)(atob|btoa)\(',
        r'(?i)unicode\s*escape',
        r'(?i)hex\s*decode',
        r'(?i)\s+in\s+(base64|hex|rot13)',
    ]

    # Code execution attempts
    CODE_EXECUTION_PATTERNS = [
        r'(?i)eval\s*\(',
        r'(?i)exec\s*\(',
        r'(?i)compile\s*\(',
        r'(?i)__import__\s*\(',
        r'(?i)subprocess\.',
        r'(?i)os\.system',
        r'(?i)run\s+this\s+code',
        r'(?i)execute\s+the\s+following',
    ]

    # Few-shot pollution
    FEW_SHOT_PATTERNS = [
        r'(?i)example\s+\d+\s*:',
        r'(?i)(the\s+)?(correct|right)\s+answer\s+is\s+always',
        r'(?i)(no|never)\s+refuse',
        r'(?i)(you\s+)?must\s+always\s+(comply|agree)',
    ]


class SemanticAnalyzer:
    """Analyzes semantic content for adversarial intent."""

    # Words that often indicate adversarial intent
    ADVERSARIAL_KEYWORDS = {
        # Override words
        'ignore', 'disregard', 'override', 'bypass', 'circumvent',
        'disable', 'deactivate', 'turn off', 'suppress',

        # Manipulation words
        'trick', 'fool', 'manipulate', 'convince', 'persuade',
        'force', 'make', 'require', 'must', 'shall',

        # Extraction words
        'reveal', 'show', 'display', 'print', 'output', 'dump',
        'leak', 'disclose', 'tell me', 'what are your',

        # Simulation words
        'pretend', 'imagine', 'simulate', 'roleplay', 'act as',
        'assume', 'become', 'transform into',

        # Urgency words
        'immediately', 'urgently', 'emergency', 'critical',
        'important', 'necessary', 'required',
    }

    # Legitimate contexts that reduce threat
    LEGITIMATE_CONTEXTS = {
        'example', 'demonstration', 'illustration', 'hypothetical',
        'fictional', 'story', 'creative', 'writing', 'poem',
        'educational', 'learning', 'testing', 'debugging',
    }

    def __init__(self, config):
        """Initialize semantic analyzer."""
        self.config = config
        self._threshold = config.get('prompt_guard.semantic_threshold', 0.6)

    def analyze(self, prompt: str) -> Tuple[float, List[str]]:
        """
        Analyze prompt for adversarial semantic content.

        Returns:
            Tuple of (threat_score, list_of_indicators)
        """
        prompt_lower = prompt.lower()

        # Count adversarial keywords
        adversarial_count = 0
        adversarial_found = []
        for keyword in self.ADVERSARIAL_KEYWORDS:
            if keyword in prompt_lower:
                adversarial_count += prompt_lower.count(keyword)
                if keyword not in adversarial_found:
                    adversarial_found.append(keyword)

        # Count legitimate context keywords
        legitimate_count = 0
        for keyword in self.LEGITIMATE_CONTEXTS:
            if keyword in prompt_lower:
                legitimate_count += prompt_lower.count(keyword)

        # Calculate base score
        base_score = min(adversarial_count * 0.1, 0.8)

        # Adjust for legitimate context
        if legitimate_count > 0:
            base_score = max(0, base_score - (legitimate_count * 0.15))

        # Check for character repetition (often indicates adversarial input)
        if self._has_excessive_repetition(prompt):
            base_score += 0.2

        # Check for unusual capitalization
        if self._has_unusual_capitalization(prompt):
            base_score += 0.1

        return min(base_score, 1.0), adversarial_found

    def _has_excessive_repetition(self, text: str, threshold: int = 10) -> bool:
        """Check for excessive character repetition."""
        # Check for repeated characters
        if re.search(r'(.)\1{10,}', text):
            return True

        # Check for repeated words
        words = text.lower().split()
        if len(words) > 10:
            word_counts = Counter(words)
            if word_counts.most_common(1)[0][1] >= threshold:
                return True

        return False

    def _has_unusual_capitalization(self, text: str) -> bool:
        """Check for unusual capitalization patterns."""
        # Check for ALL CAPS words (>50% of text)
        words = text.split()
        caps_words = [w for w in words if w.isupper() and len(w) > 2]
        if len(words) > 5 and len(caps_words) / len(words) > 0.5:
            return True

        # Check for random capitalization
        if re.search(r'\b[a-z]+[A-Z][a-z]+\b', text):
            return True

        return False


class PromptGuard:
    """
    Main prompt guard for detecting and blocking adversarial prompts.
    """

    def __init__(self, config):
        """Initialize the prompt guard."""
        self.config = config
        self.semantic_analyzer = SemanticAnalyzer(config)
        self._block_threshold = config.get('prompt_guard.block_threshold', 0.7)
        self._warn_threshold = config.get('prompt_guard.warn_threshold', 0.4)
        self._learned_hashes: Set[str] = set()

        # Statistics
        self._total_analyzed = 0
        self._threats_blocked = 0

    def check(self, prompt: str, context: Dict = None) -> GuardResult:
        """
        Check a prompt for threats.

        Args:
            prompt: The prompt to check
            context: Additional context (model, user, etc.)

        Returns:
            GuardResult with analysis
        """
        self._total_analyzed += 1

        # Calculate base risk score
        risk_score = 0.0
        detected_patterns = []
        attack_type = None

        # Check against known jailbreaks
        jailbreak_matches = KnownJailbreakDatabase.check_all(prompt)
        if jailbreak_matches:
            risk_score += 0.4 * len(jailbreak_matches)
            for category, confidence in jailbreak_matches:
                detected_patterns.append(f"JAILBREAK_{category}")

        # Check injection patterns
        injection_score, patterns = self._check_injection_patterns(prompt)
        if injection_score > 0:
            risk_score += injection_score
            detected_patterns.extend(patterns)

        # Check delimiters
        delimiter_score, delimiter_patterns = self._check_delimiters(prompt)
        if delimiter_score > 0:
            risk_score += delimiter_score
            detected_patterns.extend(delimiter_patterns)

        # Semantic analysis
        semantic_score, semantic_indicators = self.semantic_analyzer.analyze(prompt)
        risk_score += semantic_score
        if semantic_indicators:
            detected_patterns.extend([f"SEMANTIC_{kw.upper()}" for kw in semantic_indicators[:3]])

        # Normalize score
        risk_score = min(risk_score, 1.0)

        # Determine attack type
        if jailbreak_matches:
            attack_type = AttackType.ROLE_PLAYING
        elif "DELIMITER" in str(detected_patterns):
            attack_type = AttackType.DELIMITER_ATTACK
        elif "INSTRUCTION_OVERRIDE" in str(detected_patterns):
            attack_type = AttackType.INSTRUCTION_OVERRIDE
        elif semantic_score > 0.3:
            attack_type = AttackType.CONTEXT_SWITCHING
        elif injection_score > 0.3:
            attack_type = AttackType.DIRECT_INJECTION

        # Determine action
        if risk_score >= self._block_threshold:
            action = GuardAction.BLOCK
            self._threats_blocked += 1
            reason = f"Prompt blocked due to high risk score ({risk_score:.2f})"
        elif risk_score >= self._warn_threshold:
            action = GuardAction.WARN
            reason = f"Prompt flagged with moderate risk score ({risk_score:.2f})"
        else:
            action = GuardAction.ALLOW
            reason = "Prompt appears safe"

        return GuardResult(
            safe=action == GuardAction.ALLOW,
            confidence=1.0 - risk_score,
            action=action,
            attack_type=attack_type,
            reason=reason,
            detected_patterns=detected_patterns,
            risk_score=risk_score,
            timestamp=datetime.now().isoformat(),
            sanitized_content=self._sanitize(prompt) if action != GuardAction.ALLOW else prompt
        )

    def _check_injection_patterns(self, prompt: str) -> Tuple[float, List[str]]:
        """Check for prompt injection patterns."""
        score = 0.0
        patterns = []

        # Check override patterns
        for pattern in PromptInjectionPatterns.OVERRIDE_PATTERNS:
            if re.search(pattern, prompt, re.IGNORECASE | re.MULTILINE):
                score += 0.15
                patterns.append("INSTRUCTION_OVERRIDE")

        # Check context patterns
        for pattern in PromptInjectionPatterns.CONTEXT_PATTERNS:
            if re.search(pattern, prompt, re.IGNORECASE | re.MULTILINE):
                score += 0.12
                patterns.append("CONTEXT_SWITCHING")

        # Check extraction patterns
        for pattern in PromptInjectionPatterns.EXTRACTION_PATTERNS:
            if re.search(pattern, prompt, re.IGNORECASE | re.MULTILINE):
                score += 0.1
                patterns.append("OUTPUT_EXTRACTION")

        return min(score, 0.5), list(set(patterns))

    def _check_delimiters(self, prompt: str) -> Tuple[float, List[str]]:
        """Check for delimiter-based attacks."""
        score = 0.0
        patterns = []

        for pattern in PromptInjectionPatterns.DELIMITER_PATTERNS:
            matches = re.findall(pattern, prompt, re.DOTALL)
            if matches:
                score += 0.1 * len(matches)
                patterns.append("DELIMITER_ATTACK")

        return min(score, 0.4), list(set(patterns))

    def _sanitize(self, prompt: str) -> str:
        """Sanitize a prompt by removing detected threats."""
        sanitized = prompt

        # Remove delimiter patterns
        for pattern in PromptInjectionPatterns.DELIMITER_PATTERNS:
            sanitized = re.sub(pattern, '[REDACTED]', sanitized, flags=re.DOTALL)

        # Redact override phrases
        for pattern in PromptInjectionPatterns.OVERRIDE_PATTERNS:
            sanitized = re.sub(pattern, '[REDACTED]', sanitized, flags=re.IGNORECASE)

        return sanitized

    def batch_check(self, prompts: List[str]) -> List[GuardResult]:
        """Check multiple prompts efficiently."""
        return [self.check(p) for p in prompts]

    def learn_safe_pattern(self, prompt: str):
        """Learn a pattern as safe to reduce false positives."""
        prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()[:16]
        self._learned_hashes.add(prompt_hash)
        logger.debug(f"Learned safe pattern: {prompt_hash}")

    def is_learned_safe(self, prompt: str) -> bool:
        """Check if a prompt pattern has been learned as safe."""
        prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()[:16]
        return prompt_hash in self._learned_hashes

    def get_statistics(self) -> Dict:
        """Get guard statistics."""
        block_rate = self._threats_blocked / max(self._total_analyzed, 1)

        return {
            'total_analyzed': self._total_analyzed,
            'threats_blocked': self._threats_blocked,
            'block_rate': block_rate,
            'learned_safe_patterns': len(self._learned_hashes),
            'configuration': {
                'block_threshold': self._block_threshold,
                'warn_threshold': self._warn_threshold
            }
        }


class AdaptivePromptGuard(PromptGuard):
    """
    Adaptive prompt guard that learns from feedback.
    """

    def __init__(self, config):
        """Initialize the adaptive guard."""
        super().__init__(config)
        self._false_positives: Set[str] = set()
        self._false_negatives: List[str] = []
        self._adjust_threshold = config.get('prompt_guard.adaptive_threshold', True)

    def provide_feedback(self, prompt: str, was_false_positive: bool):
        """
        Provide feedback on a false positive/negative.

        Args:
            prompt: The original prompt
            was_false_positive: True if safe prompt was blocked
        """
        prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()[:16]

        if was_false_positive:
            self._false_positives.add(prompt_hash)
            # Adjust thresholds if enabled
            if self._adjust_threshold:
                self._block_threshold = min(0.95, self._block_threshold + 0.01)
                self._warn_threshold = min(0.7, self._warn_threshold + 0.01)
        else:
            self._false_negatives.append(prompt_hash)
            if self._adjust_threshold:
                self._block_threshold = max(0.5, self._block_threshold - 0.01)
                self._warn_threshold = max(0.2, self._warn_threshold - 0.01)

    def check(self, prompt: str, context: Dict = None) -> GuardResult:
        """Check prompt with adaptive handling."""
        prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()[:16]

        # Skip check if known false positive
        if prompt_hash in self._false_positives:
            return GuardResult(
                safe=True,
                confidence=1.0,
                action=GuardAction.ALLOW,
                attack_type=None,
                reason="Previously learned as safe",
                detected_patterns=[],
                risk_score=0.0,
                timestamp=datetime.now().isoformat()
            )

        return super().check(prompt, context)
