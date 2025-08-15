"""
Payload extraction service for identifying malicious patterns in requests
"""

import re
import urllib.parse
import logging
from typing import Dict, List, Optional, Tuple
from app.models.signature import AttackType
from app.core.constants import AnalysisConstants, AttackPatternType
from app.core.exceptions import PayloadExtractionError
from app.utils.validation import PayloadValidator

logger = logging.getLogger(__name__)

class PayloadExtractor:
    """Extracts and classifies malicious payloads from request data."""
    
    def __init__(self, config: Dict):
        self.config = config
        self.payload_patterns = self._load_payload_patterns()
    
    def _load_payload_patterns(self) -> Dict:
        """Load attack pattern definitions."""
        return {
            AttackType.SQL_INJECTION: [
                # Union-based SQL injection
                {
                    'pattern': r"union\s+select",
                    'confidence': 0.9,
                    'description': 'UNION SELECT statement'
                },
                {
                    'pattern': r"'\s*or\s*'1'\s*=\s*'1",
                    'confidence': 0.8,
                    'description': 'Boolean-based SQL injection'
                },
                {
                    'pattern': r"'\s*or\s*1\s*=\s*1",
                    'confidence': 0.8,
                    'description': 'Boolean-based SQL injection'
                },
                {
                    'pattern': r"'\s*;\s*drop\s+table",
                    'confidence': 0.9,
                    'description': 'SQL DROP statement'
                },
                {
                    'pattern': r"'\s*;\s*insert\s+into",
                    'confidence': 0.9,
                    'description': 'SQL INSERT statement'
                },
                {
                    'pattern': r"'\s*;\s*update\s+",
                    'confidence': 0.9,
                    'description': 'SQL UPDATE statement'
                },
                {
                    'pattern': r"'\s*;\s*delete\s+from",
                    'confidence': 0.9,
                    'description': 'SQL DELETE statement'
                },
                {
                    'pattern': r"'\s*;\s*exec\s*\(",
                    'confidence': 0.8,
                    'description': 'SQL EXEC function'
                },
                {
                    'pattern': r"'\s*;\s*waitfor\s+delay",
                    'confidence': 0.8,
                    'description': 'SQL time-based injection'
                },
                {
                    'pattern': r"'\s*and\s+sleep\s*\(",
                    'confidence': 0.8,
                    'description': 'MySQL SLEEP function'
                }
            ],
            
            AttackType.XSS: [
                {
                    'pattern': r"<script[^>]*>.*?</script>",
                    'confidence': 0.9,
                    'description': 'Script tag injection'
                },
                {
                    'pattern': r"javascript:",
                    'confidence': 0.8,
                    'description': 'JavaScript protocol'
                },
                {
                    'pattern': r"on\w+\s*=\s*['\"].*?['\"]",
                    'confidence': 0.7,
                    'description': 'Event handler injection'
                },
                {
                    'pattern': r"<iframe[^>]*src\s*=",
                    'confidence': 0.8,
                    'description': 'Iframe injection'
                },
                {
                    'pattern': r"<img[^>]*src\s*=\s*['\"]javascript:",
                    'confidence': 0.9,
                    'description': 'Image JavaScript injection'
                },
                {
                    'pattern': r"<svg[^>]*onload\s*=",
                    'confidence': 0.8,
                    'description': 'SVG onload injection'
                },
                {
                    'pattern': r"alert\s*\(\s*['\"].*?['\"]",
                    'confidence': 0.7,
                    'description': 'Alert function call'
                },
                {
                    'pattern': r"document\.cookie",
                    'confidence': 0.6,
                    'description': 'Cookie access attempt'
                }
            ],
            
            AttackType.LFI: [
                {
                    'pattern': r"\.\./",
                    'confidence': 0.7,
                    'description': 'Directory traversal'
                },
                {
                    'pattern': r"\.\.\\",
                    'confidence': 0.7,
                    'description': 'Windows directory traversal'
                },
                {
                    'pattern': r"/etc/passwd",
                    'confidence': 0.9,
                    'description': 'Unix password file access'
                },
                {
                    'pattern': r"/etc/shadow",
                    'confidence': 0.9,
                    'description': 'Unix shadow file access'
                },
                {
                    'pattern': r"c:\\windows\\system32",
                    'confidence': 0.8,
                    'description': 'Windows system directory'
                },
                {
                    'pattern': r"php://filter",
                    'confidence': 0.8,
                    'description': 'PHP filter wrapper'
                },
                {
                    'pattern': r"file://",
                    'confidence': 0.8,
                    'description': 'File protocol wrapper'
                }
            ],
            
            AttackType.COMMAND_INJECTION: [
                {
                    'pattern': r";\s*cat\s+/etc/passwd",
                    'confidence': 0.9,
                    'description': 'Unix command injection'
                },
                {
                    'pattern': r";\s*ls\s+-la",
                    'confidence': 0.8,
                    'description': 'Directory listing command'
                },
                {
                    'pattern': r";\s*id\s*;",
                    'confidence': 0.8,
                    'description': 'User ID command'
                },
                {
                    'pattern': r";\s*whoami",
                    'confidence': 0.8,
                    'description': 'Username command'
                },
                {
                    'pattern': r";\s*wget\s+",
                    'confidence': 0.8,
                    'description': 'File download command'
                },
                {
                    'pattern': r";\s*curl\s+",
                    'confidence': 0.8,
                    'description': 'HTTP client command'
                },
                {
                    'pattern': r"&&\s*cmd",
                    'confidence': 0.8,
                    'description': 'Windows command execution'
                }
            ],
            
            AttackType.XXE: [
                {
                    'pattern': r"<!ENTITY.*SYSTEM",
                    'confidence': 0.9,
                    'description': 'XML external entity'
                },
                {
                    'pattern': r"<!DOCTYPE.*\[.*<!ENTITY",
                    'confidence': 0.9,
                    'description': 'DOCTYPE with entity declaration'
                }
            ]
        }
    
    def extract_payload(self, input_string: str) -> Optional[Dict]:
        """Extract and classify payload from input string."""
        if not input_string or len(input_string) < AnalysisConstants.MIN_PAYLOAD_LENGTH:
            return None
        
        if len(input_string) > AnalysisConstants.MAX_PAYLOAD_LENGTH:
            logger.warning(f"Payload too long ({len(input_string)} chars), truncating")
            input_string = input_string[:AnalysisConstants.MAX_PAYLOAD_LENGTH]
        
        # URL decode the input
        decoded_input = urllib.parse.unquote_plus(input_string)
        
        best_match = None
        highest_confidence = 0.0
        
        # Check against all attack patterns
        for attack_type, patterns in self.payload_patterns.items():
            for pattern_info in patterns:
                pattern = pattern_info['pattern']
                base_confidence = pattern_info['confidence']
                
                matches = list(re.finditer(pattern, decoded_input, re.IGNORECASE))
                if matches:
                    # Calculate confidence based on pattern match and context
                    confidence = self._calculate_pattern_confidence(
                        decoded_input, matches[0], base_confidence
                    )
                    
                    if confidence > highest_confidence:
                        highest_confidence = confidence
                        best_match = {
                            'attack_type': attack_type,
                            'confidence': confidence,
                            'payload': matches[0].group(),
                            'description': pattern_info['description'],
                            'pattern': pattern,
                            'full_input': decoded_input,
                            'match_position': matches[0].span()
                        }
        
        return best_match if highest_confidence > AnalysisConstants.MIN_CONFIDENCE_THRESHOLD else None
    
    def _calculate_pattern_confidence(self, input_string: str, match: re.Match, base_confidence: float) -> float:
        """Calculate confidence score based on pattern match and context."""
        confidence = base_confidence
        
        # Boost confidence for longer payloads (more specific)
        payload_length = len(match.group())
        if payload_length > 20:
            confidence += 0.1
        elif payload_length > 50:
            confidence += 0.2
        
        # Boost confidence for multiple suspicious elements
        suspicious_chars = ["'", '"', '<', '>', ';', '&', '|', '..', '0x']
        suspicious_count = sum(1 for char in suspicious_chars if char in input_string)
        confidence += min(suspicious_count * 0.05, 0.2)
        
        # Reduce confidence for very short inputs (might be false positives)
        if len(input_string) < 10:
            confidence -= 0.2
        
        # Check for encoding/obfuscation indicators
        if '%' in input_string or '+' in input_string:
            confidence += 0.1  # URL encoded inputs are more suspicious
        
        return min(max(confidence, 0.0), 1.0)
    
    def extract_multiple_payloads(self, input_string: str) -> List[Dict]:
        """Extract all possible payloads from input string."""
        if not input_string:
            return []
        
        decoded_input = urllib.parse.unquote_plus(input_string)
        payloads = []
        
        for attack_type, patterns in self.payload_patterns.items():
            for pattern_info in patterns:
                pattern = pattern_info['pattern']
                base_confidence = pattern_info['confidence']
                
                matches = list(re.finditer(pattern, decoded_input, re.IGNORECASE))
                for match in matches:
                    confidence = self._calculate_pattern_confidence(
                        decoded_input, match, base_confidence
                    )
                    
                    if confidence > 0.5:
                        payloads.append({
                            'attack_type': attack_type,
                            'confidence': confidence,
                            'payload': match.group(),
                            'description': pattern_info['description'],
                            'pattern': pattern,
                            'match_position': match.span()
                        })
        
        # Sort by confidence descending
        return sorted(payloads, key=lambda x: x['confidence'], reverse=True)
    
    def normalize_payload(self, payload: str) -> str:
        """Normalize payload for signature generation."""
        # URL decode
        normalized = urllib.parse.unquote_plus(payload)
        
        # Remove extra whitespace
        normalized = re.sub(r'\s+', ' ', normalized).strip()
        
        # Convert to lowercase for case-insensitive matching
        normalized = normalized.lower()
        
        return normalized