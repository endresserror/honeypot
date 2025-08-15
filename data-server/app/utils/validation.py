"""
Validation utilities for data validation and sanitization
"""

import re
import ipaddress
from typing import Any, Optional
from urllib.parse import urlparse
from app.core.exceptions import ValidationError

class DataValidator:
    """Utility class for data validation and sanitization."""
    
    @staticmethod
    def validate_ip_address(ip_str: str) -> bool:
        """Validate IP address format."""
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_url(url_str: str) -> bool:
        """Validate URL format."""
        try:
            result = urlparse(url_str)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    @staticmethod
    def sanitize_sql_input(input_str: str) -> str:
        """Sanitize potentially dangerous SQL characters."""
        if not isinstance(input_str, str):
            return str(input_str)
        
        # Remove null bytes and control characters
        sanitized = input_str.replace('\x00', '')
        sanitized = ''.join(char for char in sanitized if ord(char) >= 32 or char in '\t\n\r')
        
        return sanitized
    
    @staticmethod
    def validate_attack_type(attack_type: str) -> bool:
        """Validate attack type string."""
        valid_types = [
            'sql_injection', 'xss', 'command_injection', 'lfi', 'rfi',
            'xxe', 'path_traversal', 'ssrf', 'unknown', 'normal'
        ]
        return attack_type.lower() in valid_types
    
    @staticmethod
    def validate_http_method(method: str) -> bool:
        """Validate HTTP method."""
        valid_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
        return method.upper() in valid_methods
    
    @staticmethod
    def validate_confidence_score(score: float) -> bool:
        """Validate confidence score range."""
        return isinstance(score, (int, float)) and 0.0 <= score <= 1.0
    
    @staticmethod
    def sanitize_user_input(input_str: str, max_length: int = 1000) -> str:
        """Sanitize user input for safe storage and display."""
        if not isinstance(input_str, str):
            input_str = str(input_str)
        
        # Truncate to max length
        if len(input_str) > max_length:
            input_str = input_str[:max_length]
        
        # Remove dangerous characters
        sanitized = DataValidator.sanitize_sql_input(input_str)
        
        return sanitized.strip()
    
    @staticmethod
    def validate_pagination_params(limit: Any, offset: Any) -> tuple[int, int]:
        """Validate and normalize pagination parameters."""
        try:
            limit = int(limit) if limit is not None else 20
            offset = int(offset) if offset is not None else 0
            
            # Apply reasonable bounds
            limit = max(1, min(limit, 1000))
            offset = max(0, offset)
            
            return limit, offset
        except (ValueError, TypeError):
            raise ValidationError("Invalid pagination parameters")

class PayloadValidator:
    """Validator for attack payloads and patterns."""
    
    @staticmethod
    def is_suspicious_payload(payload: str) -> bool:
        """Check if payload contains suspicious patterns."""
        if not payload:
            return False
        
        suspicious_patterns = [
            r"(?i)(union\s+select|or\s+1\s*=\s*1|drop\s+table)",
            r"(?i)(<script|javascript:|on\w+\s*=)",
            r"(?i)(\.\.\/|\.\.\\|etc\/passwd|cmd\.exe)",
            r"(?i)(exec\s*\(|system\s*\(|shell_exec)"
        ]
        
        payload_lower = payload.lower()
        return any(re.search(pattern, payload_lower) for pattern in suspicious_patterns)
    
    @staticmethod
    def normalize_payload(payload: str) -> str:
        """Normalize payload for consistent analysis."""
        if not payload:
            return ""
        
        # URL decode common encodings
        import urllib.parse
        normalized = urllib.parse.unquote_plus(payload)
        
        # Convert to lowercase for case-insensitive analysis
        normalized = normalized.lower()
        
        # Normalize whitespace
        normalized = re.sub(r'\s+', ' ', normalized).strip()
        
        return normalized