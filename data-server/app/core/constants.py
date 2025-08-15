"""
Application constants and configuration values
"""

from enum import Enum

class AttackPatternType(Enum):
    """Types of attack patterns for better organization."""
    SQL_INJECTION_UNION = "sql_injection_union"
    SQL_INJECTION_BOOLEAN = "sql_injection_boolean"
    SQL_INJECTION_TIME = "sql_injection_time"
    SQL_INJECTION_ERROR = "sql_injection_error"
    XSS_REFLECTED = "xss_reflected"
    XSS_STORED = "xss_stored"
    XSS_DOM = "xss_dom"
    COMMAND_INJECTION_UNIX = "command_injection_unix"
    COMMAND_INJECTION_WINDOWS = "command_injection_windows"
    PATH_TRAVERSAL_UNIX = "path_traversal_unix"
    PATH_TRAVERSAL_WINDOWS = "path_traversal_windows"
    FILE_INCLUSION_LOCAL = "file_inclusion_local"
    FILE_INCLUSION_REMOTE = "file_inclusion_remote"

class AnalysisConstants:
    """Constants for analysis processes."""
    
    # Confidence thresholds
    MIN_CONFIDENCE_THRESHOLD = 0.5
    HIGH_CONFIDENCE_THRESHOLD = 0.8
    CRITICAL_CONFIDENCE_THRESHOLD = 0.9
    
    # Payload analysis
    MIN_PAYLOAD_LENGTH = 3
    MAX_PAYLOAD_LENGTH = 1000
    MAX_NORMALIZED_PAYLOAD_LENGTH = 200
    
    # Response analysis
    MAX_BASELINE_SAMPLES = 100
    ANOMALY_THRESHOLD = 2.0  # Standard deviations
    
    # Signature generation
    MAX_SIGNATURES_PER_BATCH = 50
    SIGNATURE_MERGE_SIMILARITY_THRESHOLD = 0.85

class SecurityConstants:
    """Security-related constants."""
    
    # Rate limiting
    DEFAULT_RATE_LIMIT = "100 per hour"
    API_RATE_LIMIT = "1000 per hour"
    
    # JWT
    JWT_ALGORITHM = "HS256"
    DEFAULT_TOKEN_EXPIRY_HOURS = 24
    
    # Password policy
    MIN_PASSWORD_LENGTH = 8

class DatabaseConstants:
    """Database-related constants."""
    
    # Connection pool
    DEFAULT_POOL_SIZE = 10
    DEFAULT_MAX_OVERFLOW = 20
    DEFAULT_POOL_TIMEOUT = 30
    
    # Query limits
    MAX_QUERY_LIMIT = 1000
    DEFAULT_PAGE_SIZE = 20