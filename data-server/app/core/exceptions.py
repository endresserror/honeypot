"""
Custom application exceptions for better error handling
"""

class ScannerException(Exception):
    """Base exception for scanner application errors."""
    
    def __init__(self, message: str, code: str = None):
        super().__init__(message)
        self.message = message
        self.code = code or 'SCANNER_ERROR'

class ConfigurationError(ScannerException):
    """Exception raised for configuration-related errors."""
    
    def __init__(self, message: str):
        super().__init__(message, 'CONFIG_ERROR')

class PayloadExtractionError(ScannerException):
    """Exception raised during payload extraction process."""
    
    def __init__(self, message: str):
        super().__init__(message, 'PAYLOAD_ERROR')

class SignatureGenerationError(ScannerException):
    """Exception raised during signature generation process."""
    
    def __init__(self, message: str):
        super().__init__(message, 'SIGNATURE_ERROR')

class LogAnalysisError(ScannerException):
    """Exception raised during log analysis process."""
    
    def __init__(self, message: str):
        super().__init__(message, 'ANALYSIS_ERROR')

class DatabaseError(ScannerException):
    """Exception raised for database-related errors."""
    
    def __init__(self, message: str):
        super().__init__(message, 'DATABASE_ERROR')

class ValidationError(ScannerException):
    """Exception raised for data validation errors."""
    
    def __init__(self, message: str, field: str = None):
        super().__init__(message, 'VALIDATION_ERROR')
        self.field = field