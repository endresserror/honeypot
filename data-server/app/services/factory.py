"""
Service factory for creating and managing application services
"""

from typing import Dict, Any
from app.services.log_analyzer import LogAnalyzer
from app.services.payload_extractor import PayloadExtractor
from app.services.response_analyzer import ResponseAnalyzer
from app.services.signature_generator import SignatureGenerator
from app.config import config_manager

class ServiceFactory:
    """Factory for creating and managing application services."""
    
    def __init__(self):
        self._services = {}
        self._config = config_manager.load_config()
    
    def get_log_analyzer(self) -> LogAnalyzer:
        """Get or create log analyzer service."""
        if 'log_analyzer' not in self._services:
            self._services['log_analyzer'] = LogAnalyzer(self._config)
        return self._services['log_analyzer']
    
    def get_payload_extractor(self) -> PayloadExtractor:
        """Get or create payload extractor service."""
        if 'payload_extractor' not in self._services:
            self._services['payload_extractor'] = PayloadExtractor(self._config)
        return self._services['payload_extractor']
    
    def get_response_analyzer(self) -> ResponseAnalyzer:
        """Get or create response analyzer service."""
        if 'response_analyzer' not in self._services:
            self._services['response_analyzer'] = ResponseAnalyzer(self._config)
        return self._services['response_analyzer']
    
    def get_signature_generator(self) -> SignatureGenerator:
        """Get or create signature generator service."""
        if 'signature_generator' not in self._services:
            self._services['signature_generator'] = SignatureGenerator(self._config)
        return self._services['signature_generator']
    
    def reload_config(self):
        """Reload configuration and recreate services."""
        config_manager.reload_config()
        self._config = config_manager.load_config()
        self._services.clear()

# Global service factory instance
service_factory = ServiceFactory()