"""
Configuration management module for centralized config handling
"""

import os
import yaml
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)

class ConfigManager:
    """Centralized configuration manager for application settings."""
    
    def __init__(self, config_path: str = None):
        self.config_path = config_path or self._get_default_config_path()
        self._config_cache = None
    
    def _get_default_config_path(self) -> str:
        """Get default configuration file path."""
        return os.path.join(os.path.dirname(__file__), '../../config/config.yml')
    
    def load_config(self) -> Dict[str, Any]:
        """Load and cache configuration from file."""
        if self._config_cache is None:
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    self._config_cache = yaml.safe_load(f)
                logger.info(f"Configuration loaded from {self.config_path}")
            except FileNotFoundError:
                logger.error(f"Configuration file not found: {self.config_path}")
                raise
            except yaml.YAMLError as e:
                logger.error(f"Error parsing YAML configuration: {e}")
                raise
        
        return self._config_cache
    
    def get_section(self, section_name: str) -> Dict[str, Any]:
        """Get specific configuration section."""
        config = self.load_config()
        return config.get(section_name, {})
    
    def get_value(self, section_name: str, key: str, default: Any = None) -> Any:
        """Get specific configuration value with default."""
        section = self.get_section(section_name)
        return section.get(key, default)
    
    def get_database_config(self) -> Dict[str, Any]:
        """Get database-specific configuration."""
        return self.get_section('database')
    
    def get_security_config(self) -> Dict[str, Any]:
        """Get security-specific configuration."""
        return self.get_section('security')
    
    def get_logging_config(self) -> Dict[str, Any]:
        """Get logging-specific configuration."""
        return self.get_section('logging')
    
    def get_analysis_config(self) -> Dict[str, Any]:
        """Get analysis-specific configuration."""
        return self.get_section('analysis')
    
    def reload_config(self) -> None:
        """Reload configuration from file."""
        self._config_cache = None
        self.load_config()

# Global configuration instance
config_manager = ConfigManager()