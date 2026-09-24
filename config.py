# heimdall/config.py
"""
Configuration module for Heimdall - A2A agent threat intelligence CLI tool.
This module handles configuration loading from environment variables and
provides type-safe configuration management.
"""
import os
from dataclasses import dataclass
from typing import Optional
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

@dataclass
class HeimdallConfig:
    """
    Configuration dataclass for Heimdall application.
    All configuration values are loaded from environment variables and
    validated at initialization time.
    """
    # LangSmith configuration
    langsmith_api_key: str
    langsmith_api_url: str = "https://api.smith.langchain.com"
    langsmith_max_retries: int = 3
    langsmith_pool_connections: int = 10
    langsmith_pool_maxsize: int = 10
    langsmith_timeout: int = 30
    
    # Output configuration
    output_dir: str = "./output"
    
    def __post_init__(self):
        """
        Validate configuration values after initialization.
        Raises:
            ValueError: If required fields are missing or invalid
        """
        if not self.langsmith_api_key:
            raise ValueError("LANGSMITH_API_KEY environment variable is required")
        if self.langsmith_max_retries < 0:
            raise ValueError("langsmith_max_retries must be non-negative")
        if self.langsmith_pool_connections <= 0:
            raise ValueError("langsmith_pool_connections must be positive")
        if self.langsmith_pool_maxsize <= 0:
            raise ValueError("langsmith_pool_maxsize must be positive")
        if self.langsmith_timeout <= 0:
            raise ValueError("langsmith_timeout must be positive")
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
    
    @classmethod
    def from_env(cls) -> 'HeimdallConfig':
        """
        Create configuration instance from environment variables.
        Returns:
            HeimdallConfig instance with values from environment
        """
        return cls(
            langsmith_api_key=os.getenv("LANGSMITH_API_KEY", ""),
            langsmith_api_url=os.getenv("LANGSMITH_API_URL", "https://api.smith.langchain.com"),
            langsmith_max_retries=int(os.getenv("LANGSMITH_MAX_RETRIES", "3")),
            langsmith_pool_connections=int(os.getenv("LANGSMITH_POOL_CONNECTIONS", "10")),
            langsmith_pool_maxsize=int(os.getenv("LANGSMITH_POOL_MAXSIZE", "10")),
            langsmith_timeout=int(os.getenv("LANGSMITH_TIMEOUT", "30")),
            output_dir=os.getenv("OUTPUT_DIR", "./output")
        )