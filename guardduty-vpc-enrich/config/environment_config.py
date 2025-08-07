import os
from typing import Dict, Any


class EnvironmentConfig:
    def __init__(self, environment: str = "dev"):
        self.environment = environment
        self._config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        base_config = {
            "lambda_timeout": 300,
            "lambda_memory": 1024,
            "lambda_runtime": "python3.11",
            "log_level": "INFO",
            "time_window_before": 15,
            "time_window_after": 15,
            "severity_threshold": 4.0,
            "retention_days": 30,
            "enable_xray": True,
            "tags": {
                "Environment": self.environment,
                "Project": "GuardDuty-VPC-Enrichment",
                "Owner": "SecurityTeam",
                "CostCenter": "Security",
                "SecurityLevel": "High"
            }
        }
        
        env_specific_config = {
            "dev": {
                "lambda_memory": 512,
                "log_level": "DEBUG",
                "retention_days": 7,
                "enable_xray": False
            },
            "staging": {
                "lambda_memory": 1024,
                "log_level": "INFO",
                "retention_days": 14
            },
            "prod": {
                "lambda_memory": 1024,
                "log_level": "WARN",
                "retention_days": 90,
                "severity_threshold": 6.0
            }
        }
        
        if self.environment in env_specific_config:
            base_config.update(env_specific_config[self.environment])
        
        return base_config
    
    def get(self, key: str, default: Any = None) -> Any:
        return self._config.get(key, default)
    
    @property
    def lambda_timeout(self) -> int:
        return self._config["lambda_timeout"]
    
    @property
    def lambda_memory(self) -> int:
        return self._config["lambda_memory"]
    
    @property
    def lambda_runtime(self) -> str:
        return self._config["lambda_runtime"]
    
    @property
    def log_level(self) -> str:
        return self._config["log_level"]
    
    @property
    def time_window_before(self) -> int:
        return self._config["time_window_before"]
    
    @property
    def time_window_after(self) -> int:
        return self._config["time_window_after"]
    
    @property
    def severity_threshold(self) -> float:
        return self._config["severity_threshold"]
    
    @property
    def retention_days(self) -> int:
        return self._config["retention_days"]
    
    @property
    def enable_xray(self) -> bool:
        return self._config["enable_xray"]
    
    @property
    def tags(self) -> Dict[str, str]:
        return self._config["tags"]