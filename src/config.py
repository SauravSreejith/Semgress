import yaml
import os
from pathlib import Path

CONFIG_PATH = Path(__file__).parent.parent / "config.yaml"

class Config:
    def __init__(self):
        with open(CONFIG_PATH, "r") as f:
            self._cfg = yaml.safe_load(f)
            
        self.host = self._cfg["server"]["host"]
        self.port = self._cfg["server"]["port"]
        
        self.upstream_url = os.getenv("UPSTREAM_URL", self._cfg["upstream"]["url"])
        
        self.model_id = self._cfg["waf"]["model_id"]
        self.risk_threshold = self._cfg["waf"]["risk_threshold"]
        self.max_batch_size = self._cfg["waf"]["max_batch_size"]
        self.batch_timeout_ms = self._cfg["waf"]["batch_timeout_ms"]
        
        # Redis config allows environment variable override for Docker
        self.redis_url = os.getenv("REDIS_URL", self._cfg["redis"]["url"])
        self.cache_ttl = self._cfg["redis"]["cache_ttl_seconds"]
        
        self.rl_limit = self._cfg["rate_limiter"]["requests_per_second"]

settings = Config()