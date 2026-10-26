import time
import redis.asyncio as redis
from src.config import settings

# Global async Redis connection pool
redis_db = redis.from_url(settings.redis_url, decode_responses=True)

async def is_rate_limited(ip: str) -> bool:
    """
    Distributed Fixed-Window Rate Limiting.
    Creates a new key every second based on the timestamp.
    """
    current_second = int(time.time())
    key = f"rate_limit:{ip}:{current_second}"
    
    # Increment counter
    requests_this_second = await redis_db.incr(key)
    
    # Set expiry on the first request of this second to auto-cleanup
    if requests_this_second == 1:
        await redis_db.expire(key, 2)
        
    return requests_this_second > settings.rl_limit

async def get_cached_score(signature: str):
    """Fetches a WAF decision from Redis (<1ms)."""
    score = await redis_db.get(f"waf_cache:{signature}")
    return float(score) if score else None

async def set_cached_score(signature: str, score: float):
    """Caches a WAF decision using SETEX (Set with Expiry)."""
    await redis_db.setex(
        name=f"waf_cache:{signature}",
        time=settings.cache_ttl,
        value=str(score)
    )