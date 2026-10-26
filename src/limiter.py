import time
from src.redis_client import redis_db
from src.config import settings

async def is_rate_limited(ip: str) -> bool:
    """Distributed Fixed-Window Rate Limiting via Redis."""
    current_second = int(time.time())
    key = f"rl:{ip}:{current_second}"
    
    # Use a pipeline to send multiple commands in a single atomic network trip
    async with redis_db.pipeline(transaction=True) as pipe:
        pipe.incr(key)
        pipe.expire(key, 5)  # Auto-cleanup memory after 5 seconds
        result = await pipe.execute()
    
    current_count = result[0]
    return current_count > settings.rl_capacity