from redis.asyncio import Redis

from app.core.config import settings

# Module-level singleton: redis-py's async client manages its own connection
# pool internally, so a single shared instance is the intended usage rather
# than opening a new client per request.
redis_client = Redis.from_url(settings.redis_url, decode_responses=True)
