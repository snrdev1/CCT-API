"""Refresh-token sessions and login rate limiting, both stored in Redis.

session:{sid}         hash: user_id, current_hash, previous_hash, rotated_at, created_at
refresh:{token_hash}  -> sid   (old hashes are kept, so a reused token can be detected)
login_fail:{user}:{ip} -> number of failed logins
"""

import logging
import time

from app.config import settings
from app.db import redis

log = logging.getLogger(__name__)

REFRESH_TTL = settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400
MAX_LIFETIME = settings.SESSION_MAX_DAYS * 86400

# Runs atomically inside Redis, so two concurrent refreshes with the same token can't both rotate.
#   rotated: the presented token is the current one, so swap in the new hash
#   grace:   it was replaced seconds ago (another tab or a retry won the race)
#   reused:  it's older than that, so it was stolen, and the whole session is deleted
_rotate = redis.register_script("""
local key = KEYS[1]
if redis.call('EXISTS', key) == 0 then return {'invalid', ''} end

local now = tonumber(redis.call('TIME')[1])
local s = redis.call('HGETALL', key)
local session = {}
for i = 1, #s, 2 do session[s[i]] = s[i + 1] end

if session.current_hash == ARGV[1] then
    local ttl = math.min(tonumber(ARGV[4]), tonumber(session.created_at) + tonumber(ARGV[5]) - now)
    if ttl <= 0 then
        redis.call('DEL', key)
        return {'invalid', ''}
    end
    redis.call('HSET', key, 'current_hash', ARGV[2], 'previous_hash', ARGV[1], 'rotated_at', now)
    redis.call('EXPIRE', key, ttl)
    redis.call('SET', KEYS[2], ARGV[3], 'EX', ttl)
    return {'rotated', session.user_id}
end

if session.previous_hash == ARGV[1] and now - tonumber(session.rotated_at) <= tonumber(ARGV[6]) then
    return {'grace', session.user_id}
end

redis.call('DEL', key)
return {'reused', session.user_id}
""")


async def create(session_id: str, user_id: int, token_hash: str) -> None:
    ttl = min(REFRESH_TTL, MAX_LIFETIME)
    session = {"user_id": user_id, "current_hash": token_hash, "previous_hash": "", "rotated_at": 0}
    async with redis.pipeline() as pipe:
        pipe.hset(f"session:{session_id}", mapping=session | {"created_at": int(time.time())})
        pipe.expire(f"session:{session_id}", ttl)
        pipe.set(f"refresh:{token_hash}", session_id, ex=ttl)
        await pipe.execute()


async def find(token_hash: str) -> str | None:
    return await redis.get(f"refresh:{token_hash}")


async def rotate(session_id: str, presented_hash: str, new_hash: str) -> tuple[str, int | None]:
    """Returns (status, user_id), where status is 'rotated', 'grace', 'reused' or 'invalid'."""
    status, user_id = await _rotate(
        keys=[f"session:{session_id}", f"refresh:{new_hash}"],
        args=[presented_hash, new_hash, session_id, REFRESH_TTL, MAX_LIFETIME, settings.REFRESH_GRACE_SECONDS],
    )
    if status == "reused":
        log.warning("Refresh token reuse detected, session %s revoked (user %s)", session_id, user_id)
    return status, int(user_id) if user_id else None


async def exists(session_id: str) -> bool:
    return await redis.exists(f"session:{session_id}") == 1


async def delete(session_id: str) -> None:
    await redis.delete(f"session:{session_id}")


async def locked_for(username: str, ip: str) -> int:
    """Seconds until this username + IP may try to log in again (0 = allowed)."""
    failures = await redis.get(f"login_fail:{username}:{ip}")
    if failures is None or int(failures) < settings.LOGIN_MAX_ATTEMPTS:
        return 0
    return max(await redis.ttl(f"login_fail:{username}:{ip}"), 1)


async def record_failure(username: str, ip: str) -> None:
    async with redis.pipeline() as pipe:
        pipe.incr(f"login_fail:{username}:{ip}")
        pipe.expire(f"login_fail:{username}:{ip}", settings.LOGIN_LOCKOUT_MINUTES * 60, nx=True)
        await pipe.execute()


async def clear_failures(username: str, ip: str) -> None:
    await redis.delete(f"login_fail:{username}:{ip}")
