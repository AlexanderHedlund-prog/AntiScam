"""Shared, process-local VirusTotal request budget for free public API.

The limit is deliberately lower than the public maximum (4/min) to leave a
margin. Multiple Render workers/instances need a shared Redis-style limiter.
"""
import asyncio
import time
from collections import deque

_CALLS: deque[float] = deque()
_LOCK = asyncio.Lock()


async def take_virustotal_slot() -> bool:
    async with _LOCK:
        now = time.monotonic()
        while _CALLS and now - _CALLS[0] >= 60.0:
            _CALLS.popleft()
        if len(_CALLS) >= 3:
            return False
        _CALLS.append(now)
        return True
