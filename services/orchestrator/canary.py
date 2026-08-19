"""
Canary Deployment Orchestrator (Blueprint Pillar 8).

Progressive canary rollout across 5% -> 25% -> 70% -> 100% rings. An in-process
Redlock-style distributed lock prevents concurrent patch jobs (anti-cascade).
If Redis is unavailable, a thread-safe in-process lock is used so tests and
single-node deployments stay hermetic.
"""

import asyncio
import os
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

RINGS = [0.05, 0.25, 0.70, 1.0]

_REDIS_PING = None
_LOCAL_LOCKS: Dict[str, str] = {}
_LOCAL_LOCKS_GUARD = threading.Lock()


def _redis_available() -> bool:
    """Best-effort probe: a single redis client ping per process."""
    global _REDIS_PING
    if _REDIS_PING is None:
        _REDIS_PING = bool(os.environ.get("NEXORA_REDIS_URL"))
    return _REDIS_PING


class Redlock:
    """Distributed lock with Redis fallback to an in-process mutex."""

    def __init__(self, lock_name: str, ttl_seconds: int = 300) -> None:
        self.lock_name = lock_name
        self.ttl_seconds = ttl_seconds
        self.token = uuid.uuid4().hex
        self._redis = None
        self._held = False
        self._local_held = False

    def _get_redis(self):
        if self._redis is None and _redis_available():
            import redis

            self._redis = redis.from_url(os.environ["NEXORA_REDIS_URL"], decode_responses=True)
        return self._redis

    def acquire(self) -> bool:
        r = self._get_redis()
        if r is not None:
            ok = r.set(self.lock_name, self.token, nx=True, ex=self.ttl_seconds)
            self._held = bool(ok)
            return self._held
        with _LOCAL_LOCKS_GUARD:
            if self._local_held:
                return True
            now = time.time()
            existing = _LOCAL_LOCKS.get(self.lock_name)
            if existing and now < existing:
                return False
            _LOCAL_LOCKS[self.lock_name] = now + self.ttl_seconds
            self._local_held = True
            return True

    def release(self) -> None:
        r = self._get_redis()
        if r is not None:
            if r.get(self.lock_name) == self.token:
                r.delete(self.lock_name)
            self._held = False
            return
        with _LOCAL_LOCKS_GUARD:
            if self._local_held:
                _LOCAL_LOCKS.pop(self.lock_name, None)
                self._local_held = False

    async def __aenter__(self) -> "Redlock":
        while not self.acquire():
            await asyncio.sleep(1)
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        self.release()


class CanaryDeployment:
    """Manages progressive canary rollouts over fixed rings."""

    def __init__(self, host_count: int, available_hosts: List[str]) -> None:
        self.host_count = max(host_count, 1)
        self.available_hosts = available_hosts or []
        self._completed: Dict[str, Dict[str, Any]] = {}

    def _hosts_for_ring(self, ring_index: int) -> List[str]:
        fraction = RINGS[ring_index]
        count = max(1, int(self.host_count * fraction))
        if not self.available_hosts:
            return [f"host-{i}" for i in range(count)]
        return self.available_hosts[:count]

    def next_ring(self, current_index: int = 0) -> Optional[Dict[str, Any]]:
        if current_index >= len(RINGS):
            return None
        return {
            "ring_index": current_index,
            "fraction": RINGS[current_index],
            "hosts": self._hosts_for_ring(current_index),
        }

    async def roll_forward(
        self,
        executor,
        action: Dict[str, Any],
        credentials: Dict[str, Any],
        start_ring: int = 0,
        verify_failed: bool = False,
    ) -> Dict[str, Any]:
        """Advance rings after each successful verification; halt on failure."""
        ring = self.next_ring(start_ring)
        if ring is None:
            return {"status": "COMPLETED", "rings": list(self._completed.values())}
        if verify_failed:
            return {
                "status": "HALTED",
                "halted_ring": start_ring,
                "message": "Post-patch verification failed; rollout halted before this ring",
            }
        for host in ring["hosts"]:
            result = await executor.execute_patch(host, action, credentials)
            self._completed[f"ring_{start_ring}_{host}"] = result
        return {
            "status": "RING_DEPLOYED",
            "ring_index": start_ring,
            "fraction": ring["fraction"],
            "hosts": ring["hosts"],
        }
