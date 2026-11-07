"""Bridge from synchronous worker threads to asyncio SSE queues."""
from __future__ import annotations

import asyncio
import threading
from collections import deque
from dataclasses import dataclass

from contracts.models import LiveEvent


@dataclass
class Subscription:
    loop: asyncio.AbstractEventLoop
    queue: "asyncio.Queue[tuple[str, str]]"


class EventBus:
    """publish() is safe to call from any thread; subscribe() must run inside the event loop."""

    def __init__(self, history: int = 1000):
        self._subs: list[Subscription] = []
        self._lock = threading.Lock()
        self.history: deque[tuple[str, str]] = deque(maxlen=history)  # (type, json) for tests and replay

    def subscribe(self, maxsize: int = 1000) -> Subscription:
        sub = Subscription(asyncio.get_running_loop(), asyncio.Queue(maxsize=maxsize))
        with self._lock:
            self._subs.append(sub)
        return sub

    def unsubscribe(self, sub: Subscription) -> None:
        with self._lock:
            if sub in self._subs:
                self._subs.remove(sub)

    @staticmethod
    def _offer(queue: "asyncio.Queue[tuple[str, str]]", item: tuple[str, str]) -> None:
        if queue.full():
            try:
                queue.get_nowait()  # drop the oldest rather than block the producer
            except asyncio.QueueEmpty:
                pass
        queue.put_nowait(item)

    def publish(self, event: LiveEvent) -> None:
        item = (event.type.value, event.model_dump_json())
        with self._lock:
            self.history.append(item)
            subs = list(self._subs)
        for sub in subs:
            try:
                sub.loop.call_soon_threadsafe(self._offer, sub.queue, item)
            except RuntimeError:  # the loop is closed
                self.unsubscribe(sub)
