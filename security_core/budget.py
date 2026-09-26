"""Per-request guard budget. Every provider attempt consumes one slot."""
from contextvars import ContextVar
from contextlib import contextmanager

_remaining: ContextVar[int | None] = ContextVar('guard_calls_remaining', default=None)


@contextmanager
def model_budget(limit: int = 4):
    token = _remaining.set(max(0, min(4, limit)))
    try:
        yield
    finally:
        _remaining.reset(token)


def consume_attempt():
    from .gemini import GuardModelError
    remaining = _remaining.get()
    if remaining is None:
        # Direct pipeline callers still have two bounded calls, each at most
        # two attempts. HTTP callers additionally enter model_budget.
        return
    if remaining <= 0:
        raise GuardModelError('Guard model budget exhausted')
    _remaining.set(remaining - 1)
