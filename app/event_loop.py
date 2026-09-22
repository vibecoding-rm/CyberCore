import asyncio
import selectors
import sys


def psycopg_compatible_loop() -> asyncio.AbstractEventLoop:
    if sys.platform == "win32":
        return asyncio.SelectorEventLoop(selectors.SelectSelector())

    try:
        import uvloop
    except ImportError:  # pragma: no cover - uvloop is installed in production
        return asyncio.new_event_loop()
    return uvloop.new_event_loop()
