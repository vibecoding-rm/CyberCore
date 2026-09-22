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


def configure_windows_asyncio() -> None:
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

