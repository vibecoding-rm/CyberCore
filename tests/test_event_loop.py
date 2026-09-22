import asyncio
import sys

from app.event_loop import psycopg_compatible_loop


def test_psycopg_compatible_loop_is_not_proactor_on_windows():
    loop = psycopg_compatible_loop()
    try:
        if sys.platform == "win32":
            assert isinstance(loop, asyncio.SelectorEventLoop)
    finally:
        loop.close()
