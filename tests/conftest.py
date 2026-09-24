import asyncio
import os
import sys

# Tests that start the app lifespan use Settings().database_url, which would
# otherwise come from .env and write test traces and reviews into the
# development database. Point it at the test database, or at an address that
# cannot be reached when no test database is configured.
os.environ["DATABASE_URL"] = os.getenv(
    "CYBERCORE_TEST_DATABASE_URL",
    "postgresql://tests:tests@127.0.0.1:1/no-test-database",
)


def pytest_asyncio_loop_factories(config, item):
    if sys.platform == "win32":
        return {"selector": asyncio.SelectorEventLoop}
    return {"default": asyncio.new_event_loop}
