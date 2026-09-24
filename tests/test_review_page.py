import re
from pathlib import Path

import httpx
import pytest

from app.main import app

WEB = Path(__file__).parents[1] / "app" / "web"


async def get(path: str) -> httpx.Response:
    # No lifespan: the page must not depend on the database or credentials.
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        return await client.get(path)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("path", "media"),
    [("/review", "text/html"), ("/review/review.js", "text/javascript"), ("/review/review.css", "text/css")],
)
async def test_review_assets_are_served_with_strict_headers(path, media):
    response = await get(path)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith(media)
    csp = response.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "default-src 'none'" in csp
    assert "unsafe-inline" not in csp
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/review/..%2Fmain.py", "/review/review.py", "/review/secret"])
async def test_only_whitelisted_review_files_are_served(path):
    assert (await get(path)).status_code == 404


def test_page_never_renders_trace_content_as_html():
    script = (WEB / "review.js").read_text(encoding="utf-8")
    html = (WEB / "review.html").read_text(encoding="utf-8")

    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
        assert sink not in script
    # CSP blocks inline code; keep the page free of it so nothing silently breaks.
    assert not re.search(r"<script(?![^>]*\bsrc=)", html)
    assert not re.search(r"\son[a-z]+\s*=", html)
    # The key must not outlive the tab.
    assert "localStorage" not in script
