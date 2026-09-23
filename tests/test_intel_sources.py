import json

import httpx
import pytest

from app.intelligence.nvd import NvdClient, NvdError, parse_nvd_cve
from app.intelligence.osv import OsvClient, OsvError, parse_osv_record

NVD_PAYLOAD = {
    "resultsPerPage": 1,
    "totalResults": 1,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2024-6387",
                "published": "2024-07-01T13:15:10.197",
                "lastModified": "2026-06-17T04:08:53.933",
                "descriptions": [
                    {"lang": "es", "value": "descripción"},
                    {"lang": "en", "value": "regreSSHion race condition"},
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "secalert@redhat.com",
                            "type": "Secondary",
                            "cvssData": {"version": "3.1", "baseScore": 8.1, "vectorString": "CVSS:3.1/SEC"},
                        },
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {"version": "3.1", "baseScore": 8.1, "vectorString": "CVSS:3.1/PRI"},
                        },
                    ],
                    "cvssMetricV2": [
                        {"type": "Primary", "cvssData": {"version": "2.0", "baseScore": 5.0}}
                    ],
                },
                "weaknesses": [
                    {"description": [{"lang": "en", "value": "CWE-364"}]},
                    {"description": [{"lang": "en", "value": "NVD-CWE-noinfo"}]},
                ],
                "configurations": [
                    {
                        "nodes": [
                            {
                                "operator": "OR",
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                                        "versionStartIncluding": "8.6",
                                        "versionEndIncluding": "9.8",
                                    },
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:openbsd:openssh:8.5:p1:*:*:*:*:*:*",
                                    },
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:a:openbsd:openssh:1.0:*:*:*:*:*:*:*",
                                    },
                                ],
                            }
                        ]
                    },
                    {
                        "operator": "AND",
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:netapp:ontap:-:*:*:*:*:*:*:*",
                                    }
                                ]
                            },
                            {
                                "negate": True,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
                                    }
                                ],
                            },
                        ],
                    },
                ],
            }
        }
    ],
}

OSV_RECORD = {
    "id": "GHSA-xxxx-yyyy-zzzz",
    "aliases": ["cve-2024-0001"],
    "related": ["DEBIAN-CVE-2024-0001"],
    "summary": "Prototype pollution",
    "modified": "2026-01-01T00:00:00Z",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N"}],
    "database_specific": {"cwe_ids": ["CWE-1321"]},
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "lodash"},
            "ranges": [
                {
                    "type": "SEMVER",
                    "events": [
                        {"introduced": "0"},
                        {"fixed": "4.17.21"},
                        {"introduced": "5.0.0"},
                        {"last_affected": "5.0.2"},
                        {"introduced": "6.0.0"},
                    ],
                },
                {"type": "GIT", "repo": "https://x", "events": [{"introduced": "abc123"}]},
            ],
            "versions": ["4.17.20"],
        },
        {"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]},
    ],
}


def test_parse_nvd_prefers_primary_newest_metric_and_keeps_ranges():
    record = parse_nvd_cve(NVD_PAYLOAD)

    assert record is not None
    assert record.vulnerability_id == "CVE-2024-6387"
    assert record.description == "regreSSHion race condition"
    assert (record.cvss, record.cvss_vector, record.cvss_version) == (8.1, "CVSS:3.1/PRI", "3.1")
    assert record.cwe_ids == ["CWE-364"]
    assert record.published_at is not None and record.published_at.tzinfo is not None

    by_criteria = {r.criteria: r for r in record.ranges}
    assert len(record.ranges) == 3  # non-vulnerable and negated matches dropped
    ranged = by_criteria["cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"]
    assert ranged.range_type == "cpe"
    assert (ranged.version_start_including, ranged.version_end_including) == ("8.6", "9.8")
    exact = by_criteria["cpe:2.3:a:openbsd:openssh:8.5:p1:*:*:*:*:*:*"]
    assert (exact.range_type, exact.exact_version) == ("exact", "8.5p1")
    platform = by_criteria["cpe:2.3:a:netapp:ontap:-:*:*:*:*:*:*:*"]
    assert platform.requires_platform is True
    assert platform.version_start_including == "0"


def test_parse_nvd_empty_and_invalid():
    assert parse_nvd_cve({"vulnerabilities": []}) is None
    with pytest.raises(NvdError):
        parse_nvd_cve({"message": "error"})


def test_parse_osv_record_ranges_and_aliases():
    record = parse_osv_record(OSV_RECORD)

    assert record.aliases == ["CVE-2024-0001", "DEBIAN-CVE-2024-0001"]
    assert record.cvss is None and record.cvss_vector == "CVSS:3.1/AV:N"
    assert record.cwe_ids == ["CWE-1321"]
    criteria = [r.criteria for r in record.ranges]
    assert criteria == [
        "osv:npm/lodash@4.17.20",
        "osv:npm/lodash SEMVER [0, 4.17.21)",
        "osv:npm/lodash SEMVER [5.0.0, 5.0.2]",
        "osv:npm/lodash SEMVER [6.0.0, ∞)",
    ]
    assert all(r.range_type in {"exact", "semver"} for r in record.ranges)


@pytest.mark.asyncio
async def test_nvd_client_throttles_and_sends_key():
    seen: list[httpx.Request] = []
    waits: list[float] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=NVD_PAYLOAD)

    async def fake_sleep(seconds: float) -> None:
        waits.append(seconds)

    http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        headers={"apiKey": "secret"},
    )
    client = NvdClient(api_key="secret", http_client=http_client, sleep=fake_sleep)
    try:
        record, raw = await client.fetch_cve("cve-2024-6387")
        await client.fetch_cve("CVE-2024-6387")
    finally:
        await http_client.aclose()

    assert record is not None and raw == NVD_PAYLOAD
    assert seen[0].url.params["cveId"] == "CVE-2024-6387"
    assert seen[0].headers["apiKey"] == "secret"
    assert len(waits) == 1 and 0 < waits[0] <= 0.6


@pytest.mark.asyncio
async def test_nvd_client_rejects_bad_ids_and_sanitizes_errors():
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="internal detail")

    http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = NvdClient(http_client=http_client)
    try:
        with pytest.raises(ValueError):
            await client.fetch_cve("CVE-2024; DROP")
        with pytest.raises(NvdError, match="HTTP 503") as exc_info:
            await client.fetch_cve("CVE-2024-6387")
    finally:
        await http_client.aclose()
    assert "internal detail" not in str(exc_info.value)


@pytest.mark.asyncio
async def test_osv_client_paginates_and_handles_missing():
    bodies: list[dict] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.startswith("/v1/vulns/"):
            return httpx.Response(404, json={"message": "Bug not found"})
        body = json.loads(request.content)
        bodies.append(body)
        if "page_token" not in body:
            return httpx.Response(200, json={"vulns": [{"id": "A"}], "next_page_token": "t1"})
        return httpx.Response(200, json={"vulns": [{"id": "B"}]})

    http_client = httpx.AsyncClient(
        base_url="https://osv.test",
        transport=httpx.MockTransport(handler),
    )
    client = OsvClient(http_client=http_client)
    try:
        assert await client.get_vulnerability("CVE-2099-0001") is None
        records = await client.query_package("npm", "lodash", "4.17.20")
    finally:
        await http_client.aclose()

    assert [r["id"] for r in records] == ["A", "B"]
    assert bodies[0] == {"package": {"ecosystem": "npm", "name": "lodash"}, "version": "4.17.20"}
    assert bodies[1]["page_token"] == "t1"


@pytest.mark.asyncio
async def test_osv_client_errors_are_sanitized():
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="stack trace")

    http_client = httpx.AsyncClient(
        base_url="https://osv.test",
        transport=httpx.MockTransport(handler),
    )
    client = OsvClient(http_client=http_client)
    try:
        with pytest.raises(OsvError, match="HTTP 500") as exc_info:
            await client.get_vulnerability("CVE-2024-0001")
    finally:
        await http_client.aclose()
    assert "stack" not in str(exc_info.value)
