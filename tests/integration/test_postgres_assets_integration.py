from datetime import datetime, timezone
import os
from uuid import uuid4
import psycopg
import pytest

from app.api.models import Evidence
from app.storage.postgres_assets import PostgresAssetRepository


DATABASE_URL = os.getenv("CYBERCORE_TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not DATABASE_URL,
        reason="CYBERCORE_TEST_DATABASE_URL no está configurada",
    ),
]


@pytest.mark.asyncio
async def test_asset_upsert_and_retrieval():
    repo = PostgresAssetRepository(DATABASE_URL)
    uid = uuid4().hex[:6]
    test_key = f"test-host-{uid}"
    test_ip = f"10.200.{(uuid4().int % 200) + 1}.{(uuid4().int % 200) + 1}"

    asset_id = await repo.upsert_asset(
        asset_key=test_key,
        display_name="Test Host",
        environment="test",
        criticality=4,
    )
    assert asset_id > 0

    addr_id = await repo.upsert_address(asset_id, test_ip)
    assert addr_id > 0

    svc_id = await repo.upsert_service(
        asset_id=asset_id,
        port=22,
        protocol="tcp",
        service_name="ssh",
        product="OpenSSH",
        version="8.9p1",
    )
    assert svc_id > 0

    # Retrieve by asset_id
    asset = await repo.get_asset(asset_id)
    assert asset is not None
    assert asset["asset_key"] == test_key
    assert asset["criticality"] == 4
    assert len(asset["addresses"]) == 1
    assert test_ip in asset["addresses"][0]["address"]
    assert len(asset["services"]) == 1
    assert asset["services"][0]["port"] == 22
    assert asset["services"][0]["product"] == "OpenSSH"

    # Retrieve by IP
    by_addr = await repo.get_asset_by_address(test_ip)
    assert by_addr is not None
    assert by_addr["id"] == asset_id


@pytest.mark.asyncio
async def test_record_discovery_evidence_upserts_assets():
    repo = PostgresAssetRepository(DATABASE_URL)
    test_ip = f"10.201.{(uuid4().int % 200) + 1}.{(uuid4().int % 200) + 1}"

    evidence = Evidence(
        source="discover_hosts",
        target="192.168.10.0/24",
        data={
            "target": "192.168.10.0/24",
            "total_hosts_up": 1,
            "hosts": [
                # Same shape NmapDiscoverHostsTool emits.
                {"address": test_ip, "hostname": "discovered-node-01", "status": "up"}
            ],
        },
        sha256="1" * 64,
    )

    asset_ids = await repo.record_evidence(evidence)
    assert len(asset_ids) == 1
    asset = await repo.get_asset(asset_ids[0])
    assert asset is not None
    assert asset["asset_key"] == f"host:{test_ip}"
    assert asset["display_name"] == "discovered-node-01"
    assert any(test_ip in a["address"] for a in asset["addresses"])


@pytest.mark.asyncio
async def test_record_inspect_services_evidence_upserts_services():
    repo = PostgresAssetRepository(DATABASE_URL)
    test_ip = f"10.202.{(uuid4().int % 200) + 1}.{(uuid4().int % 200) + 1}"

    evidence = Evidence(
        source="inspect_services",
        target=test_ip,
        data={
            "target": test_ip,
            "hostname": "inspected-node-01",
            "ports_scanned": [80, 443],
            "services": [
                {
                    "port": 80,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "http",
                    "product": "nginx",
                    "version": "1.24.0",
                },
                {
                    "port": 443,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "https",
                    "product": "nginx",
                    "version": "1.24.0",
                },
            ],
        },
        sha256="2" * 64,
    )

    asset_ids = await repo.record_evidence(evidence)
    assert len(asset_ids) == 1
    asset = await repo.get_asset(asset_ids[0])
    assert asset is not None
    assert len(asset["services"]) == 2
    ports = [s["port"] for s in asset["services"]]
    assert 80 in ports
    assert 443 in ports
