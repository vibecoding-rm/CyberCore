import pytest

from app.storage.postgres_assets import PostgresAssetRepository


def test_asset_repo_rejects_invalid_timeout():
    with pytest.raises(ValueError, match="timeout de conexión"):
        PostgresAssetRepository("postgresql://unused", connect_timeout_seconds=0)


@pytest.mark.asyncio
async def test_asset_repo_rejects_invalid_criticality():
    repo = PostgresAssetRepository("postgresql://unused")
    with pytest.raises(ValueError, match="criticidad"):
        await repo.upsert_asset("host:1.1.1.1", criticality=6)


@pytest.mark.asyncio
async def test_asset_repo_rejects_invalid_port():
    repo = PostgresAssetRepository("postgresql://unused")
    with pytest.raises(ValueError, match="Puerto fuera de rango"):
        await repo.upsert_service(1, port=70000)


@pytest.mark.asyncio
async def test_asset_repo_rejects_invalid_protocol():
    repo = PostgresAssetRepository("postgresql://unused")
    with pytest.raises(ValueError, match="Protocolo inválido"):
        await repo.upsert_service(1, port=80, protocol="icmp")
