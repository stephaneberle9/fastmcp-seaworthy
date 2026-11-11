"""Shared fixtures: DynamoDB and PostgreSQL endpoints for the store backend tests."""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import AsyncIterator, Iterator

import boto3
import pytest
from moto.server import ThreadedMotoServer

REGION = "eu-central-1"


@pytest.fixture(scope="session")
def dynamodb_endpoint() -> Iterator[str]:
    """moto's DynamoDB emulation, served on an ephemeral 127.0.0.1 port.

    Server mode because the store talks through aioboto3, whose aiohttp
    transport moto's in-process botocore patches do not reach. Bound to the
    IPv4 loopback literal: ``localhost`` can resolve to ``::1`` first, which
    the server does not listen on.
    """
    server = ThreadedMotoServer(ip_address="127.0.0.1", port=0, verbose=False)
    server.start()
    host, port = server.get_host_and_port()
    try:
        yield f"http://{host}:{port}"
    finally:
        server.stop()


@pytest.fixture
def aws_env(dynamodb_endpoint: str, monkeypatch: pytest.MonkeyPatch, tmp_path) -> str:
    """Point the AWS SDK at the emulator, with throwaway credentials.

    ``AWS_ENDPOINT_URL_DYNAMODB`` is the SDK's own per-service endpoint
    override, so the store needs no endpoint setting of its own to be tested
    -- or to run against DynamoDB Local. The config and credentials files are
    pointed at nothing so a developer's real AWS profile cannot leak in.
    """
    monkeypatch.setenv("AWS_ENDPOINT_URL_DYNAMODB", dynamodb_endpoint)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "aws-config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "aws-credentials"))
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)
    return dynamodb_endpoint


def dynamodb_client(endpoint: str):
    return boto3.client("dynamodb", endpoint_url=endpoint, region_name=REGION)


@pytest.fixture
def dynamodb_table(aws_env: str) -> str:
    """A fresh table with the schema the README documents for infrastructure."""
    name = f"fastmcp-seaworthy-{uuid.uuid4().hex[:12]}"
    client = dynamodb_client(aws_env)
    client.create_table(
        TableName=name,
        KeySchema=[
            {"AttributeName": "collection", "KeyType": "HASH"},
            {"AttributeName": "key", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "collection", "AttributeType": "S"},
            {"AttributeName": "key", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    client.update_time_to_live(
        TableName=name,
        TimeToLiveSpecification={"Enabled": True, "AttributeName": "ttl"},
    )
    return name


# --- PostgreSQL -------------------------------------------------------------

DEFAULT_TEST_POSTGRES_URL = "postgresql://postgres:postgres@127.0.0.1:5432/postgres"
"""Where the PostgreSQL tests look when ``TEST_POSTGRES_URL`` is unset.

The IPv4 loopback literal, not ``localhost``: a server published from a
container often binds IPv4 only, and a client trying ``::1`` first waits for
that attempt to time out on every connection.
"""


def _postgres_unavailable(url: str) -> str | None:
    """Why ``url`` cannot be used, or ``None`` when a server answers there."""
    try:
        import asyncpg
    except ImportError:
        return "asyncpg is not installed (the 'postgres' extra)"

    async def probe() -> None:
        connection = await asyncpg.connect(url, timeout=5)
        await connection.close()

    try:
        asyncio.run(probe())
    except (
        OSError,
        asyncio.TimeoutError,
        asyncpg.PostgresError,
        asyncpg.InterfaceError,
    ) as e:
        return f"no PostgreSQL server reachable ({type(e).__name__})"
    return None


@pytest.fixture(scope="session")
def postgres_url() -> str:
    """A PostgreSQL server for the store backend tests, or a skip.

    ``TEST_POSTGRES_URL`` points at it, defaulting to a local container on
    127.0.0.1:5432. Without a server the tests skip, so the suite runs on a
    machine without Docker; CI sets ``TEST_POSTGRES_REQUIRED=1`` next to its
    service container, which turns the skip into a failure, so a broken
    service cannot quietly skip the backend's tests there.
    """
    url = os.environ.get("TEST_POSTGRES_URL") or DEFAULT_TEST_POSTGRES_URL
    reason = _postgres_unavailable(url)
    if reason is not None:
        if os.environ.get("TEST_POSTGRES_REQUIRED", "").lower() in ("1", "true"):
            pytest.fail(f"TEST_POSTGRES_REQUIRED is set, but {reason}")
        pytest.skip(reason)
    return url


async def postgres_execute(url: str, sql: str, *args: object) -> list:
    """Run one statement on a connection of its own and return its rows."""
    import asyncpg

    connection = await asyncpg.connect(url)
    try:
        return await connection.fetch(sql, *args)
    finally:
        await connection.close()


@pytest.fixture
async def postgres_table(postgres_url: str) -> AsyncIterator[str]:
    """A table name no other test uses, created by the store, dropped afterwards.

    Only the name: whether the table exists before the store starts is what
    the auto-create tests are about, so the tests that need it create it
    themselves with :func:`create_postgres_table`.
    """
    name = f"fastmcp_seaworthy_{uuid.uuid4().hex[:12]}"
    yield name
    await postgres_execute(postgres_url, f"DROP TABLE IF EXISTS {name}")


async def create_postgres_table(url: str, name: str) -> None:
    """The schema PostgreSQLStore creates with auto-create on, as the README
    documents it for creating the table ahead of time."""
    await postgres_execute(
        url,
        f"CREATE TABLE {name} ("
        "collection TEXT NOT NULL, key TEXT NOT NULL, value JSONB NOT NULL, "
        "ttl DOUBLE PRECISION, created_at TIMESTAMPTZ, expires_at TIMESTAMPTZ, "
        "PRIMARY KEY (collection, key))",
    )


@pytest.fixture
async def postgres_schema(postgres_url: str) -> AsyncIterator[str]:
    """An empty schema of its own, dropped with everything in it afterwards."""
    name = f"fastmcp_seaworthy_schema_{uuid.uuid4().hex[:12]}"
    await postgres_execute(postgres_url, f"CREATE SCHEMA {name}")
    yield name
    await postgres_execute(postgres_url, f"DROP SCHEMA IF EXISTS {name} CASCADE")
