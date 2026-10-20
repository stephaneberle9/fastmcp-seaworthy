"""Tests for the settings and the store behind an OAuth proxy's state."""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import textwrap
from unittest.mock import patch

import pytest
from key_value.aio.wrappers.encryption import FernetEncryptionWrapper

from fastmcp_seaworthy.storage import (
    MIN_JWT_SIGNING_KEY_LENGTH,
    OAuthStateSettings,
    build_client_storage,
)

from .conftest import dynamodb_client

SIGNING_KEY = "a-signing-key-shared-by-every-replica"


def _dynamodb_settings(table: str = "oauth-state", **overrides) -> OAuthStateSettings:
    return OAuthStateSettings(
        jwt_signing_key=SIGNING_KEY,
        store_backend="dynamodb",
        store_dynamodb_table=table,
        **overrides,
    )


class TestValidation:
    def test_defaults_are_fastmcps_own(self):
        settings = OAuthStateSettings()
        assert settings.jwt_signing_key is None
        assert settings.store_backend == "file"

    def test_file_store_needs_no_signing_key(self):
        OAuthStateSettings(store_backend="file")

    def test_external_backend_without_signing_key_is_refused_naming_the_setting(
        self,
    ):
        """Without it the store's key follows the upstream client secret, whose
        rotation would strand everything stored."""
        with pytest.raises(ValueError, match="requires JWT_SIGNING_KEY"):
            OAuthStateSettings(store_backend="dynamodb", store_dynamodb_table="t")

    def test_dynamodb_without_table_is_refused_naming_the_setting(self):
        with pytest.raises(ValueError, match="requires STORE_DYNAMODB_TABLE"):
            OAuthStateSettings(jwt_signing_key=SIGNING_KEY, store_backend="dynamodb")

    def test_short_signing_key_is_refused_naming_its_length_not_the_key(self):
        """Whoever guesses the key mints access tokens, and its stretching salt
        is the same in every deployment."""
        short = "x" * (MIN_JWT_SIGNING_KEY_LENGTH - 1)
        with pytest.raises(ValueError, match="at least 32 characters") as excinfo:
            OAuthStateSettings(jwt_signing_key=short)
        assert f"got {len(short)}" in str(excinfo.value)
        assert short not in str(excinfo.value)

    def test_short_signing_key_is_refused_with_the_file_store_too(self):
        """The key signs the tokens whatever the store."""
        with pytest.raises(ValueError, match="JWT_SIGNING_KEY must be at least"):
            OAuthStateSettings.from_env({"JWT_SIGNING_KEY": "x"})

    def test_signing_key_of_the_minimum_length_is_accepted(self):
        OAuthStateSettings(jwt_signing_key="x" * MIN_JWT_SIGNING_KEY_LENGTH)

    def test_unknown_backend_is_refused(self):
        """A typo must not quietly fall back to the restart-fragile file store."""
        with pytest.raises(ValueError, match="STORE_BACKEND must be one of"):
            OAuthStateSettings(store_backend="dynamo")  # ty: ignore[invalid-argument-type]


class TestFromEnv:
    def test_empty_environment_gives_the_defaults(self):
        assert OAuthStateSettings.from_env({}) == OAuthStateSettings()

    def test_every_variable(self):
        settings = OAuthStateSettings.from_env(
            {
                "JWT_SIGNING_KEY": SIGNING_KEY,
                "STORE_BACKEND": "dynamodb",
                "STORE_DYNAMODB_TABLE": "oauth-state",
                "STORE_DYNAMODB_REGION": "eu-west-1",
                "STORE_DYNAMODB_AUTO_CREATE": "true",
            }
        )
        assert settings == OAuthStateSettings(
            jwt_signing_key=SIGNING_KEY,
            store_backend="dynamodb",
            store_dynamodb_table="oauth-state",
            store_dynamodb_region="eu-west-1",
            store_dynamodb_auto_create=True,
        )

    def test_empty_values_count_as_unset(self):
        """Kubernetes renders an optional secret that is absent as an empty
        string; that must read as "not configured", not as an empty key."""
        settings = OAuthStateSettings.from_env(
            {"JWT_SIGNING_KEY": "", "STORE_BACKEND": "", "STORE_DYNAMODB_REGION": ""}
        )
        assert settings == OAuthStateSettings()

    def test_reads_os_environ_by_default(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("JWT_SIGNING_KEY", SIGNING_KEY)
        monkeypatch.delenv("STORE_BACKEND", raising=False)
        assert OAuthStateSettings.from_env().jwt_signing_key == SIGNING_KEY

    @pytest.mark.parametrize(("raw", "expected"), [("1", True), ("Off", False)])
    def test_auto_create_flag_spellings(self, raw, expected):
        settings = OAuthStateSettings.from_env({"STORE_DYNAMODB_AUTO_CREATE": raw})
        assert settings.store_dynamodb_auto_create is expected

    def test_unparsable_flag_is_refused(self):
        with pytest.raises(ValueError, match="STORE_DYNAMODB_AUTO_CREATE must be"):
            OAuthStateSettings.from_env({"STORE_DYNAMODB_AUTO_CREATE": "enabled"})

    def test_unknown_backend_is_refused(self):
        with pytest.raises(ValueError, match="got 'dynamo'"):
            OAuthStateSettings.from_env({"STORE_BACKEND": "dynamo"})


class TestDescribe:
    """Every accepted combination starts a healthy-looking server, so the
    startup line is what tells a half-configured deployment apart."""

    def test_dynamodb_names_the_table_and_the_key_setting(self):
        assert _dynamodb_settings("oauth-state").describe() == (
            "OAuth state in DynamoDB table 'oauth-state', "
            "tokens signed with JWT_SIGNING_KEY"
        )

    def test_a_signing_key_without_a_backend_shows_the_file_store(self):
        description = OAuthStateSettings.from_env(
            {"JWT_SIGNING_KEY": SIGNING_KEY}
        ).describe()
        assert "FastMCP's file store" in description
        assert SIGNING_KEY not in description

    def test_an_empty_signing_key_shows_the_derived_key(self):
        description = OAuthStateSettings.from_env({"JWT_SIGNING_KEY": ""}).describe()
        assert description.endswith("a key derived from the upstream client secret")


class TestProviderKwargs:
    """Only what is set reaches the provider, so an unconfigured deployment
    builds it exactly as before."""

    def test_nothing_is_passed_when_nothing_is_set(self):
        assert OAuthStateSettings().provider_kwargs(None) == {}

    def test_a_signing_key_alone(self):
        settings = OAuthStateSettings(jwt_signing_key=SIGNING_KEY)
        assert settings.provider_kwargs(None) == {"jwt_signing_key": SIGNING_KEY}

    def test_the_wrapped_store_not_the_backend_is_passed(self):
        settings = _dynamodb_settings()
        storage = build_client_storage(settings)
        assert storage is not None
        kwargs = settings.provider_kwargs(storage)
        assert kwargs == {
            "jwt_signing_key": SIGNING_KEY,
            "client_storage": storage.store,
        }
        assert kwargs["client_storage"] is not storage.backend


class TestBuildClientStorage:
    def test_default_is_fastmcps_file_store(self):
        """None leaves FastMCP to build its own encrypted file store."""
        assert build_client_storage(OAuthStateSettings()) is None

    def test_a_signing_key_alone_keeps_the_file_store(self):
        settings = OAuthStateSettings(jwt_signing_key=SIGNING_KEY)
        assert build_client_storage(settings) is None

    def test_dynamodb_is_wrapped_in_fernet_encryption(self):
        storage = build_client_storage(
            _dynamodb_settings(store_dynamodb_region="eu-west-1")
        )

        assert storage is not None
        assert isinstance(storage.store, FernetEncryptionWrapper)
        assert storage.store.raise_on_decryption_error is False
        assert storage.backend._table_name == "oauth-state"  # ty: ignore[unresolved-attribute]
        assert storage.backend._auto_create is False  # ty: ignore[unresolved-attribute]
        assert "'oauth-state'" in storage.description

    def test_missing_extra_names_it(self):
        """Without the extra the store class cannot be imported; the error says
        which extra to install rather than surfacing a bare ImportError."""
        with (
            patch.dict(sys.modules, {"key_value.aio.stores.dynamodb": None}),
            pytest.raises(RuntimeError, match=r"fastmcp-seaworthy\[dynamodb\]"),
        ):
            build_client_storage(_dynamodb_settings())


def test_nothing_configured_imports_no_backend_dependency():
    """Acceptance: a deployment that selects no backend loads no cloud SDK.

    Run in a fresh interpreter, because this test session itself has imported
    them for the DynamoDB tests.
    """
    script = textwrap.dedent(
        """
        import sys

        import fastmcp_seaworthy
        from fastmcp_seaworthy import OAuthStateSettings, build_client_storage

        settings = OAuthStateSettings.from_env({})
        assert build_client_storage(settings) is None
        assert settings.provider_kwargs(None) == {}

        loaded = sorted(
            name for name in sys.modules
            if name.split(".")[0] in {"aioboto3", "aiobotocore", "boto3", "botocore"}
            or name.startswith("key_value.aio.stores.dynamodb")
        )
        print(",".join(loaded))
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
        env=os.environ.copy(),
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == ""


class TestDynamoDBStorage:
    async def test_values_at_rest_are_encrypted(self, dynamodb_table: str, aws_env):
        """FastMCP encrypts only the store it builds itself. What reaches the
        table must carry no plaintext -- it holds the upstream IdP's tokens."""
        storage = build_client_storage(_dynamodb_settings(dynamodb_table))
        assert storage is not None
        await storage.open()
        try:
            await storage.store.put(
                key="upstream-token-id",
                value={"access_token": "plaintext-upstream-access-token"},
                collection="mcp-upstream-tokens",
            )
            assert await storage.store.get(
                key="upstream-token-id", collection="mcp-upstream-tokens"
            ) == {"access_token": "plaintext-upstream-access-token"}
        finally:
            await storage.close()

        items = dynamodb_client(aws_env).scan(TableName=dynamodb_table)["Items"]
        assert len(items) == 1
        raw = items[0]["value"]["S"]
        assert "plaintext-upstream-access-token" not in raw
        assert "access_token" not in raw

    async def test_unencrypted_entries_read_as_missing(
        self, dynamodb_table: str, aws_env, caplog: pytest.LogCaptureFixture
    ):
        """Write access to the table without the key must not be enough to plant
        state: FernetEncryptionWrapper returns an entry lacking its ciphertext
        field unauthenticated, so a plaintext client registration with a
        foreign redirect URI would otherwise be served as genuine."""
        storage = build_client_storage(_dynamodb_settings(dynamodb_table))
        assert storage is not None
        collection = "mcp-oauth-proxy-clients"
        forged = {
            "client_id": "legit-client",
            "redirect_uris": ["https://evil.example/"],
        }
        await storage.open()
        try:
            await storage.store.put(
                key="legit-client",
                value={"client_id": "legit-client"},
                collection=collection,
            )
            # The backend itself, unencrypted: what a writer without the key can do.
            await storage.backend.put(
                key="legit-client", value=forged, collection=collection
            )
            await storage.backend.put(
                key="planted", value=forged, collection=collection
            )

            with caplog.at_level(logging.WARNING, logger="fastmcp_seaworthy.storage"):
                assert (
                    await storage.store.get(key="legit-client", collection=collection)
                    is None
                )
                assert await storage.store.get_many(
                    ["legit-client", "planted"], collection=collection
                ) == [None, None]
                assert await storage.store.ttl(
                    key="planted", collection=collection
                ) == (
                    None,
                    None,
                )
                assert await storage.store.ttl_many(
                    ["planted"], collection=collection
                ) == [(None, None)]
        finally:
            await storage.close()

        assert "Ignoring unencrypted entry 'planted'" in caplog.text

    async def test_encrypted_entries_keep_their_ttl(self, dynamodb_table: str, aws_env):
        storage = build_client_storage(_dynamodb_settings(dynamodb_table))
        assert storage is not None
        await storage.open()
        try:
            await storage.store.put(key="k", value={"v": 1}, collection="c", ttl=300)
            value, ttl = await storage.store.ttl(key="k", collection="c")
            [(many_value, many_ttl)] = await storage.store.ttl_many(
                ["k"], collection="c"
            )
        finally:
            await storage.close()

        assert value == many_value == {"v": 1}
        assert ttl is not None and 0 < ttl <= 300
        assert many_ttl is not None and 0 < many_ttl <= 300

    async def test_missing_table_fails_at_startup_naming_it(self, aws_env):
        """Infrastructure creates the table; with auto_create off a missing one
        is a deployment error, reported at startup with the table's name."""
        storage = build_client_storage(_dynamodb_settings("no-such-table"))
        assert storage is not None

        with pytest.raises(ValueError, match="'no-such-table'") as excinfo:
            await storage.open()

        assert "STORE_DYNAMODB_TABLE" in str(excinfo.value)

    async def test_auto_create_creates_a_missing_table(self, aws_env):
        table = "created-at-startup"
        storage = build_client_storage(
            _dynamodb_settings(table, store_dynamodb_auto_create=True)
        )
        assert storage is not None

        await storage.open()
        await storage.close()

        description = dynamodb_client(aws_env).describe_table(TableName=table)
        assert {
            k["AttributeName"]: k["KeyType"] for k in description["Table"]["KeySchema"]
        } == {
            "collection": "HASH",
            "key": "RANGE",
        }
