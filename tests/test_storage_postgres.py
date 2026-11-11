"""Tests for the PostgreSQL store backend.

The settings tests run everywhere. The ones marked with the ``postgres_url``
fixture need a real server and skip without one; see ``conftest.py``.
"""

from __future__ import annotations

import logging
import sys
import traceback
import warnings
from unittest.mock import patch

import pytest
from key_value.aio.stores.postgresql import PostgreSQLStore
from key_value.aio.stores.postgresql.store import _validate_table_name
from key_value.aio.wrappers.encryption import FernetEncryptionWrapper

from fastmcp_seaworthy.storage import (
    DEFAULT_POSTGRES_TABLE,
    OAuthStateSettings,
    build_client_storage,
)

from .conftest import create_postgres_table, postgres_execute

SIGNING_KEY = "a-signing-key-shared-by-every-replica"

PASSWORD = "s3cr3t-Pa55word-that-must-never-be-shown"
"""Distinctive enough that finding it anywhere in a message is a leak."""

URL = f"postgresql://oauth_user:{PASSWORD}@db.example.com:5432/appdb?sslmode=require"


def _postgres_settings(url: str = URL, **overrides) -> OAuthStateSettings:
    return OAuthStateSettings(
        jwt_signing_key=SIGNING_KEY,
        store_backend="postgres",
        store_postgres_url=url,
        **overrides,
    )


def _with_password(url: str, password: str) -> str:
    """``url`` with its password replaced, to provoke an authentication failure."""
    scheme, rest = url.split("://", 1)
    userinfo, _, hostpart = rest.rpartition("@")
    user = userinfo.partition(":")[0] or "postgres"
    return f"{scheme}://{user}:{password}@{hostpart}"


def _everything_shown(excinfo: pytest.ExceptionInfo[BaseException]) -> str:
    """The exception as the startup log would print it, chained causes included."""
    return "".join(traceback.format_exception(excinfo.value))


class TestValidation:
    def test_requires_a_url_naming_the_setting(self):
        with pytest.raises(ValueError, match="requires STORE_POSTGRES_URL"):
            OAuthStateSettings(jwt_signing_key=SIGNING_KEY, store_backend="postgres")

    def test_requires_the_signing_key(self):
        with pytest.raises(ValueError, match="requires JWT_SIGNING_KEY"):
            OAuthStateSettings(store_backend="postgres", store_postgres_url=URL)

    @pytest.mark.parametrize("scheme", ["postgresql", "postgres"])
    def test_both_schemes_asyncpg_accepts(self, scheme):
        _postgres_settings(f"{scheme}://u:p@db.example.com/appdb")

    def test_another_scheme_is_refused(self):
        with pytest.raises(ValueError, match="must start with postgresql://"):
            _postgres_settings(f"mysql://u:{PASSWORD}@db.example.com/appdb")

    @pytest.mark.parametrize(
        "password",
        [
            # asyncpg would split at the first '@', urllib at the last.
            "pa@ss",
            # Each of these ends the authority early, moving the rest of the
            # password into the path, query or fragment.
            "pa/ss",
            "pa?ss",
            "pa#ss",
        ],
    )
    def test_unencoded_delimiters_in_the_password_are_refused(self, password):
        url = f"postgresql://u:{password}{PASSWORD}@db.example.com/appdb"
        with pytest.raises(ValueError, match="percent-encode") as excinfo:
            _postgres_settings(url)
        assert PASSWORD not in _everything_shown(excinfo)

    def test_a_percent_encoded_password_is_accepted(self):
        _postgres_settings("postgresql://u:pa%40ss%2F%3F%23@db.example.com/appdb")

    @pytest.mark.parametrize(
        "table",
        [
            "oauth-state",  # PostgreSQLStore's own rules
            "oauth state",
            "1oauth",
            "a" * 64,
            "OAuth_State",  # and lowercase
        ],
    )
    def test_invalid_table_names_are_refused_at_construction(self, table):
        with pytest.raises(ValueError, match="STORE_POSTGRES_TABLE"):
            _postgres_settings(store_postgres_table=table)

    @pytest.mark.parametrize(
        "table",
        [
            "a.b.c",
            ".oauth_state",
            "oauth.",
            "Auth.oauth_state",
            "1auth.oauth_state",
            "auth-x.oauth_state",
            f"{'a' * 64}.oauth_state",
        ],
    )
    def test_invalid_qualified_names_are_refused(self, table):
        with pytest.raises(ValueError, match="STORE_POSTGRES_TABLE"):
            _postgres_settings(store_postgres_table=table)

    def test_a_schema_qualified_name_is_accepted(self):
        settings = _postgres_settings(store_postgres_table="auth.oauth_state")
        assert "PostgreSQL table 'auth.oauth_state'" in settings.describe()

    @pytest.mark.parametrize(
        "table", ["oauth_state", "_oauth", "a" * 63, "oauth-state", "1oauth", "a" * 64]
    )
    def test_the_table_rules_include_the_stores_own(self, table):
        """Every name the store refuses is refused here first, so nothing that
        passes the settings fails only once the store is built."""
        try:
            _validate_table_name(table)
        except ValueError:
            with pytest.raises(ValueError):
                _postgres_settings(store_postgres_table=table)
        else:
            _postgres_settings(store_postgres_table=table)


class TestFromEnv:
    def test_every_variable(self):
        settings = OAuthStateSettings.from_env(
            {
                "JWT_SIGNING_KEY": SIGNING_KEY,
                "STORE_BACKEND": "postgres",
                "STORE_POSTGRES_URL": URL,
                "STORE_POSTGRES_TABLE": "oauth_state",
                "STORE_POSTGRES_AUTO_CREATE": "yes",
            }
        )
        assert settings == _postgres_settings(
            store_postgres_table="oauth_state", store_postgres_auto_create=True
        )

    def test_empty_values_count_as_unset(self):
        settings = OAuthStateSettings.from_env(
            {
                "JWT_SIGNING_KEY": SIGNING_KEY,
                "STORE_BACKEND": "postgres",
                "STORE_POSTGRES_URL": URL,
                "STORE_POSTGRES_TABLE": "",
                "STORE_POSTGRES_AUTO_CREATE": "",
            }
        )
        assert settings.store_postgres_table is None
        assert settings.store_postgres_auto_create is False

    def test_unparsable_auto_create_flag_is_refused(self):
        with pytest.raises(ValueError, match="STORE_POSTGRES_AUTO_CREATE must be"):
            OAuthStateSettings.from_env({"STORE_POSTGRES_AUTO_CREATE": "enabled"})


class TestRedaction:
    """The URL usually carries the database password. Whatever the startup log
    or an error can show -- the settings' repr, describe(), the backend
    description, a failed startup -- names the server without it."""

    def test_describe_names_table_database_and_host_only(self):
        description = _postgres_settings().describe()
        assert description == (
            f"OAuth state in PostgreSQL table {DEFAULT_POSTGRES_TABLE!r} in "
            "database 'appdb' on db.example.com:5432, tokens signed with "
            "JWT_SIGNING_KEY"
        )
        assert "oauth_user" not in description

    @pytest.mark.parametrize(
        ("url", "where"),
        [
            ("postgresql://db.example.com/appdb", "database 'appdb' on db.example.com"),
            (
                "postgresql://u:p@h1.example.com:5432,h2.example.com:5433/appdb",
                "database 'appdb' on h1.example.com:5432,h2.example.com:5433",
            ),
            (
                "postgresql:///appdb?host=/var/run/postgresql&port=5433",
                "database 'appdb' on /var/run/postgresql:5433",
            ),
            (
                "postgresql://u:p@db.example.com?dbname=appdb",
                "database 'appdb' on db.example.com",
            ),
            (
                "postgresql://u:p@db.example.com",
                "the default database on db.example.com",
            ),
        ],
    )
    def test_describe_reads_the_url_the_way_asyncpg_does(self, url, where):
        assert f" in {where}," in _postgres_settings(url).describe()

    def test_repr_leaves_the_signing_key_out(self):
        assert SIGNING_KEY not in repr(_postgres_settings())
        assert SIGNING_KEY not in repr(OAuthStateSettings(jwt_signing_key=SIGNING_KEY))

    def test_repr_leaves_the_url_out(self):
        assert PASSWORD not in repr(_postgres_settings())
        assert "db.example.com" not in repr(_postgres_settings())

    def test_backend_description_names_the_settings_not_the_password(self):
        storage = build_client_storage(_postgres_settings())
        assert storage is not None
        assert storage.description == (
            f"PostgreSQL table {DEFAULT_POSTGRES_TABLE!r} in database 'appdb' on "
            "db.example.com:5432 (STORE_POSTGRES_URL, STORE_POSTGRES_TABLE)"
        )
        assert PASSWORD not in repr(storage)

    @pytest.mark.parametrize(
        "password", [PASSWORD, "pa%40ss%2F" + PASSWORD], ids=["plain", "encoded"]
    )
    async def test_a_setup_error_quoting_the_url_is_redacted(
        self, password, caplog: pytest.LogCaptureFixture
    ):
        """The backstop: should asyncpg ever put the URL into an error -- or
        the password, encoded or decoded -- the startup error still shows
        neither, not even in the traceback of a chained cause."""
        url = f"postgresql://oauth_user:{password}@db.example.com:5432/appdb"
        decoded = password.replace("%40", "@").replace("%2F", "/")

        async def failing_pool(dsn: str):
            raise ConnectionError(f"cannot connect to {dsn} with {decoded}")

        storage = build_client_storage(_postgres_settings(url))
        assert storage is not None
        with (
            patch(
                "key_value.aio.stores.postgresql.store._create_postgresql_pool_from_url",
                failing_pool,
            ),
            caplog.at_level(logging.DEBUG),
            pytest.raises(ValueError, match="Cannot use PostgreSQL table") as excinfo,
        ):
            await storage.open()

        shown = _everything_shown(excinfo) + caplog.text
        assert "ConnectionError: cannot connect to *** with ***" in shown
        assert PASSWORD not in shown
        assert url not in shown

    async def test_a_setup_error_without_the_secret_keeps_its_cause(self):
        """Redaction only replaces the errors it has to: anything else reaches
        the operator unchanged, chained cause and all."""

        async def failing_pool(dsn: str):
            raise ConnectionRefusedError("connection refused")

        storage = build_client_storage(_postgres_settings())
        assert storage is not None
        with (
            patch(
                "key_value.aio.stores.postgresql.store._create_postgresql_pool_from_url",
                failing_pool,
            ),
            pytest.raises(ValueError, match="connection refused") as excinfo,
        ):
            await storage.open()
        setup_error = excinfo.value.__cause__
        assert setup_error is not None
        assert isinstance(setup_error.__cause__, ConnectionRefusedError)


class TestBuildClientStorage:
    def test_is_wrapped_in_fernet_encryption(self):
        storage = build_client_storage(
            _postgres_settings(
                store_postgres_table="oauth_state", store_postgres_auto_create=True
            )
        )
        assert storage is not None
        assert isinstance(storage.store, FernetEncryptionWrapper)
        assert storage.store.raise_on_decryption_error is False
        assert isinstance(storage.backend, PostgreSQLStore)
        assert storage.backend._table_name == "oauth_state"
        assert storage.backend._auto_create is True

    def test_auto_create_is_off_by_default(self):
        storage = build_client_storage(_postgres_settings())
        assert storage is not None
        assert storage.backend._table_name == DEFAULT_POSTGRES_TABLE  # ty: ignore[unresolved-attribute]
        assert storage.backend._auto_create is False  # ty: ignore[unresolved-attribute]

    def test_the_unstable_store_warning_is_not_passed_on(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            build_client_storage(_postgres_settings())
        assert not [w for w in caught if "unstable" in str(w.message)]

    def test_missing_extra_names_it(self):
        with (
            patch.dict(sys.modules, {"key_value.aio.stores.postgresql": None}),
            pytest.raises(RuntimeError, match=r"fastmcp-seaworthy\[postgres\]"),
        ):
            build_client_storage(_postgres_settings())


async def _open(url: str, table: str, **overrides):
    storage = build_client_storage(
        _postgres_settings(url, store_postgres_table=table, **overrides)
    )
    assert storage is not None
    await storage.open()
    return storage


class TestPostgreSQLStorage:
    async def test_values_at_rest_are_encrypted(
        self, postgres_url: str, postgres_table: str
    ):
        """Database operators and backups can read the table; what reaches it
        must carry no plaintext -- it holds the upstream IdP's tokens."""
        await create_postgres_table(postgres_url, postgres_table)
        storage = await _open(postgres_url, postgres_table)
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

        rows = await postgres_execute(
            postgres_url, f"SELECT value::text AS value FROM {postgres_table}"
        )
        assert len(rows) == 1
        assert "plaintext-upstream-access-token" not in rows[0]["value"]
        assert "access_token" not in rows[0]["value"]

    async def test_unencrypted_entries_read_as_missing(
        self, postgres_url: str, postgres_table: str
    ):
        """Write access to the table without the key is not enough to plant a
        client registration."""
        await create_postgres_table(postgres_url, postgres_table)
        storage = await _open(postgres_url, postgres_table)
        try:
            await storage.backend.put(
                key="planted",
                value={
                    "client_id": "planted",
                    "redirect_uris": ["https://evil.example/"],
                },
                collection="mcp-oauth-proxy-clients",
            )
            assert (
                await storage.store.get(
                    key="planted", collection="mcp-oauth-proxy-clients"
                )
                is None
            )
        finally:
            await storage.close()

    async def test_missing_table_fails_at_startup_naming_it(
        self, postgres_url: str, postgres_table: str
    ):
        """With auto-create off, a missing table is a deployment error reported
        at startup -- and the error names the table, not the URL."""
        storage = build_client_storage(
            _postgres_settings(postgres_url, store_postgres_table=postgres_table)
        )
        assert storage is not None

        with pytest.raises(ValueError, match=f"'{postgres_table}'") as excinfo:
            await storage.open()

        shown = _everything_shown(excinfo)
        assert "does not exist" in shown
        assert "STORE_POSTGRES_TABLE" in shown
        assert postgres_url not in shown

    async def test_auto_create_creates_a_missing_table(
        self, postgres_url: str, postgres_table: str
    ):
        storage = await _open(
            postgres_url, postgres_table, store_postgres_auto_create=True
        )
        try:
            await storage.store.put(key="k", value={"v": 1}, collection="c")
        finally:
            await storage.close()

        columns = await postgres_execute(
            postgres_url,
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = $1 ORDER BY ordinal_position",
            postgres_table,
        )
        assert [c["column_name"] for c in columns] == [
            "collection",
            "key",
            "value",
            "ttl",
            "created_at",
            "expires_at",
        ]

    async def test_the_documented_schema_is_the_one_auto_create_makes(
        self, postgres_url: str, postgres_table: str
    ):
        """A table created ahead of time from the README's statement is one the
        store, with auto-create off, accepts and uses."""
        await create_postgres_table(postgres_url, postgres_table)
        storage = await _open(postgres_url, postgres_table)
        try:
            await storage.store.put(key="k", value={"v": 1}, collection="c", ttl=60)
            assert await storage.store.get(key="k", collection="c") == {"v": 1}
        finally:
            await storage.close()

    async def test_a_wrong_password_fails_at_startup_without_showing_it(
        self, postgres_url: str, postgres_table: str, caplog: pytest.LogCaptureFixture
    ):
        url = _with_password(postgres_url, PASSWORD)
        storage = build_client_storage(
            _postgres_settings(url, store_postgres_table=postgres_table)
        )
        assert storage is not None

        with (
            caplog.at_level(logging.DEBUG),
            pytest.raises(ValueError, match="Cannot use PostgreSQL table") as excinfo,
        ):
            await storage.open()

        shown = _everything_shown(excinfo) + caplog.text
        assert "password authentication failed" in shown
        assert PASSWORD not in shown

    async def test_expired_rows_stay_until_pruned(
        self, postgres_url: str, postgres_table: str
    ):
        """PostgreSQLStore filters expired rows on read but never deletes them,
        so the table keeps every expired token record until the operator
        prunes it with the statement the README gives -- which keeps the rows
        that have not expired and the ones that never do."""
        await create_postgres_table(postgres_url, postgres_table)
        storage = await _open(postgres_url, postgres_table)
        try:
            await storage.store.put(
                key="expired", value={"v": 1}, collection="c", ttl=60
            )
            await storage.store.put(
                key="live", value={"v": 2}, collection="c", ttl=3600
            )
            await storage.store.put(key="forever", value={"v": 3}, collection="c")
            await postgres_execute(
                postgres_url,
                f"UPDATE {postgres_table} SET expires_at = now() - interval '1 second'"
                " WHERE key = 'expired'",
            )
            assert await storage.store.get(key="expired", collection="c") is None

            count = f"SELECT count(*) AS n FROM {postgres_table}"
            assert (await postgres_execute(postgres_url, count))[0]["n"] == 3

            await postgres_execute(
                postgres_url, f"DELETE FROM {postgres_table} WHERE expires_at < now()"
            )
            assert (await postgres_execute(postgres_url, count))[0]["n"] == 2
            assert await storage.store.get(key="live", collection="c") == {"v": 2}
            assert await storage.store.get(key="forever", collection="c") == {"v": 3}
        finally:
            await storage.close()

    # The store is built directly here, not through build_client_storage,
    # which is what silences its construction-time warning.
    @pytest.mark.filterwarnings("ignore:A configured store is unstable")
    async def test_a_mixed_case_table_name_is_never_found_again(
        self, postgres_url: str
    ):
        """Why the settings demand a lowercase table name: the store creates
        the table unquoted, which PostgreSQL folds to lowercase, then checks
        for it under the name as given. A second start with auto-create off
        would refuse to run against the table the first one created."""
        name = "FastMCP_Seaworthy_Mixed_Case"
        try:
            async with PostgreSQLStore(url=postgres_url, table_name=name):
                pass
            with pytest.raises(Exception, match="does not exist"):
                async with PostgreSQLStore(
                    url=postgres_url, table_name=name, auto_create=False
                ):
                    pass
        finally:
            await postgres_execute(postgres_url, f"DROP TABLE IF EXISTS {name}")


class TestSchemas:
    """A schema-qualified STORE_POSTGRES_TABLE pins the table to that schema,
    and the table check looks where the queries will look -- not in every
    schema, as PostgreSQLStore's own check does."""

    async def test_auto_create_creates_the_table_in_the_given_schema(
        self, postgres_url: str, postgres_schema: str, postgres_table: str
    ):
        qualified = f"{postgres_schema}.{postgres_table}"
        storage = await _open(postgres_url, qualified, store_postgres_auto_create=True)
        try:
            await storage.store.put(key="k", value={"v": 1}, collection="c")
        finally:
            await storage.close()

        rows = await postgres_execute(
            postgres_url,
            "SELECT table_schema FROM information_schema.tables WHERE table_name = $1",
            postgres_table,
        )
        assert [r["table_schema"] for r in rows] == [postgres_schema]

        # A fresh store -- a restart -- finds it there with auto-create off.
        storage = await _open(postgres_url, qualified)
        try:
            assert await storage.store.get(key="k", collection="c") == {"v": 1}
        finally:
            await storage.close()

    async def test_a_same_named_table_elsewhere_does_not_count(
        self, postgres_url: str, postgres_schema: str, postgres_table: str
    ):
        """PostgreSQLStore alone would take the table in the default schema for
        the one asked for, start, and fail on the first sign-in."""
        await create_postgres_table(postgres_url, postgres_table)  # in public
        storage = build_client_storage(
            _postgres_settings(
                postgres_url, store_postgres_table=f"{postgres_schema}.{postgres_table}"
            )
        )
        assert storage is not None

        with pytest.raises(ValueError, match="does not exist"):
            await storage.open()

    async def test_auto_create_skipped_for_a_table_elsewhere_fails_at_startup(
        self, postgres_url: str, postgres_schema: str, postgres_table: str
    ):
        """The table exists only in a schema off the search path. PostgreSQLStore
        takes it for its own and skips creating one; that surfaces at startup
        as such, rather than as a failed query at the first sign-in."""
        await create_postgres_table(postgres_url, f"{postgres_schema}.{postgres_table}")
        storage = build_client_storage(
            _postgres_settings(
                postgres_url,
                store_postgres_table=postgres_table,
                store_postgres_auto_create=True,
            )
        )
        assert storage is not None

        with pytest.raises(ValueError, match="exists in another schema"):
            await storage.open()
