"""The ``postgres`` store backend: a table in a PostgreSQL database."""

from __future__ import annotations

import urllib.parse
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any

from ._factory import StoreFactory, env_flag

if TYPE_CHECKING:
    from key_value.aio.stores.base import BaseContextManagerStore

    from ._settings import OAuthStateSettings

DEFAULT_POSTGRES_TABLE = "fastmcp_oauth_state"
"""The table ``STORE_BACKEND=postgres`` uses when ``STORE_POSTGRES_TABLE`` is unset.

Not py-key-value-aio's own default, ``kv_store``: the database is often the
application's own, where a name that says what the table holds is easier to
grant on and harder to collide with.
"""

_POSTGRES_SCHEMES = ("postgresql", "postgres")
_POSTGRES_MAX_IDENTIFIER_LENGTH = 63


def _validate_url(url: str) -> None:
    """Refuse a URL asyncpg would misread, without ever quoting the URL.

    asyncpg splits the user and password from the host at the *first* ``@``,
    ``urllib`` at the last, and an unencoded ``/``, ``?`` or ``#`` in the
    password ends the authority early, so the rest of the password lands in
    the path or query. Either way part of the password would be read as a host
    or database name, and then shown in :meth:`OAuthStateSettings.describe` and
    in connection errors. Requiring those characters to be percent-encoded
    keeps the password confined to the part that is never shown. The messages
    name the problem only: this is the one place the raw URL is at hand.
    """
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in _POSTGRES_SCHEMES:
        raise ValueError(
            "STORE_POSTGRES_URL must start with postgresql:// or postgres://"
        )
    if (
        parts.netloc.count("@") > 1
        or "@" in parts.path
        or "@" in parts.query
        or "@" in parts.fragment
    ):
        raise ValueError(
            "STORE_POSTGRES_URL cannot be split into credentials and host: "
            "percent-encode '@', '/', '?' and '#' in the user name and password "
            "(as %40, %2F, %3F and %23)"
        )


def _server(url: str) -> str:
    """Name the host, port and database ``url`` points at -- no credentials.

    Mirrors how asyncpg reads the URL: host and port from the authority after
    the ``@`` (several ``host:port`` pairs are allowed), else from the ``host``
    and ``port`` query parameters; the database from the path, else from
    ``dbname`` or ``database``. Defaults are named rather than guessed.
    """
    parts = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qs(parts.query)
    _, _, hosts = parts.netloc.rpartition("@")
    if not hosts:
        hosts = query.get("host", ["the default host"])[-1]
        if "port" in query:
            hosts = f"{hosts}:{query['port'][-1]}"
    database = urllib.parse.unquote(parts.path.lstrip("/")) or next(
        (query[name][-1] for name in ("dbname", "database") if name in query),
        None,
    )
    where = f"database {database!r}" if database else "the default database"
    return f"{where} on {hosts}"


def _split_table(qualified: str) -> tuple[str | None, str]:
    """Split ``schema.table`` into its schema, or ``None``, and its table."""
    schema, dot, table = qualified.rpartition(".")
    return (schema if dot else None), table


def _validate_table(qualified: str) -> None:
    """Apply PostgreSQLStore's own table name rules at startup, plus lowercase.

    The store checks the name only when constructed, which happens after the
    settings are read; checking here makes a bad name fail together with every
    other setting. The rules are the store's (letters, digits and underscores,
    not starting with a digit, at most 63 characters), plus one: the name must
    be lowercase. The store creates the table under the unquoted name, which
    PostgreSQL folds to lowercase, but looks for it in
    ``information_schema.tables`` under the name as given -- so a mixed-case
    name is never found, and with auto-create off the server never starts. An
    optional schema in front, ``schema.table``, follows the same rules.
    """
    if qualified.count(".") > 1:
        raise ValueError(
            "STORE_POSTGRES_TABLE must be a table name or schema.table "
            f"-- got {qualified!r}"
        )
    schema, table = _split_table(qualified)
    for kind, name in (("schema", schema), ("table", table)):
        if name is None:
            continue
        if not name or not name.replace("_", "").isalnum():
            raise ValueError(
                f"STORE_POSTGRES_TABLE: the {kind} name must contain only letters, "
                f"digits and underscores -- got {qualified!r}"
            )
        if name[0].isdigit():
            raise ValueError(
                f"STORE_POSTGRES_TABLE: the {kind} name must not start with a "
                f"digit -- got {qualified!r}"
            )
        if len(name) > _POSTGRES_MAX_IDENTIFIER_LENGTH:
            raise ValueError(
                f"STORE_POSTGRES_TABLE: the {kind} name must be at most "
                f"{_POSTGRES_MAX_IDENTIFIER_LENGTH} characters -- got {len(name)}"
            )
        if name != name.lower():
            raise ValueError(
                f"STORE_POSTGRES_TABLE: the {kind} name must be lowercase -- "
                "PostgreSQL folds the name the table is created under to "
                f"lowercase, and the store would then never find it -- got "
                f"{qualified!r}"
            )


def _secrets(url: str) -> tuple[str, ...]:
    """What must not appear in a message about ``url``: the URL and its password.

    The password both as written and decoded, since a library may report
    either. Longest first, so the whole URL is replaced before its parts.
    """
    userinfo, _, _ = urllib.parse.urlsplit(url).netloc.rpartition("@")
    _, _, password = userinfo.partition(":")
    candidates = {url, password, urllib.parse.unquote(password)}
    return tuple(sorted((c for c in candidates if c), key=len, reverse=True))


def _redact(message: str, secrets: Sequence[str]) -> str:
    for secret in secrets:
        message = message.replace(secret, "***")
    return message


class PostgresStoreFactory(StoreFactory):
    extra = "postgres"
    location_variables = ("STORE_POSTGRES_URL", "STORE_POSTGRES_TABLE")

    def settings_from_env(self, environ: Mapping[str, str]) -> dict[str, Any]:
        return {
            "store_postgres_url": environ.get("STORE_POSTGRES_URL") or None,
            "store_postgres_table": environ.get("STORE_POSTGRES_TABLE") or None,
            "store_postgres_auto_create": env_flag(
                environ, "STORE_POSTGRES_AUTO_CREATE", default=False
            ),
        }

    def validate(self, settings: OAuthStateSettings) -> None:
        if not settings.store_postgres_url:
            raise ValueError("STORE_BACKEND=postgres requires STORE_POSTGRES_URL")
        _validate_url(settings.store_postgres_url)
        if settings.store_postgres_table is not None:
            _validate_table(settings.store_postgres_table)

    def location(self, settings: OAuthStateSettings) -> str:
        assert settings.store_postgres_url is not None  # validate()
        table = settings.store_postgres_table or DEFAULT_POSTGRES_TABLE
        return f"PostgreSQL table {table!r} in {_server(settings.store_postgres_url)}"

    def create(self, settings: OAuthStateSettings) -> BaseContextManagerStore:
        import asyncpg
        from key_value.aio.stores.postgresql import PostgreSQLStore

        url = settings.store_postgres_url
        assert url is not None  # validate()
        secrets = _secrets(url)
        qualified = settings.store_postgres_table or DEFAULT_POSTGRES_TABLE
        schema, table = _split_table(qualified)

        class _SeaworthyPostgreSQLStore(PostgreSQLStore):
            """PostgreSQLStore with a schema, a schema-aware table check, redaction.

            **Schema.** The store accepts no schema and builds its SQL around
            the bare table name, so a schema from ``schema.table`` becomes the
            pool's ``search_path``: every name the store uses -- in ``CREATE
            TABLE``, its index and every query -- then resolves into that
            schema, and nothing resolves anywhere else.

            **Table check.** The store looks for its table in
            ``information_schema.tables`` by name alone, so a same-named table
            in any other schema counts as found: auto-create skips the table,
            and the first query fails. ``to_regclass`` resolves the name the
            way the queries do, so the table is checked where they will look
            for it.

            **Redaction.** Setup is where the URL is parsed and connected to,
            and its error is what :meth:`ClientStorage.open` puts into its own
            message and the startup log prints. The URL validation already
            keeps the password out of every place asyncpg is known to quote;
            this is the backstop for the places it is not known to. A redacted
            error is raised without the original chained to it, since printing
            the traceback would print that one too.
            """

            async def _create_pool(self) -> asyncpg.Pool:
                if schema is None:
                    return await super()._create_pool()
                return await asyncpg.create_pool(
                    url, server_settings={"search_path": schema}
                )

            async def _table_resolves(self) -> bool:
                assert self._pool is not None
                return bool(
                    await self._pool.fetchval(
                        "SELECT to_regclass($1) IS NOT NULL", self._table_name
                    )
                )

            async def _setup_checked(self) -> None:
                # The pool first, so the check below runs on it: the base class
                # creates one only when none is set, and registers its close
                # either way -- but only once its own setup runs, so until then
                # closing it on failure is up to this method.
                pool = self._pool = await self._create_pool()
                try:
                    existed = await self._table_resolves()
                    if not existed and not self._auto_create:
                        raise ValueError(
                            f"Table {qualified!r} does not exist: create it, or "
                            "set STORE_POSTGRES_AUTO_CREATE=true"
                        )
                except BaseException:
                    self._pool = None
                    await pool.close()
                    raise
                await super()._setup()
                if not existed and not await self._table_resolves():
                    raise ValueError(
                        f"Table {qualified!r} was not created: a table of that "
                        "name exists in another schema, which PostgreSQLStore "
                        "takes for it. Create the table yourself, or qualify "
                        "STORE_POSTGRES_TABLE with a schema that has none"
                    )

            async def _setup(self) -> None:
                try:
                    await self._setup_checked()
                except Exception as e:
                    message = str(e)
                    redacted = _redact(message, secrets)
                    if redacted == message:
                        raise
                    raise RuntimeError(f"{type(e).__name__}: {redacted}") from None

        return _SeaworthyPostgreSQLStore(
            url=url,
            table_name=table,
            auto_create=settings.store_postgres_auto_create,
        )
