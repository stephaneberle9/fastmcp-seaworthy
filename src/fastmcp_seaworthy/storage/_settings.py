"""The settings that select the signing key and the store backend."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal, cast, get_args

from ._dynamodb import DynamoDBStoreFactory
from ._factory import StoreFactory
from ._postgres import PostgresStoreFactory

if TYPE_CHECKING:
    from ._client import ClientStorage

MIN_JWT_SIGNING_KEY_LENGTH = 32
"""The shortest ``JWT_SIGNING_KEY`` accepted, in characters.

Whoever guesses the key can mint access tokens, and FastMCP stretches it under a
salt that is the same in every deployment, so a short key is guessable offline
against a table computed once for all of them. 32 characters of
``secrets.token_urlsafe(32)`` carry 192 bits.
"""

StoreBackend = Literal["file", "dynamodb", "postgres"]
"""Where the OAuth proxy keeps its state.

- ``file`` -- FastMCP's own encrypted file store under ``${FASTMCP_HOME}``.
  Durable on a VM disk or a mounted volume, lost with a container filesystem.
- ``dynamodb`` -- an AWS DynamoDB table, shared by every replica and surviving
  any restart. Needs the ``dynamodb`` extra.
- ``postgres`` -- a table in a PostgreSQL database, shared by every replica and
  surviving any restart. Needs the ``postgres`` extra.
"""

STORE_FACTORIES: dict[str, StoreFactory] = {
    "dynamodb": DynamoDBStoreFactory(),
    "postgres": PostgresStoreFactory(),
}
"""Every :data:`StoreBackend` except ``file`` -> the factory for its store.

``file`` has none: it is FastMCP's own store, which FastMCP builds itself.
"""


@dataclass(frozen=True)
class OAuthStateSettings:
    """The signing key and the store an ``OAuthProxy`` keeps its state in.

    Attributes:
        jwt_signing_key: Secret the server signs the tokens it issues to MCP
            clients with, and from which the store's encryption key is
            derived. Unset, FastMCP derives both from the upstream client
            secret, so rotating that secret invalidates every issued token and
            makes the stored state unreadable. Required with any
            ``store_backend`` other than ``file``.
        store_backend: Where the client registrations, the upstream IdP's
            tokens and the token mapping live. See :data:`StoreBackend`.
        store_dynamodb_table: DynamoDB table name -- required for
            ``store_backend='dynamodb'``.
        store_dynamodb_region: AWS region of the table. Optional; unset, the
            AWS SDK's usual chain decides.
        store_dynamodb_auto_create: Create the table at startup when it is
            missing. Off by default, so the server can run with permissions
            that exclude ``dynamodb:CreateTable`` and a missing table fails the
            rollout instead.
        store_postgres_url: PostgreSQL connection URL,
            ``postgresql://user:password@host:5432/database`` -- required for
            ``store_backend='postgres'``. libpq query parameters such as
            ``sslmode`` are passed on to asyncpg. It usually carries the
            database password, so it is left out of ``repr()``,
            :meth:`describe`, the backend description and every error message
            raised here.
        store_postgres_table: Table name, optionally schema-qualified as
            ``schema.table``. Optional; unset, it is
            :data:`DEFAULT_POSTGRES_TABLE` in the schema the connection's
            ``search_path`` resolves it to. Each part: letters, digits and
            underscores, lowercase, not starting with a digit, at most 63
            characters. A qualified name pins the table to that schema, which
            must exist.
        store_postgres_auto_create: Create the table at startup when it is
            missing. Off by default, so the server can run as a role without
            ``CREATE`` on the schema and a missing table fails the rollout
            instead.

    Raises:
        ValueError: From construction, for a signing key shorter than
            :data:`MIN_JWT_SIGNING_KEY_LENGTH`, or a store the server could not
            keep readable -- an unknown backend, an external backend without a
            signing key, DynamoDB without a table, or PostgreSQL without a
            usable URL or with an invalid table name.
    """

    # repr=False on the secrets -- the signing key, and the URL, which usually
    # carries the database password: a dataclass repr ends up in tracebacks,
    # debuggers and debug logs.
    jwt_signing_key: str | None = field(default=None, repr=False)
    store_backend: StoreBackend = "file"
    store_dynamodb_table: str | None = None
    store_dynamodb_region: str | None = None
    store_dynamodb_auto_create: bool = False
    store_postgres_url: str | None = field(default=None, repr=False)
    store_postgres_table: str | None = None
    store_postgres_auto_create: bool = False

    def __post_init__(self) -> None:
        if (
            self.jwt_signing_key
            and len(self.jwt_signing_key) < MIN_JWT_SIGNING_KEY_LENGTH
        ):
            # The length only, never the key: this message reaches the log.
            raise ValueError(
                f"JWT_SIGNING_KEY must be at least {MIN_JWT_SIGNING_KEY_LENGTH} "
                f"characters -- got {len(self.jwt_signing_key)}. Generate one "
                'with: python -c "import secrets; print(secrets.token_urlsafe(32))"'
            )
        if self.store_backend not in get_args(StoreBackend):
            raise ValueError(
                f"STORE_BACKEND must be one of {', '.join(get_args(StoreBackend))}"
                f" -- got {self.store_backend!r}"
            )
        if self.store_backend == "file":
            return
        # The signing key is mandatory with any external backend because
        # without it FastMCP derives the store's encryption key from the
        # upstream client secret: the first rotation of that secret would
        # silently turn a store shared by every replica into undecryptable data
        # and sign every user out. Failing here surfaces that at the first
        # deployment instead.
        if not self.jwt_signing_key:
            raise ValueError(
                f"STORE_BACKEND={self.store_backend} requires JWT_SIGNING_KEY: "
                "without it the store's encryption key is derived from the "
                "upstream client secret, and rotating that secret would make the "
                "stored state unreadable"
            )
        STORE_FACTORIES[self.store_backend].validate(self)

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> OAuthStateSettings:
        """Read the settings from the environment, the same way in every consumer.

        ======================================  ===============================
        Variable                                Attribute
        ======================================  ===============================
        ``JWT_SIGNING_KEY``                     ``jwt_signing_key``
        ``STORE_BACKEND``                       ``store_backend`` (``file``)
        ``STORE_DYNAMODB_TABLE``                ``store_dynamodb_table``
        ``STORE_DYNAMODB_REGION``               ``store_dynamodb_region``
        ``STORE_DYNAMODB_AUTO_CREATE``          ``store_dynamodb_auto_create``
        ``STORE_POSTGRES_URL``                  ``store_postgres_url``
        ``STORE_POSTGRES_TABLE``                ``store_postgres_table``
        ``STORE_POSTGRES_AUTO_CREATE``          ``store_postgres_auto_create``
        ======================================  ===============================

        Empty values count as unset. An unknown ``STORE_BACKEND`` is an error
        rather than a fallback to ``file``: a typo would otherwise quietly leave
        the deployment as restart-fragile as before. Every backend's settings
        are read, whichever is selected, so an unparsable flag fails even
        while its backend is not in use.

        Args:
            environ: Where to read from. Defaults to ``os.environ``.

        Raises:
            ValueError: For an unknown backend, an unparsable flag, or a
                combination :class:`OAuthStateSettings` refuses.
        """
        env = os.environ if environ is None else environ
        backend_settings: dict[str, Any] = {}
        for backend in STORE_FACTORIES.values():
            backend_settings.update(backend.settings_from_env(env))
        return cls(
            jwt_signing_key=env.get("JWT_SIGNING_KEY") or None,
            store_backend=cast("StoreBackend", env.get("STORE_BACKEND") or "file"),
            **backend_settings,
        )

    def describe(self) -> str:
        """Name the store and the signing key in effect, for the startup log.

        Every combination these settings accept starts a healthy-looking server,
        including the ones that keep the restart-fragile defaults: a signing key
        with no ``STORE_BACKEND`` stays on the file store, and an empty
        ``JWT_SIGNING_KEY`` goes back to deriving the key from the upstream
        client secret. One line at startup makes what is actually in use
        visible. Names settings only, never the key, and of a PostgreSQL URL
        only the host, port and database, never the user or password.
        """
        if self.store_backend == "file":
            store = "FastMCP's file store under FASTMCP_HOME"
        else:
            store = STORE_FACTORIES[self.store_backend].location(self)
        key = (
            "JWT_SIGNING_KEY"
            if self.jwt_signing_key
            else "a key derived from the upstream client secret"
        )
        return f"OAuth state in {store}, tokens signed with {key}"

    def provider_kwargs(self, client_storage: ClientStorage | None) -> dict[str, Any]:
        """Keyword arguments carrying the signing key and store to an ``OAuthProxy``.

        Splat the result into the constructor of any ``OAuthProxy`` subclass.
        Only what is set is passed, so a deployment that configures neither
        builds its provider exactly as before and FastMCP's defaults apply. Not
        for a ``RemoteAuthProvider`` such as ``KeycloakAuthProvider``, which
        takes neither keyword: there the IdP is the authorization server and
        the server issues no tokens and keeps no OAuth state.

        Args:
            client_storage: The store from :func:`build_client_storage`, or
                ``None`` for FastMCP's default file store.
        """
        kwargs: dict[str, Any] = {}
        if self.jwt_signing_key:
            kwargs["jwt_signing_key"] = self.jwt_signing_key
        if client_storage is not None:
            kwargs["client_storage"] = client_storage.store
        return kwargs
