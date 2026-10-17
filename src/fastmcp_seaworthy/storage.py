"""OAuth state that survives restarts and rotations of the upstream client secret.

Why this exists
---------------
A FastMCP server whose auth provider is an ``OAuthProxy`` (``OIDCProxy``,
``AWSCognitoProvider``, ``GoogleProvider``, ``AzureProvider``, ...) is the OAuth
authorization server for its MCP clients. It keeps state -- the clients
registered through DCR, the upstream IdP's access and refresh tokens, and the
mapping from the tokens it issued to them -- and signs those tokens with a
signing key. Both decide what a restart costs:

- **Store.** By default FastMCP keeps the state in an encrypted file store under
  ``${FASTMCP_HOME}``. In a container whose filesystem does not survive a
  restart, every restart loses all registrations and signs every user out.
- **Signing key.** Unset, FastMCP derives the signing key -- and from it the
  store's encryption key and directory -- from the upstream client secret.
  Rotating that secret invalidates every issued token and strands everything
  stored, volume or not.

:class:`OAuthStateSettings` holds the two settings that fix this, read from the
same environment variables in every consumer, :func:`build_client_storage`
builds the external store they select, and
:meth:`OAuthStateSettings.provider_kwargs` hands both to an ``OAuthProxy``
subclass's constructor.

To add a new store backend:

1. Add a literal to ``StoreBackend``, its settings to ``OAuthStateSettings``
   and their validation to ``OAuthStateSettings.__post_init__``.
2. Add an extra for its dependencies to ``pyproject.toml``.
3. Add a factory to ``_STORE_BACKENDS`` that imports the store class lazily.
"""

from __future__ import annotations

import os
import warnings
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Literal, cast, get_args

from cryptography.fernet import Fernet
from fastmcp.server.auth.jwt_issuer import derive_jwt_key
from key_value.aio.errors import StoreSetupError
from key_value.aio.protocols.key_value import AsyncKeyValue
from key_value.aio.stores.base import BaseContextManagerStore
from key_value.aio.wrappers.encryption import FernetEncryptionWrapper

StoreBackend = Literal["file", "dynamodb"]
"""Where the OAuth proxy keeps its state.

- ``file`` -- FastMCP's own encrypted file store under ``${FASTMCP_HOME}``.
  Durable on a VM disk or a mounted volume, lost with a container filesystem.
- ``dynamodb`` -- an AWS DynamoDB table, shared by every replica and surviving
  any restart. Needs the ``dynamodb`` extra.
"""

_TRUTHY = ("1", "true", "yes", "on")
_FALSY = ("0", "false", "no", "off")


def _env_flag(environ: Mapping[str, str], name: str, *, default: bool) -> bool:
    """Read a boolean environment variable, or ``default`` when it is unset.

    An unrecognized value is an error rather than a silent default: a typo, or
    a plausible-looking ``STORE_DYNAMODB_AUTO_CREATE=enabled``, should not
    quietly resolve to whichever state the operator was trying to leave.
    """
    raw = environ.get(name)
    if raw is None or raw == "":
        return default
    value = raw.strip().lower()
    if value in _TRUTHY:
        return True
    if value in _FALSY:
        return False
    raise ValueError(
        f"{name} must be one of {', '.join((*_TRUTHY, *_FALSY))} -- got {raw!r}"
    )


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

    Raises:
        ValueError: From construction, for a store the server could not keep
            readable -- an unknown backend, an external backend without a
            signing key, or DynamoDB without a table.
    """

    jwt_signing_key: str | None = None
    store_backend: StoreBackend = "file"
    store_dynamodb_table: str | None = None
    store_dynamodb_region: str | None = None
    store_dynamodb_auto_create: bool = False

    def __post_init__(self) -> None:
        # The signing key is mandatory with any external backend because
        # without it FastMCP derives the store's encryption key from the
        # upstream client secret: the first rotation of that secret would
        # silently turn a store shared by every replica into undecryptable data
        # and sign every user out. Failing here surfaces that at the first
        # deployment instead.
        if self.store_backend not in get_args(StoreBackend):
            raise ValueError(
                f"STORE_BACKEND must be one of {', '.join(get_args(StoreBackend))}"
                f" -- got {self.store_backend!r}"
            )
        if self.store_backend == "file":
            return
        if not self.jwt_signing_key:
            raise ValueError(
                f"STORE_BACKEND={self.store_backend} requires JWT_SIGNING_KEY: "
                "without it the store's encryption key is derived from the "
                "upstream client secret, and rotating that secret would make the "
                "stored state unreadable"
            )
        if self.store_backend == "dynamodb" and not self.store_dynamodb_table:
            raise ValueError("STORE_BACKEND=dynamodb requires STORE_DYNAMODB_TABLE")

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
        ======================================  ===============================

        Empty values count as unset. An unknown ``STORE_BACKEND`` is an error
        rather than a fallback to ``file``: a typo would otherwise quietly leave
        the deployment as restart-fragile as before.

        Args:
            environ: Where to read from. Defaults to ``os.environ``.

        Raises:
            ValueError: For an unknown backend, an unparsable flag, or a
                combination :class:`OAuthStateSettings` refuses.
        """
        env = os.environ if environ is None else environ
        return cls(
            jwt_signing_key=env.get("JWT_SIGNING_KEY") or None,
            store_backend=cast("StoreBackend", env.get("STORE_BACKEND") or "file"),
            store_dynamodb_table=env.get("STORE_DYNAMODB_TABLE") or None,
            store_dynamodb_region=env.get("STORE_DYNAMODB_REGION") or None,
            store_dynamodb_auto_create=_env_flag(
                env, "STORE_DYNAMODB_AUTO_CREATE", default=False
            ),
        )

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


@dataclass
class ClientStorage:
    """An external store backend for an OAuth proxy's state, encrypted.

    Attributes:
        store: What the providers are handed as ``client_storage`` -- the
            backend behind the encryption wrapper.
        backend: The backend itself, kept for its lifecycle: the wrapper
            forwards reads and writes but not ``setup()`` or ``close()``.
        description: Names the backend's location in startup errors, e.g. the
            DynamoDB table and the setting that selects it.
    """

    store: AsyncKeyValue
    backend: BaseContextManagerStore
    description: str

    async def open(self) -> None:
        """Connect to the backend, so a backend the server cannot use fails at startup.

        Every store connects lazily on first use, which would be the first
        user's sign-in. A missing DynamoDB table, a wrong region or missing
        credentials would then surface as a failed request long after the
        deployment looked healthy.

        Raises:
            ValueError: Naming the backend's location, when setup fails.
        """
        try:
            await self.backend.setup()
        except StoreSetupError as e:
            await self.backend.close()
            cause = e.__cause__ or e
            raise ValueError(f"Cannot use {self.description}: {cause}") from e

    async def close(self) -> None:
        await self.backend.close()


def _dynamodb_backend(
    settings: OAuthStateSettings,
) -> tuple[BaseContextManagerStore, str]:
    # Imported here, not at module level: the extra is optional, and a
    # deployment on the default file store must not need -- or load -- the AWS
    # SDK.
    try:
        from key_value.aio.stores.dynamodb import DynamoDBStore
    except ImportError as e:
        raise RuntimeError(
            "STORE_BACKEND=dynamodb needs the 'dynamodb' extra: install "
            "fastmcp-seaworthy[dynamodb]"
        ) from e

    assert settings.store_dynamodb_table is not None
    with warnings.catch_warnings():
        # py-key-value-aio warns on every construction that the store's Python
        # API may still change. That is addressed to whoever calls the
        # constructor -- this function, whose range fastmcp's own <0.5 pin
        # bounds -- not to the operator reading the startup log.
        warnings.filterwarnings(
            "ignore", message="A configured store is unstable", category=UserWarning
        )
        store = DynamoDBStore(
            table_name=settings.store_dynamodb_table,
            region_name=settings.store_dynamodb_region,
            auto_create=settings.store_dynamodb_auto_create,
        )
    return (
        store,
        f"DynamoDB table {settings.store_dynamodb_table!r} (STORE_DYNAMODB_TABLE)",
    )


_STORE_BACKENDS: dict[
    str, Callable[[OAuthStateSettings], tuple[BaseContextManagerStore, str]]
] = {
    "dynamodb": _dynamodb_backend,
}
"""Store backend name -> factory returning the store and where it lives.

The stores themselves are py-key-value-aio's; a backend here is only the
mapping from these settings to a store class's constructor.
"""


def storage_encryption_key(jwt_signing_key: str) -> bytes:
    """Derive the store's Fernet key from the signing key, exactly as FastMCP does.

    ``OAuthProxy`` stretches a string signing key with PBKDF2 and then derives
    its default file store's key from the result with HKDF under this salt.
    Repeating both steps keeps an operator-chosen, possibly low-entropy key as
    hard to brute-force from a leaked store as from a leaked token.
    """
    signing_key = derive_jwt_key(
        low_entropy_material=jwt_signing_key, salt="fastmcp-jwt-signing-key"
    )
    return derive_jwt_key(
        high_entropy_material=signing_key.decode(),
        salt="fastmcp-storage-encryption-key",
    )


def build_client_storage(settings: OAuthStateSettings) -> ClientStorage | None:
    """Build the store ``settings`` select, or ``None`` for the default.

    ``None`` leaves FastMCP's own encrypted file store in place and imports no
    backend dependency.

    Build this once per process and hand the same instance to the provider of
    every hostname -- through :meth:`OAuthStateSettings.provider_kwargs` -- then
    call :meth:`ClientStorage.open` before serving and
    :meth:`ClientStorage.close` after. :func:`fastmcp_seaworthy.serve.serve_http`
    does both when given the store.

    Raises:
        RuntimeError: If the backend's extra is not installed.
    """
    if settings.store_backend == "file":
        return None
    backend, description = _STORE_BACKENDS[settings.store_backend](settings)
    assert settings.jwt_signing_key is not None  # OAuthStateSettings.__post_init__
    # FastMCP encrypts only the file store it builds itself; a store passed in
    # as client_storage is used as given. That store holds the upstream IdP's
    # access and refresh tokens, so an external one is wrapped the same way the
    # default is. raise_on_decryption_error=False matches FastMCP too: an entry
    # written under another key reads as missing -- the client re-registers or
    # the user signs in again -- instead of failing every request that touches
    # it.
    store = FernetEncryptionWrapper(
        key_value=backend,
        fernet=Fernet(key=storage_encryption_key(settings.jwt_signing_key)),
        raise_on_decryption_error=False,
    )
    return ClientStorage(store=store, backend=backend, description=description)
