"""The encrypted store handed to the providers, and its lifecycle."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from cryptography.fernet import Fernet
from fastmcp.server.auth.jwt_issuer import derive_jwt_key
from key_value.aio.errors import StoreSetupError
from key_value.aio.protocols.key_value import AsyncKeyValue
from key_value.aio.stores.base import BaseContextManagerStore
from key_value.aio.wrappers.base import BaseWrapper
from key_value.aio.wrappers.encryption import FernetEncryptionWrapper

from ._settings import STORE_FACTORIES, OAuthStateSettings

logger = logging.getLogger("fastmcp_seaworthy.storage")


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


_ENCRYPTED_DATA_KEY = "__encrypted_data__"
"""The field FernetEncryptionWrapper stores its ciphertext under."""


class _RefuseUnencryptedWrapper(BaseWrapper):
    """Reads an entry that is not encrypted as missing.

    Sits between ``FernetEncryptionWrapper`` and the backend. That wrapper
    returns an entry without its ciphertext field as-is, before decrypting
    anything, so Fernet's authentication never runs on it: whoever can write
    to the backend -- with no key -- could plant a plaintext client
    registration with their own redirect URI, and the proxy would validate
    ``/authorize`` against it. Everything this library writes is encrypted, so
    an unencrypted entry is either tampering or debris; either way it reads as
    missing, the same as an entry written under another key.
    """

    def __init__(self, key_value: AsyncKeyValue) -> None:
        self.key_value: AsyncKeyValue = key_value
        super().__init__()

    @staticmethod
    def _refuse_unencrypted(
        value: dict[str, Any] | None, key: str, collection: str | None
    ) -> dict[str, Any] | None:
        if value is None or _ENCRYPTED_DATA_KEY in value:
            return value
        logger.warning(
            "Ignoring unencrypted entry %r in collection %r: everything this "
            "server writes is encrypted, so it was written by someone else",
            key,
            collection,
        )
        return None

    async def get(
        self, key: str, *, collection: str | None = None
    ) -> dict[str, Any] | None:
        value = await self.key_value.get(key=key, collection=collection)
        return self._refuse_unencrypted(value, key, collection)

    async def get_many(
        self, keys: Sequence[str], *, collection: str | None = None
    ) -> list[dict[str, Any] | None]:
        values = await self.key_value.get_many(keys=keys, collection=collection)
        return [
            self._refuse_unencrypted(value, key, collection)
            for key, value in zip(keys, values)
        ]

    async def ttl(
        self, key: str, *, collection: str | None = None
    ) -> tuple[dict[str, Any] | None, float | None]:
        value, ttl = await self.key_value.ttl(key=key, collection=collection)
        value = self._refuse_unencrypted(value, key, collection)
        return value, ttl if value is not None else None

    async def ttl_many(
        self, keys: Sequence[str], *, collection: str | None = None
    ) -> list[tuple[dict[str, Any] | None, float | None]]:
        results = await self.key_value.ttl_many(keys=keys, collection=collection)
        refused = []
        for key, (value, ttl) in zip(keys, results):
            value = self._refuse_unencrypted(value, key, collection)
            refused.append((value, ttl if value is not None else None))
        return refused


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
    backend, description = STORE_FACTORIES[settings.store_backend].build(settings)
    assert settings.jwt_signing_key is not None  # OAuthStateSettings.__post_init__
    # FastMCP encrypts only the file store it builds itself; a store passed in
    # as client_storage is used as given. That store holds the upstream IdP's
    # access and refresh tokens, so an external one is wrapped the same way the
    # default is. raise_on_decryption_error=False matches FastMCP too: an entry
    # written under another key reads as missing -- the client re-registers or
    # the user signs in again -- instead of failing every request that touches
    # it. Below it, _RefuseUnencryptedWrapper makes "reads as missing" also hold
    # for an entry that is not encrypted at all, which the wrapper would
    # otherwise return unauthenticated.
    store = FernetEncryptionWrapper(
        key_value=_RefuseUnencryptedWrapper(backend),
        fernet=Fernet(key=storage_encryption_key(settings.jwt_signing_key)),
        raise_on_decryption_error=False,
    )
    return ClientStorage(store=store, backend=backend, description=description)
