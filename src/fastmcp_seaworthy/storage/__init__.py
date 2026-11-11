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

Layout
------
- ``_settings`` -- :class:`OAuthStateSettings`, :data:`StoreBackend` and the
  registry of store factories.
- ``_client`` -- :class:`ClientStorage`, the encryption around the backend, and
  :func:`build_client_storage`.
- ``_factory`` -- ``StoreFactory``, the interface each backend implements.
- ``_dynamodb``, ``_postgres`` -- one module per backend.

To add a new store backend:

1. Add a module with a ``StoreFactory`` subclass that reads, validates and
   describes the backend's settings and creates its store, importing the
   store class inside ``create`` only.
2. Register it in ``STORE_FACTORIES`` and add its literal to ``StoreBackend``,
   and its settings to ``OAuthStateSettings``.
3. Add an extra for its dependencies to ``pyproject.toml``.
"""

from ._client import ClientStorage, build_client_storage, storage_encryption_key
from ._postgres import DEFAULT_POSTGRES_TABLE
from ._settings import MIN_JWT_SIGNING_KEY_LENGTH, OAuthStateSettings, StoreBackend

__all__ = [
    "DEFAULT_POSTGRES_TABLE",
    "MIN_JWT_SIGNING_KEY_LENGTH",
    "ClientStorage",
    "OAuthStateSettings",
    "StoreBackend",
    "build_client_storage",
    "storage_encryption_key",
]
