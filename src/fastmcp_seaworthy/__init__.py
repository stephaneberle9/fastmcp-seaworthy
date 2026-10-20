"""Production building blocks for FastMCP servers.

- :mod:`fastmcp_seaworthy.serve` -- serve one server under several public
  hostnames, each a full OAuth identity.
- :mod:`fastmcp_seaworthy.storage` -- keep an OAuth proxy's state across
  restarts and rotations of the upstream client secret.
- :mod:`fastmcp_seaworthy.host_router` -- the ``Host``-based ASGI dispatch
  underneath :mod:`~fastmcp_seaworthy.serve`.
"""

from .host_router import HostRouter, check_distinct_hosts, host_of, split_base_urls
from .serve import AuthFactory, build_host_router, serve_http
from .storage import (
    MIN_JWT_SIGNING_KEY_LENGTH,
    ClientStorage,
    OAuthStateSettings,
    StoreBackend,
    build_client_storage,
    storage_encryption_key,
)

__all__ = [
    "MIN_JWT_SIGNING_KEY_LENGTH",
    "AuthFactory",
    "ClientStorage",
    "HostRouter",
    "OAuthStateSettings",
    "StoreBackend",
    "build_client_storage",
    "build_host_router",
    "check_distinct_hosts",
    "host_of",
    "serve_http",
    "split_base_urls",
    "storage_encryption_key",
]
