"""What survives a restart of an OAuth-proxying FastMCP server, and what does not.

A server whose auth provider is an ``OAuthProxy`` is the OAuth authorization
server for its MCP clients: it keeps the DCR client registrations, the upstream
IdP's tokens and the mapping from the tokens it issued to them in a key-value
store, and signs its own tokens with a signing key. A "restart" here is a
second provider built from the same settings -- what a new pod does -- with
either a fresh store (a container filesystem that did not survive) or the store
the first one wrote to.

The OAuth flow is driven through the provider's own methods rather than over
HTTP, because the part that matters starts after the upstream IdP's callback:
the authorization code the callback stores is seeded into the provider's code
store directly, exactly as ``OAuthProxy._handle_idp_callback`` writes it, and
everything from the token exchange on runs unmodified.
"""

from __future__ import annotations

import time
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import AsyncMock, patch

import fastmcp
from fastmcp.server.auth.auth import AccessToken
from fastmcp.server.auth.oauth_proxy.models import ClientCode
from fastmcp.server.auth.oidc_proxy import OIDCConfiguration, OIDCProxy
from mcp.server.auth.provider import AuthorizationCode
from mcp.shared.auth import OAuthClientInformationFull
from pydantic import AnyUrl

from fastmcp_seaworthy.storage import (
    ClientStorage,
    OAuthStateSettings,
    build_client_storage,
)

BASE_URL = "https://mcp.example.com"
ISSUER = "https://idp.example.com"
REDIRECT_URI = "http://127.0.0.1:33418/callback"
DCR_CLIENT_ID = "dcr-client-registered-before-the-restart"
CIMD_CLIENT_ID = "https://client.example.com/oauth/client-metadata.json"
UPSTREAM_ACCESS_TOKEN = "upstream-access-token"


def oidc_configuration() -> OIDCConfiguration:
    """A discovery document, so constructing OIDCProxy reaches no network."""
    return OIDCConfiguration(
        issuer=ISSUER,
        authorization_endpoint=f"{ISSUER}/authorize",
        token_endpoint=f"{ISSUER}/token",
        jwks_uri=f"{ISSUER}/jwks",
        response_types_supported=["code"],
        subject_types_supported=["public"],
        id_token_signing_alg_values_supported=["RS256"],
    )


CLIENT_SECRET = "upstream-client-secret"
ROTATED_SECRET = "rotated-secret"


@contextmanager
def pod(home: Path) -> Generator[None]:
    """Run as a process whose FastMCP home -- the default store's parent -- is ``home``.

    ``test_mode`` cuts FastMCP's PBKDF2 rounds for string signing keys, which
    would otherwise cost a second per provider; it changes the derived key, not
    whether derivation is deterministic, which is what a restart depends on.
    """
    with (
        patch.object(fastmcp.settings, "home", home),
        patch.object(fastmcp.settings, "test_mode", True),
    ):
        yield


def start_provider(
    settings: OAuthStateSettings,
    client_secret: str = CLIENT_SECRET,
    client_storage: ClientStorage | None = None,
) -> OIDCProxy:
    """Build the provider a server process would build, ready to issue tokens.

    The settings reach it only through ``provider_kwargs``, the way a consumer
    wires them, so these tests cover that contract as well as the store.
    """
    with patch.object(
        OIDCProxy, "get_oidc_configuration", return_value=oidc_configuration()
    ):
        provider = OIDCProxy(
            config_url=f"{ISSUER}/.well-known/openid-configuration",
            client_id="upstream-client-id",
            client_secret=client_secret,
            required_scopes=["openid"],
            base_url=BASE_URL,
            **settings.provider_kwargs(client_storage),
        )
    # get_routes() does this when the ASGI app is built; it creates the issuer
    # the tokens are signed with.
    provider.set_mcp_path("/mcp")
    return provider


def client(client_id: str) -> OAuthClientInformationFull:
    return OAuthClientInformationFull(
        client_id=client_id,
        redirect_uris=[AnyUrl(REDIRECT_URI)],
        token_endpoint_auth_method="none",
    )


async def sign_in(provider: OIDCProxy, client_info: OAuthClientInformationFull) -> str:
    """Complete a sign-in for ``client_info`` and return the server-issued access token."""
    assert client_info.client_id is not None
    code = f"code-for-{client_info.client_id}"
    now = time.time()
    await provider._code_store.put(
        key=code,
        value=ClientCode(
            code=code,
            client_id=client_info.client_id,
            redirect_uri=REDIRECT_URI,
            code_challenge="challenge",
            code_challenge_method="S256",
            scopes=["openid"],
            idp_tokens={
                "access_token": UPSTREAM_ACCESS_TOKEN,
                "refresh_token": "upstream-refresh-token",
                "token_type": "Bearer",
                "expires_in": 3600,
            },
            expires_at=now + 300,
            created_at=now,
        ),
        ttl=300,
    )
    token = await provider.exchange_authorization_code(
        client_info,
        AuthorizationCode(
            code=code,
            client_id=client_info.client_id,
            redirect_uri=AnyUrl(REDIRECT_URI),
            redirect_uri_provided_explicitly=True,
            scopes=["openid"],
            expires_at=now + 300,
            code_challenge="challenge",
        ),
    )
    return token.access_token


async def call_tool_auth(provider: OIDCProxy, token: str) -> object | None:
    """What the server's bearer-auth middleware does before every MCP request.

    The upstream IdP is stood in for by accepting exactly the upstream access
    token the sign-in stored: a token the server still maps to it is valid.
    """

    async def verify(upstream_token: str) -> AccessToken | None:
        if upstream_token != UPSTREAM_ACCESS_TOKEN:
            return None
        return AccessToken(
            token=upstream_token, client_id="upstream", scopes=["openid"]
        )

    with patch.object(
        provider._token_validator, "verify_token", AsyncMock(side_effect=verify)
    ):
        return await provider.load_access_token(token)


class TestDefaultFileStore:
    """FastMCP's default store, which is what a deployment that sets nothing gets."""

    async def test_a_restart_with_an_empty_store_signs_every_user_out(
        self, tmp_path: Path
    ):
        """The problem this change exists for, reproduced: register, sign in,
        restart on a filesystem that did not survive, call a tool -- refused.
        """
        config = OAuthStateSettings()
        with pod(tmp_path / "pod-1"):
            before = start_provider(config)
            await before.register_client(client(DCR_CLIENT_ID))
            token = await sign_in(before, client(DCR_CLIENT_ID))
            assert await call_tool_auth(before, token) is not None

        with pod(tmp_path / "pod-2"):
            after = start_provider(config)
            assert await after.get_client(DCR_CLIENT_ID) is None
            assert await call_tool_auth(after, token) is None

    async def test_a_restart_on_the_same_disk_keeps_registrations_and_sessions(
        self, tmp_path: Path
    ):
        """The control: with the default store's directory intact -- a VM disk,
        a mounted volume -- the same restart loses nothing. So what breaks above
        is the store, not the signing key, which is deterministic either way."""
        config = OAuthStateSettings()
        with pod(tmp_path / "disk"):
            before = start_provider(config)
            await before.register_client(client(DCR_CLIENT_ID))
            token = await sign_in(before, client(DCR_CLIENT_ID))

            after = start_provider(config)
            assert await after.get_client(DCR_CLIENT_ID) is not None
            assert await call_tool_auth(after, token) is not None

    async def test_rotating_the_client_secret_strands_the_store_without_a_signing_key(
        self, tmp_path: Path
    ):
        """Why a volume alone is not enough: the signing key, and with it the
        store's encryption key and directory, is derived from the upstream
        client secret, so its rotation loses everything the volume kept."""
        with pod(tmp_path / "disk"):
            before = start_provider(OAuthStateSettings())
            await before.register_client(client(DCR_CLIENT_ID))
            token = await sign_in(before, client(DCR_CLIENT_ID))

            after = start_provider(OAuthStateSettings(), ROTATED_SECRET)
            assert await after.get_client(DCR_CLIENT_ID) is None
            assert await call_tool_auth(after, token) is None

    async def test_a_signing_key_makes_the_file_store_survive_a_secret_rotation(
        self, tmp_path: Path
    ):
        """A signing key works with the default store too: the store directory
        and the token signatures then depend on it instead of the secret."""
        key = "a-signing-key-the-operator-chose-and-keeps"
        with pod(tmp_path / "disk"):
            before = start_provider(OAuthStateSettings(jwt_signing_key=key))
            await before.register_client(client(DCR_CLIENT_ID))
            token = await sign_in(before, client(DCR_CLIENT_ID))

            after = start_provider(
                OAuthStateSettings(jwt_signing_key=key), ROTATED_SECRET
            )
            assert await after.get_client(DCR_CLIENT_ID) is not None
            assert await call_tool_auth(after, token) is not None


SIGNING_KEY = "a-signing-key-shared-by-every-replica"


def dynamodb_settings(
    table: str, jwt_signing_key: str = SIGNING_KEY
) -> OAuthStateSettings:
    return OAuthStateSettings(
        jwt_signing_key=jwt_signing_key,
        store_backend="dynamodb",
        store_dynamodb_table=table,
    )


async def open_storage(settings: OAuthStateSettings) -> ClientStorage:
    """What ``serve_http`` does once per process before building providers."""
    storage = build_client_storage(settings)
    assert storage is not None
    await storage.open()
    return storage


class TestDynamoDBStore:
    """An external backend: every pod starts on an empty filesystem, and the
    state lives in a DynamoDB table the restart does not touch."""

    async def test_a_dcr_client_and_its_session_survive_a_restart(
        self, tmp_path: Path, dynamodb_table: str
    ):
        config = dynamodb_settings(dynamodb_table)
        with pod(tmp_path / "pod-1"):
            storage = await open_storage(config)
            before = start_provider(config, client_storage=storage)
            await before.register_client(client(DCR_CLIENT_ID))
            token = await sign_in(before, client(DCR_CLIENT_ID))
            await storage.close()

        with pod(tmp_path / "pod-2"):
            storage = await open_storage(config)
            after = start_provider(config, client_storage=storage)
            # Recognized without registering again: no new POST /register.
            registered = await after.get_client(DCR_CLIENT_ID)
            assert registered is not None
            assert registered.redirect_uris == [AnyUrl(REDIRECT_URI)]
            assert await call_tool_auth(after, token) is not None
            await storage.close()

    async def test_a_cimd_clients_session_survives_a_restart(
        self, tmp_path: Path, dynamodb_table: str
    ):
        """A CIMD client keeps its registration by itself -- the server re-fetches
        its metadata document -- but its session lives in the store like any
        other. The document fetch is not exercised: ``get_client`` for a URL
        client_id goes to the network, and the session does not depend on it."""
        config = dynamodb_settings(dynamodb_table)
        with pod(tmp_path / "pod-1"):
            storage = await open_storage(config)
            before = start_provider(config, client_storage=storage)
            token = await sign_in(before, client(CIMD_CLIENT_ID))
            await storage.close()

        with pod(tmp_path / "pod-2"):
            storage = await open_storage(config)
            after = start_provider(config, client_storage=storage)
            assert await call_tool_auth(after, token) is not None
            await storage.close()

    async def test_both_survive_a_rotation_of_the_client_secret(
        self, tmp_path: Path, dynamodb_table: str
    ):
        """The signing key, not the client secret, signs the tokens and keys
        the store's encryption, so the secret can be rotated freely."""
        with pod(tmp_path / "pod-1"):
            config = dynamodb_settings(dynamodb_table)
            storage = await open_storage(config)
            before = start_provider(config, client_storage=storage)
            await before.register_client(client(DCR_CLIENT_ID))
            dcr_token = await sign_in(before, client(DCR_CLIENT_ID))
            cimd_token = await sign_in(before, client(CIMD_CLIENT_ID))
            await storage.close()

        with pod(tmp_path / "pod-2"):
            config = dynamodb_settings(dynamodb_table)
            storage = await open_storage(config)
            after = start_provider(config, ROTATED_SECRET, client_storage=storage)
            assert await after.get_client(DCR_CLIENT_ID) is not None
            assert await call_tool_auth(after, dcr_token) is not None
            assert await call_tool_auth(after, cimd_token) is not None
            await storage.close()

    async def test_another_signing_key_reads_the_store_as_empty(
        self, tmp_path: Path, dynamodb_table: str
    ):
        """The other side of raise_on_decryption_error=False: entries written
        under a different key read as missing, so clients re-register and users
        sign in again instead of every request failing."""
        with pod(tmp_path / "pod-1"):
            config = dynamodb_settings(dynamodb_table)
            storage = await open_storage(config)
            before = start_provider(config, client_storage=storage)
            await before.register_client(client(DCR_CLIENT_ID))
            await storage.close()

        with pod(tmp_path / "pod-2"):
            config = dynamodb_settings(
                dynamodb_table, jwt_signing_key="a-different-signing-key-altogether"
            )
            storage = await open_storage(config)
            after = start_provider(config, client_storage=storage)
            assert await after.get_client(DCR_CLIENT_ID) is None
            await storage.close()
