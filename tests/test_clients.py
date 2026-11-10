"""Tests for the allowlist of OAuth clients an ``OAuthProxy`` accepts."""

from __future__ import annotations

import logging
from collections.abc import Iterator
from unittest.mock import AsyncMock, patch

import fastmcp
import httpx2
import pytest
from fastmcp import FastMCP
from fastmcp.server.auth.oauth_proxy import OAuthProxy
from fastmcp.server.auth.providers.in_memory import InMemoryOAuthProvider
from fastmcp.server.auth.providers.jwt import StaticTokenVerifier
from key_value.aio.stores.memory import MemoryStore
from mcp.server.auth.provider import RegistrationError
from mcp.shared.auth import InvalidRedirectUriError, OAuthClientInformationFull
from pydantic import AnyUrl
from starlette.applications import Starlette

from fastmcp_seaworthy import ClientAllowlist, build_host_router

BASE_URL = "https://mcp.example.com"
UPSTREAM = "https://idp.example.com"
UPSTREAM_CLIENT_ID = "upstream-client-id"
CLAUDE = "https://claude.ai/oauth/mcp-oauth-client-metadata"
UNLISTED = "https://client.example.net/oauth/client-metadata.json"
REDIRECT_URI = "http://127.0.0.1:33418/callback"
AS_METADATA_PATH = "/.well-known/oauth-authorization-server"


@pytest.fixture(autouse=True)
def _fast_key_derivation() -> Iterator[None]:
    """Cut FastMCP's PBKDF2 rounds for the signing key, a second per provider."""
    with patch.object(fastmcp.settings, "test_mode", True):
        yield


def make_provider(
    base_url: str = BASE_URL, store: MemoryStore | None = None, **kwargs
) -> OAuthProxy:
    """A plain ``OAuthProxy``: every IdP-specific subclass inherits the
    methods the allowlist wraps, and this one reaches no network."""
    return OAuthProxy(
        upstream_authorization_endpoint=f"{UPSTREAM}/authorize",
        upstream_token_endpoint=f"{UPSTREAM}/token",
        upstream_client_id=UPSTREAM_CLIENT_ID,
        upstream_client_secret="upstream-client-secret",
        token_verifier=StaticTokenVerifier(tokens={}),
        base_url=base_url,
        client_storage=store if store is not None else MemoryStore(),
        jwt_signing_key="a-signing-key-shared-by-every-replica",
        **kwargs,
    )


def dcr_client(client_id: str) -> OAuthClientInformationFull:
    return OAuthClientInformationFull(
        client_id=client_id,
        redirect_uris=[AnyUrl(REDIRECT_URI)],
        token_endpoint_auth_method="none",
    )


def http_client(provider: OAuthProxy) -> httpx2.AsyncClient:
    app = Starlette(routes=provider.get_routes("/mcp"))
    return httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url=BASE_URL
    )


class TestValidation:
    def test_default_is_no_allowlist(self):
        allowlist = ClientAllowlist()
        assert not allowlist.enabled
        assert allowlist.allows(UNLISTED)

    def test_a_list_is_stored_as_a_tuple(self):
        allowlist = ClientAllowlist([CLAUDE])  # ty: ignore[invalid-argument-type]
        assert allowlist.client_ids == (CLAUDE,)
        hash(allowlist)

    @pytest.mark.parametrize(
        "entry",
        [
            "https://claude.ai/",
            "https://example.com/clients/",
            CLAUDE,
            "https://example.com:8443/client.json",
            UPSTREAM_CLIENT_ID,
        ],
    )
    def test_accepted_entries(self, entry):
        ClientAllowlist((entry,))

    @pytest.mark.parametrize(
        ("entry", "reason"),
        [
            ("https://claude.ai*", "wildcards are not supported"),
            ("*", "wildcards are not supported"),
            ("http://claude.ai/", "http:// URL"),
            ("https://claude.ai", "without a path"),
            ("https:///path/", "without a plain host"),
            ("https://user@claude.ai/", "without a plain host"),
            ("https://claude.ai/?x=1", "query or fragment"),
            ("https://claude.ai/#x", "query or fragment"),
            ("https://example.com/clients/../", "path segment"),
            ("https://example.com/clients/%2E%2E/", "path segment"),
            ("", "is empty"),
            ("a,b", "comma or whitespace"),
        ],
    )
    def test_malformed_entry_is_refused_naming_the_setting_not_the_entry(
        self, entry, reason
    ):
        with pytest.raises(ValueError, match=reason) as excinfo:
            ClientAllowlist((CLAUDE, entry))
        assert "ALLOWED_CLIENT_IDS entry 2" in str(excinfo.value)
        if len(entry) > 1:  # "*" is quoted in the reason itself
            assert entry not in str(excinfo.value)


class TestFromEnv:
    @pytest.mark.parametrize("environ", [{}, {"ALLOWED_CLIENT_IDS": ""}])
    def test_unset_or_empty_is_no_allowlist(self, environ):
        assert ClientAllowlist.from_env(environ) == ClientAllowlist()

    def test_entries_are_separated_by_commas_and_whitespace(self):
        """One line in a .env file, or a YAML block scalar in a manifest."""
        allowlist = ClientAllowlist.from_env(
            {"ALLOWED_CLIENT_IDS": f" {CLAUDE},\n  https://example.com/clients/ ,, x\n"}
        )
        assert allowlist.client_ids == (CLAUDE, "https://example.com/clients/", "x")

    def test_reads_os_environ_by_default(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("ALLOWED_CLIENT_IDS", CLAUDE)
        assert ClientAllowlist.from_env().client_ids == (CLAUDE,)

    def test_malformed_entry_fails_at_startup(self):
        with pytest.raises(ValueError, match="ALLOWED_CLIENT_IDS entry 1"):
            ClientAllowlist.from_env({"ALLOWED_CLIENT_IDS": "https://claude.ai*"})


class TestMatching:
    def test_exact_match(self):
        allowlist = ClientAllowlist((CLAUDE, UPSTREAM_CLIENT_ID))
        assert allowlist.allows(CLAUDE)
        assert allowlist.allows(UPSTREAM_CLIENT_ID)
        assert not allowlist.allows(UNLISTED)

    def test_an_exact_entry_is_not_a_prefix(self):
        allowlist = ClientAllowlist((CLAUDE,))
        assert not allowlist.allows(f"{CLAUDE}-other")
        assert not allowlist.allows(f"{CLAUDE}/other")

    def test_https_entry_ending_in_slash_is_a_prefix(self):
        allowlist = ClientAllowlist(("https://claude.ai/",))
        assert allowlist.allows(CLAUDE)
        assert allowlist.allows("https://claude.ai/another/client.json")

    def test_prefix_does_not_match_a_lookalike_host(self):
        """The reason entries end in '/' and globs are refused: a lookalike
        host is one anyone can register."""
        allowlist = ClientAllowlist(("https://claude.ai/",))
        assert not allowlist.allows("https://claude.ai.attacker.example/client.json")
        assert not allowlist.allows("https://claude.aiattacker.example/client.json")
        assert not allowlist.allows("https://claude.ai:8443/client.json")
        assert not allowlist.allows("http://claude.ai/client.json")

    def test_path_prefix_stays_within_its_path(self):
        allowlist = ClientAllowlist(("https://example.com/clients/",))
        assert allowlist.allows("https://example.com/clients/a.json")
        assert not allowlist.allows("https://example.com/clientsx/a.json")
        assert not allowlist.allows("https://example.com/uploads/a.json")

    @pytest.mark.parametrize(
        "client_id",
        [
            "https://example.com/clients/../uploads/a.json",
            "https://example.com/clients/%2e%2e/uploads/a.json",
            "https://example.com/clients/./a.json",
        ],
    )
    def test_dot_segments_cannot_escape_a_prefix(self, client_id):
        assert not ClientAllowlist(("https://example.com/clients/",)).allows(client_id)

    def test_an_opaque_entry_ending_in_slash_is_exact(self):
        allowlist = ClientAllowlist(("client/",))
        assert allowlist.allows("client/")
        assert not allowlist.allows("client/other")

    def test_comparison_is_case_sensitive(self):
        assert not ClientAllowlist((CLAUDE,)).allows(CLAUDE.upper())


class TestDescribe:
    def test_unset(self):
        assert "ALLOWED_CLIENT_IDS is not set" in ClientAllowlist().describe()

    def test_names_the_entries(self):
        description = ClientAllowlist((CLAUDE, UPSTREAM_CLIENT_ID)).describe()
        assert CLAUDE in description
        assert UPSTREAM_CLIENT_ID in description
        assert "registration disabled" in description


class TestApply:
    async def test_unset_leaves_the_provider_untouched(self):
        provider = make_provider()
        assert ClientAllowlist().apply(provider) is provider
        assert "get_client" not in vars(provider)
        assert provider.client_registration_options is not None
        assert provider.client_registration_options.enabled
        await provider.register_client(dcr_client("dcr-client"))
        assert await provider.get_client("dcr-client") is not None

    def test_returns_the_same_provider(self):
        provider = make_provider()
        assert ClientAllowlist((CLAUDE,)).apply(provider) is provider

    def test_refuses_a_provider_that_is_not_an_oauth_proxy(self):
        with pytest.raises(TypeError, match="needs an OAuthProxy"):
            ClientAllowlist((CLAUDE,)).apply(
                InMemoryOAuthProvider(base_url=BASE_URL)  # ty: ignore[invalid-argument-type]
            )

    def test_refuses_to_apply_twice(self):
        provider = ClientAllowlist((CLAUDE,)).apply(make_provider())
        with pytest.raises(ValueError, match="already applied"):
            ClientAllowlist((UNLISTED,)).apply(provider)

    async def test_unlisted_cimd_client_is_rejected_without_being_fetched(
        self, caplog: pytest.LogCaptureFixture
    ):
        """Nothing outside the list makes the proxy issue an outbound request."""
        provider = ClientAllowlist(("https://claude.ai/",)).apply(make_provider())
        assert provider._cimd_manager is not None
        with (
            patch.object(provider._cimd_manager, "get_client", AsyncMock()) as fetch,
            caplog.at_level(logging.WARNING, logger="fastmcp_seaworthy.clients"),
        ):
            assert await provider.get_client(UNLISTED) is None
            assert (
                await provider.get_client("https://claude.ai.attacker.example/c")
                is None
            )
        fetch.assert_not_awaited()
        assert UNLISTED in caplog.text

    async def test_listed_cimd_client_is_fetched(self):
        provider = ClientAllowlist(("https://claude.ai/",)).apply(make_provider())
        assert provider._cimd_manager is not None
        resolved = dcr_client(CLAUDE)
        with patch.object(
            provider._cimd_manager, "get_client", AsyncMock(return_value=resolved)
        ) as fetch:
            assert await provider.get_client(CLAUDE) is resolved
        fetch.assert_awaited_once_with(CLAUDE)

    async def test_registration_is_refused(self, caplog: pytest.LogCaptureFixture):
        provider = ClientAllowlist((CLAUDE,)).apply(make_provider())
        with (
            caplog.at_level(logging.WARNING, logger="fastmcp_seaworthy.clients"),
            pytest.raises(RegistrationError) as excinfo,
        ):
            await provider.register_client(dcr_client("dcr-client"))
        assert excinfo.value.error == "invalid_client_metadata"
        assert "registration" in caplog.text

    async def test_client_stored_before_the_allowlist_is_rejected(self):
        """A deployment that turns the allowlist on keeps its store, and with
        it every client that registered through DCR before."""
        store = MemoryStore()
        await make_provider(store=store).register_client(dcr_client("dcr-client"))
        assert await make_provider(store=store).get_client("dcr-client") is not None

        provider = ClientAllowlist((CLAUDE,)).apply(make_provider(store=store))
        assert await provider.get_client("dcr-client") is None

    async def test_upstream_client_id_is_accepted_only_when_listed(self):
        unlisted = ClientAllowlist((CLAUDE,)).apply(make_provider())
        assert await unlisted.get_client(UPSTREAM_CLIENT_ID) is None

        listed = ClientAllowlist(
            (UPSTREAM_CLIENT_ID,), upstream_client_redirect_uris=(REDIRECT_URI,)
        ).apply(make_provider())
        client = await listed.get_client(UPSTREAM_CLIENT_ID)
        assert client is not None
        assert client.client_id == UPSTREAM_CLIENT_ID


class TestUpstreamClientRedirectUris:
    """The upstream client_id is the one entry a client_id alone cannot pin
    down: FastMCP accepts any redirect URI for it."""

    def test_listing_the_upstream_client_id_without_redirect_uris_is_refused(self):
        with pytest.raises(ValueError, match="ALLOWED_UPSTREAM_CLIENT_REDIRECT_URIS"):
            ClientAllowlist((CLAUDE, UPSTREAM_CLIENT_ID)).apply(make_provider())

    def test_redirect_uris_without_client_ids_are_refused(self):
        with pytest.raises(ValueError, match="no effect without ALLOWED_CLIENT_IDS"):
            ClientAllowlist(upstream_client_redirect_uris=(REDIRECT_URI,))

    def test_empty_redirect_uri_entry_is_refused(self):
        with pytest.raises(ValueError, match="REDIRECT_URIS entry 2 is empty"):
            ClientAllowlist((CLAUDE,), upstream_client_redirect_uris=("x", ""))

    def test_from_env(self):
        allowlist = ClientAllowlist.from_env(
            {
                "ALLOWED_CLIENT_IDS": UPSTREAM_CLIENT_ID,
                "ALLOWED_UPSTREAM_CLIENT_REDIRECT_URIS": (
                    "http://localhost:*, https://app.example.com/callback"
                ),
            }
        )
        assert allowlist.upstream_client_redirect_uris == (
            "http://localhost:*",
            "https://app.example.com/callback",
        )
        assert "https://app.example.com/callback" in allowlist.describe()

    def test_warns_when_the_upstream_client_id_is_not_listed(
        self, caplog: pytest.LogCaptureFixture
    ):
        with caplog.at_level(logging.WARNING, logger="fastmcp_seaworthy.clients"):
            ClientAllowlist(
                (CLAUDE,), upstream_client_redirect_uris=(REDIRECT_URI,)
            ).apply(make_provider())
        assert "has no effect" in caplog.text

    async def test_upstream_client_is_limited_to_the_listed_redirect_uris(self):
        provider = ClientAllowlist(
            (UPSTREAM_CLIENT_ID,), upstream_client_redirect_uris=("http://localhost:*",)
        ).apply(make_provider())
        client = await provider.get_client(UPSTREAM_CLIENT_ID)
        assert client is not None
        allowed = AnyUrl("http://localhost:33418/callback")
        assert client.validate_redirect_uri(allowed) == allowed
        with pytest.raises(InvalidRedirectUriError, match="not allowed"):
            client.validate_redirect_uri(AnyUrl("https://attacker.example/cb"))

    async def test_without_the_allowlist_fastmcp_accepts_any_redirect_uri(self):
        """The hole the setting closes, so this test notices if FastMCP
        ever closes it itself."""
        client = await make_provider().get_client(UPSTREAM_CLIENT_ID)
        assert client is not None
        evil = AnyUrl("https://attacker.example/cb")
        assert client.validate_redirect_uri(evil) == evil

    async def test_the_providers_own_restriction_still_applies(self):
        provider = ClientAllowlist(
            (UPSTREAM_CLIENT_ID,),
            upstream_client_redirect_uris=("http://localhost:*", "https://*"),
        ).apply(make_provider(allowed_client_redirect_uris=["http://localhost:*"]))
        client = await provider.get_client(UPSTREAM_CLIENT_ID)
        assert client is not None
        client.validate_redirect_uri(AnyUrl("http://localhost:33418/callback"))
        with pytest.raises(InvalidRedirectUriError):
            client.validate_redirect_uri(AnyUrl("https://app.example.com/callback"))

    @pytest.mark.parametrize(
        ("redirect_uri", "accepted"),
        [(REDIRECT_URI, True), ("https://attacker.example/cb", False)],
    )
    async def test_authorize_endpoint_enforces_them(self, redirect_uri, accepted):
        provider = ClientAllowlist(
            (UPSTREAM_CLIENT_ID,), upstream_client_redirect_uris=("http://127.0.0.1:*",)
        ).apply(make_provider())
        async with http_client(provider) as client:
            response = await client.get(
                "/authorize",
                params={
                    "client_id": UPSTREAM_CLIENT_ID,
                    "redirect_uri": redirect_uri,
                    "response_type": "code",
                    "code_challenge": "x" * 43,
                    "code_challenge_method": "S256",
                    "state": "state",
                },
            )
        location = response.headers.get("location", "")
        assert not location.startswith("https://attacker.example")
        if accepted:
            assert response.status_code in (302, 303, 307)
        else:
            assert response.status_code == 400

    async def test_cimd_clients_keep_their_own_redirect_uris(self):
        """A loopback CIMD client such as Claude Code is not narrowed to the
        upstream client's redirect URIs."""
        provider = ClientAllowlist(
            ("https://claude.ai/", UPSTREAM_CLIENT_ID),
            upstream_client_redirect_uris=("https://app.example.com/callback",),
        ).apply(make_provider())
        assert provider._cimd_manager is not None
        resolved = dcr_client(CLAUDE)
        with patch.object(
            provider._cimd_manager, "get_client", AsyncMock(return_value=resolved)
        ):
            assert await provider.get_client(CLAUDE) is resolved

    def test_warns_when_url_entries_cannot_match_without_cimd(
        self, caplog: pytest.LogCaptureFixture
    ):
        with caplog.at_level(logging.WARNING, logger="fastmcp_seaworthy.clients"):
            ClientAllowlist((CLAUDE,)).apply(make_provider(enable_cimd=False))
        assert "enable_cimd=False" in caplog.text


class TestOverHttp:
    async def test_metadata_advertises_no_registration_endpoint(self):
        """A client that sees no registration_endpoint does not try DCR, which
        could only end in an error; one that supports CIMD uses that."""
        provider = ClientAllowlist((CLAUDE,)).apply(make_provider())
        async with http_client(provider) as client:
            metadata = (await client.get(AS_METADATA_PATH)).json()
            register = await client.post(
                "/register", json={"redirect_uris": [REDIRECT_URI]}
            )
        assert "registration_endpoint" not in metadata
        assert metadata["client_id_metadata_document_supported"] is True
        assert register.status_code in (404, 405)

    async def test_without_allowlist_registration_stays_open(self):
        async with http_client(make_provider()) as client:
            metadata = (await client.get(AS_METADATA_PATH)).json()
            register = await client.post(
                "/register", json={"redirect_uris": [REDIRECT_URI]}
            )
        assert metadata["registration_endpoint"] == f"{BASE_URL}/register"
        assert register.status_code == 201

    @pytest.mark.parametrize(
        ("client_ids", "expected_error"),
        [
            # Listed: the client is found, and only the bogus token fails.
            (("dcr-client",), "invalid_grant"),
            # Removed from the list: refused before the token is looked at.
            ((CLAUDE,), "invalid_client"),
        ],
    )
    async def test_token_endpoint_refuses_a_removed_client(
        self, client_ids, expected_error
    ):
        """Removing an entry stops refresh too, not only new sign-ins."""
        store = MemoryStore()
        await make_provider(store=store).register_client(dcr_client("dcr-client"))
        provider = ClientAllowlist(client_ids).apply(make_provider(store=store))
        async with http_client(provider) as client:
            response = await client.post(
                "/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": "a-refresh-token",
                    "client_id": "dcr-client",
                },
            )
        assert response.status_code in (400, 401)
        assert response.json()["error"] == expected_error


async def test_per_hostname_providers_all_enforce_the_allowlist():
    """One allowlist, applied in the factory serve_http calls per hostname."""
    allowlist = ClientAllowlist((CLAUDE,))
    base_urls = [BASE_URL, "https://mcp.example.io"]
    providers: list[OAuthProxy] = []

    def auth_for(base_url: str) -> OAuthProxy:
        provider = allowlist.apply(make_provider(base_url))
        providers.append(provider)
        return provider

    router = build_host_router(FastMCP(name="test-server"), base_urls, auth_for)
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=router), base_url="http://testserver"
    ) as client:
        for base_url in base_urls:
            host = base_url.removeprefix("https://")
            metadata = (
                await client.get(AS_METADATA_PATH, headers={"Host": host})
            ).json()
            assert metadata["issuer"] == f"{base_url}/"
            assert "registration_endpoint" not in metadata
    assert len(providers) == 2
    for provider in providers:
        assert await provider.get_client(UNLISTED) is None
