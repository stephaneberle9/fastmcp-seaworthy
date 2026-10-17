"""Tests for serving one FastMCP server under several hostnames."""

from __future__ import annotations

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastmcp import FastMCP

from fastmcp_seaworthy import serve
from fastmcp_seaworthy.host_router import HostRouter

PRIMARY = "https://mcp.example.io"
ALIAS = "https://mcp.example.com"


@asynccontextmanager
async def _noop_lifespan():
    yield


def _fake_server():
    server = MagicMock(name="server")
    server._lifespan_manager.side_effect = lambda: _noop_lifespan()
    return server


def _storage(events: list[str]):
    storage = MagicMock(name="storage")
    storage.open = AsyncMock(side_effect=lambda: events.append("open"))
    storage.close = AsyncMock(side_effect=lambda: events.append("close"))
    return storage


class TestBuildHostRouter:
    def test_one_provider_per_base_url_canonical_first(self):
        built: list[str] = []

        def auth_for(base_url: str):
            built.append(base_url)

        router = serve.build_host_router(FastMCP(name="s"), [PRIMARY, ALIAS], auth_for)

        assert isinstance(router, HostRouter)
        assert built == [PRIMARY, ALIAS]
        assert router.app_for_host(None) is router.app_for_host("mcp.example.io")
        assert router.app_for_host("mcp.example.com") is not router.app_for_host(
            "mcp.example.io"
        )

    def test_rejects_no_base_url(self):
        with pytest.raises(ValueError, match="at least one base URL"):
            serve.build_host_router(FastMCP(name="s"), [], lambda _: None)

    def test_rejects_colliding_hostnames_before_building_any_provider(self):
        auth_for = MagicMock(return_value=None)
        with pytest.raises(ValueError, match="share the hostname"):
            serve.build_host_router(
                FastMCP(name="s"), [ALIAS, "http://mcp.example.com:8080"], auth_for
            )
        auth_for.assert_not_called()

    def test_fastmcp_settings_are_the_defaults(self):
        """Unset keywords fall back to FastMCP's settings, as http_app() does,
        so FASTMCP_* environment variables keep working."""
        with patch.object(serve, "create_streamable_http_app") as create_app:
            serve.build_host_router(FastMCP(name="s"), [PRIMARY], lambda _: None)

        kwargs = create_app.call_args.kwargs
        settings = serve.fastmcp.settings
        assert kwargs["streamable_http_path"] == settings.streamable_http_path
        assert kwargs["host_origin_protection"] == settings.http_host_origin_protection
        assert kwargs["allowed_hosts"] == settings.http_allowed_hosts
        assert kwargs["session_idle_timeout"] == settings.http_session_idle_timeout

    def test_explicit_keywords_reach_every_app(self):
        with patch.object(serve, "create_streamable_http_app") as create_app:
            serve.build_host_router(
                FastMCP(name="s"),
                [PRIMARY, ALIAS],
                lambda _: None,
                path="/custom",
                stateless_http=True,
                allowed_hosts=["mcp.example.io", "mcp.example.com"],
            )

        for call in create_app.call_args_list:
            assert call.kwargs["streamable_http_path"] == "/custom"
            assert call.kwargs["stateless_http"] is True
            assert call.kwargs["allowed_hosts"] == ["mcp.example.io", "mcp.example.com"]


class TestServeHttp:
    """The store is opened once per process, before any provider exists, and
    closed once uvicorn stops -- whether it stopped cleanly or not."""

    async def test_store_is_opened_before_providers_and_closed_after_serving(self):
        events: list[str] = []
        storage = _storage(events)

        def auth_for(base_url: str):
            events.append(f"auth {base_url}")

        with (
            patch.object(serve, "create_streamable_http_app"),
            patch.object(serve, "HostRouter"),
            patch.object(serve, "uvicorn") as uvicorn_mod,
        ):
            uvicorn_mod.Server.return_value.serve = AsyncMock(
                side_effect=lambda: events.append("serve")
            )
            await serve.serve_http(
                _fake_server(),
                [PRIMARY, ALIAS],
                auth_for,
                client_storage=storage,
                show_banner=False,
            )

        assert events == ["open", f"auth {PRIMARY}", f"auth {ALIAS}", "serve", "close"]

    async def test_store_is_closed_when_serving_fails(self):
        events: list[str] = []
        storage = _storage(events)
        with (
            patch.object(serve, "create_streamable_http_app"),
            patch.object(serve, "HostRouter"),
            patch.object(serve, "uvicorn") as uvicorn_mod,
            pytest.raises(OSError, match="address in use"),
        ):
            uvicorn_mod.Server.return_value.serve = AsyncMock(
                side_effect=OSError("address in use")
            )
            await serve.serve_http(
                _fake_server(),
                [PRIMARY],
                lambda _: None,
                client_storage=storage,
                show_banner=False,
            )

        assert events == ["open", "close"]

    async def test_a_store_that_cannot_open_stops_startup_before_serving(self):
        storage = MagicMock(name="storage")
        storage.open = AsyncMock(side_effect=ValueError("Cannot use DynamoDB table"))
        storage.close = AsyncMock()
        auth_for = MagicMock(return_value=None)
        with (
            patch.object(serve, "uvicorn") as uvicorn_mod,
            pytest.raises(ValueError, match="Cannot use DynamoDB table"),
        ):
            await serve.serve_http(
                _fake_server(),
                [PRIMARY],
                auth_for,
                client_storage=storage,
                show_banner=False,
            )

        auth_for.assert_not_called()
        uvicorn_mod.Server.assert_not_called()
        # ClientStorage.open() closes the backend itself on a failed setup.
        storage.close.assert_not_called()

    async def test_server_lifespan_is_held_around_uvicorn(self):
        events: list[str] = []

        @asynccontextmanager
        async def lifespan():
            events.append("lifespan enter")
            yield
            events.append("lifespan exit")

        server = MagicMock(name="server")
        server._lifespan_manager.side_effect = lambda: lifespan()
        with (
            patch.object(serve, "create_streamable_http_app"),
            patch.object(serve, "HostRouter"),
            patch.object(serve, "uvicorn") as uvicorn_mod,
        ):
            uvicorn_mod.Server.return_value.serve = AsyncMock(
                side_effect=lambda: events.append("serve")
            )
            await serve.serve_http(server, [PRIMARY], lambda _: None, show_banner=False)

        assert events == ["lifespan enter", "serve", "lifespan exit"]

    async def test_uvicorn_gets_fastmcps_defaults_and_caller_overrides(self):
        with (
            patch.object(serve, "create_streamable_http_app"),
            patch.object(serve, "HostRouter") as router_cls,
            patch.object(serve, "uvicorn") as uvicorn_mod,
        ):
            uvicorn_mod.Server.return_value.serve = AsyncMock()
            await serve.serve_http(
                _fake_server(),
                [PRIMARY],
                lambda _: None,
                show_banner=False,
                host="127.0.0.1",
                port=9000,
                uvicorn_config={"timeout_graceful_shutdown": 5},
            )

        args, kwargs = uvicorn_mod.Config.call_args
        assert args == (router_cls.return_value,)
        assert kwargs["host"] == "127.0.0.1"
        assert kwargs["port"] == 9000
        assert kwargs["lifespan"] == "on"
        assert kwargs["timeout_graceful_shutdown"] == 5

    async def test_stateless_is_an_alias_for_stateless_http(self):
        with (
            patch.object(serve, "build_host_router") as build_router,
            patch.object(serve, "uvicorn") as uvicorn_mod,
        ):
            uvicorn_mod.Server.return_value.serve = AsyncMock()
            await serve.serve_http(
                _fake_server(),
                [PRIMARY],
                lambda _: None,
                show_banner=False,
                stateless=True,
            )

        assert build_router.call_args.kwargs["stateless_http"] is True
