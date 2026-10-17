"""Serve one FastMCP server under several public hostnames, each its own OAuth identity.

:func:`build_host_router` builds one streamable-HTTP app per public base URL,
each with the auth provider the caller builds for that URL, behind a
:class:`~fastmcp_seaworthy.host_router.HostRouter`. :func:`serve_http` runs
that router under uvicorn the way ``FastMCP.run_http_async`` runs a single app,
and owns the lifecycle of an external OAuth state store.

The single-hostname case runs the same way with one child app, so a deployment
that adds a hostname later changes configuration, not code paths.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING, Any, Literal

import fastmcp
import uvicorn
from fastmcp.server.http import create_streamable_http_app
from fastmcp.utilities.logging import temporary_log_level

from .host_router import HostRouter, check_distinct_hosts

if TYPE_CHECKING:
    from fastmcp import FastMCP
    from fastmcp.server.auth.auth import AuthProvider
    from fastmcp.server.http import HostOriginProtection
    from starlette.middleware import Middleware

    from .storage import ClientStorage

logger = logging.getLogger(__name__)

AuthFactory = Callable[[str], "AuthProvider | None"]
"""Builds the auth provider that advertises the given public base URL.

Called once per base URL, because a provider bakes its ``base_url`` in at
construction and advertises it everywhere -- resource metadata,
authorization-server metadata, the IdP ``redirect_uri``, minted token claims.
Returning ``None`` serves that hostname unauthenticated.
"""


def build_host_router(
    server: FastMCP,
    base_urls: Sequence[str],
    auth_for: AuthFactory,
    /,
    *,
    path: str | None = None,
    json_response: bool | None = None,
    stateless_http: bool | None = None,
    middleware: list[Middleware] | None = None,
    host_origin_protection: HostOriginProtection | None = None,
    allowed_hosts: Sequence[str] | None = None,
    allowed_origins: Sequence[str] | None = None,
    session_idle_timeout: float | Literal["auto"] | None = None,
) -> HostRouter:
    """Build one streamable-HTTP app per base URL over ``server``, routed on ``Host``.

    The tool catalog and the server lifespan stay shared: this duplicates the
    front door, not the backend. The first base URL is canonical -- it answers
    requests with no or an unknown ``Host``, such as health probes addressing
    the pod IP.

    Construct ``server`` without ``auth=``: auth is supplied per app here, and a
    server never served through its own ``http_app()`` cannot be reached
    unauthenticated by accident.

    Args:
        server: The FastMCP server backing every identity.
        base_urls: Every public base URL to serve under, canonical first.
        auth_for: Builds the auth provider for one base URL.
        path: Path the MCP endpoint is mounted at, shared by every identity.
            Defaults to FastMCP's setting.
        json_response: Use JSON rather than SSE responses. Defaults to
            FastMCP's setting.
        stateless_http: Create a new transport per request. Defaults to
            FastMCP's setting. With sessions enabled each identity keeps its own
            session store, since each has its own app -- a session opened
            against one hostname is not resumable against another. That is the
            intended boundary: they are separate OAuth resources.
        middleware: ASGI middleware applied to every identity's app. Starlette
            instantiates these per app, so one list is safe to share.
        host_origin_protection: FastMCP's DNS-rebinding guard. Defaults to
            FastMCP's ``http_host_origin_protection`` setting. When enabled,
            ``allowed_hosts`` must list every public hostname, since one list
            applies to every identity's app.
        allowed_hosts: Defaults to FastMCP's ``http_allowed_hosts`` setting.
        allowed_origins: Defaults to FastMCP's ``http_allowed_origins`` setting.
        session_idle_timeout: Defaults to FastMCP's
            ``http_session_idle_timeout`` setting.

    Raises:
        ValueError: If ``base_urls`` is empty, an entry has no hostname, or two
            entries share one.
    """
    if not base_urls:
        raise ValueError("build_host_router requires at least one base URL")
    check_distinct_hosts(base_urls)
    mcp_path = path if path is not None else fastmcp.settings.streamable_http_path
    apps = {
        base_url: create_streamable_http_app(
            server=server,
            streamable_http_path=mcp_path,
            auth=auth_for(base_url),
            json_response=(
                json_response
                if json_response is not None
                else fastmcp.settings.json_response
            ),
            stateless_http=(
                stateless_http
                if stateless_http is not None
                else fastmcp.settings.stateless_http
            ),
            debug=fastmcp.settings.debug,
            middleware=middleware,
            host_origin_protection=(
                host_origin_protection
                if host_origin_protection is not None
                else fastmcp.settings.http_host_origin_protection
            ),
            allowed_hosts=(
                allowed_hosts
                if allowed_hosts is not None
                else fastmcp.settings.http_allowed_hosts
            ),
            allowed_origins=(
                allowed_origins
                if allowed_origins is not None
                else fastmcp.settings.http_allowed_origins
            ),
            session_idle_timeout=(
                session_idle_timeout
                if session_idle_timeout is not None
                else fastmcp.settings.http_session_idle_timeout
            ),
        )
        for base_url in base_urls
    }
    return HostRouter(apps, canonical_base_url=base_urls[0])


async def serve_http(
    server: FastMCP,
    base_urls: Sequence[str],
    auth_for: AuthFactory,
    /,
    *,
    client_storage: ClientStorage | None = None,
    show_banner: bool = True,
    host: str | None = None,
    port: int | None = None,
    log_level: str | None = None,
    path: str | None = None,
    uvicorn_config: dict[str, Any] | None = None,
    json_response: bool | None = None,
    stateless_http: bool | None = None,
    stateless: bool | None = None,
    middleware: list[Middleware] | None = None,
    host_origin_protection: HostOriginProtection | None = None,
    allowed_hosts: Sequence[str] | None = None,
    allowed_origins: Sequence[str] | None = None,
    session_idle_timeout: float | Literal["auto"] | None = None,
) -> None:
    """Serve ``server`` under every base URL until uvicorn stops.

    Mirrors ``FastMCP.run_http_async`` -- same settings fallbacks, same uvicorn
    configuration, same keyword surface -- but serves the router from
    :func:`build_host_router` instead of a single app. The keywords are spelled
    out rather than forwarded so that this function, not uvicorn, decides what a
    caller may set: anything unrecognized fails at startup instead of being
    silently dropped. ``server``, ``base_urls`` and ``auth_for`` are
    positional-only so a caller's ``**kwargs`` cannot shadow them.

    Args:
        server: The FastMCP server backing every identity.
        base_urls: Every public base URL to serve under, canonical first.
        auth_for: Builds the auth provider for one base URL. To share an
            external OAuth state store between the hostnames, close over
            ``client_storage`` and pass
            ``settings.provider_kwargs(client_storage)`` to every provider.
        client_storage: The store from
            :func:`~fastmcp_seaworthy.storage.build_client_storage`, if any.
            Opened before any provider is built, so a backend the server cannot
            reach fails at startup rather than at the first sign-in, and closed
            once uvicorn stops.
        show_banner: Whether to display FastMCP's startup banner.
        host: Bind address. Defaults to FastMCP's setting.
        port: Bind port. Defaults to FastMCP's setting.
        log_level: Log level for the duration of the run.
        path: See :func:`build_host_router`.
        uvicorn_config: Extra uvicorn ``Config`` kwargs, merged over the
            defaults. Note that ``lifespan="off"`` would stop every child app's
            session manager from ever starting.
        json_response: See :func:`build_host_router`.
        stateless_http: See :func:`build_host_router`.
        stateless: Alias for ``stateless_http``, matching FastMCP's CLI.
        middleware: See :func:`build_host_router`.
        host_origin_protection: See :func:`build_host_router`.
        allowed_hosts: See :func:`build_host_router`.
        allowed_origins: See :func:`build_host_router`.
        session_idle_timeout: See :func:`build_host_router`.
    """
    from fastmcp.utilities.cli import log_server_banner

    if stateless is not None and stateless_http is None:
        stateless_http = stateless

    host = host if host is not None else fastmcp.settings.host
    port = port if port is not None else fastmcp.settings.port
    mcp_path = path if path is not None else fastmcp.settings.streamable_http_path
    resolved_log_level = (
        log_level if log_level is not None else fastmcp.settings.log_level
    ).lower()

    # One store for every hostname, opened before any provider. The providers of
    # different hostnames are separate OAuth identities but one server: a second
    # store per hostname would split one deployment's state, and a backend
    # connection per hostname would multiply its clients for nothing. FastMCP's
    # default file store is shared the same way -- its directory depends only on
    # the signing key.
    if client_storage is not None:
        await client_storage.open()
    try:
        app = build_host_router(
            server,
            base_urls,
            auth_for,
            path=mcp_path,
            json_response=json_response,
            stateless_http=stateless_http,
            middleware=middleware,
            host_origin_protection=host_origin_protection,
            allowed_hosts=allowed_hosts,
            allowed_origins=allowed_origins,
            session_idle_timeout=session_idle_timeout,
        )

        if show_banner:
            log_server_banner(server=server)

        config_kwargs: dict[str, Any] = {
            "timeout_graceful_shutdown": 2,
            "lifespan": "on",
            "ws": "websockets-sansio",
        }
        config_kwargs.update(uvicorn_config or {})
        if "log_config" not in config_kwargs and "log_level" not in config_kwargs:
            config_kwargs["log_level"] = resolved_log_level

        with temporary_log_level(log_level):
            # Private on purpose, and why fastmcp is capped below 5: the public
            # per-app lifespans each enter this same manager through their
            # session manager, so they share one server lifespan only because it
            # is reference-counted -- a property no public API promises. Holding
            # it open here, as run_http_async does, keeps the server lifespan
            # running from before the first child starts until after the last
            # one stops.
            async with server._lifespan_manager():
                for base_url in base_urls:
                    logger.info(
                        "Serving MCP server at %s%s", base_url.rstrip("/"), mcp_path
                    )
                uvicorn_server = uvicorn.Server(
                    uvicorn.Config(app, host=host, port=port, **config_kwargs)
                )
                await uvicorn_server.serve()
    finally:
        if client_storage is not None:
            await client_storage.close()
