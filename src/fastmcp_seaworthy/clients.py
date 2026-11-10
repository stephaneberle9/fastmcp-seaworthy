"""Limit which OAuth clients an ``OAuthProxy`` accepts.

Why this exists
---------------
A server whose auth provider is an ``OAuthProxy`` (``OIDCProxy``,
``AWSCognitoProvider``, ``GoogleProvider``, ``AzureProvider``, ...) is the
OAuth authorization server its MCP clients talk to. The upstream IdP never sees
those clients: every token reaching it names the proxy's own upstream
application. Which MCP client software may connect can therefore only be
decided at the proxy -- and FastMCP's ``OAuthProxy`` accepts every client that
presents a Client ID Metadata Document (CIMD) URL and every client that
registers through Dynamic Client Registration (DCR).

That matters wherever tool results may only reach service providers the
operator has vetted: the vendor of the MCP client is one, because the client
sends the tool results to its LLM. :class:`ClientAllowlist` names the clients
that may connect, read from one environment variable in every consumer, and
:meth:`ClientAllowlist.apply` enforces it on any ``OAuthProxy`` subclass.

CIMD makes such a list possible: a CIMD ``client_id`` is an HTTPS URL under a
domain its publisher controls, so it is attributable and can be allowed by
publisher. A DCR ``client_id`` is random and anonymous, so there is nothing to
list, and an allowlist turns DCR off.

One client is not attributable by its ``client_id`` alone: some clients send
the proxy's upstream ``client_id`` directly instead of registering, and FastMCP
accepts any redirect URI for that one -- whoever knows the ``client_id`` would
receive the authorization code. Listing it therefore needs the redirect URIs
it may use, in ``ALLOWED_UPSTREAM_CLIENT_REDIRECT_URIS``.
"""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, TypeVar
from urllib.parse import unquote, urlsplit

from fastmcp.server.auth.oauth_proxy import OAuthProxy
from fastmcp.server.auth.oauth_proxy.models import ProxyDCRClient
from fastmcp.server.auth.redirect_validation import validate_redirect_uri
from mcp.server.auth.provider import RegistrationError
from mcp.shared.auth import InvalidRedirectUriError
from pydantic import AnyUrl, Field

if TYPE_CHECKING:
    from mcp.shared.auth import OAuthClientInformationFull

logger = logging.getLogger(__name__)

ProxyT = TypeVar("ProxyT", bound=OAuthProxy)

_ALLOWLIST_ATTRIBUTE = "_fastmcp_seaworthy_client_allowlist"
"""Marks a provider :meth:`ClientAllowlist.apply` has already wrapped."""

_SEPARATORS = re.compile(r"[\s,]+")


def _check_entry(position: int, entry: str) -> None:
    """Refuse an entry that cannot mean what it looks like it means.

    The message names the entry's position and the setting, never the entry
    itself, like every other settings error in this library.
    """
    where = f"ALLOWED_CLIENT_IDS entry {position}"
    if not entry or _SEPARATORS.search(entry):
        raise ValueError(f"{where} is empty or contains a comma or whitespace")
    if "*" in entry:
        # A glob such as https://claude.ai* would also match
        # https://claude.ai.attacker.example/ -- a host anyone can register.
        raise ValueError(
            f"{where} contains '*': wildcards are not supported. To allow every "
            "client a publisher serves under a path, end an https:// URL with '/'"
        )
    scheme = entry.split(":", 1)[0].lower()
    if scheme == "http":
        raise ValueError(
            f"{where} is an http:// URL: a client ID metadata document is only "
            "ever served over https://, so it could never match"
        )
    if scheme != "https":
        return  # An opaque client_id, matched exactly.
    parts = urlsplit(entry)
    if not parts.hostname or "@" in parts.netloc:
        raise ValueError(f"{where} is an https:// URL without a plain host")
    if parts.query or parts.fragment or entry.endswith(("?", "#")):
        raise ValueError(f"{where} is an https:// URL with a query or fragment")
    if not parts.path:
        raise ValueError(
            f"{where} is an https:// URL without a path, which no client ID "
            "metadata document has. End it with '/' to allow every client under "
            "that host"
        )
    if _has_dot_segment(parts.path):
        raise ValueError(f"{where} contains a '.' or '..' path segment")


def _has_dot_segment(path: str) -> bool:
    """Whether ``path`` has a ``.`` or ``..`` segment, percent-encoded or not.

    A client_id ``https://example.com/clients/../uploads/x`` starts with the
    prefix ``https://example.com/clients/`` but names -- and is fetched as --
    a document outside it.
    """
    return any(unquote(segment) in (".", "..") for segment in path.split("/"))


def _is_prefix(entry: str) -> bool:
    return entry.lower().startswith("https://") and entry.endswith("/")


def _split(raw: str | None) -> tuple[str, ...]:
    return tuple(entry for entry in _SEPARATORS.split(raw or "") if entry)


class _UpstreamClient(ProxyDCRClient):
    """The client FastMCP synthesizes for its upstream ``client_id``, narrowed.

    FastMCP builds that client to accept any redirect URI, or those matching
    ``allowed_client_redirect_uris`` when the provider sets it. This one
    additionally requires a match in ``upstream_redirect_uris``, so the
    operator's provider-wide restriction, if any, still applies.
    """

    upstream_redirect_uris: list[str] = Field(default_factory=list, exclude=True)

    def validate_redirect_uri(self, redirect_uri: AnyUrl | None) -> AnyUrl:
        resolved = super().validate_redirect_uri(redirect_uri)
        if not validate_redirect_uri(resolved, self.upstream_redirect_uris):
            raise InvalidRedirectUriError(
                f"Redirect URI '{resolved}' is not allowed for this client by "
                "ALLOWED_UPSTREAM_CLIENT_REDIRECT_URIS"
            )
        return resolved


@dataclass(frozen=True)
class ClientAllowlist:
    """The OAuth clients an ``OAuthProxy`` accepts, or every client when empty.

    Each entry matches a ``client_id`` in one of two ways:

    - **Exactly**, for any entry: a CIMD URL such as
      ``https://claude.ai/oauth/mcp-oauth-client-metadata``, or an opaque
      ``client_id`` such as that of the upstream application's static
      client, which some clients send directly instead of registering.
    - **As a prefix**, for an ``https://`` URL ending in ``/``:
      ``https://claude.ai/`` allows every client published under that host,
      ``https://example.com/clients/`` every client under that path. Because
      the entry's host is followed by a ``/``, ``https://claude.ai/`` never
      matches ``https://claude.ai.attacker.example/...``; a ``client_id``
      with a ``.`` or ``..`` path segment never matches a prefix.

    No wildcards. Comparison is case-sensitive and on the string as sent.

    Attributes:
        client_ids: The entries. Empty means no allowlist: the provider keeps
            FastMCP's behavior, unchanged.
        upstream_client_redirect_uris: The redirect URIs a client sending the
            provider's upstream ``client_id`` may use, in the pattern syntax of
            FastMCP's ``allowed_client_redirect_uris`` (``http://localhost:*``,
            ``https://*.example.com/callback``). Required when ``client_ids``
            allows the upstream ``client_id``, and applied to that client only:
            a CIMD client stays bound to the redirect URIs its own document
            lists.

    Raises:
        ValueError: From construction, for an entry with a wildcard, an
            ``http://`` URL, or an ``https://`` URL without a path or with a
            query, fragment, credentials or dot segment; or for redirect URIs
            without any client ID.
    """

    client_ids: tuple[str, ...] = ()
    upstream_client_redirect_uris: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        # A list would make the frozen dataclass unhashable and mutable from
        # outside; normalize it here rather than reject it.
        object.__setattr__(self, "client_ids", tuple(self.client_ids))
        object.__setattr__(
            self,
            "upstream_client_redirect_uris",
            tuple(self.upstream_client_redirect_uris),
        )
        for position, entry in enumerate(self.client_ids, start=1):
            _check_entry(position, entry)
        for position, entry in enumerate(self.upstream_client_redirect_uris, 1):
            if not entry or _SEPARATORS.search(entry):
                raise ValueError(
                    f"ALLOWED_UPSTREAM_CLIENT_REDIRECT_URIS entry {position} is "
                    "empty or contains a comma or whitespace"
                )
        if self.upstream_client_redirect_uris and not self.client_ids:
            raise ValueError(
                "ALLOWED_UPSTREAM_CLIENT_REDIRECT_URIS has no effect without "
                "ALLOWED_CLIENT_IDS listing the upstream client_id"
            )

    @property
    def enabled(self) -> bool:
        """Whether there is an allowlist at all."""
        return bool(self.client_ids)

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> ClientAllowlist:
        """Read the allowlist from the environment, the same way in every consumer.

        ==========================================  ==================================
        Variable                                    Attribute
        ==========================================  ==================================
        ``ALLOWED_CLIENT_IDS``                      ``client_ids``
        ``ALLOWED_UPSTREAM_CLIENT_REDIRECT_URIS``   ``upstream_client_redirect_uris``
        ==========================================  ==================================

        Entries are separated by commas, whitespace or both, so a value can be
        one line or a YAML block scalar. Unset or empty means no allowlist.

        Args:
            environ: Where to read from. Defaults to ``os.environ``.

        Raises:
            ValueError: For an entry :class:`ClientAllowlist` refuses.
        """
        env = os.environ if environ is None else environ
        return cls(
            client_ids=_split(env.get("ALLOWED_CLIENT_IDS")),
            upstream_client_redirect_uris=_split(
                env.get("ALLOWED_UPSTREAM_CLIENT_REDIRECT_URIS")
            ),
        )

    def allows(self, client_id: str) -> bool:
        """Whether ``client_id`` may connect. Always true without an allowlist."""
        if not self.enabled:
            return True
        for entry in self.client_ids:
            if client_id == entry:
                return True
            if (
                _is_prefix(entry)
                and client_id.startswith(entry)
                and not _has_dot_segment(urlsplit(client_id).path)
            ):
                return True
        return False

    def describe(self) -> str:
        """Name the clients accepted, for the startup log.

        Client IDs are public -- every client sends its own in the clear -- so
        unlike the signing key they can be logged.
        """
        if not self.enabled:
            return "Every OAuth client accepted: ALLOWED_CLIENT_IDS is not set"
        description = (
            "OAuth clients limited to "
            f"{', '.join(self.client_ids)}; dynamic client registration disabled"
        )
        if self.upstream_client_redirect_uris:
            description += (
                "; the upstream client_id limited to redirect URIs "
                f"{', '.join(self.upstream_client_redirect_uris)}"
            )
        return description

    def apply(self, provider: ProxyT) -> ProxyT:
        """Make ``provider`` accept only the listed clients, and return it.

        Call it on every provider before its routes are built -- in the
        ``auth_for`` factory handed to :func:`~fastmcp_seaworthy.serve.serve_http`,
        for instance -- so each hostname's provider enforces the same list.
        Without an allowlist the provider is returned untouched, so a consumer
        can call this unconditionally.

        With an allowlist:

        - ``get_client`` returns ``None`` -- which the endpoints answer with an
          OAuth error -- for every ``client_id`` the list does not allow,
          before anything else happens: a CIMD URL not on the list is never
          fetched, a stored DCR client is never loaded, and the upstream
          ``client_id`` some clients send directly is accepted only when
          listed. The token endpoint looks clients up the same way, so removing
          an entry also stops that client from refreshing its tokens; access
          tokens already issued stay valid until they expire.
        - The upstream ``client_id``, when listed, may only redirect to
          ``upstream_client_redirect_uris`` -- on top of the provider's
          ``allowed_client_redirect_uris``, if set.
        - Dynamic client registration is turned off: the ``/register`` route
          and the ``registration_endpoint`` in the authorization-server
          metadata disappear, and ``register_client`` raises
          ``RegistrationError``. A DCR ``client_id`` is random, so it could
          never be on the list.

        Raises:
            TypeError: If ``provider`` is not an ``OAuthProxy``. A
                ``RemoteAuthProvider`` such as ``KeycloakAuthProvider`` leaves
                the IdP as the authorization server, so the allowlist belongs
                there.
            ValueError: If an allowlist was already applied to ``provider``,
                or if ``client_ids`` allows the provider's upstream
                ``client_id`` but ``upstream_client_redirect_uris`` is empty.
        """
        if not self.enabled:
            return provider
        if not isinstance(provider, OAuthProxy):
            raise TypeError(
                "ClientAllowlist.apply needs an OAuthProxy; with any other "
                "provider the IdP is the authorization server, so limit the "
                "clients there"
            )
        if getattr(provider, _ALLOWLIST_ATTRIBUTE, None) is not None:
            raise ValueError("A client allowlist is already applied to this provider")
        upstream_client_id = provider._upstream_client_id
        upstream_allowed = self.allows(upstream_client_id)
        if upstream_allowed and not self.upstream_client_redirect_uris:
            # FastMCP's synthesized client for this ID accepts any redirect URI,
            # so the entry would let in whoever knows the ID -- every client.
            raise ValueError(
                "ALLOWED_CLIENT_IDS allows the provider's upstream client_id, "
                "which then accepts any redirect URI: set "
                "ALLOWED_UPSTREAM_CLIENT_REDIRECT_URIS to the redirect URIs the "
                "clients sending it use"
            )
        if self.upstream_client_redirect_uris and not upstream_allowed:
            logger.warning(
                "ALLOWED_UPSTREAM_CLIENT_REDIRECT_URIS is set, but "
                "ALLOWED_CLIENT_IDS does not allow the provider's upstream "
                "client_id, so it has no effect"
            )
        upstream_redirect_uris = list(self.upstream_client_redirect_uris)

        lookup = provider.get_client

        async def get_client(client_id: str) -> OAuthClientInformationFull | None:
            if not self.allows(client_id):
                logger.warning(
                    "Refused OAuth client %r: not allowed by ALLOWED_CLIENT_IDS",
                    client_id,
                )
                return None
            client = await lookup(client_id)
            if client_id == upstream_client_id and isinstance(client, ProxyDCRClient):
                # dict(), not model_dump(): it keeps the fields excluded from
                # serialization, such as allow_unregistered_redirect_uris.
                return _UpstreamClient.model_construct(
                    **dict(client), upstream_redirect_uris=upstream_redirect_uris
                )
            return client

        async def register_client(client_info: OAuthClientInformationFull) -> None:
            logger.warning(
                "Refused dynamic client registration: ALLOWED_CLIENT_IDS is set"
            )
            raise RegistrationError(
                "invalid_client_metadata",
                "Dynamic client registration is disabled on this server; "
                "only allowlisted clients may connect",
            )

        # Instance attributes shadow the class's methods for every caller --
        # the SDK's handlers, FastMCP's client authenticator and consent page
        # alike all look them up on the provider. Set through the instance
        # dict because they are plain functions, not methods taking self.
        vars(provider).update(get_client=get_client, register_client=register_client)
        # Read when the routes are built: disabled, the SDK neither mounts
        # /register nor advertises registration_endpoint.
        if provider.client_registration_options is not None:
            provider.client_registration_options.enabled = False
        setattr(provider, _ALLOWLIST_ATTRIBUTE, self)

        if provider._cimd_manager is None and any(
            entry.lower().startswith("https://") for entry in self.client_ids
        ):
            logger.warning(
                "ALLOWED_CLIENT_IDS lists https:// client IDs, but the provider "
                "has CIMD disabled (enable_cimd=False), so they can never connect"
            )
        return provider
