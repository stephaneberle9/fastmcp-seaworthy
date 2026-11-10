# CLAUDE.md

`fastmcp-seaworthy` is a public, Apache-2.0-licensed open-source project.
Everything committed here — code, comments, docstrings, tests, docs, CI
workflows, commit messages and PR descriptions — is published to the world.

## No proprietary references

Never put references to proprietary material into this repository. That
covers anything belonging to the maintainers' employers, customers or other
non-public projects, including the non-public servers that consume this
library:

- product, project, team or codename names of commercial or internal
  offerings (including in examples, fixture values and test server names);
- company-specific hostnames, domains, URLs, tenant/user-pool/account IDs,
  ARNs, cluster or namespace names, table or secret names;
- internal issue trackers, repositories, merge requests, wikis, chat
  channels, meeting decisions or people who are not public contributors;
- deployment details of a specific non-public installation.

Use neutral placeholders instead:

| Kind | Use |
| --- | --- |
| Product / server name | `Acme Analytics`, `my-server` |
| Domains and URLs | `example.com` / `.io` / `.net` (RFC 2606) |
| Cloud IDs | obviously fake values such as `eu-central-1_XXXXXXXXX`, `tid` |
| Deployment context | generic wording: "a production deployment" |

Public third-party services, standards and projects (Cognito, Keycloak, Azure,
Google, DynamoDB, RFCs, the MCP SDK, FastMCP and its issue numbers,
`authsome-mcp-proxy`) are fine to name.

Before finishing any change, check the diff for names, hosts or IDs that come
from a non-public context and replace them.

## Scope

This package holds building blocks that any FastMCP server needs to run in
production, independent of what the server does. Something belongs here when
at least two independent servers need it and it touches no server's own domain.
Code that depends on FastMCP internals (`_lifespan_manager`, `OAuthProxy`'s key
derivation) is the strongest candidate, because this is the one place a FastMCP
release that changes them gets fixed and tested.

## Upstream contribution candidates

Workarounds here that belong in FastMCP itself. When a FastMCP release ships
one, remove the workaround and its entry, and keep the tests that guard the
behavior.

- **Client allowlist on `OAuthProxy`.** `ClientAllowlist.apply`
  (`clients.py`) patches `get_client` and `register_client` on the provider
  instance, because FastMCP has no parameter for it. Proposal: an
  `allowed_client_ids` parameter on `OAuthProxy` with the same matching rule
  (exact, or an `https://` prefix ending in `/`), which refuses an unlisted
  `client_id` before any CIMD fetch and turns DCR off, plus a redirect URI
  limit scoped to the client FastMCP builds for the upstream static
  `client_id`, which otherwise accepts any redirect URI
  (`test_without_the_allowlist_fastmcp_accepts_any_redirect_uri` notices when
  that changes). Not proposed yet; no FastMCP issue or PR covered it as of
  2026-11-10.
