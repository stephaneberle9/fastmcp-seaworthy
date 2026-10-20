# fastmcp-seaworthy <!-- omit in toc -->

Production building blocks for [FastMCP](https://gofastmcp.com) servers: serve
one server under several public hostnames, each a full OAuth identity, and keep
the OAuth proxy's state across restarts and rotations of the upstream client
secret.

A FastMCP server that runs fine on a laptop can still fail in production: it
answers OAuth discovery under one hostname only, and with an `OAuthProxy`-based
auth provider (`OIDCProxy`, `AWSCognitoProvider`, `GoogleProvider`,
`AzureProvider`, ...) every container restart signs every user out. This
library closes both gaps with the same settings and the same code in every
server that uses it.

> [!NOTE]
> An independent project, not affiliated with PrefectHQ, the maintainers of
> FastMCP.

- [What Is This For](#what-is-this-for)
- [Installation](#installation)
- [Usage](#usage)
  - [Serving several hostnames](#serving-several-hostnames)
  - [Surviving restarts](#surviving-restarts)
  - [Both together](#both-together)
- [Configuration](#configuration)
  - [Environment variables](#environment-variables)
  - [DynamoDB table](#dynamodb-table)
- [API Reference](#api-reference)
  - [`serve_http`](#serve_http)
  - [`build_host_router`](#build_host_router)
  - [`OAuthStateSettings`](#oauthstatesettings)
  - [`build_client_storage`](#build_client_storage)
  - [`ClientStorage`](#clientstorage)
  - [`HostRouter`](#hostrouter)
  - [Helpers](#helpers)
- [Contributing](#contributing)
- [License](#license)

## What Is This For

Typical use cases:

- Reaching one MCP server under an alias domain, for clients whose networks
  block the primary TLD.
- Running an MCP server with an `OAuthProxy`-based provider on Kubernetes,
  where the container filesystem — and with it FastMCP's default OAuth state
  store — does not survive a restart.
- Rotating the upstream IdP's client secret without invalidating every issued
  token and every client registration.
- Running several replicas of one MCP server that share their OAuth state.

## Installation

```bash
pip install fastmcp-seaworthy
# or, with uv:
uv add fastmcp-seaworthy
```

The DynamoDB store backend needs the `dynamodb` extra:

```bash
pip install 'fastmcp-seaworthy[dynamodb]'
# or, with uv:
uv add 'fastmcp-seaworthy[dynamodb]'
```

Requires Python 3.10+ and FastMCP 4.

## Usage

### Serving several hostnames

A FastMCP auth provider is built around one `base_url`, which it advertises
everywhere: in the protected-resource and authorization-server metadata, as the
`redirect_uri` sent to the IdP, and in the tokens it mints. FastMCP never
derives it from the request, so a provider can answer as one hostname only.
Adding a second host at the ingress fixes TLS and routing, but the server keeps
sending clients to the first hostname — the one the alias exists to avoid.

`serve_http` builds one app per base URL, each with its own provider, over one
shared FastMCP server, and routes requests between them on the `Host` header:

```python
import asyncio
import os

from fastmcp import FastMCP
from fastmcp.server.auth.providers.aws import AWSCognitoProvider
from fastmcp_seaworthy import serve_http, split_base_urls

# No auth= here: it is supplied per hostname below.
mcp = FastMCP(name="my-server")


def auth_for(base_url: str) -> AWSCognitoProvider:
    return AWSCognitoProvider(
        user_pool_id=os.environ["COGNITO_USER_POOL_ID"],
        aws_region=os.environ["COGNITO_AWS_REGION"],
        client_id=os.environ["COGNITO_CLIENT_ID"],
        client_secret=os.environ["COGNITO_CLIENT_SECRET"],
        base_url=base_url,
    )


asyncio.run(
    serve_http(
        mcp,
        # e.g. "https://mcp.example.io,https://mcp.example.com"
        split_base_urls(os.environ["BASE_URLS"]),
        auth_for,
        host="0.0.0.0",
        port=8080,
    )
)
```

The first base URL is **canonical**: it answers requests with no or an unknown
`Host` header, such as container health probes addressing the pod IP. Register
`{base_url}/auth/callback` as an allowed redirect URI with your IdP for every
entry. With a single base URL, the same code serves one identity.

### Surviving restarts

An `OAuthProxy` keeps state — the clients registered through DCR, the upstream
IdP's tokens, and the mapping from the tokens it issued to them — and signs its
tokens with a signing key. By default FastMCP keeps the state in an encrypted
file store under `${FASTMCP_HOME}` and derives the signing key from the upstream
client secret. A container restart then loses all state, and a secret rotation
strands it.

`OAuthStateSettings` reads a stable signing key and an external store from the
environment, `build_client_storage` builds that store, encrypted the way FastMCP
encrypts its own, and `provider_kwargs` hands both to the provider:

```python
from fastmcp_seaworthy import OAuthStateSettings, build_client_storage

settings = OAuthStateSettings.from_env()
storage = build_client_storage(settings)  # None for FastMCP's default file store

provider = AWSCognitoProvider(
    ...,
    **settings.provider_kwargs(storage),
)
```

Open the store before serving, so a missing table or missing permissions fail
the rollout rather than the first sign-in, and close it afterwards —
`serve_http` does both when given the store.

### Both together

Build the store once and share it between the hostnames: they are separate
OAuth identities of one deployment, not separate deployments.

```python
async def main() -> None:
    settings = OAuthStateSettings.from_env()
    storage = build_client_storage(settings)

    def auth_for(base_url: str) -> AWSCognitoProvider:
        return AWSCognitoProvider(
            ...,
            base_url=base_url,
            **settings.provider_kwargs(storage),
        )

    await serve_http(
        mcp,
        split_base_urls(os.environ["BASE_URLS"]),
        auth_for,
        client_storage=storage,
        host="0.0.0.0",
        port=8080,
    )


asyncio.run(main())
```

## Configuration

### Environment variables

Read by `OAuthStateSettings.from_env()`. Empty values count as unset.

| Variable | Description |
| --- | --- |
| `JWT_SIGNING_KEY` | Secret the server signs its tokens with and derives the store's encryption key from. At least 32 characters, e.g. from `secrets.token_urlsafe(32)`; a shorter one is an error. Keep it in a secret store and stable across deployments. Unset, FastMCP derives both from the upstream client secret. Required with any `STORE_BACKEND` other than `file`. |
| `STORE_BACKEND` | `file` (default) for FastMCP's own encrypted file store, or `dynamodb`. An unknown value is an error, not a fallback to `file`. |
| `STORE_DYNAMODB_TABLE` | DynamoDB table name. Required for `STORE_BACKEND=dynamodb`. |
| `STORE_DYNAMODB_REGION` | AWS region of the table. Optional; unset, the AWS SDK's usual chain decides. |
| `STORE_DYNAMODB_AUTO_CREATE` | `true` to create a missing table at startup. Default `false`, so a missing table fails the rollout and the server needs no `dynamodb:CreateTable`. |

The values written to an external store are Fernet-encrypted with a key derived
from `JWT_SIGNING_KEY` exactly as FastMCP derives its file store's key, so the
store never holds an upstream token in plaintext. An entry written under a
different key reads as missing: clients re-register and users sign in again,
instead of every request failing. So does an entry that is not encrypted at
all: everything the server writes is, so such an entry was written by someone
with write access to the store but not the key, and is logged as a warning.

Only the values are encrypted. Each entry's collection, key and expiry are
stored as they are: client IDs, token IDs and, while they are valid,
authorization codes. None of them can be redeemed without the encrypted value
(an authorization code also needs the client's PKCE verifier), but they show
who signs in when. Treat the table's backups and exports accordingly, and
scope write access to the table to the server alone.

`JWT_SIGNING_KEY` is worth setting with the default file store too: it
decouples the stored state from the upstream client secret.

### DynamoDB table

Credentials and region come from the AWS SDK's usual chain (IRSA or EKS Pod
Identity, instance profile, `AWS_*` environment variables);
`AWS_ENDPOINT_URL_DYNAMODB` points it at DynamoDB Local for testing. Create the
table with your infrastructure code:

| Property | Value |
| --- | --- |
| Partition key | `collection` (String) |
| Sort key | `key` (String) |
| Time to live | enabled on the attribute `ttl` |
| Billing mode | any; on-demand fits the access pattern |

The server needs `dynamodb:DescribeTable`, `dynamodb:DescribeTimeToLive`,
`dynamodb:GetItem`, `dynamodb:PutItem` and `dynamodb:DeleteItem` on the table.
`STORE_DYNAMODB_AUTO_CREATE=true` additionally needs `dynamodb:CreateTable` and
`dynamodb:UpdateTimeToLive`; so does a table without TTL enabled.

## API Reference

### `serve_http`

`async serve_http(server, base_urls, auth_for, /, *, client_storage=None, show_banner=True, host=None, port=None, log_level=None, path=None, uvicorn_config=None, json_response=None, stateless_http=None, stateless=None, middleware=None, host_origin_protection=None, allowed_hosts=None, allowed_origins=None, session_idle_timeout=None)`
— serves `server` under every base URL until uvicorn stops. Mirrors
`FastMCP.run_http_async`: unset keywords fall back to FastMCP's settings, so
`FASTMCP_*` environment variables keep working.

| Parameter | Type | Description |
| --- | --- | --- |
| `server` | `FastMCP` | The server backing every identity; construct it without `auth=` |
| `base_urls` | `Sequence[str]` | Public base URLs, canonical first |
| `auth_for` | `Callable[[str], AuthProvider \| None]` | Builds the provider for one base URL |
| `client_storage` | `ClientStorage \| None` | Opened before any provider is built, closed once uvicorn stops |

The remaining keywords are those of `FastMCP.run_http_async`. With
`host_origin_protection` enabled, `allowed_hosts` must list every public
hostname, since one list applies to every identity's app.

### `build_host_router`

`build_host_router(server, base_urls, auth_for, /, *, path=None, json_response=None, stateless_http=None, middleware=None, host_origin_protection=None, allowed_hosts=None, allowed_origins=None, session_idle_timeout=None)`
— builds the `HostRouter` that `serve_http` serves, for callers that run the ASGI
app themselves. Those callers hold `server._lifespan_manager()` open around it
if the server lifespan must outlive the router, as `serve_http` does.

### `OAuthStateSettings`

`OAuthStateSettings(jwt_signing_key=None, store_backend="file", store_dynamodb_table=None, store_dynamodb_region=None, store_dynamodb_auto_create=False)`
— the signing key and the store an `OAuthProxy` keeps its state in. Frozen
dataclass; construction raises `ValueError` for a signing key shorter than
`MIN_JWT_SIGNING_KEY_LENGTH` (32) or a combination the server could not keep
readable.

| Method | Description |
| --- | --- |
| `from_env(environ=None)` | Class method; reads the [environment variables](#environment-variables) from `environ`, default `os.environ` |
| `describe()` | Returns one line naming the store and signing key in effect, for the startup log; never the key itself |
| `provider_kwargs(client_storage)` | Returns the `jwt_signing_key` and `client_storage` keyword arguments for an `OAuthProxy` subclass, each only when set; not for a `RemoteAuthProvider` such as `KeycloakAuthProvider` |

### `build_client_storage`

`build_client_storage(settings)` — returns the encrypted `ClientStorage` the
settings select, or `None` for FastMCP's default file store. Imports no backend
dependency for `file`; raises `RuntimeError` when the backend's extra is
missing.

### `ClientStorage`

Returned by `build_client_storage`.

| Member | Type | Description |
| --- | --- | --- |
| `store` | `AsyncKeyValue` | The encrypted store handed to providers as `client_storage` |
| `backend` | `BaseContextManagerStore` | The unencrypted backend, kept for its lifecycle |
| `description` | `str` | Names the backend's location in startup errors |
| `await open()` | `None` | Connects; raises `ValueError` naming the backend when it cannot be used |
| `await close()` | `None` | Closes the backend |

### `HostRouter`

`HostRouter(apps, canonical_base_url)` — an ASGI app dispatching to per-hostname
child apps keyed by base URL, and running every child's lifespan under its own.
Rejects an empty mapping, two base URLs sharing a hostname, and a canonical base
URL that is not among them.

### Helpers

| Function | Description |
| --- | --- |
| `split_base_urls(raw)` | Splits a comma-separated list of base URLs, drops blank entries and checks them with `check_distinct_hosts` |
| `check_distinct_hosts(base_urls)` | Raises `ValueError` for an entry without a hostname or two entries sharing one |
| `host_of(base_url)` | Returns the lower-cased, port-less hostname of a base URL |
| `storage_encryption_key(jwt_signing_key)` | Derives the store's Fernet key from a signing key, as FastMCP does |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## License

Apache-2.0 — see [LICENSE](LICENSE).
