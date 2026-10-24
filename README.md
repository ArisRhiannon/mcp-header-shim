# mcp-header-shim

**Use API-key MCP servers from OAuth-only MCP clients.** Many hosted MCP clients (remote "connectors") only speak the MCP OAuth flow, while many MCP servers just want an `X-API-Key` or `Authorization: Bearer <key>` header. mcp-header-shim is a small self-hosted OAuth 2.1 front door: the client registers and signs in with *your* passphrase, gets a bearer token, and every request to `/mcp` is forwarded to the real server with your configured headers injected. One JSON file, no database, no account, zero dependencies.

[![CI](https://github.com/ArisRhiannon/mcp-header-shim/actions/workflows/ci.yml/badge.svg)](https://github.com/ArisRhiannon/mcp-header-shim/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Node >= 18](https://img.shields.io/badge/node-%3E%3D18-green)
![Zero dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)

```
MCP client ──OAuth 2.1 + Bearer──▶ mcp-header-shim ──X-API-Key: ••••──▶ your MCP server
```

## Quick start

```bash
git clone https://github.com/ArisRhiannon/mcp-header-shim && cd mcp-header-shim
node bin/mcp-header-shim.js --example > shim.json      # edit upstream, publicUrl, headers
export UPSTREAM_API_KEY=... SHIM_PASSPHRASE='a long passphrase only you know'
node bin/mcp-header-shim.js -c shim.json
```

Docker:

```bash
docker build -t mcp-header-shim .
docker run -p 8787:8787 -v $PWD/shim.json:/config/shim.json:ro \
  -e UPSTREAM_API_KEY -e SHIM_PASSPHRASE mcp-header-shim
```

Put it behind a TLS reverse proxy (Caddy, nginx, Cloudflare Tunnel) and give your client the URL `https://<publicUrl>/mcp`. The client discovers the rest via `/.well-known/oauth-protected-resource`.

## Config

```json
{
  "upstream": "https://mcp.example.com/mcp",
  "publicUrl": "https://shim.example.org",
  "port": 8787,
  "host": "0.0.0.0",
  "headers": { "X-API-Key": "${UPSTREAM_API_KEY}" },
  "passphrase": "${SHIM_PASSPHRASE}",
  "allowedRedirectPrefixes": ["https://claude.ai/api/mcp/auth_callback", "http://localhost", "http://127.0.0.1"]
}
```

| Key | Meaning |
|---|---|
| `upstream` | URL of the real MCP endpoint (streamable HTTP; SSE responses are streamed through) |
| `headers` | Headers added to every upstream request. `${VAR}` is read from the environment so secrets stay out of the file. `Authorization` is allowed (e.g. `"Bearer ${TOKEN}"`) |
| `passphrase` | What you type on the consent page. 12+ characters; 5 wrong tries lock that IP for a minute |
| `allowedRedirectPrefixes` | Optional allow-list for client redirect URIs. **Recommended**: without it any client that knows your URL can start a flow (it still needs the passphrase) |
| `accessTokenTtl` / `refreshTokenTtl` | Seconds (default 1 h / 30 days) |
| `path` | Public MCP path (default `/mcp`) |

The callback prefix above is an example; check your client's docs for its real redirect URI.

## What it implements

- OAuth 2.0 Authorization Server Metadata (RFC 8414) and Protected Resource Metadata (RFC 9728), as used by the MCP authorization spec
- Dynamic Client Registration (RFC 7591) for public clients
- Authorization code flow with **mandatory PKCE S256**, single-use 2-minute codes, `iss` in the redirect
- Refresh tokens with rotation; tokens are random 256-bit values stored only as SHA-256 hashes
- Proxy: strips the client's `Authorization`, cookies and hop-by-hop headers, injects yours, passes `Mcp-Session-Id` and streams SSE

## Limits

- **State is in memory.** Restarting the shim logs every client out; they re-run the OAuth flow. Run a single instance.
- Single owner: one passphrase, no user accounts, no per-client scopes. Everyone you authorize gets the same upstream access.
- It does not speak TLS itself; terminate HTTPS in front of it. Never expose it over plain HTTP on the internet.
- Only HTTP(S) upstreams. For a local stdio server, wrap it with a stdio-to-HTTP bridge first.
- Not audited. It's ~300 lines you can read; please report issues via [security advisories](https://github.com/ArisRhiannon/mcp-header-shim/security/advisories/new).

## Comparison

- [mcp-remote](https://www.npmjs.com/package/mcp-remote) goes the other way (lets stdio-only clients reach remote OAuth servers).
- MCP gateways (e.g. Bifrost) and hosted connector platforms do much more but need more setup or an account. This is the smallest thing that solves the header-vs-OAuth mismatch.

## Related

[skillsnap](https://github.com/ArisRhiannon/skillsnap) (pin agent skills, hooks and MCP config)

## License

[MIT](LICENSE)
