'use strict';
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const { URL } = require('url');

const b64url = (buf) => buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const rand = () => b64url(crypto.randomBytes(32));
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const now = () => Math.floor(Date.now() / 1000);
const HOP = new Set(['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade', 'host', 'authorization', 'cookie']);

function expandEnv(v, env) {
  return String(v).replace(/\$\{([A-Z0-9_]+)\}/gi, (_, k) => {
    if (env[k] === undefined) throw new Error(`environment variable ${k} is not set`);
    return env[k];
  });
}

function loadConfig(raw, env = process.env) {
  const c = typeof raw === 'string' ? JSON.parse(raw) : raw;
  if (!c.upstream) throw new Error('config: "upstream" (URL of the MCP server) is required');
  const up = new URL(c.upstream);
  if (!/^https?:$/.test(up.protocol)) throw new Error('config: upstream must be http(s)');
  const headers = {};
  for (const [k, v] of Object.entries(c.headers || {})) {
    if (HOP.has(k.toLowerCase()) && k.toLowerCase() !== 'authorization' && k.toLowerCase() !== 'cookie') throw new Error(`config: header ${k} cannot be injected`);
    headers[k] = expandEnv(v, env);
  }
  const passphrase = c.passphrase ? expandEnv(c.passphrase, env) : env.SHIM_PASSPHRASE;
  if (!passphrase || passphrase.length < 12) throw new Error('config: set a passphrase of 12+ characters ("passphrase": "${SHIM_PASSPHRASE}" or env SHIM_PASSPHRASE)');
  return {
    upstream: up,
    headers,
    passphrase,
    publicUrl: (c.publicUrl || `http://localhost:${c.port || 8787}`).replace(/\/$/, ''),
    port: c.port ?? 8787,
    host: c.host || '127.0.0.1',
    path: c.path || '/mcp',
    accessTtl: c.accessTokenTtl || 3600,
    refreshTtl: c.refreshTokenTtl || 30 * 24 * 3600,
    allowedRedirects: c.allowedRedirectPrefixes || null,
    name: c.name || 'MCP header shim',
  };
}

function createShim(cfg, log = () => {}) {
  const clients = new Map(); // client_id -> {redirect_uris, name}
  const codes = new Map();   // sha(code) -> {client_id, redirect_uri, challenge, exp, scope}
  const access = new Map();  // sha(token) -> {client_id, exp}
  const refresh = new Map(); // sha(token) -> {client_id, exp}
  const fails = new Map();   // ip -> {n, until}
  const resource = cfg.publicUrl + cfg.path;

  const meta = {
    issuer: cfg.publicUrl,
    authorization_endpoint: cfg.publicUrl + '/authorize',
    token_endpoint: cfg.publicUrl + '/token',
    registration_endpoint: cfg.publicUrl + '/register',
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none'],
    scopes_supported: ['mcp'],
  };

  function json(res, status, body, extra = {}) {
    res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', ...extra });
    res.end(JSON.stringify(body));
  }
  const oauthErr = (res, error, desc, status = 400) => json(res, status, { error, error_description: desc });

  function readBody(req, limit = 1 << 20) {
    return new Promise((resolve, reject) => {
      const chunks = []; let n = 0;
      req.on('data', (c) => { n += c.length; if (n > limit) { reject(new Error('body too large')); req.destroy(); } else chunks.push(c); });
      req.on('end', () => resolve(Buffer.concat(chunks)));
      req.on('error', reject);
    });
  }
  function form(buf, type = '') {
    if (type.includes('application/json')) { try { return JSON.parse(buf.toString() || '{}'); } catch { return {}; } }
    return Object.fromEntries(new URLSearchParams(buf.toString()));
  }

  function redirectOk(uri) {
    let u; try { u = new URL(uri); } catch { return false; }
    if (u.hash) return false;
    const loopback = u.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
    if (u.protocol !== 'https:' && !loopback && !/^[a-z][a-z0-9+.-]*:$/.test(u.protocol)) return false;
    if (u.protocol === 'http:' && !loopback) return false;
    if (cfg.allowedRedirects && !cfg.allowedRedirects.some((p) => uri.startsWith(p))) return false;
    return true;
  }

  function register(req, res, body) {
    const uris = body.redirect_uris;
    if (!Array.isArray(uris) || !uris.length || !uris.every((u) => typeof u === 'string' && redirectOk(u))) return oauthErr(res, 'invalid_redirect_uri', 'redirect_uris must be https, loopback http, or a private-use scheme' + (cfg.allowedRedirects ? ' and match allowedRedirectPrefixes' : ''));
    if (clients.size > 1000) return oauthErr(res, 'temporarily_unavailable', 'too many clients', 503);
    const id = rand();
    clients.set(id, { redirect_uris: uris, name: String(body.client_name || 'client').slice(0, 100) });
    log(`registered client "${clients.get(id).name}"`);
    json(res, 201, { client_id: id, client_id_issued_at: now(), redirect_uris: uris, token_endpoint_auth_method: 'none', grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'] });
  }

  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  function page(res, p, error) {
    const c = clients.get(p.client_id);
    const hidden = ['client_id', 'redirect_uri', 'state', 'code_challenge', 'code_challenge_method', 'scope', 'resource'].map((k) => `<input type="hidden" name="${k}" value="${esc(p[k] || '')}">`).join('');
    res.writeHead(error ? 401 : 200, { 'content-type': 'text/html; charset=utf-8', 'x-frame-options': 'DENY', 'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'", 'cache-control': 'no-store' });
    res.end(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${esc(cfg.name)}</title>
<style>body{font:16px system-ui;max-width:28rem;margin:4rem auto;padding:0 1rem}input[type=password]{width:100%;padding:.5rem}button{margin-top:1rem;padding:.5rem 1rem}.e{color:#b00}</style>
<h1>${esc(cfg.name)}</h1><p><b>${esc(c.name)}</b> wants access to <code>${esc(cfg.upstream.host)}</code> through this shim.</p>
<p>Redirects to <code>${esc(p.redirect_uri)}</code></p>${error ? `<p class="e">${esc(error)}</p>` : ''}
<form method="post" action="/authorize">${hidden}<label>Owner passphrase<input type="password" name="passphrase" autofocus required></label><button>Allow</button></form>`);
  }

  function checkAuthParams(p) {
    const c = clients.get(p.client_id);
    if (!c) return 'unknown client_id';
    if (!c.redirect_uris.includes(p.redirect_uri)) return 'redirect_uri not registered for this client';
    return null;
  }

  async function authorize(req, res, url) {
    const ip = req.socket.remoteAddress;
    let p;
    if (req.method === 'GET') p = Object.fromEntries(url.searchParams);
    else p = form(await readBody(req, 16384), req.headers['content-type']);
    const bad = checkAuthParams(p);
    if (bad) { res.writeHead(400, { 'content-type': 'text/plain' }); return res.end(`invalid_request: ${bad}`); }
    const back = (params) => { const u = new URL(p.redirect_uri); for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v); if (p.state) u.searchParams.set('state', p.state); res.writeHead(302, { location: u.toString() }); res.end(); };
    if ((p.response_type && p.response_type !== 'code') && req.method === 'GET') return back({ error: 'unsupported_response_type' });
    if (!p.code_challenge || (p.code_challenge_method || 'plain') !== 'S256') return back({ error: 'invalid_request', error_description: 'PKCE with S256 is required' });
    if (p.resource && p.resource.replace(/\/$/, '') !== resource) return back({ error: 'invalid_target', error_description: 'unknown resource' });
    if (req.method === 'GET') return page(res, p);
    const f = fails.get(ip);
    if (f && f.until > Date.now()) return page(res, p, 'Too many attempts. Wait a minute.');
    const a = Buffer.from(sha(String(p.passphrase || ''))), b = Buffer.from(sha(cfg.passphrase));
    if (!crypto.timingSafeEqual(a, b)) {
      const n = (f ? f.n : 0) + 1; fails.set(ip, { n, until: n >= 5 ? Date.now() + 60000 : 0 });
      log(`wrong passphrase from ${ip}`);
      return page(res, p, 'Wrong passphrase.');
    }
    fails.delete(ip);
    const code = rand();
    codes.set(sha(code), { client_id: p.client_id, redirect_uri: p.redirect_uri, challenge: p.code_challenge, exp: now() + 120 });
    log(`authorized client "${clients.get(p.client_id).name}"`);
    back({ code, iss: cfg.publicUrl });
  }

  function issue(res, client_id) {
    const at = rand(), rt = rand();
    access.set(sha(at), { client_id, exp: now() + cfg.accessTtl });
    refresh.set(sha(rt), { client_id, exp: now() + cfg.refreshTtl });
    json(res, 200, { access_token: at, token_type: 'Bearer', expires_in: cfg.accessTtl, refresh_token: rt, scope: 'mcp' });
  }

  async function token(req, res) {
    const p = form(await readBody(req, 16384), req.headers['content-type']);
    if (p.grant_type === 'authorization_code') {
      const k = sha(String(p.code || '')); const c = codes.get(k); codes.delete(k);
      if (!c || c.exp < now()) return oauthErr(res, 'invalid_grant', 'code invalid or expired');
      if (c.client_id !== p.client_id || c.redirect_uri !== p.redirect_uri) return oauthErr(res, 'invalid_grant', 'client_id/redirect_uri mismatch');
      if (!p.code_verifier || b64url(crypto.createHash('sha256').update(p.code_verifier).digest()) !== c.challenge) return oauthErr(res, 'invalid_grant', 'PKCE verification failed');
      return issue(res, c.client_id);
    }
    if (p.grant_type === 'refresh_token') {
      const k = sha(String(p.refresh_token || '')); const r = refresh.get(k); refresh.delete(k); // rotation
      if (!r || r.exp < now() || r.client_id !== p.client_id) return oauthErr(res, 'invalid_grant', 'refresh token invalid');
      return issue(res, r.client_id);
    }
    return oauthErr(res, 'unsupported_grant_type', 'use authorization_code or refresh_token');
  }

  function bearer(req) {
    const m = /^Bearer\s+(.+)$/i.exec(req.headers.authorization || '');
    if (!m) return null;
    const t = access.get(sha(m[1].trim()));
    return t && t.exp >= now() ? t : null;
  }

  function proxy(req, res, url) {
    const target = new URL(cfg.upstream.toString());
    const sub = url.pathname.slice(cfg.path.length);
    if (sub) target.pathname = target.pathname.replace(/\/$/, '') + sub;
    for (const [k, v] of url.searchParams) target.searchParams.append(k, v);
    const headers = {};
    for (const [k, v] of Object.entries(req.headers)) if (!HOP.has(k)) headers[k] = v;
    Object.assign(headers, cfg.headers);
    headers.host = target.host;
    const mod = target.protocol === 'https:' ? https : http;
    const up = mod.request(target, { method: req.method, headers }, (ur) => {
      const h = {};
      for (const [k, v] of Object.entries(ur.headers)) if (!HOP.has(k) && k !== 'set-cookie' && k !== 'www-authenticate') h[k] = v;
      res.writeHead(ur.statusCode, h);
      ur.pipe(res);
    });
    up.on('error', (e) => { log(`upstream error: ${e.message}`); if (!res.headersSent) json(res, 502, { error: 'upstream_unreachable' }); else res.destroy(); });
    req.pipe(up);
    res.on('close', () => up.destroy());
  }

  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, cfg.publicUrl);
      const p = url.pathname;
      if (p === '/.well-known/oauth-authorization-server' || p === '/.well-known/openid-configuration') return json(res, 200, meta);
      if (p.startsWith('/.well-known/oauth-protected-resource')) return json(res, 200, { resource, authorization_servers: [cfg.publicUrl], bearer_methods_supported: ['header'], scopes_supported: ['mcp'] });
      if (p === '/register' && req.method === 'POST') return register(req, res, form(await readBody(req, 16384), 'application/json'));
      if (p === '/authorize' && (req.method === 'GET' || req.method === 'POST')) return await authorize(req, res, url);
      if (p === '/token' && req.method === 'POST') return await token(req, res);
      if (p === '/healthz') return json(res, 200, { ok: true });
      if (p === cfg.path || p.startsWith(cfg.path + '/')) {
        if (!bearer(req)) return json(res, 401, { error: 'invalid_token' }, { 'www-authenticate': `Bearer resource_metadata="${cfg.publicUrl}/.well-known/oauth-protected-resource"` });
        return proxy(req, res, url);
      }
      json(res, 404, { error: 'not_found' });
    } catch (e) {
      log(`error: ${e.message}`);
      if (!res.headersSent) json(res, 500, { error: 'server_error' });
    }
  });
  return { server, stores: { clients, codes, access, refresh }, meta };
}

module.exports = { createShim, loadConfig, expandEnv, b64url };
