'use strict';
const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const crypto = require('crypto');
const { createShim, loadConfig, b64url } = require('../src/server');
const { main } = require('../src/cli');

const PASS = 'correct horse battery';
const listen = (s) => new Promise((r) => s.listen(0, '127.0.0.1', () => r(s.address().port)));

async function setup(extra = {}) {
  const seen = [];
  const upstream = http.createServer((req, res) => {
    let body = ''; req.on('data', (c) => { body += c; });
    req.on('end', () => {
      seen.push({ method: req.method, url: req.url, headers: req.headers, body });
      if (req.url.startsWith('/mcp/sse')) { res.writeHead(200, { 'content-type': 'text/event-stream' }); res.write('event: message\ndata: {"a":1}\n\n'); return setTimeout(() => res.end('data: {"b":2}\n\n'), 20); }
      res.writeHead(200, { 'content-type': 'application/json', 'mcp-session-id': 'sess-1', 'set-cookie': 'x=1' });
      res.end(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { echo: body } }));
    });
  });
  const upPort = await listen(upstream);
  const cfg = loadConfig({ upstream: `http://127.0.0.1:${upPort}/mcp`, headers: { 'X-API-Key': '${K}' }, passphrase: '${P}', ...extra }, { K: 'secret-key', P: PASS });
  const shim = createShim(cfg);
  const port = await listen(shim.server);
  cfg.publicUrl = `http://127.0.0.1:${port}`; // tests learn the port after listen
  const base = cfg.publicUrl;
  return { base, seen, shim, cfg, close: () => { shim.server.close(); upstream.close(); } };
}

const verifier = 'v'.repeat(50);
const challenge = b64url(crypto.createHash('sha256').update(verifier).digest());
const REDIRECT = 'http://127.0.0.1:9999/cb';

async function registerClient(base) {
  const r = await fetch(base + '/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ client_name: 'Test', redirect_uris: [REDIRECT] }) });
  assert.strictEqual(r.status, 201);
  return (await r.json()).client_id;
}
async function authorize(base, client_id, pass = PASS) {
  const body = new URLSearchParams({ client_id, redirect_uri: REDIRECT, state: 'st', code_challenge: challenge, code_challenge_method: 'S256', passphrase: pass });
  return fetch(base + '/authorize', { method: 'POST', body, redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded' } });
}
async function fullToken(base) {
  const id = await registerClient(base);
  const r = await authorize(base, id);
  const loc = new URL(r.headers.get('location'));
  const t = await fetch(base + '/token', { method: 'POST', body: new URLSearchParams({ grant_type: 'authorization_code', code: loc.searchParams.get('code'), client_id: id, redirect_uri: REDIRECT, code_verifier: verifier }) });
  return { id, tok: await t.json() };
}

test('metadata endpoints', async () => {
  const s = await setup();
  try {
    const m = await (await fetch(s.base + '/.well-known/oauth-authorization-server')).json();
    assert.deepStrictEqual(m.code_challenge_methods_supported, ['S256']);
    const pr = await (await fetch(s.base + '/.well-known/oauth-protected-resource/mcp')).json();
    assert.ok(pr.resource.endsWith('/mcp'));
  } finally { s.close(); }
});

test('unauthenticated MCP request gets 401 with resource_metadata', async () => {
  const s = await setup();
  try {
    const r = await fetch(s.base + '/mcp', { method: 'POST', body: '{}' });
    assert.strictEqual(r.status, 401);
    assert.match(r.headers.get('www-authenticate'), /resource_metadata=/);
    assert.strictEqual(s.seen.length, 0);
  } finally { s.close(); }
});

test('full flow: register, consent, token, proxied call with injected header', async () => {
  const s = await setup();
  try {
    const { tok } = await fullToken(s.base);
    assert.strictEqual(tok.token_type, 'Bearer');
    const r = await fetch(s.base + '/mcp', { method: 'POST', headers: { authorization: `Bearer ${tok.access_token}`, 'content-type': 'application/json', 'mcp-session-id': 'abc' }, body: '{"jsonrpc":"2.0","id":1,"method":"ping"}' });
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.headers.get('mcp-session-id'), 'sess-1');
    assert.strictEqual(r.headers.get('set-cookie'), null);
    const up = s.seen[0];
    assert.strictEqual(up.headers['x-api-key'], 'secret-key');
    assert.strictEqual(up.headers.authorization, undefined);
    assert.strictEqual(up.headers['mcp-session-id'], 'abc');
    assert.match(up.body, /ping/);
  } finally { s.close(); }
});

test('SSE responses stream through', async () => {
  const s = await setup();
  try {
    const { tok } = await fullToken(s.base);
    const r = await fetch(s.base + '/mcp/sse', { headers: { authorization: `Bearer ${tok.access_token}` } });
    assert.strictEqual(r.headers.get('content-type'), 'text/event-stream');
    const text = await r.text();
    assert.match(text, /"a":1[\s\S]*"b":2/);
    assert.strictEqual(s.seen[0].url, '/mcp/sse');
  } finally { s.close(); }
});

test('wrong passphrase is rejected and rate limited', async () => {
  const s = await setup();
  try {
    const id = await registerClient(s.base);
    for (let i = 0; i < 5; i++) assert.strictEqual((await authorize(s.base, id, 'nope')).status, 401);
    const locked = await authorize(s.base, id);
    assert.strictEqual(locked.status, 401);
    assert.match(await locked.text(), /Too many attempts/);
  } finally { s.close(); }
});

test('PKCE is required and verified', async () => {
  const s = await setup();
  try {
    const id = await registerClient(s.base);
    const noPkce = await fetch(`${s.base}/authorize?client_id=${id}&redirect_uri=${encodeURIComponent(REDIRECT)}&response_type=code`, { redirect: 'manual' });
    assert.strictEqual(new URL(noPkce.headers.get('location')).searchParams.get('error'), 'invalid_request');
    const r = await authorize(s.base, id);
    const code = new URL(r.headers.get('location')).searchParams.get('code');
    const bad = await fetch(s.base + '/token', { method: 'POST', body: new URLSearchParams({ grant_type: 'authorization_code', code, client_id: id, redirect_uri: REDIRECT, code_verifier: 'wrong'.repeat(10) }) });
    assert.strictEqual((await bad.json()).error, 'invalid_grant');
  } finally { s.close(); }
});

test('codes are single use; refresh tokens rotate', async () => {
  const s = await setup();
  try {
    const { id, tok } = await fullToken(s.base);
    const r1 = await (await fetch(s.base + '/token', { method: 'POST', body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: tok.refresh_token, client_id: id }) })).json();
    assert.ok(r1.access_token);
    const r2 = await (await fetch(s.base + '/token', { method: 'POST', body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: tok.refresh_token, client_id: id }) })).json();
    assert.strictEqual(r2.error, 'invalid_grant');
  } finally { s.close(); }
});

test('unregistered redirect and bad redirect schemes rejected', async () => {
  const s = await setup({ allowedRedirectPrefixes: ['http://127.0.0.1'] });
  try {
    const bad = await fetch(s.base + '/register', { method: 'POST', body: JSON.stringify({ redirect_uris: ['http://evil.example/cb'] }) });
    assert.strictEqual(bad.status, 400);
    const off = await fetch(s.base + '/register', { method: 'POST', body: JSON.stringify({ redirect_uris: ['https://evil.example/cb'] }) });
    assert.strictEqual(off.status, 400);
    const id = await registerClient(s.base);
    const r = await fetch(`${s.base}/authorize?client_id=${id}&redirect_uri=${encodeURIComponent('http://127.0.0.1:1/other')}&code_challenge=x&code_challenge_method=S256`);
    assert.strictEqual(r.status, 400);
  } finally { s.close(); }
});

test('consent page escapes client name', async () => {
  const s = await setup();
  try {
    const r = await fetch(s.base + '/register', { method: 'POST', body: JSON.stringify({ client_name: '<script>x</script>', redirect_uris: [REDIRECT] }) });
    const { client_id } = await r.json();
    const html = await (await fetch(`${s.base}/authorize?client_id=${client_id}&redirect_uri=${encodeURIComponent(REDIRECT)}&code_challenge=${challenge}&code_challenge_method=S256&response_type=code`)).text();
    assert.ok(!html.includes('<script>x'));
    assert.match(html, /&lt;script&gt;/);
  } finally { s.close(); }
});

test('expired/unknown bearer rejected', async () => {
  const s = await setup();
  try { assert.strictEqual((await fetch(s.base + '/mcp', { headers: { authorization: 'Bearer nope' } })).status, 401); } finally { s.close(); }
});

test('config validation', () => {
  assert.throws(() => loadConfig({}, {}), /upstream/);
  assert.throws(() => loadConfig({ upstream: 'http://x', passphrase: 'short' }, {}), /12\+/);
  assert.throws(() => loadConfig({ upstream: 'http://x', headers: { A: '${MISSING}' }, passphrase: 'a'.repeat(12) }, {}), /MISSING/);
  assert.throws(() => loadConfig({ upstream: 'http://x', headers: { Host: 'h' }, passphrase: 'a'.repeat(12) }, {}), /cannot be injected/);
  const c = loadConfig({ upstream: 'http://x/mcp', headers: { Authorization: 'Bearer ${T}' } }, { T: 't', SHIM_PASSPHRASE: 'a'.repeat(12) });
  assert.strictEqual(c.headers.Authorization, 'Bearer t');
});

test('cli --help and --example', async () => {
  let out = '';
  const io = { stdout: { write: (s) => { out += s; } }, stderr: { write: () => {} } };
  assert.strictEqual(await main(['--help'], io), 0);
  assert.match(out, /OAuth 2.1 front door/);
  out = '';
  assert.strictEqual(await main(['--example'], io), 0);
  assert.ok(JSON.parse(out).upstream);
  assert.strictEqual(await main(['-c', '/no/such.json'], io), 2);
});
