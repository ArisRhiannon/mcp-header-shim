'use strict';
const fs = require('fs');
const { createShim, loadConfig } = require('./server');
const VERSION = require('../package.json').version;

const HELP = `mcp-header-shim ${VERSION} - OAuth 2.1 front door for MCP servers that only take API keys or custom headers.

Usage:
  mcp-header-shim -c shim.json        start the shim
  mcp-header-shim --example           print an example config

Options:
  -c, --config <file>   JSON config (default: ./shim.json)
  -h, --help, -v, --version

OAuth-only MCP clients (e.g. remote connectors) register, sign in with your owner passphrase, and get a
bearer token. Requests to <publicUrl>/mcp are forwarded to "upstream" with your configured headers added
and the client's Authorization header removed. Secrets come from env vars: "\${MY_API_KEY}".`;

const EXAMPLE = {
  upstream: 'https://mcp.example.com/mcp',
  publicUrl: 'https://shim.example.org',
  port: 8787,
  host: '0.0.0.0',
  headers: { 'X-API-Key': '${UPSTREAM_API_KEY}' },
  passphrase: '${SHIM_PASSPHRASE}',
  allowedRedirectPrefixes: ['https://claude.ai/api/mcp/auth_callback', 'http://localhost', 'http://127.0.0.1'],
};

async function main(argv, io = { stdout: process.stdout, stderr: process.stderr }) {
  let file = 'shim.json';
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '-h' || a === '--help') { io.stdout.write(HELP + '\n'); return 0; }
    if (a === '-v' || a === '--version') { io.stdout.write(VERSION + '\n'); return 0; }
    if (a === '--example') { io.stdout.write(JSON.stringify(EXAMPLE, null, 2) + '\n'); return 0; }
    if (a === '-c' || a === '--config') file = argv[++i];
    else { io.stderr.write(`mcp-header-shim: unknown argument ${a}\n`); return 2; }
  }
  let cfg;
  try { cfg = loadConfig(fs.readFileSync(file, 'utf8')); } catch (e) { io.stderr.write(`mcp-header-shim: ${e.message}\n`); return 2; }
  const { server } = createShim(cfg, (m) => io.stderr.write(`[shim] ${new Date().toISOString()} ${m}\n`));
  await new Promise((r) => server.listen(cfg.port, cfg.host, r));
  io.stderr.write(`[shim] listening on ${cfg.host}:${server.address().port}; MCP URL for clients: ${cfg.publicUrl}${cfg.path} -> ${cfg.upstream.origin}\n`);
  if (!cfg.publicUrl.startsWith('https://') && !/localhost|127\.0\.0\.1/.test(cfg.publicUrl)) io.stderr.write('[shim] WARNING: publicUrl is not https; put a TLS reverse proxy in front.\n');
  return undefined;
}

module.exports = { main, EXAMPLE };
