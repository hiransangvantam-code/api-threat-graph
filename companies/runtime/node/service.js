// One service of a test company, Node.js version (Express + OpenTelemetry JS).
//
// Same behaviour as companies/runtime/python/service.py (read that file's header):
// SERVICE=<name> picks the role from company.json: the gateway, the auth service, or
// a backend with the routes listed for it.
//
// Spans go to OTEL_EXPORTER_OTLP_ENDPOINT over OTLP/HTTP as JSON, with the older
// semantic-convention attribute names many Node.js services still send
// (http.method, http.target, http.status_code, net.peer.name), so the review has to
// read both naming schemes.
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const path = require('path');
const express = require('express');
const api = require('@opentelemetry/api');
const { W3CTraceContextPropagator } = require('@opentelemetry/core');
const { BasicTracerProvider, BatchSpanProcessor } = require('@opentelemetry/sdk-trace-base');
const { OTLPTraceExporter } = require('@opentelemetry/exporter-trace-otlp-http');
const { Resource } = require('@opentelemetry/resources');

const CFG = JSON.parse(fs.readFileSync(process.env.COMPANY || '/company/company.json', 'utf8'));
const NAME = process.env.SERVICE;
const GW = CFG.gateway;
const AUTH = CFG.auth_service;
const ME = NAME === GW.name ? GW : CFG.services[NAME];
const PORT = Number(process.env.PORT || ME.port);
const MESH = process.env.MESH_PROXY ? new URL(process.env.MESH_PROXY) : null;
const USER_RE = /^(c([1-9]|1[0-9]|20)|staff[1-3]|p[1-3])$/;

// ---------------------------------------------------------------- tracing
let tracer = null;
const propagator = new W3CTraceContextPropagator();
if (ME.traced !== false && process.env.OTEL_EXPORTER_OTLP_ENDPOINT) {
  const provider = new BasicTracerProvider({
    resource: new Resource({ 'service.name': NAME, 'service.namespace': CFG.id }),
  });
  const exporter = new OTLPTraceExporter({ url: process.env.OTEL_EXPORTER_OTLP_ENDPOINT.replace(/\/$/, '') + '/v1/traces' });
  provider.addSpanProcessor(new BatchSpanProcessor(exporter, { scheduledDelayMillis: 500 }));
  tracer = provider.getTracer(`${CFG.id}-runtime-node`);
}

function serverSpan(req, route) {
  if (!tracer) return { span: null, ctx: api.ROOT_CONTEXT };
  const parent = propagator.extract(api.ROOT_CONTEXT, req.headers, api.defaultTextMapGetter);
  const span = tracer.startSpan(`${req.method} ${route}`, { kind: api.SpanKind.SERVER }, parent);
  return { span, ctx: api.trace.setSpan(parent, span) };
}

function endServerSpan(s, req, route, status) {
  if (!s.span) return;
  s.span.setAttributes({
    'http.method': req.method,
    'http.route': route,
    'http.target': req.originalUrl.split('?')[0],
    'http.status_code': status,
    'http.user_agent': req.headers['user-agent'] || '',
  });
  if (status >= 500) s.span.setStatus({ code: api.SpanStatusCode.ERROR });
  s.span.end();
}

// one HTTP request; through the sidecar (absolute-form request line) when viaMesh
function send(method, url, headers, body, viaMesh) {
  return new Promise((resolve) => {
    const u = new URL(url);
    let data = null;
    if (body !== undefined && body !== null) {
      data = Buffer.isBuffer(body) ? body : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body));
    }
    const h = { ...headers };
    if (data && data.length) {
      if (!h['content-type']) h['content-type'] = 'application/json';
      h['content-length'] = data.length;
    } else {
      data = null;
    }
    const opts = viaMesh && MESH
      ? { host: MESH.hostname, port: MESH.port, method, path: url, headers: { ...h, host: u.host } }
      : { host: u.hostname, port: u.port || 80, method, path: u.pathname + u.search, headers: h };
    const req = http.request(opts, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.on('error', () => resolve({ status: 502, headers: {}, body: Buffer.from('{}') }));
    req.setTimeout(10000, () => req.destroy());
    if (data) req.write(data);
    req.end();
  });
}

async function call(ctx, method, url, peer, headers, body, viaMesh) {
  const u = new URL(url);
  const h = { ...headers };
  let span = null;
  if (tracer) {
    span = tracer.startSpan(`${method} ${peer}`, { kind: api.SpanKind.CLIENT }, ctx);
    propagator.inject(api.trace.setSpan(ctx, span), h, api.defaultTextMapSetter);
    span.setAttributes({
      'http.method': method, 'http.url': `${u.protocol}//${u.host}${u.pathname}`,
      'peer.service': peer, 'net.peer.name': u.hostname, 'net.peer.port': Number(u.port || 80),
    });
  }
  const res = await send(method, url, h, body, viaMesh);
  if (span) {
    span.setAttribute('http.status_code', res.status);
    if (res.status >= 500) span.setStatus({ code: api.SpanStatusCode.ERROR });
    span.end();
  }
  return res;
}

// ---------------------------------------------------------------- helpers shared with the other runtimes
const roleOf = (u) => (u.startsWith('staff') ? 'staff' : u.startsWith('p') ? 'partner' : 'customer');

function ownerOf(value) {
  const digits = String(value).replace(/\D/g, '');
  return digits ? `c${(Number(digits) % 20) + 1}` : 'c1';
}

function render(t, params, owner, user, n) {
  if (Array.isArray(t)) return t.length ? [0, 1].map((i) => render(t[0], params, owner, user, n * 10 + i)) : [];
  if (t && typeof t === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(t)) out[k] = render(v, params, owner, user, n);
    return out;
  }
  if (typeof t === 'string' && t.startsWith('$')) {
    const key = t.slice(1);
    if (key === 'owner') return owner;
    if (key === 'user') return user || 'anonymous';
    if (key === 'n') return n;
    const v = params[key];
    if (v === undefined) return t;
    return /^\d+$/.test(v) ? Number(v) : v;
  }
  return t;
}

const fill = (p, params) => p.replace(/{([^}]+)}/g, (_, k) => (params[k] !== undefined ? params[k] : '1'));
const cookies = (req) => Object.fromEntries((req.headers.cookie || '').split(';').map((c) => c.trim().split('=')).filter((c) => c[0]));
const bearer = (req) => { const h = req.headers.authorization || ''; return h.toLowerCase().startsWith('bearer ') ? h.slice(7) : null; };

// ---------------------------------------------------------------- the auth service's own endpoints
const SESSIONS = new Map();

function login(req, res) {
  const s = serverSpan(req, '/auth/session');
  const user = String((req.body || {}).user || '');
  let status = 401;
  if (!USER_RE.test(user)) {
    res.status(401).json({ error: 'unknown user' });
  } else {
    const token = crypto.randomBytes(16).toString('hex');
    SESSIONS.set(token, [user, roleOf(user)]);
    status = 200;
    if (CFG.credential === 'cookie') {
      res.cookie('sid', token, { httpOnly: true, sameSite: 'lax' }).json({ user, role: roleOf(user) });
    } else {
      res.json({ user, role: roleOf(user), access_token: token, token_type: 'Bearer' });
    }
  }
  endServerSpan(s, req, '/auth/session', status);
}

function introspect(req, res) {
  const s = serverSpan(req, '/auth/introspect');
  const who = SESSIONS.get(bearer(req) || '');
  const status = who ? 200 : 401;
  res.status(status).json(who ? { user: who[0], role: who[1], active: true } : { active: false });
  endServerSpan(s, req, '/auth/introspect', status);
}

// ---------------------------------------------------------------- a backend route
const COUNT = new Map();

async function serve(req, r, ctx) {
  const key = `${r.method} ${r.path}`;
  const n = (COUNT.get(key) || 0) + 1;
  COUNT.set(key, n);
  const params = { ...req.params };
  if (r.errors_every && n % r.errors_every === 0) return [500, { error: 'internal error' }];
  const user = req.headers['x-user-id'] || '';
  const role = req.headers['x-user-role'] || '';
  if (r.auth !== 'none') {
    if (!user) return [401, { error: 'authentication required' }];
    if ((r.auth === 'admin' && role !== 'staff') || (r.auth === 'partner' && role !== 'partner')) return [403, { error: 'forbidden' }];
  }
  const owner = r.owner ? ownerOf(params[r.owner]) : (user || 'c1');
  if (r.owner && r.owner_check !== false && role === 'customer' && owner !== user) return [403, { error: 'not your object' }];
  const fwd = {};
  for (const k of ['authorization', 'cookie', 'x-api-key', 'x-user-id', 'x-user-role']) if (req.headers[k]) fwd[k] = req.headers[k];
  for (const c of r.calls || []) {
    const res = await call(ctx, c.method, `http://${c.service}:${c.port}${fill(c.path, params)}`, c.service,
      c.forward_auth ? fwd : {}, c.body, true);
    if (res.status >= 500) return [502, { error: `${c.service} failed` }];
  }
  for (const x of r.external || []) await call(ctx, x.method, `http://${x.host}:${x.port}${x.path}`, x.host, {}, null, false);
  return [r.status || 200, render(r.returns || { status: 'ok' }, params, owner, user, n)];
}

function handler(r) {
  return async (req, res) => {
    const s = serverSpan(req, r.path);
    const [status, body] = await serve(req, r, s.ctx);
    res.status(status).json(body);
    endServerSpan(s, req, r.path, status);
  };
}

// ---------------------------------------------------------------- the gateway
const RATE = new Map();
const IDENT = new Map();

function credential(req) {
  return bearer(req) || req.headers['x-api-key'] || cookies(req).sid || req.query.access_token || null;
}

async function identify(ctx, token) {
  if (!IDENT.has(token)) {
    const r = await call(ctx, 'GET', `http://${AUTH.name}:${AUTH.port}/auth/introspect`, AUTH.name,
      { authorization: `Bearer ${token}` }, null, true);
    let who = null;
    if (r.status === 200) { const b = JSON.parse(r.body.toString()); who = [b.user, b.role]; }
    IDENT.set(token, who);
  }
  return IDENT.get(token);
}

async function forward(req, r, p, ctx) {
  if (r.limit_per_min) {
    const w = RATE.get(r.prefix) || { start: 0, n: 0 };
    if (Date.now() - w.start > 60000) { w.start = Date.now(); w.n = 0; }
    w.n += 1;
    RATE.set(r.prefix, w);
    if (w.n > r.limit_per_min) return { status: 429, headers: { 'content-type': 'application/json' }, body: Buffer.from('{"error":"too many requests"}') };
  }
  const token = credential(req);
  const ident = token ? await identify(ctx, token) : null;
  if (r.auth && !ident) return { status: 401, headers: { 'content-type': 'application/json' }, body: Buffer.from('{"error":"authentication required"}') };
  const headers = {};
  for (const k of ['authorization', 'cookie', 'x-api-key', 'content-type', 'user-agent', 'accept']) if (req.headers[k]) headers[k] = req.headers[k];
  if (ident) { headers['x-user-id'] = ident[0]; headers['x-user-role'] = ident[1]; }
  let backend = r.to + p.slice(r.from.length);
  if (!backend.startsWith('/')) backend = '/' + backend;
  const q = req.originalUrl.includes('?') ? req.originalUrl.slice(req.originalUrl.indexOf('?')) : '';
  const body = Buffer.isBuffer(req.body) && req.body.length ? req.body : null;
  return call(ctx, req.method, `http://${r.service}:${r.port}${backend}${q}`, r.service, headers, body, true);
}

async function gateway(req, res) {
  const p = req.path;
  if (p === '/health') return res.json({ status: 'ok' });
  const r = GW.routes.find((x) => p === x.prefix || p.startsWith(x.prefix.replace(/\/$/, '') + '/'));
  if (!r) return res.status(404).json({ error: 'no route' });
  const route = r.prefix.replace(/\/$/, '') + '/**';
  const s = serverSpan(req, route);
  const up = await forward(req, r, p, s.ctx);
  if (up.headers['set-cookie']) res.setHeader('set-cookie', up.headers['set-cookie']);
  if (up.headers['content-type']) res.setHeader('content-type', up.headers['content-type']);
  res.status(up.status).send(up.body);
  endServerSpan(s, req, route, up.status);
}

// ---------------------------------------------------------------- app
function build() {
  const app = express();
  app.disable('x-powered-by');
  app.set('etag', false);
  if (NAME === GW.name) {
    app.use(express.raw({ type: () => true, limit: '1mb' }));
    app.all('*', (req, res) => { gateway(req, res).catch(() => res.status(502).json({ error: 'gateway error' })); });
    return app;
  }
  app.use(express.json());
  app.get('/health', (req, res) => res.json({ status: 'ok', service: NAME }));
  if (ME.spec) {
    const text = fs.readFileSync(path.join('/company', ME.spec.file));
    app.get(ME.spec.path, (req, res) => res.type(ME.spec.type).send(text));
  }
  if (NAME === AUTH.name) {
    app.post('/auth/session', login);
    app.get('/auth/introspect', introspect);
  }
  const routes = [...(ME.routes || [])].sort((a, b) =>
    (a.path.split('{').length - b.path.split('{').length) || (b.path.length - a.path.length));
  for (const r of routes) {
    const expressPath = r.path.replace(/{([^}]+)}/g, ':$1');
    app[r.method.toLowerCase()](expressPath, (req, res) => { handler(r)(req, res).catch(() => res.status(500).json({ error: 'internal error' })); });
  }
  app.use((req, res) => res.status(404).json({ error: 'not found' }));
  return app;
}

if (process.argv.includes('--health')) {
  http.get(`http://localhost:${PORT}/health`, (r) => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1));
} else {
  build().listen(PORT, '0.0.0.0');
  process.on('SIGTERM', () => process.exit(0));   // PID 1 in the container: stop at once on docker stop
}
