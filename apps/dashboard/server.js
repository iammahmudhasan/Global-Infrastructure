// NexusEdge Dashboard Authenticated Backend-For-Frontend (BFF)
// Enforces zero-credential browser boundary, real server-side credential verification,
// strict upstream credential isolation, and RBAC / multi-tenant scoping.

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = parseInt(process.env.PORT || '3000', 10);
const CONTROL_PLANE_URL = process.env.CONTROL_PLANE_URL || 'http://127.0.0.1:9091';
const CONTROL_PLANE_TOKEN = process.env.CONTROL_PLANE_SERVICE_TOKEN || process.env.CONTROL_PLANE_TOKEN || process.env.NEXUSEDGE_CP_AUTH_TOKEN || '';
const EDGE_GATEWAY_URL = process.env.EDGE_GATEWAY_URL || 'http://127.0.0.1:8080';
const EDGE_GATEWAY_AI_KEY = process.env.EDGE_GATEWAY_AI_KEY || process.env.NEXUSEDGE_AI_API_KEY || '';
const OPERATOR_TOKEN = process.env.NEXUSEDGE_OPERATOR_TOKEN || '';
const DEFAULT_PROJECT_ID = process.env.NEXUSEDGE_PROJECT_ID || 'proj-core';
const PUBLIC_DIR = path.join(__dirname, 'public');

// Resolve project-scoped AI key from NEXUSEDGE_PROJECT_AI_KEYS
function resolveProjectAIKey(projectId) {
  const raw = process.env.NEXUSEDGE_PROJECT_AI_KEYS || '';
  if (raw) {
    const delimiters = raw.includes(';') ? ';' : ',';
    for (const item of raw.split(delimiters)) {
      const trimmed = item.trim();
      if (!trimmed) continue;
      const sep = trimmed.includes('=') ? '=' : ':';
      const [proj, key] = trimmed.split(sep);
      if (proj && key && proj.trim() === projectId) {
        return key.trim();
      }
    }
  }
  if (EDGE_GATEWAY_AI_KEY) {
    const isProd = process.env.NODE_ENV === 'production' || process.env.NEXUSEDGE_ENV === 'production';
    if (!isProd || projectId === DEFAULT_PROJECT_ID) {
      return EDGE_GATEWAY_AI_KEY;
    }
  }
  return null;
}

// Maximum allowed payload size for login requests (16 KB)
const MAX_LOGIN_BODY_BYTES = 16384;
// Maximum allowed failed login attempts per minute per IP
const MAX_LOGIN_ATTEMPTS_PER_MIN = 10;
const RATE_LIMIT_WINDOW_MS = 60 * 1000;

// Valid and allowed Dashboard user roles
const ALLOWED_ROLES = new Set(['PLATFORM_OPERATOR', 'TENANT_ADMIN', 'DEVELOPER', 'VIEWER']);
// Roles permitted to perform state-mutating operations on domains (POST, PUT, DELETE)
const DOMAIN_MUTATION_ROLES = new Set(['PLATFORM_OPERATOR', 'TENANT_ADMIN']);

// Maximum bounded size for login rate limit cache
const MAX_RATE_LIMIT_ENTRIES = 10000;

// In-Memory Active Session Store
const sessions = new Map();

// In-Memory Cryptographic API Key Vault: id -> { id, projectId, name, prefix, hashedSecret, role, scopes, createdAt, lastUsedAt, status }
const apiKeys = new Map();

function hashSecret(secret) {
  return crypto.createHash('sha256').update(secret).digest('hex');
}

function generateAPIKey(projectId, name, role = 'DEVELOPER', scopes = ['inference', 'domains:read']) {
  const randomHex = crypto.randomBytes(32).toString('hex');
  const secretKey = `nke_live_${randomHex}`;
  const prefix = `nke_live_${randomHex.substring(0, 8)}...`;
  const hashedSecret = hashSecret(secretKey);
  const id = `key-${crypto.randomBytes(6).toString('hex')}`;

  const record = {
    id,
    projectId,
    name: name || 'Default API Key',
    prefix,
    hashedSecret,
    role: ALLOWED_ROLES.has(role) ? role : 'DEVELOPER',
    scopes: Array.isArray(scopes) ? scopes : ['inference', 'domains:read'],
    createdAt: new Date().toISOString(),
    lastUsedAt: null,
    status: 'ACTIVE'
  };

  apiKeys.set(id, record);
  return { record, secretKey };
}

function validateAPIKey(token) {
  if (!token || typeof token !== 'string') return null;
  if (!token.startsWith('nke_live_') && !token.startsWith('nke_test_')) return null;

  const tokenHash = hashSecret(token);
  for (const record of apiKeys.values()) {
    if (record.status === 'ACTIVE' && safeCompare(record.hashedSecret, tokenHash)) {
      record.lastUsedAt = new Date().toISOString();
      return {
        id: record.id,
        user: `apikey:${record.name}`,
        role: record.role,
        projectId: record.projectId,
        scopes: record.scopes,
        isAPIKey: true,
        expiresAt: Date.now() + 365 * 24 * 60 * 60 * 1000
      };
    }
  }
  return null;
}

// In-Memory Token-Bucket Rate Limiter per API Key
const apiKeyBuckets = new Map();
const RATE_LIMIT_TIERS = {
  DEVELOPER: { capacity: 60, refillPerMs: 60 / 60000 },
  TENANT_ADMIN: { capacity: 300, refillPerMs: 300 / 60000 },
  PLATFORM_OPERATOR: { capacity: 1000, refillPerMs: 1000 / 60000 },
  VIEWER: { capacity: 30, refillPerMs: 30 / 60000 }
};

function checkAndConsumeAPIKeyRateLimit(keyId, role) {
  const now = Date.now();
  const tier = RATE_LIMIT_TIERS[role] || RATE_LIMIT_TIERS.DEVELOPER;
  let bucket = apiKeyBuckets.get(keyId);

  if (!bucket) {
    bucket = {
      tokens: tier.capacity - 1,
      lastRefill: now,
      capacity: tier.capacity,
      refillPerMs: tier.refillPerMs
    };
    apiKeyBuckets.set(keyId, bucket);
    return {
      allowed: true,
      remaining: tier.capacity - 1,
      capacity: tier.capacity,
      resetAt: Math.ceil(now / 1000) + 60
    };
  }

  const elapsedMs = Math.max(0, now - bucket.lastRefill);
  const refillTokens = elapsedMs * bucket.refillPerMs;
  bucket.tokens = Math.min(bucket.capacity, bucket.tokens + refillTokens);
  bucket.lastRefill = now;

  if (bucket.tokens < 1.0) {
    return {
      allowed: false,
      remaining: 0,
      capacity: bucket.capacity,
      resetAt: Math.ceil(now / 1000) + 1
    };
  }

  bucket.tokens -= 1.0;
  return {
    allowed: true,
    remaining: Math.floor(bucket.tokens),
    capacity: bucket.capacity,
    resetAt: Math.ceil(now / 1000) + 60
  };
}

// In-Memory Sliding-Window Real-Time Telemetry Ring Buffer
const MAX_TELEMETRY_RECORDS = 10000;
const telemetryBuffer = [];
let telemetryIndex = 0;

function recordTelemetry(entry) {
  if (telemetryBuffer.length < MAX_TELEMETRY_RECORDS) {
    telemetryBuffer.push(entry);
  } else {
    telemetryBuffer[telemetryIndex % MAX_TELEMETRY_RECORDS] = entry;
    telemetryIndex++;
  }
}

function getTelemetrySummary(targetProject = 'ALL') {
  const now = Date.now();
  const windowStart = now - (24 * 60 * 60 * 1000);

  const filtered = [];
  for (let i = 0; i < telemetryBuffer.length; i++) {
    const item = telemetryBuffer[i];
    if (item && item.timestamp >= windowStart) {
      if (targetProject === 'ALL' || item.projectId === targetProject) {
        filtered.push(item);
      }
    }
  }

  if (filtered.length === 0) {
    return {
      project_id: targetProject,
      total_requests: 0,
      p50_latency_ms: 0,
      p95_latency_ms: 0,
      p99_latency_ms: 0,
      cache_hit_ratio: 1.0,
      threat_blocks: 0,
      success_rate: 1.0,
      status_distribution: { '2xx': 0, '4xx': 0, '5xx': 0 },
      pop_distribution: { dhaka: 0, singapore: 0, frankfurt: 0, virginia: 0 }
    };
  }

  let c2 = 0;
  let c4 = 0;
  let c5 = 0;
  let threatBlocks = 0;
  let cacheHits = 0;
  const durations = [];
  const popDistribution = { dhaka: 0, singapore: 0, frankfurt: 0, virginia: 0 };

  for (const r of filtered) {
    if (r.statusCode >= 200 && r.statusCode < 300) c2++;
    else if (r.statusCode >= 400 && r.statusCode < 500) c4++;
    else if (r.statusCode >= 500) c5++;

    if (r.statusCode === 403 || r.statusCode === 429) {
      threatBlocks++;
    }
    if (r.cacheHit) {
      cacheHits++;
    }
    if (r.pop && Object.prototype.hasOwnProperty.call(popDistribution, r.pop)) {
      popDistribution[r.pop]++;
    }
    durations.push(r.durationMs || 0);
  }

  durations.sort((a, b) => a - b);
  const total = filtered.length;
  const p50 = durations[Math.floor(0.50 * (total - 1))] || 0;
  const p95 = durations[Math.floor(0.95 * (total - 1))] || 0;
  const p99 = durations[Math.min(total - 1, Math.ceil(0.99 * (total - 1)))] || 0;

  return {
    project_id: targetProject,
    total_requests: total,
    p50_latency_ms: p50,
    p95_latency_ms: p95,
    p99_latency_ms: p99,
    cache_hit_ratio: total > 0 ? Number((cacheHits / total).toFixed(3)) : 1.0,
    threat_blocks: threatBlocks,
    success_rate: total > 0 ? Number((c2 / total).toFixed(3)) : 1.0,
    status_distribution: { '2xx': c2, '4xx': c4, '5xx': c5 },
    pop_distribution: popDistribution
  };
}

// In-Memory Login Rate Limiter Store: ip -> { count, windowStart }
const loginRateLimits = new Map();

// Timing-safe string comparison to prevent timing side-channel attacks
function safeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

// Helper to generate cryptographically secure session ID
function generateSessionId() {
  return crypto.randomBytes(32).toString('hex');
}

// Clean up expired rate limiting entries
function pruneExpiredRateLimits() {
  const now = Date.now();
  for (const [key, entry] of loginRateLimits.entries()) {
    if ((now - entry.windowStart) > RATE_LIMIT_WINDOW_MS) {
      loginRateLimits.delete(key);
    }
  }
}

// Client IP extractor strictly protecting against X-Forwarded-For spoofing
function getClientIp(req) {
  let socketIp = (req.socket && req.socket.remoteAddress) ? req.socket.remoteAddress : 'unknown';
  if (socketIp.startsWith('::ffff:')) {
    socketIp = socketIp.substring(7);
  }
  const trustedProxies = (process.env.TRUSTED_PROXY_IPS || '')
    .split(',')
    .map(ip => ip.trim())
    .filter(Boolean);

  // Only inspect X-Forwarded-For if socket IP matches an explicitly configured trusted proxy
  if (trustedProxies.length > 0 && trustedProxies.includes(socketIp)) {
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded && typeof forwarded === 'string') {
      const parts = forwarded.split(',').map(s => s.trim()).filter(Boolean);
      if (parts.length > 0) {
        let clientIp = parts[parts.length - 1];
        if (clientIp.startsWith('::ffff:')) {
          clientIp = clientIp.substring(7);
        }
        return clientIp;
      }
    }
  }

  // Direct socket peer IP (immune to client-forged headers)
  return socketIp;
}

// Check and record failed login attempt for rate limiting
function checkLoginRateLimit(ip) {
  const now = Date.now();
  const entry = loginRateLimits.get(ip);
  if (!entry) {
    return { allowed: true, remaining: MAX_LOGIN_ATTEMPTS_PER_MIN };
  }
  if ((now - entry.windowStart) > RATE_LIMIT_WINDOW_MS) {
    loginRateLimits.delete(ip);
    return { allowed: true, remaining: MAX_LOGIN_ATTEMPTS_PER_MIN };
  }
  if (entry.count >= MAX_LOGIN_ATTEMPTS_PER_MIN) {
    return { allowed: false, remaining: 0 };
  }
  return { allowed: true, remaining: MAX_LOGIN_ATTEMPTS_PER_MIN - entry.count };
}

function recordFailedLogin(ip) {
  const now = Date.now();
  if (loginRateLimits.size >= MAX_RATE_LIMIT_ENTRIES) {
    pruneExpiredRateLimits();
    if (loginRateLimits.size >= MAX_RATE_LIMIT_ENTRIES) {
      const oldestKey = loginRateLimits.keys().next().value;
      if (oldestKey) loginRateLimits.delete(oldestKey);
    }
  }
  const entry = loginRateLimits.get(ip);
  if (!entry || (now - entry.windowStart) > RATE_LIMIT_WINDOW_MS) {
    loginRateLimits.set(ip, { count: 1, windowStart: now });
  } else {
    entry.count += 1;
  }
}

function recordSuccessfulLogin(ip) {
  loginRateLimits.delete(ip);
}

// Server-Side Credential Verification
// Returns authenticated identity { user, role, projectId } or null if invalid
function verifyCredentials(token) {
  if (!token || typeof token !== 'string') return null;

  // 1. Check primary platform operator token
  if (OPERATOR_TOKEN && safeCompare(token, OPERATOR_TOKEN)) {
    return {
      user: 'operator@nexusedge.io',
      role: 'PLATFORM_OPERATOR',
      projectId: DEFAULT_PROJECT_ID
    };
  }

  // 2. Check structured user directory: NEXUSEDGE_DASHBOARD_USERS
  // Format: token:user:role:projectId;token2:user2:role2:projectId2
  const userRegistry = process.env.NEXUSEDGE_DASHBOARD_USERS;
  if (userRegistry) {
    for (const entry of userRegistry.split(';')) {
      const parts = entry.trim().split(':');
      if (parts.length >= 4) {
        const [regToken, regUser, rawRole, regProj] = parts;
        if (safeCompare(token, regToken)) {
          const validatedRole = ALLOWED_ROLES.has(rawRole) ? rawRole : 'UNKNOWN';
          return {
            user: regUser,
            role: validatedRole,
            projectId: regProj
          };
        }
      }
    }
  }

  // 3. In non-production development mode, allow explicit dev fixtures ONLY
  const isProd = process.env.NODE_ENV === 'production' || process.env.NEXUSEDGE_ENV === 'production';
  if (!isProd) {
    if (safeCompare(token, 'dev-operator-key')) {
      return {
        user: 'dev-operator@nexusedge.local',
        role: 'PLATFORM_OPERATOR',
        projectId: DEFAULT_PROJECT_ID
      };
    }
    if (safeCompare(token, 'dev-viewer-key')) {
      return {
        user: 'dev-viewer@nexusedge.local',
        role: 'VIEWER',
        projectId: 'proj-viewer'
      };
    }
  }

  return null;
}

// Parse cookies from request header safely without throwing on malformed percent encoding
function parseCookies(req) {
  const list = {};
  const cookieHeader = req.headers && req.headers.cookie;
  if (!cookieHeader || typeof cookieHeader !== 'string') return list;

  cookieHeader.split(';').forEach(cookie => {
    const parts = cookie.split('=');
    if (parts.length < 2) return;
    const key = parts.shift().trim();
    const rawVal = parts.join('=').trim();
    try {
      list[key] = decodeURIComponent(rawVal);
    } catch {
      // Fallback safely to raw string to avoid URIError crashing the Node.js process
      list[key] = rawVal;
    }
  });
  return list;
}

// Authenticate session strictly via active server session or cryptographic API key
function authenticateSession(req) {
  let cookies;
  try {
    cookies = parseCookies(req);
  } catch {
    return null;
  }
  let sessionId = cookies['nexusedge_session'];

  const authHeader = req.headers && req.headers['authorization'];
  if (!sessionId && authHeader && typeof authHeader === 'string' && authHeader.startsWith('Bearer ')) {
    sessionId = authHeader.substring(7).trim();
  }

  // Check if token is an API key (nke_live_... or nke_test_...)
  if (sessionId && (sessionId.startsWith('nke_live_') || sessionId.startsWith('nke_test_'))) {
    return validateAPIKey(sessionId);
  }

  // Also check X-API-Key header
  const apiKeyHeader = req.headers && req.headers['x-api-key'];
  if (apiKeyHeader && typeof apiKeyHeader === 'string') {
    const keySession = validateAPIKey(apiKeyHeader.trim());
    if (keySession) return keySession;
  }

  // Session IDs must be 64-character hexadecimal strings
  if (sessionId && typeof sessionId === 'string' && /^[0-9a-f]{64}$/i.test(sessionId) && sessions.has(sessionId)) {
    const session = sessions.get(sessionId);
    if (session.expiresAt > Date.now()) {
      return session;
    }
    sessions.delete(sessionId);
  }

  return null;
}

// Safely parse JSON body up to maxBytes with strict error handling and resource bounds
function parseJSONBody(req, res, maxBytes, callback) {
  let body = '';
  let bodyLength = 0;
  let destroyed = false;

  req.on('data', chunk => {
    if (destroyed) return;
    bodyLength += chunk.length;
    if (bodyLength > maxBytes) {
      destroyed = true;
      sendJSON(res, 413, { error: 'Payload too large: maximum body size exceeded' });
      req.destroy();
      if (req.socket && !req.socket.destroyed) {
        req.socket.destroy();
      }
      return;
    }
    body += chunk;
  });

  req.on('end', () => {
    if (destroyed) return;
    try {
      const payload = JSON.parse(body || '{}');
      callback(null, payload);
    } catch {
      callback(new Error('Invalid JSON payload'), null);
    }
  });

  req.on('error', err => {
    if (!destroyed) {
      callback(err, null);
    }
  });
}

// Detect whether connection is TLS-secured
function isConnectionSecure(req) {
  return process.env.NODE_ENV === 'production' ||
         req.headers['x-forwarded-proto'] === 'https' ||
         Boolean(req.socket && req.socket.encrypted);
}

// Send standard JSON response
function sendJSON(res, statusCode, data, headers = {}) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
    ...headers
  });
  res.end(JSON.stringify(data));
}

// Upstream Proxy Handler 1: Control Plane (Go :9091)
// Strictly attaches Control Plane token; NEVER sends AI Gateway keys
function proxyToControlPlane(upstreamPath, req, res, session = null, extraHeaders = {}) {
  const targetUrl = new URL(upstreamPath, CONTROL_PLANE_URL);
  const forwardHeaders = {
    'accept': 'application/json',
    'content-type': req.headers['content-type'] || 'application/json',
    'connection': 'close',
    ...extraHeaders
  };

  if (CONTROL_PLANE_TOKEN) {
    forwardHeaders['X-API-Key'] = CONTROL_PLANE_TOKEN;
    forwardHeaders['Authorization'] = `Bearer ${CONTROL_PLANE_TOKEN}`;
  }

  if (session) {
    if (session.user) forwardHeaders['X-Authenticated-Actor'] = session.user;
    if (session.role) forwardHeaders['X-Authenticated-Role'] = session.role;
    if (session.projectId) forwardHeaders['X-Authenticated-Project-Id'] = session.projectId;
  }

  const options = {
    hostname: targetUrl.hostname,
    port: targetUrl.port,
    path: targetUrl.pathname + targetUrl.search,
    method: req.method,
    headers: forwardHeaders,
    agent: false,
    timeout: 5000
  };

  const proxyReq = http.request(options, (upstreamRes) => {
    res.writeHead(upstreamRes.statusCode, {
      'Content-Type': upstreamRes.headers['content-type'] || 'application/json',
      'Cache-Control': 'no-store'
    });
    upstreamRes.pipe(res);
  });

  proxyReq.on('timeout', () => {
    proxyReq.destroy();
    sendJSON(res, 504, { code: 504, error: 'Control plane upstream gateway timeout' });
  });

  proxyReq.on('error', (err) => {
    sendJSON(res, 502, { code: 502, error: 'Control plane service unavailable: ' + err.message });
  });

  req.pipe(proxyReq);
}

  // Upstream Proxy Handler 2: Edge Gateway (Rust :8080)
// Strictly attaches project-scoped Edge Gateway AI credentials; NEVER leaks Control Plane token
function proxyToEdgeGateway(upstreamPath, req, res, session, extraHeaders = {}) {
  const targetUrl = new URL(upstreamPath, EDGE_GATEWAY_URL);
  const forwardHeaders = {
    'accept': 'application/json',
    'content-type': req.headers['content-type'] || 'application/json',
    'connection': 'close',
    'X-NexusEdge-Project-Id': session.projectId,
    'X-NexusEdge-Tenant-Id': session.projectId,
    ...extraHeaders
  };

  // Attach project-scoped Edge Gateway AI key
  const projectAIKey = resolveProjectAIKey(session.projectId);
  if (projectAIKey) {
    forwardHeaders['Authorization'] = `Bearer ${projectAIKey}`;
  } else {
    const isProd = process.env.NODE_ENV === 'production' || process.env.NEXUSEDGE_ENV === 'production';
    if (isProd) {
      return sendJSON(res, 403, {
        code: 403,
        error: `Forbidden: No AI Gateway credential configured for project "${session.projectId}". Wildcard or unauthenticated inference is blocked in production.`
      });
    }
  }

  // Double check: NEVER leak Control Plane token to Edge Gateway
  if (CONTROL_PLANE_TOKEN && forwardHeaders['Authorization'] === `Bearer ${CONTROL_PLANE_TOKEN}`) {
    return sendJSON(res, 500, {
      code: 500,
      error: 'Security boundary invariant violation: Control Plane service token cannot be sent to Edge Gateway'
    });
  }

  const options = {
    hostname: targetUrl.hostname,
    port: targetUrl.port,
    path: targetUrl.pathname + targetUrl.search,
    method: req.method,
    headers: forwardHeaders,
    agent: false,
    timeout: 10000
  };

  const proxyReq = http.request(options, (upstreamRes) => {
    const responseHeaders = {
      'Content-Type': upstreamRes.headers['content-type'] || 'application/json',
      'Cache-Control': 'no-store'
    };
    for (const [key, val] of Object.entries(upstreamRes.headers)) {
      if (key.toLowerCase().startsWith('x-nexusedge-')) {
        responseHeaders[key] = val;
      }
    }
    res.writeHead(upstreamRes.statusCode, responseHeaders);
    upstreamRes.pipe(res);
  });

  proxyReq.on('timeout', () => {
    proxyReq.destroy();
    sendJSON(res, 504, { code: 504, error: 'Edge gateway upstream timeout' });
  });

  proxyReq.on('error', (err) => {
    sendJSON(res, 502, { code: 502, error: 'Edge gateway service unavailable: ' + err.message });
  });

  req.pipe(proxyReq);
}

// Static file content type mapping
const MIME_TYPES = {
  '.html': 'text/html',
  '.js': 'application/javascript',
  '.css': 'text/css',
  '.json': 'application/json',
  '.png': 'image/png',
  '.svg': 'image/svg+xml'
};

// Main HTTP Server
const server = http.createServer((req, res) => {
  const startTime = process.hrtime.bigint();
  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = parsedUrl.pathname;

  req.__projectId = null;
  req.__pop = req.headers['x-nexusedge-pop'] || null;

  res.on('finish', () => {
    const durationMs = Number((process.hrtime.bigint() - startTime) / 1000000n);
    const cacheHeader = res.getHeader ? res.getHeader('x-cache') : null;
    const isCacheHit = cacheHeader === 'HIT' || Boolean(req.headers['x-cache-hit']);
    recordTelemetry({
      timestamp: Date.now(),
      projectId: req.__projectId || 'unknown',
      path: pathname,
      method: req.method,
      statusCode: res.statusCode,
      durationMs,
      clientIp: getClientIp(req),
      pop: req.__pop,
      cacheHit: isCacheHit
    });
  });

  // --- API Routes (BFF) ---

  // 1. Session Context
  if (pathname === '/api/auth/session') {
    const session = authenticateSession(req);
    if (!session) {
      return sendJSON(res, 401, { authenticated: false, error: 'Authentication required' });
    }
    return sendJSON(res, 200, {
      authenticated: true,
      user: session.user,
      role: session.role,
      project_id: session.projectId
    });
  }

  // 2. Login Endpoint
  if (pathname === '/api/auth/login' && req.method === 'POST') {
    const clientIp = getClientIp(req);
    const rateCheck = checkLoginRateLimit(clientIp);
    if (!rateCheck.allowed) {
      return sendJSON(res, 429, { error: 'Too many failed login attempts. Please try again later.' });
    }

    let body = '';
    let bodyLength = 0;
    let destroyed = false;

    req.on('data', chunk => {
      if (destroyed) return;
      bodyLength += chunk.length;
      if (bodyLength > MAX_LOGIN_BODY_BYTES) {
        destroyed = true;
        sendJSON(res, 413, { error: 'Payload too large: maximum login payload size exceeded' });
        req.destroy();
        if (req.socket && !req.socket.destroyed) {
          req.socket.destroy();
        }
        return;
      }
      body += chunk;
    });

    req.on('end', () => {
      if (destroyed) return;
      try {
        const payload = JSON.parse(body || '{}');
        const token = payload.token || payload.password;
        if (!token || typeof token !== 'string') {
          recordFailedLogin(clientIp);
          return sendJSON(res, 400, { error: 'Credential token is required' });
        }

        const identity = verifyCredentials(token.trim());
        if (!identity) {
          recordFailedLogin(clientIp);
          return sendJSON(res, 401, { error: 'Invalid credentials: authentication failed' });
        }

        recordSuccessfulLogin(clientIp);

        const sid = generateSessionId();
        const session = {
          id: sid,
          user: identity.user,
          role: identity.role,
          projectId: identity.projectId,
          expiresAt: Date.now() + 8 * 60 * 60 * 1000
        };
        sessions.set(sid, session);

        const cookieFlags = ['HttpOnly', 'Path=/', 'SameSite=Strict'];
        if (isConnectionSecure(req)) {
          cookieFlags.push('Secure');
        }

        return sendJSON(res, 200, {
          success: true,
          user: session.user,
          role: session.role,
          project_id: session.projectId
        }, {
          'Set-Cookie': `nexusedge_session=${sid}; ${cookieFlags.join('; ')}`
        });
      } catch (err) {
        recordFailedLogin(clientIp);
        return sendJSON(res, 400, { error: 'Invalid JSON payload' });
      }
    });
    return;
  }

  // 3. Logout Endpoint
  if (pathname === '/api/auth/logout' && req.method === 'POST') {
    const cookies = parseCookies(req);
    const sid = cookies['nexusedge_session'];
    if (sid) sessions.delete(sid);
    const cookieFlags = ['HttpOnly', 'Path=/', 'Max-Age=0'];
    if (isConnectionSecure(req)) {
      cookieFlags.push('Secure');
    }
    return sendJSON(res, 200, { success: true }, {
      'Set-Cookie': `nexusedge_session=; ${cookieFlags.join('; ')}`
    });
  }

  // 4. Proxy: Control Plane Health (Public)
  if (pathname === '/api/health') {
    return proxyToControlPlane('/healthz', req, res);
  }

  // --- Authenticated Proxy Endpoints ---

  // Require verified session for all /api/proxy/* endpoints
  if (pathname.startsWith('/api/proxy/')) {
    const session = authenticateSession(req);
    if (!session) {
      return sendJSON(res, 401, { code: 401, error: 'Unauthorized: valid user session required' });
    }
    req.__projectId = session.projectId;

    // Token-Bucket Rate Limiter per API Key
    if (session.isAPIKey) {
      const rateLimitResult = checkAndConsumeAPIKeyRateLimit(session.id, session.role);
      if (!rateLimitResult.allowed) {
        return sendJSON(res, 429, {
          code: 429,
          error: 'Too Many Requests: Rate limit exceeded for API key'
        }, {
          'Retry-After': '1',
          'X-RateLimit-Limit': String(rateLimitResult.capacity),
          'X-RateLimit-Remaining': '0',
          'X-RateLimit-Reset': String(rateLimitResult.resetAt)
        });
      }
      res.setHeader('X-RateLimit-Limit', String(rateLimitResult.capacity));
      res.setHeader('X-RateLimit-Remaining', String(rateLimitResult.remaining));
      res.setHeader('X-RateLimit-Reset', String(rateLimitResult.resetAt));
    }

    // --- Real-Time Telemetry & Observability Summary (Multi-Tenant boundary) ---
    if (pathname === '/api/proxy/analytics/summary' && req.method === 'GET') {
      const requestedProject = parsedUrl.searchParams.get('project_id');
      if (requestedProject && requestedProject !== session.projectId && session.role !== 'PLATFORM_OPERATOR') {
        return sendJSON(res, 403, { code: 403, error: 'Forbidden: Cross-tenant project access not permitted' });
      }
      const targetProject = session.role === 'PLATFORM_OPERATOR'
        ? (requestedProject || 'ALL')
        : session.projectId;

      const summary = getTelemetrySummary(targetProject);
      return sendJSON(res, 200, summary);
    }

    // --- Milestone 1.1: Cryptographic API Key Management Vault ---

    // 1. List API Keys (Strict multi-tenant project boundary)
    if (pathname === '/api/proxy/api-keys' && req.method === 'GET') {
      const requestedProject = parsedUrl.searchParams.get('project_id');
      if (requestedProject && requestedProject !== session.projectId && session.role !== 'PLATFORM_OPERATOR') {
        return sendJSON(res, 403, { code: 403, error: 'Forbidden: Cross-tenant project access not permitted' });
      }
      const targetProject = session.role === 'PLATFORM_OPERATOR' && requestedProject ? requestedProject : session.projectId;

      const result = [];
      for (const key of apiKeys.values()) {
        if (key.projectId === targetProject) {
          result.push({
            id: key.id,
            project_id: key.projectId,
            name: key.name,
            prefix: key.prefix,
            role: key.role,
            scopes: key.scopes,
            created_at: key.createdAt,
            last_used_at: key.lastUsedAt,
            status: key.status
          });
        }
      }
      return sendJSON(res, 200, { keys: result });
    }

    // 2. Generate new API Key (PLATFORM_OPERATOR or TENANT_ADMIN)
    if (pathname === '/api/proxy/api-keys' && req.method === 'POST') {
      if (!DOMAIN_MUTATION_ROLES.has(session.role)) {
        return sendJSON(res, 403, {
          code: 403,
          error: `Forbidden: Role "${session.role}" is not authorized to generate API keys. PLATFORM_OPERATOR or TENANT_ADMIN role required.`
        });
      }

      return parseJSONBody(req, res, 16384, (err, payload) => {
        if (err) {
          return sendJSON(res, 400, { error: 'Invalid JSON payload' });
        }
        const name = (payload && payload.name && typeof payload.name === 'string')
          ? payload.name.trim().substring(0, 100)
          : 'Default API Key';
        const requestedRole = (payload && payload.role && ALLOWED_ROLES.has(payload.role))
          ? payload.role
          : 'DEVELOPER';

        // Privilege escalation protection: only operator can create operator keys
        if (requestedRole === 'PLATFORM_OPERATOR' && session.role !== 'PLATFORM_OPERATOR') {
          return sendJSON(res, 403, { error: 'Forbidden: Only PLATFORM_OPERATOR can create operator-scoped API keys' });
        }

        const scopes = (payload && Array.isArray(payload.scopes))
          ? payload.scopes.filter(s => typeof s === 'string').map(s => s.trim())
          : ['inference', 'domains:read'];

        const { record, secretKey } = generateAPIKey(session.projectId, name, requestedRole, scopes);
        return sendJSON(res, 201, {
          id: record.id,
          project_id: record.projectId,
          name: record.name,
          prefix: record.prefix,
          secret_key: secretKey,
          role: record.role,
          scopes: record.scopes,
          created_at: record.createdAt,
          warning: 'This secret key will never be displayed again. Please store it securely.'
        });
      });
    }

    // 3. Revoke API Key (PLATFORM_OPERATOR or TENANT_ADMIN)
    const keyMatch = pathname.match(/^\/api\/proxy\/api-keys\/([a-zA-Z0-9_-]+)$/);
    if (keyMatch && req.method === 'DELETE') {
      const keyId = keyMatch[1];
      if (!DOMAIN_MUTATION_ROLES.has(session.role)) {
        return sendJSON(res, 403, {
          code: 403,
          error: `Forbidden: Role "${session.role}" is not authorized to revoke API keys. PLATFORM_OPERATOR or TENANT_ADMIN role required.`
        });
      }

      const keyRecord = apiKeys.get(keyId);
      if (!keyRecord) {
        return sendJSON(res, 404, { code: 404, error: 'API key not found' });
      }

      if (keyRecord.projectId !== session.projectId && session.role !== 'PLATFORM_OPERATOR') {
        return sendJSON(res, 403, { code: 403, error: 'Forbidden: Cannot revoke API key of another project' });
      }

      keyRecord.status = 'REVOKED';
      return sendJSON(res, 200, {
        success: true,
        id: keyRecord.id,
        status: 'REVOKED',
        revoked_at: new Date().toISOString()
      });
    }

    // Proxy Audit Verification (PLATFORM_OPERATOR only)
    if (pathname === '/api/proxy/audit-logs/verify') {
      if (session.role !== 'PLATFORM_OPERATOR') {
        return sendJSON(res, 403, { code: 403, error: 'Forbidden: PLATFORM_OPERATOR role required for audit verification' });
      }
      return proxyToControlPlane('/v1/audit-logs/verify', req, res, session);
    }

    // Proxy Audit Logs (Strict multi-tenant project boundary)
    if (pathname === '/api/proxy/audit-logs') {
      const requestedProject = parsedUrl.searchParams.get('project_id');
      if (requestedProject && requestedProject !== session.projectId && session.role !== 'PLATFORM_OPERATOR') {
        return sendJSON(res, 403, { code: 403, error: 'Forbidden: Cross-tenant project access not permitted' });
      }
      const limit = parsedUrl.searchParams.get('limit') || '10';
      const targetProject = session.role === 'PLATFORM_OPERATOR' && requestedProject ? requestedProject : session.projectId;
      return proxyToControlPlane(`/v1/audit-logs?limit=${encodeURIComponent(limit)}&project_id=${encodeURIComponent(targetProject)}`, req, res, session);
    }

    // Proxy Domains (Strict multi-tenant project boundary; Only PLATFORM_OPERATOR & TENANT_ADMIN permitted to mutate)
    if (pathname === '/api/proxy/domains') {
      if (req.method !== 'GET') {
        if (!DOMAIN_MUTATION_ROLES.has(session.role)) {
          return sendJSON(res, 403, {
            code: 403,
            error: `Forbidden: Role "${session.role}" is not authorized to modify domains. Only PLATFORM_OPERATOR and TENANT_ADMIN roles can perform domain mutations.`
          });
        }
      }
      return proxyToControlPlane(`/v1/projects/${encodeURIComponent(session.projectId)}/domains`, req, res, session);
    }

    // Proxy Domain DNS Verification (PLATFORM_OPERATOR or TENANT_ADMIN)
    const domainVerifyMatch = pathname.match(/^\/api\/proxy\/domains\/([a-zA-Z0-9_-]+)\/verify$/);
    if (domainVerifyMatch) {
      if (req.method !== 'POST') {
        return sendJSON(res, 405, { code: 405, error: 'Method not allowed' });
      }
      if (!DOMAIN_MUTATION_ROLES.has(session.role)) {
        return sendJSON(res, 403, {
          code: 403,
          error: `Forbidden: Role "${session.role}" is not authorized to verify domains. PLATFORM_OPERATOR or TENANT_ADMIN role required.`
        });
      }
      const domainId = domainVerifyMatch[1];
      const forceQuery = (session.role === 'PLATFORM_OPERATOR' && parsedUrl.searchParams.get('force') === 'true') ? '?force=true' : '';
      return proxyToControlPlane(`/v1/domains/${encodeURIComponent(domainId)}/verify${forceQuery}`, req, res, session);
    }

    // Proxy Single Domain Operations (GET details, DELETE domain)
    const domainDetailMatch = pathname.match(/^\/api\/proxy\/domains\/([a-zA-Z0-9_-]+)$/);
    if (domainDetailMatch) {
      const domainId = domainDetailMatch[1];
      if (req.method === 'DELETE') {
        if (!DOMAIN_MUTATION_ROLES.has(session.role)) {
          return sendJSON(res, 403, {
            code: 403,
            error: `Forbidden: Role "${session.role}" is not authorized to delete domains. PLATFORM_OPERATOR or TENANT_ADMIN role required.`
          });
        }
        return proxyToControlPlane(`/v1/domains/${encodeURIComponent(domainId)}`, req, res, session);
      }
      if (req.method === 'GET') {
        return proxyToControlPlane(`/v1/domains/${encodeURIComponent(domainId)}`, req, res, session);
      }
      return sendJSON(res, 405, { code: 405, error: 'Method not allowed' });
    }

    // Proxy AI Inference (Dedicated Edge Gateway handler; zero Control Plane credential leakage)
    if (pathname === '/api/proxy/inference') {
      const extraHeaders = {};
      if (req.headers['x-nexusedge-routing-strategy']) {
        extraHeaders['X-NexusEdge-Routing-Strategy'] = req.headers['x-nexusedge-routing-strategy'];
      }
      if (req.headers['x-nexusedge-jurisdiction']) {
        extraHeaders['X-NexusEdge-Jurisdiction'] = req.headers['x-nexusedge-jurisdiction'];
      }
      return proxyToEdgeGateway('/v1/chat/completions', req, res, session, extraHeaders);
    }

    // Proxy Alert Status (Authenticated session)
    if (pathname === '/api/proxy/alerts/status') {
      return proxyToControlPlane('/v1/alerts/status', req, res, session);
    }

    // Proxy Alert Test (Only PLATFORM_OPERATOR & TENANT_ADMIN permitted)
    if (pathname === '/api/proxy/alerts/test') {
      if (req.method !== 'POST') {
        return sendJSON(res, 405, { code: 405, error: 'Method not allowed' });
      }
      if (!DOMAIN_MUTATION_ROLES.has(session.role)) {
        return sendJSON(res, 403, {
          code: 403,
          error: `Forbidden: Role "${session.role}" is not authorized to trigger alert tests. PLATFORM_OPERATOR or TENANT_ADMIN role required.`
        });
      }
      return proxyToControlPlane('/v1/alerts/test', req, res, session);
    }

    // Proxy Edge PoPs: Global Latency Matrix (Authenticated session)
    if (pathname === '/api/proxy/pops/matrix') {
      if (req.method !== 'GET') {
        return sendJSON(res, 405, { code: 405, error: 'Method not allowed' });
      }
      return proxyToControlPlane('/v1/edge/routing/matrix', req, res, session);
    }

    // Proxy Edge PoPs: Multi-PoP Failover Routes (Authenticated session)
    if (pathname === '/api/proxy/pops/routes') {
      if (req.method !== 'GET') {
        return sendJSON(res, 405, { code: 405, error: 'Method not allowed' });
      }
      return proxyToControlPlane('/v1/edge/pops/routes', req, res, session);
    }

    // Proxy Edge PoPs: Multi-PoP Live Telemetry & Health States (Authenticated session)
    if (pathname === '/api/proxy/pops/health') {
      if (req.method !== 'GET') {
        return sendJSON(res, 405, { code: 405, error: 'Method not allowed' });
      }
      return proxyToControlPlane('/v1/edge/pops/health', req, res, session);
    }

    // Proxy Edge PoPs: Run Synthetic Latency & Health Probes (PLATFORM_OPERATOR only)
    if (pathname === '/api/proxy/pops/health/probe') {
      if (req.method !== 'POST') {
        return sendJSON(res, 405, { code: 405, error: 'Method not allowed' });
      }
      if (session.role !== 'PLATFORM_OPERATOR') {
        return sendJSON(res, 403, {
          code: 403,
          error: `Forbidden: Role "${session.role}" is not authorized to trigger synthetic probes. PLATFORM_OPERATOR role required.`
        });
      }
      return proxyToControlPlane('/v1/edge/pops/health/probe', req, res, session);
    }

    // Proxy Edge PoPs: List all connected PoPs (Authenticated session)
    if (pathname === '/api/proxy/pops') {
      if (req.method !== 'GET') {
        return sendJSON(res, 405, { code: 405, error: 'Method not allowed' });
      }
      return proxyToControlPlane('/v1/edge/pops', req, res, session);
    }

    // Proxy Edge PoPs: Inspect single PoP (Authenticated session)
    const popMatch = pathname.match(/^\/api\/proxy\/pops\/([a-zA-Z0-9_-]+)$/);
    if (popMatch) {
      const popId = popMatch[1];
      if (req.method !== 'GET') {
        return sendJSON(res, 405, { code: 405, error: 'Method not allowed' });
      }
      return proxyToControlPlane(`/v1/edge/pops/${encodeURIComponent(popId)}`, req, res, session);
    }

    // Proxy Edge PoPs: BGP State Mutation (PLATFORM_OPERATOR only)
    const popBgpMatch = pathname.match(/^\/api\/proxy\/pops\/([a-zA-Z0-9_-]+)\/bgp\/(announce|withdraw)$/);
    if (popBgpMatch) {
      const popId = popBgpMatch[1];
      const bgpAction = popBgpMatch[2];
      if (req.method !== 'POST') {
        return sendJSON(res, 405, { code: 405, error: 'Method not allowed' });
      }
      if (session.role !== 'PLATFORM_OPERATOR') {
        return sendJSON(res, 403, {
          code: 403,
          error: `Forbidden: Role "${session.role}" is not authorized to modify BGP route state. Only PLATFORM_OPERATOR can announce or withdraw PoP Anycast routes.`
        });
      }
      return proxyToControlPlane(`/v1/edge/pops/${encodeURIComponent(popId)}/bgp/${encodeURIComponent(bgpAction)}`, req, res, session);
    }

    return sendJSON(res, 404, { code: 404, error: 'Proxy route not found' });
  }

  // --- Static File Server ---
  let filePath = path.join(PUBLIC_DIR, pathname === '/' ? 'index.html' : pathname);
  // Prevent directory traversal
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    res.end('Forbidden');
    return;
  }

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      filePath = path.join(PUBLIC_DIR, 'index.html');
    }
    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';

    fs.readFile(filePath, (readErr, content) => {
      if (readErr) {
        res.writeHead(500);
        res.end('Error reading file');
        return;
      }
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(content);
    });
  });
});

if (require.main === module) {
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`NexusEdge Dashboard BFF listening on port ${PORT}`);
  });
}

server.apiKeys = apiKeys;
server.sessions = sessions;
server.apiKeyBuckets = apiKeyBuckets;
server.telemetryBuffer = telemetryBuffer;
server.recordTelemetry = recordTelemetry;
server.getTelemetrySummary = getTelemetrySummary;
server.checkAndConsumeAPIKeyRateLimit = checkAndConsumeAPIKeyRateLimit;

module.exports = server;
