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

// In-Memory Active Session Store
const sessions = new Map();

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

// Client IP extractor strictly protecting against X-Forwarded-For spoofing
function getClientIp(req) {
  const socketIp = (req.socket && req.socket.remoteAddress) ? req.socket.remoteAddress : 'unknown';
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
        return parts[parts.length - 1];
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
  if (!entry || (now - entry.windowStart) > RATE_LIMIT_WINDOW_MS) {
    return { allowed: true, remaining: MAX_LOGIN_ATTEMPTS_PER_MIN };
  }
  if (entry.count >= MAX_LOGIN_ATTEMPTS_PER_MIN) {
    return { allowed: false, remaining: 0 };
  }
  return { allowed: true, remaining: MAX_LOGIN_ATTEMPTS_PER_MIN - entry.count };
}

function recordFailedLogin(ip) {
  const now = Date.now();
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
        const [regToken, regUser, regRole, regProj] = parts;
        if (safeCompare(token, regToken)) {
          return {
            user: regUser,
            role: regRole,
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

// Authenticate session strictly via active server session
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
function proxyToControlPlane(upstreamPath, req, res, extraHeaders = {}) {
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
  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = parsedUrl.pathname;

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

    // Proxy Audit Verification (PLATFORM_OPERATOR only)
    if (pathname === '/api/proxy/audit-logs/verify') {
      if (session.role !== 'PLATFORM_OPERATOR') {
        return sendJSON(res, 403, { code: 403, error: 'Forbidden: PLATFORM_OPERATOR role required for audit verification' });
      }
      return proxyToControlPlane('/v1/audit-logs/verify', req, res);
    }

    // Proxy Audit Logs (Strict multi-tenant project boundary)
    if (pathname === '/api/proxy/audit-logs') {
      const requestedProject = parsedUrl.searchParams.get('project_id');
      if (requestedProject && requestedProject !== session.projectId && session.role !== 'PLATFORM_OPERATOR') {
        return sendJSON(res, 403, { code: 403, error: 'Forbidden: Cross-tenant project access not permitted' });
      }
      const limit = parsedUrl.searchParams.get('limit') || '10';
      const targetProject = session.role === 'PLATFORM_OPERATOR' && requestedProject ? requestedProject : session.projectId;
      return proxyToControlPlane(`/v1/audit-logs?limit=${encodeURIComponent(limit)}&project_id=${encodeURIComponent(targetProject)}`, req, res);
    }

    // Proxy Domains (Strict multi-tenant project boundary; Read-only viewers forbidden from mutation)
    if (pathname === '/api/proxy/domains') {
      if (req.method !== 'GET' && session.role === 'VIEWER') {
        return sendJSON(res, 403, { code: 403, error: 'Forbidden: Read-only viewer role cannot modify domains' });
      }
      return proxyToControlPlane(`/v1/projects/${encodeURIComponent(session.projectId)}/domains`, req, res);
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

module.exports = server;
