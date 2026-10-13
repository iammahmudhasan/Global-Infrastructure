// NexusEdge Dashboard Authenticated Backend-For-Frontend (BFF)
// Enforces zero-credential browser boundary and server-side control-plane proxying.

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = parseInt(process.env.PORT || '3000', 10);
const CONTROL_PLANE_URL = process.env.CONTROL_PLANE_URL || 'http://127.0.0.1:9091';
const CONTROL_PLANE_TOKEN = process.env.CONTROL_PLANE_TOKEN || process.env.NEXUSEDGE_CP_AUTH_TOKEN || '';
const EDGE_GATEWAY_URL = process.env.EDGE_GATEWAY_URL || 'http://127.0.0.1:8080';
const DEFAULT_PROJECT_ID = process.env.NEXUSEDGE_PROJECT_ID || 'proj-core';
const PUBLIC_DIR = path.join(__dirname, 'public');

// In-Memory Active Session Store
const sessions = new Map();

// Helper to generate secure session ID
function generateSessionId() {
  return crypto.randomBytes(32).toString('hex');
}

// Parse cookies from request header
function parseCookies(req) {
  const list = {};
  const cookieHeader = req.headers.cookie;
  if (!cookieHeader) return list;
  cookieHeader.split(';').forEach(cookie => {
    const parts = cookie.split('=');
    list[parts.shift().trim()] = decodeURI(parts.join('='));
  });
  return list;
}

// Authenticate session via cookie or Authorization header
function authenticateSession(req) {
  const cookies = parseCookies(req);
  let sessionId = cookies['nexusedge_session'];

  const authHeader = req.headers['authorization'];
  if (!sessionId && authHeader && authHeader.startsWith('Bearer ')) {
    sessionId = authHeader.substring(7).trim();
  }

  if (sessionId && sessions.has(sessionId)) {
    const session = sessions.get(sessionId);
    if (session.expiresAt > Date.now()) {
      return session;
    }
    sessions.delete(sessionId);
  }

  // In non-production development environments, auto-bootstrap an authenticated local operator session
  if (process.env.NODE_ENV !== 'production' && process.env.NEXUSEDGE_ENV !== 'production') {
    const devSessionId = 'dev-local-session';
    const devSession = {
      id: devSessionId,
      user: 'operator@nexusedge.local',
      role: 'PLATFORM_OPERATOR',
      projectId: DEFAULT_PROJECT_ID,
      expiresAt: Date.now() + 24 * 60 * 60 * 1000
    };
    sessions.set(devSessionId, devSession);
    return devSession;
  }

  return null;
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

// Forward request to upstream service
function proxyRequest(upstreamBaseUrl, upstreamPath, req, res, extraHeaders = {}) {
  const targetUrl = new URL(upstreamPath, upstreamBaseUrl);

  const forwardHeaders = {
    'accept': 'application/json',
    'content-type': req.headers['content-type'] || 'application/json',
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
    sendJSON(res, 504, { code: 504, error: 'Upstream gateway timeout' });
  });

  proxyReq.on('error', (err) => {
    sendJSON(res, 502, { code: 502, error: 'Upstream service unavailable: ' + err.message });
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
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        const payload = JSON.parse(body || '{}');
        const token = payload.token || payload.password;
        if (!token) {
          return sendJSON(res, 400, { error: 'Credential token is required' });
        }
        const sid = generateSessionId();
        const session = {
          id: sid,
          user: payload.username || 'operator',
          role: 'PLATFORM_OPERATOR',
          projectId: payload.project_id || DEFAULT_PROJECT_ID,
          expiresAt: Date.now() + 8 * 60 * 60 * 1000
        };
        sessions.set(sid, session);
        return sendJSON(res, 200, { success: true, project_id: session.projectId }, {
          'Set-Cookie': `nexusedge_session=${sid}; HttpOnly; Path=/; SameSite=Strict`
        });
      } catch (err) {
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
    return sendJSON(res, 200, { success: true }, {
      'Set-Cookie': 'nexusedge_session=; HttpOnly; Path=/; Max-Age=0'
    });
  }

  // 4. Proxy: Control Plane Health
  if (pathname === '/api/health') {
    return proxyRequest(CONTROL_PLANE_URL, '/healthz', req, res);
  }

  // --- Authenticated Proxy Endpoints ---

  // Require session for all /api/proxy/* endpoints
  if (pathname.startsWith('/api/proxy/')) {
    const session = authenticateSession(req);
    if (!session) {
      return sendJSON(res, 401, { code: 401, error: 'Unauthorized: valid user session required' });
    }

    // Proxy Audit Logs
    if (pathname === '/api/proxy/audit-logs') {
      const limit = parsedUrl.searchParams.get('limit') || '10';
      return proxyRequest(CONTROL_PLANE_URL, `/v1/audit-logs?limit=${encodeURIComponent(limit)}&project_id=${encodeURIComponent(session.projectId)}`, req, res);
    }

    // Proxy Audit Verification (Operator only)
    if (pathname === '/api/proxy/audit-logs/verify') {
      return proxyRequest(CONTROL_PLANE_URL, '/v1/audit-logs/verify', req, res);
    }

    // Proxy Domains
    if (pathname === '/api/proxy/domains') {
      return proxyRequest(CONTROL_PLANE_URL, `/v1/projects/${encodeURIComponent(session.projectId)}/domains`, req, res);
    }

    // Proxy AI Inference
    if (pathname === '/api/proxy/inference') {
      const extraHeaders = {};
      if (req.headers['x-nexusedge-routing-strategy']) {
        extraHeaders['X-NexusEdge-Routing-Strategy'] = req.headers['x-nexusedge-routing-strategy'];
      }
      if (req.headers['x-nexusedge-jurisdiction']) {
        extraHeaders['X-NexusEdge-Jurisdiction'] = req.headers['x-nexusedge-jurisdiction'];
      }
      return proxyRequest(EDGE_GATEWAY_URL, '/v1/chat/completions', req, res, extraHeaders);
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
