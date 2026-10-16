const { describe, it } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const http = require('http');

function safeClose(server) {
  return new Promise((resolve) => {
    if (!server) return resolve();
    if (server.closeAllConnections) {
      server.closeAllConnections();
    }
    server.close(() => resolve());
  });
}

describe('Dashboard Security & BFF Acceptance Tests', () => {
  const publicDir = path.join(__dirname, '..', 'public');
  const appJsPath = path.join(publicDir, 'app.js');
  const indexHtmlPath = path.join(publicDir, 'index.html');

  it('Requirement 2.1: Frontend bundle must contain ZERO secrets or fixture tokens', () => {
    const appJsContent = fs.readFileSync(appJsPath, 'utf8');
    const indexHtmlContent = fs.readFileSync(indexHtmlPath, 'utf8');

    // Forbidden fixture credentials and patterns
    const forbiddenPatterns = [
      'dev-fixture-key-01',
      'dev-fixture-key-banking',
      'dev-fixture-key-node',
      'test-client-token',
      'Authorization\': \'Bearer',
      'X-API-Key\': \'',
      ':9091/v1/',
      ':8081/v1/'
    ];

    for (const pattern of forbiddenPatterns) {
      assert.strictEqual(
        appJsContent.includes(pattern),
        false,
        `CRITICAL SECURITY VIOLATION: Forbidden credential or direct upstream endpoint "${pattern}" found in app.js`
      );
      assert.strictEqual(
        indexHtmlContent.includes(pattern),
        false,
        `CRITICAL SECURITY VIOLATION: Forbidden credential or direct upstream endpoint "${pattern}" found in index.html`
      );
    }
  });

  it('Requirement 8: Inference simulator must clearly separate demo mode from real errors', () => {
    const appJsContent = fs.readFileSync(appJsPath, 'utf8');
    assert.strictEqual(
      appJsContent.includes('sim-demo-mode'),
      true,
      'app.js must read explicit sim-demo-mode toggle'
    );
    assert.strictEqual(
      appJsContent.includes('(DEMO SIMULATION ONLY)'),
      true,
      'Simulation output must be explicitly marked as DEMO SIMULATION'
    );
    assert.strictEqual(
      appJsContent.includes('[ERROR] Edge Gateway inference dispatch failed'),
      true,
      'Real mode failures must emit honest error diagnostics instead of synthetic 200 OK'
    );
  });

  it('Requirement 2.2: Production BFF must reject unauthenticated proxy requests with 401', async () => {
    process.env.NODE_ENV = 'production';
    process.env.NEXUSEDGE_ENV = 'production';

    delete require.cache[require.resolve('../server.js')];
    const server = require('../server.js');

    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;

    try {
      // 1. Unauthenticated request to /api/proxy/audit-logs must return 401
      const res1 = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/proxy/audit-logs',
          method: 'GET',
          agent: false,
          headers: { 'Connection': 'close' }
        }, resolve);
        req.on('error', reject);
        req.end();
      });

      assert.strictEqual(res1.statusCode, 401, 'Unauthenticated proxy request must be rejected with 401 Unauthorized');
      let body1 = '';
      res1.on('data', chunk => { body1 += chunk; });
      await new Promise(resolve => res1.on('end', resolve));
      const json1 = JSON.parse(body1);
      assert.strictEqual(json1.code, 401);

      // 2. Unauthenticated request to /api/auth/session must return 401
      const res2 = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/auth/session',
          method: 'GET',
          agent: false,
          headers: { 'Connection': 'close' }
        }, resolve);
        req.on('error', reject);
        req.end();
      });
      assert.strictEqual(res2.statusCode, 401);
      res2.resume();
    } finally {
      await safeClose(server);
    }
  });

  it('Requirement 2.3: Arbitrary or invalid login token must be rejected with 401 and NO session cookie', async () => {
    process.env.NODE_ENV = 'production';
    process.env.NEXUSEDGE_ENV = 'production';
    process.env.NEXUSEDGE_OPERATOR_TOKEN = 'secret-operator-token-xyz';

    delete require.cache[require.resolve('../server.js')];
    const server = require('../server.js');

    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;

    try {
      const postData = JSON.stringify({
        token: 'arbitrary-fake-token-12345',
        username: 'attacker',
        role: 'PLATFORM_OPERATOR',
        project_id: 'victim-project'
      });

      const res = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/auth/login',
          method: 'POST',
          agent: false,
          headers: {
            'Connection': 'close',
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(postData)
          }
        }, resolve);
        req.on('error', reject);
        req.write(postData);
        req.end();
      });

      assert.strictEqual(res.statusCode, 401, 'Invalid token must be rejected with 401 Unauthorized');
      const setCookie = res.headers['set-cookie'];
      assert.strictEqual(setCookie, undefined, 'No session cookie should be issued for invalid credentials');

      let body = '';
      res.on('data', chunk => { body += chunk; });
      await new Promise(resolve => res.on('end', resolve));
      const json = JSON.parse(body);
      assert.strictEqual(json.error.includes('authentication failed'), true);
    } finally {
      await safeClose(server);
    }
  });

  it('Requirement 2.4: Missing token must be rejected with 400 Bad Request', async () => {
    delete require.cache[require.resolve('../server.js')];
    const server = require('../server.js');

    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;

    try {
      const postData = JSON.stringify({ username: 'operator' });
      const res = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/auth/login',
          method: 'POST',
          agent: false,
          headers: {
            'Connection': 'close',
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(postData)
          }
        }, resolve);
        req.on('error', reject);
        req.write(postData);
        req.end();
      });

      assert.strictEqual(res.statusCode, 400);
      res.resume();
    } finally {
      await safeClose(server);
    }
  });

  it('Requirement 2.5: Client cannot forge role or project ID (Server-derived identity enforcement)', async () => {
    process.env.NODE_ENV = 'production';
    process.env.NEXUSEDGE_ENV = 'production';
    process.env.NEXUSEDGE_DASHBOARD_USERS = 'token-viewer-999:viewer@tenant.io:VIEWER:proj-viewer';

    delete require.cache[require.resolve('../server.js')];
    const server = require('../server.js');

    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;

    try {
      const postData = JSON.stringify({
        token: 'token-viewer-999',
        username: 'forged-operator',
        role: 'PLATFORM_OPERATOR',
        project_id: 'proj-root-core'
      });

      const res = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/auth/login',
          method: 'POST',
          agent: false,
          headers: {
            'Connection': 'close',
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(postData)
          }
        }, resolve);
        req.on('error', reject);
        req.write(postData);
        req.end();
      });

      assert.strictEqual(res.statusCode, 200);
      let body = '';
      res.on('data', chunk => { body += chunk; });
      await new Promise(resolve => res.on('end', resolve));
      const json = JSON.parse(body);

      assert.strictEqual(json.role, 'VIEWER', 'Role must be derived strictly from server identity, not client body');
      assert.strictEqual(json.project_id, 'proj-viewer', 'Project must be derived strictly from server identity');
      assert.strictEqual(json.user, 'viewer@tenant.io');

      const cookieHeader = res.headers['set-cookie'][0];
      assert.strictEqual(cookieHeader.includes('Secure'), true, 'Production session cookie must contain Secure flag');
      assert.strictEqual(cookieHeader.includes('HttpOnly'), true);

      const sessionId = cookieHeader.split(';')[0].split('=')[1];
      const sessionRes = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/auth/session',
          method: 'GET',
          agent: false,
          headers: {
            'Connection': 'close',
            'Cookie': `nexusedge_session=${sessionId}`
          }
        }, resolve);
        req.on('error', reject);
        req.end();
      });

      assert.strictEqual(sessionRes.statusCode, 200);
      let sBody = '';
      sessionRes.on('data', chunk => { sBody += chunk; });
      await new Promise(resolve => sessionRes.on('end', resolve));
      const sJson = JSON.parse(sBody);
      assert.strictEqual(sJson.role, 'VIEWER');
      assert.strictEqual(sJson.project_id, 'proj-viewer');
    } finally {
      await safeClose(server);
    }
  });

  it('Requirement 2.6: Sensitive operations (audit-logs/verify) require PLATFORM_OPERATOR role (403 for viewers)', async () => {
    process.env.NODE_ENV = 'production';
    process.env.NEXUSEDGE_ENV = 'production';
    process.env.NEXUSEDGE_DASHBOARD_USERS = 'token-viewer-abc:alice@tenant.io:VIEWER:proj-alice';

    delete require.cache[require.resolve('../server.js')];
    const server = require('../server.js');

    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;

    try {
      const postData = JSON.stringify({ token: 'token-viewer-abc' });
      const loginRes = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/auth/login',
          method: 'POST',
          agent: false,
          headers: {
            'Connection': 'close',
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(postData)
          }
        }, resolve);
        req.on('error', reject);
        req.write(postData);
        req.end();
      });

      assert.strictEqual(loginRes.statusCode, 200);
      const cookie = loginRes.headers['set-cookie'][0].split(';')[0];
      loginRes.resume();

      const verifyRes = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/proxy/audit-logs/verify',
          method: 'POST',
          agent: false,
          headers: {
            'Connection': 'close',
            'Cookie': cookie
          }
        }, resolve);
        req.on('error', reject);
        req.end();
      });

      assert.strictEqual(verifyRes.statusCode, 403, 'Non-operator must receive 403 Forbidden for audit verification');
      verifyRes.resume();
    } finally {
      await safeClose(server);
    }
  });

  it('Requirement 2.7: Multi-tenant boundary prevents cross-project access for non-operators', async () => {
    process.env.NODE_ENV = 'production';
    process.env.NEXUSEDGE_ENV = 'production';
    process.env.NEXUSEDGE_DASHBOARD_USERS = 'token-tenant-1:user1@tenant.io:DEVELOPER:proj-tenant-1';

    delete require.cache[require.resolve('../server.js')];
    const server = require('../server.js');

    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;

    try {
      const postData = JSON.stringify({ token: 'token-tenant-1' });
      const loginRes = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/auth/login',
          method: 'POST',
          agent: false,
          headers: {
            'Connection': 'close',
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(postData)
          }
        }, resolve);
        req.on('error', reject);
        req.write(postData);
        req.end();
      });

      assert.strictEqual(loginRes.statusCode, 200);
      const cookie = loginRes.headers['set-cookie'][0].split(';')[0];
      loginRes.resume();

      const crossRes = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/proxy/audit-logs?project_id=proj-tenant-2',
          method: 'GET',
          agent: false,
          headers: {
            'Connection': 'close',
            'Cookie': cookie
          }
        }, resolve);
        req.on('error', reject);
        req.end();
      });

      assert.strictEqual(crossRes.statusCode, 403, 'Cross-tenant project query must be rejected with 403 Forbidden');
      crossRes.resume();
    } finally {
      await safeClose(server);
    }
  });

  it('Requirement 3.1: Upstream Credential Boundary: Control Plane token is NEVER leaked to Edge Gateway inference requests', async () => {
    const SECRET_CONTROL_PLANE_TOKEN = 'super-secret-cp-token-xyz-123';
    const EDGE_AI_KEY = 'edge-ai-inference-key-789';

    let capturedHeaders = null;
    const mockEdgeGateway = http.createServer((req, res) => {
      capturedHeaders = req.headers;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ choices: [{ message: { content: 'mock answer' } }] }));
    });

    await new Promise((resolve) => mockEdgeGateway.listen(0, '127.0.0.1', resolve));
    const edgePort = mockEdgeGateway.address().port;

    process.env.CONTROL_PLANE_TOKEN = SECRET_CONTROL_PLANE_TOKEN;
    process.env.EDGE_GATEWAY_URL = `http://127.0.0.1:${edgePort}`;
    process.env.EDGE_GATEWAY_AI_KEY = EDGE_AI_KEY;
    process.env.NEXUSEDGE_OPERATOR_TOKEN = 'operator-test-token';

    delete require.cache[require.resolve('../server.js')];
    const server = require('../server.js');

    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const bffPort = server.address().port;

    try {
      const loginData = JSON.stringify({ token: 'operator-test-token' });
      const loginRes = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: bffPort,
          path: '/api/auth/login',
          method: 'POST',
          agent: false,
          headers: {
            'Connection': 'close',
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(loginData)
          }
        }, resolve);
        req.on('error', reject);
        req.write(loginData);
        req.end();
      });

      assert.strictEqual(loginRes.statusCode, 200);
      const cookie = loginRes.headers['set-cookie'][0].split(';')[0];
      loginRes.resume();

      const inferRes = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: bffPort,
          path: '/api/proxy/inference',
          method: 'POST',
          agent: false,
          headers: {
            'Connection': 'close',
            'Cookie': cookie,
            'Content-Type': 'application/json'
          }
        }, resolve);
        req.on('error', reject);
        req.write(JSON.stringify({ prompt: 'test' }));
        req.end();
      });

      assert.strictEqual(inferRes.statusCode, 200);
      assert.notStrictEqual(capturedHeaders, null);
      assert.strictEqual(
        capturedHeaders['x-api-key'],
        undefined,
        'Control plane X-API-Key must NOT be sent to Edge Gateway'
      );
      assert.strictEqual(
        capturedHeaders['authorization'],
        `Bearer ${EDGE_AI_KEY}`,
        'Edge Gateway must receive dedicated AI inference key, NOT Control Plane token'
      );
      assert.strictEqual(
        capturedHeaders['authorization'].includes(SECRET_CONTROL_PLANE_TOKEN),
        false,
        'Control Plane token must NEVER leak to Edge Gateway'
      );
      inferRes.resume();
    } finally {
      await safeClose(server);
      await safeClose(mockEdgeGateway);
    }
  });

  it('Requirement 2.8: Login rate limiting triggers 429 after exceeding max attempts', async () => {
    process.env.NEXUSEDGE_OPERATOR_TOKEN = 'legit-operator-token';

    delete require.cache[require.resolve('../server.js')];
    const server = require('../server.js');

    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;

    try {
      const invalidData = JSON.stringify({ token: 'bad-token' });

      for (let i = 1; i <= 10; i++) {
        const res = await new Promise((resolve, reject) => {
          const req = http.request({
            hostname: '127.0.0.1',
            port: port,
            path: '/api/auth/login',
            method: 'POST',
            agent: false,
            headers: {
              'Connection': 'close',
              'Content-Type': 'application/json',
              'Content-Length': Buffer.byteLength(invalidData)
            }
          }, resolve);
          req.on('error', reject);
          req.write(invalidData);
          req.end();
        });
        assert.strictEqual(res.statusCode, 401);
        res.resume();
      }

      // The 11th attempt must trigger 429 Too Many Requests
      const resLimit = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/auth/login',
          method: 'POST',
          agent: false,
          headers: {
            'Connection': 'close',
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(invalidData)
          }
        }, resolve);
        req.on('error', reject);
        req.write(invalidData);
        req.end();
      });

      assert.strictEqual(resLimit.statusCode, 429, 'Excessive failed login attempts must trigger 429 Rate Limit');
      resLimit.resume();
    } finally {
      await safeClose(server);
    }
  });

  it('Requirement 2.9: Oversized login payload (>16KB) is rejected with 413 Payload Too Large', async () => {
    delete require.cache[require.resolve('../server.js')];
    const server = require('../server.js');

    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;

    try {
      const hugePadding = 'A'.repeat(20 * 1024);
      const postData = JSON.stringify({ token: 'test', padding: hugePadding });

      const res = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/auth/login',
          method: 'POST',
          agent: false,
          headers: {
            'Connection': 'close',
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(postData)
          }
        }, resolve);
        req.on('error', (err) => {
          // Socket destruction on 413 payload truncation is valid
          resolve({ statusCode: 413, resume: () => {} });
        });
        req.write(postData);
        req.end();
      });

      assert.strictEqual(res.statusCode, 413, 'Oversized login payload must be rejected with 413 Payload Too Large');
      res.resume();
    } finally {
      await safeClose(server);
    }
  });

  it('Requirement 3.2: Control Plane token cannot be used to log in as Dashboard Operator', async () => {
    process.env.NODE_ENV = 'production';
    process.env.NEXUSEDGE_ENV = 'production';
    process.env.CONTROL_PLANE_TOKEN = 'secret-cp-token-only';
    delete process.env.NEXUSEDGE_OPERATOR_TOKEN;
    delete process.env.NEXUSEDGE_DASHBOARD_USERS;

    delete require.cache[require.resolve('../server.js')];
    const server = require('../server.js');

    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;

    try {
      const postData = JSON.stringify({
        token: 'secret-cp-token-only'
      });

      const res = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/auth/login',
          method: 'POST',
          agent: false,
          headers: {
            'Connection': 'close',
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(postData)
          }
        }, resolve);
        req.on('error', reject);
        req.write(postData);
        req.end();
      });

      assert.strictEqual(res.statusCode, 401, 'Control Plane token must NOT be accepted for Operator login');
      assert.strictEqual(
        res.headers['set-cookie'],
        undefined,
        'No session cookie should be issued when logging in with Control Plane token'
      );
      res.resume();
    } finally {
      await safeClose(server);
    }
  });

  it('Requirement 2.10: Login rate limiting cannot be bypassed via X-Forwarded-For header spoofing', async () => {
    delete process.env.TRUSTED_PROXY_IPS;
    delete require.cache[require.resolve('../server.js')];
    const server = require('../server.js');

    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;

    try {
      // Send 10 failed login requests, each with a different spoofed X-Forwarded-For
      for (let i = 0; i < 10; i++) {
        const invalidData = JSON.stringify({ token: `invalid-token-${i}` });
        const res = await new Promise((resolve, reject) => {
          const req = http.request({
            hostname: '127.0.0.1',
            port: port,
            path: '/api/auth/login',
            method: 'POST',
            agent: false,
            headers: {
              'Connection': 'close',
              'Content-Type': 'application/json',
              'Content-Length': Buffer.byteLength(invalidData),
              'X-Forwarded-For': `203.0.113.${i + 1}, 198.51.100.1`
            }
          }, resolve);
          req.on('error', reject);
          req.write(invalidData);
          req.end();
        });
        assert.strictEqual(res.statusCode, 401);
        res.resume();
      }

      // The 11th attempt with yet another spoofed IP must STILL be rate-limited (429)
      const eleventhData = JSON.stringify({ token: 'invalid-token-11' });
      const resLimit = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/auth/login',
          method: 'POST',
          agent: false,
          headers: {
            'Connection': 'close',
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(eleventhData),
            'X-Forwarded-For': '192.0.2.99'
          }
        }, resolve);
        req.on('error', reject);
        req.write(eleventhData);
        req.end();
      });

      assert.strictEqual(
        resLimit.statusCode,
        429,
        'Spoofed X-Forwarded-For must not bypass login rate limiting from same peer socket'
      );
      resLimit.resume();
    } finally {
      await safeClose(server);
    }
  });

  it('Requirement 2.11: Malformed cookie (%E0%A4%A) does not crash the Node.js process and returns 401', async () => {
    delete require.cache[require.resolve('../server.js')];
    const server = require('../server.js');

    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;

    try {
      // Send request with malformed percent-encoded cookie
      const res1 = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/proxy/audit-logs',
          method: 'GET',
          agent: false,
          headers: {
            'Connection': 'close',
            'Cookie': 'nexusedge_session=%E0%A4%A'
          }
        }, resolve);
        req.on('error', reject);
        req.end();
      });

      assert.strictEqual(res1.statusCode, 401, 'Malformed cookie must safely return 401 Unauthorized');
      res1.resume();

      // Ensure server is still alive and responds to subsequent valid requests
      const res2 = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/',
          method: 'GET',
          agent: false,
          headers: { 'Connection': 'close' }
        }, resolve);
        req.on('error', reject);
        req.end();
      });

      assert.strictEqual(res2.statusCode, 200, 'Server must remain alive and responsive after malformed cookie');
      res2.resume();
    } finally {
      await safeClose(server);
    }
  });

  it('Requirement 3.3: Edge Gateway telemetry headers (X-NexusEdge-*) are forwarded to client', async () => {
    let capturedHeaders = null;
    const mockEdgeGateway = http.createServer((req, res) => {
      capturedHeaders = req.headers;
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'X-NexusEdge-Provider': 'spot-coreweave',
        'X-NexusEdge-Cost': '0.42',
        'X-NexusEdge-TTFT-Ms': '15',
        'X-NexusEdge-Region': 'dhaka'
      });
      res.end(JSON.stringify({ choices: [{ message: { content: 'mock answer' } }] }));
    });

    await new Promise((resolve) => mockEdgeGateway.listen(0, '127.0.0.1', resolve));
    const edgePort = mockEdgeGateway.address().port;

    process.env.EDGE_GATEWAY_URL = `http://127.0.0.1:${edgePort}`;
    process.env.EDGE_GATEWAY_AI_KEY = 'edge-test-key';
    process.env.NEXUSEDGE_OPERATOR_TOKEN = 'operator-test-token-telemetry';

    delete require.cache[require.resolve('../server.js')];
    const server = require('../server.js');

    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const bffPort = server.address().port;

    try {
      const loginData = JSON.stringify({ token: 'operator-test-token-telemetry' });
      const loginRes = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: bffPort,
          path: '/api/auth/login',
          method: 'POST',
          agent: false,
          headers: {
            'Connection': 'close',
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(loginData)
          }
        }, resolve);
        req.on('error', reject);
        req.write(loginData);
        req.end();
      });

      assert.strictEqual(loginRes.statusCode, 200);
      const cookie = loginRes.headers['set-cookie'][0].split(';')[0];
      loginRes.resume();

      const inferRes = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: bffPort,
          path: '/api/proxy/inference',
          method: 'POST',
          agent: false,
          headers: {
            'Connection': 'close',
            'Cookie': cookie,
            'Content-Type': 'application/json'
          }
        }, resolve);
        req.on('error', reject);
        req.write(JSON.stringify({ prompt: 'test telemetry forwarding' }));
        req.end();
      });

      assert.strictEqual(inferRes.statusCode, 200);
      assert.strictEqual(inferRes.headers['x-nexusedge-provider'], 'spot-coreweave');
      assert.strictEqual(inferRes.headers['x-nexusedge-cost'], '0.42');
      assert.strictEqual(inferRes.headers['x-nexusedge-ttft-ms'], '15');
      assert.strictEqual(inferRes.headers['x-nexusedge-region'], 'dhaka');
      inferRes.resume();
    } finally {
      await safeClose(server);
      await safeClose(mockEdgeGateway);
    }
  });

  it('Requirement 4.1: Production mode strictly rejects development login fixtures (dev-operator-key, dev-viewer-key)', async () => {
    process.env.NODE_ENV = 'production';
    process.env.NEXUSEDGE_ENV = 'production';
    delete process.env.NEXUSEDGE_OPERATOR_TOKEN;

    delete require.cache[require.resolve('../server.js')];
    const server = require('../server.js');

    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;

    try {
      for (const devKey of ['dev-operator-key', 'dev-viewer-key']) {
        const postData = JSON.stringify({ token: devKey });
        const res = await new Promise((resolve, reject) => {
          const req = http.request({
            hostname: '127.0.0.1',
            port: port,
            path: '/api/auth/login',
            method: 'POST',
            agent: false,
            headers: {
              'Connection': 'close',
              'Content-Type': 'application/json',
              'Content-Length': Buffer.byteLength(postData)
            }
          }, resolve);
          req.on('error', reject);
          req.write(postData);
          req.end();
        });

        assert.strictEqual(res.statusCode, 401, `Development fixture "${devKey}" must be rejected with 401 in production mode`);
        assert.strictEqual(res.headers['set-cookie'], undefined, `No session cookie should be issued for "${devKey}" in production mode`);
        res.resume();
      }
    } finally {
      await safeClose(server);
    }
  });

  it('Requirement 4.2: Dedicated Control Plane Service Token is segregated from operator login', async () => {
    process.env.NODE_ENV = 'production';
    process.env.NEXUSEDGE_ENV = 'production';
    process.env.CONTROL_PLANE_SERVICE_TOKEN = 'cp-dedicated-service-key-999';
    process.env.NEXUSEDGE_OPERATOR_TOKEN = 'human-operator-key-111';

    let capturedHeaders = null;
    const mockControlPlane = http.createServer((req, res) => {
      capturedHeaders = req.headers;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'healthy', version: '1.0.0' }));
    });
    await new Promise((resolve) => mockControlPlane.listen(0, '127.0.0.1', resolve));
    const cpPort = mockControlPlane.address().port;
    process.env.CONTROL_PLANE_URL = `http://127.0.0.1:${cpPort}`;

    delete require.cache[require.resolve('../server.js')];
    const server = require('../server.js');

    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;

    try {
      // 1. Attempting login with CONTROL_PLANE_SERVICE_TOKEN must fail
      const loginAttemptData = JSON.stringify({ token: 'cp-dedicated-service-key-999' });
      const failLoginRes = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/auth/login',
          method: 'POST',
          agent: false,
          headers: {
            'Connection': 'close',
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(loginAttemptData)
          }
        }, resolve);
        req.on('error', reject);
        req.write(loginAttemptData);
        req.end();
      });
      assert.strictEqual(failLoginRes.statusCode, 401, 'Control Plane service token must not allow operator login');
      failLoginRes.resume();

      // 2. Control plane proxy call must use CONTROL_PLANE_SERVICE_TOKEN
      const healthRes = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/health',
          method: 'GET',
          agent: false,
          headers: { 'Connection': 'close' }
        }, resolve);
        req.on('error', reject);
        req.end();
      });
      assert.strictEqual(healthRes.statusCode, 200);
      assert.strictEqual(capturedHeaders['x-api-key'], 'cp-dedicated-service-key-999');
      assert.strictEqual(capturedHeaders['authorization'], 'Bearer cp-dedicated-service-key-999');
      healthRes.resume();
    } finally {
      await safeClose(server);
      await safeClose(mockControlPlane);
    }
  });

  it('Requirement 4.3: Project-scoped AI credential mapping attaches correct key per project and rejects unmapped projects with 403', async () => {
    process.env.NODE_ENV = 'production';
    process.env.NEXUSEDGE_ENV = 'production';
    process.env.NEXUSEDGE_PROJECT_AI_KEYS = 'proj-fintech:ai-key-fintech-99,proj-core:ai-key-core-11';
    process.env.NEXUSEDGE_DASHBOARD_USERS = 'fintech-tok:user-fintech:TENANT_ADMIN:proj-fintech;core-tok:user-core:PLATFORM_OPERATOR:proj-core;unmapped-tok:user-guest:DEVELOPER:proj-unmapped';

    let capturedHeaders = null;
    const mockEdgeGateway = http.createServer((req, res) => {
      capturedHeaders = req.headers;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ choices: [{ message: { content: 'ok' } }] }));
    });
    await new Promise((resolve) => mockEdgeGateway.listen(0, '127.0.0.1', resolve));
    const edgePort = mockEdgeGateway.address().port;
    process.env.EDGE_GATEWAY_URL = `http://127.0.0.1:${edgePort}`;

    delete require.cache[require.resolve('../server.js')];
    const server = require('../server.js');

    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;

    const loginAndGetCookie = async (token) => {
      const data = JSON.stringify({ token });
      const res = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/auth/login',
          method: 'POST',
          agent: false,
          headers: {
            'Connection': 'close',
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(data)
          }
        }, resolve);
        req.on('error', reject);
        req.write(data);
        req.end();
      });
      assert.strictEqual(res.statusCode, 200);
      const cookie = res.headers['set-cookie'][0].split(';')[0];
      res.resume();
      return cookie;
    };

    const callInference = async (cookie) => {
      return new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/proxy/inference',
          method: 'POST',
          agent: false,
          headers: {
            'Connection': 'close',
            'Cookie': cookie,
            'Content-Type': 'application/json'
          }
        }, resolve);
        req.on('error', reject);
        req.write(JSON.stringify({ prompt: 'test' }));
        req.end();
      });
    };

    try {
      // 1. proj-fintech gets ai-key-fintech-99
      const fintechCookie = await loginAndGetCookie('fintech-tok');
      const res1 = await callInference(fintechCookie);
      assert.strictEqual(res1.statusCode, 200);
      assert.strictEqual(capturedHeaders['authorization'], 'Bearer ai-key-fintech-99');
      assert.strictEqual(capturedHeaders['x-nexusedge-project-id'], 'proj-fintech');
      res1.resume();

      // 2. proj-core gets ai-key-core-11
      const coreCookie = await loginAndGetCookie('core-tok');
      const res2 = await callInference(coreCookie);
      assert.strictEqual(res2.statusCode, 200);
      assert.strictEqual(capturedHeaders['authorization'], 'Bearer ai-key-core-11');
      assert.strictEqual(capturedHeaders['x-nexusedge-project-id'], 'proj-core');
      res2.resume();

      // 3. proj-unmapped has no key configured -> 403 Forbidden in production
      const unmappedCookie = await loginAndGetCookie('unmapped-tok');
      const res3 = await callInference(unmappedCookie);
      assert.strictEqual(res3.statusCode, 403, 'Unmapped project in production must receive 403 Forbidden');
      res3.resume();
    } finally {
      await safeClose(server);
      await safeClose(mockEdgeGateway);
    }
  });

  it('Requirement 4.4: Domain mutation RBAC strictly enforces allowlist (VIEWER, DEVELOPER, UNKNOWN rejected with 403; TENANT_ADMIN & PLATFORM_OPERATOR permitted)', async () => {
    process.env.NODE_ENV = 'production';
    process.env.NEXUSEDGE_ENV = 'production';
    process.env.NEXUSEDGE_DASHBOARD_USERS = [
      'tok-admin:admin@acme.com:TENANT_ADMIN:proj-acme',
      'tok-op:op@nexusedge.io:PLATFORM_OPERATOR:proj-core',
      'tok-dev:dev@acme.com:DEVELOPER:proj-acme',
      'tok-view:view@acme.com:VIEWER:proj-acme',
      'tok-unknown:unknown@acme.com:INVALID_ROLE:proj-acme'
    ].join(';');

    let capturedMethod = null;
    let capturedPath = null;
    const mockControlPlane = http.createServer((req, res) => {
      capturedMethod = req.method;
      capturedPath = req.url;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify([{ id: 'dom-1', hostname: 'test.example.com' }]));
    });
    await new Promise((resolve) => mockControlPlane.listen(0, '127.0.0.1', resolve));
    const cpPort = mockControlPlane.address().port;
    process.env.CONTROL_PLANE_URL = `http://127.0.0.1:${cpPort}`;

    delete require.cache[require.resolve('../server.js')];
    const server = require('../server.js');

    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;

    const loginAndGetCookie = async (token) => {
      const data = JSON.stringify({ token });
      const res = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/auth/login',
          method: 'POST',
          agent: false,
          headers: {
            'Connection': 'close',
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(data)
          }
        }, resolve);
        req.on('error', reject);
        req.write(data);
        req.end();
      });
      assert.strictEqual(res.statusCode, 200);
      const cookie = res.headers['set-cookie'][0].split(';')[0];
      res.resume();
      return cookie;
    };

    const callDomainAPI = async (cookie, method) => {
      return new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/proxy/domains',
          method: method,
          agent: false,
          headers: {
            'Connection': 'close',
            'Cookie': cookie,
            'Content-Type': 'application/json'
          }
        }, resolve);
        req.on('error', reject);
        if (method !== 'GET') {
          req.write(JSON.stringify({ hostname: 'new.example.com' }));
        }
        req.end();
      });
    };

    try {
      // 1. VIEWER can GET (200) but cannot POST (403)
      const viewCookie = await loginAndGetCookie('tok-view');
      const getResView = await callDomainAPI(viewCookie, 'GET');
      assert.strictEqual(getResView.statusCode, 200, 'VIEWER must be able to read domains');
      getResView.resume();

      const postResView = await callDomainAPI(viewCookie, 'POST');
      assert.strictEqual(postResView.statusCode, 403, 'VIEWER role must receive 403 Forbidden for domain mutation');
      postResView.resume();

      // 2. DEVELOPER can GET (200) but cannot POST (403)
      const devCookie = await loginAndGetCookie('tok-dev');
      const getResDev = await callDomainAPI(devCookie, 'GET');
      assert.strictEqual(getResDev.statusCode, 200, 'DEVELOPER must be able to read domains');
      getResDev.resume();

      const postResDev = await callDomainAPI(devCookie, 'POST');
      assert.strictEqual(postResDev.statusCode, 403, 'DEVELOPER role must receive 403 Forbidden for domain mutation');
      postResDev.resume();

      // 3. UNKNOWN role cannot mutate domains (403)
      const unknownCookie = await loginAndGetCookie('tok-unknown');
      const postResUnknown = await callDomainAPI(unknownCookie, 'POST');
      assert.strictEqual(postResUnknown.statusCode, 403, 'UNKNOWN role must receive 403 Forbidden for domain mutation');
      postResUnknown.resume();

      // 4. TENANT_ADMIN can mutate domains (200)
      const adminCookie = await loginAndGetCookie('tok-admin');
      const postResAdmin = await callDomainAPI(adminCookie, 'POST');
      assert.strictEqual(postResAdmin.statusCode, 200, 'TENANT_ADMIN must be permitted to mutate domains');
      postResAdmin.resume();

      // 5. PLATFORM_OPERATOR can mutate domains (200)
      const opCookie = await loginAndGetCookie('tok-op');
      const postResOp = await callDomainAPI(opCookie, 'POST');
      assert.strictEqual(postResOp.statusCode, 200, 'PLATFORM_OPERATOR must be permitted to mutate domains');
      postResOp.resume();
    } finally {
      await safeClose(server);
      await safeClose(mockControlPlane);
    }
  });

  it('Requirement 4.5: Downstream Control Plane requests include human actor attribution (X-Authenticated-Actor)', async () => {
    process.env.NODE_ENV = 'production';
    process.env.NEXUSEDGE_ENV = 'production';
    process.env.NEXUSEDGE_DASHBOARD_USERS = 'tok-alice:alice.engineer@corp.com:TENANT_ADMIN:proj-corp';

    let capturedHeaders = null;
    const mockControlPlane = http.createServer((req, res) => {
      capturedHeaders = req.headers;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify([]));
    });
    await new Promise((resolve) => mockControlPlane.listen(0, '127.0.0.1', resolve));
    const cpPort = mockControlPlane.address().port;
    process.env.CONTROL_PLANE_URL = `http://127.0.0.1:${cpPort}`;

    delete require.cache[require.resolve('../server.js')];
    const server = require('../server.js');

    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;

    try {
      const loginData = JSON.stringify({ token: 'tok-alice' });
      const loginRes = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/auth/login',
          method: 'POST',
          agent: false,
          headers: {
            'Connection': 'close',
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(loginData)
          }
        }, resolve);
        req.on('error', reject);
        req.write(loginData);
        req.end();
      });
      assert.strictEqual(loginRes.statusCode, 200);
      const cookie = loginRes.headers['set-cookie'][0].split(';')[0];
      loginRes.resume();

      const domainRes = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/proxy/domains',
          method: 'GET',
          agent: false,
          headers: {
            'Connection': 'close',
            'Cookie': cookie
          }
        }, resolve);
        req.on('error', reject);
        req.end();
      });
      assert.strictEqual(domainRes.statusCode, 200);
      assert.strictEqual(
        capturedHeaders['x-authenticated-actor'],
        'alice.engineer@corp.com',
        'Control plane proxy must include human actor identity for audit attribution'
      );
      assert.strictEqual(capturedHeaders['x-authenticated-role'], 'TENANT_ADMIN');
      assert.strictEqual(capturedHeaders['x-authenticated-project-id'], 'proj-corp');
      domainRes.resume();
    } finally {
      await safeClose(server);
      await safeClose(mockControlPlane);
    }
  });

  it('Requirement 4.6: Trusted proxy forwarding isolates rate limits across distinct client IPs', async () => {
    process.env.TRUSTED_PROXY_IPS = '127.0.0.1';
    delete require.cache[require.resolve('../server.js')];
    const server = require('../server.js');

    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;

    try {
      const sendLoginFrom = async (clientIp, token) => {
        const data = JSON.stringify({ token });
        return new Promise((resolve, reject) => {
          const req = http.request({
            hostname: '127.0.0.1',
            port: port,
            path: '/api/auth/login',
            method: 'POST',
            agent: false,
            headers: {
              'Connection': 'close',
              'Content-Type': 'application/json',
              'Content-Length': Buffer.byteLength(data),
              'X-Forwarded-For': clientIp
            }
          }, resolve);
          req.on('error', reject);
          req.write(data);
          req.end();
        });
      };

      // Client A exhausts rate limit (10 failed attempts)
      for (let i = 0; i < 10; i++) {
        const resA = await sendLoginFrom('203.0.113.10', `bad-token-${i}`);
        assert.strictEqual(resA.statusCode, 401);
        resA.resume();
      }

      // 11th attempt for Client A must be rate-limited (429)
      const resLimitA = await sendLoginFrom('203.0.113.10', 'bad-token-11');
      assert.strictEqual(resLimitA.statusCode, 429, 'Client A must be rate limited after 10 attempts');
      resLimitA.resume();

      // Client B from different IP must STILL be allowed (401 invalid creds, NOT 429)
      const resB = await sendLoginFrom('203.0.113.20', 'bad-token-client-b');
      assert.strictEqual(resB.statusCode, 401, 'Client B from distinct IP must have independent rate limit bucket');
      resB.resume();
    } finally {
      await safeClose(server);
    }
  });

  it('Requirement 11: Alert endpoints proxy correctly and enforce RBAC', async () => {
    process.env.NODE_ENV = 'production';
    process.env.NEXUSEDGE_ENV = 'production';
    process.env.NEXUSEDGE_OPERATOR_TOKEN = 'prod-operator-token-alerts';
    process.env.NEXUSEDGE_DASHBOARD_USERS = 'prod-viewer-token:viewer@test.com:VIEWER:proj-viewer';

    delete require.cache[require.resolve('../server.js')];
    const server = require('../server.js');

    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;

    try {
      // 1. Unauthenticated request to /api/proxy/alerts/status returns 401
      const resUnauth = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/proxy/alerts/status',
          method: 'GET',
          agent: false,
          headers: { 'Connection': 'close' }
        }, resolve);
        req.on('error', reject);
        req.end();
      });
      assert.strictEqual(resUnauth.statusCode, 401);
      resUnauth.resume();

      // 2. Login as VIEWER
      const loginViewerRes = await new Promise((resolve, reject) => {
        const data = JSON.stringify({ token: 'prod-viewer-token' });
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/auth/login',
          method: 'POST',
          agent: false,
          headers: {
            'Connection': 'close',
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(data)
          }
        }, resolve);
        req.on('error', reject);
        req.write(data);
        req.end();
      });
      const viewerCookie = loginViewerRes.headers['set-cookie'][0].split(';')[0];
      loginViewerRes.resume();

      // 3. VIEWER attempting POST /api/proxy/alerts/test must get 403 Forbidden
      const resViewerTest = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/proxy/alerts/test',
          method: 'POST',
          agent: false,
          headers: {
            'Connection': 'close',
            'Cookie': viewerCookie
          }
        }, resolve);
        req.on('error', reject);
        req.end();
      });
      assert.strictEqual(resViewerTest.statusCode, 403, 'VIEWER role must be rejected from triggering alert tests');
      resViewerTest.resume();
    } finally {
      await safeClose(server);
    }
  });

  it('Requirement 12: Multi-PoP & BGP endpoints proxy correctly and enforce RBAC', async () => {
    process.env.NODE_ENV = 'production';
    process.env.NEXUSEDGE_ENV = 'production';
    process.env.NEXUSEDGE_DASHBOARD_USERS = 'prod-viewer-token:viewer@nexusedge.io:VIEWER:proj-test;prod-op-token:op@nexusedge.io:PLATFORM_OPERATOR:proj-test';
    process.env.CONTROL_PLANE_SERVICE_TOKEN = 'cp-service-token';

    // Mock Upstream Control Plane for PoP endpoints
    const mockCP = http.createServer((req, res) => {
      if (req.url === '/v1/edge/pops' && req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
          total_pops: 4,
          pops: [
            { id: 'dhaka', name: 'Dhaka BDIX Edge 01', bgp_state: 'ANNOUNCED', status: 'ACTIVE' },
            { id: 'singapore', name: 'Singapore Equinix SG1', bgp_state: 'ANNOUNCED', status: 'ACTIVE' },
            { id: 'frankfurt', name: 'Frankfurt DE-CIX Edge 01', bgp_state: 'ANNOUNCED', status: 'ACTIVE' },
            { id: 'virginia', name: 'Virginia Equinix Ashburn DC2', bgp_state: 'ANNOUNCED', status: 'ACTIVE' }
          ]
        }));
      }
      if (req.url === '/v1/edge/pops/dhaka' && req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
          id: 'dhaka',
          name: 'Dhaka BDIX Edge 01',
          country: 'BD',
          bgp_state: 'ANNOUNCED',
          status: 'ACTIVE'
        }));
      }
      if (req.url === '/v1/edge/routing/matrix' && req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
          routes_count: 6,
          routes: [
            { from_pop: 'dhaka', to_target: 'singapore', latency_ms: 32.0, status: 'ACTIVE' },
            { from_pop: 'dhaka', to_target: 'frankfurt', latency_ms: 125.0, status: 'ACTIVE' },
            { from_pop: 'singapore', to_target: 'frankfurt', latency_ms: 145.0, status: 'ACTIVE' }
          ]
        }));
      }
      if (req.url === '/v1/edge/pops/dhaka/bgp/withdraw' && req.method === 'POST') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
          id: 'dhaka',
          bgp_state: 'WITHDRAWN',
          status: 'POP_DRAINING'
        }));
      }
      if (req.url === '/v1/edge/pops/dhaka/bgp/announce' && req.method === 'POST') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
          id: 'dhaka',
          bgp_state: 'ANNOUNCED',
          status: 'POP_ACTIVE'
        }));
      }
      if (req.url === '/v1/edge/pops/routes' && req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
          total_routes: 4,
          routes: [
            { pop_id: 'dhaka', region: 'asia-south1', primary_target: 'singapore', primary_rtt_ms: 32.0, status: 'OPTIMAL' },
            { pop_id: 'singapore', region: 'asia-southeast1', primary_target: 'frankfurt', primary_rtt_ms: 145.0, status: 'OPTIMAL' }
          ]
        }));
      }
      if (req.url === '/v1/edge/pops/health' && req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
          total_pops: 4,
          pops: [
            { pop_id: 'dhaka', healthy: true, status: 'OPTIMAL', ewma_latency_ms: 4.2, packet_loss_percent: 0.0 },
            { pop_id: 'singapore', healthy: true, status: 'OPTIMAL', ewma_latency_ms: 8.1, packet_loss_percent: 0.0 }
          ],
          timestamp: new Date().toISOString()
        }));
      }
      if (req.url === '/v1/edge/pops/health/probe' && req.method === 'POST') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
          total_probed: 4,
          results: [
            { pop_id: 'dhaka', success: true, latency_ms: 4.1, status_code: 200 },
            { pop_id: 'singapore', success: true, latency_ms: 8.0, status_code: 200 }
          ],
          timestamp: new Date().toISOString()
        }));
      }
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'not found' }));
    });

    await new Promise((resolve) => mockCP.listen(0, '127.0.0.1', resolve));
    process.env.CONTROL_PLANE_URL = `http://127.0.0.1:${mockCP.address().port}`;

    delete require.cache[require.resolve('../server.js')];
    const server = require('../server.js');
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;

    try {
      // 1. Unauthenticated requests to /api/proxy/pops and /api/proxy/pops/matrix return 401
      const resUnauthPops = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/proxy/pops',
          method: 'GET',
          agent: false,
          headers: { 'Connection': 'close' }
        }, resolve);
        req.on('error', reject);
        req.end();
      });
      assert.strictEqual(resUnauthPops.statusCode, 401);
      resUnauthPops.resume();

      const resUnauthMatrix = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/proxy/pops/matrix',
          method: 'GET',
          agent: false,
          headers: { 'Connection': 'close' }
        }, resolve);
        req.on('error', reject);
        req.end();
      });
      assert.strictEqual(resUnauthMatrix.statusCode, 401);
      resUnauthMatrix.resume();

      // 2. Login as VIEWER
      const loginViewerRes = await new Promise((resolve, reject) => {
        const data = JSON.stringify({ token: 'prod-viewer-token' });
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/auth/login',
          method: 'POST',
          agent: false,
          headers: {
            'Connection': 'close',
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(data)
          }
        }, resolve);
        req.on('error', reject);
        req.write(data);
        req.end();
      });
      const viewerCookie = loginViewerRes.headers['set-cookie'][0].split(';')[0];
      loginViewerRes.resume();

      // 3. VIEWER can read /api/proxy/pops and /api/proxy/pops/matrix
      const resViewerPops = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/proxy/pops',
          method: 'GET',
          agent: false,
          headers: {
            'Connection': 'close',
            'Cookie': viewerCookie
          }
        }, resolve);
        req.on('error', reject);
        req.end();
      });
      assert.strictEqual(resViewerPops.statusCode, 200);
      let viewerPopsBody = '';
      resViewerPops.on('data', chunk => { viewerPopsBody += chunk; });
      await new Promise(resolve => resViewerPops.on('end', resolve));
      const parsedPops = JSON.parse(viewerPopsBody);
      assert.strictEqual(parsedPops.total_pops, 4);

      // 4. VIEWER attempting to mutate BGP route state gets 403 Forbidden
      const resViewerBgp = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/proxy/pops/dhaka/bgp/withdraw',
          method: 'POST',
          agent: false,
          headers: {
            'Connection': 'close',
            'Cookie': viewerCookie
          }
        }, resolve);
        req.on('error', reject);
        req.end();
      });
      assert.strictEqual(resViewerBgp.statusCode, 403, 'VIEWER role must be rejected from modifying BGP state');
      resViewerBgp.resume();

      // 5. Login as PLATFORM_OPERATOR
      const loginOpRes = await new Promise((resolve, reject) => {
        const data = JSON.stringify({ token: 'prod-op-token' });
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/auth/login',
          method: 'POST',
          agent: false,
          headers: {
            'Connection': 'close',
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(data)
          }
        }, resolve);
        req.on('error', reject);
        req.write(data);
        req.end();
      });
      const opCookie = loginOpRes.headers['set-cookie'][0].split(';')[0];
      loginOpRes.resume();

      // 6. PLATFORM_OPERATOR can withdraw and announce BGP routes
      const resOpWithdraw = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/proxy/pops/dhaka/bgp/withdraw',
          method: 'POST',
          agent: false,
          headers: {
            'Connection': 'close',
            'Cookie': opCookie
          }
        }, resolve);
        req.on('error', reject);
        req.end();
      });
      assert.strictEqual(resOpWithdraw.statusCode, 200);
      let withdrawBody = '';
      resOpWithdraw.on('data', chunk => { withdrawBody += chunk; });
      await new Promise(resolve => resOpWithdraw.on('end', resolve));
      const withdrawData = JSON.parse(withdrawBody);
      assert.strictEqual(withdrawData.bgp_state, 'WITHDRAWN');

      const resOpAnnounce = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/proxy/pops/dhaka/bgp/announce',
          method: 'POST',
          agent: false,
          headers: {
            'Connection': 'close',
            'Cookie': opCookie
          }
        }, resolve);
        req.on('error', reject);
        req.end();
      });
      assert.strictEqual(resOpAnnounce.statusCode, 200);
      let announceBody = '';
      resOpAnnounce.on('data', chunk => { announceBody += chunk; });
      await new Promise(resolve => resOpAnnounce.on('end', resolve));
      // 7. Multi-PoP Live Routes & Health Telemetry
      const resViewerRoutes = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/proxy/pops/routes',
          method: 'GET',
          agent: false,
          headers: { 'Connection': 'close', 'Cookie': viewerCookie }
        }, resolve);
        req.on('error', reject);
        req.end();
      });
      assert.strictEqual(resViewerRoutes.statusCode, 200);
      let routesBody = '';
      resViewerRoutes.on('data', chunk => { routesBody += chunk; });
      await new Promise(resolve => resViewerRoutes.on('end', resolve));
      assert.strictEqual(JSON.parse(routesBody).total_routes, 4);

      const resViewerHealth = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/proxy/pops/health',
          method: 'GET',
          agent: false,
          headers: { 'Connection': 'close', 'Cookie': viewerCookie }
        }, resolve);
        req.on('error', reject);
        req.end();
      });
      assert.strictEqual(resViewerHealth.statusCode, 200);
      let healthBody = '';
      resViewerHealth.on('data', chunk => { healthBody += chunk; });
      await new Promise(resolve => resViewerHealth.on('end', resolve));
      assert.strictEqual(JSON.parse(healthBody).total_pops, 4);

      // 8. VIEWER attempting to trigger synthetic probe cycle gets 403 Forbidden
      const resViewerProbe = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/proxy/pops/health/probe',
          method: 'POST',
          agent: false,
          headers: { 'Connection': 'close', 'Cookie': viewerCookie }
        }, resolve);
        req.on('error', reject);
        req.end();
      });
      assert.strictEqual(resViewerProbe.statusCode, 403, 'VIEWER role must be rejected from triggering synthetic probes');
      resViewerProbe.resume();

      // 9. PLATFORM_OPERATOR can trigger synthetic probe cycle
      const resOpProbe = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/proxy/pops/health/probe',
          method: 'POST',
          agent: false,
          headers: { 'Connection': 'close', 'Cookie': opCookie }
        }, resolve);
        req.on('error', reject);
        req.end();
      });
      assert.strictEqual(resOpProbe.statusCode, 200, 'PLATFORM_OPERATOR must be permitted to trigger synthetic probes');
      let probeBody = '';
      resOpProbe.on('data', chunk => { probeBody += chunk; });
      await new Promise(resolve => resOpProbe.on('end', resolve));
      assert.strictEqual(JSON.parse(probeBody).total_probed, 4);

    } finally {
      await safeClose(server);
      await safeClose(mockCP);
    }
  });

  it('Requirement 13: Interactive Global Multi-PoP Topology Map & Telemetry HUD are present in frontend bundle', () => {
    const appJsContent = fs.readFileSync(appJsPath, 'utf8');
    const indexHtmlContent = fs.readFileSync(indexHtmlPath, 'utf8');
    const styleCssPath = path.join(publicDir, 'style.css');
    const styleCssContent = fs.readFileSync(styleCssPath, 'utf8');

    // 1. Verify SVG World Canvas and Subsea Cables in index.html
    const requiredSvgElements = [
      'topology-map-card',
      'topology-svg',
      'svg-cable-smw6',
      'svg-cable-tat14',
      'svg-node-dhaka',
      'svg-node-singapore',
      'svg-node-frankfurt',
      'svg-node-virginia',
      'map-sync-badge',
      'map-probe-status',
      'hud-dhaka',
      'hud-singapore',
      'hud-frankfurt',
      'hud-virginia'
    ];
    for (const elemId of requiredSvgElements) {
      assert.strictEqual(
        indexHtmlContent.includes(elemId),
        true,
        `Expected index.html to contain element "${elemId}"`
      );
    }

    // 2. Verify interactive JavaScript hooks in app.js
    assert.strictEqual(
      appJsContent.includes('function selectMapPoP(popId)'),
      true,
      'app.js must define selectMapPoP(popId)'
    );
    assert.strictEqual(
      appJsContent.includes('mapSyncBadge'),
      true,
      'app.js loadPoPTelemetry must update mapSyncBadge'
    );
    assert.strictEqual(
      appJsContent.includes('map-rtt-'),
      true,
      'app.js must dynamically bind EWMA RTT to map nodes'
    );
    assert.strictEqual(
      appJsContent.includes('hud-rtt-val-'),
      true,
      'app.js must dynamically bind EWMA RTT to HUD cards'
    );

    // 3. Verify high-tech styling in style.css
    assert.strictEqual(styleCssContent.includes('.topology-map-card'), true);
    assert.strictEqual(styleCssContent.includes('.cable-primary'), true);
    assert.strictEqual(styleCssContent.includes('.cable-transatlantic'), true);
    assert.strictEqual(styleCssContent.includes('.map-pulse-circle'), true);
    assert.strictEqual(styleCssContent.includes('.topology-hud-grid'), true);
  });

  it('Requirement 14: Cryptographic API Key Management Vault & View-Once Lifecycle', async () => {
    process.env.NODE_ENV = 'production';
    process.env.NEXUSEDGE_OPERATOR_TOKEN = 'prod-op-token';
    process.env.NEXUSEDGE_DASHBOARD_USERS = 'token-tenant-a:alice@client.com:TENANT_ADMIN:proj-alpha;token-tenant-b:bob@client.com:TENANT_ADMIN:proj-beta;token-viewer:charlie@client.com:VIEWER:proj-alpha';

    // Mock Upstream Control Plane
    const mockCP = http.createServer((cReq, cRes) => {
      if (cReq.url === '/v1/edge/pops') {
        cRes.writeHead(200, { 'Content-Type': 'application/json' });
        cRes.end(JSON.stringify({ pops: [{ pop_id: 'dhaka' }] }));
        return;
      }
      cRes.writeHead(404, { 'Content-Type': 'application/json' });
      cRes.end(JSON.stringify({ error: 'Not found' }));
    });

    await new Promise((resolve) => mockCP.listen(0, '127.0.0.1', resolve));
    const cpPort = mockCP.address().port;
    process.env.CONTROL_PLANE_URL = `http://127.0.0.1:${cpPort}`;

    delete require.cache[require.resolve('../server.js')];
    const server = require('../server.js');
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;

    try {
      // 1. Unauthenticated request to GET /api/proxy/api-keys is rejected with 401
      const resUnauth = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/proxy/api-keys',
          method: 'GET',
          agent: false,
          headers: { 'Connection': 'close' }
        }, resolve);
        req.on('error', reject);
        req.end();
      });
      assert.strictEqual(resUnauth.statusCode, 401);
      resUnauth.resume();

      // Login as VIEWER (charlie) in proj-alpha
      const loginViewerRes = await new Promise((resolve, reject) => {
        const data = JSON.stringify({ token: 'token-viewer' });
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/auth/login',
          method: 'POST',
          agent: false,
          headers: { 'Connection': 'close', 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) }
        }, resolve);
        req.on('error', reject);
        req.write(data);
        req.end();
      });
      const viewerCookie = loginViewerRes.headers['set-cookie'][0].split(';')[0];
      loginViewerRes.resume();

      // 2. VIEWER cannot generate API keys (403 Forbidden)
      const resViewerCreate = await new Promise((resolve, reject) => {
        const data = JSON.stringify({ name: 'Hacker Key' });
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/proxy/api-keys',
          method: 'POST',
          agent: false,
          headers: { 'Connection': 'close', 'Cookie': viewerCookie, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) }
        }, resolve);
        req.on('error', reject);
        req.write(data);
        req.end();
      });
      assert.strictEqual(resViewerCreate.statusCode, 403);
      resViewerCreate.resume();

      // Login as TENANT_ADMIN (alice) in proj-alpha
      const loginAliceRes = await new Promise((resolve, reject) => {
        const data = JSON.stringify({ token: 'token-tenant-a' });
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/auth/login',
          method: 'POST',
          agent: false,
          headers: { 'Connection': 'close', 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) }
        }, resolve);
        req.on('error', reject);
        req.write(data);
        req.end();
      });
      const aliceCookie = loginAliceRes.headers['set-cookie'][0].split(';')[0];
      loginAliceRes.resume();

      // 3. Non-operator cannot escalate role to PLATFORM_OPERATOR (403 Forbidden)
      const resEscalate = await new Promise((resolve, reject) => {
        const data = JSON.stringify({ name: 'Escalation Key', role: 'PLATFORM_OPERATOR' });
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/proxy/api-keys',
          method: 'POST',
          agent: false,
          headers: { 'Connection': 'close', 'Cookie': aliceCookie, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) }
        }, resolve);
        req.on('error', reject);
        req.write(data);
        req.end();
      });
      assert.strictEqual(resEscalate.statusCode, 403);
      resEscalate.resume();

      // 4. TENANT_ADMIN creates valid DEVELOPER API key
      const resAliceCreate = await new Promise((resolve, reject) => {
        const data = JSON.stringify({ name: 'Production Backend Ingestion', role: 'DEVELOPER' });
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/proxy/api-keys',
          method: 'POST',
          agent: false,
          headers: { 'Connection': 'close', 'Cookie': aliceCookie, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) }
        }, resolve);
        req.on('error', reject);
        req.write(data);
        req.end();
      });
      assert.strictEqual(resAliceCreate.statusCode, 201);
      let createBody = '';
      resAliceCreate.on('data', chunk => { createBody += chunk; });
      await new Promise(resolve => resAliceCreate.on('end', resolve));
      const createdKey = JSON.parse(createBody);
      assert.strictEqual(createdKey.project_id, 'proj-alpha');
      assert.strictEqual(createdKey.name, 'Production Backend Ingestion');
      assert.strictEqual(createdKey.secret_key.startsWith('nke_live_'), true);
      assert.strictEqual(createdKey.prefix.startsWith('nke_live_'), true);
      assert.strictEqual(createdKey.secret_key.length, 73);

      // Verify server vault only stores SHA-256 hash, NEVER plaintext secret key
      const vaultRecord = server.apiKeys.get(createdKey.id);
      assert.notStrictEqual(vaultRecord, undefined);
      assert.strictEqual(vaultRecord.secretKey, undefined);
      assert.strictEqual(vaultRecord.hashedSecret.length, 64);

      // 5. List keys via GET /api/proxy/api-keys: secret_key must be absent!
      const resAliceList = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/proxy/api-keys',
          method: 'GET',
          agent: false,
          headers: { 'Connection': 'close', 'Cookie': aliceCookie }
        }, resolve);
        req.on('error', reject);
        req.end();
      });
      assert.strictEqual(resAliceList.statusCode, 200);
      let listBody = '';
      resAliceList.on('data', chunk => { listBody += chunk; });
      await new Promise(resolve => resAliceList.on('end', resolve));
      const keyList = JSON.parse(listBody).keys;
      assert.strictEqual(keyList.length, 1);
      assert.strictEqual(keyList[0].secret_key, undefined);
      assert.strictEqual(keyList[0].id, createdKey.id);
      assert.strictEqual(keyList[0].status, 'ACTIVE');

      // 6. Authenticate request using generated API Key in Authorization Bearer header
      const resAuthBearer = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/proxy/pops',
          method: 'GET',
          agent: false,
          headers: { 'Connection': 'close', 'Authorization': `Bearer ${createdKey.secret_key}` }
        }, resolve);
        req.on('error', reject);
        req.end();
      });
      assert.strictEqual(resAuthBearer.statusCode, 200);
      resAuthBearer.resume();

      // 7. Authenticate request using X-API-Key header
      const resAuthHeader = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/proxy/pops',
          method: 'GET',
          agent: false,
          headers: { 'Connection': 'close', 'X-API-Key': createdKey.secret_key }
        }, resolve);
        req.on('error', reject);
        req.end();
      });
      assert.strictEqual(resAuthHeader.statusCode, 200);
      resAuthHeader.resume();

      // Login as TENANT_ADMIN (bob) in proj-beta
      const loginBobRes = await new Promise((resolve, reject) => {
        const data = JSON.stringify({ token: 'token-tenant-b' });
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/auth/login',
          method: 'POST',
          agent: false,
          headers: { 'Connection': 'close', 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) }
        }, resolve);
        req.on('error', reject);
        req.write(data);
        req.end();
      });
      const bobCookie = loginBobRes.headers['set-cookie'][0].split(';')[0];
      loginBobRes.resume();

      // 8. Multi-tenant isolation: Bob in proj-beta cannot revoke Alice's key in proj-alpha (403 Forbidden)
      const resBobRevoke = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: `/api/proxy/api-keys/${createdKey.id}`,
          method: 'DELETE',
          agent: false,
          headers: { 'Connection': 'close', 'Cookie': bobCookie }
        }, resolve);
        req.on('error', reject);
        req.end();
      });
      assert.strictEqual(resBobRevoke.statusCode, 403);
      resBobRevoke.resume();

      // 9. Alice successfully revokes her own key
      const resAliceRevoke = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: `/api/proxy/api-keys/${createdKey.id}`,
          method: 'DELETE',
          agent: false,
          headers: { 'Connection': 'close', 'Cookie': aliceCookie }
        }, resolve);
        req.on('error', reject);
        req.end();
      });
      assert.strictEqual(resAliceRevoke.statusCode, 200);
      let revokeBody = '';
      resAliceRevoke.on('data', chunk => { revokeBody += chunk; });
      await new Promise(resolve => resAliceRevoke.on('end', resolve));
      assert.strictEqual(JSON.parse(revokeBody).status, 'REVOKED');

      // 10. Subsequent requests using revoked API Key are immediately rejected with 401
      const resRevokedCall = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/proxy/pops',
          method: 'GET',
          agent: false,
          headers: { 'Connection': 'close', 'Authorization': `Bearer ${createdKey.secret_key}` }
        }, resolve);
        req.on('error', reject);
        req.end();
      });
      assert.strictEqual(resRevokedCall.statusCode, 401);
      resRevokedCall.resume();

    } finally {
      await safeClose(server);
      await safeClose(mockCP);
    }
  });

  it('Requirement 15: Developer API Key UI elements & view-once modals are wired in frontend bundle', () => {
    const appJsContent = fs.readFileSync(appJsPath, 'utf8');
    const indexHtmlContent = fs.readFileSync(indexHtmlPath, 'utf8');

    assert.strictEqual(indexHtmlContent.includes('api-keys-tbody'), true, 'index.html must define #api-keys-tbody');
    assert.strictEqual(indexHtmlContent.includes('modal-new-api-key'), true, 'index.html must define #modal-new-api-key');
    assert.strictEqual(indexHtmlContent.includes('modal-key-revealed'), true, 'index.html must define #modal-key-revealed');
    assert.strictEqual(indexHtmlContent.includes('revealed-secret-key'), true, 'index.html must define #revealed-secret-key');

    assert.strictEqual(appJsContent.includes('function openNewKeyModal()'), true, 'app.js must define openNewKeyModal()');
    assert.strictEqual(appJsContent.includes('function loadAPIKeys()'), true, 'app.js must define loadAPIKeys()');
    assert.strictEqual(appJsContent.includes('function submitNewAPIKey()'), true, 'app.js must define submitNewAPIKey()');
    assert.strictEqual(appJsContent.includes('function copyRevealedSecretKey()'), true, 'app.js must define copyRevealedSecretKey()');
    assert.strictEqual(appJsContent.includes('function revokeAPIKey('), true, 'app.js must define revokeAPIKey()');
  });

  it('Requirement 16: Custom Domain Onboarding & Live DNS Verification Proxying', async () => {
    process.env.NODE_ENV = 'production';
    process.env.NEXUSEDGE_OPERATOR_TOKEN = 'prod-op-token';
    process.env.NEXUSEDGE_DASHBOARD_USERS = 'token-tenant-a:alice@client.com:TENANT_ADMIN:proj-alpha;token-tenant-b:bob@client.com:TENANT_ADMIN:proj-beta;token-viewer:charlie@client.com:VIEWER:proj-alpha';

    let lastForwardedHeaders = {};
    let lastForwardedPath = '';

    // Mock Upstream Control Plane for Domain Lifecycle
    const mockCP = http.createServer((cReq, cRes) => {
      lastForwardedHeaders = { ...cReq.headers };
      lastForwardedPath = cReq.url;

      // POST /v1/projects/proj-alpha/domains (Onboard Domain)
      if (cReq.method === 'POST' && cReq.url === '/v1/projects/proj-alpha/domains') {
        let body = '';
        cReq.on('data', chunk => { body += chunk; });
        cReq.on('end', () => {
          const parsed = JSON.parse(body);
          cRes.writeHead(201, { 'Content-Type': 'application/json' });
          cRes.end(JSON.stringify({
            domain_id: 'dom-alpha-001',
            hostname: parsed.hostname,
            cname_target: 'dom-alpha-001.edge.nexusedge.net',
            verification_token: 'nke-verify-token-alpha-001',
            status: 'pending_verification',
            allowed_pops: parsed.allowed_pops || ['dhaka', 'singapore']
          }));
        });
        return;
      }

      // POST /v1/domains/dom-alpha-001/verify (DNS Verification)
      if (cReq.method === 'POST' && cReq.url.startsWith('/v1/domains/dom-alpha-001/verify')) {
        // IDOR check simulation
        const callerProj = cReq.headers['x-authenticated-project-id'];
        const callerRole = cReq.headers['x-authenticated-role'];
        if (callerRole !== 'PLATFORM_OPERATOR' && callerProj !== 'proj-alpha') {
          cRes.writeHead(403, { 'Content-Type': 'application/json' });
          cRes.end(JSON.stringify({ error: 'Forbidden: caller not authorized for domain' }));
          return;
        }

        const isForce = cReq.url.includes('force=true');
        cRes.writeHead(200, { 'Content-Type': 'application/json' });
        cRes.end(JSON.stringify({
          status: 'verified',
          domain_id: 'dom-alpha-001',
          hostname: 'api.alpha.com',
          state: 'active',
          message: isForce ? 'domain force-verified by platform operator' : 'domain verified successfully; active on edge proxy'
        }));
        return;
      }

      // GET /v1/domains/dom-alpha-001
      if (cReq.method === 'GET' && cReq.url === '/v1/domains/dom-alpha-001') {
        cRes.writeHead(200, { 'Content-Type': 'application/json' });
        cRes.end(JSON.stringify({
          id: 'dom-alpha-001',
          project_id: 'proj-alpha',
          hostname: 'api.alpha.com',
          status: 'active',
          cname_target: 'dom-alpha-001.edge.nexusedge.net'
        }));
        return;
      }

      // DELETE /v1/domains/dom-alpha-001
      if (cReq.method === 'DELETE' && cReq.url === '/v1/domains/dom-alpha-001') {
        const callerProj = cReq.headers['x-authenticated-project-id'];
        const callerRole = cReq.headers['x-authenticated-role'];
        if (callerRole !== 'PLATFORM_OPERATOR' && callerProj !== 'proj-alpha') {
          cRes.writeHead(403, { 'Content-Type': 'application/json' });
          cRes.end(JSON.stringify({ error: 'Forbidden: caller not authorized for domain' }));
          return;
        }
        cRes.writeHead(200, { 'Content-Type': 'application/json' });
        cRes.end(JSON.stringify({ status: 'deleted', domain_id: 'dom-alpha-001' }));
        return;
      }

      cRes.writeHead(404, { 'Content-Type': 'application/json' });
      cRes.end(JSON.stringify({ error: 'Not found in mock control plane' }));
    });

    await new Promise((resolve) => mockCP.listen(0, '127.0.0.1', resolve));
    const cpPort = mockCP.address().port;
    process.env.CONTROL_PLANE_URL = `http://127.0.0.1:${cpPort}`;

    delete require.cache[require.resolve('../server')];
    const server = require('../server');
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;

    try {
      // 1. Unauthenticated request to verify domain returns 401
      const resUnauthVerify = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/proxy/domains/dom-alpha-001/verify',
          method: 'POST',
          agent: false,
          headers: { 'Connection': 'close' }
        }, resolve);
        req.on('error', reject);
        req.end();
      });
      assert.strictEqual(resUnauthVerify.statusCode, 401);
      resUnauthVerify.resume();

      // Login as VIEWER (charlie) in proj-alpha
      const loginViewerRes = await new Promise((resolve, reject) => {
        const data = JSON.stringify({ token: 'token-viewer' });
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/auth/login',
          method: 'POST',
          agent: false,
          headers: { 'Connection': 'close', 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) }
        }, resolve);
        req.on('error', reject);
        req.write(data);
        req.end();
      });
      const viewerCookie = loginViewerRes.headers['set-cookie'][0].split(';')[0];
      loginViewerRes.resume();

      // 2. VIEWER cannot verify domains (403 Forbidden)
      const resViewerVerify = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/proxy/domains/dom-alpha-001/verify',
          method: 'POST',
          agent: false,
          headers: { 'Connection': 'close', 'Cookie': viewerCookie }
        }, resolve);
        req.on('error', reject);
        req.end();
      });
      assert.strictEqual(resViewerVerify.statusCode, 403);
      resViewerVerify.resume();

      // Login as TENANT_ADMIN (alice) in proj-alpha
      const loginAliceRes = await new Promise((resolve, reject) => {
        const data = JSON.stringify({ token: 'token-tenant-a' });
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/auth/login',
          method: 'POST',
          agent: false,
          headers: { 'Connection': 'close', 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) }
        }, resolve);
        req.on('error', reject);
        req.write(data);
        req.end();
      });
      const aliceCookie = loginAliceRes.headers['set-cookie'][0].split(';')[0];
      loginAliceRes.resume();

      // 3. Alice onboards custom domain via POST /api/proxy/domains
      const resAliceOnboard = await new Promise((resolve, reject) => {
        const data = JSON.stringify({
          hostname: 'api.alpha.com',
          origin_address: '203.0.113.195',
          origin_port: 443,
          origin_protocol: 'https',
          allowed_pops: ['dhaka', 'singapore']
        });
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/proxy/domains',
          method: 'POST',
          agent: false,
          headers: { 'Connection': 'close', 'Cookie': aliceCookie, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) }
        }, resolve);
        req.on('error', reject);
        req.write(data);
        req.end();
      });
      assert.strictEqual(resAliceOnboard.statusCode, 201);
      let onboardBody = '';
      resAliceOnboard.on('data', chunk => { onboardBody += chunk; });
      await new Promise(resolve => resAliceOnboard.on('end', resolve));
      const onboardResult = JSON.parse(onboardBody);
      assert.strictEqual(onboardResult.domain_id, 'dom-alpha-001');
      assert.strictEqual(onboardResult.cname_target, 'dom-alpha-001.edge.nexusedge.net');
      assert.strictEqual(onboardResult.status, 'pending_verification');
      assert.strictEqual(lastForwardedPath, '/v1/projects/proj-alpha/domains');
      assert.strictEqual(lastForwardedHeaders['x-authenticated-project-id'], 'proj-alpha');

      // 4. Alice verifies DNS via POST /api/proxy/domains/:id/verify
      const resAliceVerify = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/proxy/domains/dom-alpha-001/verify',
          method: 'POST',
          agent: false,
          headers: { 'Connection': 'close', 'Cookie': aliceCookie }
        }, resolve);
        req.on('error', reject);
        req.end();
      });
      assert.strictEqual(resAliceVerify.statusCode, 200);
      let verifyBody = '';
      resAliceVerify.on('data', chunk => { verifyBody += chunk; });
      await new Promise(resolve => resAliceVerify.on('end', resolve));
      const verifyResult = JSON.parse(verifyBody);
      assert.strictEqual(verifyResult.status, 'verified');
      assert.strictEqual(verifyResult.state, 'active');
      assert.strictEqual(lastForwardedPath, '/v1/domains/dom-alpha-001/verify');

      // Login as TENANT_ADMIN (bob) in proj-beta
      const loginBobRes = await new Promise((resolve, reject) => {
        const data = JSON.stringify({ token: 'token-tenant-b' });
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/auth/login',
          method: 'POST',
          agent: false,
          headers: { 'Connection': 'close', 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) }
        }, resolve);
        req.on('error', reject);
        req.write(data);
        req.end();
      });
      const bobCookie = loginBobRes.headers['set-cookie'][0].split(';')[0];
      loginBobRes.resume();

      // 5. Bob (proj-beta) is rejected with 403 when trying to verify Alice's domain (proj-alpha)
      const resBobVerify = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/proxy/domains/dom-alpha-001/verify',
          method: 'POST',
          agent: false,
          headers: { 'Connection': 'close', 'Cookie': bobCookie }
        }, resolve);
        req.on('error', reject);
        req.end();
      });
      assert.strictEqual(resBobVerify.statusCode, 403);
      resBobVerify.resume();

      // 6. Alice deletes her domain via DELETE /api/proxy/domains/dom-alpha-001
      const resAliceDelete = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/proxy/domains/dom-alpha-001',
          method: 'DELETE',
          agent: false,
          headers: { 'Connection': 'close', 'Cookie': aliceCookie }
        }, resolve);
        req.on('error', reject);
        req.end();
      });
      assert.strictEqual(resAliceDelete.statusCode, 200);
      resAliceDelete.resume();

    } finally {
      await safeClose(server);
      await safeClose(mockCP);
    }
  });

  it('Requirement 17: Custom Domain Onboarding & DNS Verification UI Components', () => {
    const appJsContent = fs.readFileSync(appJsPath, 'utf8');
    const indexHtmlContent = fs.readFileSync(indexHtmlPath, 'utf8');

    // index.html structural elements
    assert.strictEqual(indexHtmlContent.includes('new-domain-modal'), true, 'index.html must define #new-domain-modal');
    assert.strictEqual(indexHtmlContent.includes('modal-domain-origin'), true, 'index.html must define #modal-domain-origin');
    assert.strictEqual(indexHtmlContent.includes('modal-domain-port'), true, 'index.html must define #modal-domain-port');
    assert.strictEqual(indexHtmlContent.includes('modal-domain-proto'), true, 'index.html must define #modal-domain-proto');
    assert.strictEqual(indexHtmlContent.includes('modal-domain-dns-instructions'), true, 'index.html must define #modal-domain-dns-instructions');
    assert.strictEqual(indexHtmlContent.includes('dns-wizard-cname-host'), true, 'index.html must define #dns-wizard-cname-host');
    assert.strictEqual(indexHtmlContent.includes('dns-wizard-cname-target'), true, 'index.html must define #dns-wizard-cname-target');
    assert.strictEqual(indexHtmlContent.includes('dns-wizard-txt-name'), true, 'index.html must define #dns-wizard-txt-name');
    assert.strictEqual(indexHtmlContent.includes('dns-wizard-txt-token'), true, 'index.html must define #dns-wizard-txt-token');
    assert.strictEqual(indexHtmlContent.includes('btn-wizard-verify-now'), true, 'index.html must define #btn-wizard-verify-now');

    // app.js helper and proxy functions
    assert.strictEqual(appJsContent.includes('function loadDomains()'), true, 'app.js must define loadDomains()');
    assert.strictEqual(appJsContent.includes('function submitNewDomain()'), true, 'app.js must define submitNewDomain()');
    assert.strictEqual(appJsContent.includes('function openDomainDnsModal('), true, 'app.js must define openDomainDnsModal()');
    assert.strictEqual(appJsContent.includes('function copyDnsWizardTarget()'), true, 'app.js must define copyDnsWizardTarget()');
    assert.strictEqual(appJsContent.includes('function copyDnsWizardToken()'), true, 'app.js must define copyDnsWizardToken()');
    assert.strictEqual(appJsContent.includes('function triggerWizardVerify()'), true, 'app.js must define triggerWizardVerify()');
    assert.strictEqual(appJsContent.includes('function verifyDomain('), true, 'app.js must define verifyDomain()');
    assert.strictEqual(appJsContent.includes('function deleteDomain('), true, 'app.js must define deleteDomain()');
  });

  it('Requirement 18: Real-Time Telemetry Aggregation & API Key Token-Bucket Rate Limiting', async () => {
    process.env.NODE_ENV = 'production';
    process.env.NEXUSEDGE_OPERATOR_TOKEN = 'prod-op-token';

    const mockCP = http.createServer((cReq, cRes) => {
      if (cReq.url === '/v1/edge/pops') {
        cRes.writeHead(200, { 'Content-Type': 'application/json' });
        cRes.end(JSON.stringify({ pops: [] }));
        return;
      }
      cRes.writeHead(404);
      cRes.end();
    });

    await new Promise((resolve) => mockCP.listen(0, '127.0.0.1', resolve));
    const cpPort = mockCP.address().port;
    process.env.CONTROL_PLANE_URL = `http://127.0.0.1:${cpPort}`;

    delete require.cache[require.resolve('../server')];
    const server = require('../server');
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;

    try {
      // 1. Setup a valid API Key for DEVELOPER (capacity: 60)
      const crypto = require('crypto');
      const secretKey = 'nke_live_test_ratelimit_secret_abc123';
      const keyId = 'key-test-ratelimit-01';
      const hashedSecret = crypto.createHash('sha256').update(secretKey).digest('hex');

      server.apiKeys.set(keyId, {
        id: keyId,
        projectId: 'proj-alpha',
        name: 'Rate Limit Test Key',
        prefix: 'nke_live_test...',
        hashedSecret,
        role: 'DEVELOPER',
        scopes: ['inference'],
        createdAt: new Date().toISOString(),
        lastUsedAt: null,
        status: 'ACTIVE'
      });

      // 2. Initial request must succeed and return standard rate limit headers
      const resInit = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/proxy/pops',
          method: 'GET',
          agent: false,
          headers: { 'Connection': 'close', 'Authorization': `Bearer ${secretKey}` }
        }, resolve);
        req.on('error', reject);
        req.end();
      });
      assert.strictEqual(resInit.statusCode, 200);
      assert.strictEqual(resInit.headers['x-ratelimit-limit'], '60');
      assert.strictEqual(Number(resInit.headers['x-ratelimit-remaining']) <= 59, true);
      resInit.resume();

      // 3. Exhaust bucket tokens to test 429 Too Many Requests
      const bucket = server.apiKeyBuckets.get(keyId);
      assert.notStrictEqual(bucket, undefined);
      bucket.tokens = 0.2; // Insufficient for next request

      const res429 = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/proxy/pops',
          method: 'GET',
          agent: false,
          headers: { 'Connection': 'close', 'Authorization': `Bearer ${secretKey}` }
        }, resolve);
        req.on('error', reject);
        req.end();
      });

      assert.strictEqual(res429.statusCode, 429, 'Exhausted token bucket must return HTTP 429');
      assert.strictEqual(res429.headers['retry-after'], '1');
      assert.strictEqual(res429.headers['x-ratelimit-limit'], '60');
      assert.strictEqual(res429.headers['x-ratelimit-remaining'], '0');

      let body429 = '';
      res429.on('data', c => { body429 += c; });
      await new Promise(r => res429.on('end', r));
      const json429 = JSON.parse(body429);
      assert.strictEqual(json429.code, 429);
      assert.strictEqual(json429.error.includes('Rate limit exceeded'), true);

      // 4. Refill bucket tokens and verify subsequent request succeeds
      bucket.tokens = 10;
      const resRecover = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/proxy/pops',
          method: 'GET',
          agent: false,
          headers: { 'Connection': 'close', 'Authorization': `Bearer ${secretKey}` }
        }, resolve);
        req.on('error', reject);
        req.end();
      });
      assert.strictEqual(resRecover.statusCode, 200);
      assert.strictEqual(Number(resRecover.headers['x-ratelimit-remaining']), 9);
      resRecover.resume();

      // 5. Test Sliding-Window Telemetry Calculations
      server.telemetryBuffer.length = 0; // Clear buffer
      const now = Date.now();

      // 7 successful requests with varied latencies
      [5, 10, 15, 20, 25, 30, 35].forEach(lat => {
        server.recordTelemetry({
          timestamp: now,
          projectId: 'proj-alpha',
          path: '/api/proxy/pops',
          method: 'GET',
          statusCode: 200,
          durationMs: lat,
          clientIp: '127.0.0.1',
          pop: 'dhaka',
          cacheHit: true
        });
      });

      // 2 blocked requests (403 and 429)
      [40, 50].forEach(lat => {
        server.recordTelemetry({
          timestamp: now,
          projectId: 'proj-alpha',
          path: '/api/proxy/pops',
          method: 'GET',
          statusCode: 403,
          durationMs: lat,
          clientIp: '127.0.0.1',
          pop: 'singapore',
          cacheHit: false
        });
      });

      // 1 gateway failure (502)
      server.recordTelemetry({
        timestamp: now,
        projectId: 'proj-alpha',
        path: '/api/proxy/pops',
        method: 'GET',
        statusCode: 502,
        durationMs: 100,
        clientIp: '127.0.0.1',
        pop: 'frankfurt',
        cacheHit: false
      });

      const summary = server.getTelemetrySummary('proj-alpha');
      assert.strictEqual(summary.total_requests, 10);
      assert.strictEqual(summary.status_distribution['2xx'], 7);
      assert.strictEqual(summary.status_distribution['4xx'], 2);
      assert.strictEqual(summary.status_distribution['5xx'], 1);
      assert.strictEqual(summary.threat_blocks, 2);
      assert.strictEqual(summary.cache_hit_ratio, 0.7);
      assert.strictEqual(summary.success_rate, 0.7);
      assert.strictEqual(summary.p50_latency_ms, 25);
      assert.strictEqual(summary.p95_latency_ms, 50);
      assert.strictEqual(summary.p99_latency_ms, 100);
      assert.strictEqual(summary.pop_distribution.dhaka, 7);
      assert.strictEqual(summary.pop_distribution.singapore, 2);
      assert.strictEqual(summary.pop_distribution.frankfurt, 1);
      assert.strictEqual(summary.pop_distribution.virginia, 0);

    } finally {
      await safeClose(server);
      await safeClose(mockCP);
    }
  });

  it('Requirement 19: Analytics Summary Multi-Tenant Scoping & UI Wiring', async () => {
    process.env.NODE_ENV = 'production';
    process.env.NEXUSEDGE_OPERATOR_TOKEN = 'prod-op-token';
    process.env.NEXUSEDGE_DASHBOARD_USERS = 'token-alice:alice@client.com:TENANT_ADMIN:proj-alpha;token-bob:bob@client.com:TENANT_ADMIN:proj-beta';

    delete require.cache[require.resolve('../server')];
    const server = require('../server');
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;

    try {
      // 1. Unauthenticated request to /api/proxy/analytics/summary returns 401
      const resUnauth = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/proxy/analytics/summary',
          method: 'GET',
          agent: false,
          headers: { 'Connection': 'close' }
        }, resolve);
        req.on('error', reject);
        req.end();
      });
      assert.strictEqual(resUnauth.statusCode, 401);
      resUnauth.resume();

      // Login as Alice (proj-alpha)
      const loginAliceRes = await new Promise((resolve, reject) => {
        const data = JSON.stringify({ token: 'token-alice' });
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/auth/login',
          method: 'POST',
          agent: false,
          headers: { 'Connection': 'close', 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) }
        }, resolve);
        req.on('error', reject);
        req.write(data);
        req.end();
      });
      const aliceCookie = loginAliceRes.headers['set-cookie'][0].split(';')[0];
      loginAliceRes.resume();

      // 2. Alice cannot query Bob's project telemetry (403 Forbidden)
      const resCrossTenant = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/proxy/analytics/summary?project_id=proj-beta',
          method: 'GET',
          agent: false,
          headers: { 'Connection': 'close', 'Cookie': aliceCookie }
        }, resolve);
        req.on('error', reject);
        req.end();
      });
      assert.strictEqual(resCrossTenant.statusCode, 403);
      resCrossTenant.resume();

      // 3. Seed telemetry for both Alice (proj-alpha) and Bob (proj-beta)
      server.telemetryBuffer.length = 0;
      server.recordTelemetry({ timestamp: Date.now(), projectId: 'proj-alpha', path: '/api/v1', method: 'GET', statusCode: 200, durationMs: 12, clientIp: '127.0.0.1', pop: 'dhaka', cacheHit: true });
      server.recordTelemetry({ timestamp: Date.now(), projectId: 'proj-beta', path: '/api/v1', method: 'GET', statusCode: 500, durationMs: 99, clientIp: '127.0.0.1', pop: 'singapore', cacheHit: false });

      // Alice queries her own analytics summary
      const resAliceSummary = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: '/api/proxy/analytics/summary',
          method: 'GET',
          agent: false,
          headers: { 'Connection': 'close', 'Cookie': aliceCookie }
        }, resolve);
        req.on('error', reject);
        req.end();
      });
      assert.strictEqual(resAliceSummary.statusCode, 200);
      let aliceBody = '';
      resAliceSummary.on('data', c => { aliceBody += c; });
      await new Promise(r => resAliceSummary.on('end', r));
      const aliceJson = JSON.parse(aliceBody);
      assert.strictEqual(aliceJson.project_id, 'proj-alpha');
      assert.strictEqual(aliceJson.total_requests, 1);
      assert.strictEqual(aliceJson.status_distribution['2xx'], 1);
      assert.strictEqual(aliceJson.status_distribution['5xx'], 0); // Bob's 5xx error must NOT leak to Alice!

      // 4. Verify UI HTML & JS Components
      const appJsContent = fs.readFileSync(appJsPath, 'utf8');
      const indexHtmlContent = fs.readFileSync(indexHtmlPath, 'utf8');

      assert.strictEqual(indexHtmlContent.includes('analytics-total-requests'), true, 'index.html must define #analytics-total-requests');
      assert.strictEqual(indexHtmlContent.includes('analytics-latency-p50'), true, 'index.html must define #analytics-latency-p50');
      assert.strictEqual(indexHtmlContent.includes('analytics-latency-p99'), true, 'index.html must define #analytics-latency-p99');
      assert.strictEqual(indexHtmlContent.includes('analytics-cache-hit-ratio'), true, 'index.html must define #analytics-cache-hit-ratio');
      assert.strictEqual(indexHtmlContent.includes('analytics-threat-blocks'), true, 'index.html must define #analytics-threat-blocks');
      assert.strictEqual(indexHtmlContent.includes('analytics-status-2xx'), true, 'index.html must define #analytics-status-2xx');
      assert.strictEqual(indexHtmlContent.includes('analytics-pop-breakdown'), true, 'index.html must define #analytics-pop-breakdown');
      assert.strictEqual(indexHtmlContent.includes('btn-refresh-analytics'), true, 'index.html must define #btn-refresh-analytics');

      assert.strictEqual(appJsContent.includes('async function loadAnalytics()'), true, 'app.js must define async function loadAnalytics()');
      assert.strictEqual(appJsContent.includes('window.loadAnalytics = loadAnalytics;'), true, 'app.js must expose window.loadAnalytics');

    } finally {
      await safeClose(server);
    }
  });

  it('Requirement 20: Developer Quickstart, SDK Navigation & Code Generator Components', () => {
    const appJsContent = fs.readFileSync(appJsPath, 'utf8');
    const indexHtmlContent = fs.readFileSync(indexHtmlPath, 'utf8');

    // 1. Verify navigation and view containers
    assert.strictEqual(indexHtmlContent.includes('data-view="developers"'), true, 'index.html must define data-view="developers"');
    assert.strictEqual(indexHtmlContent.includes('id="view-developers"'), true, 'index.html must define #view-developers');

    // 2. Verify interactive generator controls
    assert.strictEqual(indexHtmlContent.includes('id="qs-key-select"'), true, 'index.html must define #qs-key-select');
    assert.strictEqual(indexHtmlContent.includes('id="qs-model-select"'), true, 'index.html must define #qs-model-select');
    assert.strictEqual(indexHtmlContent.includes('id="qs-strategy-select"'), true, 'index.html must define #qs-strategy-select');
    assert.strictEqual(indexHtmlContent.includes('id="qs-jurisdiction-select"'), true, 'index.html must define #qs-jurisdiction-select');

    // 3. Verify language tabs and action buttons
    assert.strictEqual(indexHtmlContent.includes('id="qs-tab-curl"'), true, 'index.html must define #qs-tab-curl');
    assert.strictEqual(indexHtmlContent.includes('id="qs-tab-ts"'), true, 'index.html must define #qs-tab-ts');
    assert.strictEqual(indexHtmlContent.includes('id="qs-tab-python"'), true, 'index.html must define #qs-tab-python');
    assert.strictEqual(indexHtmlContent.includes('id="qs-copy-btn"'), true, 'index.html must define #qs-copy-btn');
    assert.strictEqual(indexHtmlContent.includes('id="qs-run-btn"'), true, 'index.html must define #qs-run-btn');
    assert.strictEqual(indexHtmlContent.includes('id="qs-code-output"'), true, 'index.html must define #qs-code-output');

    // 4. Verify JavaScript methods in app.js
    assert.strictEqual(appJsContent.includes('function switchQuickstartTab'), true, 'app.js must define switchQuickstartTab');
    assert.strictEqual(appJsContent.includes('function populateQuickstartKeySelect'), true, 'app.js must define populateQuickstartKeySelect');
    assert.strictEqual(appJsContent.includes('function renderQuickstartSnippets'), true, 'app.js must define renderQuickstartSnippets');
    assert.strictEqual(appJsContent.includes('function copyQuickstartSnippet'), true, 'app.js must define copyQuickstartSnippet');
    assert.strictEqual(appJsContent.includes('async function runQuickstartTest'), true, 'app.js must define runQuickstartTest');
  });

  it('Requirement 21: Sovereignty & Workload Placement UI, Simulator & BFF Proxy Endpoints', () => {
    const appJsContent = fs.readFileSync(appJsPath, 'utf8');
    const indexHtmlContent = fs.readFileSync(indexHtmlPath, 'utf8');
    const serverJsContent = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');

    // 1. Verify navigation and view containers
    assert.strictEqual(indexHtmlContent.includes('data-view="sovereignty"'), true, 'index.html must define data-view="sovereignty"');
    assert.strictEqual(indexHtmlContent.includes('id="view-sovereignty"'), true, 'index.html must define #view-sovereignty');

    // 2. Verify interactive placement simulator elements
    assert.strictEqual(indexHtmlContent.includes('id="sim-client-origin"'), true, 'index.html must define #sim-client-origin');
    assert.strictEqual(indexHtmlContent.includes('id="sim-workload-type"'), true, 'index.html must define #sim-workload-type');
    assert.strictEqual(indexHtmlContent.includes('id="sim-classification"'), true, 'index.html must define #sim-classification');
    assert.strictEqual(indexHtmlContent.includes('id="sim-jurisdiction"'), true, 'index.html must define #sim-jurisdiction');
    assert.strictEqual(indexHtmlContent.includes('id="sim-strict-sovereignty"'), true, 'index.html must define #sim-strict-sovereignty');
    assert.strictEqual(indexHtmlContent.includes('id="btn-simulate-placement"'), true, 'index.html must define #btn-simulate-placement');
    assert.strictEqual(indexHtmlContent.includes('id="sim-result-box"'), true, 'index.html must define #sim-result-box');
    assert.strictEqual(indexHtmlContent.includes('id="table-compute-nodes-body"'), true, 'index.html must define #table-compute-nodes-body');

    // 3. Verify JavaScript functions in app.js
    assert.strictEqual(appJsContent.includes('async function loadSovereigntyData'), true, 'app.js must define loadSovereigntyData');
    assert.strictEqual(appJsContent.includes('async function simulateWorkloadPlacement'), true, 'app.js must define simulateWorkloadPlacement');
    assert.strictEqual(appJsContent.includes('window.loadSovereigntyData = loadSovereigntyData;'), true, 'app.js must export window.loadSovereigntyData');
    assert.strictEqual(appJsContent.includes('window.simulateWorkloadPlacement = simulateWorkloadPlacement;'), true, 'app.js must export window.simulateWorkloadPlacement');

    // 4. Verify BFF proxy routes in server.js
    assert.strictEqual(serverJsContent.includes('/api/proxy/policies/sovereignty/evaluate'), true, 'server.js must define proxy for sovereignty evaluate');
    assert.strictEqual(serverJsContent.includes('/api/proxy/workloads/schedule'), true, 'server.js must define proxy for workloads schedule');
    assert.strictEqual(serverJsContent.includes('/api/proxy/workloads/nodes'), true, 'server.js must define proxy for workloads nodes');
  });

  it('Requirement 21: Sovereign S3 Object Storage & Subsea Cable BGP Steering proxy and UI', async () => {
    const fs = require('fs');
    const path = require('path');
    const indexHtmlContent = fs.readFileSync(path.join(__dirname, '../public/index.html'), 'utf-8');
    const appJsContent = fs.readFileSync(path.join(__dirname, '../public/app.js'), 'utf-8');
    const serverJsContent = fs.readFileSync(path.join(__dirname, '../server.js'), 'utf-8');

    // 1. Verify index.html UI elements for Sovereign Storage
    assert.strictEqual(indexHtmlContent.includes('id="view-storage"'), true, 'index.html must define #view-storage');
    assert.strictEqual(indexHtmlContent.includes('id="storage-buckets-tbody"'), true, 'index.html must define #storage-buckets-tbody');
    assert.strictEqual(indexHtmlContent.includes('id="modal-new-bucket"'), true, 'index.html must define #modal-new-bucket');
    assert.strictEqual(indexHtmlContent.includes('id="new-bucket-name"'), true, 'index.html must define #new-bucket-name');
    assert.strictEqual(indexHtmlContent.includes('id="new-bucket-sovereignty"'), true, 'index.html must define #new-bucket-sovereignty');

    // 2. Verify index.html UI elements for Subsea Cables
    assert.strictEqual(indexHtmlContent.includes('id="subsea-cables-table"'), true, 'index.html must define #subsea-cables-table');
    assert.strictEqual(indexHtmlContent.includes('id="subsea-cables-tbody"'), true, 'index.html must define #subsea-cables-tbody');
    assert.strictEqual(indexHtmlContent.includes('id="cables-active-badge"'), true, 'index.html must define #cables-active-badge');

    // 3. Verify app.js client functions
    assert.strictEqual(appJsContent.includes('async function loadStorageBuckets'), true, 'app.js must define loadStorageBuckets');
    assert.strictEqual(appJsContent.includes('async function submitCreateStorageBucket'), true, 'app.js must define submitCreateStorageBucket');
    assert.strictEqual(appJsContent.includes('async function deleteStorageBucket'), true, 'app.js must define deleteStorageBucket');
    assert.strictEqual(appJsContent.includes('async function loadSubseaCables'), true, 'app.js must define loadSubseaCables');
    assert.strictEqual(appJsContent.includes('async function simulateCableAction'), true, 'app.js must define simulateCableAction');
    assert.strictEqual(appJsContent.includes('window.loadStorageBuckets = loadStorageBuckets;'), true, 'app.js must export window.loadStorageBuckets');
    assert.strictEqual(appJsContent.includes('window.loadSubseaCables = loadSubseaCables;'), true, 'app.js must export window.loadSubseaCables');

    // 4. Verify server.js BFF proxy routes
    assert.strictEqual(serverJsContent.includes('/api/proxy/storage/buckets'), true, 'server.js must define proxy for storage buckets');
    assert.strictEqual(serverJsContent.includes('/api/proxy/network/cables'), true, 'server.js must define proxy for subsea cables');
  });
});







