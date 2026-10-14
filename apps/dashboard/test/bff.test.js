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
});
