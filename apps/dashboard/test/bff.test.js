const { describe, it } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const http = require('http');

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

  it('Requirement 2.2: Production BFF must reject unauthenticated proxy requests with 401', (done) => {
    process.env.NODE_ENV = 'production';
    process.env.NEXUSEDGE_ENV = 'production';

    const server = require('../server.js');
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;

      // 1. Unauthenticated request to /api/proxy/audit-logs must return 401
      const req = http.request({
        hostname: '127.0.0.1',
        port: port,
        path: '/api/proxy/audit-logs',
        method: 'GET'
      }, (res) => {
        assert.strictEqual(res.statusCode, 401, 'Unauthenticated proxy request must be rejected with 401 Unauthorized');
        let body = '';
        res.on('data', chunk => { body += chunk; });
        res.on('end', () => {
          const json = JSON.parse(body);
          assert.strictEqual(json.code, 401);

          // 2. Unauthenticated request to /api/auth/session must return 401
          http.get(`http://127.0.0.1:${port}/api/auth/session`, (sessionRes) => {
            assert.strictEqual(sessionRes.statusCode, 401);
            server.close(done);
          });
        });
      });

      req.on('error', (err) => {
        server.close();
        done(err);
      });
      req.end();
    });
  });
});
