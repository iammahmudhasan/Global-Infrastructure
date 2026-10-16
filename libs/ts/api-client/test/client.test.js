const { describe, it } = require('node:test');
const assert = require('assert');
const http = require('http');
const { NexusEdgeClient, NexusEdgeError } = require('../dist/index.js');

function safeClose(server) {
  return new Promise((resolve) => {
    if (!server) return resolve();
    if (server.closeAllConnections) {
      server.closeAllConnections();
    }
    server.close(() => resolve());
  });
}

describe('NexusEdge Official TypeScript SDK Acceptance Tests', () => {
  it('Requirement SDK.1: Client rejects missing or empty API keys', () => {
    assert.throws(
      () => new NexusEdgeClient({ apiKey: '' }),
      (err) => err instanceof NexusEdgeError && err.status === 400 && err.code === 'INVALID_API_KEY'
    );
    assert.throws(
      () => new NexusEdgeClient(null),
      (err) => err instanceof NexusEdgeError && err.status === 400
    );
  });

  it('Requirement SDK.2: Inference createCompletion dispatches multi-objective routing & parses telemetry', async () => {
    let capturedHeaders = null;
    let capturedBody = null;

    const mockServer = http.createServer((req, res) => {
      if (req.method === 'POST' && req.url === '/api/proxy/inference') {
        capturedHeaders = req.headers;
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', () => {
          capturedBody = JSON.parse(body);
          res.writeHead(200, {
            'Content-Type': 'application/json',
            'X-NexusEdge-Provider': 'spot-coreweave',
            'X-NexusEdge-Cost': '0.0042',
            'X-NexusEdge-TTFT-Ms': '24',
            'X-NexusEdge-Region': 'dhaka'
          });
          res.end(JSON.stringify({
            id: 'chatcmpl-test-001',
            choices: [{
              index: 0,
              message: { role: 'assistant', content: 'Latency-optimal inference complete.' }
            }],
            usage: { prompt_tokens: 12, completion_tokens: 8, total_tokens: 20 }
          }));
        });
        return;
      }
      res.writeHead(404);
      res.end();
    });

    await new Promise((resolve) => mockServer.listen(0, '127.0.0.1', resolve));
    const port = mockServer.address().port;

    try {
      const client = new NexusEdgeClient({
        apiKey: 'nke_live_test_secret_12345',
        baseUrl: `http://127.0.0.1:${port}`
      });

      const response = await client.inference.createCompletion({
        model: 'meta-llama/Llama-3.3-70B-Instruct',
        messages: [{ role: 'user', content: 'Status check' }],
        routingStrategy: 'LATENCY_OPTIMAL',
        jurisdiction: 'BD',
        temperature: 0.2
      });

      assert.strictEqual(response.id, 'chatcmpl-test-001');
      assert.strictEqual(response.choices[0].message.content, 'Latency-optimal inference complete.');
      assert.strictEqual(response.telemetry.provider, 'spot-coreweave');
      assert.strictEqual(response.telemetry.cost, 0.0042);
      assert.strictEqual(response.telemetry.ttftMs, 24);
      assert.strictEqual(response.telemetry.region, 'dhaka');

      assert.strictEqual(capturedHeaders['authorization'], 'Bearer nke_live_test_secret_12345');
      assert.strictEqual(capturedHeaders['x-nexusedge-routing-strategy'], 'LATENCY_OPTIMAL');
      assert.strictEqual(capturedHeaders['x-nexusedge-jurisdiction'], 'BD');
      assert.strictEqual(capturedBody.model, 'meta-llama/Llama-3.3-70B-Instruct');
      assert.strictEqual(capturedBody.temperature, 0.2);
    } finally {
      await safeClose(mockServer);
    }
  });

  it('Requirement SDK.3: Domains namespace handles onboarding, verification, and deletion', async () => {
    let lastUrl = '';
    let lastMethod = '';
    let lastBody = null;

    const mockServer = http.createServer((req, res) => {
      lastUrl = req.url;
      lastMethod = req.method;

      if (req.method === 'GET' && req.url === '/api/proxy/domains') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          domains: [{ id: 'dom-01', project_id: 'proj-alpha', hostname: 'api.alpha.com', status: 'verified' }]
        }));
        return;
      }

      if (req.method === 'POST' && req.url === '/api/proxy/domains') {
        let body = '';
        req.on('data', c => { body += c; });
        req.on('end', () => {
          lastBody = JSON.parse(body);
          res.writeHead(201, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            domain_id: 'dom-new-99',
            hostname: lastBody.hostname,
            cname_target: 'dom-new-99.edge.nexusedge.net',
            verification_token: 'nke-verify-token-99',
            status: 'pending_verification',
            allowed_pops: lastBody.allowed_pops
          }));
        });
        return;
      }

      if (req.method === 'POST' && req.url === '/api/proxy/domains/dom-new-99/verify?force=true') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          status: 'verified',
          domain_id: 'dom-new-99',
          hostname: 'beta.app.com',
          state: 'active'
        }));
        return;
      }

      if (req.method === 'DELETE' && req.url === '/api/proxy/domains/dom-new-99') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'deleted', domain_id: 'dom-new-99' }));
        return;
      }

      res.writeHead(404);
      res.end();
    });

    await new Promise((resolve) => mockServer.listen(0, '127.0.0.1', resolve));
    const port = mockServer.address().port;

    try {
      const client = new NexusEdgeClient({
        apiKey: 'nke_live_domain_test_key',
        baseUrl: `http://127.0.0.1:${port}`
      });

      // 1. List
      const listRes = await client.domains.list();
      assert.strictEqual(listRes.domains.length, 1);
      assert.strictEqual(listRes.domains[0].hostname, 'api.alpha.com');

      // 2. Onboard
      const onboardRes = await client.domains.onboard({
        hostname: 'beta.app.com',
        originAddress: '198.51.100.25',
        originPort: 443,
        originProtocol: 'https'
      });
      assert.strictEqual(onboardRes.domain_id, 'dom-new-99');
      assert.strictEqual(onboardRes.cname_target, 'dom-new-99.edge.nexusedge.net');
      assert.strictEqual(lastBody.hostname, 'beta.app.com');

      // 3. Verify
      const verifyRes = await client.domains.verify('dom-new-99', { force: true });
      assert.strictEqual(verifyRes.status, 'verified');
      assert.strictEqual(verifyRes.state, 'active');

      // 4. Delete
      const deleteRes = await client.domains.delete('dom-new-99');
      assert.strictEqual(deleteRes.status, 'deleted');
      assert.strictEqual(lastMethod, 'DELETE');
    } finally {
      await safeClose(mockServer);
    }
  });

  it('Requirement SDK.4: Telemetry namespace queries summary, matrix, and PoP health', async () => {
    let capturedSummaryUrl = '';

    const mockServer = http.createServer((req, res) => {
      if (req.url.startsWith('/api/proxy/analytics/summary')) {
        capturedSummaryUrl = req.url;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          project_id: 'proj-core',
          total_requests: 12450,
          p50_latency_ms: 3.8,
          p95_latency_ms: 16.4,
          p99_latency_ms: 28.1,
          cache_hit_ratio: 0.942,
          threat_blocks: 14,
          success_rate: 0.998,
          status_distribution: { '2xx': 12420, '4xx': 25, '5xx': 5 },
          pop_distribution: { dhaka: 6200, singapore: 4100, frankfurt: 1500, virginia: 650 }
        }));
        return;
      }

      if (req.url === '/api/proxy/pops/matrix') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          routes: [{ from_pop: 'dhaka', to_pop: 'singapore', latency_ms: 32 }]
        }));
        return;
      }

      if (req.url === '/api/proxy/pops/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          pops: [{ id: 'pop-dhk-01', name: 'Dhaka Edge 01', region: 'dhaka', status: 'ONLINE', latency_p50_ms: 2.1, capacity_used_pct: 34, anycast_announced: true }]
        }));
        return;
      }

      res.writeHead(404);
      res.end();
    });

    await new Promise((resolve) => mockServer.listen(0, '127.0.0.1', resolve));
    const port = mockServer.address().port;

    try {
      const client = new NexusEdgeClient({
        apiKey: 'nke_live_telemetry_key',
        baseUrl: `http://127.0.0.1:${port}`
      });

      const summary = await client.telemetry.getSummary('proj-analytics-test');
      assert.strictEqual(summary.total_requests, 12450);
      assert.strictEqual(summary.p99_latency_ms, 28.1);
      assert.strictEqual(summary.threat_blocks, 14);
      assert.strictEqual(capturedSummaryUrl, '/api/proxy/analytics/summary?project_id=proj-analytics-test');

      const matrix = await client.telemetry.getLatencyMatrix();
      assert.strictEqual(matrix.routes.length, 1);
      assert.strictEqual(matrix.routes[0].latency_ms, 32);

      const health = await client.telemetry.getPoPHealth();
      assert.strictEqual(health.pops.length, 1);
      assert.strictEqual(health.pops[0].region, 'dhaka');
    } finally {
      await safeClose(mockServer);
    }
  });

  it('Requirement SDK.5: HTTP error responses throw NexusEdgeError with status and message', async () => {
    const mockServer = http.createServer((req, res) => {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        code: 403,
        error: 'Forbidden: Insufficient role permissions for this resource'
      }));
    });

    await new Promise((resolve) => mockServer.listen(0, '127.0.0.1', resolve));
    const port = mockServer.address().port;

    try {
      const client = new NexusEdgeClient({
        apiKey: 'nke_live_unauthorized_key',
        baseUrl: `http://127.0.0.1:${port}`
      });

      await assert.rejects(
        () => client.domains.delete('dom-restricted'),
        (err) => {
          assert.strictEqual(err instanceof NexusEdgeError, true);
          assert.strictEqual(err.status, 403);
          assert.strictEqual(err.code, 403);
          assert.strictEqual(err.message.includes('Insufficient role permissions'), true);
          return true;
        }
      );
    } finally {
      await safeClose(mockServer);
    }
  });
});
