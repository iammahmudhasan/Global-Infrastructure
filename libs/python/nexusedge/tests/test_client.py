"""
Unit tests for NexusEdge Python SDK using standard library unittest and http.server.
"""

import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional

pkg_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if pkg_dir not in sys.path:
    sys.path.insert(0, pkg_dir)

from nexusedge import (
    ChatMessage,
    NexusEdgeClient,
    NexusEdgeError,
)


class MockServerHandler(BaseHTTPRequestHandler):
    """Mock HTTP Handler simulating NexusEdge BFF Endpoints."""

    def log_message(self, format: str, *args) -> None:
        pass  # Suppress console logging during test runs

    def do_GET(self) -> None:
        auth_hdr = self.headers.get("Authorization", "")
        if auth_hdr != "Bearer nke_live_test_key_01":
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "unauthorized: invalid key", "code": 401}).encode("utf-8"))
            return

        if self.path == "/api/proxy/domains":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = {
                "domains": [
                    {
                        "id": "dom_001",
                        "project_id": "proj_core",
                        "hostname": "api.example.com",
                        "status": "ACTIVE",
                        "cname_target": "edge.nexusedge.net",
                        "origin_address": "203.0.113.10",
                        "origin_port": 443,
                        "origin_protocol": "https",
                        "allowed_pops": ["dhaka", "singapore"],
                    }
                ]
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        if self.path == "/api/proxy/domains/dom_001":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = {
                "id": "dom_001",
                "project_id": "proj_core",
                "hostname": "api.example.com",
                "status": "ACTIVE",
                "cname_target": "edge.nexusedge.net",
                "origin_address": "203.0.113.10",
                "origin_port": 443,
                "origin_protocol": "https",
                "allowed_pops": ["dhaka", "singapore"],
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        if self.path.startswith("/api/proxy/analytics/summary"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = {
                "project_id": "proj_core",
                "total_requests": 1500,
                "p50_latency_ms": 12.4,
                "p95_latency_ms": 28.1,
                "p99_latency_ms": 45.2,
                "cache_hit_ratio": 0.885,
                "threat_blocks": 4,
                "success_rate": 0.998,
                "status_distribution": {"2xx": 1490, "4xx": 8, "5xx": 2},
                "pop_distribution": {"dhaka": 800, "singapore": 700},
                "rate_limit": {"limit": 60, "remaining": 59},
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        if self.path == "/api/proxy/pops/matrix":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = {
                "routes": [
                    {"from_pop": "dhaka", "to_pop": "singapore", "latency_ms": 32.5, "status": "OPTIMAL"}
                ],
                "timestamp": "2026-10-16T09:00:00Z",
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        if self.path == "/api/proxy/pops/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = {
                "pops": [
                    {
                        "id": "dhaka",
                        "name": "Dhaka BDIX Edge",
                        "region": "asia-south1",
                        "status": "ACTIVE",
                        "latency_p50_ms": 4.2,
                        "capacity_used_pct": 22.0,
                        "anycast_announced": True,
                    }
                ]
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self) -> None:
        auth_hdr = self.headers.get("Authorization", "")
        if auth_hdr != "Bearer nke_live_test_key_01":
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "unauthorized", "code": 401}).encode("utf-8"))
            return

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
        payload = json.loads(body)

        if self.path == "/api/proxy/slow":
            import time
            time.sleep(1.0)
            self.send_response(200)
            self.end_headers()
            return

        if self.path == "/api/proxy/inference":
            if payload.get("model") == "trigger-429":
                self.send_response(429)
                self.send_header("Content-Type", "application/json")
                self.send_header("Retry-After", "1")
                self.end_headers()
                self.wfile.write(json.dumps({
                    "error": "rate limit exceeded: max 60 req/min for key",
                    "code": "RATE_LIMIT_EXCEEDED"
                }).encode("utf-8"))
                return

            routing = self.headers.get("X-NexusEdge-Routing-Strategy", "")
            jurisdiction = self.headers.get("X-NexusEdge-Jurisdiction", "")

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("x-nexusedge-provider", "Groq-Llama-Engine")
            self.send_header("x-nexusedge-cost", "0.000150")
            self.send_header("x-nexusedge-ttft-ms", "42")
            self.send_header("x-nexusedge-region", "dhaka-bdix")
            self.end_headers()

            resp = {
                "id": "chatcmpl_mock_001",
                "object": "chat.completion",
                "created": 1729065600,
                "model": payload.get("model", "meta-llama/Llama-3.3-70B-Instruct"),
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": f"Echo: strategy={routing}, jurisdiction={jurisdiction}",
                        },
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 12, "total_tokens": 22},
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        if self.path == "/api/proxy/domains":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = {
                "domain_id": "dom_new_123",
                "hostname": payload.get("hostname"),
                "cname_target": "edge.nexusedge.net",
                "verification_token": "nke_token_abc123",
                "status": "PENDING_VERIFICATION",
                "allowed_pops": payload.get("allowed_pops", []),
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        if self.path.startswith("/api/proxy/domains/dom_001/verify"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = {
                "status": "ok",
                "domain_id": "dom_001",
                "hostname": "api.example.com",
                "state": "ACTIVE",
                "message": "CNAME and TLS verified",
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()

    def do_DELETE(self) -> None:
        auth_hdr = self.headers.get("Authorization", "")
        if auth_hdr != "Bearer nke_live_test_key_01":
            self.send_response(401)
            self.end_headers()
            return

        if self.path == "/api/proxy/domains/dom_001":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "deleted", "domain_id": "dom_001"}).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()


class NexusEdgePythonSDKTests(unittest.TestCase):
    """Test suite verifying official Python SDK behavior."""

    server: Optional[HTTPServer] = None
    server_thread: Optional[threading.Thread] = None
    port: int = 0

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = HTTPServer(("127.0.0.1", 0), MockServerHandler)
        cls.port = cls.server.server_port
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.server:
            cls.server.shutdown()
            cls.server.server_close()

    def setUp(self) -> None:
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.api_key = "nke_live_test_key_01"
        self.client = NexusEdgeClient(api_key=self.api_key, base_url=self.base_url, timeout_seconds=5.0)

    def test_client_initialization_validation(self) -> None:
        """Verifies that client rejects empty or missing API keys."""
        with self.assertRaises(NexusEdgeError) as cm:
            NexusEdgeClient(api_key="")
        self.assertEqual(cm.exception.status, 400)
        self.assertEqual(cm.exception.code, "INVALID_API_KEY")

    def test_unauthorized_rejection(self) -> None:
        """Verifies 401 Unauthorized handling with invalid API keys."""
        bad_client = NexusEdgeClient(api_key="nke_live_bad_key", base_url=self.base_url)
        with self.assertRaises(NexusEdgeError) as cm:
            bad_client.domains.list()
        self.assertEqual(cm.exception.status, 401)

    def test_multi_objective_inference_completion(self) -> None:
        """Verifies AI inference with custom routing strategy, jurisdiction, and telemetry."""
        messages = [
            ChatMessage(role="system", content="You are an edge AI assistant."),
            {"role": "user", "content": "Ping!"},
        ]
        resp = self.client.inference.create_completion(
            messages=messages,
            model="meta-llama/Llama-3.3-70B-Instruct",
            routing_strategy="LATENCY_OPTIMAL",
            jurisdiction="BD",
        )
        self.assertEqual(resp.model, "meta-llama/Llama-3.3-70B-Instruct")
        self.assertTrue(len(resp.choices) > 0)
        self.assertIn("LATENCY_OPTIMAL", resp.choices[0].message.content)
        self.assertIn("BD", resp.choices[0].message.content)

        # Telemetry verification
        self.assertEqual(resp.telemetry.provider, "Groq-Llama-Engine")
        self.assertEqual(resp.telemetry.cost, 0.00015)
        self.assertEqual(resp.telemetry.ttft_ms, 42)
        self.assertEqual(resp.telemetry.region, "dhaka-bdix")

    def test_custom_domains_lifecycle(self) -> None:
        """Verifies full domain lifecycle: list, onboard, get, verify, delete."""
        # 1. List
        domains = self.client.domains.list()
        self.assertEqual(len(domains), 1)
        self.assertEqual(domains[0].hostname, "api.example.com")
        self.assertEqual(domains[0].allowed_pops, ["dhaka", "singapore"])

        # 2. Onboard
        new_dom = self.client.domains.onboard(
            hostname="app.example.com",
            origin_address="198.51.100.5",
            origin_port=443,
            origin_protocol="https",
            allowed_pops=["dhaka"],
        )
        self.assertEqual(new_dom.domain_id, "dom_new_123")
        self.assertEqual(new_dom.verification_token, "nke_token_abc123")
        self.assertEqual(new_dom.status, "PENDING_VERIFICATION")

        # 3. Get
        d = self.client.domains.get("dom_001")
        self.assertEqual(d.id, "dom_001")
        self.assertEqual(d.status, "ACTIVE")

        # 4. Verify
        v = self.client.domains.verify("dom_001", force=True)
        self.assertEqual(v.state, "ACTIVE")

        # 5. Delete
        del_res = self.client.domains.delete("dom_001")
        self.assertEqual(del_res.get("status"), "deleted")

    def test_real_time_telemetry_and_health(self) -> None:
        """Verifies telemetry summary, pop health, and latency matrix."""
        # 1. Summary
        summary = self.client.telemetry.get_summary(project_id="proj_core")
        self.assertEqual(summary.total_requests, 1500)
        self.assertEqual(summary.p50_latency_ms, 12.4)
        self.assertEqual(summary.p99_latency_ms, 45.2)
        self.assertEqual(summary.cache_hit_ratio, 0.885)
        self.assertIsNotNone(summary.rate_limit)
        if summary.rate_limit:
            self.assertEqual(summary.rate_limit.limit, 60)
            self.assertEqual(summary.rate_limit.remaining, 59)

        # 2. Latency Matrix
        matrix = self.client.telemetry.get_latency_matrix()
        self.assertEqual(len(matrix.routes), 1)
        self.assertEqual(matrix.routes[0].from_pop, "dhaka")
        self.assertEqual(matrix.routes[0].to_pop, "singapore")
        self.assertEqual(matrix.routes[0].latency_ms, 32.5)

        # 3. PoP Health
        health = self.client.telemetry.get_pop_health()
        self.assertEqual(len(health), 1)
        self.assertEqual(health[0].id, "dhaka")
        self.assertEqual(health[0].region, "asia-south1")
        self.assertTrue(health[0].anycast_announced)

    def test_rate_limit_429_error(self) -> None:
        """Verifies 429 Rate Limit error parsing and exception details."""
        with self.assertRaises(NexusEdgeError) as cm:
            self.client.inference.create_completion(
                messages=[{"role": "user", "content": "Hello"}],
                model="trigger-429"
            )
        self.assertEqual(cm.exception.status, 429)
        self.assertEqual(cm.exception.code, "RATE_LIMIT_EXCEEDED")
        self.assertIn("rate limit exceeded", cm.exception.message)

    def test_parameter_validation_errors(self) -> None:
        """Verifies client-side validation errors for missing or invalid parameters."""
        # 1. Empty messages list
        with self.assertRaises(NexusEdgeError) as cm1:
            self.client.inference.create_completion(messages=[])
        self.assertEqual(cm1.exception.status, 400)
        self.assertEqual(cm1.exception.code, "INVALID_PARAMS")

        # 2. Missing hostname or origin_address
        with self.assertRaises(NexusEdgeError) as cm2:
            self.client.domains.onboard(hostname="", origin_address="10.0.0.1")
        self.assertEqual(cm2.exception.status, 400)

        # 3. Missing domain_id
        with self.assertRaises(NexusEdgeError) as cm3:
            self.client.domains.get("")
        self.assertEqual(cm3.exception.status, 400)

    def test_client_request_timeout(self) -> None:
        """Verifies timeout handling when endpoint response exceeds configured timeout."""
        fast_timeout_client = NexusEdgeClient(
            api_key=self.api_key,
            base_url=self.base_url,
            timeout_seconds=0.2
        )
        with self.assertRaises(NexusEdgeError) as cm:
            fast_timeout_client.request("/api/proxy/slow", method="POST", body={"test": 1})
        self.assertEqual(cm.exception.status, 504)
        self.assertEqual(cm.exception.code, "TIMEOUT")


if __name__ == "__main__":
    unittest.main()

