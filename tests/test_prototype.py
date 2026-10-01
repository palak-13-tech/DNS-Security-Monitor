"""
Unit and Integration Tests for Prototype Web Dashboard & Analyzer (app.py).
Verifies:
1. Flask app initialization and routes.
2. Dashboard HTML rendering and KPI statistics.
3. Domain Analyzer page and POST inspection.
4. REST API endpoints (/api/stats, /api/recent-requests, /api/recent-alerts, /api/analyze).
5. Background simulator start/stop API controls.
"""

import json
import unittest
from app import app
from core import database


class TestPrototypeDashboard(unittest.TestCase):
    """Test suite for the prototype web dashboard and analyzer."""

    def setUp(self):
        """Set up Flask test client and ensure DB schema is initialized."""
        app.config["TESTING"] = True
        self.client = app.test_client()
        database.init_db()

    def test_dashboard_route_get(self):
        """Verify GET / returns HTTP 200 and contains required dashboard UI elements."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)

        # Check for KPI titles
        self.assertIn("Total DNS Requests", html)
        self.assertIn("Safe Domains", html)
        self.assertIn("Malicious Domains", html)
        self.assertIn("Security Alerts", html)

        # Check for control buttons
        self.assertIn("Start Monitoring", html)
        self.assertIn("Stop Monitoring", html)

        # Check for tables and charts
        self.assertIn("Recent DNS Activity Log", html)
        self.assertIn("Recent Security Alerts", html)
        self.assertIn("threatRatioChart", html)

    def test_analyzer_route_get_and_post(self):
        """Verify GET and POST /analyzer for domain analysis."""
        # 1. GET /analyzer
        get_res = self.client.get("/analyzer")
        self.assertEqual(get_res.status_code, 200)
        self.assertIn("Manual Domain Security Analyzer", get_res.get_data(as_text=True))
        self.assertIn("Prototype Rule-Based Heuristics", get_res.get_data(as_text=True))

        # 2. POST /analyzer with benign domain
        post_benign = self.client.post("/analyzer", data={"domain": "google.com"})
        self.assertEqual(post_benign.status_code, 200)
        html_benign = post_benign.get_data(as_text=True)
        self.assertIn("SAFE", html_benign)
        self.assertIn("Domain Length", html_benign)
        self.assertIn("Digit Count", html_benign)

        # 3. POST /analyzer with malicious domain
        post_mal = self.client.post("/analyzer", data={"domain": "paypal-security-update.xyz"})
        self.assertEqual(post_mal.status_code, 200)
        html_mal = post_mal.get_data(as_text=True)
        self.assertIn("MALICIOUS", html_mal)
        self.assertIn("Reason for Detection", html_mal)

    def test_api_stats(self):
        """Verify GET /api/stats returns proper JSON structure."""
        response = self.client.get("/api/stats")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("total_requests", data)
        self.assertIn("safe_requests", data)
        self.assertIn("malicious_requests", data)
        self.assertIn("total_alerts", data)
        self.assertIn("simulator_running", data)

    def test_api_recent_requests(self):
        """Verify GET /api/recent-requests returns list of records."""
        response = self.client.get("/api/recent-requests?limit=5")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIsInstance(data, list)

    def test_api_recent_alerts(self):
        """Verify GET /api/recent-alerts returns list of alerts."""
        response = self.client.get("/api/recent-alerts?limit=5")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIsInstance(data, list)

    def test_api_analyze(self):
        """Verify POST /api/analyze returns feature breakdown and classification."""
        payload = {"domain": "k8x92m0qvwz14.info"}
        response = self.client.post(
            "/api/analyze",
            data=json.dumps(payload),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["prediction"], "MALICIOUS")
        self.assertIn("domain_length", data)
        self.assertIn("digit_count", data)
        self.assertIn("special_char_count", data)
        self.assertIn("subdomain_count", data)
        self.assertIn("suspicious_keyword_count", data)
        self.assertIn("reasons", data)

    def test_api_simulator_controls(self):
        """Verify simulator start and stop API controls."""
        # Stop first to ensure clean state
        self.client.post("/api/simulator/stop")

        # Start
        start_res = self.client.post(
            "/api/simulator/start",
            data=json.dumps({"interval": 0.5}),
            content_type="application/json",
        )
        self.assertEqual(start_res.status_code, 200)
        self.assertTrue(start_res.get_json()["running"])

        # Check status
        status_res = self.client.get("/api/simulator/status")
        self.assertTrue(status_res.get_json()["running"])

        # Stop
        stop_res = self.client.post("/api/simulator/stop")
        self.assertEqual(stop_res.status_code, 200)
        self.assertFalse(stop_res.get_json()["running"])


if __name__ == "__main__":
    unittest.main()
