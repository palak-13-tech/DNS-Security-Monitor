"""
Unit tests for Database Operations and DNS Simulator (Phase 1).
Verifies:
1. Database file creation & connection.
2. Table creation (dns_requests, domain_analysis, security_alerts).
3. Index creation for query optimization.
4. Foreign key constraint enforcement.
5. DNS request insertion and retrieval with field fidelity.
6. Aggregation helper methods.
7. Simulator query generation and database recording.
"""

import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from core import database
from simulator.dns_simulator import DNSSimulator


class TestDatabasePhase1(unittest.TestCase):
    """Test suite for Phase 1 database operations."""

    def setUp(self):
        """Create a temporary SQLite database for isolated test execution."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_db_path = Path(self.temp_dir.name) / "test_dns_monitor.db"

    def tearDown(self):
        """Clean up the temporary directory and test database."""
        self.temp_dir.cleanup()

    def test_database_creation(self):
        """Verify database file is created and connection can be established."""
        self.assertFalse(self.test_db_path.exists())
        conn = database.get_connection(self.test_db_path)
        self.assertIsInstance(conn, sqlite3.Connection)
        conn.close()
        self.assertTrue(self.test_db_path.exists())

    def test_table_creation(self):
        """Verify all required tables are properly created."""
        database.init_db(self.test_db_path)
        tables = database.get_table_names(self.test_db_path)

        expected_tables = ["dns_requests", "domain_analysis", "security_alerts"]
        for expected in expected_tables:
            self.assertIn(
                expected,
                tables,
                f"Table '{expected}' was not created in database.",
            )

    def test_index_creation(self):
        """Verify all performance indexes are properly created."""
        database.init_db(self.test_db_path)
        indexes = database.get_index_names(self.test_db_path)

        expected_indexes = [
            "idx_requests_timestamp",
            "idx_requests_domain",
            "idx_requests_client_ip",
            "idx_requests_is_malicious",
            "idx_analysis_request_id",
            "idx_analysis_prediction",
            "idx_alerts_request_id",
            "idx_alerts_status",
            "idx_alerts_created_at",
            "idx_alerts_severity",
        ]
        for expected_idx in expected_indexes:
            self.assertIn(
                expected_idx,
                indexes,
                f"Index '{expected_idx}' was not created.",
            )

    def test_dns_request_insertion_and_retrieval(self):
        """Verify DNS request record insertion and accurate field retrieval."""
        database.init_db(self.test_db_path)

        sample_ip = "192.168.1.55"
        sample_domain = "google.com"
        sample_type = "A"
        sample_mode = "MOCK"
        sample_malicious = 0

        req_id = database.insert_dns_request(
            client_ip=sample_ip,
            query_domain=sample_domain,
            query_type=sample_type,
            source_mode=sample_mode,
            is_malicious=sample_malicious,
            db_path=self.test_db_path,
        )

        self.assertIsInstance(req_id, int)
        self.assertGreater(req_id, 0)

        # Retrieve by ID
        record = database.get_request_by_id(req_id, db_path=self.test_db_path)
        self.assertIsNotNone(record)
        self.assertEqual(record["id"], req_id)
        self.assertEqual(record["client_ip"], sample_ip)
        self.assertEqual(record["query_domain"], sample_domain)
        self.assertEqual(record["query_type"], sample_type)
        self.assertEqual(record["source_mode"], sample_mode)
        self.assertEqual(record["is_malicious"], sample_malicious)
        self.assertTrue(len(record["timestamp"]) > 0)

    def test_foreign_key_enforcement(self):
        """Verify foreign key constraint enforces parent existence and cascade deletes."""
        database.init_db(self.test_db_path)

        # Inserting domain_analysis with non-existent dns_request_id should fail
        with self.assertRaises(sqlite3.IntegrityError):
            database.insert_domain_analysis(
                dns_request_id=99999,  # Does not exist
                domain="invalid.com",
                domain_length=11,
                entropy=2.5,
                digit_count=0,
                special_char_count=0,
                subdomain_count=1,
                vowel_ratio=0.3,
                tld="com",
                suspicious_keyword_count=0,
                prediction="SAFE",
                confidence_score=0.95,
                db_path=self.test_db_path,
            )

        # Insert parent DNS request
        req_id = database.insert_dns_request(
            client_ip="10.0.0.5",
            query_domain="test-phish.xyz",
            query_type="A",
            source_mode="MOCK",
            is_malicious=1,
            db_path=self.test_db_path,
        )

        # Now inserting child records succeeds
        analysis_id = database.insert_domain_analysis(
            dns_request_id=req_id,
            domain="test-phish.xyz",
            domain_length=14,
            entropy=3.4,
            digit_count=0,
            special_char_count=1,
            subdomain_count=1,
            vowel_ratio=0.25,
            tld="xyz",
            suspicious_keyword_count=1,
            prediction="MALICIOUS",
            confidence_score=0.92,
            db_path=self.test_db_path,
        )
        self.assertGreater(analysis_id, 0)

        alert_id = database.insert_security_alert(
            dns_request_id=req_id,
            domain="test-phish.xyz",
            client_ip="10.0.0.5",
            severity="HIGH",
            threat_type="Phishing Keyword",
            confidence_score=0.92,
            db_path=self.test_db_path,
        )
        self.assertGreater(alert_id, 0)

        # Deleting parent request should cascade delete children
        conn = database.get_connection(self.test_db_path)
        conn.execute("DELETE FROM dns_requests WHERE id = ?;", (req_id,))
        conn.commit()

        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM domain_analysis WHERE dns_request_id = ?;", (req_id,))
        self.assertEqual(cursor.fetchone()[0], 0)

        cursor.execute("SELECT COUNT(*) FROM security_alerts WHERE dns_request_id = ?;", (req_id,))
        self.assertEqual(cursor.fetchone()[0], 0)
        conn.close()

    def test_recent_requests_ordering_and_limit(self):
        """Verify get_recent_requests respects limits and returns newest first."""
        database.init_db(self.test_db_path)

        for i in range(15):
            database.insert_dns_request(
                client_ip=f"192.168.1.{i+1}",
                query_domain=f"domain-{i}.com",
                db_path=self.test_db_path,
            )

        self.assertEqual(database.get_request_count(self.test_db_path), 15)

        recent = database.get_recent_requests(limit=5, db_path=self.test_db_path)
        self.assertEqual(len(recent), 5)
        # Should be ordered newest first (IDs 15, 14, 13, 12, 11)
        self.assertEqual(recent[0]["id"], 15)
        self.assertEqual(recent[1]["id"], 14)

    def test_dns_simulator_integration(self):
        """Verify DNSSimulator produces and records queries across all expected categories."""
        simulator = DNSSimulator(db_path=self.test_db_path, interval=0.01)

        # Generate a batch of 20 queries
        count = simulator.run(count=20, verbose=False)
        self.assertEqual(count, 20)
        self.assertEqual(database.get_request_count(self.test_db_path), 20)

        # Verify query fields in database
        requests = database.get_recent_requests(limit=20, db_path=self.test_db_path)
        for req in requests:
            self.assertEqual(req["source_mode"], "MOCK")
            self.assertTrue(len(req["query_domain"]) > 3)
            self.assertIn(req["is_malicious"], [0, 1])


if __name__ == "__main__":
    unittest.main()
