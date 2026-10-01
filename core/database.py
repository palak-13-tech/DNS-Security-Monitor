"""
Database Module for DNS Security Monitor.
Manages SQLite connections, schema creation, indexes, foreign keys,
and CRUD operations for DNS requests, domain analysis, and security alerts.
"""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import config


def get_connection(db_path: Optional[Path | str] = None) -> sqlite3.Connection:
    """
    Establish and return a SQLite database connection with:
    - Foreign keys enforced
    - WAL (Write-Ahead Logging) journal mode for concurrency
    - sqlite3.Row factory for dictionary-like column access
    """
    target_path = Path(db_path) if db_path else config.DB_PATH
    target_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(
        target_path,
        timeout=config.SQLITE_TIMEOUT,
        check_same_thread=False,
    )
    conn.row_factory = sqlite3.Row

    # Enforce foreign key constraints and WAL mode
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")

    return conn


def init_db(db_path: Optional[Path | str] = None) -> None:
    """
    Initialize SQLite database tables and indexes.
    Creates dns_requests, domain_analysis, and security_alerts tables if they don't exist.
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()

    try:
        # Table 1: dns_requests
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS dns_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                query_domain TEXT NOT NULL,
                query_type TEXT NOT NULL DEFAULT 'A',
                source_mode TEXT NOT NULL,
                is_malicious INTEGER NOT NULL DEFAULT 0
            );
            """
        )

        # Table 2: domain_analysis
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS domain_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dns_request_id INTEGER NOT NULL,
                domain TEXT NOT NULL,
                domain_length INTEGER NOT NULL,
                entropy REAL NOT NULL,
                digit_count INTEGER NOT NULL,
                special_char_count INTEGER NOT NULL,
                subdomain_count INTEGER NOT NULL,
                vowel_ratio REAL NOT NULL,
                tld TEXT NOT NULL,
                suspicious_keyword_count INTEGER NOT NULL,
                prediction TEXT NOT NULL,
                confidence_score REAL NOT NULL,
                analyzed_at TEXT NOT NULL,
                FOREIGN KEY (dns_request_id) REFERENCES dns_requests (id) ON DELETE CASCADE
            );
            """
        )

        # Table 3: security_alerts
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS security_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dns_request_id INTEGER NOT NULL,
                domain TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                severity TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                confidence_score REAL NOT NULL,
                status TEXT NOT NULL DEFAULT 'NEW',
                details TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (dns_request_id) REFERENCES dns_requests (id) ON DELETE CASCADE
            );
            """
        )

        # Indexes for query performance
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_requests_timestamp ON dns_requests(timestamp);",
            "CREATE INDEX IF NOT EXISTS idx_requests_domain ON dns_requests(query_domain);",
            "CREATE INDEX IF NOT EXISTS idx_requests_client_ip ON dns_requests(client_ip);",
            "CREATE INDEX IF NOT EXISTS idx_requests_is_malicious ON dns_requests(is_malicious);",
            "CREATE INDEX IF NOT EXISTS idx_analysis_request_id ON domain_analysis(dns_request_id);",
            "CREATE INDEX IF NOT EXISTS idx_analysis_prediction ON domain_analysis(prediction);",
            "CREATE INDEX IF NOT EXISTS idx_alerts_request_id ON security_alerts(dns_request_id);",
            "CREATE INDEX IF NOT EXISTS idx_alerts_status ON security_alerts(status);",
            "CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON security_alerts(created_at);",
            "CREATE INDEX IF NOT EXISTS idx_alerts_severity ON security_alerts(severity);",
        ]

        for idx_sql in indexes:
            cursor.execute(idx_sql)

        conn.commit()
    finally:
        conn.close()


def insert_dns_request(
    client_ip: str,
    query_domain: str,
    query_type: str = "A",
    source_mode: str = "MOCK",
    is_malicious: int = 0,
    timestamp: Optional[str] = None,
    db_path: Optional[Path | str] = None,
) -> int:
    """
    Insert a captured or simulated DNS request record.
    Returns the newly created request ID.
    """
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat()

    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO dns_requests (
                timestamp, client_ip, query_domain, query_type, source_mode, is_malicious
            ) VALUES (?, ?, ?, ?, ?, ?);
            """,
            (timestamp, client_ip, query_domain, query_type, source_mode, is_malicious),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def insert_domain_analysis(
    dns_request_id: int,
    domain: str,
    domain_length: int,
    entropy: float,
    digit_count: int,
    special_char_count: int,
    subdomain_count: int,
    vowel_ratio: float,
    tld: str,
    suspicious_keyword_count: int,
    prediction: str,
    confidence_score: float,
    analyzed_at: Optional[str] = None,
    db_path: Optional[Path | str] = None,
) -> int:
    """
    Insert feature extraction & classification results for a DNS request.
    Returns the newly created analysis ID.
    """
    if analyzed_at is None:
        analyzed_at = datetime.now(timezone.utc).isoformat()

    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO domain_analysis (
                dns_request_id, domain, domain_length, entropy, digit_count,
                special_char_count, subdomain_count, vowel_ratio, tld,
                suspicious_keyword_count, prediction, confidence_score, analyzed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                dns_request_id,
                domain,
                domain_length,
                entropy,
                digit_count,
                special_char_count,
                subdomain_count,
                vowel_ratio,
                tld,
                suspicious_keyword_count,
                prediction,
                confidence_score,
                analyzed_at,
            ),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def insert_security_alert(
    dns_request_id: int,
    domain: str,
    client_ip: str,
    severity: str,
    threat_type: str,
    confidence_score: float,
    status: str = "NEW",
    details: Optional[str] = None,
    created_at: Optional[str] = None,
    db_path: Optional[Path | str] = None,
) -> int:
    """
    Insert a security alert triggered by a malicious/suspicious detection.
    Returns the newly created alert ID.
    """
    if created_at is None:
        created_at = datetime.now(timezone.utc).isoformat()

    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO security_alerts (
                dns_request_id, domain, client_ip, severity,
                threat_type, confidence_score, status, details, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                dns_request_id,
                domain,
                client_ip,
                severity,
                threat_type,
                confidence_score,
                status,
                details,
                created_at,
            ),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def get_recent_requests(
    limit: int = 50,
    db_path: Optional[Path | str] = None,
) -> List[Dict[str, Any]]:
    """
    Retrieve the most recent DNS requests, ordered newest first.
    """
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, timestamp, client_ip, query_domain, query_type, source_mode, is_malicious
            FROM dns_requests
            ORDER BY id DESC
            LIMIT ?;
            """,
            (limit,),
        )
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_request_by_id(
    request_id: int,
    db_path: Optional[Path | str] = None,
) -> Optional[Dict[str, Any]]:
    """
    Fetch a single DNS request record by primary key ID.
    """
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, timestamp, client_ip, query_domain, query_type, source_mode, is_malicious
            FROM dns_requests
            WHERE id = ?;
            """,
            (request_id,),
        )
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_request_count(db_path: Optional[Path | str] = None) -> int:
    """
    Return the total number of DNS request records in the database.
    """
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) AS total FROM dns_requests;")
        row = cursor.fetchone()
        return int(row["total"]) if row else 0
    finally:
        conn.close()


def get_table_names(db_path: Optional[Path | str] = None) -> List[str]:
    """
    Return the list of user tables in the SQLite database.
    """
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT name FROM sqlite_master
            WHERE type='table' AND name NOT LIKE 'sqlite_%'
            ORDER BY name;
            """
        )
        return [row["name"] for row in cursor.fetchall()]
    finally:
        conn.close()


def get_index_names(db_path: Optional[Path | str] = None) -> List[str]:
    """
    Return the list of user indexes in the SQLite database.
    """
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT name FROM sqlite_master
            WHERE type='index' AND name NOT LIKE 'sqlite_%'
            ORDER BY name;
            """
        )
        return [row["name"] for row in cursor.fetchall()]
    finally:
        conn.close()


def get_dashboard_stats(db_path: Optional[Path | str] = None) -> Dict[str, int]:
    """
    Compute aggregate statistics for the dashboard KPI cards:
    - total_requests: Total count of DNS queries
    - safe_requests: Count of queries classified as SAFE (is_malicious = 0)
    - malicious_requests: Count of queries classified as MALICIOUS (is_malicious = 1)
    - total_alerts: Total security alerts logged
    """
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT
                COUNT(*) AS total_requests,
                COALESCE(SUM(CASE WHEN is_malicious = 0 THEN 1 ELSE 0 END), 0) AS safe_requests,
                COALESCE(SUM(CASE WHEN is_malicious = 1 THEN 1 ELSE 0 END), 0) AS malicious_requests
            FROM dns_requests;
            """
        )
        req_row = cursor.fetchone()
        total_requests = int(req_row["total_requests"]) if req_row else 0
        safe_requests = int(req_row["safe_requests"]) if req_row else 0
        malicious_requests = int(req_row["malicious_requests"]) if req_row else 0

        cursor.execute("SELECT COUNT(*) AS total_alerts FROM security_alerts;")
        alert_row = cursor.fetchone()
        total_alerts = int(alert_row["total_alerts"]) if alert_row else 0

        return {
            "total_requests": total_requests,
            "safe_requests": safe_requests,
            "malicious_requests": malicious_requests,
            "total_alerts": total_alerts,
        }
    finally:
        conn.close()


def get_recent_alerts(
    limit: int = 10,
    db_path: Optional[Path | str] = None,
) -> List[Dict[str, Any]]:
    """
    Retrieve the most recent security alerts ordered newest first.
    """
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, dns_request_id, domain, client_ip, severity,
                   threat_type, confidence_score, status, details, created_at
            FROM security_alerts
            ORDER BY id DESC
            LIMIT ?;
            """,
            (limit,),
        )
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()
