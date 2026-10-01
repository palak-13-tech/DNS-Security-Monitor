"""
DNS Request Simulator Module.
Generates realistic benign and malicious (Phishing, High-Entropy, DGA) DNS traffic,
logs queries to the terminal, and records them in the SQLite database.
"""

import argparse
import random
import string
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

# Ensure project root is in sys.path when executed directly
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

import config
from core import database
from core.analyzer import analyze_domain


@dataclass
class SimulatedDNSQuery:
    """Represents a single simulated DNS query event."""
    timestamp: str
    client_ip: str
    domain: str
    query_type: str
    source_mode: str
    category: str
    is_malicious: int


class DNSSimulator:
    """
    Simulates DNS network traffic containing a balanced mix of:
    1. Normal/Benign domains (Google, GitHub, Wikipedia, Microsoft, etc.)
    2. Suspicious/Phishing domains (Brand lures, deceptive subdomains)
    3. High-entropy domains (Random hex/alphanumeric strings)
    4. DGA domains (Domain Generation Algorithm consonant-cluster patterns)
    """

    def __init__(
        self,
        db_path: Optional[Path | str] = None,
        interval: float = config.DEFAULT_SIMULATOR_INTERVAL,
    ):
        self.db_path = db_path or config.DB_PATH
        self.interval = max(0.01, interval)
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        # Seed lists
        self.normal_domains = list(config.SAMPLE_NORMAL_DOMAINS)
        self.suspicious_domains = list(config.SAMPLE_SUSPICIOUS_DOMAINS)
        self.high_entropy_domains = list(config.SAMPLE_HIGH_ENTROPY_DOMAINS)
        self.dga_domains = list(config.SAMPLE_DGA_DOMAINS)
        self.client_ips = list(config.SIMULATOR_CLIENT_IPS)

        # Common TLDs for synthetic domain generation
        self.risky_tlds = ["xyz", "top", "biz", "info", "ru", "cn", "cc", "pw", "site"]
        self.standard_tlds = ["com", "org", "net", "io", "co"]

        # Category distribution weights: 65% Normal, 15% Phishing, 10% High-Entropy, 10% DGA
        self.categories = ["NORMAL", "PHISHING", "HIGH_ENTROPY", "DGA"]
        self.category_weights = [0.65, 0.15, 0.10, 0.10]

    def _generate_synthetic_high_entropy(self) -> str:
        """Generate a random high-entropy alphanumeric domain name."""
        length = random.randint(12, 22)
        charset = string.ascii_lowercase + string.digits
        label = "".join(random.choices(charset, k=length))
        tld = random.choice(self.risky_tlds)
        return f"{label}.{tld}"

    def _generate_synthetic_dga(self) -> str:
        """Generate a synthetic DGA domain with consonant clustering."""
        consonants = "bcdfghjklmnpqrstvwxz"
        vowels = "aeiouy"
        # DGAs typically have very low vowel ratios or unnatural consonant streaks
        parts = []
        for _ in range(random.randint(2, 4)):
            streak = "".join(random.choices(consonants, k=random.randint(3, 6)))
            parts.append(streak)
            if random.random() < 0.3:
                parts.append(random.choice(vowels))
        label = "".join(parts)[: random.randint(10, 18)]
        tld = random.choice(self.risky_tlds)
        return f"{label}.{tld}"

    def _generate_synthetic_phishing(self) -> str:
        """Generate a synthetic phishing lure domain."""
        brands = ["paypal", "apple", "microsoft", "google", "netflix", "wellsfargo", "chase"]
        actions = ["login", "verify", "secure", "update", "account-alert", "auth-check", "portal"]
        tlds = ["com", "net", "org", "xyz", "support", "online", "center"]

        brand = random.choice(brands)
        action = random.choice(actions)
        tld = random.choice(tlds)

        pattern = random.choice([
            f"{brand}-{action}-security.{tld}",
            f"{action}-{brand}-support.{tld}",
            f"{brand}.account-verify-{action}.{tld}",
            f"security-check.{brand}-{action}.{tld}",
        ])
        return pattern

    def generate_query(self) -> SimulatedDNSQuery:
        """
        Produce a single realistic simulated DNS query event.
        """
        category = random.choices(self.categories, weights=self.category_weights, k=1)[0]
        client_ip = random.choice(self.client_ips)
        query_type = random.choices(
            config.DNS_QUERY_TYPES,
            weights=config.DNS_QUERY_WEIGHTS,
            k=1,
        )[0]
        timestamp = datetime.now(timezone.utc).isoformat()

        if category == "NORMAL":
            domain = random.choice(self.normal_domains)
            # Occasionally prepend a realistic benign subdomain
            if random.random() < 0.35:
                sub = random.choice(["www", "mail", "api", "auth", "cdn", "status"])
                domain = f"{sub}.{domain}"
            is_malicious = 0

        elif category == "PHISHING":
            # Pick from curated list or synthesize
            if random.random() < 0.5:
                domain = random.choice(self.suspicious_domains)
            else:
                domain = self._generate_synthetic_phishing()
            is_malicious = 1

        elif category == "HIGH_ENTROPY":
            if random.random() < 0.4:
                domain = random.choice(self.high_entropy_domains)
            else:
                domain = self._generate_synthetic_high_entropy()
            is_malicious = 1

        else:  # DGA
            if random.random() < 0.4:
                domain = random.choice(self.dga_domains)
            else:
                domain = self._generate_synthetic_dga()
            is_malicious = 1

        return SimulatedDNSQuery(
            timestamp=timestamp,
            client_ip=client_ip,
            domain=domain,
            query_type=query_type,
            source_mode="MOCK",
            category=category,
            is_malicious=is_malicious,
        )

    def record_query(self, query: SimulatedDNSQuery) -> int:
        """
        Persist a simulated query into the SQLite database.
        Also runs prototype domain analysis and logs security alerts for malicious queries.
        Returns the inserted request ID.
        """
        # Run prototype heuristic analysis
        analysis = analyze_domain(query.domain)
        is_malicious = 1 if analysis["prediction"] == "MALICIOUS" else 0

        # 1. Insert DNS request
        req_id = database.insert_dns_request(
            client_ip=query.client_ip,
            query_domain=query.domain,
            query_type=query.query_type,
            source_mode=query.source_mode,
            is_malicious=is_malicious,
            timestamp=query.timestamp,
            db_path=self.db_path,
        )

        # 2. Insert domain analysis record
        database.insert_domain_analysis(
            dns_request_id=req_id,
            domain=analysis["domain"],
            domain_length=analysis["domain_length"],
            entropy=analysis["entropy"],
            digit_count=analysis["digit_count"],
            special_char_count=analysis["special_char_count"],
            subdomain_count=analysis["subdomain_count"],
            vowel_ratio=analysis["vowel_ratio"],
            tld=analysis["tld"],
            suspicious_keyword_count=analysis["suspicious_keyword_count"],
            prediction=analysis["prediction"],
            confidence_score=analysis["confidence_score"],
            analyzed_at=query.timestamp,
            db_path=self.db_path,
        )

        # 3. If malicious, insert security alert
        if is_malicious:
            reason_text = " | ".join(analysis["reasons"])
            database.insert_security_alert(
                dns_request_id=req_id,
                domain=analysis["domain"],
                client_ip=query.client_ip,
                severity=analysis["severity"],
                threat_type=analysis["primary_threat_type"],
                confidence_score=analysis["confidence_score"],
                status="NEW",
                details=reason_text,
                created_at=query.timestamp,
                db_path=self.db_path,
            )

        return req_id

    @property
    def is_running(self) -> bool:
        """Return True if background simulation thread is currently active."""
        return (
            self._thread is not None
            and self._thread.is_alive()
            and not self._stop_event.is_set()
        )

    def run(self, count: Optional[int] = None, verbose: bool = True) -> int:
        """
        Run the simulator:
        - If count is specified, runs for that many queries and returns.
        - If count is None, runs continuously until KeyboardInterrupt or stop() called.
        Returns the number of queries generated.
        """
        # Ensure database and tables are ready
        database.init_db(self.db_path)

        generated = 0
        if verbose:
            mode_str = f"{count} queries" if count else "continuous mode (Press Ctrl+C to stop)"
            print(f"[DNSSimulator] Started in {mode_str} (Interval: {self.interval}s)")
            print("-" * 75)

        try:
            while not self._stop_event.is_set():
                query = self.generate_query()
                req_id = self.record_query(query)
                generated += 1

                if verbose:
                    flag = "MALICIOUS" if query.is_malicious else "SAFE"
                    print(
                        f"[{query.timestamp[11:19]}] #{req_id:<4} "
                        f"{query.client_ip:<15} | {query.query_type:<5} | "
                        f"{query.domain:<40} | [{flag} - {query.category}]"
                    )

                if count and generated >= count:
                    break

                # Responsive wait: wakes up immediately if stop() is called
                if self._stop_event.wait(timeout=self.interval):
                    break

        except KeyboardInterrupt:
            if verbose:
                print("\n[DNSSimulator] Stopped by user (KeyboardInterrupt).")
        finally:
            self._stop_event.set()
            if verbose:
                print(f"[DNSSimulator] Session ended. Total queries generated: {generated}")

        return generated

    def start_background(self, interval: Optional[float] = None) -> bool:
        """Start the simulator in a background daemon thread."""
        if self.is_running:
            return False  # Already running

        if interval:
            self.interval = interval
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self.run,
            kwargs={"count": None, "verbose": False},
            daemon=True,
        )
        self._thread.start()
        return True

    def stop(self) -> bool:
        """Stop the background simulation loop."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        return True


# Global simulator instance for shared application lifecycle
_global_simulator: Optional[DNSSimulator] = None


def get_simulator(
    db_path: Optional[Path | str] = None,
    interval: float = config.DEFAULT_SIMULATOR_INTERVAL,
) -> DNSSimulator:
    """Return or initialize the global shared DNSSimulator instance."""
    global _global_simulator
    if _global_simulator is None:
        _global_simulator = DNSSimulator(db_path=db_path, interval=interval)
    return _global_simulator


def main():
    """Command-line entry point for the DNS simulator."""
    parser = argparse.ArgumentParser(
        description="DNS Security Monitor - Mock DNS Traffic Simulator"
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=config.DEFAULT_SIMULATOR_INTERVAL,
        help=f"Interval between queries in seconds (default: {config.DEFAULT_SIMULATOR_INTERVAL})",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=None,
        help="Number of queries to generate (default: continuous until Ctrl+C)",
    )
    parser.add_argument(
        "--db",
        type=str,
        default=None,
        help=f"Path to SQLite database (default: {config.DB_PATH})",
    )

    args = parser.parse_args()

    simulator = DNSSimulator(db_path=args.db, interval=args.interval)
    simulator.run(count=args.count, verbose=True)


if __name__ == "__main__":
    main()
