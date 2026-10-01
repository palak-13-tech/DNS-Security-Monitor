"""
Centralized Configuration Module for DNS Security Monitor.
Manages file paths, database settings, and simulation presets.
"""

from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "dns_monitor.db"

# Ensure data directory exists
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Database Configuration
SQLITE_TIMEOUT = 10.0  # seconds to wait for database locks

# Simulator Configuration
DEFAULT_SIMULATOR_INTERVAL = 1.0  # seconds between simulated DNS requests

# Sample Client IPs for realistic local network traffic simulation
SIMULATOR_CLIENT_IPS = [
    "192.168.1.10",
    "192.168.1.15",
    "192.168.1.24",
    "192.168.1.35",
    "192.168.1.42",
    "192.168.1.78",
    "192.168.1.105",
    "10.0.0.12",
    "10.0.0.45",
    "10.0.0.88",
]

# Supported DNS query record types
DNS_QUERY_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT"]
DNS_QUERY_WEIGHTS = [0.80, 0.10, 0.05, 0.03, 0.02]

# 1. Normal/Benign domains (Popular, reputable services)
SAMPLE_NORMAL_DOMAINS = [
    "google.com",
    "github.com",
    "wikipedia.org",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "cloudflare.com",
    "stackoverflow.com",
    "zoom.us",
    "netflix.com",
    "linkedin.com",
    "mit.edu",
    "nih.gov",
    "reddit.com",
    "youtube.com",
]

# 2. Suspicious / Phishing-style domains (Brand spoofing & deceptive keywords)
SAMPLE_SUSPICIOUS_DOMAINS = [
    "paypal-security-update.account-verification.com",
    "secure-login-wellsfargo.com",
    "appleid-verify-alert.net",
    "chase-online-banking-auth.support",
    "netflix-billing-update-portal.org",
    "microsoft-security-auth-check.xyz",
    "bankofamerica-alert-center.info",
    "amazon-order-cancellation-confirm.top",
    "google-docs-drive-shared-doc.xyz",
    "crypto-wallet-ledger-validation.co",
]

# 3. High-entropy / Random-looking domains (Suspicious unstructured alphanumeric names)
SAMPLE_HIGH_ENTROPY_DOMAINS = [
    "k8x92m0qvwz14.info",
    "zq91bx847fplk2.biz",
    "d3f8a92e10c7b.top",
    "qx928374hfkjsdf.cc",
    "99a1b2c3d4e5f.club",
    "w8v7u6t5s4r3q2.site",
    "m4n3b2v1c0x9z.pw",
    "p1o2i3u4y5t6r7.online",
]

# 4. DGA-style domains (Domain Generation Algorithms: consonant clustering / pseudo-random seeds)
SAMPLE_DGA_DOMAINS = [
    "bcdfghjklmnpqrst.net",
    "vxbzqwkjhgf.cc",
    "akdflqowieurytz.org",
    "rxytpwqkmzb.ru",
    "jhgfdsazxcvb.cn",
    "mnbvcxzlkjhgfd.biz",
    "qwrtypsdfghjkl.info",
    "zxcvbnmasdfgh.top",
]
