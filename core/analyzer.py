"""
Domain Feature Extractor & Prototype Detection Engine.
Computes lexical features and applies rule-based heuristic classification.
Clearly labeled as a prototype detection mechanism prior to Phase 2 ML integration.
"""

import math
import re
from typing import Any, Dict, List

# Prototype Phishing & Lure Keywords
SUSPICIOUS_KEYWORDS = [
    "paypal",
    "login",
    "verify",
    "verification",
    "account",
    "security",
    "bank",
    "update",
    "auth",
    "support",
    "billing",
    "wallet",
    "token",
    "portal",
    "alert",
    "confirm",
    "wellsfargo",
    "chase",
    "appleid",
    "cancellation",
    "password",
]

# High-risk TLDs commonly observed in malicious DNS campaigns
HIGH_RISK_TLDS = {"xyz", "top", "biz", "info", "ru", "cn", "cc", "pw", "site", "club", "online"}


def calculate_entropy(text: str) -> float:
    """
    Calculate Shannon character entropy: H = -sum(p * log2(p)).
    High entropy (> 3.5) often signifies DGA or randomly generated strings.
    """
    if not text:
        return 0.0
    text_clean = text.lower().replace(".", "").replace("-", "")
    if not text_clean:
        return 0.0

    length = len(text_clean)
    counts: Dict[str, int] = {}
    for char in text_clean:
        counts[char] = counts.get(char, 0) + 1

    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 3)


def extract_features(domain_input: str) -> Dict[str, Any]:
    """
    Extract lexical, structural, and linguistic features from a domain string.
    """
    domain = domain_input.strip().lower()

    # Strip protocol or trailing slash if passed by user in manual input
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/")[0].split(":")[0]

    domain_length = len(domain)

    # Count digits
    digit_count = sum(c.isdigit() for c in domain)

    # Count special characters (excluding dots)
    special_char_count = sum(not c.isalnum() and c != "." for c in domain)

    # Subdomain count
    parts = domain.split(".")
    # e.g., 'sub.example.com' has 3 parts -> 1 subdomain
    subdomain_count = max(0, len(parts) - 2) if len(parts) > 1 else 0

    # TLD
    tld = parts[-1] if len(parts) > 1 else ""

    # Suspicious keywords matching
    matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in domain]
    suspicious_keyword_count = len(matched_keywords)

    # Linguistic features: Vowel ratio & entropy
    alpha_chars = [c for c in domain if c.isalpha()]
    total_alpha = len(alpha_chars)
    vowels = sum(c in "aeiouy" for c in alpha_chars)
    vowel_ratio = round(vowels / total_alpha, 3) if total_alpha > 0 else 0.0

    entropy = calculate_entropy(domain)

    return {
        "domain": domain,
        "domain_length": domain_length,
        "digit_count": digit_count,
        "special_char_count": special_char_count,
        "subdomain_count": subdomain_count,
        "tld": tld,
        "suspicious_keyword_count": suspicious_keyword_count,
        "matched_keywords": matched_keywords,
        "vowel_ratio": vowel_ratio,
        "entropy": entropy,
    }


def analyze_domain(domain_input: str) -> Dict[str, Any]:
    """
    Analyze domain and classify as SAFE or MALICIOUS using prototype rule-based heuristics.
    Returns feature dictionary along with detection result and human-readable reasoning.
    """
    features = extract_features(domain_input)
    domain = features["domain"]

    reasons: List[str] = []
    risk_score = 0
    threat_type = "Benign"

    # Rule 1: Suspicious / Phishing Keywords
    if features["suspicious_keyword_count"] > 0:
        kw_list = ", ".join(features["matched_keywords"])
        reasons.append(f"Contains phishing/lure keyword(s): '{kw_list}'")
        risk_score += features["suspicious_keyword_count"] * 2
        threat_type = "Phishing Keyword Match"

    # Rule 2: High Entropy (DGA or Random Hex String)
    if features["entropy"] >= 3.65 and features["domain_length"] >= 10:
        reasons.append(f"High character entropy ({features['entropy']:.2f}) indicates random/algorithmic generation")
        risk_score += 2
        threat_type = "DGA / High Entropy"

    # Rule 3: High-Risk TLD with other anomalies
    if features["tld"] in HIGH_RISK_TLDS:
        reasons.append(f"Registered on elevated-risk TLD (.{features['tld']})")
        risk_score += 1
        if threat_type == "Benign":
            threat_type = "Suspicious TLD"

    # Rule 4: High Digit Count
    if features["digit_count"] >= 4:
        reasons.append(f"Abnormally high numeric digit count ({features['digit_count']} digits)")
        risk_score += 1
        if threat_type == "Benign":
            threat_type = "Suspicious Digit Pattern"

    # Rule 5: Multiple Hyphens / Special Characters
    if features["special_char_count"] >= 2:
        reasons.append(f"High special character / hyphen count ({features['special_char_count']} characters)")
        risk_score += 1

    # Rule 6: Low Vowel Ratio with sufficient length (DGA Consonant Clustering)
    if features["vowel_ratio"] < 0.20 and features["domain_length"] >= 10:
        reasons.append(f"Unusually low vowel ratio ({features['vowel_ratio'] * 100:.1f}%), typical of DGA strings")
        risk_score += 2
        threat_type = "DGA Consonant Pattern"

    # Rule 7: Excessive Subdomains
    if features["subdomain_count"] >= 3:
        reasons.append(f"Deep subdomain chaining ({features['subdomain_count']} subdomains)")
        risk_score += 1

    # Classification Decision
    if risk_score >= 2:
        prediction = "MALICIOUS"
        confidence_score = min(0.98, 0.65 + (risk_score * 0.07))
        if risk_score >= 4:
            severity = "CRITICAL"
        elif risk_score >= 3:
            severity = "HIGH"
        else:
            severity = "MEDIUM"
    else:
        prediction = "SAFE"
        confidence_score = 0.92
        severity = "LOW"
        reasons.append("Standard lexical structure, reputable TLD, normal character distribution, and no phishing lures.")

    return {
        **features,
        "prediction": prediction,
        "confidence_score": round(confidence_score, 2),
        "severity": severity,
        "primary_threat_type": threat_type,
        "reasons": reasons,
        "risk_score": risk_score,
        "engine_label": "Prototype Rule-Based Engine (Pre-ML Baseline)",
    }
