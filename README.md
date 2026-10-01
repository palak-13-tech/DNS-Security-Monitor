# DNS Security Monitoring & Malicious Domain Detection

## About the Project

This project is a DNS Security Monitoring System designed to monitor DNS requests and identify potentially malicious domains.

The system analyzes domain names using security-based features and classifies them as **SAFE** or **MALICIOUS**. When a suspicious domain is detected, the system generates a security alert.

## Features

- DNS request monitoring
- Malicious domain detection
- SAFE / MALICIOUS classification
- Security alerts for suspicious domains
- Domain analysis
- SOC-style security dashboard
- Mock DNS traffic simulation
- SQLite database for storing DNS activity

## Technology Used

- Python
- Flask
- SQLite
- HTML
- CSS
- JavaScript
- Gunicorn

## How It Works

1. DNS requests are generated through the DNS simulator.
2. The domain is analyzed using security-based features.
3. The system classifies the domain as SAFE or MALICIOUS.
4. Suspicious domains generate security alerts.
5. The results are displayed on the security dashboard.

## Project Status

This is a prototype version of the DNS Security Monitoring and Malicious Domain Detection System.

## Future Scope

- Machine Learning based malicious domain detection
- Live DNS traffic monitoring
- Advanced threat detection
- Real-time security alerts
- Integration with external threat intelligence sources
