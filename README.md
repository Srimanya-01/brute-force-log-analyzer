# Brute-Force Log Analyzer

A Python-based security tool that analyzes authentication logs to detect potential brute-force attacks by identifying repeated failed login attempts from the same IP address.

## Objective
To automate threat detection workflows by identifying malicious reconnaissance and unauthorized brute-force guessing patterns inside corporate access logs.

## Features
- Parses complex unstructured server string logs into key metrics (IP, Timestamp, Status).
- Implements a localized state table to aggregate risk metrics per unique host.
- Generates immediate, conditional security alert flags when risk thresholds are exceeded.

## Incident Remediation Advice
The script successfully flagged IP `192.168.1.50` with high-risk behavior.
**Remediation Steps:**
1. Configure the enterprise firewall or router access control list (ACL) to block all incoming traffic from the malicious IP immediately.
2. Implement an Account Lockout Policy that freezes user accounts automatically after 3 incorrect password attempts to completely neutralize automated guessing tools.
## How to Run

### 1. Clone the repository

```bash
git clone https://github.com/Srimanya-01/brute-force-log-analyzer.git
```

### 2. Navigate to the project folder

```bash
cd brute-force-log-analyzer
```

### 3. Run the program

```bash
