# Scope, Authorization & Limitations

## 1. Authorized Assessment Environment

This security assessment platform operates strictly within an **authorized, local, air-gapped evaluation environment**.

- **Target System:** World Monitor Application (local Git repository clone).
- **Network Scope:** Offline local execution (`localhost:8000`, `localhost:5173`). No external packets are transmitted to any public network.
- **Data Boundary:** Critical infrastructure coordinates from the IAEA DIIF database are isolated to `private/` and gitignored. Non-admin queries receive HMAC-jittered coarsened coordinates.
- **Evaluation Mandate:** SIH 26163 Security Audit & Defense Verification Team.

---

## 2. Claims This Project DOES NOT Make (Explicit Non-Claims)

To ensure academic and professional integrity during judging and technical review, the following limitations are explicitly stated:

### 2.1 No Live External Network Exploitation
- This project **DOES NOT** perform active port scanning, denial of service, fuzzing, or credential brute-forcing against production external systems, including the United Nations (UN), the International Atomic Energy Agency (IAEA), or third-party news agencies.
- All network interactions occur entirely within local Docker containers or temporary in-memory TestClient sessions.

### 2.2 No Exfiltration or Storage of Real-World Secrets
- This project **DOES NOT** store, harvest, or transmit genuine operational passwords, AWS access keys, or production certificates.
- All scanned tokens in test datasets are synthetic, masked (`AKIA***1234`), or managed via local `.env` configuration.

### 2.3 No Physical Facility Intrusion or SCADA/OT Access
- This project evaluates **application-level API security and data privacy**.
- It **DOES NOT** claim physical security testing, SCADA/ICS programmable logic controller intrusion, or operational technology bypass at any radiological or nuclear facility.

### 2.4 Local Static Analysis Scope
- Attack surface scanning performed by `backend/targets/worldmonitor_review.py` is strictly read-only and static. Findings generated from route discovery start with **Confidence: "Needs Validation"** and **Lifecycle: "DISCOVERED"** until verified by a test harness.

### 2.5 No Absolute Production Immunity Claim
- Successful remediation of the tested OWASP API Top 10 vulnerabilities does not constitute an absolute guarantee against zero-day exploits.
- In production, defense-in-depth requires active Web Application Firewalls (WAF), mutual TLS (mTLS), DDoS scrubbing, and continuous threat monitoring.

---

## 3. Rules of Engagement & Ethical Boundaries

1. **Safety First:** Test scripts must never execute destructive modifications or drop production tables without confirmation.
2. **Deterministic Reproducibility:** Every reported vulnerability must be independently verifiable using the automated PoC suite in `backend/poc/`.
3. **Responsible Disclosure:** Flaws detected in open-source third-party dependencies are handled in compliance with ISO/IEC 29147 standard vulnerability handling practices.
