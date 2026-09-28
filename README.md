# ThreatLens

A web security scanner that fingerprints tech stacks, audits HTTP headers, and maps CVEs from the NVD database.

## Quick start

\\\ash
pip install -r requirements.txt
uvicorn main:app --reload
\\\`n
Open http://localhost:8000

## Configuration

Copy \.env.example\ to \.env\ and set your values:

\\\`nNVD_API_KEY=your_key_here
\\\`n
> **NEVER commit \.env\ or any real API keys to source control.**
> The \.env\ file is already in \.gitignore\.
> Rotate keys immediately if accidentally exposed.

## Running tests

\\\ash
pip install -r requirements-dev.txt
pytest tests/ -v
\\\`n
## Security notes

- Scanning private/internal addresses is blocked by default (SSRF protection).
- Set \ALLOW_PRIVATE_TARGETS=true\ in \.env\ only for local development against targets like Juice Shop or DVWA.
- CVE results marked **Confirmed** use CPE-based NVD lookup (more accurate).
- Results marked **Possible** use keyword search and may include false positives.
- For authorized security assessment only.
