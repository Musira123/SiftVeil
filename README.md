# SiftVeil

**Email Phishing and Social-Engineering Scanner**

SiftVeil is a Python command-line tool for examining `.eml` email files and, optionally, monitoring an IMAP inbox for unread messages. It combines content heuristics, sender-domain checks, link analysis, and optional external reputation services.

## Features

- Parses email headers, text/HTML bodies, links, and attachment filenames.
- Looks for urgency, credential requests, and common social-engineering cues.
- Reviews available SPF, DKIM, and DMARC results in email headers.
- Checks basic DNS records and domain registration age through RDAP.
- Checks links with VirusTotal and urlscan.io when API keys are configured.
- Optionally submits URLs to Joe Sandbox when a key is configured.
- Inspects redirect chains and basic page structure without executing JavaScript.
- Produces technical or plain-English reports.

## Requirements

- Python 3.9 or newer recommended.
- Internet connection for online lookups.
- API keys are optional; some online checks will be skipped without them.

## Installation

```bash
python3 -m pip install -r requirements.txt
```

## API key configuration (no `.env` file required)

1. Open `siftveil.py` in a text editor.
2. Find **API CONFIGURATION** near the top.
3. Add your own keys between the quotation marks:

```python
VT_KEY = "YOUR_VIRUSTOTAL_API_KEY"
URLSCAN_KEY = "YOUR_URLSCAN_API_KEY"
JOE_KEY = "YOUR_JOE_SANDBOX_API_KEY"  # optional
```

4. Save the file and test the keys:

```bash
python3 siftveil.py keys
```

> **Important:** The public repository intentionally contains empty key placeholders. Never commit real API keys, mailbox passwords, private emails, or confidential scan reports. Keep your working copy with real keys outside the public repository, or restore blank values before committing.

## Usage

```bash
# Test configured API keys
python3 siftveil.py keys

# Scan one email
python3 siftveil.py scan suspicious.eml

# Scan multiple emails
python3 siftveil.py scan sample1.eml sample2.eml

# Plain-English report
python3 siftveil.py scan suspicious.eml --simple

# Save a JSON report
python3 siftveil.py scan suspicious.eml --json report.json

# Skip direct requests to suspicious URLs
python3 siftveil.py scan suspicious.eml --no-fetch
```

The default maximum is five links per email. Use `--max-links` to change it or `--offline` to skip external online services.

## Optional IMAP watch mode

The existing `watch` mode uses the environment variables `IMAP_HOST`, `IMAP_USER`, and `IMAP_PASS` to monitor unread messages in the INBOX. This is separate from API-key configuration. Do not hardcode mailbox passwords into a public source file.

## Security and privacy notes

- Keep API keys, mailbox passwords, personal emails, and private scan reports out of public repositories.
- `.gitignore` excludes common local secrets, `.eml` samples, reports, and Python cache files. Always review `git status` before committing.
- VirusTotal, urlscan.io, and Joe Sandbox receive URLs submitted for analysis. Do not submit confidential, password-reset, invitation, or private tracking URLs unless authorized and aware of the disclosure implications.
- The optional direct page-fetch feature contacts URLs from your machine. Use an isolated virtual machine and consider `--no-fetch`.
- Attachment checks currently inspect filenames and extensions; they do not perform full malware analysis of attachment contents.
- A low risk score is not proof that an email is safe. Treat results as indicators for further review, not definitive security verdicts.
- This project is intended for defensive email analysis and authorized testing.

## Repository files

- `siftveil.py` — main Python application
- `README.md` — GitHub project documentation
- `README.txt` — plain-text instructions
- `requirements.txt` — Python dependencies
- `.gitignore` — excludes local secrets and test artifacts

## License

No license is included. Add a license only after choosing how you want others to use, modify, and redistribute your project.
