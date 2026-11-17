SIFTVEIL
Email Phishing and Social-Engineering Scanner
============================================================

OVERVIEW
--------
SiftVeil is a Python command-line tool for examining .eml email files and,
optionally, monitoring an IMAP inbox for unread messages. It combines email
content heuristics, sender-domain checks, link analysis, and optional external
reputation services.

FEATURES
--------
- Parses email headers, text/HTML bodies, links, and attachment filenames.
- Looks for urgency, credential requests, and common social-engineering cues.
- Reviews available SPF, DKIM, and DMARC results in email headers.
- Checks basic DNS records and domain registration age through RDAP.
- Checks links with VirusTotal and urlscan.io when API keys are configured.
- Optionally submits URLs to Joe Sandbox when a key is configured.
- Can inspect redirect chains and basic page structure without executing JS.
- Produces a technical report or a plain-English report.

REQUIREMENTS
------------
- Python 3.9 or newer recommended.
- Internet connection for online lookups.
- API keys are optional; some online checks will be skipped without them.

INSTALLATION
------------
1. Download or clone this repository.
2. Open a terminal in the project folder.
3. Install dependencies:

   python3 -m pip install -r requirements.txt

API KEY CONFIGURATION (NO .ENV FILE REQUIRED)
---------------------------------------------
1. Open siftveil.py in a text editor.
2. Find the section named "API CONFIGURATION" near the top.
3. Put your own keys between the quotation marks:

   VT_KEY = "YOUR_VIRUSTOTAL_API_KEY"
   URLSCAN_KEY = "YOUR_URLSCAN_API_KEY"
   JOE_KEY = "YOUR_JOE_SANDBOX_API_KEY"  # optional

4. Save the file.
5. Test configured keys:

   python3 siftveil.py keys

IMPORTANT: Never commit real API keys to GitHub. The public version of this
repository intentionally contains empty key placeholders. Keep your working
copy with real keys outside the public repository, or restore blank values
before every commit. Do not include screenshots that reveal key values.

USAGE
-----
Test API connections:

   python3 siftveil.py keys

Scan one email:

   python3 siftveil.py scan suspicious.eml

Scan multiple email files:

   python3 siftveil.py scan sample1.eml sample2.eml

Show a plain-English report:

   python3 siftveil.py scan suspicious.eml --simple

Save a JSON report:

   python3 siftveil.py scan suspicious.eml --json report.json

Skip direct requests to suspicious URLs:

   python3 siftveil.py scan suspicious.eml --no-fetch

The tool processes up to five links per email by default. Use --max-links to
change this limit. Use --offline to skip external online services.

LIVE IMAP WATCH MODE
--------------------
The optional watch mode uses IMAP credentials supplied through the environment
variables IMAP_HOST, IMAP_USER, and IMAP_PASS. It checks unread messages in the
INBOX. This is separate from the API-key configuration above. Do not hardcode
mailbox passwords into a public source file.

SECURITY AND PRIVACY NOTES
--------------------------
- Keep API keys, mailbox passwords, personal emails, and private scan reports
  out of public repositories.
- The .gitignore file excludes common local secrets, .eml samples, reports,
  and Python cache files. Always review `git status` before committing.
- VirusTotal, urlscan.io, and Joe Sandbox receive URLs submitted for analysis.
  Do not submit confidential, password-reset, invitation, or private tracking
  URLs unless you are authorized and understand the disclosure implications.
- The optional direct page-fetch feature contacts URLs from your machine. Use
  an isolated virtual machine and consider --no-fetch.
- Attachment checks currently inspect filenames and extensions; they do not
  perform full malware analysis of attachment contents.
- A low risk score is not proof that an email is safe. Treat results as
  indicators for further review, not a definitive security verdict.
- This project is for defensive email analysis and authorized testing.

REPOSITORY FILES
----------------
siftveil.py       Main Python application
README.md         GitHub-formatted project documentation
README.txt        Plain-text instructions
requirements.txt  Python dependencies
.gitignore        Excludes local secrets and test artifacts

LICENSE
-------
No license is included. Add a license only after choosing the terms under
which you want others to use, modify, and redistribute your project.
