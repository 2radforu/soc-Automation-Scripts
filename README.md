# SOC Automation Scripts

[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](#)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](#)
[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-lightgrey)](#)

* Updated log_parser.py to support automated disk writes and active forensic timestamping.

A collection of lightweight Python automation tools to assist Tier‑1 Security Operations Center (SOC) analysts with rapid incident response, log triage, and basic network monitoring.

This repository contains small, focused scripts intended for lab use, training, and lightweight automation in investigative workflows. Do not run these tools on production systems or sensitive dat[...]

## Quick summary

- Small, standalone Python scripts that parse logs, surface high-priority events, and assist with basic triage workflows.
- Designed for learning and lab environments; follow organizational policies before running on production data.

## Table of contents

- Installation
- Requirements
- Usage
- Example input & output
- Available scripts
- Roadmap
- Contributing
- Security & Privacy
- License
- Donate / Contact

## Installation

1. Clone the repository:

   git clone https://github.com/2radforu/soc-Automation-Scripts.git
   cd soc-Automation-Scripts

2. (Optional but recommended) Create a virtual environment and install dependencies:

   python -m venv .venv
   source .venv/bin/activate    # Linux / macOS
   .venv\Scripts\activate     # Windows

   pip install -r requirements.txt

If requirements.txt is not present, install only the packages your environment needs (e.g., pytest for tests) or run the scripts with the system Python for quick testing.

## Requirements

- Tested with Python 3.8+.
- Recommended: run inside a virtual environment.

If you add third-party packages, list them in requirements.txt (pip freeze > requirements.txt after installing) or provide a pyproject.toml.

## Usage

The primary script is log_parser.py. It now provides a small library function and a CLI so you can call it from other tools or directly from the shell.

Examples (exact flags are implemented in the script):

- Basic log parsing (JSON output):

  python log_parser.py --input examples/sample.log --output out/alerts.json --format json

- Basic log parsing (text output):

  python log_parser.py --input examples/sample.log --output out/alerts.txt --format text --pattern "Malicious"

- Run tests:

  pytest

## Example input & output

Example input (examples/sample.log):

    2026-06-25 14:03:12 sshd[12345]: Failed password for invalid user admin from 203.0.113.42 port 54212 ssh2
    2026-06-25 14:04:10 webapp[54321]: Malicious request detected from 198.51.100.23 - /admin.php

Example output (examples/sample_alerts.json - JSON Lines):

{"timestamp": "2026-06-25T14:04:10Z", "event": "Malicious request detected from 198.51.100.23 - /admin.php", "rule": "pattern: Malicious", "severity": "high"}

Note: The parser writes one JSON object per line when using --format json. This makes it easy to stream results into other tools.

## Available scripts

- log_parser.py — Automated Log Parser & Incident Triage Pipeline
  - Purpose: Scan system/server logs, detect high-priority events (by simple pattern matching), and write alert streams to disk in plain text or JSON lines.
  - Behavior: By default it looks for the literal string "Malicious" but you can pass any pattern (substring) via --pattern.

- port_scanner.py — Concurrent TCP port scanner
  - Purpose: Scan TCP ports on a host concurrently using ThreadPoolExecutor and report open ports (shows common service names when available).
  - Usage: python3 port_scanner.py <target> [options]
  - Flags:
    - -s, --start: Start port (default: 1)
    - -e, --end: End port (inclusive, default: 1024)
    - -t, --timeout: Socket timeout in seconds (default: 0.5)
    - -w, --workers: Number of concurrent worker threads (default: 100)
    - -o, --output: Optional output file to append results
  - Example:

    python3 port_scanner.py 127.0.0.1 -s 1 -e 1024 -o open_ports.txt

(If you add more scripts, list them here and include usage examples.)

## Roadmap

- Phase 1: ChatOps Integration (Webhooks) — integrate `requests` to post alerts to Slack/Discord/MS Teams.
- Phase 2: Data Architecture Normalization (JSON) — migrate outputs to structured JSON for Splunk/Elastic compatibility.
- Phase 3: Network Concurrency (asyncio/multi-threading) — upgrade network tools to handle concurrent operations at scale.

## Contributing

Contributions are welcome. To contribute:

1. Open an issue describing the feature or bug.
2. Fork the repository, create a topic branch, and submit a pull request with a clear description of changes.
3. Include tests where possible (tests/ directory) and add examples demonstrating behavior.

Guidelines

- Keep changes small and focused.
- Do not commit real or sensitive logs. Use synthetic examples or redacted files in examples/.
- Follow PEP 8 for Python code style.

## Security & Privacy

- Do NOT commit sensitive logs, credentials, or private keys.
- Redact or synthesize example logs before committing.
- If you find a security vulnerability in the code, open a private issue or contact the repository owner.

## License

This repository is licensed under the MIT License. See LICENSE for details.

## Donate / Contact

If you find these scripts useful, consider supporting me via Buy Me A Coffee:

<a href="https://buymeacoffee.com" target="_blank">
  <img src="https://cdn.buymeacoffee.com/buttons/default-orange.png" alt="Buy Me A Coffee" height="41" width="174">
</a>
