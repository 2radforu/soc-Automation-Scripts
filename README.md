# Security Operations Center (SOC) Automation Scripts

A collection of lightweight Python automation tools designed to assist Tier 1 SOC Analysts with rapid incident response, log triage, and network monitoring.

## 🛠️ Tool 1: Automated Log Parser & Incident Triage Pipeline (`log_parser.py`)

This script simulates a Security Information and Event Management (SIEM) pipeline by automatically scanning raw server logs from a system hard drive, isolating high-priority malicious activity, and generating permanent, timestamped incident reports.

### Key Features
*   **File I/O Management:** Efficiently handles reading raw system logs and writing alert streams to disk using Python's secure context managers (`with open`).
*   **String Manipulation & Filtering:** Parses individual log entries line-by-line using conditional logic (`if/else` and `in`) to isolate threat indicators.
*   **Dynamic Forensics Stamping:** Imports the native `datetime` library to inject automated timestamps onto critical threat reports for forensic tracking.

### Skills Demonstrated
*   Python Fundamentals (Lists, Loops, Conditionals, Library Imports)
*   Linux Environment Navigation (Ubuntu, Gedit, Process Management)
*   Data Pipeline Triage & Log Analysis


## 🗺️ Project Future Roadmap

To simulate corporate infrastructure scaling, the following architectural upgrades are actively planned for implementation:

- [ ] **Phase 1: ChatOps Integration (Webhooks)** - Integrate the `requests` library to instantly shoot critical alert cards into a secure Discord/Slack channel.
- [ ] **Phase 2: Data Architecture Normalization (JSON)** - Migrate text logging outputs to enterprise-standard JSON blocks to ensure seamless pipeline compatibility with Splunk and ElasticSearch.
- [ ] **Phase 3: Network Concurrency (Multi-Threading)** - Upgrade the upcoming network socket scanner to handle concurrent operations, allowing it to triage 100+ ports simultaneously.




<a href="https://buymeacoffee.com" target="_blank">
  <img src="https://cdn.buymeacoffee.com/buttons/default-orange.png" alt="Buy Me A Coffee" height="41" width="174">
</a>
