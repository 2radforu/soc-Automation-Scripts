"""
SOC Log Parser - Advanced log analysis for security threats
Features: severity filtering, regex patterns, and alerting integration
"""

import argparse
import re
import json
import smtplib
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Tuple
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


class LogParser:
    """Parse security logs and generate alerts based on configurable rules."""
    
    # Severity levels mapping
    SEVERITY_LEVELS = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "INFO": 0
    }
    
    # Default threat patterns with severity
    DEFAULT_PATTERNS = {
        "CRITICAL": [
            r"(?i)(privilege\s+escalation|root\s+access|sudo|unauthorized\s+admin)",
            r"(?i)(sql\s+injection|command\s+injection|code\s+execution)",
            r"(?i)(ransomware|malware|trojan|backdoor)"
        ],
        "HIGH": [
            r"(?i)(malicious|threat|attack|exploit)",
            r"(?i)(unauthorized\s+access|brute\s+force|failed\s+login)",
            r"(?i)(suspicious\s+activity|anomaly)"
        ],
        "MEDIUM": [
            r"(?i)(error|failed|denied|refused)",
            r"(?i)(warning|alert)"
        ],
        "LOW": [
            r"(?i)(info|notice)"
        ]
    }
    
    def __init__(self, log_file: str, alert_file: str, json_output: bool = False,
                 min_severity: str = "LOW", custom_patterns: Dict = None):
        """
        Initialize the log parser.
        
        Args:
            log_file: Path to input log file
            alert_file: Path to output alerts file
            json_output: Whether to output alerts as JSON
            min_severity: Minimum severity level to report (CRITICAL, HIGH, MEDIUM, LOW, INFO)
            custom_patterns: Custom regex patterns dict {severity: [patterns]}
        """
        self.log_path = Path(log_file)
        self.alert_path = Path(alert_file)
        self.json_output = json_output
        self.min_severity = min_severity.upper()
        self.patterns = custom_patterns or self.DEFAULT_PATTERNS
        self.alerts = []
        self.stats = {"total_lines": 0, "alerts_by_severity": {}}
        
        # Validate paths
        if not self.log_path.exists():
            raise FileNotFoundError(f"Log file not found: {log_file}")
        
        self.alert_path.parent.mkdir(parents=True, exist_ok=True)
    
    def _extract_timestamp(self, line: str) -> str:
        """
        Extract timestamp from log line or use current time.
        Supports formats: [HH:MM:SS], YYYY-MM-DD, ISO 8601
        """
        timestamp_patterns = [
            r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}',  # ISO 8601
            r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}',  # YYYY-MM-DD HH:MM:SS
            r'\[\d{2}:\d{2}:\d{2}\]',  # [HH:MM:SS]
            r'\d{2}:\d{2}:\d{2}',  # HH:MM:SS
        ]
        
        for pattern in timestamp_patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(0)
        
        return datetime.now().isoformat()
    
    def _classify_severity(self, line: str) -> str:
        """Classify log line by severity based on pattern matching."""
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            for pattern in self.patterns.get(severity, []):
                if re.search(pattern, line):
                    return severity
        return "INFO"
    
    def _should_report(self, severity: str) -> bool:
        """Check if alert should be reported based on minimum severity."""
        return self.SEVERITY_LEVELS.get(severity, 0) >= self.SEVERITY_LEVELS.get(self.min_severity, 0)
    
    def parse(self) -> int:
        """
        Parse log file and generate alerts.
        
        Returns:
            int: Number of alerts generated
        """
        alert_count = 0
        
        try:
            with open(self.log_path, "r", encoding="utf-8", errors="ignore") as log_file:
                print(f"Parsing logs from {self.log_path}...")
                
                for line_num, line in enumerate(log_file, 1):
                    line = line.rstrip('\n')
                    self.stats["total_lines"] += 1
                    
                    severity = self._classify_severity(line)
                    
                    if self._should_report(severity):
                        log_timestamp = self._extract_timestamp(line)
                        process_timestamp = datetime.now().isoformat()
                        
                        alert = {
                            "severity": severity,
                            "log_line_number": line_num,
                            "log_timestamp": log_timestamp,
                            "process_timestamp": process_timestamp,
                            "message": line.strip()
                        }
                        
                        self.alerts.append(alert)
                        alert_count += 1
                        
                        # Update statistics
                        self.stats["alerts_by_severity"][severity] = \
                            self.stats["alerts_by_severity"].get(severity, 0) + 1
            
            self._write_alerts()
            self._print_summary(alert_count)
            
            return alert_count
        
        except IOError as e:
            print(f"❌ Error reading/writing files: {e}")
            raise
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            raise
    
    def _write_alerts(self):
        """Write alerts to file in specified format."""
        if not self.alerts:
            return
        
        try:
            with open(self.alert_path, "a", encoding="utf-8") as alert_file:
                if self.json_output:
                    for alert in self.alerts:
                        alert_file.write(json.dumps(alert) + "\n")
                else:
                    for alert in self.alerts:
                        formatted = (
                            f"[{alert['process_timestamp']}] "
                            f"[{alert['severity']}] "
                            f"[LINE_{alert['log_line_number']}] "
                            f"{alert['message']}\n"
                        )
                        alert_file.write(formatted)
            
            print(f"✓ Alerts written to {self.alert_path}")
        
        except IOError as e:
            print(f"❌ Error writing alerts: {e}")
            raise
    
    def _print_summary(self, alert_count: int):
        """Print summary statistics."""
        print(f"\n{'='*60}")
        print(f"Process finished! {alert_count} alerts found.")
        print(f"Total lines processed: {self.stats['total_lines']}")
        if self.stats["alerts_by_severity"]:
            print("\nAlerts by severity:")
            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                count = self.stats["alerts_by_severity"].get(severity, 0)
                if count > 0:
                    print(f"  {severity}: {count}")
        print(f"{'='*60}\n")
    
    def send_alert_email(self, smtp_server: str, sender: str, recipients: List[str],
                        password: str = None, min_severity_for_email: str = "HIGH"):
        """
        Send critical alerts via email.
        
        Args:
            smtp_server: SMTP server address (e.g., 'smtp.gmail.com:587')
            sender: Sender email address
            recipients: List of recipient email addresses
            password: SMTP password (use environment variable for security)
            min_severity_for_email: Minimum severity to email (default: HIGH)
        """
        if not self.alerts:
            print("No alerts to send.")
            return
        
        critical_alerts = [
            alert for alert in self.alerts
            if self.SEVERITY_LEVELS.get(alert["severity"], 0) >= 
               self.SEVERITY_LEVELS.get(min_severity_for_email, 0)
        ]
        
        if not critical_alerts:
            print(f"No alerts with severity >= {min_severity_for_email} to email.")
            return
        
        try:
            # Parse SMTP server and port
            server_parts = smtp_server.split(":")
            smtp_host = server_parts[0]
            smtp_port = int(server_parts[1]) if len(server_parts) > 1 else 587
            
            # Create email message
            msg = MIMEMultipart()
            msg["From"] = sender
            msg["To"] = ", ".join(recipients)
            msg["Subject"] = f"🚨 SOC Alert: {len(critical_alerts)} Critical/High Severity Events"
            
            # Build email body
            body = f"""
SECURITY ALERT REPORT
Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

Summary: {len(critical_alerts)} alert(s) detected

"""
            for alert in critical_alerts:
                body += f"""
[{alert['severity']}] Line {alert['log_line_number']}
Log Time: {alert['log_timestamp']}
Message: {alert['message']}
---
"""
            
            msg.attach(MIMEText(body, "plain"))
            
            # Send email
            if password is None:
                import os
                password = os.environ.get("SOC_EMAIL_PASSWORD")
                if not password:
                    print("❌ No password provided. Set SOC_EMAIL_PASSWORD environment variable.")
                    return
            
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                server.starttls()
                server.login(sender, password)
                server.send_message(msg)
            
            print(f"✓ Email sent to {recipients} with {len(critical_alerts)} critical alert(s)")
        
        except Exception as e:
            print(f"❌ Error sending email: {e}")
    
    def export_json_report(self, report_file: str):
        """Export detailed JSON report."""
        report = {
            "generated_at": datetime.now().isoformat(),
            "statistics": self.stats,
            "alerts": self.alerts
        }
        
        try:
            with open(report_file, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            print(f"✓ JSON report exported to {report_file}")
        except IOError as e:
            print(f"❌ Error exporting report: {e}")


def main():
    """Command-line interface for log parser."""
    parser = argparse.ArgumentParser(
        description="Advanced SOC log parser with severity filtering and alerting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --log server.log --alert alerts.txt
  %(prog)s --log access.log --severity HIGH --json
  %(prog)s --log system.log --email admin@company.com --smtp smtp.gmail.com:587
        """
    )
    
    parser.add_argument("--log", default="server_logs.txt", help="Input log file")
    parser.add_argument("--alert", default="security_alerts.txt", help="Output alert file")
    parser.add_argument("--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                       default="LOW", help="Minimum severity level to report")
    parser.add_argument("--json", action="store_true", help="Output alerts as JSON")
    parser.add_argument("--email", nargs="+", help="Email alert to recipients")
    parser.add_argument("--smtp", help="SMTP server (e.g., smtp.gmail.com:587)")
    parser.add_argument("--sender", help="Sender email address")
    parser.add_argument("--report", help="Export JSON report to file")
    
    args = parser.parse_args()
    
    try:
        # Initialize parser
        log_parser = LogParser(
            log_file=args.log,
            alert_file=args.alert,
            json_output=args.json,
            min_severity=args.severity
        )
        
        # Parse logs
        alert_count = log_parser.parse()
        
        # Export JSON report if requested
        if args.report:
            log_parser.export_json_report(args.report)
        
        # Send email alerts if configured
        if args.email and args.smtp and args.sender:
            log_parser.send_alert_email(
                smtp_server=args.smtp,
                sender=args.sender,
                recipients=args.email,
                min_severity_for_email="HIGH"
            )
        
        return 0 if alert_count > 0 else 1
    
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        return 1


if __name__ == "__main__":
    exit(main())
