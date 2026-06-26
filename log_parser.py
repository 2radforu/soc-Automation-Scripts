# Import Python's built-in time module
from datetime import datetime

try:
    # Open the logs to read ('r') and the alert file to append ('a')
    with open("server_logs.txt", "r") as log_file, open("security_alerts.txt", "a") as alert_file:
        
        print("Parsing logs and adding timestamps...")
        alert_count = 0
        
        for line in log_file:
            if "Malicious" in line:
                # Grab the timestamp for each alert detected
                alert_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                alert_file.write(f"[{alert_time}] [ALERT]: {line}")
                alert_count += 1
    
    print(f"Process finished! {alert_count} alerts found. Check your updated report.")

except FileNotFoundError as e:
    print(f"Error: {e}")
