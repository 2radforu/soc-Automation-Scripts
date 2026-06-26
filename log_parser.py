# Import Python's built-in time module
from datetime import datetime

# Grab the current year, month, day, hour, and minute
current_time = datetime.now().strftime("%Y-%m-%d %H:%M")

# Open the logs to read ('r') and the alert file to write ('w')
with open("server_logs.txt", "r") as log_file, open("security_alerts.txt", "w") as alert_file:
    
    print("Parsing logs and adding timestamps...")
    
    for line in log_file:
        if "Malicious" in line:
            # Add the current time stamp directly into the written line
            alert_file.write("[" + current_time + "] [ALERT]: " + line)

print("Process finished! Check your updated report.")







