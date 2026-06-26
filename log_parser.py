from datetime import datetime
current_time = datetime.now().strftime("%Y-%m-%d %H:%M")



# 1. Open the file from the hard drive in read ('r') mode
with open("server_logs.txt", "r") as log_file:

     print("--- Reading Live Logs From Drive ---")
     
     # 2. Loop through every single line in that file automatically
     for line in log_file:
         # 3. Print the line, removing extra hidden spacing with .strip()
         print(line.strip())
         
  
  
# 1. Open the raw logs to read ('r') And a new file to write ('w') our alerts
with open("server_logs.txt", "r") as log_file, open("security_alerts.txt", "w") as alert_file:
     
     print("Parsing logs and writing alerts to disk...")
     
     for line in log_file:
         # 2. Look for the threat keyword
         if "malicious" in line:
             # THIS LINE UPDATED: it adds the time variable right before the log text
             alert_file.write("[" + current_time + "] [ALERT]: " + line)
             
print("Process finished! Check your folder.")
