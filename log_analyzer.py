import sys
from datetime import datetime

# Simulated server logs
server_logs = [
    "2026-06-15 10:01:00 - IP: 192.168.1.50 - Status: FAIL - User: admin",
    "2026-06-15 10:01:05 - IP: 192.168.1.50 - Status: FAIL - User: root",
    "2026-06-15 10:01:10 - IP: 192.168.1.50 - Status: FAIL - User: backup",
    "2026-06-15 10:01:15 - IP: 192.168.1.50 - Status: FAIL - User: guest",
    "2026-06-15 10:02:00 - IP: 10.0.0.12 - Status: SUCCESS - User: srimanya",
    "2026-06-15 10:03:22 - IP: 192.168.1.50 - Status: FAIL - User: mysql",
    "2026-06-15 10:04:00 - IP: 172.16.5.99 - Status: FAIL - User: user1"
]

# Set the threshold for triggering an alert (e.g., more than 3 failures)
FAILED_THRESHOLD = 3
failed_attempts = {}

print("-" * 60)
print(f"SOC Log Analysis Report - Executed at: {datetime.now()}")
print("-" * 60)

# Process each log entry
for entry in server_logs:
    if "Status: FAIL" in entry:
        # Split the string to extract the IP address cleanly
        parts = entry.split(" - ")
        
        # FIXED: We look inside the second element of the list (index 1) to find the IP
        ip_string = parts[1] 
        ip_address = ip_string.replace("IP: ", "")
        
        # Increment the failure counter for this specific IP
        failed_attempts[ip_address] = failed_attempts.get(ip_address, 0) + 1

# Analyze the results and flag malicious actors
incident_detected = False
for ip, count in failed_attempts.items():
    if count >= FAILED_THRESHOLD:
        print(f" [🚨] SECURITY ALERT: Potential Brute-Force Attack Detected!")
        print(f"      Source IP: {ip}")
        print(f"      Total Failed Login Attempts: {count}")
        print(f"      Risk Level: HIGH")
        print("-" * 60)
        incident_detected = True

if not incident_detected:
    print(" [✓] Analysis complete. No malicious activity detected.")
    print("-" * 60)
