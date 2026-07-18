from datetime import datetime

# Read server logs from a text file
with open("sample_logs.txt", "r") as file:
    server_logs = file.readlines()


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
