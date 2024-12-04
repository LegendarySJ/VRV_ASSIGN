import random
from datetime import datetime, timedelta

# Define sample data
ips = ["192.168.1.1", "203.0.113.5", "10.0.0.2", "198.51.100.23", "192.168.1.100"]
endpoints = ["/home", "/login", "/about", "/contact", "/dashboard", "/profile", "/register", "/feedback"]
methods = ["GET", "POST"]
statuses = [200, 401, 404, 500]
sizes = [128, 256, 512, 768, 1024]

# Generate timestamps
start_time = datetime(2024, 12, 3, 10, 12, 34)
log_entries = []

# Generate random log entries
for _ in range(50):  # Change 50 to the number of entries you want
    ip = random.choice(ips)
    method = random.choice(methods)
    endpoint = random.choice(endpoints)
    status = random.choice(statuses)
    size = random.choice(sizes)
    timestamp = start_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
    start_time += timedelta(seconds=random.randint(1, 10))  # Increment time randomly
    log_entry = f'{ip} - - [{timestamp}] "{method} {endpoint} HTTP/1.1" {status} {size}'
    
    # Add failed login message for 401 status
    if status == 401:
        log_entry += ' "Invalid credentials"'
    
    log_entries.append(log_entry)

# Save to file
with open("sample.log", "w") as log_file:
    log_file.write("\n".join(log_entries))

print("Sample log file generated: generated_sample.log")
