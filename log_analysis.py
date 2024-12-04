import re
import csv
from collections import Counter

# File paths
log_file = 'sample.log'
output_file = 'log_analysis_results.csv'

# Configurable threshold
failed_login_threshold = 10

# Helper functions
def parse_log_file(file_path):
    with open(file_path, 'r') as file:
        return file.readlines()

def count_requests_per_ip(log_entries):
    ip_pattern = r'^(\d+\.\d+\.\d+\.\d+)'
    ip_addresses = [re.match(ip_pattern, entry).group(1) for entry in log_entries if re.match(ip_pattern, entry)]
    return Counter(ip_addresses)

def find_most_accessed_endpoint(log_entries):
    endpoint_pattern = r'"[A-Z]+\s(/[\w/-]*)'
    endpoints = [re.search(endpoint_pattern, entry).group(1) for entry in log_entries if re.search(endpoint_pattern, entry)]
    return Counter(endpoints).most_common(1)[0]

def detect_suspicious_activity(log_entries, threshold):
    failed_login_pattern = r'^(\d+\.\d+\.\d+\.\d+).*"POST.*" 401'
    failed_ips = [re.match(failed_login_pattern, entry).group(1) for entry in log_entries if re.match(failed_login_pattern, entry)]
    failed_count = Counter(failed_ips)
    return {ip: count for ip, count in failed_count.items() if count > threshold}

def save_to_csv(requests, most_accessed, suspicious_activities, output_path):
    with open(output_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Section: Requests per IP
        writer.writerow(['Requests per IP'])
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in requests.items():
            writer.writerow([ip, count])

        # Section: Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(['Most Accessed Endpoint'])
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow([most_accessed[0], most_accessed[1]])

        # Section: Suspicious Activity
        writer.writerow([])
        writer.writerow(['Suspicious Activity'])
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in suspicious_activities.items():
            writer.writerow([ip, count])

# Main process
log_entries = parse_log_file(log_file)

# Part 1: Requests per IP
requests_per_ip = count_requests_per_ip(log_entries)

# Part 2: Most accessed endpoint
most_accessed_endpoint = find_most_accessed_endpoint(log_entries)

# Part 3: Suspicious activity detection
suspicious_activity = detect_suspicious_activity(log_entries, failed_login_threshold)

# Save results
save_to_csv(requests_per_ip, most_accessed_endpoint, suspicious_activity, output_file)

print(f"Analysis complete. Results saved to {output_file}.")
