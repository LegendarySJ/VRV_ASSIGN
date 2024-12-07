import re
from collections import defaultdict
import csv

# Configurable threshold for failed login attempts to flag as suspicious activity
FAILED_LOGIN_THRESHOLD = 3

# Function to parse the log file and analyze data
def analyze_log_file(file_path):
    ip_request_count = defaultdict(int)
    endpoint_access_count = defaultdict(int)
    failed_login_attempts = defaultdict(int)

    # Regular expressions for extracting data
    ip_pattern = r'(\d+\.\d+\.\d+\.\d+)'
    endpoint_pattern = r'"\w+ (\/[^\s]+) HTTP'
    failed_login_pattern = r'401.*"Invalid credentials"'

    with open(file_path, 'r') as log_file:
        for line in log_file:
            # Extract the IP address
            ip_match = re.search(ip_pattern, line)
            if ip_match:
                ip = ip_match.group(1)
                ip_request_count[ip] += 1

            # Extract the endpoint accessed
            endpoint_match = re.search(endpoint_pattern, line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_access_count[endpoint] += 1

            # Check for failed login attempts
            if re.search(failed_login_pattern, line):
                ip = ip_match.group(1)
                failed_login_attempts[ip] += 1

    # Generate output data
    sorted_ip_request_count = sorted(ip_request_count.items(), key=lambda x: x[1], reverse=True)
    most_accessed_endpoint = max(endpoint_access_count.items(), key=lambda x: x[1], default=("None", 0))
    suspicious_activity = [(ip, count) for ip, count in failed_login_attempts.items() if count >= FAILED_LOGIN_THRESHOLD]

    # Print output to the console
    print("Requests per IP")
    print(f"{'IP Address':<20} {'Request Count':<15}")
    for ip, count in sorted_ip_request_count:
        print(f"{ip:<20} {count:<15}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    print(f"{'IP Address':<20} {'Failed Login Attempts':<20}")
    if suspicious_activity:
        for ip, count in suspicious_activity:
            print(f"{ip:<20} {count:<20}")
    else:
        print("No suspicious activity detected.")

    # Save the output to a CSV file
    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in sorted_ip_request_count:
            writer.writerow([ip, count])

        writer.writerow([])  # Add an empty row for separation
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        writer.writerow([])  # Add an empty row for separation
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_activity:
            writer.writerow([ip, count])

# Main function to run the script
if __name__ == "__main__":
    log_file_path = 'sample.log'  # Path to your log file
    analyze_log_file(log_file_path)
