# Log Analysis Script

## Overview
This Python script processes a web server log file to extract and analyze key information, such as:
- Counting requests per IP address.
- Identifying the most frequently accessed endpoints.
- Detecting suspicious activity by identifying potential brute force login attempts.

The script displays the results in the terminal and saves them to a CSV file for easy analysis.

## Requirements
- Python 3.x
- No external dependencies (uses standard Python libraries only).

## How to Run the Script

### 1. Generate a Sample Log File
To generate a log file for testing, use the `sample_generator.py` script provided. This script will create a file named `sample.log` with diverse log entries.

1. Open a terminal or command prompt.
2. Navigate to the directory containing `sample_generator.py`.
3. Run the script:
   ```bash
   python sample_generator.py
4. A sample.log file will be created in the same directory.
### 2. Analyze the Log File
Once you have the sample.log file (either generated or your own), run the log analysis script.

Open a terminal or command prompt.
Navigate to the directory containing log_analysis.py.
Run the script, specifying the log file as an argument:

python log_analysis.py sample.log

Output
The script produces two outputs:

Terminal Output: Displays:

Requests per IP address.
The most frequently accessed endpoint.
Suspicious activity (IPs with failed login attempts exceeding the threshold).
CSV File: A file named log_analysis_results.csv is generated with the following sections:

Requests per IP:
Columns: IP Address, Request Count.
Most Accessed Endpoint:
Columns: Endpoint, Access Count.
Suspicious Activity:
Columns: IP Address, Failed Login Count.

How It Works:
Step 1: Run sample_generator.py to create sample.log (if you do not already have a log file).
Step 2: Run log_analysis.py with sample.log as input to process and analyze the log data.
Step 3: View the results printed in the terminal and check the log_analysis_results.csv for a detailed breakdown.
Features:
File Handling: The script handles reading from a log file and writing output to a CSV file.
String Manipulation: Extracts key elements (e.g., IP addresses, endpoints, HTTP status codes) from each log entry.
Data Analysis: Counts, identifies, and flags data points based on criteria like request frequency and login attempts.
Use Cases:
Cybersecurity: Analyze log files to detect unusual patterns and potential security breaches.
Server Monitoring: Track which IPs are making the most requests and identify overused or misused endpoints.
Installation & Requirements:
Python 3.x is required (no additional libraries needed).
Simply run the scripts in a Python environment.
Example Output:
The terminal and CSV output display:

IP request counts.
The most frequently accessed endpoint and its access count.
Suspicious IPs with failed login attempts.
