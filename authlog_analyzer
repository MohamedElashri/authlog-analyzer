import re
import requests
from prettytable import PrettyTable

# Helper function to add rows to a table
def add_to_table(table, fields):
    table.add_row(fields)

# Function to extract details from log lines
def extract_details(line, previous_line, success=False):
    time_pattern = r'\w{3}\s+\d+\s+\d+:\d+:\d+'
    user_pattern = r'user\s+(\S+)' if success else r'Invalid user\s+(\S+)'
    ip_pattern = r'\d{1,3}(?:\.\d{1,3}){3}'
    port_pattern = r'port\s+(\d+)'
    session_pattern = r'session opened for user (\S+) by (\S+)(?:\s+\[)?(sshd|sudo|su)?'

    time_match = re.search(time_pattern, line)
    user_match = re.search(user_pattern, line)
    ip_match = re.search(ip_pattern, previous_line) if not success else None
    port_match = re.search(port_pattern, previous_line) if not success else None
    session_match = re.search(session_pattern, line) if success else None

    time = time_match.group(0) if time_match else 'N/A'
    user = user_match.group(1) if user_match else 'N/A'
    ip = ip_match.group(0) if ip_match else 'N/A'
    port = port_match.group(1) if port_match else 'N/A'
    session = session_match.group(3) if session_match else 'N/A'

    return [time, user, ip, port] if not success else [time, user, session]

# Function to get country from IP using a free service
def get_country(ip, ip_countries):
    if ip in ip_countries:
        return ip_countries[ip]

    try:
        response = requests.get(f'http://ip-api.com/json/{ip}')
        if response.status_code == 200:
            country = response.json().get('country', 'Unknown')
            ip_countries[ip] = country
            return country
    except requests.RequestException:
        return 'Unknown'

# Variables
success_attempts = []
failed_attempts = []
root_failed_attempts = []
ip_attempts = {}
username_attempts = {}
ip_countries = {}
country_attempts = {}

# Opens authlog file
previous_line = ""
with open("/var/log/auth.log", "r") as file:
    for line in file:
        # Check for successful attempts
        if 'session opened' in line and ('sshd' in line or 'sudo' in line or 'su' in line):
            success_attempts.append(extract_details(line, previous_line, success=True))

        # Check for failed attempts
        elif 'Invalid user' in line:
            details = extract_details(line, previous_line)
            failed_attempts.append(details)
            if 'for root' in previous_line:
                root_failed_attempts.append(details)
            # Update username_attempts
            username = details[1]
            username_attempts[username] = username_attempts.get(username, 0) + 1

        # IP address extraction
        ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
        if ip_match:
            ip = ip_match.group(1)
            ip_attempts[ip] = ip_attempts.get(ip, 0) + 1

        # Update previous_line at the end of the loop
        previous_line = line

# Creating and displaying tables
def create_table(data, column_names, title):
    table = PrettyTable()
    table.title = title
    table.field_names = column_names
    for row in data:
        add_to_table(table, row)
    return table

# Displaying the tables
print(create_table(failed_attempts, ["Time", "User", "IP Address", "Port"], "Failed Login Attempts"))
print(create_table(root_failed_attempts, ["Time", "User", "IP Address", "Port"], "Failed Login Attempts for Root"))
print(create_table(success_attempts, ["Time", "User", "Session Type"], "Successful Login Attempts"))

# Table for IP attempts
ip_table = PrettyTable()
ip_table.title = "IP Address Attempt Counts"
ip_table.field_names = ["IP Address", "Attempt Count"]
for ip, count in ip_attempts.items():
    add_to_table(ip_table, [ip, count])
print(ip_table)

# Table for Username attempts
username_table = PrettyTable()
username_table.title = "Username Attempt Counts"
username_table.field_names = ["Username", "Attempt Count"]
for username, count in username_attempts.items():
    add_to_table(username_table, [username, count])
print(username_table)

# Table for Country attempts
for ip in ip_attempts:
    country = get_country(ip, ip_countries)
    country_attempts[country] = country_attempts.get(country, 0) + ip_attempts[ip]

country_table = PrettyTable()
country_table.title = "Country Attempt Counts"
country_table.field_names = ["Country", "Attempt Count"]
for country, count in country_attempts.items():
    add_to_table(country_table, [country, count])
print(country_table)

# Other information
print("\nTotal Log Lines:", len(success_attempts) + len(failed_attempts) + len(root_failed_attempts))
print("Successful Login Attempts:", len(success_attempts))
print("Failed Login Attempts:", len(failed_attempts))
print("Failed Login Attempts for Root:", len(root_failed_attempts))
