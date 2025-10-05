import re
import sys
import subprocess
from datetime import datetime, timedelta
from collections import deque, defaultdict

# Standard regex strings to indentify IP addresses and usernames

IP = r'(?:\d{1,3}\.){3}\d{1,3}'
USER = r'\S+'

# Creating a list of patterns to loop through as there are a variety of ways a login attempt could fail
# Using rf' so that I can use raw strings but also insert variables
# p1 Invalid username, the password doesn't matter because the username isn't valid
# p2 Right username, but authentication failed
# p3 Scanning SSHD logs to identify login attempts, and specifically catching when PAM reports failed credential checks

PATTERNS = [
    re.compile(
        rf'Failed password for invalid user (?P<user>{USER}) from (?P<ip>{IP})',
        re.IGNORECASE
    ),
    re.compile(
        rf'Failed password for (?:user )?(?P<user>{USER}) from (?P<ip>{IP})',
        re.IGNORECASE
    ),
    re.compile(
        rf'authentication failure.*rhost=(?P<ip>{IP}).*user=(?P<user>{USER})',
        re.IGNORECASE
    ),
]


# Define function to search patterns in a log file, looping through the patterns listed above
# p.search to identify any match (match object) in the log line
# if there is a match, save whatever the regex captured for user and ip 
# Return as a tuple so its immutable
def find_failed_event(line): 
  
  for p in PATTERNS:
    match = p.search(line)
    
    if match:
      user = match.group('user')
      ip = match.group('ip')
      return user, ip
      
  return None


# Bridge python with MacOS logs by iterating over SSHD log lines from MacOS
# Create a list of the terminal commands I want to run and save as a variable to increase efficiency
# Loop through the output text from MacOS logs
# Yield line (result) so that the script runs through each line one at a time, and doesn't end a function like return
def iter_macos_sshd_log(last="24h"):
    
    cmd = [
        "log", "show",
        "--style", "syslog",
        "--predicate",
        'process == "sshd" AND (eventMessage CONTAINS[c] "Failed password" OR eventMessage CONTAINS[c] "Invalid user" OR eventMessage CONTAINS[c] "authentication failure")',
        "--info", "--debug",
        "--last", last,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, errors="ignore")
    for line in result.stdout.splitlines():
        yield line

# Core loop that ties in previous functions
# Process lines and print any detected user/IP pairs
def process_lines(lines):

    found = False
    for line in lines:
        match = find_failed_event(line)
        if match:
            user, ip = match
            print(f"User: {user}, IP: {ip}")
            found = True
    return found

# First, the script checks to see if there is a log file path 
# If there is, it opens the log file path, scans for failed SSHD logins, and prints results
# If no file provided, will autmoateically scan MacOS file logs for past 24 hours
if __name__ == "__main__":

    if len(sys.argv) > 1:
        logfile = sys.argv[1]
        try:
            with open(logfile, "r", errors="ignore") as f:
                found = process_lines(f)
            if not found:
                print(f"No failed logins found in {logfile}.")
        except FileNotFoundError:
            print(f"Error: file '{logfile}' not found.")
        except PermissionError:
            print(f"Error: permission denied reading '{logfile}'. Try using sudo.")
    else:
        found = process_lines(iter_macos_sshd_log(last="24h"))
        if not found:
            print("No sshd auth failures found in the last 24h.")



  
