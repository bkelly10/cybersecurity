import re
import sys
from datetime import datetime, timedelta
from collections import deque, defaultdict
import subprocess

# standard regex strings to indentify IP addresses and Usernames

IP = r'(?:\d{1,3}\.){3}\d{1,3}'
USER = r'\S+'

# Creating a list of patterns to loop through as there are a variety of ways a login attempt could fail

PATTERNS = [
  #Invalid username, the password doesn't matter because the username isn't valid
  #Using rf' so that I can use raw strings but also insert variables
  
  re.compile(
    rf'Failed password for invalid user (?P<user>{USER}) from (?P<ip>{IP})',
    re.IGNORECASE
  ),

  # Right username, but authentication failed

  re.compile(
    rf'Failed password for (?P<user>{USER}) from (?P<ip>{IP})',
    re.IGNORECASE
  ),
  
  #Scanning SSHD logs to identify login attempts, and specifically catching when PAM reports failed credential checks
  
  re.compile(
    rf'authentication failure.*rhost=(?P<ip>{IP}).*user=(?P<user>{USER})',
    re.IGNORECASE
  )

]

#Define function to search patterns
def find_failed_event(line): 
  
  for p in PATTERNS:
    match = p.search(line)
    
    if match:
      user = match.group('user')
      ip = match.group('ip')
      return user, ip
      
  return None


#TEMP TEST BLOCK TO ENSURE FUNCTIONING
def iter_macos_sshd_log(last="24h"):
    """Yield sshd-related lines from macOS unified log."""
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


def process_lines(lines):
    """Process lines and print detected user/IP pairs."""
    found = False
    for line in lines:
        match = find_failed_event(line)
        if match:
            user, ip = match
            print(f"User: {user}, IP: {ip}")
            found = True
    return found



  
