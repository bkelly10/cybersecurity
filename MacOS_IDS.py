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
def iter_macos_sshd_log(last="1h"):
    """
    Yield lines from macOS's unified log filtered to the sshd process.
    Example 'last' values: '30m', '1h', '24h'.
    """
    cmd = [
        "log", "show",
        "--predicate", 'process == "sshd"',
        "--info",
        "--last", last,
    ]
    # capture text output; ignore decoding errors just in case
    proc = subprocess.run(cmd, capture_output=True, text=True, errors="ignore")
    # iterate over each log line
    for line in proc.stdout.splitlines():
        yield line


if __name__ == "__main__":
    # Pull the last hour of sshd logs from macOS and parse them
    for line in iter_macos_sshd_log(last="1h"):
        result = find_failed_event(line)
        if result:
            user, ip = result
            print(f"User: {user}, IP: {ip}")



  
