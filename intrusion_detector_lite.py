import re
import sys
from datetime import datetime, timedelta
from collections import deque, defaultdict

# standard regex strings to indentify IP addresses and Usernames

IP = r'(?:\d{1,3}\.){3}\d{1,3}'
USER = r'/S+'

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

#TEMP TEST BLOCK TO ENSURE FUNCTIONING
if __name__ == "__main__":
    samples = [
        "Oct  4 16:56:02 myhost sshd[1234]: Failed password for invalid user admin from 192.0.2.10 port 54422 ssh2",
        "Oct  4 16:57:00 myhost sshd[1234]: Failed password for root from 198.51.100.5 port 34211 ssh2",
        "authentication failure; rhost=203.0.113.12  user=guest",
        "unrelated line",
    ]
    for s in samples:
        for p in PATTERNS:
            m = p.search(s)
            if m:
                print("Matched pattern:", p.pattern)
                print("User:", m.group('user'))
                print("IP:", m.group('ip'))
                print()



  
