# First step is "pip install --upgrade google-api-python-client google-auth-httplib2 google-auth-oauthlib" to access a vareity of google apis and modules for this script

# standard python imports
import os
import pickle
import time
import re
import logging
from datetime import datetime

# google imports
from google.auth.transport.requests import Request         # refresh tokens when access token expires
from google_auth_oauthlib.flow import InstalledAppFlow     # manages browser-based OAuth flow for Google login
from googleapiclient.discovery import build                # creates Gmail API service object used to read and label messages

# variable configuration "constants"

SCOPES = ['https://www.googleapis.com/auth/gmail.modify'] # scopes is inside a list because Google's autho client expects list of strings since you can request multiple permissions at once

CREDENTIALS_FILE = 'credentials.json' 
TOKEN_FILE = 'token.pickle'

SEARCH_QUERY = (
  'from:(no-reply@accounts.google.com OR accounts-noreply@google.com OR no-reply@google.com) '
    'subject:("New sign-in" OR "Sign-in attempt" OR "New sign-in to your Google Account" OR "Suspicious sign-in attempt")'
)                                                        # Gmail search query to find Google sign-in / security alert emails

SCAN_INTERVAL = 60                                            # how often script scans for new alerts in seconds

LOGFILE = 'gmail_signin_monitor.log'
LABEL_NAME = 'Signin-Alerts/Processed'

  
