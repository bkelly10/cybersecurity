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
)  # Gmail search query to find Google sign-in / security alert emails

SCAN_INTERVAL = 60  # how often script scans for new alerts in seconds

LOGFILE = 'gmail_signin_monitor.log'
LABEL_NAME = 'Signin-Alerts/Processed'

# Gmail Auth / Connection Function

def get_gmail_service():

    # import Google libraries locally  
    from google.auth.transport.requests import Request
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build

    creds = None # holds authenticated credentials

    # checks for existing token file -- stores refresh / access tokens
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, 'rb') as f:
            creds = pickle.load(f)

    # if no valid creds, either refresh or run full OAuth flow
    if not creds or not creds.valid:
        # first recovery path -- refreshes token automatically if it exists and is expired 
        if creds and creds.expired and getattr(creds, "refresh_token", None):
            creds.refresh(Request())
        else:
            # second recovery path -- we run full OAuth flow, because we never logged in before or token is revoked / missing 
            if not os.path.exists(CREDENTIALS_FILE):
                raise FileNotFoundError(
                    f"Missing {CREDENTIALS_FILE}. "
                    "Download your OAuth client JSON from Google Cloud and place it beside this script."
                )
            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
            # On Windows 11 this opens your default browser for Google sign-in
            creds = flow.run_local_server(port=0)

        # Cache tokens for next run
        with open(TOKEN_FILE, 'wb') as f:
            pickle.dump(creds, f)

    # Build Gmail service client
    return build('gmail', 'v1', credentials=creds)

# function to ensure Gmail label exists

def ensure_label(service, label_name):
 
    results = service.users().labels().list(userId='me').execute()
    labels = results.get('labels', [])

    for lab in labels:
        if lab.get('name') == label_name:
            return lab['id']

    label_body = {
        'name': label_name,
        'labelListVisibility': 'labelShow',
        'messageListVisibility': 'show'
    }
    new_label = service.users().labels().create(userId='me', body=label_body).execute()
    return new_label['id']

# Searches the user's Gmail inbox for messages matching the query and returns a list of message IDs

def search_messages(service, query, max_results=50):
    # needed to use "dot chain" to access Gmail API's hierarchy
    # .list method returns up to 100 messages per request
    # need a loop to retrieve all matches in a larger inbox / environment
    response = service.users().messages().list(
        userId='me',
        q=query,
        maxResults=max_results
    ).execute()

    # returns the list of message IDs if present, or an empty list as a safe fallback
    return response.get('messages', [])

# function to grab the full message by ID 
def get_message(service, msg_id):
    """
    Fetch a single message by ID in 'full' format.
    Returns the full message resource (headers, payload, snippet).
    """
    return service.users().messages().get(
        userId='me',
        id=msg_id,
        format='full'  # alternatives: 'metadata', 'minimal', 'raw'
    ).execute()

# Defining monitor loop after helper functions
# Polls Gmail for likely Google sign-in/security alert emails, logs a brief line, labels them to avoid reprocessing, then sleeps

def monitor_loop():
    service = get_gmail_service()
    label_id = ensure_label(service, LABEL_NAME)
    seen = set()

    print(f"Polling every {SCAN_INTERVAL}s. Logging to: {LOGFILE}. Press Ctrl+C to stop.")

    # outer try is to help program exit gracefully or log issue
    # inner try keeps any labeling fails contained, continued to next message
    try:
        while True:
            results = search_messages(service, SEARCH_QUERY, max_results=50) or []

            for m in results:
                message_id = m['id']
                if message_id in seen:
                    continue

                msg = get_message(service, message_id)
                snippet = msg.get('snippet', '') or ''

                logging.info(f"[ALERT?] id={message_id} snippet={snippet}")

                try:
                    service.users().messages().modify(
                        userId='me',
                        id=message_id,
                        body={'addLabelIds': [label_id]}
                    ).execute()
                except Exception as e:
                    logging.warning(f"Failed to label message {message_id}: {e}")

                seen.add(message_id)

            time.sleep(SCAN_INTERVAL)
    except KeyboardInterrupt:
        print("Stopping monitor.")

# run login monitor
if __name__ == "__main__":
    monitor_loop()


































