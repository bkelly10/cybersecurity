# First step is "pip install --upgrade google-api-python-client google-auth-httplib2 google-auth-oauthlib" to access a vareity of google apis and modules for this script

#imports
import os
import pickle
import time
import re
import logging
from datetime import datetime

#google imports
from google.auth.transport.requests import Request         # refresh tokens when access token expires
from google_auth_oauthlib.flow import InstalledAppFlow     # manages browser-based OAuth flow for Google login
from googleapiclient.discovery import build                # creates Gmail API service object used to read and label messages


