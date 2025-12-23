# logger.py

from datetime import datetime

LOG_FILE = "firewall.log"

def log_event(event):
    with open(LOG_FILE, "a") as file:
        file.write(f"{datetime.now()} - {event}\n")
