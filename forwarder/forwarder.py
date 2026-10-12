import json
import os
import time

import boto3

ALERTS = "/var/ossec/logs/alerts/alerts.json"
MIN_LEVEL = 7
bus = boto3.client("events", region_name=os.environ.get("AWS_REGION", "us-east-1"))


def follow(path):
    """Yield new lines from alerts.json, reopening it when Wazuh rotates the file."""
    skip_history = True
    while True:
        try:
            f = open(path)
        except FileNotFoundError:
            time.sleep(2)
            continue
        with f:
            if skip_history:
                f.seek(0, os.SEEK_END)
                skip_history = False
            inode = os.fstat(f.fileno()).st_ino
            while True:
                line = f.readline()
                if line:
                    yield line
                    continue
                time.sleep(0.5)
                try:
                    if os.stat(path).st_ino != inode:
                        break
                except FileNotFoundError:
                    break


for line in follow(ALERTS):
    try:
        alert = json.loads(line)
    except json.JSONDecodeError:
        continue
    if alert.get("rule", {}).get("level", 0) < MIN_LEVEL:
        continue
    try:
        bus.put_events(Entries=[{
            "Source": "wazuh.siem",
            "DetailType": "Security Alert",
            "Detail": json.dumps(alert),
        }])
    except Exception as e:
        print("put_events failed:", e)
