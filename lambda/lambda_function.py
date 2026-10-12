import ipaddress
import json
import os
import time
import urllib.error
import urllib.request

import boto3
from botocore.exceptions import ClientError

GEMINI_KEY = os.environ["GEMINI_API_KEY"]
SLACK_URL = os.environ.get("SLACK_WEBHOOK_URL")
NACL_ID = os.environ["VPC_NACL_ID"]
ALLOWLIST = set(filter(None, os.environ.get("ALLOWLIST", "").split(",")))  # never block these
RULE_NUMBERS = range(50, 100)  # keep below your allow rules (100+)
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash:generateContent"

ec2 = boto3.client("ec2")

PROMPT = """You are a Tier-2 SOC analyst. Decide whether this SIEM alert is a real attack.
Rule {id} (level {level}): {desc}
Source IP: {ip}
Log: {log}
Reply with JSON only: {{"verdict": "TRUE_POSITIVE" or "FALSE_POSITIVE", "confidence": 0 to 1, "mitre_attack": "Name (Txxxx.xxx)", "summary": "one or two sentences"}}"""


def post(url, body, headers=None, timeout=12):
    req = urllib.request.Request(
        url, json.dumps(body).encode(), {"Content-Type": "application/json", **(headers or {})}
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def ask_gemini(prompt, tries=3):
    body = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.1, "responseMimeType": "application/json"},
    }
    for n in range(tries):
        try:
            out = json.loads(post(GEMINI_URL, body, {"x-goog-api-key": GEMINI_KEY}))
            return json.loads(out["candidates"][0]["content"]["parts"][0]["text"])
        except urllib.error.HTTPError as e:  # 429 / 503 are worth retrying
            if e.code not in (429, 503) or n == tries - 1:
                raise
        except (urllib.error.URLError, TimeoutError):
            if n == tries - 1:
                raise
        time.sleep(2 ** (n + 1))


def block(ip):
    cidr = f"{ip}/32"
    acl = ec2.describe_network_acls(NetworkAclIds=[NACL_ID])["NetworkAcls"][0]
    inbound = [e for e in acl["Entries"] if not e["Egress"]]
    if any(e.get("CidrBlock") == cidr and e["RuleAction"] == "deny" for e in inbound):
        return "already blocked"
    used = {e["RuleNumber"] for e in inbound}
    for n in RULE_NUMBERS:
        if n in used:
            continue
        try:
            ec2.create_network_acl_entry(
                NetworkAclId=NACL_ID, RuleNumber=n, Protocol="-1",
                RuleAction="deny", Egress=False, CidrBlock=cidr,
            )
            return f"blocked (rule {n})"
        except ClientError as e:  # another invocation grabbed this number first
            if e.response["Error"]["Code"] != "NetworkAclEntryAlreadyExists":
                raise
    return "ACL full, not blocked"


def notify(t, ip, status):
    if not SLACK_URL:
        return
    text = (f"*{t.get('verdict')}* from `{ip}` | {t.get('mitre_attack')} | "
            f"confidence {float(t.get('confidence', 0)):.0%}\n{t.get('summary')}\nContainment: {status}")
    try:
        post(SLACK_URL, {"text": text}, timeout=5)
    except Exception as e:
        print("slack failed:", e)


def is_public(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def lambda_handler(event, context):
    for rec in event["Records"]:
        body = json.loads(rec["body"])
        alert = body.get("detail", body)
        rule = alert.get("rule", {})
        ip = alert.get("data", {}).get("srcip")
        if not ip or ip in ALLOWLIST or not is_public(ip):
            continue
        verdict = ask_gemini(PROMPT.format(
            id=rule.get("id"), level=rule.get("level"), desc=rule.get("description"),
            ip=ip, log=alert.get("full_log", "")[:2000],
        ))  # a failure here raises, so SQS retries and eventually parks it in the DLQ
        if verdict.get("verdict") != "TRUE_POSITIVE":
            print("dismissed:", verdict.get("summary"))
            continue
        status = block(ip)
        if status != "already blocked":
            notify(verdict, ip, status)
