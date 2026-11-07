"""AWS bait keys.

`lure aws create` makes an IAM user with no permissions at all and an access
key for it, then writes a realistic credentials file holding that key. The key
can do nothing. Anyone who finds it and tries it makes an AWS API call that is
refused, and CloudTrail records the attempt. `lure aws watch` polls CloudTrail's
free 90-day event history for any call made with a bait key and raises an alert.

Cost: IAM users, access keys and CloudTrail event history are free. CloudTrail
event history usually shows a call within 5 to 15 minutes.

Standard library only: requests are signed with AWS Signature Version 4 here.
"""

import configparser
import datetime as _dt
import hashlib
import hmac
import json
import os
import time
import urllib.parse
import urllib.request


def _load_credentials(profile=None):
    key, secret, token = (os.environ.get("AWS_ACCESS_KEY_ID"), os.environ.get("AWS_SECRET_ACCESS_KEY"),
                          os.environ.get("AWS_SESSION_TOKEN"))
    if key and secret and not profile:
        return key, secret, token
    cp = configparser.ConfigParser()
    cp.read(os.path.expanduser(os.environ.get("AWS_SHARED_CREDENTIALS_FILE", "~/.aws/credentials")))
    name = profile or os.environ.get("AWS_PROFILE", "default")
    if name not in cp:
        raise SystemExit(f"lure: no AWS credentials for profile {name!r}")
    s = cp[name]
    return s["aws_access_key_id"], s["aws_secret_access_key"], s.get("aws_session_token")


def _sign(method, host, region, service, body, headers, creds, path="/", query="", now=None):
    key, secret, token = creds
    now = now or _dt.datetime.now(_dt.timezone.utc)
    amz, day = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
    headers = dict(headers, host=host, **{"x-amz-date": amz})
    if token:
        headers["x-amz-security-token"] = token
    signed = ";".join(sorted(k.lower() for k in headers))
    canon_headers = "".join(f"{k.lower()}:{str(v).strip()}\n" for k, v in sorted(headers.items(), key=lambda kv: kv[0].lower()))
    payload = hashlib.sha256(body).hexdigest()
    canonical = "\n".join([method, path, query, canon_headers, signed, payload])
    scope = f"{day}/{region}/{service}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    k = hmac.new(("AWS4" + secret).encode(), day.encode(), hashlib.sha256).digest()
    for part in (region, service, "aws4_request"):
        k = hmac.new(k, part.encode(), hashlib.sha256).digest()
    sig = hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()
    headers["Authorization"] = f"AWS4-HMAC-SHA256 Credential={key}/{scope}, SignedHeaders={signed}, Signature={sig}"
    return headers


def _iam(action, params, creds):
    body = urllib.parse.urlencode(dict({"Action": action, "Version": "2010-05-08"}, **params)).encode()
    host = "iam.amazonaws.com"
    h = _sign("POST", host, "us-east-1", "iam", body,
              {"content-type": "application/x-www-form-urlencoded; charset=utf-8"}, creds)
    req = urllib.request.Request(f"https://{host}/", data=body, headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.read().decode()
    except urllib.error.HTTPError as e:
        raise SystemExit(f"lure: IAM {action} failed: {e.code} {e.read().decode()[:300]}") from None


def _between(xml, tag):
    a = xml.find(f"<{tag}>")
    return xml[a + len(tag) + 2: xml.find(f"</{tag}>", a)] if a >= 0 else None


def lookup_events(access_key_id, creds, region, start=None):
    """CloudTrail event history calls made with one access key (newest first)."""
    host = f"cloudtrail.{region}.amazonaws.com"
    body = {"LookupAttributes": [{"AttributeKey": "AccessKeyId", "AttributeValue": access_key_id}], "MaxResults": 50}
    if start:
        body["StartTime"] = start
    raw = json.dumps(body).encode()
    h = _sign("POST", host, region, "cloudtrail", raw,
              {"content-type": "application/x-amz-json-1.1",
               "x-amz-target": "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents"}, creds)
    req = urllib.request.Request(f"https://{host}/", data=raw, headers=h, method="POST")
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read()).get("Events", [])


def create_bait_key(out_dir, manifest_path, aws_profile=None, user_name=None):
    """Create a no-permission IAM user and key; write the bait file; add it to the manifest."""
    creds = _load_credentials(aws_profile)
    user = user_name or "svc-backup-sync"
    _iam("CreateUser", {"UserName": user, "Tags.member.1.Key": "lure",
                        "Tags.member.1.Value": "bait: no permissions, do not grant any"}, creds)
    xml = _iam("CreateAccessKey", {"UserName": user}, creds)
    key_id, secret = _between(xml, "AccessKeyId"), _between(xml, "SecretAccessKey")
    name = "aws credentials (backup job).txt"
    with open(os.path.join(out_dir, name), "w") as f:
        f.write("[default]\n"
                f"aws_access_key_id = {key_id}\n"
                f"aws_secret_access_key = {secret}\n"
                "region = ap-south-1\n"
                f"# nightly backup sync ({user}); copy to ~/.aws/credentials on the backup host\n")
    with open(manifest_path) as f:
        m = json.load(f)
    m["baits"].append({"file": name, "service": "aws", "username": key_id, "iam_user": user,
                       "plant_on": "a backup server, a script folder, or a developer home directory",
                       "leads_to": [], "location": None})
    with open(manifest_path, "w") as f:
        json.dump(m, f, indent=2)
    return {"file": name, "access_key_id": key_id, "iam_user": user}


def watch(alerter, aws_profile=None, region="us-east-1", interval=300, once=False):
    """Poll CloudTrail for calls made with any bait key in the manifest."""
    creds = _load_credentials(aws_profile)
    keys = [b["username"] for b in alerter.manifest.get("baits", []) if b.get("service") == "aws"]
    seen = set()
    while True:
        for key_id in keys:
            for ev in lookup_events(key_id, creds, region):
                if ev["EventId"] in seen:
                    continue
                seen.add(ev["EventId"])
                detail = json.loads(ev.get("CloudTrailEvent", "{}"))
                alerter.event("aws", detail.get("sourceIPAddress", "unknown"), 0, key_id,
                              source_detail=f"{detail.get('eventSource')}:{ev.get('EventName')} "
                                            f"{detail.get('errorCode', '')} ua={detail.get('userAgent', '')[:80]}")
        if once:
            return
        time.sleep(interval)
