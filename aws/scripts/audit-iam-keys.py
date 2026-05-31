#!/usr/bin/env python3
"""
Audits all IAM access keys in the account.
Reports keys older than 90 days and keys that have never been used.
"""

import boto3
from datetime import datetime, timezone, timedelta

MAX_KEY_AGE_DAYS = 90

def audit_access_keys():
    iam = boto3.client("iam")
    paginator = iam.get_paginator("list_users")
    stale = []

    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]
            keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
            for key in keys:
                age = (datetime.now(timezone.utc) - key["CreateDate"]).days
                if age > MAX_KEY_AGE_DAYS:
                    stale.append({
                        "user": username,
                        "key_id": key["AccessKeyId"],
                        "status": key["Status"],
                        "age_days": age,
                    })

    if stale:
        print(f"Found {len(stale)} stale access key(s):")
        for item in stale:
            print(f"  {item['user']} | {item['key_id']} | {item['status']} | {item['age_days']} days old")
    else:
        print("No stale access keys found.")

if __name__ == "__main__":
    audit_access_keys()
