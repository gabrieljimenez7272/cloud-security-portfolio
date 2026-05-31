#!/usr/bin/env python3
"""
Lists all GCS buckets in a project that have public IAM bindings.
"""

from google.cloud import storage

def audit_public_buckets(project_id: str):
    client = storage.Client(project=project_id)
    public_buckets = []

    for bucket in client.list_buckets():
        policy = bucket.get_iam_policy(requested_policy_version=3)
        for binding in policy.bindings:
            if "allUsers" in binding["members"] or "allAuthenticatedUsers" in binding["members"]:
                public_buckets.append(bucket.name)
                break

    if public_buckets:
        print(f"Found {len(public_buckets)} public bucket(s):")
        for b in public_buckets:
            print(f"  gs://{b}")
    else:
        print("No public buckets found.")

if __name__ == "__main__":
    import sys
    project = sys.argv[1] if len(sys.argv) > 1 else input("GCP Project ID: ")
    audit_public_buckets(project)
