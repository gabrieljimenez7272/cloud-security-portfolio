# GCP Organization Policies

Boolean and list constraints applied at the org level.

## Key Policies

| Constraint | Effect |
|------------|--------|
| `compute.requireOsLogin` | Enforce OS Login on all VMs |
| `compute.skipDefaultNetworkCreation` | Prevent default VPC on new projects |
| `iam.disableServiceAccountKeyCreation` | Block SA key downloads |
| `compute.restrictCloudNATUsage` | Limit NAT to approved subnets |
| `storage.publicAccessPrevention` | Block public GCS buckets |
