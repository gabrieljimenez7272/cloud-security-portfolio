# Cloud Resource Tagging Standard

All cloud resources must carry the following tags at minimum.

| Tag Key       | Required | Example Value           | Notes |
|---------------|----------|-------------------------|-------|
| Environment   | Yes      | prod / staging / dev    | |
| Owner         | Yes      | team-platform           | Team or individual |
| CostCenter    | Yes      | CC-1042                 | Finance cost center |
| DataClass     | Yes      | public / internal / confidential / restricted | |
| ManagedBy     | Yes      | terraform               | terraform, manual, cdk |
| Project       | No       | project-phoenix         | |
| ExpiresOn     | No       | 2025-12-31              | For temporary resources |
