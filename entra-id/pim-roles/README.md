# Privileged Identity Management (PIM) Role Settings

## Roles Configured

| Role | Max Duration | Approval Required | Justification Required |
|------|-------------|-------------------|------------------------|
| Global Administrator | 1 hour | Yes | Yes |
| Security Administrator | 4 hours | No | Yes |
| Exchange Administrator | 8 hours | No | Yes |
| User Administrator | 8 hours | No | Yes |

## Deployment

```powershell
Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory"
./Set-PIMRoleSettings.ps1
```
