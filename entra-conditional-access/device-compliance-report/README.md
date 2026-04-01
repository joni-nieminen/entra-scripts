# Conditional Access Device Compliance Report

A PowerShell script that generates device compliance reports for Entra ID users. The report helps you to assess the readiness when about to onboard new users to Conditional Access Policies which expects a compliant (Intune) or a hybrid-joined (Active Directory) device.

## What It Does

- Queries Entra ID for users matching filter criterias
    - See the Quick Start for filtering options, you can combine the filters to suit your scenario
- Correlates device data from Entra ID and Intune
- Identifies which devices meet Conditional Access policy requirements
- Exports results to a timestamped CSV file

## Prerequisites

- **PowerShell 5.1+** (or PowerShell Core 7+)
- **Microsoft.Graph PowerShell Module** installed
  ```powershell
  Install-Module Microsoft.Graph -Scope CurrentUser
  ```
- **Permissions**: User.Read.All, Device.Read.All, DeviceManagementManagedDevices.Read.All, Group.Read.All
  - **Optional**: AuditLog.Read.All (required only if using -QuerySignInLogs)

## Quick Start

```powershell
# Install module (one-time)
Install-Module Microsoft.Graph -Scope CurrentUser

# Run with no filters - reports all tenant users
.\conditionalAccessDeviceReport.ps1

# Filter by domain/userPrincipalName suffix
.\conditionalAccessDeviceReport.ps1 -UpnSuffix 'contoso.com'

# Filter by multiple domain/userPrincipalName suffixes
.\conditionalAccessDeviceReport.ps1 -UpnSuffix 'contoso.com,fabrikam.com'

# Filter by userPrincipalName prefix
.\conditionalAccessDeviceReport.ps1 -UPNPrefix 'svc_'

# Exclude by userPrincipalName prefix
.\conditionalAccessDeviceReport.ps1 -ExcludeUPNprefix 'svc_'

# Multiple filters
.\conditionalAccessDeviceReport.ps1 -UpnSuffix 'contoso.com' -CountryFilter 'United States' -ExcludeUPNprefix 'svc_'

# Include sign-in log devices (slower, attempts to find hidden devices)
.\conditionalAccessDeviceReport.ps1 -UpnSuffix 'contoso.com' -QuerySignInLogs
```

## Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| **UpnSuffix** | string | Filter by UPN suffix (e.g., 'contoso.com' or 'contoso.com,fabrikam.com'). @ symbol auto-added. |
| **UPNPrefix** | string | Filter by UPN prefix (e.g., 'admin_' or 'ext_'). |
| **CountryFilter** | string | Filter by country (uses Entra ID user.Country property). |
| **ExcludeUPNprefix** | string | Exclude users by UPN prefix (e.g., 'svc_'). |
| **QuerySignInLogs** | switch | Query sign-in logs for users with no registered devices (slower). |

## Output

The script generates a CSV file:
```
DeviceComplianceReport_[timestamp]_[filters].csv
```

**Example filename:**
- `DeviceComplianceReport_20260401_072223_contoso.com.csv`
- `DeviceComplianceReport_20260401_072223_prefix-svc.csv`

**CSV Columns:**
- UserUPN
- AccountEnabled
- LastInteractiveSignIn, LastNonInteractiveSignIn
- DeviceName, Platform
- ComplianceState (compliant/unknown/<none>)
- EntraJoinType (hybrid/AAD/workplace)
- LastActivity
- MeetsRequirements (true/false)
- EntraDeviceCount, IntuneDeviceCount

## Compliance Requirements

A device **meets CA requirements** if:
- **Hybrid-joined** (on-premises AD), OR
- **Azure AD joined** AND compliant, OR
- **Mobile (iOS/Android)** AND compliant

## Troubleshooting

**"No users found"**
- Verify the UPN suffix/prefix is correct
- Ensure the account has User.Read.All permissions

**Sign-in logs are slow**
- Normal for large tenants; only use -QuerySignInLogs if needed
- Querying the sign-in logs is currently hardcoded to last 7 days

**Skip group errors**
- Script silently skips groups that don't exist
- Define these groups or ensure they exist if you want members excluded

## Notes

- The script automatically skips members of CA-related groups
- You typically onboard to policies in phases, so add the Conditional Access Policy Entra ID groups here to skip users who are already in the policies
- Modify the `$skipGroupNames` array in the script to customize exclusions
- Output is UTF-8 encoded CSV (Excel-compatible)

## License

Free for public use. Modify as needed for your environment.