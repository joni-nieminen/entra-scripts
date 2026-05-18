# Shared Mailbox Sign-In Report

A PowerShell script that reports sign-in activity for shared mailbox accounts in Exchange Online. The report helps you identify shared mailboxes whose underlying Entra ID accounts have never signed in, have active sign-in history, or are enabled when they shouldn't be.

## What It Does

- Fetches all shared mailboxes from Exchange Online
- Bulk-fetches all tenant users from Microsoft Graph in a single paginated pass and indexes them in memory — no per-mailbox API calls during processing
- Correlates each mailbox to its Entra ID user account by object ID, UPN, or primary SMTP address
- Reports last successful, interactive, and non-interactive sign-in timestamps
- Exports results to a timestamped CSV file that opens correctly in Excel on all regional locales

## Prerequisites

- **PowerShell 5.1+** (or PowerShell Core 7+)
- **Required modules** (auto-install prompt or use `-InstallMissingModules`):
  ```powershell
  Install-Module ExchangeOnlineManagement -Scope CurrentUser
  Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
  Install-Module Microsoft.Graph.Users -Scope CurrentUser
  ```
- **Graph API permissions (delegated):** `User.Read.All`, `AuditLog.Read.All`
- **Entra ID role** with access to `signInActivity`: Reports Reader, Security Reader, or Global Reader
  - If access is denied, activate an eligible PIM role and re-run

## Quick Start

```powershell
# Run with defaults — exports full report CSV to current directory
.\Get-SharedMailBoxSignIns.ps1

# Only report mailboxes that have never signed in
.\Get-SharedMailBoxSignIns.ps1 -OnlyNeverSignedIn

# Display summary only, no CSV export
.\Get-SharedMailBoxSignIns.ps1 -SkipCsvExport

# Auto-install missing modules without prompting
.\Get-SharedMailBoxSignIns.ps1 -InstallMissingModules

# Combine filters
.\Get-SharedMailBoxSignIns.ps1 -OnlyNeverSignedIn -InstallMissingModules
```

## Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| **OutputPath** | string | Full path for the exported CSV. Defaults to `SharedMailboxSignInReport_<timestamp>.csv` in the current directory. |
| **OnlyNeverSignedIn** | switch | Filters the report to only include mailboxes with no recorded sign-in activity. |
| **SkipCsvExport** | switch | Suppresses CSV creation. Only the console summary is shown. |
| **InstallMissingModules** | switch | Automatically installs missing required modules for the current user without prompting. |

## Output

The script generates a CSV file:
```
SharedMailboxSignInReport_[timestamp].csv
```

**CSV Columns:**

| Column | Description |
|--------|-------------|
| MailboxDisplayName | Display name of the shared mailbox |
| PrimarySmtpAddress | Primary SMTP address |
| MailboxUserPrincipalName | UPN as seen in Exchange Online |
| MailboxCreatedDateTime | When the mailbox was created |
| EntraUserFound | Whether a matching Entra ID user account was found |
| EntraObjectId | Entra ID object ID |
| EntraUserPrincipalName | UPN in Entra ID |
| EntraMail | Mail attribute in Entra ID |
| EntraAccountEnabled | Whether the account is enabled |
| HasEverSignedIn | Whether any sign-in activity has been recorded |
| LastSuccessfulSignInDateTime | Timestamp of the last successful sign-in |
| LastInteractiveSignInDateTime | Timestamp of the last interactive sign-in |
| LastNonInteractiveSignInDateTime | Timestamp of the last non-interactive sign-in |

A console summary is printed at the end - for example:
```
--- Summary ---
  Total mailboxes:       905
  Entra user found:      870
  Account enabled:       120
  Has ever signed in:    450
  Never signed in:       455
```

## Troubleshooting

**"Graph signInActivity access denied (403)"**
- Activate an eligible Entra ID PIM role (Reports Reader, Security Reader, or Global Reader) and re-run
- Ensure `User.Read.All` and `AuditLog.Read.All` are consented in the tenant
- Check whether Conditional Access is blocking the Microsoft Graph Command Line Tools app

**Columns appear merged in Excel**
- The CSV includes a `sep=,` hint on line 1 — open with **File > Open** in Excel rather than double-clicking if issues persist

**Shared mailbox not found in Entra ID**
- The script attempts matching by object ID, UPN, and primary SMTP address in that order
- Mailboxes with no match are still included in the report with `EntraUserFound = False`

## License

Free for public use. Modify as needed for your environment.
