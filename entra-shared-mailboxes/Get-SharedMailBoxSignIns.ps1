<#
.SYNOPSIS
Reports shared mailboxes and their Entra ID sign-in activity.

.DESCRIPTION
Fetches all shared mailboxes from Exchange Online and correlates each one to its
Entra ID user account. Sign-in activity (last successful, interactive, and
non-interactive) is resolved by bulk-fetching all tenant users from Microsoft
Graph in a single paginated pass and indexing them in memory — no per-mailbox
API calls are made during processing.

The report is exported as a UTF-8 CSV with a sep=, hint so Excel opens it with
correct column splitting on all regional locales.

.PARAMETER OutputPath
Full path for the exported CSV file.
Defaults to SharedMailboxSignInReport_<timestamp>.csv in the current directory.

.PARAMETER OnlyNeverSignedIn
When specified, the exported report and console summary include only mailboxes
whose Entra ID account has never had any sign-in activity recorded.

.PARAMETER SkipCsvExport
Suppresses CSV file creation. Only the console summary is displayed.

.PARAMETER InstallMissingModules
Automatically installs any missing required PowerShell modules for the current
user without prompting.

.EXAMPLE
.\Get-SharedMailBoxSignIns.ps1

Runs with defaults. Exports a full report CSV to the current directory.

.EXAMPLE
.\Get-SharedMailBoxSignIns.ps1 -OnlyNeverSignedIn

Exports only the mailboxes that have never signed in.

.EXAMPLE
.\Get-SharedMailBoxSignIns.ps1 -SkipCsvExport

Displays the console summary without writing a file.

.NOTES
Required Graph API permissions (delegated):
  User.Read.All
  AuditLog.Read.All

Required PowerShell modules:
  ExchangeOnlineManagement
  Microsoft.Graph.Authentication
  Microsoft.Graph.Users

The account running the script must have an Entra ID role that permits reading
signInActivity (e.g. Reports Reader, Security Reader, or Global Reader).
If access is denied, activate an eligible PIM role and re-run.
#>

[CmdletBinding()]
param(
	[string]$OutputPath = (Join-Path -Path (Get-Location) -ChildPath ("SharedMailboxSignInReport_{0:yyyyMMdd_HHmmss}.csv" -f (Get-Date))),
	[switch]$OnlyNeverSignedIn,
	[switch]$SkipCsvExport,
	[switch]$InstallMissingModules
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Import-RequiredModule {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[string]$Name
	)

	if (-not (Get-Module -ListAvailable -Name $Name)) {
		$installNow = $false

		if ($InstallMissingModules) {
			$installNow = $true
		}
		else {
			$reply = Read-Host "Required module '$Name' is not installed. Install now? (Y/N)"
			if ($reply -match '^(?i)y(?:es)?$') {
				$installNow = $true
			}
		}

		if (-not $installNow) {
			throw "Required module '$Name' is not installed. Re-run with -InstallMissingModules or install manually: Install-Module $Name -Scope CurrentUser"
		}

		Write-Host "Installing module '$Name' for current user..." -ForegroundColor Yellow
		Install-Module -Name $Name -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
	}

	Import-Module -Name $Name -ErrorAction Stop | Out-Null
}

function Connect-ExchangeIfNeeded {
	[CmdletBinding()]
	param()

	try {
		Get-EXOMailbox -ResultSize 1 -ErrorAction Stop | Out-Null
	}
	catch {
		Write-Host "Connecting to Exchange Online..." -ForegroundColor Cyan
		Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
	}
}

function Connect-GraphIfNeeded {
	[CmdletBinding()]
	param()

	$requiredScopes = @("User.Read.All", "AuditLog.Read.All")
	$context = Get-MgContext -ErrorAction SilentlyContinue

	$needsConnect = $true
	if ($null -ne $context -and $null -ne $context.Scopes) {
		$currentScopes = @($context.Scopes)
		$missingScopes = @($requiredScopes | Where-Object { $_ -notin $currentScopes })
		$needsConnect = ($missingScopes.Count -gt 0)
	}

	if ($needsConnect) {
		Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
		Connect-MgGraph -Scopes $requiredScopes -NoWelcome -ErrorAction Stop | Out-Null
	}
}

function Assert-GraphAccess {
	[CmdletBinding()]
	param()

	Write-Host "Verifying Graph API access..." -ForegroundColor Cyan
	try {
		Get-MgUser -Top 1 -Property "id,userPrincipalName,signInActivity" -ConsistencyLevel eventual -ErrorAction Stop | Out-Null
	}
	catch {
		$msg = $_.Exception.Message
		if ($msg -match 'Authentication_RequestFromUnsupportedUserRole|403|Forbidden|Authorization_RequestDenied|Insufficient privileges|AccessDenied|privilegedAccess') {
			throw (@(
				"Graph signInActivity access denied (403).",
				"This script needs permissions that your current user/role does not currently have.",
				"  1. Activate an eligible Entra role in PIM and re-run.",
				"  2. Ensure required scopes are consented in tenant: User.Read.All, AuditLog.Read.All.",
				"  3. Conditional Access is blocking the Microsoft Graph Command Line Tools app.",
				("Original error: {0}" -f $msg)
			) -join [Environment]::NewLine)
		}
		throw
	}
}

function Get-AllGraphUsersIndex {
	[CmdletBinding()]
	param()

	$selectProperties = "id,displayName,userPrincipalName,mail,accountEnabled,signInActivity"
	$byObjectId = @{}
	$byUpn     = @{}
	$byMail    = @{}

	$uri = "https://graph.microsoft.com/v1.0/users?`$select={0}&`$top=999" -f $selectProperties
	$pageCount = 0
	$totalFetched = 0

	Write-Host "Fetching all users from Graph (paginated)..." -ForegroundColor Cyan

	do {
		$pageCount++
		Write-Progress -Activity "Fetching all users from Graph" -Status ("Page {0} — {1} users so far" -f $pageCount, $totalFetched)

		$response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop

		if ($null -eq $response.value) {
			break
		}

		foreach ($u in $response.value) {
			$obj = [pscustomobject]$u
			if (-not [string]::IsNullOrWhiteSpace($u.id)) {
				$byObjectId[$u.id] = $obj
			}
			if (-not [string]::IsNullOrWhiteSpace($u.userPrincipalName)) {
				$byUpn[$u.userPrincipalName.ToLowerInvariant()] = $obj
			}
			if (-not [string]::IsNullOrWhiteSpace($u.mail)) {
				$byMail[$u.mail.ToLowerInvariant()] = $obj
			}
		}

		$totalFetched += $response.value.Count
		$uri = $response['@odata.nextLink']
	} while (-not [string]::IsNullOrWhiteSpace($uri))

	Write-Progress -Activity "Fetching all users from Graph" -Completed
	Write-Host ("Graph user index built: {0} users (ObjectId:{1} UPN:{2} Mail:{3})" -f $totalFetched, $byObjectId.Count, $byUpn.Count, $byMail.Count) -ForegroundColor Cyan

	return @{
		ByObjectId = $byObjectId
		ByUpn      = $byUpn
		ByMail     = $byMail
	}
}

Import-RequiredModule -Name ExchangeOnlineManagement
Import-RequiredModule -Name Microsoft.Graph.Authentication
Import-RequiredModule -Name Microsoft.Graph.Users

Connect-ExchangeIfNeeded
Connect-GraphIfNeeded
Assert-GraphAccess

Write-Host "Getting shared mailboxes from Exchange Online..." -ForegroundColor Cyan
$sharedMailboxes = @(Get-EXOMailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited -Properties DisplayName,PrimarySmtpAddress,UserPrincipalName,ExternalDirectoryObjectId,WhenCreated)
Write-Host ("Shared mailboxes found: {0}" -f $sharedMailboxes.Count) -ForegroundColor Cyan

$userIndex = Get-AllGraphUsersIndex

if ($sharedMailboxes.Count -eq 0) {
	Write-Warning "No shared mailboxes were returned by Exchange Online. Verify you're connected to the expected tenant and that shared mailboxes exist."
}

$totalMailboxes = $sharedMailboxes.Count
$processedCount = 0

$report = @(
	foreach ($mailbox in $sharedMailboxes) {
		$processedCount++
		Write-Progress -Activity "Processing shared mailboxes" -Status ("{0}/{1}: {2}" -f $processedCount, $totalMailboxes, $mailbox.PrimarySmtpAddress) -PercentComplete (($processedCount / [math]::Max($totalMailboxes, 1)) * 100)
		Write-Verbose ("Processing mailbox {0}/{1}: {2}" -f $processedCount, $totalMailboxes, $mailbox.PrimarySmtpAddress)

		$user = $null
		$mailboxObjectId = [string]$mailbox.ExternalDirectoryObjectId

		if (-not [string]::IsNullOrWhiteSpace($mailboxObjectId) -and $userIndex.ByObjectId.ContainsKey($mailboxObjectId)) {
			$user = $userIndex.ByObjectId[$mailboxObjectId]
		}
		elseif (-not [string]::IsNullOrWhiteSpace($mailbox.UserPrincipalName) -and $userIndex.ByUpn.ContainsKey($mailbox.UserPrincipalName.ToLowerInvariant())) {
			$user = $userIndex.ByUpn[$mailbox.UserPrincipalName.ToLowerInvariant()]
		}
		elseif ($null -ne $mailbox.PrimarySmtpAddress -and $userIndex.ByMail.ContainsKey($mailbox.PrimarySmtpAddress.ToString().ToLowerInvariant())) {
			$user = $userIndex.ByMail[$mailbox.PrimarySmtpAddress.ToString().ToLowerInvariant()]
		}

		if (($processedCount % 50) -eq 0) {
			Write-Host ("Processed {0}/{1} mailboxes..." -f $processedCount, $totalMailboxes) -ForegroundColor DarkCyan
		}

	if (-not $user) {
		[PSCustomObject]@{
			MailboxDisplayName             = $mailbox.DisplayName
			PrimarySmtpAddress             = $mailbox.PrimarySmtpAddress.ToString()
			MailboxUserPrincipalName       = $mailbox.UserPrincipalName
			MailboxCreatedDateTime         = $mailbox.WhenCreated
			EntraUserFound                 = $false
			EntraObjectId                  = $null
			EntraUserPrincipalName         = $null
			EntraMail                      = $null
			EntraAccountEnabled            = $null
			HasEverSignedIn                = $false
			LastSuccessfulSignInDateTime   = $null
			LastInteractiveSignInDateTime  = $null
			LastNonInteractiveSignInDateTime = $null
		}

		continue
	}

	$signIn = $null
	if ($user.PSObject.Properties['signInActivity']) {
		$signIn = $user.signInActivity
	}

	$lastSuccessful     = $null
	$lastInteractive    = $null
	$lastNonInteractive = $null

	if ($null -ne $signIn) {
		if ($signIn -is [System.Collections.IDictionary]) {
			$lastSuccessful     = $signIn['lastSuccessfulSignInDateTime']
			$lastInteractive    = $signIn['lastSignInDateTime']
			$lastNonInteractive = $signIn['lastNonInteractiveSignInDateTime']
		} else {
			if ($signIn.PSObject.Properties['lastSuccessfulSignInDateTime'])    { $lastSuccessful     = $signIn.lastSuccessfulSignInDateTime }
			if ($signIn.PSObject.Properties['lastSignInDateTime'])              { $lastInteractive    = $signIn.lastSignInDateTime }
			if ($signIn.PSObject.Properties['lastNonInteractiveSignInDateTime']) { $lastNonInteractive = $signIn.lastNonInteractiveSignInDateTime }
		}
	}

	$hasEverSignedIn = [bool]($lastSuccessful -or $lastInteractive -or $lastNonInteractive)

	[PSCustomObject]@{
		MailboxDisplayName             = $mailbox.DisplayName
		PrimarySmtpAddress             = $mailbox.PrimarySmtpAddress.ToString()
		MailboxUserPrincipalName       = $mailbox.UserPrincipalName
		MailboxCreatedDateTime         = $mailbox.WhenCreated
		EntraUserFound                 = $true
		EntraObjectId                  = $user.Id
		EntraUserPrincipalName         = $user.UserPrincipalName
		EntraMail                      = $user.Mail
		EntraAccountEnabled            = $user.AccountEnabled
		HasEverSignedIn                = $hasEverSignedIn
		LastSuccessfulSignInDateTime   = $lastSuccessful
		LastInteractiveSignInDateTime  = $lastInteractive
		LastNonInteractiveSignInDateTime = $lastNonInteractive
	}
}
)

Write-Progress -Activity "Processing shared mailboxes" -Completed

Write-Host ("Rows before filter: {0}" -f $report.Count) -ForegroundColor Cyan

if ($OnlyNeverSignedIn) {
	$beforeFilterCount = $report.Count
	$report = $report | Where-Object { -not $_.HasEverSignedIn }
	$afterFilterCount = @($report).Count
	Write-Host ("Rows after -OnlyNeverSignedIn filter: {0} (removed {1})" -f $afterFilterCount, ($beforeFilterCount - $afterFilterCount)) -ForegroundColor Cyan
}

$report = @($report | Sort-Object -Property PrimarySmtpAddress)

if ($report.Count -eq 0) {
	Write-Warning "Report contains 0 rows. This can happen when no shared mailboxes are found, or when -OnlyNeverSignedIn filters everything out."
}

if (-not $SkipCsvExport) {
	if ($report.Count -eq 0) {
		# Export a typed empty row set so the CSV still includes headers.
		$emptyReport = @(
			[PSCustomObject]@{
				MailboxDisplayName               = $null
				PrimarySmtpAddress               = $null
				MailboxUserPrincipalName         = $null
				MailboxCreatedDateTime           = $null
				EntraUserFound                   = $null
				EntraObjectId                    = $null
				EntraUserPrincipalName           = $null
				EntraMail                        = $null
				EntraAccountEnabled              = $null
				HasEverSignedIn                  = $null
				LastSuccessfulSignInDateTime     = $null
				LastInteractiveSignInDateTime    = $null
				LastNonInteractiveSignInDateTime = $null
			}
		)

		$csvLines = $emptyReport | Select-Object * | Select-Object -First 0 | ConvertTo-Csv -NoTypeInformation
		[System.IO.File]::WriteAllText($OutputPath, ("sep=,`r`n" + ($csvLines -join "`r`n")), [System.Text.UTF8Encoding]::new($true))
	}
	else {
		$csvLines = $report | ConvertTo-Csv -NoTypeInformation
		[System.IO.File]::WriteAllText($OutputPath, ("sep=,`r`n" + ($csvLines -join "`r`n")), [System.Text.UTF8Encoding]::new($true))
	}

	Write-Host "Report exported to: $OutputPath" -ForegroundColor Green
}

$totalCount        = $report.Count
$foundCount        = @($report | Where-Object { $_.EntraUserFound }).Count
$enabledCount      = @($report | Where-Object { $_.EntraAccountEnabled }).Count
$signedInCount     = @($report | Where-Object { $_.HasEverSignedIn }).Count
$neverSignedIn     = $totalCount - $signedInCount

Write-Host ""
Write-Host "--- Summary ---" -ForegroundColor White
Write-Host ("  Total mailboxes:       {0}" -f $totalCount)
Write-Host ("  Entra user found:      {0}" -f $foundCount)
Write-Host ("  Account enabled:       {0}" -f $enabledCount)
Write-Host ("  Has ever signed in:    {0}" -f $signedInCount)
Write-Host ("  Never signed in:       {0}" -f $neverSignedIn)