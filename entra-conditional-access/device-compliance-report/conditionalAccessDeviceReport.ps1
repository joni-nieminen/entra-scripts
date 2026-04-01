<#
.SYNOPSIS
    Generate a device compliance report for users matching specified criteria.

.DESCRIPTION
    Queries Microsoft Entra ID and Intune for users matching optional filter criteria,
    then correlates their Entra-registered and Intune-managed devices to generate a compliance
    report. The report indicates whether each device meets compliance requirements for Conditional
    Access policies. By default, if a user has no registered devices, the script will not check
    sign-in logs for historical device activity. Use -QuerySignInLogs to enable discovery of devices
    from sign-in logs for users with no registered devices.

.PARAMETER UpnSuffix
    (Optional) The UPN suffix or multiple suffixes (comma-separated) to filter users by (e.g., 'contoso.com' or
    'contoso.com,fabrikam.com'). Only users whose UserPrincipalName ends with one of these suffixes will be included.
    The @ symbol is optional and will be auto-prefixed if not provided. If not specified, all users in the tenant will be queried.

.PARAMETER CountryFilter
    (Optional) Filters users by country (e.g., 'United States'). If not specified, all users
    (or users matching other filters) are included. This is effectively the Entra ID 'user.Country' property, which may not be populated for all users.

.PARAMETER UPNPrefix
    (Optional) Filters users whose UserPrincipalName starts with the specified prefix
    (e.g., 'admin_' or 'svc_'). If not specified, no UPN prefix filter is applied.

.PARAMETER ExcludeUPNprefix
    (Optional) Excludes users whose UserPrincipalName starts with the specified prefix
    (e.g., 'admin_' or 'svc_'). If not specified, no UPN-based exclusion is applied.

.PARAMETER QuerySignInLogs
    (Optional) Switch parameter. When specified, the script will query sign-in logs for users
    with no registered Entra or Intune devices to discover devices from recent activity.
    This can impact performance when processing large numbers of users. Default: disabled.

.EXAMPLE
    .\conditionalAccessDeviceReport.ps1
    Generate report for all users in the tenant.

.EXAMPLE
    .\conditionalAccessDeviceReport.ps1 -UpnSuffix 'contoso.com'
    Generate report for all users with @contoso.com suffix.

.EXAMPLE
    .\conditionalAccessDeviceReport.ps1 -UpnSuffix 'contoso.com,fabrikam.com'
    Generate report for all users with @contoso.com or @fabrikam.com suffixes.

.EXAMPLE
    .\conditionalAccessDeviceReport.ps1 -UpnSuffix '@contoso.com' -CountryFilter 'US' -ExcludeUPNprefix 'svc_'
    Generate report for US-based users with @contoso.com suffix, excluding service accounts.

.EXAMPLE
    .\conditionalAccessDeviceReport.ps1 -UPNPrefix 'admin_'
    Generate report for all users whose UPN starts with 'admin_'.

.NOTES
    Author: Joni Nieminen
    Requires: Microsoft.Graph PowerShell module with appropriate scopes
    Report is exported to a timestamped CSV file in the script directory.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$UpnSuffix,
    [string]$CountryFilter,
    [string]$UPNPrefix,
    [string]$ExcludeUPNprefix,
    [switch]$QuerySignInLogs
)

$skipGroupNames = @(
    "<your CA group name 1>",
    "<your CA group name 2>",
    "<your CA group name 3>",
    "<add more group names as needed>"
)

$ComplianceStates = @{
    Compliant = 'compliant'
    Unknown   = 'Unknown'
    None      = '<none>'
}

$EntraJoinTypes = @{
    Hybrid      = 'ServerAd'
    AzureAdOnly = 'AzureAd'
    Unknown     = 'Unknown'
    None        = '<none>'
}

$PlatformMobilePattern = 'iOS|Android|IPhone|IPad'
$DeviceNotFound = '<none>'
$ActivityNotFound = 'Unknown'

if (-not [string]::IsNullOrWhiteSpace($UpnSuffix)) {
    $upnList = @($UpnSuffix -split ',' | ForEach-Object {$_.Trim()} | Where-Object {$_})
    $upnList = @($upnList | ForEach-Object {if ($_ -notlike '@*') {"@$_"} else {$_}})
    $UpnSuffix = $upnList -join ','
}

function Write-Log {
    param(
        [Parameter(Mandatory=$false)] [string]$Message = '',
        [ValidateSet('INFO','SUCCESS','WARN','ERROR','DEBUG')] [string]$Level = 'INFO',
        [int]$Indent = 0
    )
    if ($Level -eq 'DEBUG' -and $VerbosePreference -ne [System.Management.Automation.ActionPreference]::Continue) { return }
    if ([string]::IsNullOrEmpty($Message)) { Write-Host ''; return }

    $prefix = switch ($Level) {
        'INFO'    { '▶' }
        'SUCCESS' { '✔' }
        'WARN'    { '⚠' }
        'ERROR'   { '✖' }
        'DEBUG'   { '•' }
    }

    $color = switch ($Level) {
        'INFO'    { 'Cyan' }
        'SUCCESS' { 'Green' }
        'WARN'    { 'Yellow' }
        'ERROR'   { 'Red' }
        'DEBUG'   { 'DarkGray' }
    }

    $ts = (Get-Date).ToString("HH:mm:ss")
    $pad = (' ' * ($Indent * 2))
    $message = "[$ts] $pad$prefix $Message"

    # Output DEBUG messages via Write-Verbose
    if ($Level -eq 'DEBUG') {
        Write-Verbose $message
    } else {
        Write-Host $message -ForegroundColor $color
    }
}

try {
    Write-Log "Connecting to Microsoft Graph..." INFO
    Connect-MgGraph -Scopes "User.Read.All","AuditLog.Read.All","Device.Read.All","DeviceManagementManagedDevices.Read.All","Group.Read.All" -NoWelcome -ErrorAction Stop
    Write-Log "Successfully connected to Microsoft Graph" SUCCESS
} catch {
    Write-Log "Failed to connect to Microsoft Graph: $_" ERROR
    return
}

$clauses = @()
if (-not [string]::IsNullOrWhiteSpace($UpnSuffix)) {
    $upnList = @($UpnSuffix -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if (@($upnList).Count -eq 1) {
        $clauses += "endsWith(userPrincipalName,'$($upnList[0])')"
    } else {
        $orExpressions = @($upnList | ForEach-Object { "endsWith(userPrincipalName,'$_')" })
        $clauses += "($($orExpressions -join ' or '))"
    }
}
if (-not [string]::IsNullOrWhiteSpace($countryFilter)) { $clauses += "country eq '$countryFilter'" }
if (-not [string]::IsNullOrWhiteSpace($UPNPrefix)) { $clauses += "startsWith(userPrincipalName,'$UPNPrefix')" }
if (-not [string]::IsNullOrWhiteSpace($excludeUPNprefix)) { $clauses += "not startsWith(userPrincipalName,'$excludeUPNprefix')" }
$filter = if ($clauses.Count -gt 0) { $clauses -join " and " } else { "" }
if ($filter) { Write-Log "Constructed OData filter: $filter" INFO } else { Write-Log "No filters specified. Querying all users." INFO } 

function New-DeviceReportRow {
    param(
        [Parameter(Mandatory)] [string]$UserUPN,
        [Nullable[bool]]$AccountEnabled,
        [Nullable[datetime]]$LastInteractiveSignIn,
        [Nullable[datetime]]$LastNonInteractiveSignIn,
        [string]$DeviceName,
        [string]$Platform,
        [string]$ComplianceState,
        [string]$EntraJoinType,
        $LastActivity,
        [bool]$MeetsRequirements,
        [int]$EntraDeviceCount,
        [int]$IntuneDeviceCount
    )

    [PSCustomObject]@{
        UserUPN                  = $UserUPN
        AccountEnabled           = $AccountEnabled
        LastInteractiveSignIn    = $LastInteractiveSignIn
        LastNonInteractiveSignIn = $LastNonInteractiveSignIn
        DeviceName               = $DeviceName
        Platform                 = $Platform
        ComplianceState          = $ComplianceState
        EntraJoinType            = $EntraJoinType
        LastActivity             = $LastActivity
        MeetsRequirements        = $MeetsRequirements
        EntraDeviceCount         = $EntraDeviceCount
        IntuneDeviceCount        = $IntuneDeviceCount
    }
}

function Get-DevicesFromSignInLogs {
    param(
        [Parameter(Mandatory)] [string]$UserUPN,
        [Parameter(Mandatory)] [hashtable]$AllEntraDevicesLookup,
        [int]$DaysBack = 7
    )

    $sevenDaysAgo = (Get-Date).AddDays(-$DaysBack).ToUniversalTime()
    $sevenDaysAgoString = $sevenDaysAgo.ToString('o')

    try {
        Write-Log "Querying sign-in logs for $UserUPN (last $DaysBack days)..." DEBUG -Indent 2
        $signInLogs = Get-MgAuditLogSignIn -Filter "userPrincipalName eq '$UserUPN' and createdDateTime gt $sevenDaysAgoString" -All -ErrorAction Stop

        if (-not $signInLogs) { return @() }
        Write-Log "Found $(@($signInLogs).Count) sign-in events for $UserUPN." DEBUG -Indent 2
        $discoveredDevices = @{}
        foreach ($log in $signInLogs) {
            $deviceDetail = $log.DeviceDetail
            if (-not $deviceDetail) { continue }

            $displayName = $deviceDetail.DisplayName
            if (-not $displayName) { continue }
            if (-not (($deviceDetail.DeviceId -and $AllEntraDevicesLookup.ContainsKey($deviceDetail.DeviceId)) -or
                      ($displayName -and $AllEntraDevicesLookup.ContainsKey($displayName.ToLowerInvariant())))) {
                Write-Log "Skipping unknown device: $displayName" DEBUG -Indent 2
                continue
            }
            if (-not $discoveredDevices.ContainsKey($displayName)) {
                $discoveredDevices[$displayName] = @{
                    DisplayName  = $displayName
                    DeviceId     = $deviceDetail.DeviceId
                    OS           = $deviceDetail.OperatingSystem
                    IsCompliant  = $deviceDetail.IsCompliant
                    TrustType    = $deviceDetail.TrustType
                    LastActivity = $log.CreatedDateTime
                }
            } elseif ($log.CreatedDateTime -gt $discoveredDevices[$displayName].LastActivity) {
                $discoveredDevices[$displayName].LastActivity = $log.CreatedDateTime
            }
        }

        return $discoveredDevices.Values
    } catch {
        Write-Log "Error querying sign-in logs for $UserUPN : $_" WARN -Indent 2
        return @()
    }
}

$skipUserIds = @()

foreach ($skipGroupName in $skipGroupNames) {
    Write-Log "Resolving group '$skipGroupName'..." INFO
    try {
        $skipGroup = Get-MgGroup -Filter "displayName eq '$skipGroupName'" -All -ConsistencyLevel eventual -ErrorAction Stop | Select-Object -First 1
        if (-not $skipGroup) { continue }
        Write-Log "Found group '$($skipGroup.DisplayName)'. Getting transitive members..." SUCCESS -Indent 1
        $members = Get-MgGroupTransitiveMember -GroupId $skipGroup.Id -All -ErrorAction Stop
        $userMembers = $members | Where-Object {
            $_ -is [Microsoft.Graph.PowerShell.Models.MicrosoftGraphUser] -or
            ($_.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.user')
        }
        $skipUserIds += $userMembers | Select-Object -ExpandProperty Id
    } catch { 
        Write-Log "Error resolving group '$skipGroupName': $_" ERROR -Indent 1
    }
}

try {
    $users = Get-MgUser -Filter $filter -All -ConsistencyLevel eventual -Property "id,userPrincipalName,accountEnabled,signInActivity" -ErrorAction Stop
    if (-not $users) { Write-Log "No users found matching filters." WARN; return }
} catch {
    Write-Log "Error querying users: $_" ERROR
    return
}

$usersToProcess = if ($skipUserIds -and @($skipUserIds).Count -gt 0) {
    $users | Where-Object { $_.Id -notin $skipUserIds }
} else { $users }

if (@($usersToProcess).Count -eq 0) { Write-Log "No users remaining after exclusions. Exiting." WARN; return }
$skippedCount = @($users).Count - @($usersToProcess).Count

$filterSummary = @()
if (-not [string]::IsNullOrWhiteSpace($UpnSuffix)) { $filterSummary += "UPN suffix: $UpnSuffix" }
if (-not [string]::IsNullOrWhiteSpace($UPNPrefix)) { $filterSummary += "UPN prefix: $UPNPrefix" }
if (-not [string]::IsNullOrWhiteSpace($CountryFilter)) { $filterSummary += "Country: $CountryFilter" }
if (-not [string]::IsNullOrWhiteSpace($ExcludeUPNprefix)) { $filterSummary += "Exclude UPN prefix: $ExcludeUPNprefix" }
$filterLabel = if ($filterSummary.Count -gt 0) { " (Filters: $($filterSummary -join ', '))"} else { " (No filters)" }
Write-Log "Found $(@($users).Count) users$filterLabel." SUCCESS
if ($skippedCount -gt 0) { Write-Log "Skipping $skippedCount users in exclusion groups." WARN -Indent 1 }
Write-Log "Processing $(@($usersToProcess).Count) users..." SUCCESS

$targetUpnSet = @{}
foreach ($u in $usersToProcess) { if ($u.UserPrincipalName) { $targetUpnSet[$u.UserPrincipalName.ToLowerInvariant()] = $true } }

Write-Log "Fetching Intune managed devices..." INFO
try {
    $allIntuneDevices = Get-MgDeviceManagementManagedDevice -All -Property @(
        "id",
        "deviceName",
        "operatingSystem",
        "complianceState",
        "azureADDeviceId",
        "userPrincipalName"
    ) -ErrorAction Stop
} catch {
    Write-Log "Error querying Intune managed devices: $_" ERROR
    return
}

$allIntuneDevices = $allIntuneDevices | Where-Object { $_.UserPrincipalName -and $targetUpnSet.ContainsKey($_.UserPrincipalName.ToLowerInvariant()) }
$intuneByUpn = @{}
foreach ($d in $allIntuneDevices) {
    if (-not $d.UserPrincipalName) { continue }
    $k = $d.UserPrincipalName.ToLowerInvariant()
    if (-not $intuneByUpn.ContainsKey($k)) { $intuneByUpn[$k] = New-Object System.Collections.Generic.List[object] }
    $intuneByUpn[$k].Add($d)
}
$intuneByAzureAdDeviceId = @{}
foreach ($d in $allIntuneDevices) { if ($d.AzureADDeviceId) { $intuneByAzureAdDeviceId[$d.AzureADDeviceId] = $d } }

try {
    $allEntraDevices = Get-MgDevice -ExpandProperty RegisteredOwners -All -ErrorAction Stop
} catch {
    Write-Log "Error querying Entra devices: $_" ERROR
    return
}

Write-Log "Fetching Entra devices owned by users..." INFO

$entraByOwnerId = @{}
$allEntraDevicesLookup = @{}
foreach ($dev in $allEntraDevices) {
    if (-not $dev.RegisteredOwners) { continue }
    if ($dev.DeviceId) { $allEntraDevicesLookup[$dev.DeviceId] = $dev }
    if ($dev.DisplayName) { $allEntraDevicesLookup[$dev.DisplayName.ToLowerInvariant()] = $dev }
    foreach ($owner in $dev.RegisteredOwners) {
        if (-not $owner.Id) { continue }
        if (-not $entraByOwnerId.ContainsKey($owner.Id)) { $entraByOwnerId[$owner.Id] = New-Object System.Collections.Generic.List[object] }
        $entraByOwnerId[$owner.Id].Add($dev)
    }
}

$results = New-Object System.Collections.Generic.List[object]

foreach ($user in $usersToProcess) {
    $userUPN = $user.UserPrincipalName
    $entraDevices = if ($entraByOwnerId.ContainsKey($user.Id)) { $entraByOwnerId[$user.Id] } else { @() }
    $userUpnKey = $userUPN.ToLowerInvariant()
    $intuneDevices = if ($intuneByUpn.ContainsKey($userUpnKey)) { $intuneByUpn[$userUpnKey] } else { @() }
    $entraCount = @($entraDevices).Count
    $intuneCount = @($intuneDevices).Count
    if ($entraCount -eq 0 -and $intuneCount -eq 0) {
        $signInLogDevices = if ($QuerySignInLogs) {
            Write-Log "Checking sign-in logs for $userUPN..." DEBUG -Indent 1
            Get-DevicesFromSignInLogs -UserUPN $userUPN -AllEntraDevicesLookup $allEntraDevicesLookup
        } else { @() }
        if ($signInLogDevices -and @($signInLogDevices).Count -gt 0) {
            foreach ($device in $signInLogDevices) {
                $compliance = if ($device.IsCompliant) { $ComplianceStates.Compliant } else { $ComplianceStates.Unknown }
            
                $results.Add((New-DeviceReportRow `
                    -UserUPN $userUPN `
                    -AccountEnabled $user.AccountEnabled `
                    -LastInteractiveSignIn $user.SignInActivity?.LastSignInDateTime `
                    -LastNonInteractiveSignIn $user.SignInActivity?.LastNonInteractiveSignInDateTime `
                    -DeviceName $device.DisplayName `
                    -Platform $device.OS `
                    -ComplianceState $compliance `
                    -EntraJoinType $device.TrustType `
                    -LastActivity $device.LastActivity `
                    -MeetsRequirements $false `
                    -EntraDeviceCount 0 `
                    -IntuneDeviceCount 0
                ))
            }
        } else {
            $results.Add((New-DeviceReportRow `
                -UserUPN $userUPN `
                -AccountEnabled $user.AccountEnabled `
                -LastInteractiveSignIn $user.SignInActivity?.LastSignInDateTime `
                -LastNonInteractiveSignIn $user.SignInActivity?.LastNonInteractiveSignInDateTime `
                -DeviceName $DeviceNotFound `
                -Platform $DeviceNotFound `
                -ComplianceState $ComplianceStates.None `
                -EntraJoinType $EntraJoinTypes.None `
                -LastActivity $null `
                -MeetsRequirements $false `
                -EntraDeviceCount 0 `
                -IntuneDeviceCount 0
            ))
        }
        continue
    }
    foreach ($entraDevice in $entraDevices) {
        $entraDeviceId = $entraDevice.DeviceId
        $intuneMatch = if ($entraDeviceId -and $intuneByAzureAdDeviceId.ContainsKey($entraDeviceId)) { $intuneByAzureAdDeviceId[$entraDeviceId] } else { $null }
        $complianceState = if ($intuneMatch) { $intuneMatch.ComplianceState } else { $ComplianceStates.Unknown }
        $meetsRequirements = ($entraDevice.TrustType -eq $EntraJoinTypes.Hybrid) -or
                             (($complianceState -eq $ComplianceStates.Compliant) -and
                              (($entraDevice.TrustType -eq $EntraJoinTypes.AzureAdOnly) -or
                               ($entraDevice.OperatingSystem -match $PlatformMobilePattern)))

        $results.Add((New-DeviceReportRow -UserUPN $userUPN -AccountEnabled $user.AccountEnabled `
            -LastInteractiveSignIn $user.SignInActivity?.LastSignInDateTime `
            -LastNonInteractiveSignIn $user.SignInActivity?.LastNonInteractiveSignInDateTime `
            -DeviceName $entraDevice.DisplayName -Platform $entraDevice.OperatingSystem `
            -ComplianceState $complianceState -EntraJoinType $entraDevice.TrustType `
            -LastActivity $entraDevice.ApproximateLastSignInDateTime -MeetsRequirements $meetsRequirements `
            -EntraDeviceCount $entraCount -IntuneDeviceCount $intuneCount
        ))
    }
    $entraDeviceIdSet = @{}
    foreach ($ed in $entraDevices) { if ($ed.DeviceId) { $entraDeviceIdSet[$ed.DeviceId] = $true } }
    foreach ($intuneDevice in $intuneDevices) {
        if (-not $intuneDevice.AzureADDeviceId -or -not $entraDeviceIdSet.ContainsKey($intuneDevice.AzureADDeviceId)) {
            $results.Add((New-DeviceReportRow -UserUPN $userUPN -AccountEnabled $user.AccountEnabled `
                -LastInteractiveSignIn $user.SignInActivity?.LastSignInDateTime `
                -LastNonInteractiveSignIn $user.SignInActivity?.LastNonInteractiveSignInDateTime `
                -DeviceName $intuneDevice.DeviceName -Platform $intuneDevice.OperatingSystem `
                -ComplianceState $intuneDevice.ComplianceState -EntraJoinType $ActivityNotFound `
                -LastActivity $ActivityNotFound -MeetsRequirements $false `
                -EntraDeviceCount $entraCount -IntuneDeviceCount $intuneCount
            ))
        }
    }
}

# Select columns which prevents surprises if any row ever differs
$columns = @("UserUPN","AccountEnabled","LastInteractiveSignIn","LastNonInteractiveSignIn",
    "DeviceName","Platform","ComplianceState","EntraJoinType","LastActivity",
    "MeetsRequirements","EntraDeviceCount","IntuneDeviceCount")

$totalRows = $results.Count
$meetsRequirementsCount = (@($results | Where-Object { $_.MeetsRequirements -eq $true })).Count
$notMeetsRequirementsCount = $totalRows - $meetsRequirementsCount
$compliantDevicesCount = (@($results | Where-Object { $_.ComplianceState -eq $ComplianceStates.Compliant })).Count
$nonCompliantDevicesCount = $totalRows - $compliantDevicesCount
$hybridJoinCount = (@($results | Where-Object { $_.EntraJoinType -eq $EntraJoinTypes.Hybrid })).Count
$noDeviceCount = ($results | Where-Object { $_.DeviceName -eq $DeviceNotFound } | Measure-Object).Count

Write-Log "Summary Statistics" SUCCESS
Write-Log "  Total device rows: $totalRows" INFO
Write-Log "  Meeting CA requirements: $meetsRequirementsCount | NOT meeting: $notMeetsRequirementsCount" INFO
Write-Log "  Compliant: $compliantDevicesCount | Non-compliant: $nonCompliantDevicesCount" INFO
Write-Log "  Hybrid-joined: $hybridJoinCount" INFO
$aadAndWorkplaceJoinCount = ($results | Where-Object { 
    ($_.EntraJoinType -eq $EntraJoinTypes.AzureAdOnly) -or 
    (($_.Platform -match $PlatformMobilePattern) -and ($_.EntraJoinType -eq 'Workplace' -or $_.EntraJoinType -eq 'WorkplaceJoined'))
} | Measure-Object).Count
Write-Log "  Azure AD joined: $aadAndWorkplaceJoinCount | No devices: $noDeviceCount" INFO

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$filenameParts = @()
if (-not [string]::IsNullOrWhiteSpace($UpnSuffix)) { $filenameParts += ($UpnSuffix -replace ',', '-' -replace '@', '') }
if (-not [string]::IsNullOrWhiteSpace($UPNPrefix)) { $filenameParts += "prefix-$UPNPrefix" }
if (-not [string]::IsNullOrWhiteSpace($CountryFilter)) { $filenameParts += "country-$CountryFilter" }
if (-not [string]::IsNullOrWhiteSpace($ExcludeUPNprefix)) { $filenameParts += "exclude-$ExcludeUPNprefix" }
$filenameLabel = if ($filenameParts.Count -gt 0) { $filenameParts -join '_' } else { "all-users" }
$outputCsv = "DeviceComplianceReport_$($timestamp)_$filenameLabel.csv"
$results | Select-Object $columns | Export-Csv -Path $outputCsv -NoTypeInformation -Encoding UTF8
Write-Log "Report exported to: $outputCsv" SUCCESS