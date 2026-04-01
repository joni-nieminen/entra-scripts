# Entra ID Scripts

A collection of production-ready, field-tested PowerShell scripts for Microsoft Entra ID administration and security operations.

## Solutions

### Conditional Access

#### [Device Compliance Report](./entra-conditional-access/device-compliance-report/)
Generate compliance reports for devices across your Entra ID users to assess readiness for Conditional Access policy deployment. Correlates Entra ID and Intune device data, identifies which devices meet policy requirements, and exports results to CSV.

**Use cases:**
- Assess CA policy readiness before rollout
- Identify non-compliant devices by user
- Filter users by domain, country, or naming patterns
- Discover sign-in activity devices for scenarios where user doesn't have Intune or Entra registered device(s)

**Quick start:**
```powershell
.\conditionalAccessDeviceReport.ps1 -UpnSuffix 'contoso.com'
```

[Full documentation →](./entra-conditional-access/device-compliance-report/README.md)

---

## Requirements

- PowerShell 5.1+ or PowerShell Core 7+
- Microsoft.Graph PowerShell Module
- Appropriate Entra ID scopes (varies by script)

## Installation

Each solution includes full setup instructions. Start with the solution's README.

## Contributing

These scripts are provided as-is. Modify and extend them for your environment.

## License

See [LICENSE](./LICENSE) for details.