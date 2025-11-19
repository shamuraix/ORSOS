# New-RandomComputerGroups.ps1

## Overview
This script randomly distributes computer objects from a specified Active Directory OU into multiple AD groups. It's useful for creating balanced groups for staged deployments, testing, or workload distribution.

## Prerequisites
- Active Directory PowerShell module must be installed
- Appropriate permissions to read computer objects and create/modify AD groups
- PowerShell 5.1 or later

## Usage Examples

### Dry run (no changes) to review the random distribution:

```powershell
.\New-RandomComputerGroups.ps1 `
  -SearchBase "OU=Workstations,OU=Client,DC=corp,DC=example,DC=com" `
  -GroupNamePrefix "WKST-Random" `
  -Verbose -PreviewOnly
```

### Actually create/update 5 groups under the same OU (safe with -WhatIf first):

```powershell
.\New-RandomComputerGroups.ps1 `
  -SearchBase "OU=Workstations,DC=corp,DC=example,DC=com" `
  -GroupNamePrefix "WKST-Random" `
  -Verbose -WhatIf
```

### Create groups in a separate OU and replace membership if groups already exist:

```powershell
.\New-RandomComputerGroups.ps1 `
  -SearchBase "OU=Servers,DC=corp,DC=example,DC=com" `
  -GroupOU    "OU=BatchGroups,OU=Infra,DC=corp,DC=example,DC=com" `
  -GroupNamePrefix "SRV-Batch" `
  -GroupCount 5 `
  -ReplaceMembership -Verbose
```

### Filter to only include computers that have logged on within the last 30 days:

```powershell
.\New-RandomComputerGroups.ps1 `
  -SearchBase "OU=Workstations,DC=corp,DC=example,DC=com" `
  -GroupNamePrefix "WKST-Active" `
  -LastLogonDays 30 `
  -Verbose
```

This uses the `lastLogonTimestamp` attribute (replicated across DCs) to filter computers. Computers without a `lastLogonTimestamp` or with a timestamp older than the specified days are excluded.

## Error Handling and Logging

The script includes comprehensive error handling to gracefully manage various failure scenarios:

### Enhanced Error Handling Features

- **Detailed Diagnostics**: When operations fail, the script provides specific error messages indicating which operation failed and why
- **Verbose Logging**: Use `-Verbose` parameter to see detailed progress information, including:
  - Current member counts before operations
  - Number of members added/removed
  - Details about which members failed to be added (visible in verbose output)
- **Graceful Degradation**: The script continues processing remaining groups even if one group encounters errors
- **Clear Warnings**: Warnings are issued for:
  - Failed member removal operations
  - Failed member addition operations
  - Group creation failures
  - Unexpected errors during group processing

### Common Error Scenarios

1. **"Failed to add members"**: This may occur if:
   - Computer objects no longer exist in AD
   - Computer objects are disabled
   - Insufficient permissions to modify group membership
   - Network connectivity issues to domain controller

2. **"Could not retrieve current members"**: This may occur if:
   - The group exists but you don't have read permissions
   - The group is empty (handled gracefully)
   - Network connectivity issues

3. **"Failed to create group"**: This may occur if:
   - Group already exists with different case
   - Insufficient permissions in target OU
   - Target OU doesn't exist

### Best Practices

- Always test with `-WhatIf` first to preview changes
- Use `-Verbose` to see detailed operation logs
- Review warnings carefully - they indicate which specific operations failed
- If warnings persist, verify:
  - Computer objects still exist and are enabled
  - You have appropriate AD permissions
  - Network connectivity to domain controllers is stable
