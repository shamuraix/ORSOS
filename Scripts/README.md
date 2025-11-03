# New-RandomComputerGroups.ps1

## Overview
This script randomly distributes computer objects from a specified Active Directory OU into multiple AD groups. It's useful for creating balanced groups for staged deployments, testing, or workload distribution.

## Prerequisites
- Active Directory PowerShell module must be installed
- Appropriate permissions to read computer objects and create/modify AD groups
- PowerShell 5.1 or later

## Usage Examples

## Dry run (no changes) to review the random distribution:

```powershell
.\New-RandomComputerGroups.ps1 `
  -SearchBase "OU=Workstations,OU=Client,DC=corp,DC=example,DC=com" `
  -GroupNamePrefix "WKST-Random" `
  -Verbose -PreviewOnly
```

## Actually create/update 5 groups under the same OU (safe with -WhatIf first):

```powershell
.\New-RandomComputerGroups.ps1 `
  -SearchBase "OU=Workstations,DC=corp,DC=example,DC=com" `
  -GroupNamePrefix "WKST-Random" `
  -Verbose -WhatIf
```


## Create groups in a separate OU and replace membership if groups already exist:

```powershell
.\New-RandomComputerGroups.ps1 `
  -SearchBase "OU=Servers,DC=corp,DC=example,DC=com" `
  -GroupOU    "OU=BatchGroups,OU=Infra,DC=corp,DC=example,DC=com" `
  -GroupNamePrefix "SRV-Batch" `
  -GroupCount 5 `
  -ReplaceMembership -Verbose
```
