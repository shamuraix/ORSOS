<#
.SYNOPSIS
Provision and synchronize Active Directory role and resource groups from a JSON or object.

.DESCRIPTION
Reads a JSON file (or equivalent object) with two keys:
 - role_groups:  { "RoleGroupName": ["user1","user2",...] }
 - resource_groups: { "ResourceGroupName": ["RoleGroup1","RoleGroup2",...] }

The function will:
 - Ensure role groups (Global, Security) exist in the specified OU, add/remove users.
 - Ensure resource groups (DomainLocal, Security) exist in the specified OU, add/remove role groups.

Implements AGDLP best practice.

.PARAMETER Path
Path to JSON file (alternative to -InputObject).

.PARAMETER InputObject
In-memory object with the same structure as the JSON file.

.PARAMETER RoleGroupsOU
DistinguishedName of OU where role groups should be created.

.PARAMETER ResourceGroupsOU
DistinguishedName of OU where resource groups should be created.

.PARAMETER Mode
Membership sync mode. 'Exact' = JSON is source of truth (adds/removes). 'Additive' = only add.

.PARAMETER LogPath
Optional log file path.

.EXAMPLE
# From JSON file (dry run)
Invoke-AdGroupProvisioning -Path .\orsos_splunk_role_mapping.json `
  -RoleGroupsOU "OU=Roles,DC=contoso,DC=local" `
  -ResourceGroupsOU "OU=Resources,DC=contoso,DC=local" `
  -Mode Exact -WhatIf -Verbose

.EXAMPLE
# From object
$map = @{
  role_groups     = @{ "Splunk_Admins" = @("alice","bob") }
  resource_groups = @{ "Splunk_Prod"   = @("Splunk_Admins") }
}
Invoke-AdGroupProvisioning -InputObject $map `
  -RoleGroupsOU "OU=Roles,DC=contoso,DC=local" `
  -ResourceGroupsOU "OU=Resources,DC=contoso,DC=local"

.NOTES
Author: Oregon Secretary of State – Systems Engineering
License: MIT
#>

# strictness
Set-StrictMode -Version Latest

# ---- helper functions (trimmed for brevity; same as last version) ----
# Test-AdModuleAvailable
# Write-StructuredLog
# Set-AdGroupPresence
# Set-AdGroupMembership
# Invoke-AdGroupProvisioning
# (functions omitted here for brevity; use the definitions from previous version)

Export-ModuleMember -Function Invoke-AdGroupProvisioning, Set-AdGroupPresence, Set-AdGroupMembership, Test-AdModuleAvailable, Write-StructuredLog
