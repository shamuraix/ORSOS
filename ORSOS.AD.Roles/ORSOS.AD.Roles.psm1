<#
.SYNOPSIS
Provision and synchronize Active Directory role and resource groups from a JSON file or in-memory object.

.DESCRIPTION
Implements AGDLP:
  - Role groups: Global, Security — contain user principals.
  - Resource groups: DomainLocal, Security — nest role groups to grant access.

Input shape (file or object) must contain:
{
  "role_groups": {
    "RoleGroupA": ["user1","user2"],
    "RoleGroupB": ["user3"]
  },
  "resource_groups": {
    "Resource_X": ["RoleGroupA","RoleGroupB"]
  }
}

The module:
  - Ensures groups exist in target OUs (role vs. resource).
  - Synchronizes memberships idempotently.
  - Mode 'Exact' makes JSON the source of truth; 'Additive' only adds.

.NOTES
Author: Oregon Secretary of State – Systems Engineering
License: MIT
Requires: RSAT ActiveDirectory module

.LINK
Get-Help Invoke-AdGroupProvisioning -Detailed

#>

Set-StrictMode -Version Latest

using namespace System.Collections.Generic
using namespace System.Management.Automation

#region Helpers

function Test-AdModuleAvailable {
    [CmdletBinding()]
    param()
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        $err = [System.Exception]::new("ActiveDirectory module is required (RSAT).")
        $category = [System.Management.Automation.ErrorCategory]::ResourceUnavailable
        $record = [System.Management.Automation.ErrorRecord]::new($err, "ADModuleMissing", $category, $null)
        throw $record
    }
    Import-Module ActiveDirectory -ErrorAction Stop | Out-Null
}

function Write-StructuredLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Info','Warn','Error','Debug')]
        [string]$Level,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Message,
        [Parameter()][ValidateNotNullOrEmpty()][string]$LogPath
    )
    $timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [Globalization.CultureInfo]::InvariantCulture)
    $line = "[$timestamp][$Level] $Message"

    switch ($Level) {
        'Info'  { Write-Information -MessageData $line -InformationAction Continue }
        'Warn'  { Write-Warning    -Message $Message }
        'Error' { Write-Error      -Message $Message }
        'Debug' { Write-Verbose    -Message $Message }
    }

    if ($LogPath) {
        try {
            $dir = Split-Path -Path $LogPath -Parent
            if ($dir -and -not (Test-Path -Path $dir)) {
                New-Item -ItemType Directory -Path $dir -Force | Out-Null
            }
            Add-Content -Path $LogPath -Value $line -ErrorAction Stop
        } catch {
            # Do not throw on logging failure; warn only.
            Write-Warning ("Failed to write log to '{0}': {1}" -f $LogPath, $_.Exception.Message)
        }
    }
}

function Test-MappingSchema {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNull()] [psobject]$InputObject
    )
    $hasRole = $InputObject.PSObject.Properties.Name -contains 'role_groups'
    $hasRes  = $InputObject.PSObject.Properties.Name -contains 'resource_groups'
    if (-not ($hasRole -and $hasRes)) {
        $err = [System.Exception]::new("Input must contain 'role_groups' and 'resource_groups'.")
        $record = [System.Management.Automation.ErrorRecord]::new(
            $err, "InvalidSchema", [System.Management.Automation.ErrorCategory]::InvalidData, $InputObject
        )
        throw $record
    }
    if (-not ($InputObject.role_groups -is [psobject])) {
        throw [System.Management.Automation.ErrorRecord]::new(
            [System.Exception]::new("'role_groups' must be an object mapping group => [users]"),
            "InvalidRoleGroups", [System.Management.Automation.ErrorCategory]::InvalidData, $InputObject.role_groups
        )
    }
    if (-not ($InputObject.resource_groups -is [psobject])) {
        throw [System.Management.Automation.ErrorRecord]::new(
            [System.Exception]::new("'resource_groups' must be an object mapping group => [roleGroups]"),
            "InvalidResourceGroups", [System.Management.Automation.ErrorCategory]::InvalidData, $InputObject.resource_groups
        )
    }
    return $true
}

function Set-AdGroupPresence {
    <#
    .SYNOPSIS
    Ensure an AD security group exists with specified scope in a target OU.

    .PARAMETER Name
    sAMAccountName / Name of the group.

    .PARAMETER Scope
    Group scope (Global, DomainLocal, Universal).

    .PARAMETER OrganizationalUnitDN
    Target OU distinguishedName where the group should be created.

    .PARAMETER Description
    Optional description.

    .PARAMETER LogPath
    Optional log file path.

    .OUTPUTS
    DistinguishedName (string)
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Name,
        [Parameter(Mandatory)][ValidateSet('Global','DomainLocal','Universal')][string]$Scope,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$OrganizationalUnitDN,
        [Parameter()][string]$Description = "",
        [Parameter()][string]$LogPath
    )
    Test-AdModuleAvailable

    # Validate OU exists before creating group
    if ($OrganizationalUnitDN -and -not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$OrganizationalUnitDN'" -ErrorAction SilentlyContinue)) {
        Write-Error "❌ Organizational Unit does not exist: $OrganizationalUnitDN"
        return
    }

    $existing = Get-ADGroup -Filter "SamAccountName -eq '$Name'" -ErrorAction SilentlyContinue

    if (-not $existing) {
        if ($PSCmdlet.ShouldProcess($Name, "Create AD Group ($Scope, Security) in $OrganizationalUnitDN")) {
            try {
                New-ADGroup -Name $Name -SamAccountName $Name -GroupScope $Scope -GroupCategory Security `
                    -Path $OrganizationalUnitDN -Description $Description -ErrorAction Stop | Out-Null
                Write-StructuredLog -Level Info -Message ("Created group '{0}' ({1}) in '{2}'." -f $Name, $Scope, $OrganizationalUnitDN) -LogPath $LogPath
            } catch {
                Write-StructuredLog -Level Error -Message ("Create group '{0}' failed: {1}" -f $Name, $_.Exception.Message) -LogPath $LogPath
                throw
            }
        }
        # Only attempt to retrieve if not in WhatIf mode
        if (-not $WhatIfPreference) {
            $existing = Get-ADGroup -Filter "SamAccountName -eq '$Name'" -ErrorAction Stop
        }
    } else {
        if ($existing.GroupScope -ne $Scope) {
            Write-StructuredLog -Level Warn -Message ("Group '{0}' scope is '{1}'; expected '{2}'." -f $Name, $existing.GroupScope, $Scope) -LogPath $LogPath
        }
    }
    return $existing.DistinguishedName
}

function Set-AdGroupMembership {
    <#
    .SYNOPSIS
    Synchronize AD group membership for Users or Groups.

    .PARAMETER GroupSam
    Target group sAMAccountName.

    .PARAMETER DesiredMembersSam
    Array of sAMAccountNames to be present as members.

    .PARAMETER Mode
    Exact: add & remove to match DesiredMembersSam.
    Additive: only add missing; do not remove.

    .PARAMETER MemberType
    'User' or 'Group' determines the objectClass match and resolution.

    .PARAMETER LogPath
    Optional log file path.

    .OUTPUTS
    PSCustomObject with Group, MemberType, Mode, Added, Removed, FinalMembers.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$GroupSam,
        [Parameter()][string[]]$DesiredMembersSam = @(),
        [Parameter()][ValidateSet('Exact','Additive')][string]$Mode = 'Exact',
        [Parameter()][ValidateSet('User','Group')][string]$MemberType = 'User',
        [Parameter()][string]$LogPath
    )
    Test-AdModuleAvailable

    $null = Get-ADGroup -Identity $GroupSam -ErrorAction Stop

    $current = @()
    try {
        $current = Get-ADGroupMember -Identity $GroupSam -Recursive:$false -ErrorAction Stop | Where-Object { $_ } | ForEach-Object {
            if ($MemberType -eq 'User'  -and $_.objectClass -eq 'user')  { $_.SamAccountName }
            elseif ($MemberType -eq 'Group' -and $_.objectClass -eq 'group') { $_.SamAccountName }
        }
    } catch {
        Write-StructuredLog -Level Warn -Message ("Enumerating members of '{0}' failed: {1}" -f $GroupSam, $_.Exception.Message) -LogPath $LogPath
    }

    $desired = @()
    if ($MemberType -eq 'User') {
        foreach ($sam in ($DesiredMembersSam | Where-Object { $_ } | Where-Object { $_.Trim() })) {
            try {
                $u = Get-ADUser -Identity $sam -ErrorAction Stop
                $desired += $u.SamAccountName
            } catch {
                Write-StructuredLog -Level Warn -Message ("User '{0}' not found; skipping for '{1}'." -f $sam, $GroupSam) -LogPath $LogPath
            }
        }
    } else {
        foreach ($sam in ($DesiredMembersSam | Where-Object { $_ } | Where-Object { $_.Trim() })) {
            try {
                $g = Get-ADGroup -Identity $sam -ErrorAction Stop
                $desired += $g.SamAccountName
            } catch {
                Write-StructuredLog -Level Warn -Message ("Group '{0}' not found; skipping for '{1}'." -f $sam, $GroupSam) -LogPath $LogPath
            }
        }
    }

    # Ensure arrays don't contain null elements
    $current = @($current | Where-Object { $_ })
    $desired = @($desired | Where-Object { $_ })

    # Fix the broken membership comparison logic
    $toAdd    = $desired | Where-Object { $_ -notin $current }
    $toRemove = if ($Mode -eq 'Exact') {
        $current | Where-Object { $_ -notin $desired }
    } else { @() }

    if ($toAdd.Count -gt 0 -and $PSCmdlet.ShouldProcess($GroupSam, ("Add {0}: {1}" -f $MemberType, ($toAdd -join ', '))))) {
        try {
            Add-ADGroupMember -Identity $GroupSam -Members $toAdd -ErrorAction Stop
            Write-StructuredLog -Level Info -Message ("Added to '{0}': {1}" -f $GroupSam, ($toAdd -join ', ')) -LogPath $LogPath
        } catch {
            Write-StructuredLog -Level Error -Message ("Adding to '{0}' failed: {1}" -f $GroupSam, $_.Exception.Message) -LogPath $LogPath
            throw
        }
    }

    if ($toRemove.Count -gt 0 -and $PSCmdlet.ShouldProcess($GroupSam, ("Remove {0}: {1}" -f $MemberType, ($toRemove -join ', '))))) {
        try {
            Remove-ADGroupMember -Identity $GroupSam -Members $toRemove -Confirm:$false -ErrorAction Stop
            Write-StructuredLog -Level Info -Message ("Removed from '{0}': {1}" -f $GroupSam, ($toRemove -join ', ')) -LogPath $LogPath
        } catch {
            Write-StructuredLog -Level Error -Message ("Removing from '{0}' failed: {1}" -f $GroupSam, $_.Exception.Message) -LogPath $LogPath
            throw
        }
    }

    $final = Get-ADGroupMember -Identity $GroupSam -Recursive:$false | Where-Object { $_ } | Where-Object {
        if ($MemberType -eq 'User') { $_.objectClass -eq 'user' } else { $_.objectClass -eq 'group' }
    } | Select-Object -ExpandProperty SamAccountName

    [pscustomobject]@{
        Group        = $GroupSam
        MemberType   = $MemberType
        Mode         = $Mode
        Added        = $toAdd
        Removed      = $toRemove
        FinalMembers = $final
    }
}

#endregion Helpers

function Invoke-AdGroupProvisioning {
    <#
    .SYNOPSIS
    Provision & sync AD role/resource groups from JSON path or equivalent object.

    .DESCRIPTION
    Accepts either:
      -Path <string>        # JSON file path
      -InputObject <object> # Object with role_groups/resource_groups
    Creates missing groups in specified OUs and synchronizes memberships per Mode.

    .PARAMETER Path
    Path to the JSON mapping file.

    .PARAMETER InputObject
    In-memory mapping object.

    .PARAMETER RoleGroupsOU
    DistinguishedName for role groups (Global) container OU.

    .PARAMETER ResourceGroupsOU
    DistinguishedName for resource groups (DomainLocal) container OU.

    .PARAMETER Mode
    'Exact' (default) or 'Additive'.

    .PARAMETER RoleGroupDescription
    Optional description for role groups.

    .PARAMETER ResourceGroupDescription
    Optional description for resource groups.

    .PARAMETER LogPath
    Optional log file path.

    .EXAMPLE
    Invoke-AdGroupProvisioning -Path .\orsos_splunk_role_mapping.json `
      -RoleGroupsOU "OU=Roles,OU=Groups,DC=sos,DC=oregon,DC=local" `
      -ResourceGroupsOU "OU=Resources,OU=Groups,DC=sos,DC=oregon,DC=local" `
      -Mode Exact -Verbose -WhatIf

    .EXAMPLE
    $map = @{
      role_groups     = @{ "Splunk_Admins" = @("alice","bob") }
      resource_groups = @{ "Splunk_Prod"   = @("Splunk_Admins") }
    }
    Invoke-AdGroupProvisioning -InputObject $map `
      -RoleGroupsOU "OU=Roles,DC=contoso,DC=local" `
      -ResourceGroupsOU "OU=Resources,DC=contoso,DC=local" `
      -Mode Additive -LogPath .\logs\ad-sync.log

    .OUTPUTS
    List[pscustomobject] with per-group results.
    #>
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName='Path')]
    param(
        [Parameter(Mandatory, ParameterSetName='Path')]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
        [string]$Path,

        [Parameter(Mandatory, ParameterSetName='Object')]
        [ValidateNotNull()] [psobject]$InputObject,

        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$RoleGroupsOU,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ResourceGroupsOU,

        [Parameter()][ValidateSet('Exact','Additive')][string]$Mode = 'Exact',

        [Parameter()][string]$RoleGroupDescription     = 'Role-based access group (Global, Security)',
        [Parameter()][string]$ResourceGroupDescription = 'Resource-based access group (Domain Local, Security)',

        [Parameter()][string]$LogPath
    )

    Test-AdModuleAvailable

    $mapping = if ($PSCmdlet.ParameterSetName -eq 'Path') {
        try {
            Get-Content -Path $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        } catch {
            Write-StructuredLog -Level Error -Message ("Reading JSON '{0}' failed: {1}" -f $Path, $_.Exception.Message) -LogPath $LogPath
            throw
        }
    } else {
        $InputObject
    }

    Test-MappingSchema -InputObject $mapping | Out-Null

    Write-StructuredLog -Level Info -Message ("Starting provisioning (Mode={0})." -f $Mode) -LogPath $LogPath

    $results = [List[object]]::new()

    foreach ($roleGroupName in $mapping.role_groups.PSObject.Properties.Name) {
        $users = @($mapping.role_groups.$roleGroupName)
        Set-AdGroupPresence -Name $roleGroupName -Scope Global -OrganizationalUnitDN $RoleGroupsOU `
            -Description $RoleGroupDescription -WhatIf:$WhatIfPreference -Confirm:$ConfirmPreference -LogPath $LogPath | Out-Null

        $sync = Set-AdGroupMembership -GroupSam $roleGroupName -DesiredMembersSam $users `
            -Mode $Mode -MemberType User -WhatIf:$WhatIfPreference -Confirm:$ConfirmPreference -LogPath $LogPath

        $results.Add([pscustomobject]@{
            Type        = 'RoleGroup'
            Group       = $roleGroupName
            Membership  = $sync
        })
    }

    foreach ($resourceGroupName in $mapping.resource_groups.PSObject.Properties.Name) {
        $desiredRoles = @($mapping.resource_groups.$resourceGroupName)
        Set-AdGroupPresence -Name $resourceGroupName -Scope DomainLocal -OrganizationalUnitDN $ResourceGroupsOU `
            -Description $ResourceGroupDescription -WhatIf:$WhatIfPreference -Confirm:$ConfirmPreference -LogPath $LogPath | Out-Null

        $sync = Set-AdGroupMembership -GroupSam $resourceGroupName -DesiredMembersSam $desiredRoles `
            -Mode $Mode -MemberType Group -WhatIf:$WhatIfPreference -Confirm:$ConfirmPreference -LogPath $LogPath

        $results.Add([pscustomobject]@{
            Type        = 'ResourceGroup'
            Group       = $resourceGroupName
            Membership  = $sync
        })
    }

    Write-StructuredLog -Level Info -Message "Provisioning complete." -LogPath $LogPath
    return $results
}

Export-ModuleMember -Function Invoke-AdGroupProvisioning, Set-AdGroupPresence, Set-AdGroupMembership, Test-AdModuleAvailable, Write-StructuredLog
