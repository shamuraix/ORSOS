<#
.SYNOPSIS
  Randomly partitions computer objects from a specific OU into N AD groups.

.DESCRIPTION
  Retrieves all computer accounts beneath -SearchBase, shuffles them, and assigns them
  across GroupCount groups (default 5). Creates groups if they don't exist and
  optionally replaces membership for existing groups.

.PARAMETER SearchBase
  Distinguished Name (DN) of the OU to search for computer objects (e.g., "OU=Workstations,DC=corp,DC=example,DC=com").

.PARAMETER GroupOU
  DN where the groups should be created. Defaults to -SearchBase if omitted.

.PARAMETER GroupNamePrefix
  Name prefix for groups. Final names are "<prefix>-01", "<prefix>-02", etc.

.PARAMETER GroupCount
  Number of groups to create (default: 5).

.PARAMETER GroupScope
  AD group scope. Default: Global.

.PARAMETER GroupCategory
  AD group category. Default: Security.

.PARAMETER ReplaceMembership
  If set and a target group already exists, its membership will be replaced with
  the computed set. Otherwise, existing members are left as-is and we only add missing ones.

.PARAMETER PreviewOnly
  If set, no changes are made; groupings are output for review.

.EXAMPLE
  .\New-RandomComputerGroups.ps1 -SearchBase "OU=Workstations,DC=corp,DC=example,DC=com" -GroupNamePrefix "WKST-Random" -Verbose -WhatIf

.EXAMPLE
  .\New-RandomComputerGroups.ps1 -SearchBase "OU=Servers,DC=corp,DC=example,DC=com" -GroupOU "OU=RoleGroups,DC=corp,DC=example,DC=com" -GroupNamePrefix "SRV-Batch" -GroupCount 5 -ReplaceMembership
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string]$SearchBase,

  [Parameter()]
  [string]$GroupOU,

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$GroupNamePrefix = "OU-Random",

  [Parameter()]
  [ValidateRange(1, 1000)]
  [int]$GroupCount = 5,

  [Parameter()]
  [ValidateSet('DomainLocal','Global','Universal')]
  [string]$GroupScope = 'Global',

  [Parameter()]
  [ValidateSet('Security','Distribution')]
  [string]$GroupCategory = 'Security',

  [Parameter()]
  [switch]$ReplaceMembership,

  [Parameter()]
  [switch]$PreviewOnly
)

begin {
  try {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
      throw "The ActiveDirectory module is not installed on this system."
    }
    Import-Module ActiveDirectory -ErrorAction Stop
  }
  catch {
    throw "Failed to load ActiveDirectory module: $($_.Exception.Message)"
  }

  if (-not $GroupOU) { $GroupOU = $SearchBase }

  # Validate that SearchBase exists
  try {
    $null = Get-ADObject -Identity $SearchBase -ErrorAction Stop
    Write-Verbose "Validated SearchBase: $SearchBase"
  }
  catch {
    throw "SearchBase '$SearchBase' does not exist or is not accessible - $($_.Exception.Message)"
  }

  # Validate that GroupOU exists
  try {
    $null = Get-ADObject -Identity $GroupOU -ErrorAction Stop
    Write-Verbose "Validated GroupOU: $GroupOU"
  }
  catch {
    throw "GroupOU '$GroupOU' does not exist or is not accessible - $($_.Exception.Message)"
  }

  Write-Verbose ("SearchBase : {0}" -f $SearchBase)
  Write-Verbose ("GroupOU    : {0}" -f $GroupOU)
  Write-Verbose ("Prefix     : {0}" -f $GroupNamePrefix)
  Write-Verbose ("GroupCount : {0}" -f $GroupCount)
  Write-Verbose ("Scope/Cat  : {0}/{1}" -f $GroupScope, $GroupCategory)
  Write-Verbose ("Preview    : {0}" -f $PreviewOnly.IsPresent)
  Write-Verbose ("Replace    : {0}" -f $ReplaceMembership.IsPresent)
}

process {
  try {
    # Pull all computer objects under the OU
    $computers = Get-ADComputer -SearchBase $SearchBase -SearchScope Subtree -LDAPFilter '(objectClass=computer)' -Properties samAccountName -ErrorAction Stop

    if (-not $computers -or $computers.Count -eq 0) {
      Write-Warning "No computer objects found under $SearchBase."
      return
    }

    Write-Verbose ("Found {0} computer(s)." -f $computers.Count)

    # Shuffle
    $shuffled = $computers | Get-Random -Count $computers.Count

    # Bucketize by modulo for even spread
    $buckets = for ($i = 0; $i -lt $GroupCount; $i++) { New-Object System.Collections.Generic.List[object] }

    for ($i = 0; $i -lt $shuffled.Count; $i++) {
      $bucketIndex = $i % $GroupCount
      [void]$buckets[$bucketIndex].Add($shuffled[$i])
    }

    # Prepare name helper that keeps sAMAccountName <= 20 chars (if you care about NetBIOS limits)
    function Get-SafeSamAccountName {
      param([string]$Name)
      if ($Name.Length -le 20) { return $Name }
      # Keep prefix, suffix "-NN" intact; trim middle if needed
      $suffixLen = 3 # "-NN"
      $maxPrefix = 20 - $suffixLen
      return ($Name.Substring(0, [Math]::Max(1,$maxPrefix)) + $Name.Substring($Name.Length - $suffixLen))
    }

    $script:result = @()

    for ($i = 0; $i -lt $GroupCount; $i++) {
      $groupName = "{0}-{1:00}" -f $GroupNamePrefix, ($i + 1)
      # Variable is used in New-ADGroup call when creating new groups
      $samAccountName = Get-SafeSamAccountName -Name $groupName
      $members = $buckets[$i] | ForEach-Object { $_.DistinguishedName }

      $entry = [PSCustomObject]@{
        GroupName   = $groupName
        MemberCount = $members.Count
        Members     = $buckets[$i] | Select-Object -ExpandProperty Name
      }
      $script:result += $entry

      if ($PreviewOnly) { continue }

      # Create/update group and membership
      try {
        $existing = Get-ADGroup -Identity $groupName -ErrorAction SilentlyContinue

        if ($existing) {
          Write-Verbose "Group exists: $groupName"

          $action = if ($ReplaceMembership) { "Replace membership" } else { "Add missing members" }
          if ($PSCmdlet.ShouldProcess($groupName, $action)) {
            if ($ReplaceMembership) {
              # Remove all current members (not just computers)
              $current = Get-ADGroupMember -Identity $existing -ErrorAction SilentlyContinue
              if ($current) {
                try {
                  Remove-ADGroupMember -Identity $existing -Members $current -Confirm:$false -ErrorAction Stop
                  Write-Verbose "Removed $($current.Count) existing member(s) from $groupName"
                } catch {
                  Write-Warning "Failed to remove some members from ${groupName}: $($_.Exception.Message)"
                }
              }
            }

            if ($members.Count -gt 0) {
              try {
                if (-not $ReplaceMembership) {
                  # When not replacing, only add members that aren't already in the group
                  $currentMembers = Get-ADGroupMember -Identity $existing -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DistinguishedName
                  $membersToAdd = $members | Where-Object { $_ -notin $currentMembers }
                  if ($membersToAdd) {
                    Add-ADGroupMember -Identity $existing -Members $membersToAdd -ErrorAction Stop
                    Write-Verbose "Added $($membersToAdd.Count) new member(s) to $groupName"
                  } else {
                    Write-Verbose "No new members to add to $groupName (all already present)"
                  }
                } else {
                  # When replacing, we already cleared members, so add all
                  Add-ADGroupMember -Identity $existing -Members $members -ErrorAction Stop
                  Write-Verbose "Added $($members.Count) member(s) to $groupName"
                }
              } catch {
                Write-Warning "Failed to add some members to ${groupName}: $($_.Exception.Message)"
              }
            }
          }
        }
        else {
          if ($PSCmdlet.ShouldProcess($groupName, "Create group and add $($members.Count) member(s)")) {
            New-ADGroup -Name $groupName `
                        -SamAccountName $samAccountName `
                        -Path $GroupOU `
                        -GroupScope $GroupScope `
                        -GroupCategory $GroupCategory `
                        -DisplayName $groupName `
                        -Description "Random partition from $SearchBase on $(Get-Date -Format o)" `
                        -ErrorAction Stop | Out-Null
            Write-Verbose "Created group: $groupName"
            if ($members.Count -gt 0) {
              try {
                Add-ADGroupMember -Identity $groupName -Members $members -ErrorAction Stop
                Write-Verbose "Added $($members.Count) member(s) to $groupName"
              } catch {
                Write-Warning "Failed to add some members to new group ${groupName}: $($_.Exception.Message)"
              }
            }
          }
        }
      }
      catch {
        Write-Warning "Error processing group '${groupName}' - $($_.Exception.Message)"
      }
    }
  }
  catch {
    throw "Unhandled error: $($_.Exception.Message)"
  }
}

end {
  # Output a concise summary object
  if ($script:result) {
    $script:result | Sort-Object GroupName | Format-Table -AutoSize
    Write-Output $script:result
  }
}
