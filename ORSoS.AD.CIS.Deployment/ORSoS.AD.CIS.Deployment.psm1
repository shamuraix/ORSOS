#Requires -Modules ActiveDirectory, GroupPolicy, powershell-yaml

. "$PSScriptRoot\Private\Logging.ps1"
#. "$PSScriptRoot\Private\InputParser.ps1"

function Import-AdcisConfiguration {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )
    process {
        try {
            switch -Wildcard ($Path) {
                '*.json' { $config = Get-Content $Path | ConvertFrom-Json }
                '*.yaml' { Import-Module powershell-yaml -ErrorAction Stop; $config = ConvertFrom-Yaml (Get-Content $Path -Raw) }
                '*.csv'  { $config = Import-Csv $Path }
                default  { throw "Unsupported file type: $Path" }
            }
            Write-AdcisLog -Message "Imported configuration from $Path" -Level Info
            return $config
        } catch {
            Write-AdcisLog -Message "Failed to import configuration: $_" -Level Error
            throw $_
        }
    }
}

function New-AdcisOrganizationalUnit {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [PSCustomObject[]]$OUConfig
    )
    process {
        foreach ($ou in $OUConfig) {
            try {
                if ($PSCmdlet.ShouldProcess($ou.Name, "Create AD Organizational Unit")) {
                    if (-not (Get-ADOrganizationalUnit -LDAPFilter "(distinguishedName=$($ou.DistinguishedName))" -ErrorAction SilentlyContinue)) {
                        New-ADOrganizationalUnit -Name $ou.Name -Path $ou.ParentDN -ProtectedFromAccidentalDeletion $true
                        Write-AdcisLog -Message "Created OU: $($ou.Name) in $($ou.ParentDN)" -Level Info
                    } else {
                        Write-AdcisLog -Message "OU already exists: $($ou.Name)" -Level Warning
                    }
                }
            } catch {
                Write-AdcisLog -Message "Failed to create OU $($ou.Name): $_" -Level Error
            }
        }
    }
}

function New-AdcisGpo {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [PSCustomObject[]]$GpoConfig
    )
    process {
        foreach ($gpo in $GpoConfig) {
            try {
                if (-not (Get-GPO -Name $gpo.Name -ErrorAction SilentlyContinue)) {
                    New-GPO -Name $gpo.Name
                    Write-AdcisLog -Message "Created GPO: $($gpo.Name)" -Level Info
                } else {
                    Write-AdcisLog -Message "GPO already exists: $($gpo.Name)" -Level Warning
                }
            } catch {
                Write-AdcisLog -Message "Failed to create GPO $($gpo.Name): $_" -Level Error
            }
        }
    }
}

function Set-AdcisGpoLink {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$GpoName,
        [Parameter(Mandatory)]
        [string]$TargetOU,
        [switch]$Enforced
    )
    try {
        New-GPLink -Name $GpoName -Target $TargetOU -Enforced:$Enforced
        Write-AdcisLog -Message "Linked GPO $GpoName to $TargetOU (Enforced: $Enforced)" -Level Info
    } catch {
        Write-AdcisLog -Message "Failed to link GPO $GpoName: $_" -Level Error
    }
}

function Set-AdcisSecurityDelegation {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$OU,
        [Parameter(Mandatory)]
        [string]$Group,
        [Parameter(Mandatory)]
        [string[]]$Permissions
    )
    try {
        $ouObj = Get-ADOrganizationalUnit -Identity $OU
        foreach ($perm in $Permissions) {
            Write-AdcisLog -Message "Would delegate $perm to $Group on $OU" -Level Info
        }
    } catch {
        Write-AdcisLog -Message "Failed delegation on $OU: $_" -Level Error
    }
}

function Set-AdcisGpoFiltering {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$GpoName,
        [Parameter(Mandatory)]
        [string[]]$SecurityGroups,
        [Parameter()]
        [string]$WmiFilter
    )
    try {
        $gpo = Get-GPO -Name $GpoName
        Set-GPPermission -Name $gpo.DisplayName -TargetName "Authenticated Users" -TargetType Group -PermissionLevel None
        foreach ($group in $SecurityGroups) {
            Set-GPPermission -Name $gpo.DisplayName -TargetName $group -TargetType Group -PermissionLevel GpoApply
            Write-AdcisLog -Message "Set GPO $GpoName filtering to $group" -Level Info
        }
        if ($WmiFilter) {
            Set-GPWmiFilter -Name $gpo.DisplayName -WmiFilter $WmiFilter
            Write-AdcisLog -Message "Applied WMI filter $WmiFilter to $GpoName" -Level Info
        }
    } catch {
        Write-AdcisLog -Message "Failed GPO filtering on $GpoName: $_" -Level Error
    }
}
