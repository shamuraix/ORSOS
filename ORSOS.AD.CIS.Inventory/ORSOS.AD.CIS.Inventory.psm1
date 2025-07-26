#Requires -Modules ActiveDirectory, GroupPolicy

function Get-ORSOSAdOuStructure {
    [CmdletBinding()]
    param()
    process {
        Get-ADOrganizationalUnit -Filter * -Properties Name, DistinguishedName, Description | 
            Select-Object Name, DistinguishedName, Description
    }
}

function Get-ORSOSAdGpoLinks {
    [CmdletBinding()]
    param()
    process {
        $gpos = Get-GPO -All | Group-Object -Property Id -AsHashTable
        $ous = Get-ADOrganizationalUnit -Filter * -Properties gPLink, DistinguishedName
        foreach ($ou in $ous) {
            if ($ou.gPLink) {
                # gPLink is a string with one or more LDAP://... entries
                # Format: [LDAP://<GUID>;<options>]
                $gpoLinks = ($ou.gPLink -split '\]\[') -replace '\[|\]', ''
                foreach ($gpoLink in $gpoLinks) {
                    if ($gpoLink -match 'LDAP://\{(?<guid>[^\}]+)\};(?<options>\d+)') {
                        $guid = $matches['guid']
                        $options = [int]$matches['options']
                        $enforced = ($options -band 2) -ne 0
                        $gpoName = $gpos["{$guid}"].DisplayName
                        [PSCustomObject]@{
                            GpoGuid     = $guid
                            GpoName     = $gpoName
                            TargetOU    = $ou.DistinguishedName
                            Enforced    = $enforced
                        }
                    }
                }
            }
        }
    }
}


function Get-ORSOSAdSecurityDelegation {
    [CmdletBinding()]
    param()
    process {
        Get-ADOrganizationalUnit -Filter * | ForEach-Object {
            $ou = $_
            try {
                $acl = Get-Acl -Path ("AD:\" + $ou.DistinguishedName)
                foreach ($ace in $acl.Access) {
                    [PSCustomObject]@{
                        OU                 = $ou.DistinguishedName
                        IdentityReference  = $ace.IdentityReference
                        ActiveDirectoryRights = $ace.ActiveDirectoryRights
                        AccessControlType   = $ace.AccessControlType
                        InheritanceType     = $ace.InheritanceType
                        ObjectType          = $ace.ObjectType
                    }
                }
            } catch {
                Write-Warning "Failed to get ACL for $($ou.DistinguishedName): $_"
            }
        }
    }
}

function Get-ORSOSAdObjectInventory {
    [CmdletBinding()]
    param(
        [ValidateSet('User','Computer','Group')]
        [string[]]$ObjectType = @('User','Computer','Group')
    )
    process {
        foreach ($type in $ObjectType) {
            switch ($type) {
                'User' {
                    Get-ADUser -Filter * -Properties DistinguishedName, Description |
                        Select-Object Name, DistinguishedName, Description, Enabled
                }
                'Computer' {
                    Get-ADComputer -Filter * -Properties DistinguishedName, Description |
                        Select-Object Name, DistinguishedName, Description, Enabled
                }
                'Group' {
                    Get-ADGroup -Filter * -Properties DistinguishedName, Description |
                        Select-Object Name, DistinguishedName, Description, GroupScope, GroupCategory
                }
            }
        }
    }
}

function Get-ORSOSAdGpoInventory {
    [CmdletBinding()]
    param()
    process {
        $gpoLinks = Get-ORSOSAdGpoLinks
        $gpoLinksGrouped = @{}
        foreach ($item in $gpoLinks) {
            $id = $item.GpoGuid
            if (-not $gpoLinksGrouped.ContainsKey($id)) {
                $gpoLinksGrouped[$id] = @()
            }
            $gpoLinksGrouped[$id] += $item
        }

        Get-GPO -All | ForEach-Object {
            $gpo = $_
            $links = @()
            if ($gpoLinksGrouped.ContainsKey("$($gpo.Id)")) {
                $links = $gpoLinksGrouped["$($gpo.Id)"] | ForEach-Object {
                    [PSCustomObject]@{
                        TargetOU = $_.TargetOU
                        Enforced = $_.Enforced
                    }
                }
            }
            [PSCustomObject]@{
                Name              = $gpo.DisplayName
                Guid              = $gpo.Id
                Status            = $gpo.GpoStatus
                Owner             = $gpo.Owner
                Created           = $gpo.CreationTime
                Modified          = $gpo.ModificationTime
                SecurityFiltering = (Get-GPPermission -Guid $gpo.Id -All | Where-Object { $_.Permission -eq 'GpoApply' } | Select-Object -ExpandProperty Trustee)
                WMIFilter         = $gpo.WmiFilter.Name
                Links             = $links
            }
        }
    }
}

function Get-ORSOSAdGpoSettingSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$GpoName
    )
    process {
        $report = Get-GPOReport -Name $GpoName -ReportType Xml
        $xml = [xml]$report
        $settings = $xml.GPO.Computer.ExtensionData.Extension | ForEach-Object { $_.Name }
        [PSCustomObject]@{
            GpoName = $GpoName
            SettingCategories = $settings
        }
    }
}

function Export-ORSOSAdInventory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateSet('JSON','YAML')][string]$Format = "JSON"
    )
    $inventory = @{
        OUs            = Get-ORSOSAdOuStructure
        Delegations    = Get-ORSOSAdSecurityDelegation
        Objects        = Get-ORSOSAdObjectInventory
        GPOs           = Get-ORSOSAdGpoInventory
        Timestamp      = (Get-Date)
    }
    switch ($Format) {
        "JSON" { $inventory | ConvertTo-Json -Depth 5 | Out-File $Path -Encoding UTF8 }
        "YAML" { 
            if (-not (Get-Module -ListAvailable -Name powershell-yaml)) {
                throw "powershell-yaml module required for YAML export."
            }
            $inventory | ConvertTo-Yaml | Out-File $Path -Encoding UTF8
        }
    }
    Write-Host "Inventory exported to $Path as $Format."
}
