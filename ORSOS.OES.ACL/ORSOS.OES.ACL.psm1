<#
.SYNOPSIS
    Convert and apply OES trustee permissions to NTFS ACLs.

.DESCRIPTION
    Provides functions to normalize trustee exports from OES 2018 SP3 into CSV/JSON,
    and apply them as NTFS ACLs on Windows systems.

.EXAMPLE
    Convert-OESTrustees -InputFile C:\Temp\trustees.txt -CsvOut C:\Temp\trustees.csv -JsonOut C:\Temp\trustees.json

.EXAMPLE
    Set-NTFSTrustees -InputFile C:\Temp\trustees.csv -TargetPath D:\MigratedData
#>

# --- Internal rights mapping ---
$OES2NTFSMap = @{
    "R" = "Read"
    "W" = "Write"
    "C" = "CreateFiles"
    "E" = "Delete"
    "F" = "ReadAndExecute"
    "M" = "Modify"
    "A" = "FullControl"
}

function Convert-OESTrustees {
    <#
    .SYNOPSIS
        Normalize OES trustee export into structured CSV/JSON.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$InputFile,

        [string]$CsvOut = "$PSScriptRoot\trustees.csv",
        [string]$JsonOut = "$PSScriptRoot\trustees.json"
    )

    $results = @()

    try {
        Get-Content $InputFile | ForEach-Object {
            if ($_ -match "Trustee:\s+(?<trustee>.+?)\s+Rights:\s+\[(?<rights>[A-Z]+)\]") {
                $results += [PSCustomObject]@{
                    Trustee = $matches.trustee
                    Rights  = ($matches.rights.ToCharArray() -join ",")
                }
            }
        }

        if ($results.Count -eq 0) {
            throw "No trustee entries parsed from $InputFile"
        }

        $results | Export-Csv -Path $CsvOut -NoTypeInformation -Encoding UTF8
        $results | ConvertTo-Json -Depth 3 | Out-File $JsonOut -Encoding UTF8

        Write-Verbose "Trustees normalized to CSV: $CsvOut"
        Write-Verbose "Trustees normalized to JSON: $JsonOut"
        return $results
    }
    catch {
        Write-Error "Failed to normalize OES trustees: $_"
    }
}

function Export-OESTrustees {
    <#
    .SYNOPSIS
        Helper to quickly dump OES trustees to CSV/JSON.
    #>
    [CmdletBinding()]
    param(
        [string]$InputFile,
        [string]$OutputPath = "$PSScriptRoot"
    )

    $csv = Join-Path $OutputPath "trustees.csv"
    $json = Join-Path $OutputPath "trustees.json"

    Convert-OESTrustees -InputFile $InputFile -CsvOut $csv -JsonOut $json
}

function Set-NTFSTrustees {
    <#
    .SYNOPSIS
        Apply normalized OES trustee entries to an NTFS path.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$InputFile,

        [Parameter(Mandatory=$true)]
        [string]$TargetPath
    )

    try {
        $trustees = Import-Csv $InputFile
        foreach ($t in $trustees) {
            $rights = $t.Rights -split "," | ForEach-Object { $OES2NTFSMap[$_] } | Where-Object { $_ }
            if (-not $rights) {
                Write-Warning "No NTFS mapping for trustee $($t.Trustee) with rights $($t.Rights)"
                continue
            }

            $ntfsRights = [System.Security.AccessControl.FileSystemRights]($rights -join ",")
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $t.Trustee,
                $ntfsRights,
                "ContainerInherit,ObjectInherit",
                "None",
                "Allow"
            )

            $acl = Get-Acl $TargetPath
            $acl.AddAccessRule($rule)
            Set-Acl $TargetPath $acl

            Write-Verbose "Applied NTFS rights [$rights] for trustee $($t.Trustee) on $TargetPath"
        }
    }
    catch {
        Write-Error "Failed to apply NTFS trustees: $_"
    }
}
