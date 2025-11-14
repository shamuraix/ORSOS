[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$ServiceName,

    [Parameter(Mandatory = $true)]
    [string]$UserAccount,

    [Parameter(Mandatory = $true)]
    [string]$SetObjectSecurityPath,

    [Parameter()]
    [string]$AccessChkPath,

    [Parameter()]
    [string]$LogPath = "${env:TEMP}\GrantServiceAccess_$((Get-Date).ToString('yyyyMMdd_HHmmss')).log"
)

function Write-LogEntry {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet("INFO", "ERROR", "WARN", "VERBOSE")]
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "{0} [{1}] {2}" -f $timestamp, $Level, $Message
    Add-Content -Path $LogPath -Value $entry

    switch ($Level) {
        "ERROR"   { Write-Error $Message }
        "WARN"    { Write-Warning $Message }
        "VERBOSE" { Write-Verbose $Message }
        default   { Write-Output $Message }
    }
}

function Get-UserSID {
    param ([string]$AccountName)
    try {
        $sid = (New-Object System.Security.Principal.NTAccount($AccountName)).Translate([System.Security.Principal.SecurityIdentifier]).Value
        return $sid
    }
    catch {
        Write-LogEntry -Message ("Failed to resolve SID for {0}: {1}" -f $AccountName, $_) -Level "ERROR"
        exit 1
    }
}

function Get-CurrentSDDL {
    param ([string]$Service)
    try {
        $output = sc.exe sdshow $Service 2>&1
        if ($LASTEXITCODE -ne 0 -or $output -match "FAILED") {
            throw "sc.exe failed to retrieve SDDL for service '$Service'. Output: $output"
        }

        $regex = [regex]"D:(.*?)(S:|$)"
        $match = $regex.Match($output)

        if ($match.Success) {
            return "D:$($match.Groups[1].Value)"
        } else {
            throw "Could not parse DACL from sc.exe output: $output"
        }
    }
    catch {
        Write-LogEntry -Message ("Failed to retrieve current SDDL for {0}: {1}" -f $Service, $_) -Level "ERROR"
        exit 1
    }
}

function Set-ServiceSDDL {
    param (
        [string]$Service,
        [string]$NewSDDL
    )
    try {
        $arguments = @(
            "service"
            "`"$Service`""
            "`"$NewSDDL`""
            "-q"
        ) -join ' '

        Write-LogEntry -Message "Executing: $SetObjectSecurityPath $arguments" -Level "VERBOSE"

        $process = Start-Process -FilePath $SetObjectSecurityPath -ArgumentList $arguments -NoNewWindow -Wait -PassThru

        if ($process.ExitCode -ne 0) {
            throw "SetObjectSecurity.exe exited with code $($process.ExitCode)"
        }

        Write-LogEntry -Message "Successfully applied new SDDL to service '$Service'."
    }
    catch {
        Write-LogEntry -Message ("Failed to apply SDDL: {0}" -f $_) -Level "ERROR"
        exit 1
    }
}


function Test-ServiceAccessWithAccessChk {
    param (
        [string]$ServiceName,
        [string]$UserAccount,
        [string]$AccessChkPath
    )

    if (-not (Test-Path $AccessChkPath)) {
        Write-LogEntry -Message "AccessChk.exe not found at $AccessChkPath" -Level "WARN"
        return
    }

    try {
        $arguments = @(
            '-v',
            '-nobanner',
            '-c',
            "`"$UserAccount`"",
            $ServiceName
        )

        $tempFile = [System.IO.Path]::GetTempFileName()

        $processInfo = @{
            FilePath               = $AccessChkPath
            ArgumentList           = $arguments
            RedirectStandardOutput = $tempFile
            NoNewWindow            = $true
            Wait                   = $true
        }

        Write-LogEntry -Message "Running AccessChk with arguments: $($arguments -join ' ')" -Level "VERBOSE"

        Start-Process @processInfo

        if (Test-Path $tempFile) {
            $result = Get-Content $tempFile -Raw
            Remove-Item $tempFile -Force
        } else {
            throw "AccessChk did not produce output."
        }

        if (-not $result) {
            throw "AccessChk returned no output for service '$ServiceName'."
        }

        Write-LogEntry -Message "AccessChk output:`n$result"
    }
    catch {
        Write-LogEntry -Message "AccessChk failed for service '$ServiceName': $_" -Level "ERROR"
    }
}


# === MAIN EXECUTION ===

Write-LogEntry -Message "Starting permission grant for service '$ServiceName' to user '$UserAccount'..."

if (-not (Test-Path $SetObjectSecurityPath)) {
    Write-LogEntry -Message "SetObjectSecurity.exe not found at $SetObjectSecurityPath" -Level "ERROR"
    exit 1
}

$userSID = Get-UserSID -AccountName $UserAccount
$currentSDDL = Get-CurrentSDDL -Service $ServiceName

Write-LogEntry -Message "Current SDDL: $currentSDDL" -Level "VERBOSE"
Write-LogEntry -Message "User SID: $userSID" -Level "VERBOSE"

$newACE = "(A;;CCLCSWRPWPDTLOCRRC;;;${userSID})"
$newSDDL = $currentSDDL -replace '^D:', "D:${newACE}"

Write-LogEntry -Message "New SDDL: $newSDDL" -Level "VERBOSE"

Set-ServiceSDDL -Service $ServiceName -NewSDDL $newSDDL

if ($AccessChkPath) {
    Test-ServiceAccessWithAccessChk -ServiceName $ServiceName -UserAccount $UserAccount -AccessChkPath $AccessChkPath
}

Write-LogEntry -Message "Script completed. Log saved to: $LogPath"
