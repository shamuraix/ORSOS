<#
.SYNOPSIS
    Grants service access permissions to a specified user account.

.DESCRIPTION
    This script modifies the security descriptor (SDDL) of a Windows service to grant
    access permissions to a specified user account. It uses SetObjectSecurity.exe to
    apply the new SDDL and optionally validates the changes using AccessChk.exe.

.PARAMETER ServiceName
    The name of the Windows service to modify. Must contain only alphanumeric characters,
    hyphens, underscores, and periods.

.PARAMETER UserAccount
    The user account (in DOMAIN\User or User@Domain format) to grant access to.

.PARAMETER SetObjectSecurityPath
    The full path to the SetObjectSecurity.exe executable.

.PARAMETER AccessChkPath
    Optional. The full path to the AccessChk.exe executable for verification.

.PARAMETER LogPath
    Optional. The full path to the log file. Defaults to a timestamped file in the temp directory.

.PARAMETER MaxLogSizeMB
    Optional. Maximum log file size in megabytes before truncation. Default is 10 MB.
    Set to 0 to disable size checking.

.PARAMETER StrictAccessChkValidation
    Optional. If specified, script will fail if AccessChk validation encounters errors.

.EXAMPLE
    .\Grant-ServiceAccess.ps1 -ServiceName "MyService" -UserAccount "DOMAIN\User" -SetObjectSecurityPath "C:\Tools\SetObjectSecurity.exe"

.EXAMPLE
    .\Grant-ServiceAccess.ps1 -ServiceName "MyService" -UserAccount "DOMAIN\User" -SetObjectSecurityPath "C:\Tools\SetObjectSecurity.exe" -AccessChkPath "C:\Tools\accesschk.exe" -StrictAccessChkValidation

.NOTES
    Requires administrative privileges to modify service security descriptors.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = "Name of the Windows service to modify")]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^[a-zA-Z0-9\-_.]+$', ErrorMessage = "ServiceName must contain only alphanumeric characters, hyphens, underscores, and periods")]
    [string]$ServiceName,

    [Parameter(Mandatory = $true, HelpMessage = "User account to grant access (DOMAIN\User or User@Domain format)")]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^[a-zA-Z0-9\-_.\\@]+$', ErrorMessage = "UserAccount must be in valid format (DOMAIN\User or User@Domain)")]
    [string]$UserAccount,

    [Parameter(Mandatory = $true, HelpMessage = "Full path to SetObjectSecurity.exe")]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({ Test-Path $_ -PathType Leaf }, ErrorMessage = "SetObjectSecurityPath must point to an existing file")]
    [string]$SetObjectSecurityPath,

    [Parameter(HelpMessage = "Full path to AccessChk.exe for verification")]
    [ValidateScript({
        if ($_ -and -not (Test-Path $_ -PathType Leaf)) {
            throw "AccessChkPath must point to an existing file"
        }
        $true
    })]
    [string]$AccessChkPath,

    [Parameter(HelpMessage = "Full path to the log file")]
    [string]$LogPath = "${env:TEMP}\GrantServiceAccess_$((Get-Date).ToString('yyyyMMdd_HHmmss')).log",

    [Parameter(HelpMessage = "Maximum log file size in MB before truncation (0 to disable)")]
    [ValidateRange(0, 1024)]
    [int]$MaxLogSizeMB = 10,

    [Parameter(HelpMessage = "Enable strict validation - fail script if AccessChk encounters errors")]
    [switch]$StrictAccessChkValidation
)

function Write-LogEntry {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet("INFO", "ERROR", "WARN", "VERBOSE")]
        [string]$Level = "INFO"
    )

    # Manage log file size
    if ($MaxLogSizeMB -gt 0 -and (Test-Path $LogPath)) {
        $logSize = (Get-Item $LogPath).Length / 1MB
        if ($logSize -gt $MaxLogSizeMB) {
            $archivePath = $LogPath -replace '\.log$', "_archived_$((Get-Date).ToString('yyyyMMdd_HHmmss')).log"
            Move-Item -Path $LogPath -Destination $archivePath -Force
            Write-Output "Log file exceeded ${MaxLogSizeMB}MB. Archived to: $archivePath"
        }
    }

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
    param (
        [ValidateNotNullOrEmpty()]
        [string]$AccountName
    )
    try {
        # Sanitize account name to prevent injection
        $sanitizedAccount = $AccountName -replace '[^\w\-_.\\@]', ''
        if ($sanitizedAccount -ne $AccountName) {
            throw "Account name contains invalid characters"
        }

        $sid = (New-Object System.Security.Principal.NTAccount($sanitizedAccount)).Translate([System.Security.Principal.SecurityIdentifier]).Value
        return $sid
    }
    catch {
        Write-LogEntry -Message ("Failed to resolve SID for {0}: {1}" -f $AccountName, $_) -Level "ERROR"
        exit 1
    }
}

function Get-CurrentSDDL {
    param (
        [ValidateNotNullOrEmpty()]
        [string]$Service
    )
    try {
        # Sanitize service name to prevent command injection
        $sanitizedService = $Service -replace '[^\w\-_.]', ''
        if ($sanitizedService -ne $Service) {
            throw "Service name contains invalid characters"
        }

        $output = sc.exe sdshow $sanitizedService 2>&1
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

function Test-SDDLValidity {
    param (
        [Parameter(Mandatory = $true)]
        [string]$SDDL
    )

    try {
        # Basic SDDL format validation
        # SDDL should start with D: for DACL or O: for Owner or G: for Group
        if (-not ($SDDL -match '^[DOGUS]:')) {
            Write-LogEntry -Message "SDDL does not start with valid descriptor type (D:, O:, G:, S:, U:)" -Level "ERROR"
            return $false
        }

        # Validate ACE format: (AceType;AceFlags;Rights;ObjectGuid;InheritObjectGuid;AccountSid)
        # Basic pattern check for ACEs within DACL
        if ($SDDL -match 'D:') {
            $daclPart = ($SDDL -split 'D:')[1] -split '[OGSU]:' | Select-Object -First 1
            # Check for balanced parentheses
            $openCount = ($daclPart.ToCharArray() | Where-Object { $_ -eq '(' }).Count
            $closeCount = ($daclPart.ToCharArray() | Where-Object { $_ -eq ')' }).Count
            if ($openCount -ne $closeCount) {
                Write-LogEntry -Message "SDDL has unbalanced parentheses in DACL" -Level "ERROR"
                return $false
            }

            # Validate ACE pattern (basic check)
            $acePattern = '\([AD];[^;]*;[^;]*;[^;]*;[^;]*;[^)]+\)'
            if ($daclPart -and -not ($daclPart -match $acePattern)) {
                Write-LogEntry -Message "SDDL DACL contains invalid ACE format" -Level "WARN"
            }
        }

        # Try to create a RawSecurityDescriptor to validate the SDDL
        try {
            $null = New-Object System.Security.AccessControl.RawSecurityDescriptor($SDDL)
            Write-LogEntry -Message "SDDL validation successful" -Level "VERBOSE"
            return $true
        }
        catch {
            Write-LogEntry -Message "SDDL failed .NET validation: $_" -Level "ERROR"
            return $false
        }
    }
    catch {
        Write-LogEntry -Message "Error during SDDL validation: $_" -Level "ERROR"
        return $false
    }
}

function Set-ServiceSDDL {
    param (
        [ValidateNotNullOrEmpty()]
        [string]$Service,
        [ValidateNotNullOrEmpty()]
        [string]$NewSDDL,
        [string]$OriginalSDDL
    )
    try {
        # Validate SDDL before applying
        if (-not (Test-SDDLValidity -SDDL $NewSDDL)) {
            throw "New SDDL failed validation checks"
        }

        # Sanitize service name
        $sanitizedService = $Service -replace '[^\w\-_.]', ''
        if ($sanitizedService -ne $Service) {
            throw "Service name contains invalid characters"
        }

        # Use array-based argument passing to prevent command injection
        # Do not use string concatenation for arguments
        $arguments = @(
            'service',
            $sanitizedService,
            $NewSDDL,
            '-q'
        )

        Write-LogEntry -Message "Executing SetObjectSecurity for service '$sanitizedService'" -Level "VERBOSE"

        $process = Start-Process -FilePath $SetObjectSecurityPath -ArgumentList $arguments -NoNewWindow -Wait -PassThru -RedirectStandardError "${env:TEMP}\SetObjSec_Error_$((Get-Date).Ticks).txt"

        if ($process.ExitCode -ne 0) {
            # Attempt rollback if we have the original SDDL
            if ($OriginalSDDL) {
                Write-LogEntry -Message "SetObjectSecurity failed. Attempting rollback..." -Level "WARN"
                try {
                    $rollbackArgs = @('service', $sanitizedService, $OriginalSDDL, '-q')
                    $rollbackProcess = Start-Process -FilePath $SetObjectSecurityPath -ArgumentList $rollbackArgs -NoNewWindow -Wait -PassThru
                    if ($rollbackProcess.ExitCode -eq 0) {
                        Write-LogEntry -Message "Rollback successful" -Level "INFO"
                    } else {
                        Write-LogEntry -Message "Rollback failed with exit code $($rollbackProcess.ExitCode)" -Level "ERROR"
                    }
                }
                catch {
                    Write-LogEntry -Message "Rollback attempt failed: $_" -Level "ERROR"
                }
            }
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
        [ValidateNotNullOrEmpty()]
        [string]$ServiceName,
        [ValidateNotNullOrEmpty()]
        [string]$UserAccount,
        [ValidateNotNullOrEmpty()]
        [string]$AccessChkPath,
        [switch]$StrictMode
    )

    if (-not (Test-Path $AccessChkPath)) {
        $message = "AccessChk.exe not found at $AccessChkPath"
        Write-LogEntry -Message $message -Level "WARN"
        if ($StrictMode) {
            Write-LogEntry -Message "Strict validation enabled - failing script" -Level "ERROR"
            exit 1
        }
        return
    }

    # Test if AccessChk is executable
    try {
        $testProcess = Start-Process -FilePath $AccessChkPath -ArgumentList '/?' -NoNewWindow -Wait -PassThru -RedirectStandardOutput "${env:TEMP}\AccessChk_Test_$((Get-Date).Ticks).txt" -RedirectStandardError "${env:TEMP}\AccessChk_TestErr_$((Get-Date).Ticks).txt"
        if ($testProcess.ExitCode -notin @(0, 1)) {
            throw "AccessChk executable test failed with exit code $($testProcess.ExitCode)"
        }
    }
    catch {
        $message = "AccessChk.exe is not functional: $_"
        Write-LogEntry -Message $message -Level "ERROR"
        if ($StrictMode) {
            exit 1
        }
        return
    }

    try {
        # Sanitize inputs
        $sanitizedService = $ServiceName -replace '[^\w\-_.]', ''
        $sanitizedUser = $UserAccount -replace '[^\w\-_.\\@]', ''

        if ($sanitizedService -ne $ServiceName -or $sanitizedUser -ne $UserAccount) {
            throw "Service name or user account contains invalid characters"
        }

        $arguments = @(
            '-v',
            '-nobanner',
            '-c',
            $sanitizedUser,
            $sanitizedService
        )

        $tempFile = [System.IO.Path]::GetTempFileName()
        $errorFile = [System.IO.Path]::GetTempFileName()

        $processInfo = @{
            FilePath               = $AccessChkPath
            ArgumentList           = $arguments
            RedirectStandardOutput = $tempFile
            RedirectStandardError  = $errorFile
            NoNewWindow            = $true
            Wait                   = $true
            PassThru               = $true
        }

        Write-LogEntry -Message "Running AccessChk with arguments: $($arguments -join ' ')" -Level "VERBOSE"

        $accessChkProcess = Start-Process @processInfo

        if (Test-Path $tempFile) {
            $result = Get-Content $tempFile -Raw
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        }

        if (Test-Path $errorFile) {
            $errorOutput = Get-Content $errorFile -Raw
            if ($errorOutput) {
                Write-LogEntry -Message "AccessChk stderr: $errorOutput" -Level "WARN"
            }
            Remove-Item $errorFile -Force -ErrorAction SilentlyContinue
        }

        if ($accessChkProcess.ExitCode -ne 0) {
            $message = "AccessChk exited with code $($accessChkProcess.ExitCode)"
            Write-LogEntry -Message $message -Level "ERROR"
            if ($StrictMode) {
                exit 1
            }
            return
        }

        if (-not $result) {
            $message = "AccessChk returned no output for service '$ServiceName'"
            Write-LogEntry -Message $message -Level "ERROR"
            if ($StrictMode) {
                exit 1
            }
            return
        }

        Write-LogEntry -Message "AccessChk output:`n$result"
    }
    catch {
        $message = "AccessChk failed for service '$ServiceName': $_"
        Write-LogEntry -Message $message -Level "ERROR"
        if ($StrictMode) {
            exit 1
        }
    }
}


# === MAIN EXECUTION ===

Write-LogEntry -Message "Starting permission grant for service '$ServiceName' to user '$UserAccount'..."

# Validate SetObjectSecurity.exe exists and is executable
if (-not (Test-Path $SetObjectSecurityPath -PathType Leaf)) {
    Write-LogEntry -Message "SetObjectSecurity.exe not found at $SetObjectSecurityPath" -Level "ERROR"
    exit 1
}

# Test if SetObjectSecurity.exe is functional
try {
    $testProcess = Start-Process -FilePath $SetObjectSecurityPath -ArgumentList '-?' -NoNewWindow -Wait -PassThru -RedirectStandardOutput "${env:TEMP}\SetObjSec_Test_$((Get-Date).Ticks).txt" -RedirectStandardError "${env:TEMP}\SetObjSec_TestErr_$((Get-Date).Ticks).txt" -ErrorAction Stop
    # Exit codes 0 or 1 are acceptable for help display
    if ($testProcess.ExitCode -notin @(0, 1)) {
        throw "SetObjectSecurity.exe test failed with exit code $($testProcess.ExitCode)"
    }
    Write-LogEntry -Message "SetObjectSecurity.exe validation successful" -Level "VERBOSE"
}
catch {
    Write-LogEntry -Message "SetObjectSecurity.exe is not functional: $_" -Level "ERROR"
    exit 1
}

$userSID = Get-UserSID -AccountName $UserAccount
$currentSDDL = Get-CurrentSDDL -Service $ServiceName

Write-LogEntry -Message "Current SDDL: $currentSDDL" -Level "VERBOSE"
Write-LogEntry -Message "User SID: $userSID" -Level "VERBOSE"

# Validate current SDDL
if (-not (Test-SDDLValidity -SDDL $currentSDDL)) {
    Write-LogEntry -Message "Current SDDL failed validation - this may indicate a problem with the service" -Level "WARN"
}

$newACE = "(A;;CCLCSWRPWPDTLOCRRC;;;${userSID})"
$newSDDL = $currentSDDL -replace '^D:', "D:${newACE}"

Write-LogEntry -Message "New SDDL: $newSDDL" -Level "VERBOSE"

# Validate new SDDL before applying
if (-not (Test-SDDLValidity -SDDL $newSDDL)) {
    Write-LogEntry -Message "Constructed SDDL failed validation" -Level "ERROR"
    exit 1
}

Set-ServiceSDDL -Service $ServiceName -NewSDDL $newSDDL -OriginalSDDL $currentSDDL

if ($AccessChkPath) {
    Test-ServiceAccessWithAccessChk -ServiceName $ServiceName -UserAccount $UserAccount -AccessChkPath $AccessChkPath -StrictMode:$StrictAccessChkValidation
}

Write-LogEntry -Message "Script completed successfully. Log saved to: $LogPath"
