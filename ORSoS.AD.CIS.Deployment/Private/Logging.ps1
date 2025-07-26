function Write-AdcisLog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Message,
        [ValidateSet("Info", "Warning", "Error")]
        [string]$Level = "Info"
    )
    $timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
    $entry = "$timestamp [$Level] $Message"
    Write-Host $entry
    # Uncomment for event log logging if source registered:
    # Write-EventLog -LogName 'Application' -Source 'ORSoS.AD.CIS.Deployment' -EventId 1000 -EntryType $Level -Message $entry
}
