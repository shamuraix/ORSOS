@{
    RootModule           = 'ORSOS.AD.Roles.psm1'
    ModuleVersion        = '1.0.0'
    GUID                 = 'c3c6f0af-9b8a-4a18-8f3f-0a1f41db8a1a'
    Author               = 'Oregon Secretary of State – Systems Engineering'
    CompanyName          = 'Oregon Secretary of State'
    Copyright            = '(c) 2025 Oregon Secretary of State. MIT License.'
    Description          = 'Provision and synchronize AD role/resource groups from JSON/object mappings (AGDLP).'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop','Core')
    RequiredModules      = @('ActiveDirectory')
    FunctionsToExport    = @(
        'Invoke-AdGroupProvisioning',
        'Set-AdGroupPresence',
        'Set-AdGroupMembership',
        'Test-AdModuleAvailable',
        'Write-StructuredLog'
    )
    CmdletsToExport      = @()
    AliasesToExport      = @()
    VariablesToExport    = @()
    PrivateData          = @{
        PSData = @{
            Tags         = @('ActiveDirectory','Automation','Groups','RBAC','AGDLP')
            LicenseUri   = 'https://opensource.org/licenses/MIT'
            ProjectUri   = 'https://github.com/orsos/ORSOS.AD.Roles'
            ReleaseNotes = 'Initial release with idempotent sync and logging.'
        }
    }
}
