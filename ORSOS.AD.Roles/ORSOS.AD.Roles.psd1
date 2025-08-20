@{
    RootModule        = 'ORSOS.AD.Roles.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'c3c6f0af-9b8a-4a18-8f3f-0a1f41db8a1a'
    Author            = 'Oregon Secretary of State – Systems Engineering'
    CompanyName       = 'Oregon Secretary of State'
    Copyright         = '(c) 2025 Oregon Secretary of State. All rights reserved.'
    Description       = 'Provision and synchronize AD role/resource groups from JSON/object mappings, implementing AGDLP best practice.'
    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop','Core')
    RequiredModules   = @('ActiveDirectory')
    FunctionsToExport = @('Invoke-AdGroupProvisioning','Set-AdGroupPresence','Set-AdGroupMembership','Test-AdModuleAvailable','Write-StructuredLog')
    CmdletsToExport   = @()
    AliasesToExport   = @()
    VariablesToExport = @()
    PrivateData       = @{
        PSData = @{
            Tags         = @('ActiveDirectory','Automation','Provisioning','Groups','RBAC')
            LicenseUri   = 'https://opensource.org/licenses/MIT'
            ProjectUri   = 'https://github.com/orsos/ORSOS.AD.Roles'
            ReleaseNotes = 'Initial release: sync AD groups from JSON mapping.'
        }
    }
}
