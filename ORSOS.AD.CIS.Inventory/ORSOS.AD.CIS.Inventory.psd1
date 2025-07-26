@{
    RootModule        = 'ORSoS.AD.CIS.Inventory.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = '37d95d6a-3a40-43c3-a4e4-dfbe26430bc2'
    Author            = 'Hodson'
    Description       = 'Automates discovery of CIS-compliant OU structure, GPOs, delegations, and filtering in AD.'
    FunctionsToExport = @(
        'Get-ORSOSAdOuStructure',
        'Get-ORSOSAdSecurityDelegation',
        'Get-ORSOSAdObjectInventory',
        'Get-ORSOSAdGpoInventory',
        'Get-ORSOSAdGpoSettingSummary',
        'Export-ORSOSAdInventory'
    )
    RequiredModules   = @('ActiveDirectory', 'GroupPolicy', 'powershell-yaml')
}
