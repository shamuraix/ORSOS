@{
    RootModule        = 'ORSoS.AD.CIS.Deployment.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'e4c63b2e-5c21-4a0e-bc50-6f14b5fdc471'
    Author            = 'Hodson'
    Description       = 'Automates deployment of CIS-compliant OU structure, GPOs, delegations, and filtering in AD.'
    FunctionsToExport = @(
        'Import-AdcisConfiguration',
        'New-AdcisOrganizationalUnit',
        'New-AdcisGpo',
        'Set-AdcisGpoLink',
        'Set-AdcisSecurityDelegation',
        'Set-AdcisGpoFiltering'
    )
    RequiredModules   = @('ActiveDirectory', 'GroupPolicy', 'powershell-yaml')
}
