@{
    RootModule        = 'ORSOS.OES.ACL.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'c6b0c7e0-dc71-4fb9-bf40-1234567890ab'
    Author            = 'Christopher Hodson'
    CompanyName       = 'Oregon Secretary of State'
    Copyright         = '(c) 2025 Oregon SoS. All rights reserved.'
    Description       = 'Convert and apply OES trustee permissions to Windows NTFS ACLs.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Convert-OESTrustees',
        'Export-OESTrustees',
        'Set-NTFSTrustees'
    )
    CmdletsToExport   = @()
    VariablesToExport = '*'
    AliasesToExport   = '*'
}
