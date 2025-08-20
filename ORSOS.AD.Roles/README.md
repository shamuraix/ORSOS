# Import
Import-Module .\ORSOS.AD.Roles.psd1 -Force

# Dry run
Invoke-AdGroupProvisioning `
  -Path .\orsos_splunk_role_mapping.json `
  -RoleGroupsOU "OU=Roles,OU=Groups,DC=sos,DC=oregon,DC=local" `
  -ResourceGroupsOU "OU=Resources,OU=Groups,DC=sos,DC=oregon,DC=local" `
  -Mode Exact -WhatIf -Verbose

# Execute
Invoke-AdGroupProvisioning `
  -Path .\orsos_splunk_role_mapping.json `
  -RoleGroupsOU "OU=Roles,OU=Groups,DC=sos,DC=oregon,DC=local" `
  -ResourceGroupsOU "OU=Resources,OU=Groups,DC=sos,DC=oregon,DC=local" `
  -Mode Exact -LogPath .\logs\ad-roles-sync.log -Verbose
