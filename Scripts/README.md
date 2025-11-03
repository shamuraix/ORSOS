# Dry run (no changes) to review the random distribution:

```powershell
.\New-RandomComputerGroups.ps1 `
  -SearchBase "OU=Workstations,OU=Client,DC=corp,DC=example,DC=com" `
  -GroupNamePrefix "WKST-Random" `
  -Verbose -PreviewOnly
```

# Actually create/update 5 groups under the same OU (safe with -WhatIf first):

```powershell
.\New-RandomComputerGroups.ps1 `
  -SearchBase "OU=Workstations,DC=corp,DC=example,DC=com" `
  -GroupNamePrefix "WKST-Random" `
  -Verbose -WhatIf
```


# Create groups in a separate OU and replace membership if groups already exist:

```powershell
.\New-RandomComputerGroups.ps1 `
  -SearchBase "OU=Servers,DC=corp,DC=example,DC=com" `
  -GroupOU    "OU=BatchGroups,OU=Infra,DC=corp,DC=example,DC=com" `
  -GroupNamePrefix "SRV-Batch" `
  -GroupCount 5 `
  -ReplaceMembership -Verbose
```
