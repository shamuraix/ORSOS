# Import module

```powershell
Import-Module .\ORSOS.OES.ACL\ORSOS.OES.ACL.psd1 -Force
```
# Convert raw OES export to normalized formats

```powershell
Convert-OESTrustees -InputFile C:\Temp\trustees.txt -CsvOut C:\Temp\trustees.csv -JsonOut C:\Temp\trustees.json
```

# Quick dump using helper

```powershell
Export-OESTrustees -InputFile C:\Temp\trustees.txt -OutputPath C:\Temp
```

# Apply NTFS ACLs to migrated folder

```powershell
Set-NTFSTrustees -InputFile C:\Temp\trustees.csv -TargetPath D:\MigratedData
```
