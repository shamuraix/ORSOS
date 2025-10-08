# Import module

```powershell
Import-Module .\ORSOS.OES.ACL\ORSOS.OES.ACL.psd1 -Force
```

# Convert raw OES export to normalized formats

## Text format (legacy)

```powershell
Convert-OESTrustees -InputFile C:\Temp\trustees.txt -CsvOut C:\Temp\trustees.csv -JsonOut C:\Temp\trustees.json
```

## XML format (OES 2018 SP3 trustee_database.xml)

```powershell
Convert-OESTrustees -InputFile C:\Temp\trustee_database.xml -CsvOut C:\Temp\trustees.csv -JsonOut C:\Temp\trustees.json
```

# Quick dump using helper

```powershell
Export-OESTrustees -InputFile C:\Temp\trustees.txt -OutputPath C:\Temp
```

# Apply NTFS ACLs to migrated folder

```powershell
Set-NTFSTrustees -InputFile C:\Temp\trustees.csv -TargetPath D:\MigratedData
```

## Supported Input Formats

### Text Format
```
Trustee: DOMAIN\Administrator Rights: [RWCEFMA]
Trustee: DOMAIN\Users Rights: [RF]
```

### XML Format (OES 2018 SP3)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<trustee-database>
  <trustee>
    <name>CN=Users,OU=Groups,DC=example,DC=com</name>
    <rights>
      <right>R</right>
      <right>W</right>
      <right>F</right>
    </rights>
  </trustee>
</trustee-database>
```

