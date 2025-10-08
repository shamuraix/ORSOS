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

The module supports two XML format variations:

#### Multiple `<right>` elements (nested format)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<trustee-database>
  <trustee>
    <path>/vol1/data/shared</path>
    <name>CN=Users,OU=Groups,DC=example,DC=com</name>
    <rights>
      <right>R</right>
      <right>W</right>
      <right>F</right>
    </rights>
  </trustee>
</trustee-database>
```

#### Single-line rights (compact format)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<trustee-database>
  <trustee>
    <path>/vol1/data/private</path>
    <name>CN=Users,OU=Groups,DC=example,DC=com</name>
    <rights>RWF</rights>
  </trustee>
</trustee-database>
```

**Note**: The `<path>` element is optional. If present, it will be included in the output CSV/JSON. If omitted, the Path field will be empty.

## Output Format

The converted output (CSV/JSON) includes the following columns:

- **Path**: The file system path where the trustee permissions apply (from `<path>` element in XML, or empty for text format)
- **Trustee**: The trustee name (user or group)
- **Rights**: Comma-separated list of permission codes (R,W,C,E,F,M,A)

### Example CSV Output
```csv
"Path","Trustee","Rights"
"/vol1/data/shared","CN=Users,OU=Groups,DC=example,DC=com","R,W,F"
"/vol1/data/private","CN=Admins,OU=Groups,DC=example,DC=com","R,W,F,A"
```

### Example JSON Output
```json
[
  {
    "Path": "/vol1/data/shared",
    "Trustee": "CN=Users,OU=Groups,DC=example,DC=com",
    "Rights": "R,W,F"
  },
  {
    "Path": "/vol1/data/private",
    "Trustee": "CN=Admins,OU=Groups,DC=example,DC=com",
    "Rights": "R,W,F,A"
  }
]
```

