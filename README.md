# Get-LAPSv2Computers

A PowerShell script for enumerating computers with Microsoft LAPS v2 (Local Administrator Password Solution) configured in Active Directory environments.

## 🎯 Purpose

This script helps security professionals and system administrators identify computers with LAPS v2 configured in their Active Directory domain. It uses direct LDAP queries to enumerate the new LAPS v2 attributes (`msLAPS-PasswordExpirationTime`, `msLAPS-Password`, `msLAPS-EncryptedPassword`) which are not supported by older AD PowerShell modules.

## ✨ Features

- **Two enumeration methods**: DirectorySearcher and ADSISearcher
- **Domain flexibility**: Specify any AD domain for enumeration
- **Password display**: Show LAPS passwords (requires appropriate permissions)
- **Password type detection**: Automatically detects if passwords are plain text or encrypted
- **CSV export**: Export results for further analysis
- **No dependencies**: Works without RSAT or AD PowerShell module
- **Detailed output**: Shows DNS hostname, Distinguished Name, password expiration, and password type

## 📋 Requirements

- Windows PowerShell 5.1 or later
- Network connection to domain controller
- Valid domain credentials
- Read permissions on LAPS attributes (for password retrieval)

## 🚀 Usage

### Basic Usage
```powershell
Import-module Get-LAPSv2Computers.ps1
```

### Specify Different Domain
```powershell
Get-LAPSv2Computers -Domain "DC=contoso,DC=com"
```

### Decrypt Password
```powershell
Get-LAPSv2Computers -DecryptPassword
```

### Export to CSV
```powershell
Get-LAPSv2Computers -ExportCSV -ExportPath "C:\temp\LAPS_Report.csv"
```

### Use Alternative Method
```powershell
Get-LAPSv2Computers -Method Method2
```

### Combined Example
```powershell
Get-LAPSv2Computers -Domain "DC=lab,DC=local" -DecryptPassword -ExportCSV -Method Method2
```

## 📝 Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-Domain` | String | `DC=prod,DC=cybercorp,DC=lab` | Target domain in LDAP format |
| `-Method` | String | `Method1` | Enumeration method (`Method1` or `Method2`) |
| `-DecryptPassword` | Switch | False | Display LAPS passwords if accessible |
| `-ExportCSV` | Switch | False | Export results to CSV file |
| `-ExportPath` | String | `C:\LAPS_Computers.csv` | Path for CSV export |


## 🔒 Security Considerations

- This script requires appropriate permissions to read LAPS attributes
- Passwords are only displayed when explicitly requested with `-ShowPassword`
- Encrypted passwords will show as `*** Encrypted ***` even with `-ShowPassword`
- Use responsibly and in accordance with your organization's security policies

## 🛠️ Troubleshooting

### Common Issues

1. **"Error during query"**: Verify domain connectivity and credentials
2. **No results returned**: Ensure LAPS v2 is deployed in your environment
3. **Cannot see passwords**: Verify you have read permissions on LAPS attributes
4. **Domain not found**: Check the domain parameter format (must be LDAP format)

### Why not use standard AD module?

The standard Active Directory PowerShell module (including the one from samratashok's ADModule) may not support the new LAPS v2 attributes. This script uses direct LDAP queries to ensure compatibility with LAPS v2.

## 📜 License

This script is provided as-is for educational and professional use in authorized security assessments and system administration.

## 🤝 Contributing

Feel free to submit issues, fork the repository, and create pull requests for any improvements.

## ⚠️ Disclaimer

This tool is intended for authorized security assessments and system administration only. Users are responsible for complying with applicable laws and regulations.

