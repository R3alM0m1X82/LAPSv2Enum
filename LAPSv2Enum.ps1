<#
.SYNOPSIS
    Enumerates computers with LAPS v2 configured in Active Directory domain.

.DESCRIPTION
    This script enumerates all computers that have LAPS v2 configured in the specified
    domain using direct LDAP queries. It can display LAPS passwords (if user has 
    permissions) and export results to CSV.

.PARAMETER Domain
    The domain to enumerate in LDAP format (e.g., DC=prod,DC=cybercorp,DC=lab).
    Default: DC=prod,DC=cybercorp,DC=lab

.PARAMETER Method
    Search method to use. Values: Method1 (DirectorySearcher) or Method2 (ADSISearcher).
    Default: Method1

.PARAMETER ShowPassword
    If specified, shows LAPS passwords (requires read permissions).

.PARAMETER ExportCSV
    If specified, exports results to a CSV file.

.PARAMETER ExportPath
    Path for CSV export file. Default: C:\LAPS_Computers.csv

.EXAMPLE
    .\Get-LAPSv2Computers.ps1
    Enumerates all computers with LAPS v2 using default method and domain.

.EXAMPLE
    .\Get-LAPSv2Computers.ps1 -Domain "DC=contoso,DC=com"
    Enumerates computers in the contoso.com domain.

.EXAMPLE
    .\Get-LAPSv2Computers.ps1 -ShowPassword -Domain "DC=lab,DC=local"
    Enumerates computers showing LAPS passwords in lab.local domain.

.EXAMPLE
    .\Get-LAPSv2Computers.ps1 -Method Method2 -ExportCSV -ExportPath "C:\temp\LAPS.csv"
    Uses method 2 and exports results to C:\temp\LAPS.csv

.NOTES
    Author: R3alM0m1X82 
    Version: 1.1
    Date: 2025
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Domain = "DC=prod,DC=cybercorp,DC=lab",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Method1", "Method2")]
    [string]$Method = "Method1",
    
    [Parameter(Mandatory=$false)]
    [switch]$ShowPassword,
    
    [Parameter(Mandatory=$false)]
    [switch]$ExportCSV,
    
    [Parameter(Mandatory=$false)]
    [string]$ExportPath = "C:\LAPS_Computers.csv"
)

# Main function
function Get-LAPSv2Computers {
    [CmdletBinding()]
    param(
        [string]$Domain,
        [string]$Method,
        [switch]$ShowPassword,
        [switch]$ExportCSV,
        [string]$ExportPath
    )
    
    $computers = @()
    
    if ($Method -eq "Method1") {
        # Method 1: System.DirectoryServices.DirectorySearcher
        Write-Host "`n[*] Using Method 1: DirectorySearcher" -ForegroundColor Cyan
        Write-Host "[*] Connecting to domain $Domain..." -ForegroundColor Yellow
        
        try {
            $searcher = New-Object System.DirectoryServices.DirectorySearcher
            $searcher.SearchRoot = "LDAP://$Domain"
            $searcher.Filter = "(objectClass=computer)"
            $searcher.PropertiesToLoad.Add("dNSHostName") | Out-Null
            $searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
            $searcher.PropertiesToLoad.Add("msLAPS-PasswordExpirationTime") | Out-Null
            $searcher.PropertiesToLoad.Add("msLAPS-Password") | Out-Null
            $searcher.PropertiesToLoad.Add("msLAPS-EncryptedPassword") | Out-Null
            $searcher.PageSize = 1000
            
            Write-Host "[*] Executing LDAP query..." -ForegroundColor Yellow
            $results = $searcher.FindAll()
            
            foreach ($result in $results) {
                if ($result.Properties["msLAPS-PasswordExpirationTime"].Count -gt 0) {
                    # Check if password is plain or encrypted
                    $hasPlainPassword = ($result.Properties["msLAPS-Password"].Count -gt 0) -and 
                                       ($null -ne $result.Properties["msLAPS-Password"][0]) -and 
                                       ($result.Properties["msLAPS-Password"][0] -ne "")
                    
                    $obj = [PSCustomObject]@{
                        DNSHostName = $result.Properties["dNSHostName"][0]
                        DistinguishedName = $result.Properties["distinguishedName"][0]
                        LAPSPasswordExpiration = [datetime]::FromFileTime([long]$result.Properties["msLAPS-PasswordExpirationTime"][0])
                        PasswordType = if($hasPlainPassword) {"Plain"} else {"Encrypted"}
                    }
                    
                    if ($ShowPassword -and $hasPlainPassword) {
                        $obj | Add-Member -MemberType NoteProperty -Name "LAPSPassword" -Value $result.Properties["msLAPS-Password"][0]
                    }
                    elseif ($ShowPassword) {
                        $obj | Add-Member -MemberType NoteProperty -Name "LAPSPassword" -Value "*** Encrypted ***"
                    }
                    
                    $computers += $obj
                }
            }
        }
        catch {
            Write-Host "[!] Error during query: $_" -ForegroundColor Red
            return
        }
    }
    else {
        # Method 2: ADSISearcher
        Write-Host "`n[*] Using Method 2: ADSISearcher" -ForegroundColor Cyan
        Write-Host "[*] Connecting to domain..." -ForegroundColor Yellow
        
        try {
            # For Method2, use the provided domain or auto-detect
            if ($Domain -eq "DC=prod,DC=cybercorp,DC=lab") {
                # Auto-detect current domain
                $domainObj = [ADSI]"LDAP://RootDSE"
                $searchBase = $domainObj.defaultNamingContext
            }
            else {
                # Use specified domain
                $searchBase = $Domain
            }
            
            $searcher = [adsisearcher]"(&(objectClass=computer)(msLAPS-PasswordExpirationTime=*))"
            $searcher.SearchRoot = [ADSI]"LDAP://$searchBase"
            $searcher.PageSize = 1000
            $searcher.PropertiesToLoad.AddRange(@("dNSHostName","distinguishedName","msLAPS-PasswordExpirationTime","msLAPS-Password"))
            
            Write-Host "[*] Executing LDAP query..." -ForegroundColor Yellow
            $results = $searcher.FindAll()
            
            foreach ($result in $results) {
                # Check if password is plain or encrypted
                $hasPlainPassword = ($result.Properties.'mslaps-password'.Count -gt 0) -and 
                                   ($null -ne $result.Properties.'mslaps-password'[0]) -and 
                                   ($result.Properties.'mslaps-password'[0] -ne "")
                
                $obj = [PSCustomObject]@{
                    DNSHostName = $result.Properties.dnshostname[0]
                    DistinguishedName = $result.Properties.distinguishedname[0]
                    LAPSPasswordExpiration = [datetime]::FromFileTime([long]$result.Properties.'mslaps-passwordexpirationtime'[0])
                    PasswordType = if($hasPlainPassword) {"Plain"} else {"Encrypted"}
                }
                
                if ($ShowPassword -and $hasPlainPassword) {
                    $obj | Add-Member -MemberType NoteProperty -Name "LAPSPassword" -Value $result.Properties.'mslaps-password'[0]
                }
                elseif ($ShowPassword) {
                    $obj | Add-Member -MemberType NoteProperty -Name "LAPSPassword" -Value "*** Encrypted ***"
                }
                
                $computers += $obj
            }
        }
        catch {
            Write-Host "[!] Error during query: $_" -ForegroundColor Red
            return
        }
    }
    
    # Output results
    Write-Host "`n[+] Found $($computers.Count) computers with LAPS v2 configured" -ForegroundColor Green
    
    if ($computers.Count -gt 0) {
        # Show results
        $computers | Format-Table -AutoSize
        
        # Export if requested
        if ($ExportCSV) {
            try {
                $computers | Export-Csv -Path $ExportPath -NoTypeInformation
                Write-Host "`n[+] Results exported to: $ExportPath" -ForegroundColor Green
            }
            catch {
                Write-Host "[!] Error during export: $_" -ForegroundColor Red
            }
        }
    }
    else {
        Write-Host "[!] No computers found with LAPS v2 configured" -ForegroundColor Yellow
    }
    
    return $computers
}

# Banner
Write-Host @"
=========================================
        LAPS v2 Enumerator Script
=========================================
"@ -ForegroundColor Cyan

# Execute function with provided parameters
$results = Get-LAPSv2Computers -Domain $Domain -Method $Method -ShowPassword:$ShowPassword -ExportCSV:$ExportCSV -ExportPath $ExportPath

# Final statistics
if ($results.Count -gt 0) {
    Write-Host "`n[*] Statistics:" -ForegroundColor Yellow
    $plainCount = ($results | Where-Object {$_.PasswordType -eq "Plain"}).Count
    $encryptedCount = ($results | Where-Object {$_.PasswordType -eq "Encrypted"}).Count
    Write-Host "    - Plain passwords: $plainCount" -ForegroundColor Green
    Write-Host "    - Encrypted passwords: $encryptedCount" -ForegroundColor Red
}