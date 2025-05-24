<#
.SYNOPSIS
    PowerShell module to enumerate computers with LAPS v2 configured in Active Directory.

.DESCRIPTION
    This module provides a function to enumerate all computers that have LAPS v2 configured
    in the specified domain using direct LDAP queries. It works with standard user permissions
    and optionally attempts to decrypt passwords if requested.

.NOTES
    Module Name: LAPSv2Enum
    Author: @R3alM0m1X82
    Version: 2.0
    Date: 2025
#>

function Get-LAPSv2Computers {
    <#
    .SYNOPSIS
        Enumerates computers with LAPS v2 configured in Active Directory.

    .DESCRIPTION
        This function enumerates all computers that have LAPS v2 configured in the specified
        domain using direct LDAP queries. It only checks for the presence of LAPS v2 by default,
        without attempting to read password attributes that require elevated permissions.

    .PARAMETER Domain
        The domain to enumerate in LDAP format (e.g., DC=prod,DC=cybercorp,DC=lab).
        Default: DC=prod,DC=cybercorp,DC=lab

    .PARAMETER Method
        Search method to use. Values: Method1 (DirectorySearcher) or Method2 (ADSISearcher).
        Default: Method1

    .PARAMETER DecryptPassword
        If specified, attempts to read and decrypt LAPS passwords (requires appropriate permissions).

    .PARAMETER ExportCSV
        If specified, exports results to a CSV file.

    .PARAMETER ExportPath
        Path for CSV export file. Default: C:\LAPS_Computers.csv

    .EXAMPLE
        Get-LAPSv2Computers
        Enumerates all computers with LAPS v2 in the default domain.

    .EXAMPLE
        Get-LAPSv2Computers -Domain "DC=contoso,DC=com"
        Enumerates computers in the contoso.com domain.

    .EXAMPLE
        Get-LAPSv2Computers -Domain "DC=lab,DC=local" -DecryptPassword
        Attempts to decrypt passwords in lab.local domain (requires permissions).
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Domain = "DC=prod,DC=cybercorp,DC=lab",
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("Method1", "Method2")]
        [string]$Method = "Method1",
        
        [Parameter(Mandatory=$false)]
        [switch]$DecryptPassword,
        
        [Parameter(Mandatory=$false)]
        [switch]$ExportCSV,
        
        [Parameter(Mandatory=$false)]
        [string]$ExportPath = "C:\LAPS_Computers.csv"
    )
    
    Write-Host "`n[*] Starting LAPS v2 enumeration..." -ForegroundColor Cyan
    Write-Host "[*] Target domain: $Domain" -ForegroundColor Yellow
    
    $computers = @()
    
    if ($Method -eq "Method1") {
        # Method 1: System.DirectoryServices.DirectorySearcher
        Write-Host "[*] Using Method 1: DirectorySearcher" -ForegroundColor Cyan
        
        try {
            $searcher = New-Object System.DirectoryServices.DirectorySearcher
            $searcher.SearchRoot = "LDAP://$Domain"
            $searcher.Filter = "(&(objectClass=computer)(msLAPS-PasswordExpirationTime=*))"
            $searcher.PropertiesToLoad.Add("cn") | Out-Null
            $searcher.PropertiesToLoad.Add("dNSHostName") | Out-Null
            $searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
            $searcher.PropertiesToLoad.Add("msLAPS-PasswordExpirationTime") | Out-Null
            
            # Only load password attributes if requested
            if ($DecryptPassword) {
                Write-Host "[*] Password decryption requested - loading password attributes" -ForegroundColor Yellow
                $searcher.PropertiesToLoad.Add("msLAPS-Password") | Out-Null
                $searcher.PropertiesToLoad.Add("msLAPS-EncryptedPassword") | Out-Null
            }
            
            $searcher.PageSize = 1000
            
            Write-Host "[*] Executing LDAP query..." -ForegroundColor Yellow
            $results = $searcher.FindAll()
            
            Write-Host "[*] Processing results..." -ForegroundColor Yellow
            
            foreach ($result in $results) {
                # Basic info that any user can read
                $computerName = if ($result.Properties["cn"].Count -gt 0) { 
                    $result.Properties["cn"][0].ToString() 
                } else { 
                    "Unknown" 
                }
                
                $dnsName = if ($result.Properties["dNSHostName"].Count -gt 0) { 
                    $result.Properties["dNSHostName"][0].ToString() 
                } else { 
                    $computerName 
                }
                
                $dn = if ($result.Properties["distinguishedName"].Count -gt 0) { 
                    $result.Properties["distinguishedName"][0].ToString() 
                } else { 
                    "Unknown" 
                }
                
                $expTime = try {
                    [datetime]::FromFileTime([long]$result.Properties["msLAPS-PasswordExpirationTime"][0])
                } catch {
                    "Unable to parse"
                }
                
                $obj = [PSCustomObject]@{
                    ComputerName = $computerName
                    DNSHostName = $dnsName
                    DistinguishedName = $dn
                    LAPSEnabled = $true
                    LAPSPasswordExpiration = $expTime
                }
                
                # Only try to read password if requested
                if ($DecryptPassword) {
                    $hasPlainPassword = ($result.Properties["msLAPS-Password"].Count -gt 0) -and 
                                       ($null -ne $result.Properties["msLAPS-Password"][0]) -and 
                                       ($result.Properties["msLAPS-Password"][0] -ne "")
                    
                    if ($hasPlainPassword) {
                        $obj | Add-Member -MemberType NoteProperty -Name "PasswordType" -Value "Plain"
                        $obj | Add-Member -MemberType NoteProperty -Name "LAPSPassword" -Value $result.Properties["msLAPS-Password"][0]
                    } else {
                        $obj | Add-Member -MemberType NoteProperty -Name "PasswordType" -Value "Encrypted"
                        $obj | Add-Member -MemberType NoteProperty -Name "LAPSPassword" -Value "*** Requires Decryption Permissions ***"
                    }
                }
                
                $computers += $obj
            }
            
            $results.Dispose()
        }
        catch {
            Write-Host "[!] Error during query: $_" -ForegroundColor Red
            return @()
        }
    }
    else {
        # Method 2: ADSISearcher
        Write-Host "[*] Using Method 2: ADSISearcher" -ForegroundColor Cyan
        
        try {
            # For Method2, use the provided domain or auto-detect
            if ($Domain -eq "DC=prod,DC=cybercorp,DC=lab") {
                $domainObj = [ADSI]"LDAP://RootDSE"
                $searchBase = $domainObj.defaultNamingContext
            } else {
                $searchBase = $Domain
            }
            
            $searcher = [adsisearcher]"(&(objectClass=computer)(msLAPS-PasswordExpirationTime=*))"
            $searcher.SearchRoot = [ADSI]"LDAP://$searchBase"
            $searcher.PageSize = 1000
            $searcher.PropertiesToLoad.AddRange(@("cn","dNSHostName","distinguishedName","msLAPS-PasswordExpirationTime"))
            
            if ($DecryptPassword) {
                Write-Host "[*] Password decryption requested - loading password attributes" -ForegroundColor Yellow
                $searcher.PropertiesToLoad.Add("msLAPS-Password") | Out-Null
            }
            
            Write-Host "[*] Executing LDAP query..." -ForegroundColor Yellow
            $results = $searcher.FindAll()
            
            Write-Host "[*] Processing results..." -ForegroundColor Yellow
            
            foreach ($result in $results) {
                # Basic info that any user can read
                $computerName = if ($result.Properties.cn.Count -gt 0) { 
                    $result.Properties.cn[0].ToString() 
                } else { 
                    "Unknown" 
                }
                
                $dnsName = if ($result.Properties.dnshostname.Count -gt 0) { 
                    $result.Properties.dnshostname[0].ToString() 
                } else { 
                    $computerName 
                }
                
                $dn = if ($result.Properties.distinguishedname.Count -gt 0) { 
                    $result.Properties.distinguishedname[0].ToString() 
                } else { 
                    "Unknown" 
                }
                
                $expTime = try {
                    [datetime]::FromFileTime([long]$result.Properties.'mslaps-passwordexpirationtime'[0])
                } catch {
                    "Unable to parse"
                }
                
                $obj = [PSCustomObject]@{
                    ComputerName = $computerName
                    DNSHostName = $dnsName
                    DistinguishedName = $dn
                    LAPSEnabled = $true
                    LAPSPasswordExpiration = $expTime
                }
                
                # Only try to read password if requested
                if ($DecryptPassword) {
                    $hasPlainPassword = ($result.Properties.'mslaps-password'.Count -gt 0) -and 
                                       ($null -ne $result.Properties.'mslaps-password'[0]) -and 
                                       ($result.Properties.'mslaps-password'[0] -ne "")
                    
                    if ($hasPlainPassword) {
                        $obj | Add-Member -MemberType NoteProperty -Name "PasswordType" -Value "Plain"
                        $obj | Add-Member -MemberType NoteProperty -Name "LAPSPassword" -Value $result.Properties.'mslaps-password'[0]
                    } else {
                        $obj | Add-Member -MemberType NoteProperty -Name "PasswordType" -Value "Encrypted"
                        $obj | Add-Member -MemberType NoteProperty -Name "LAPSPassword" -Value "*** Requires Decryption Permissions ***"
                    }
                }
                
                $computers += $obj
            }
            
            $results.Dispose()
        }
        catch {
            Write-Host "[!] Error during query: $_" -ForegroundColor Red
            return @()
        }
    }
    
    # Output results
    Write-Host "`n[+] Found $($computers.Count) computers with LAPS v2 configured" -ForegroundColor Green
    
    if ($computers.Count -gt 0) {
        # Display the results
        Write-Host "`n[*] LAPS v2 Enabled Computers:" -ForegroundColor Cyan
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
        
        # Statistics
        Write-Host "`n[*] Summary:" -ForegroundColor Yellow
        Write-Host "    - Total computers with LAPS v2: $($computers.Count)" -ForegroundColor Green
        
        if ($DecryptPassword) {
            $plainCount = ($computers | Where-Object {$_.PasswordType -eq "Plain"}).Count
            $encryptedCount = ($computers | Where-Object {$_.PasswordType -eq "Encrypted"}).Count
            Write-Host "    - Plain passwords: $plainCount" -ForegroundColor Green
            Write-Host "    - Encrypted passwords: $encryptedCount" -ForegroundColor Red
        }
    }
    else {
        Write-Host "[!] No computers found with LAPS v2 configured" -ForegroundColor Yellow
    }
    
    return $computers
}

# The function is now available for use
# If saved as .psm1, it will be automatically exported
# If saved as .ps1, you can dot-source it: . .\Get-LAPSv2Computers.ps1