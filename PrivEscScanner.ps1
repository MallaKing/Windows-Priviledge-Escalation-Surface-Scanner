<#
.SYNOPSIS
    Windows Privilege Escalation Surface Scanner
    Author: Sahaj Malla
    Description: Detects Weak Named Pipe permissions and Third-Party Kernel Drivers.
#>

function Get-WeakNamedPipes {
    Write-Host "[-] Scanning Named Pipes for Weak Permissions..." -ForegroundColor Cyan
    
    # Get all named pipes
    $pipes = Get-ChildItem "\\.\pipe\" -ErrorAction SilentlyContinue

    foreach ($pipe in $pipes) {
        try {
            # Get Access Control List (ACL)
            $acl = Get-Acl -Path $pipe.FullName -ErrorAction SilentlyContinue
            
            # Check if 'Everyone' or 'Authenticated Users' have write access
            foreach ($access in $acl.Access) {
                if ($access.IdentityReference -match "Everyone|Authenticated Users") {
                    if ($access.FileSystemRights -match "Write|FullControl|GenericWrite") {
                        
                        Write-Host "[!] WEAK PIPE FOUND: $($pipe.FullName)" -ForegroundColor Red
                        Write-Host "    User Group: $($access.IdentityReference)"
                        Write-Host "    Permissions: $($access.FileSystemRights)"
                        Write-Host "    Owner: $($acl.Owner)"
                        Write-Host "------------------------------------------------"
                    }
                }
            }
        }
        catch {
            # Access denied to some system pipes is normal
        }
    }
}

function Get-ThirdPartyDrivers {
    Write-Host "`n[-] Scanning for Non-Microsoft Kernel Drivers (Attack Surface)..." -ForegroundColor Cyan
    
    # Get all drivers, filter out those signed by Microsoft/Windows
    $drivers = Get-WmiObject Win32_SystemDriver | Where-Object { 
        $_.Started -eq $true -and $_.PathName -notmatch "Windows\\System32" 
    }
    
    if ($drivers) {
        foreach ($driver in $drivers) {
            Write-Host "[*] Loaded Driver: $($driver.Name)" -ForegroundColor Yellow
            Write-Host "    Path: $($driver.PathName)"
            Write-Host "    State: $($driver.State)"
        }
        Write-Host "`n[i] TIP: Use 'DriverView' or 'IDA Pro' to reverse these specific drivers for IOCTL vulnerabilities." -ForegroundColor Gray
    } else {
        Write-Host "[+] No obvious 3rd party drivers found in non-standard paths." -ForegroundColor Green
    }
}

# --- Main Execution ---
Write-Host "=== Windows PrivEsc Surface Scanner ===" -ForegroundColor Magenta
Write-Host "Tool by Sahaj Malla | Educational Use Only`n"

Get-WeakNamedPipes
Get-ThirdPartyDrivers

Write-Host "`n[+] Scan Complete." -ForegroundColor Green
