function Check-KerberosUnconstrainedDelegation {
    Write-Host "[*] Checking for Unconstrained Delegation..."
    try {
        $computers = Get-ADComputer -Filter {TrustedForDelegation -eq $True} -Properties Name
        if ($computers.Count -gt 0) {
            Write-Host "[!] Unconstrained Delegation found on the following computers:"
            $computers | Format-Table Name
        } else {
            Write-Host "[+] No Unconstrained Delegation found."
        }
    } catch {
        Write-Host "[!] Error checking Unconstrained Delegation: $_"
    }
}

function Check-KerberosConstrainedDelegation {
    Write-Host "[*] Checking for Constrained Delegation..."
    try {
        $users = Get-ADUser -Filter {TrustedForDelegation -eq $True} -Properties Name
        if ($users.Count -gt 0) {
            Write-Host "[!] Constrained Delegation found on the following users:"
            $users | Format-Table Name
        } else {
            Write-Host "[+] No Constrained Delegation found."
        }
    } catch {
        Write-Host "[!] Error checking Constrained Delegation: $_"
    }
}

function Check-AdminSDHolder {
    Write-Host "[*] Checking AdminSDHolder for malicious modifications..."
    try {
        $adminSDHolder = Get-ADObject -SearchBase "CN=AdminSDHolder,CN=System,DC=domain,DC=com" -Filter * -Properties ntSecurityDescriptor
        $defaultDescriptor = Get-ADObject -SearchBase "CN=Configuration,DC=domain,DC=com" -Filter * -Properties ntSecurityDescriptor | Select-Object -First 1
        if ($adminSDHolder.ntSecurityDescriptor -ne $defaultDescriptor.ntSecurityDescriptor) {
            Write-Host "[!] AdminSDHolder has been modified!"
        } else {
            Write-Host "[+] AdminSDHolder appears to be intact."
        }
    } catch {
        Write-Host "[!] Error checking AdminSDHolder: $_"
    }
}

function Check-SIDHistoryAbuse {
    Write-Host "[*] Checking for SID History abuse..."
    try {
        $users = Get-ADUser -Filter {SIDHistory -ne $null} -Properties Name, SIDHistory
        if ($users.Count -gt 0) {
            Write-Host "[!] SID History found on the following users:"
            $users | Format-Table Name, SIDHistory
        } else {
            Write-Host "[+] No SID History abuse detected."
        }
    } catch {
        Write-Host "[!] Error checking SID History: $_"
    }
}

function Check-DCShadow {
    Write-Host "[*] Checking for DCShadow attack artifacts..."
    try {
        $dcObjects = Get-ADDomainController -Filter * | Select-Object Name, HostName, ServerObject, IsReadOnly
        foreach ($dc in $dcObjects) {
            if ($dc.IsReadOnly -eq $false) {
                Write-Host "[+] $($dc.Name) appears to be a normal writable DC."
            } else {
                Write-Host "[!] $($dc.Name) is read-only. Check for potential DCShadow attack."
            }
        }
    } catch {
        Write-Host "[!] Error checking for DCShadow: $_"
    }
}

function Check-KrbtgtAccountCompromise {
    Write-Host "[*] Checking if krbtgt account is compromised..."
    try {
        $krbtgt = Get-ADUser -Identity krbtgt
        $lastPasswordSet = $krbtgt.PasswordLastSet
        Write-Host "[+] krbtgt password last set on: $lastPasswordSet"
        if ($lastPasswordSet -lt (Get-Date).AddMonths(-6)) {
            Write-Host "[!] Warning: krbtgt password has not been reset in over 6 months. Consider resetting to prevent Golden Ticket attacks."
        }
    } catch {
        Write-Host "[!] Error checking krbtgt account: $_"
    }
}

function Check-PKICompromise {
    param (
        [string]$LdapServer,
        [string]$LdapUser,
        [string]$LdapPassword
    )

    Write-Host "[*] Checking for PKI-related vulnerabilities..."
    try {
        $creds = New-Object System.Management.Automation.PSCredential($LdapUser, (ConvertTo-SecureString $LdapPassword -AsPlainText -Force))
        $connection = New-Object DirectoryServices.DirectoryEntry("LDAP://$LdapServer", $LdapUser, $LdapPassword)
        $searcher = New-Object DirectoryServices.DirectorySearcher($connection)
        $searcher.Filter = "(objectclass=pKIEnrollmentService)"
        $searcher.SearchRoot = "CN=Configuration,DC=domain,DC=com"
        $searcher.PropertiesToLoad.Add("cACertificate")
        $results = $searcher.FindAll()
        if ($results.Count -gt 0) {
            Write-Host "[!] Potential PKI misconfigurations or vulnerabilities detected:"
            foreach ($result in $results) {
                Write-Host $result.Properties["cACertificate"]
            }
        } else {
            Write-Host "[+] No PKI-related vulnerabilities detected."
        }
    } catch {
        Write-Host "[!] Error checking PKI vulnerabilities: $_"
    }
}

function Main {
    $ldapServer = Read-Host "Enter LDAP server address"
    $ldapUser = Read-Host "Enter LDAP user (e.g., domain\user)"
    $ldapPassword = Read-Host "Enter LDAP password" -AsSecureString

    Check-KerberosUnconstrainedDelegation
    Check-KerberosConstrainedDelegation
    Check-AdminSDHolder
    Check-SIDHistoryAbuse
    Check-DCShadow
    Check-KrbtgtAccountCompromise
    Check-PKICompromise -LdapServer $ldapServer -LdapUser $ldapUser -LdapPassword $ldapPassword
}

Main
