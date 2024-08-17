function Check-KerberosUnconstrainedDelegation {
    Write-Host "[*] Checking for Unconstrained Delegation..."
    try {
        Get-ADComputer -Filter {TrustedForDelegation -eq $True} | Format-Table Name
    } catch {
        Write-Host "[!] Error checking Unconstrained Delegation: $_"
    }
}

function Check-KerberosConstrainedDelegation {
    Write-Host "[*] Checking for Constrained Delegation..."
    try {
        Get-ADUser -Filter {TrustedForDelegation -eq $True} | Format-Table Name
    } catch {
        Write-Host "[!] Error checking Constrained Delegation: $_"
    }
}

function Check-AdminSDHolder {
    Write-Host "[*] Checking AdminSDHolder for malicious modifications..."
    try {
        Get-ADObject -SearchBase "CN=AdminSDHolder,CN=System,DC=domain,DC=com" -Filter * -Properties ntSecurityDescriptor | Format-Table Name, ntSecurityDescriptor
    } catch {
        Write-Host "[!] Error checking AdminSDHolder: $_"
    }
}

function Check-SIDHistory {
    Write-Host "[*] Checking for SID History on accounts..."
    try {
        Get-ADUser -Filter {SIDHistory -ne $null} | Format-Table Name, SIDHistory
    } catch {
        Write-Host "[!] Error checking SID History: $_"
    }
}

function Check-DCShadow {
    Write-Host "[*] Checking for DCShadow attack artifacts..."
    try {
        Get-ADDomainController -Filter * | Format-Table Name, HostName, ServerObject, IsReadOnly
    } catch {
        Write-Host "[!] Error checking DCShadow: $_"
    }
}

function Check-KrbtgtKeyRotation {
    Write-Host "[*] Checking if krbtgt key was rotated recently..."
    try {
        (Get-ADUser -Identity krbtgt).PasswordLastSet
    } catch {
        Write-Host "[!] Error checking krbtgt key rotation: $_"
    }
}

function Check-PKIVulnerabilities {
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
        foreach ($result in $results) {
            Write-Host $result.Properties["cACertificate"]
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
    Check-SIDHistory
    Check-DCShadow
    Check-KrbtgtKeyRotation
    Check-PKIVulnerabilities -LdapServer $ldapServer -LdapUser $ldapUser -LdapPassword $ldapPassword
}

Main
