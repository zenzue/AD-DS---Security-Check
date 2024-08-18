function Check-AccountPermissions {
    param (
        [string]$AccountName
    )

    Write-Host "[*] Checking permissions for account: $AccountName..."

    try {
        $permissions = Get-ACL "AD:\$AccountName" | Select-Object -ExpandProperty Access

        $criticalPermissions = $permissions | Where-Object {
            $_.ActiveDirectoryRights -match "GenericAll" -or
            $_.ActiveDirectoryRights -match "WriteDacl" -or
            $_.ActiveDirectoryRights -match "WriteOwner" -or
            $_.ActiveDirectoryRights -match "WriteProperty" -or
            $_.ActiveDirectoryRights -match "ExtendedRight"
        }

        if ($criticalPermissions) {
            Write-Host "[!] Warning: Account $AccountName has critical permissions:"
            $criticalPermissions | Format-Table IdentityReference, ActiveDirectoryRights
        } else {
            Write-Host "[+] No critical permissions found for account $AccountName."
        }
    } catch {
        Write-Host "[!] Error checking permissions for account $AccountName: $_"
    }
}

function Check-BackupAndRestoreRights {
    Write-Host "[*] Checking for Backup and Restore rights..."

    try {
        $backupRestoreAccounts = Get-WmiObject -Class Win32_UserAccount | Where-Object {
            $_.SID -match "S-1-5-32-544" -or $_.SID -match "S-1-5-32-551"  # Backup Operators, Administrators
        }

        if ($backupRestoreAccounts) {
            Write-Host "[!] Accounts with Backup and Restore rights:"
            $backupRestoreAccounts | Format-Table Name, SID
        } else {
            Write-Host "[+] No accounts with Backup and Restore rights found."
        }
    } catch {
        Write-Host "[!] Error checking Backup and Restore rights: $_"
    }
}

function Check-UnconstrainedDelegation {
    Write-Host "[*] Checking for unconstrained delegation..."

    try {
        $delegationAccounts = Get-ADUser -Filter {TrustedForDelegation -eq $True} -Properties Name
        if ($delegationAccounts.Count -gt 0) {
            Write-Host "[!] Warning: The following accounts have Unconstrained Delegation enabled:"
            $delegationAccounts | Format-Table Name
        } else {
            Write-Host "[+] No accounts with Unconstrained Delegation found."
        }
    } catch {
        Write-Host "[!] Error checking Unconstrained Delegation: $_"
    }
}

function Check-DangerousGPOs {
    Write-Host "[*] Checking for potentially dangerous GPOs..."

    try {
        $gpos = Get-GPO -All | Get-GPOReport -ReportType Xml | Select-Xml -XPath "//GPO/Computer/ComputerSection/UserRightsAssignment/Right[@name='SeBackupPrivilege' or @name='SeRestorePrivilege']"

        if ($gpos) {
            Write-Host "[!] Warning: The following GPOs grant Backup and Restore privileges:"
            foreach ($gpo in $gpos) {
                $gpoNode = $gpo.Node
                $gpoName = $gpoNode.GPO.Name
                $privileges = $gpoNode.Right.Name -join ', '
                Write-Host "GPO: $gpoName, Privileges: $privileges"
            }
        } else {
            Write-Host "[+] No dangerous GPOs found."
        }
    } catch {
        Write-Host "[!] Error checking GPOs: $_"
    }
}

function Main {
    $accountName = Read-Host "Enter the AD account name to check"

    Check-AccountPermissions -AccountName $accountName
    Check-BackupAndRestoreRights
    Check-UnconstrainedDelegation
    Check-DangerousGPOs

    Write-Host "[*] Security check complete."
}

Main
