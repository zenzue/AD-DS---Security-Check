# Active Directory Security Vulnerability Checker

This PowerShell script is designed to help security professionals and system administrators assess potential security vulnerabilities in an Active Directory (AD) environment. It performs several checks related to Kerberos delegation, AdminSDHolder, SID History, DCShadow attack artifacts, and PKI-related vulnerabilities.

## Features

- **Kerberos Unconstrained Delegation Check:** Identifies computers that have unconstrained delegation enabled.
- **Kerberos Constrained Delegation Check:** Identifies users that have constrained delegation enabled.
- **AdminSDHolder Integrity Check:** Detects potential malicious modifications to the AdminSDHolder object.
- **SID History Check:** Finds accounts with a non-null SIDHistory attribute, which can indicate potential security risks.
- **DCShadow Attack Detection:** Lists Domain Controllers and checks for attributes that could indicate a DCShadow attack.
- **krbtgt Key Rotation Check:** Verifies the last password set time for the krbtgt account, a common defense against Golden Ticket attacks.
- **PKI Vulnerabilities Check:** Uses LDAP to search for potential misconfigurations in the Public Key Infrastructure (PKI) related objects.

## Requirements

- **PowerShell:** The script requires PowerShell running on a Windows machine.
- **Active Directory Module:** The Active Directory module for PowerShell must be installed and imported.
- **Permissions:** The script should be run with an account that has sufficient privileges to query AD objects and LDAP.

## Usage

1. **Download the Script:**
   - Save the script as `AD_Security_Check.ps1` on your machine.

2. **Run the Script:**
   - Open PowerShell with administrative privileges.
   - Execute the script:
     ```powershell
     .\AD_Security_Check.ps1
     ```

3. **Provide Inputs:**
   - The script will prompt for the LDAP server address and credentials. Enter the required information when prompted.

4. **Review Output:**
   - The script will display the results of each check directly in the PowerShell console.

## Example Output

```plaintext
[*] Checking for Unconstrained Delegation...
Name
----
DC01

[*] Checking for Constrained Delegation...
Name
----
user01

[*] Checking AdminSDHolder for malicious modifications...
Name   ntSecurityDescriptor
----   ---------------------
AdminSDHolder  {Descriptor}

[*] Checking for SID History on accounts...
Name       SIDHistory
----       ----------
user02     {SID}

[*] Checking for DCShadow attack artifacts...
Name     HostName     ServerObject  IsReadOnly
----     --------     ------------  ----------
DC01     dc01.domain.com  CN=Server,CN=System,DC=domain,DC=com False

[*] Checking if krbtgt key was rotated recently...
PasswordLastSet
---------------
01/01/2024 12:00:00

[*] Checking for PKI-related vulnerabilities...
<Certificate Details>
```

## Author

This script was developed by **Aung Myat Thu aka w01f**.

## License

This project is licensed under the MIT License

## Disclaimer

This script is provided "as is" and is intended for educational and testing purposes only. Use it at your own risk and only in environments where you have explicit permission to perform such security assessments.


