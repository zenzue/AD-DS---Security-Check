import subprocess
import os
import sys
import ldap3
import getpass

def check_kerberos_unconstrained_delegation():
    print("[*] Checking for Unconstrained Delegation...")
    try:
        subprocess.run(["powershell", "-Command",
                        "Get-ADComputer -Filter {TrustedForDelegation -eq $True} | FT Name"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Error checking Unconstrained Delegation: {e}")

def check_kerberos_constrained_delegation():
    print("[*] Checking for Constrained Delegation...")
    try:
        subprocess.run(["powershell", "-Command",
                        "Get-ADUser -Filter {TrustedForDelegation -eq $True} | FT Name"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Error checking Constrained Delegation: {e}")

def check_adminsdholder():
    print("[*] Checking AdminSDHolder for malicious modifications...")
    try:
        subprocess.run(["powershell", "-Command",
                        "Get-ADObject -SearchBase \"CN=AdminSDHolder,CN=System,DC=domain,DC=com\" -Filter * -Properties ntSecurityDescriptor | FT Name,ntSecurityDescriptor"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Error checking AdminSDHolder: {e}")

def check_sid_history():
    print("[*] Checking for SID History on accounts...")
    try:
        subprocess.run(["powershell", "-Command",
                        "Get-ADUser -Filter {SIDHistory -ne $null} | FT Name,SIDHistory"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Error checking SID History: {e}")

def check_dc_shadow():
    print("[*] Checking for DCShadow attack artifacts...")
    try:
        subprocess.run(["powershell", "-Command",
                        "Get-ADDomainController -Filter * | FT Name,HostName,ServerObject,IsReadOnly"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Error checking DCShadow: {e}")

def check_for_krbtgt_key_rotation():
    print("[*] Checking if krbtgt key was rotated recently...")
    try:
        subprocess.run(["powershell", "-Command",
                        "(Get-ADUser -Identity krbtgt).PasswordLastSet"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Error checking krbtgt key rotation: {e}")

def check_pki_vulnerabilities(ldap_server, ldap_user, ldap_password):
    print("[*] Checking for PKI-related vulnerabilities...")
    try:
        server = ldap3.Server(ldap_server, get_info=ldap3.ALL)
        conn = ldap3.Connection(server, ldap_user, ldap_password, auto_bind=True)
        conn.search('CN=Configuration,DC=domain,DC=com', '(objectclass=pKIEnrollmentService)', attributes=['cACertificate'])
        for entry in conn.entries:
            print(entry)
    except ldap3.LDAPException as e:
        print(f"[!] Error checking PKI vulnerabilities: {e}")

def main():
    ldap_server = input("Enter LDAP server address: ")
    ldap_user = input("Enter LDAP user (e.g., domain\\user): ")
    ldap_password = getpass.getpass("Enter LDAP password: ")

    check_kerberos_unconstrained_delegation()
    check_kerberos_constrained_delegation()
    check_adminsdholder()
    check_sid_history()
    check_dc_shadow()
    check_for_krbtgt_key_rotation()
    check_pki_vulnerabilities(ldap_server, ldap_user, ldap_password)

if __name__ == "__main__":
    main()
