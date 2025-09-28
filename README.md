# OmniWin Auditor – Free Windows Security Audit Tool  

**Check your Windows security in minutes with one PowerShell script**  

OmniWin Auditor is a free and open-source PowerShell tool that makes it easy to check how secure your Windows PC really is. No need to click through dozens of menus or hidden settings—just run the script and get a clear report.  

Works on Windows 10, Windows 11, and Windows Server. 

### Helpful for everyday users, IT staff, and anyone who wants to know if their system is locked down.  

---

## 🔍 What it does  

- Scans your password and account lockout settings  
- Checks user rights and permissions that could be risky  
- Reviews local security policies  
- Analyzes antivirus, firewall, and group policy configs  
- Creates easy-to-read reports with all the details  

In short: you run one command, and the tool gives you a full security snapshot.  

---

## 🖥️ Supported versions  

- Windows 10 (Home, Pro, Enterprise, Education)  
- Windows 11 (Home, Pro, Enterprise, Education)  
- Windows Server 2022 / 2025 (Standard, Datacenter)  
- Microsoft 365 / Office 365 setups  
- Azure AD and Hybrid AD systems (partially tested)  

---

## 🚀 Quick Start  

1. **Download** this repo (no install needed)  
2. **Open PowerShell as Administrator**  
3. **Navigate** to the folder  
4. Run:  
   ```powershell
   .\omniwin-auditor.ps1
    ```

Pick the recommended scan and you're on your way!

⏱ Takes about 5–10 minutes.

📊 Saves timestamped reports automatically.

    💡 A graphical version (GUI) is in development for people who prefer clicking over command-line.

🛡️ What gets checked

    Passwords & Accounts

    Password length and complexity

    Account lockout rules

    User rights and permissions

System & Network

    Group Policy settings

    Windows Defender and antivirus status

    Firewall rules

    Installed features, roles, and services

Compliance & Reporting

    Security baselines and benchmarks

    Privacy and regulatory indicators

    Custom baseline comparisons

📁 Reports

You’ll get several files, all timestamped and easy to read:
File	
**What it is and Why it matters**
audit-[COMPUTERNAME].txt	Full security report	Main summary + details
secpol-[OSNAME].cfg	Policy export	Backup and review
gpo-[OSNAME].html	Group Policy in HTML	Easy visual reference
auditpolicy-[OSNAME].txt	Audit policy export	Compliance / logging checks
📋 Requirements

    PowerShell 5.0 or newer (built into Windows 10/11)

    Admin rights

    Script execution allowed (Set-ExecutionPolicy RemoteSigned)

    At least 2GB RAM

    50MB free disk space

✅ Works offline — no internet required.

⚠️ Known limits

    Some policy exports need domain access

    Windows Home has fewer policy features

    Certain checks only work on newer Windows versions

⚖️ Use responsibly

This tool is for legit security checks only.

    Only run on systems you own or manage

    Get permission if scanning work machines

    Follow laws and company policies

🤝 Contribute

Ideas, bug fixes, or new checks are welcome:

    Report bugs

    Suggest features

    Improve the code or docs

    Share better usage examples

📄 License

Released under the MIT License. Free to use, modify, and share—at your own risk.
🔧 Troubleshooting

If secedit logs fail, the tool will automatically fall back and grab the data another way. No manual fixing needed.