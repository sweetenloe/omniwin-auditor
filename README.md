# OmniWin Auditor: Windows Security Audit Tool  
[![PowerShell 7+](https://img.shields.io/badge/PowerShell-7%2B-5391FE?logo=powershell&logoColor=white)](#quick-start) [![License: MIT](https://img.shields.io/badge/license-MIT-brightgreen.svg)](LICENSE)

OmniWin Auditor is a free and open-source PowerShell tool that makes it easy to check how secure your Windows PC really is according to partial CIS and DOD standards. No need to click through dozens of menus or hidden settings—just run the script and get a clear report.  

New features: quicker policy diffs and streamlined exports. 

Currently only tested on Windows 11. 

### Helpful for everyday users, IT staff, and anyone who wants to know if their system is locked down.  

---

## What it does  

- Scans your password and account lockout settings  
- Checks user rights and permissions that could be risky  
- Reviews local security policies  
- Analyzes antivirus, firewall, and group policy configs  
- Creates easy-to-read reports with all the details  

---

## Fully Supported Versions  

- Windows 11 (Home, Pro, Enterprise, Education) — tested  

## Still In Testing

- Windows 10 (Home, Pro, Enterprise, Education) — pending validation  
- Windows Server 2022 / 2025 — pending validation  
- Microsoft 365 / Office 365 setups — pending validation
- Azure AD and Hybrid AD systems — partially tested  

---

## Quick Start  

1. **Download** this repo (no install needed)  
2. **Open PowerShell as Administrator** (run `Set-ExecutionPolicy -Scope Process RemoteSigned` if needed)  
3. **Navigate** to the folder  
4. Run:  
   ```powershell
   .\omniwin-auditor.ps1
    ```
5. Optional:  
   ```powershell
   .\OmniWin-Resolve.ps1
   ```
   apply supported fixes.

# Resolve helper

- Autoloads the latest audit report and highlights high-severity items first  
- Lets you batch-select remediation commands (password policy, services, registry, etc.), then runs them with undo tracking  
- Stores undo history in `logs/resolution-history.json` and offers per-item rollback  
- Can re-run or back out changes later, keeping track of what was applied  
- Works best in the same session you ran the audit, so logs stay in sync


## Verify the safety standards of the following:

    Passwords & Accounts

    Password length and complexity

    Account lockout rules

    User rights and permissions
    
    Group Policy settings

    Windows Defender and antivirus status

    Firewall rules

    Installed features, roles, and services

    Security baselines and benchmarks

    Privacy and regulatory indicators

    Custom baseline comparisons


### Example of an audit export:

## Preview: [Sample audit report](docs/sample_audit.pdf)


📋 Requirements

    - PowerShell 7.0 or newer (you might be able to run it through PS v5, but I've seen it fail)

    - Admin rights

    - Script execution allowed (Set-ExecutionPolicy RemoteSigned)

    - At least 2GB RAM

    - 50MB free disk space

✅ Works offline — no internet required.

⚠️ Known limits

    Some policy exports need domain access

    Windows Home has fewer policy features

    Certain checks only work on newer Windows versions

If secedit logs fail, the tool will automatically fall back and grab the data. No manual fixing needed.

## Support

Need help or spot a bug? [Open an issue](https://github.com/sweetenloe/omniwin-auditor/issues).
