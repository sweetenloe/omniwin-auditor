# OmniWin Auditor: Windows Security Audit Tool  

OmniWin Auditor is a free and open-source PowerShell tool that makes it easy to check how secure your Windows PC really is according to partial CIS and DOD standards. No need to click through dozens of menus or hidden settings—just run the script and get a clear report.  

Works on Windows 10, Windows 11, and Windows Server. 

### Helpful for everyday users, IT staff, and anyone who wants to know if their system is locked down.  

---

## What it does  

- Scans your password and account lockout settings  
- Checks user rights and permissions that could be risky  
- Reviews local security policies  
- Analyzes antivirus, firewall, and group policy configs  
- Creates easy-to-read reports with all the details  

---

## Supported versions  

- Windows 10 (Home, Pro, Enterprise, Education)  
- Windows 11 (Home, Pro, Enterprise, Education)  
- Windows Server 2022 / 2025 (new edition not tested)  
- Microsoft 365 / Office 365 setups (new edition not tested)
- Azure AD and Hybrid AD systems (partially tested)  

---

## Quick Start  

1. **Download** this repo (no install needed)  
2. **Open PowerShell as Administrator**  
3. **Navigate** to the folder  
4. Run:  
   ```powershell
   .\omniwin-auditor.ps1
    ```

Pick the recommended scan and you're on your way!

## What gets checked

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
Here's what the main audit report looks like:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Windows Security Audit Report - DESKTOP-ABC123</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 15px; border-radius: 5px; }
        .section { margin: 20px 0; }
        .pass { color: green; font-weight: bold; }
        .warn { color: orange; font-weight: bold; }
        .fail { color: red; font-weight: bold; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Audit Report</h1>
        <p><strong>Computer:</strong> DESKTOP-ABC123</p>
        <p><strong>Scan Date:</strong> 2025-09-28 14:32:15</p>
        <p><strong>Windows Version:</strong> Windows 11 Pro (22H2)</p>
    </div>
    
    <div class="section">
        <h2>Password Policy</h2>
        <p>Minimum Password Length: <span class="warn">8 characters (Recommended: 12+)</span></p>
        <p>Password Complexity: <span class="pass">Enabled</span></p>
        <p>Account Lockout Threshold: <span class="fail">Disabled (Security Risk)</span></p>
    </div>
    
    <div class="section">
        <h2>Windows Defender</h2>
        <p>Real-time Protection: <span class="pass">Enabled</span></p>
        <p>Firewall Status: <span class="pass">Active</span></p>
        <p>Last Scan: <span class="pass">2025-09-28 06:00:00</span></p>
    </div>
</body>
</html>
```

📋 Requirements

    PowerShell 7.0 or newer (you might be able to run it through PS v5, but I've seen it fail)

    Admin rights

    Script execution allowed (Set-ExecutionPolicy RemoteSigned)

    At least 2GB RAM

    50MB free disk space

✅ Works offline — no internet required.

⚠️ Known limits

    Some policy exports need domain access

    Windows Home has fewer policy features

    Certain checks only work on newer Windows versions

If secedit logs fail, the tool will automatically fall back and grab the data another way. No manual fixing needed.
