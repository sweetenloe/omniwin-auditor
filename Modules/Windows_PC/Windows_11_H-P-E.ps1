#Requires -RunAsAdministrator
#Requires -Version 4.0
$ErrorActionPreference = 'silentlycontinue'

# Section

$reverveCommand = Get-Command | where { $_.name -match "Get-WSManInstance"}
if($reverveCommand -ne $null){
 $reverseCommandExist= $true
}else{
 $reverseCommandExist= $false
}





Function Reverse-SID ($nullSID) {


 $nullSID = $nullSID -creplace '^[^\\]*=', ''
 $nullSID = $nullSID.replace("*", "")
 $nullSID = $nullSID.replace(" ", "")
 if ( $nullSID -ne $null){
 $array = @()
 $array = $nullSID.Split(",") 


 ForEach ($line in $array) { 
  $sid = $null
  if ($line -like "S-*") {
   if($reverseCommandExist -eq $true){
  $sid = Get-WSManInstance -ResourceURI "wmicimv2/Win32_SID" -SelectorSet @{SID="$line"}|Select-Object AccountName
   $sid = $sid.AccountName
   }
if ( $sid -eq $null) {
  $objSID = New-Object System.Security.Principal.SecurityIdentifier ("$line")
    $objUser = $objSID.Translate( [System.Security.Principal.NTAccount])
    $sid=$objUser.Value
    if ( $sid -eq $null){
  $objUser = New-Object System.Security.Principal.NTAccount("$line") 
    $strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
    $sid=$strSID.Value
}
   $outpuReverseSid += $sid + "|"

  }else{
  $outpuReverseSid += $line + "|"
  }
 }
 
 }
 return $outpuReverseSid
}else {
$outpuReverseSid += No One 
 return $outpuReverseSid

}
}

function Get-SecEditValue {
 param(
  [Parameter(Mandatory = $true)][string]$Key,
  [string]$NotConfiguredMessage = $null
 )

 $pattern = '^{0}\s*=' -f [regex]::Escape($Key)
 $match = Get-Content -Path $seceditfile | Select-String -Pattern $pattern | Select-Object -First 1
 if ($match) { return $match.Line }
 if ($NotConfiguredMessage) { return $NotConfiguredMessage }
 return "$Key = NotConfigured"
}

function Write-AuditLine {
 param(
  [Parameter(Mandatory = $true)][string]$Id,
  [Parameter(Mandatory = $true)][string]$Description,
  [Parameter()][object]$Value
 )

 $line = "{0};{1};" -f $Id, $Description
 if ($null -ne $Value) {
  if ($Value -is [System.Array]) {
   $line += ($Value -join '')
  }
  else {
   $line += $Value
  }
 }
 Add-Content -Path $fname -Value $line
}

function StringArrayToList($StringArray) {
 if ($StringArray) {
  $Result = ""
  Foreach ($Value In $StringArray) {
   if ($Result -ne "") { $Result += "," }
   $Result += $Value
  }
  return $Result
 }
 else {
  return ""
 }
}

function Get-SecEditValue {
 param(
  [Parameter(Mandatory = $true)][string]$Key,
  [string]$NotConfiguredMessage = $null
 )

 $pattern = '^{0}\s*=' -f [regex]::Escape($Key)
 $match = Get-Content -Path $seceditfile | Select-String -Pattern $pattern | Select-Object -First 1
 if ($match) { return $match.Line }
 if ($NotConfiguredMessage) { return $NotConfiguredMessage }
 return "$Key = NotConfigured"
}

function Write-AuditLine {
 param(
  [Parameter(Mandatory = $true)][string]$Id,
  [Parameter(Mandatory = $true)][string]$Description,
  [Parameter()][object]$Value
 )

 $line = "{0};{1};" -f $Id, $Description
 if ($null -ne $Value) {
  if ($Value -is [System.Array]) {
   $line += ($Value -join '')
  }
  else {
   $line += $Value
  }
 }
 Add-Content -Path $fname -Value $line
}

$OSInfo = Get-WmiObject Win32_OperatingSystem | Select-Object Caption, Version, ServicePackMajorVersion, OSArchitecture, CSName, WindowsDirectory, NumberOfUsers, BootDevice


$OSversion = $OSInfo.Caption
$OSName = $OSInfo.CSName
$OSArchi = $OSInfo.OSArchitecture


$Date = Get-Date -U %d%m%Y

$fname = "audit" + $date + "-" + $OSName +".txt"

Write-Host "#########>Create Audit directory<#########" -ForegroundColor DarkGreen

$fldrname = "OmniWinAudit" + $OSName + "_" + $date


New-Item -ItemType Directory -Name $fldrname

Set-Location $fldrname


Write-Host "#########>Take Server Information<#########" -ForegroundColor DarkGreen
"#########INFO MACHINE#########" > $fname
"Os version: $OSversion " >> $fname
"Machine name : $OSName " >> $fname
"Machine architecture : $OSArchi" >> $fname
"#########AUDIT MACHINE#########" >> $fname
$indextest = 1
$nullVar = $null
$emptyVar = $null


Write-Host "#########>Take File to analyse<#########" -ForegroundColor DarkGreen
$seceditfile = "./secpol" + "-" + "$OSName" + ".cfg"
secedit /export /cfg $seceditfile > $null 2>&1

gpresult /r /V > $gpofile

$PCUser = (Get-WMIObject -Classname Win32_ComputerSystem).Username 
$PSUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name 

if ($PCUser -Like $PSUser) { 
  $gpofile = "./gpo" + "-" + "$OSName" + "-" + $PCUser + ".txt"
	gpresult /r /V > $gpofile
} else {
	$gpofile = "./gpo" + "-" + "$OSName" + "-" + $PCUser + ".txt"
	gpresult /r /V /user $PCUSER > $gpofile 
}

$gpofile = "./gpo" + "-" + "$OSName" + "-" + $PCUser + ".html"
if ($PCUser -Like $PSUser) { 
   
	gpresult /h $gpofile /f | out-null
} else {
	
	gpresult /h $gpofile /f /user $PCUSER | out-null 
}

$gpofile = "./gpo" + "-" + "$OSName" + ".html"
gpresult /h $gpofile /f | out-null

$auditconfigfile = "./auditpolicy" + "-" + "$OSName" + ".txt"

auditpol.exe /get /Category:* > $auditconfigfile


Write-Host "#########>Dump Windows Registry <#########" -ForegroundColor DarkGreen
$registrydumping = $(Write-Host "Registry dump for analysis? (Y/N)? **MAY CAUSE AUDIT TO CRASH**" -ForegroundColor Red ; Read-Host)

If( $registrydumping -like "Y"){

$auditRegHKLM= "./auditregistry-HKLMicrosoft" + "-" + "$OSName" + ".txt"
reg export "HKLM\SOFTWARE\Microsoft\" "$auditregHKLM"
$auditregHKLM= "./auditregistry-HKLMCUrrentControlSet" + "-" + "$OSName" + ".txt"
reg export "HKLM\SYSTEM\CurrentControlSet" "$auditregHKLM"
$auditregHKLM= "./auditregistry-HKLMPolicies" + "-" + "$OSName" + ".txt"
reg export "HKLM\SOFTWARE\Policies" "$auditregHKLM"
}




Write-Host "#########>Take local Firewall Rules Information<#########" -ForegroundColor DarkGreen
$CSVFile = "./firewall-rules-" + "$OSName" + ".csv"
$FirewallRules = Get-NetFirewallRule -PolicyStore "ActiveStore"

$FirewallRuleSet = @()
ForEach ($Rule In $FirewallRules) {
 $AdressFilter = $Rule | Get-NetFirewallAddressFilter
 $PortFilter = $Rule | Get-NetFirewallPortFilter
 $ApplicationFilter = $Rule | Get-NetFirewallApplicationFilter
 $ServiceFilter = $Rule | Get-NetFirewallServiceFilter
 $InterfaceFilter = $Rule | Get-NetFirewallInterfaceFilter
 $InterfaceTypeFilter = $Rule | Get-NetFirewallInterfaceTypeFilter
 $SecurityFilter = $Rule | Get-NetFirewallSecurityFilter

 $HashProps = [PSCustomObject]@{
  Name    = $Rule.Name
  DisplayName   = $Rule.DisplayName
  Description   = $Rule.Description
  Group    = $Rule.Group
  Enabled    = $Rule.Enabled
  Profile    = $Rule.Profile
  Platform   = StringArrayToList $Rule.Platform
  Direction   = $Rule.Direction
  Action    = $Rule.Action
  EdgeTraversalPolicy = $Rule.EdgeTraversalPolicy
  LooseSourceMapping = $Rule.LooseSourceMapping
  LocalOnlyMapping = $Rule.LocalOnlyMapping
  Owner    = $Rule.Owner
  LocalAddress  = StringArrayToList $AdressFilter.LocalAddress
  RemoteAddress  = StringArrayToList $AdressFilter.RemoteAddress
  Protocol   = $PortFilter.Protocol
  LocalPort   = StringArrayToList $PortFilter.LocalPort
  RemotePort   = StringArrayToList $PortFilter.RemotePort
  IcmpType   = StringArrayToList $PortFilter.IcmpType
  DynamicTarget  = $PortFilter.DynamicTarget
  Program    = $ApplicationFilter.Program -Replace "$($ENV:SystemRoot.Replace("\","\\"))\\", "%SystemRoot%\" -Replace "$(${ENV:ProgramFiles(x86)}.Replace("\","\\").Replace("(","\(").Replace(")","\)"))\\", "%ProgramFiles(x86)%\" -Replace "$($ENV:ProgramFiles.Replace("\","\\"))\\", "%ProgramFiles%\"
  Package    = $ApplicationFilter.Package
  Service    = $ServiceFilter.Service
  InterfaceAlias  = StringArrayToList $InterfaceFilter.InterfaceAlias
  InterfaceType  = $InterfaceTypeFilter.InterfaceType
  LocalUser   = $SecurityFilter.LocalUser
  RemoteUser   = $SecurityFilter.RemoteUser
  RemoteMachine  = $SecurityFilter.RemoteMachine
  Authentication  = $SecurityFilter.Authentication
  Encryption   = $SecurityFilter.Encryption
  OverrideBlockRules = $SecurityFilter.OverrideBlockRules
 }

 $FirewallRuleSet += $HashProps
}

$FirewallRuleSet | ConvertTo-CSV -NoTypeInformation -Delimiter ";" | Set-Content $CSVFile

Write-Host "#########>Take Antivirus Information<#########" -ForegroundColor DarkGreen

$testAntivirus = Get-WmiObject -Namespace "root\SecurityCenter" -Query "SELECT * FROM AntiVirusProduct" |Select-Object displayName, pathToSignedProductExe, pathToSignedReportingExe, timestamp




if ($null -eq $testAntivirus ) {



 $testAntivirus = Get-WmiObject -Namespace "root\SecurityCenter2" -Query "SELECT * FROM AntiVirusProduct" |Select-Object displayName, pathToSignedProductExe, pathToSignedReportingExe, timestamp

 if ( $null -eq $testAntivirus) {
  Write-Host "Antivirus software not detected , please check manualy" -ForegroundColor Red
 }
} 

$CSVFileAntivirus = "./Antivirus-" + "$OSName" + ".csv"
$testAntivirus | ConvertTo-CSV -NoTypeInformation -Delimiter ";" | Set-Content $CSVFileAntivirus






Write-Host "#########>Take Share Information<#########" -ForegroundColor DarkGreen
$fnameShare = "./SHARE " + "$OSName" + ".csv"
 
function addShare {
 param([string]$NS, [string]$CS, [string]$US, [string]$TS, [string]$NDS)
 $d = New-Object PSObject
 $d | Add-Member -Name "Share Name" -MemberType NoteProperty -Value $NS
 $d | Add-Member -Name "Share Path "-MemberType NoteProperty -Value $CS
 $d | Add-Member -Name "AccountName "-MemberType NoteProperty -Value $US
 $d | Add-Member -Name "AccessControlType"-MemberType NoteProperty -Value $TS
 $d | Add-Member -Name "AccessRight"-MemberType NoteProperty -Value $NDS
 return $d
}
$shareEntries = @()
  
$listShare = Get-SmbShare 
 
 
foreach ( $share in $listShare) {
 
 
 $sharePermissions = Get-SmbShareAccess $share.name
 
 
 foreach ( $sharePermission in $sharePermissions) {
 
 
  $shareEntries += addShare -NS $share.name -CS $share.path -US $sharePermission.AccountName -TS $sharePermission.AccessControlType -NDS $sharePermission.AccessRight
 
 
 }
}

$shareEntries | ConvertTo-CSV -NoTypeInformation -Delimiter ";" | Set-Content $fnameShare

Write-Host "#########>Take Appdata Information<#########" -ForegroundColor DarkGreen
$profileDirectory = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows' 'NT\CurrentVersion\ProfileList\).ProfilesDirectory
  
  
$profileItems = Get-ChildItem $profileDirectory 
  
$resultAPP = @()
$fnameAPP = "./APPDATA" + "$OSName" + ".csv"
  
  
foreach ( $profileItem in $profileItems) {
  
  $appDataExists = Test-Path $profileDirectory\$profileItem\Appdata
  
  if ($appDataExists -eq $true) {
  
    $appDataResults = Get-ChildItem $profileDirectory\$profileItem\Appdata -Recurse -Include *.bat, *.exe, *.ps1, *.ps1xml, *.PS2, *.PS2XML, *.psc1, *.PSC2, *.msi, *.py, *.pif, *.MSP , *.COM, *.SCR, *.hta, *.CPL, *.MSC, *.JAR, *.VB, *.VBS, *.VBE, *.JS, *.JSE, *.WS, *.wsf, *.wsc, *.wsh, *.msh, *.MSH1, *.MSH2, *.MSHXML, *.MSH1XML, *.MSH2XML, *.scf, *.REG, *.INF   | Select-Object Name, Directory, Fullname 
  
  foreach ($riskyfile in $appDataResults) {

$signature = Get-FileHash -Algorithm SHA256 $riskyfile.Fullname -ErrorAction SilentlyContinue



  $resultApptemp = [PSCustomObject]@{
                            Name  = $riskyfile.Name
                            Directory = $riskyfile.Directory
                            Path = $riskyfile.Fullname
							              Signature = $signature.Hash
                            Profil= $profileItem.name
							
                        }

$resultAPP +=$resultApptemp


  }
  }
}
 
    $resultCount = $resultAPP |Measure-Object 
    $resultCount = $resultCount.Count
  
  
  
    if ( $resultCount -gt 0) {
      $resultAPP | Export-Csv -NoTypeInformation $fnameAPP
  
      
    }
  

 
Write-Host "#########>Take Feature and Optionnal Feature Information<#########" -ForegroundColor DarkGreen

$fnameOptionnalFeature = "./OptionnalFeature-" + "$OSName" + ".csv" 

Get-WindowsOptionalFeature -Online | where-object {$_.State -eq "Enabled"} | Export-Csv -NoTypeInformation $fnameOptionnalFeature
Write-Host "#########>Take Software Information<#########" -ForegroundColor DarkGreen
$fnameInstall = "./Installed-software- " + "$OSName" + ".csv"

$installedsoftware = Get-WmiObject win32_product | Select-Object Name, Caption, Description, InstallLocation, InstallSource, InstallDate, PackageName, Version

$installedsoftware | ConvertTo-CSV -NoTypeInformation -Delimiter ";" | Set-Content $fnameInstall
Write-Host "#########>Take System Information<#########" -ForegroundColor DarkGreen
$fnameSystem = "./systeminfo- " + "$OSName" + ".txt"
systeminfo > $fnameSystem 


Write-Host "#########>Take Update Information<#########" -ForegroundColor DarkGreen
$fnameUpdate = "./systemUpdate- " + "$OSName" + ".html"
wmic qfe list brief /format:htable > $fnameUpdate


Write-Host "#########>Take Service Information<#########" -ForegroundColor DarkGreen
$fnameservice = "./Service- " + "$OSName" + ".csv"

Get-WmiObject win32_service | Select-Object Name, DisplayName, State, StartName, StartMode, PathName |Export-Csv -Delimiter ";" $fnameservice -NoTypeInformation

Write-Host "#########>Take Scheduled task Information<#########" -ForegroundColor DarkGreen
$scheduledTaskFile = "./Scheduled-task- " + "$OSName" + ".csv"
$taskList = Get-ScheduledTask |Select-Object -Property *
$resultTask= @()
foreach ($task in $taskList) {
$taskactions = Get-ScheduledTask $task.Taskname |Select-Object -ExpandProperty Actions

 foreach ( $taskaction in $taskactions ) {


$resultTasktemp = [PSCustomObject]@{
                            Task_name = $task.Taskname
                            Task_URI = $task.URI
                            Task_state = $task.State
                            Task_Author = $task.Author
							Task_Description = $task.Description
                            Task_action = $taskaction.Execute 
                            Task_action_Argument = $taskaction.Arguments
                            Task_Action_WorkingDirectory = $taskaction.WorkingDirectory
							
                        }

$resultTask += $resultTasktemp

 }
  }
  



$resultTask | Export-Csv -NoTypeInformation $scheduledTaskFile

Write-Host "#########>Take Accounts Policy Information<#########" -ForegroundColor DarkGreen
$fnameNetAccount = "./AccountsPolicy- " + "$OSName" + ".txt"
net accounts > $fnameNetAccount

Write-Host "#########>Take Port listening Information<#########" -ForegroundColor DarkGreen
$fnamePort = "./Listen-port- " + "$OSName" + ".csv"
$listport = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, State, OwningProcess
Write-Host "LocalAddress;LocalPort;State;OwningProcess;Path" > $fnamePort

foreach ($port in $listport) {
 $exepath = Get-Process -PID $port.OwningProcess |Select-Object Path
 $port.LocalAddress + ";" + $port.LocalPort + ";" + $port.State + ";" + $exepath.path >> $fnamePort
}


$listlocaluser = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True'"

foreach ( $user in $listlocaluser) {


 if ( $user.sid -like "*-500") {

  $adminAccountName = $user.Name

  $adminAccountDisabled = $user.Disabled
  if ($adminAccountDisabled -eq $true) {
   $adminStatus = "disabled"
  }
  else {
   $adminStatus = "enabled"
  }
 }
 elseif ( $user.sid -like "*-501") {
  $guestAccountName = $user.Name
  $guestAccountDisabled = $user.Disabled
  if ($guestAccountDisabled -eq $true) {
   $guestStatus = "disabled"
  }
  else {
   $guestStatus = "enabled"
  }

 }

}

$listlocaluser > "localuser-$OSName.txt"

Write-Host "#########>Take Startup Registry Information<#########" -ForegroundColor DarkGreen

"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" >> $fnameStartup

$fnameStartup = "./Startup- " + "$OSName" + "HKCU-RUN" + ".csv"
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" |Select-Object * -exclude PSPath,PSParentPath, PSChildName, PSProvider, PSDrive | Export-Csv -NoTypeInformation $fnameStartup
$fnameStartup = "./Startup- " + "$OSName" + "HKCU-RUNONCE" + ".csv"
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" |Select-Object * -exclude PSPath,PSParentPath, PSChildName, PSProvider, PSDrive | Export-Csv -NoTypeInformation $fnameStartup
$fnameStartup = "./Startup- " + "$OSName" + "HKCU-Windows" + ".csv"
Get-ItemProperty "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows" |Select-Object * -exclude PSPath,PSParentPath, PSChildName, PSProvider, PSDrive | Export-Csv -NoTypeInformation $fnameStartup
$fnameStartup = "./Startup- " + "$OSName" + "HKLM-RUN" + ".csv"
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" |Select-Object * -exclude PSPath,PSParentPath, PSChildName, PSProvider, PSDrive | Export-Csv -NoTypeInformation $fnameStartup
$fnameStartup = "./Startup- " + "$OSName" + "HKLM-RUN" + ".csv"
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" |Select-Object * -exclude PSPath,PSParentPath, PSChildName, PSProvider, PSDrive | Export-Csv -NoTypeInformation $fnameStartup




Write-Host "#########>Begin CIS audit<#########" -ForegroundColor Green
Write-Host "#########>Begin password policy audit<#########" -ForegroundColor DarkGreen


$id = "PP-" + "1.1.1"
Write-AuditLine -Id $id -Description "(L1)Ensure 'Enforce password history' is set to '24 or more password(s), value must be 24 or More" -Value (Get-SecEditValue "PasswordHistorySize")



$id = "PP-" + "1.1.2"
Write-AuditLine -Id $id -Description "(L1)Maximum password age is set to 365 or fewer days, value must be 365 or less but not 0" -Value (Get-SecEditValue "MaximumPasswordAge")



$id = "PP-" + "1.1.3"
Write-AuditLine -Id $id -Description "(L1)Minimum password age is set to 1 or more day(s), value must be 1 or more but not 0" -Value (Get-SecEditValue "MinimumPasswordAge")



$id = "PP-" + "1.1.4"
Write-AuditLine -Id $id -Description "(L1)Minimum password length is set to 14 or more character(s), value must be 14 or more" -Value (Get-SecEditValue "MinimumPasswordLength")




$id = "PP-" + "1.1.5"
Write-AuditLine -Id $id -Description "(L1)Password must meet complexity requirements is set to Enabled, value must be 1" -Value (Get-SecEditValue "PasswordComplexity")




$id = "PP-" + "1.1.6"
$policyValue = "no configuration"
if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SAM") {
 $policyValue = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SAM" -ErrorAction SilentlyContinue).RelaxMinimumPasswordLengthLimits
 if ($policyValue -eq $null) {
  $policyValue = "no configuration"
 }
}
Write-AuditLine -Id $id -Description "(L1)Relax minimum password length limits' is set to Enabled, value must be 1 (Warning this may cause compatibility issues)" -Value $policyValue


$indextest += 1

$id = "PP-" + "1.1.7"
Write-AuditLine -Id $id -Description "(L1)Store passwords using reversible encryption is set to Disabled, value must be 0" -Value (Get-SecEditValue "ClearTextPassword")


Write-Host "#########>Begin account lockout policy audit<#########" -ForegroundColor DarkGreen


$id = "ALP-" + "1.2.1"

Write-AuditLine -Id $id -Description "(L1)Account lockout duration is set to 15 or more minute(s)" -Value (Get-SecEditValue "LockoutDuration")




$id = "ALP-" + "1.2.2"

Write-AuditLine -Id $id -Description "(L1)Ensure Account lockout threshold is set to 5 or fewer invalid logon attempt(s), but not 0" -Value (Get-SecEditValue "LockoutBadCount")




$id = "ALP-" + "1.2.3"

Write-AuditLine -Id $id -Description "(L1)Allow Administrator account lockout is set to Enabled, value must be 1" -Value (Get-SecEditValue "AllowAdministratorLockout")



$id = "ALP-" + "1.2.4"
Write-AuditLine -Id $id -Description "(L1)Reset account lockout counter after is set to 15 or more minute(s)" -Value (Get-SecEditValue "ResetLockoutCount")


Write-Host "#########>Begin user rights assignment audit<#########" -ForegroundColor DarkGreen


$id = "URA-" + "2.2.1"
$outputLine = "$id" + ";" + "(L1)Acess Credential Manager as a trusted caller is set to No One , value must be empty" + ";"
$policyValue = Get-Content $seceditfile |Select-String "SeTrustedCredManAccessPrivilege"

$outputLine += $policyValue
$outputLine>> $fname



$id = "URA-" + "2.2.2"
$outputLine = "$id" + ";" + "(L1)Access this computer from the network, Only Administrators, Remote Desktop Users " + ";"
$sidLine = Get-Content $seceditfile |Select-String "SeNetworkLogonRight" 
$sidLine = $sidLine.line
$policyValue = "SeNetworkLogonRight" + ":"
$policyValue += Reverse-SID $sidLine

$outputLine += $policyValue
$outputLine>> $fname




$id = "URA-" + "2.2.3"
$outputLine = "$id" + ";" + "(L1)Act as part of the operating system' , Must be empty " + ";"
$test = Get-Content $seceditfile |Select-String "SeTcbPrivilege"
$sidLine = $sidLine.line
$policyValue = "SeTcbPrivilege" + ":"

$policyValue += Reverse-SID $test

$outputLine += $policyValue
$outputLine>> $fname



$id = "URA-" + "2.2.4"
$outputLine = "$id" + ";" + "(L1)Adjust memory quotas for a process , Administrators, LOCAL SERVICE, NETWORK SERVICE " + ";"
$sidLine = Get-Content $seceditfile |Select-String "SeIncreaseQuotaPrivilege" 
$sidLine = $sidLine.line
$policyValue = "SeIncreaseQuotaPrivilege" + ":"
$policyValue += Reverse-SID $sidLine

$outputLine += $policyValue
$outputLine>> $fname




$id = "URA-" + "2.2.5"

$outputLine = "$id" + ";" + "(L1)Allow log on locally, Administrators, Users" + ";"
$sidLine = Get-Content $seceditfile |Select-String "SeInteractiveLogonRight" 
$sidLine = $sidLine.line
$policyValue = "SeInteractiveLogonRight" + ":"
$policyValue += Reverse-SID $sidLine

$outputLine += $policyValue
$outputLine>> $fname





$id = "URA-" + "2.2.6"
$outputLine = "$id" + ";" + "(L1)Allow log on through Remote Desktop Services, Only Administrators, Remote Desktop Users. If Remote Apps or CItrix authentificated users" + ";"
$sidLine = Get-Content $seceditfile |Select-String "SeRemoteInteractiveLogonRight" 
$sidLine = $sidLine.line
$policyValue = "SeRemoteInteractiveLogonRight" + ":"
$policyValue += Reverse-SID $sidLine

$outputLine += $policyValue
$outputLine>> $fname



$id = "URA-" + "2.2.7"
$outputLine = "$id" + ";" + "(L1)Ensure Back up files and directories, Only Administrators," + ";"
$sidLine = Get-Content $seceditfile |Select-String "SeBackupPrivilege" 
$sidLine = $sidLine.line
$policyValue = "SeBackupPrivilege" + ":"
$policyValue += Reverse-SID $sidLine

$outputLine += $policyValue
$outputLine>> $fname




$id = "URA-" + "2.2.8"
$outputLine = "$id" + ";" + "(L1)Change the system time, Only Administrators and local service" + ";"
$sidLine = Get-Content $seceditfile |Select-String "SeSystemtimePrivilege" 
$sidLine = $sidLine.line
$policyValue = "SeSystemtimePrivilege" + ":"
$policyValue += Reverse-SID $sidLine

$outputLine += $policyValue
$outputLine>> $fname



$id = "URA-" + "2.2.9"
$outputLine = "$id" + ";" + "(L1)Change the time zone', Only Administrators ,local service and users" + ";"
$sidLine = Get-Content $seceditfile |Select-String "SeTimeZonePrivilege" 
$sidLine = $sidLine.line
$policyValue = "SeTimeZonePrivilege" + ":"
$policyValue += Reverse-SID $sidLine

$outputLine += $policyValue
$outputLine>> $fname




$id = "URA-" + "2.2.10"
$outputLine = "$id" + ";" + "(L1)Create a pagefile, Only Administrators " + ";"
$sidLine = Get-Content $seceditfile |Select-String "SeCreatePagefilePrivilege" 
$sidLine = $sidLine.line
$policyValue = "SeCreatePagefilePrivilege" + ":"
$policyValue += Reverse-SID $sidLine

$outputLine += $policyValue
$outputLine>> $fname





$id = "URA-" + "2.2.11"
$outputLine = "$id" + ";" + "(L1)Create a token object, No one " + ";"
$sidLine = Get-Content $seceditfile |Select-String "SeCreateTokenPrivilege" 
$sidLine = $sidLine.line
$policyValue = "SeCreateTokenPrivilege" + ":"
$policyValue += Reverse-SID $sidLine

$outputLine += $policyValue
$outputLine>> $fname




$id = "URA-" + "2.2.12"
$outputLine = "$id" + ";" + "(L1)Ensure Create global objects is set to Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE" + ";"
$sidLine = Get-Content $seceditfile |Select-String "SeCreateGlobalPrivilege" 
$sidLine = $sidLine.line
$policyValue = "SeCreateGlobalPrivilege" + ":"
$policyValue += Reverse-SID $sidLine

$outputLine += $policyValue
$outputLine>> $fname



$id = "URA" + "2.2.13"
$outputLine = "$id" + ";" + "(L1)Ensure Create permanent shared objects, No one,value must empty" + ";"
$sidLine = Get-Content $seceditfile |Select-String "SeCreatePermanentPrivilege" 
$sidLine = $sidLine.line
$policyValue = "SeCreatePermanentPrivilege" + ":"
$policyValue += Reverse-SID $sidLine

$outputLine += $policyValue
$outputLine>> $fname


$id = "URA" + "2.2.14"
$id = "URA" + "$indextest"
$outputLine = "$id" + ";" + "(L1)Create symbolic links, Administrator and for Hyper V NT VIRTUAL MACHINE\Virtual Machines. " + ";"
$sidLine = Get-Content $seceditfile |Select-String "SeCreateSymbolicLinkPrivilege" 
$sidLine = $sidLine.line
$policyValue = "SeCreateSymbolicLinkPrivilege" + ":"
$policyValue += Reverse-SID $sidLine

$outputLine += $policyValue
$outputLine>> $fname

$id = "URA" + "2.2.15"
$id = "URA" + "$indextest"
$outputLine = "$id" + ";" + "(L1)Ensure Debug programs is set to Administrators or no one" + ";"
$sidLine = Get-Content $seceditfile |Select-String "SeDebugPrivilege" 
$sidLine = $sidLine.line
$policyValue = "SeDebugPrivilege" + ":"
$policyValue += Reverse-SID $sidLine

$outputLine += $policyValue
$outputLine>> $fname



$id = "URA" + "2.2.16"
$outputLine = "$id" + ";" + "(L1)Deny access to this computer from the network,Guest Local Account and member of Domain admin " + ";"
$sidLine = Get-Content $seceditfile |Select-String "SeDenyNetworkLogonRight" 
$sidLine = $sidLine.line
$policyValue = "SeDenyNetworkLogonRight" + ":"
$policyValue += Reverse-SID $sidLine

$outputLine += $policyValue
$outputLine>> $fname


$id = "URA" + "2.2.17"
$outputLine = "$id" + ";" + "(L1)Deny log on as a batch job, Guest " + ";"
$sidLine = Get-Content $seceditfile |Select-String "SeDenyBatchLogonRight" 
$sidLine = $sidLine.line
$policyValue = "SeDenyBatchLogonRight" + ":"
$policyValue += Reverse-SID $sidLine

$outputLine += $policyValue
$outputLine>> $fname


$id = "URA" + "2.2.18"
$outputLine = "$id" + ";" + "(L1)Deny log on as a service, Guest " + ";"
$sidLine = Get-Content $seceditfile |Select-String "SeDenyServiceLogonRight" 
$sidLine = $sidLine.line
$policyValue = "SeDenyServiceLogonRight" + ":"
$policyValue += Reverse-SID $sidLine

$outputLine += $policyValue
$outputLine>> $fname

$id = "URA" + "2.2.19"
$outputLine = "$id" + ";" + "(L1)Deny log on locally, Guest and member of Domain admin " + ";"
$sidLine = Get-Content $seceditfile |Select-String "SeDenyInteractiveLogonRight" 
$sidLine = $sidLine.line
$policyValue = "SeDenyInteractiveLogonRight" + ":"
$policyValue += Reverse-SID $sidLine

$outputLine += $policyValue
$outputLine>> $fname


$id = "URA" + "2.2.20"
$outputLine = "$id" + ";" + "(L1)Deny log on through Remote Desktop Services, Guest, Local account and member of Domain admin' " + ";"
$sidLine = Get-Content $seceditfile |Select-String "SeDenyRemoteInteractiveLogonRight" 
$sidLine = $sidLine.line
$policyValue = "SeDenyRemoteInteractiveLogonRight" + ":"
$policyValue += Reverse-SID $sidLine

$outputLine += $policyValue
$outputLine>> $fname


$id = "URA" + "2.2.21"
$outputLine = "$id" + ";" + "(L1)Enable computer and user accounts to be trusted for delegation,No one " + ";"
$sidLine = Get-Content $seceditfile |Select-String "SeEnableDelegationPrivilege" 
$sidLine = $sidLine.line
$policyValue = "SeEnableDelegationPrivilege" + ":"
$policyValue += Reverse-SID $sidLine

$outputLine += $policyValue
$outputLine>> $fname

$id = "URA" + "2.2.22"
$outputLine = "$id" + ";" + "(L1)Force shutdown from a remote system, Only administrators " + ";"
$sidLine = Get-Content $seceditfile |Select-String "SeRemoteShutdownPrivilege" 
$sidLine = $sidLine.line
$policyValue = "SeRemoteShutdownPrivilege" + ":"
$policyValue += Reverse-SID $sidLine

$outputLine += $policyValue
$outputLine>> $fname


$id = "URA" + "2.2.23"
$outputLine = "$id" + ";" + "(L1)Generate security audits is set to LOCAL SERVICE, NETWORK SERVICE " + ";"
$sidLine = Get-Content $seceditfile |Select-String "SeAuditPrivilege" 
$sidLine = $sidLine.line
$policyValue = "SeAuditPrivilege" + ":"
$policyValue += Reverse-SID $sidLine

$outputLine += $policyValue
$outputLine>> $fname



$id = "URA" + "2.2.24"
$outputLine = "$id" + ";" + "(L1)Impersonate a client after authentication , Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE " + ";"
$sidLine = Get-Content $seceditfile |Select-String "SeImpersonatePrivilege" 
$sidLine = $sidLine.line
$policyValue = "SeImpersonatePrivilege" + ":"
$policyValue += Reverse-SID $sidLine

$outputLine += $policyValue
$outputLine>> $fname


$id = "URA" + "2.2.25"
$outputLine = "$id" + ";" + "(L1)Increase scheduling priority , only Administrator and Window Manager\Window Manager Group" + ";"
$sidLine = Get-Content $seceditfile |Select-String "SeIncreaseBasePriorityPrivilege" 
$sidLine = $sidLine.line
$policyValue = "SeIncreaseBasePriorityPrivilege" + ":"
$policyValue += Reverse-SID $sidLine

$outputLine += $policyValue
$outputLine>> $fname


$id = "URA" + "2.2.26"
$outputLine = "$id" + ";" + "(L1)Load and unload device drivers' , only Administrator" + ";"
$sidLine = Get-Content $seceditfile |Select-String "SeLoadDriverPrivilege" 
$sidLine = $sidLine.line
$policyValue = "SeLoadDriverPrivilege" + ":"
$policyValue += Reverse-SID $sidLine

$outputLine += $policyValue
$outputLine>> $fname


$id = "URA" + "2.2.27"
$outputLine = "$id" + ";" + "(L1)Lock pages in memory, No one" + ";"
$sidLine = Get-Content $seceditfile |Select-String "SeLockMemoryPrivilege" 
$sidLine = $sidLine.line
$policyValue = "SeLockMemoryPrivilege" + ":"
$policyValue += Reverse-SID $sidLine

$outputLine += $policyValue
$outputLine>> $fname




$id = "URA" + "2.2.28"
$outputLine = "$id" + ";" + "(L2)Log on as a batch job',Administrators and very specific account" + ";"
$sidLine = Get-Content $seceditfile |Select-String "SeBatchLogonRight" 
$sidLine = $sidLine.line
$policyValue = "SeBatchLogonRight" + ":"
$policyValue += Reverse-SID $sidLine

$outputLine += $policyValue
$outputLine>> $fname


$id = "URA" + "2.2.29"
$outputLine = "$id" + ";" + "(L2)Ensure Log on as a service is set to No One and NT VIRTUAL MACHINE\Virtual Machine( When HyperV is installed)" + ";"
$sidLine = Get-Content $seceditfile |Select-String "SeServiceLogonRight" 
$sidLine = $sidLine.line
$policyValue = "SeServiceLogonRight" + ":"
$policyValue += Reverse-SID $sidLine

$outputLine += $policyValue
$outputLine>> $fname



$id = "URA" + "2.2.30"
$outputLine = "$id" + ";" + "(L1)Manage auditing and security log,Administrators" + ";"
$sidLine = Get-Content $seceditfile |Select-String "SeSecurityPrivilege" 
$sidLine = $sidLine.line
$policyValue = "SeSecurityPrivilege" + ":"
$policyValue += Reverse-SID $sidLine

$outputLine += $policyValue
$outputLine>> $fname


$id = "URA" + "2.2.31"
$outputLine = "$id" + ";" + "(L1)Modify an object label, No one" + ";"
$sidLine = Get-Content $seceditfile |Select-String "SeRelabelPrivilege" 
$sidLine = $sidLine.line
$policyValue = "SeRelabelPrivilege" + ":"
$policyValue += Reverse-SID $sidLine

$outputLine += $policyValue
$outputLine>> $fname


$id = "URA" + "2.2.32"
$outputLine = "$id" + ";" + "(L1)Modify firmware environment values is set to Administrators" + ";"
$sidLine = Get-Content $seceditfile |Select-String "SeSystemEnvironmentPrivilege" 
$sidLine = $sidLine.line
$policyValue = "SeSystemEnvironmentPrivilege" + ":"
$policyValue += Reverse-SID $sidLine

$outputLine += $policyValue
$outputLine>> $fname


$id = "URA" + "2.2.33"
$outputLine = "$id" + ";" + "(L1)Perform volume maintenance tasks is set to Administrators" + ";"
$sidLine = Get-Content $seceditfile |Select-String "SeManageVolumePrivilege" 
$sidLine = $sidLine.line
$policyValue = "SeManageVolumePrivilege" + ":"
$policyValue += Reverse-SID $sidLine

$outputLine += $policyValue
$outputLine>> $fname



$id = "URA" + "2.2.34"
$outputLine = "$id" + ";" + "(L1)Profile single process is set to Administrators" + ";"
$sidLine = Get-Content $seceditfile |Select-String "SeProfileSingleProcessPrivilege" 
$sidLine = $sidLine.line
$policyValue = "SeProfileSingleProcessPrivilege" + ":"
$policyValue += Reverse-SID $sidLine

$outputLine += $policyValue
$outputLine>> $fname


$id = "URA" + "2.2.35"
$outputLine = "$id" + ";" + "(L1)Profile system performance is set to Administrators, NT SERVICE\WdiServiceHost" + ";"
$sidLine = Get-Content $seceditfile |Select-String "SeSystemProfilePrivilege" 
$sidLine = $sidLine.line
$policyValue = "SeSystemProfilePrivilege" + ":"
$policyValue += Reverse-SID $sidLine

$outputLine += $policyValue
$outputLine>> $fname


$id = "URA" + "2.2.36"
$outputLine = "$id" + ";" + "(L1)Replace a process level token is set to LOCAL SERVICE, NETWORK SERVICE and for IIS server you may have IIS applications pools" + ";"
$sidLine = Get-Content $seceditfile |Select-String "SeAssignPrimaryTokenPrivilege" 
$sidLine = $sidLine.line
$policyValue = "SeAssignPrimaryTokenPrivilege" + ":"
$policyValue += Reverse-SID $sidLine

$outputLine += $policyValue
$outputLine>> $fname




$id = "URA" + "2.2.37"
$outputLine = "$id" + ";" + "(L1)Restore files and directories is set to Administrators" + ";"
$sidLine = Get-Content $seceditfile |Select-String "SeRestorePrivilege" 
$sidLine = $sidLine.line
$policyValue = "SeRestorePrivilege" + ":"
$policyValue += Reverse-SID $sidLine

$outputLine += $policyValue
$outputLine>> $fname


$id = "URA" + "2.2.38"
$outputLine = "$id" + ";" + "(L1)Shut down the system is set to Administrators, Users" + ";"
$sidLine = Get-Content $seceditfile |Select-String "SeShutdownPrivilege" 
$sidLine = $sidLine.line
$policyValue = "SeShutdownPrivilege" + ":"
$policyValue += Reverse-SID $sidLine

$outputLine += $policyValue
$outputLine>> $fname


$id = "URA" + "2.2.39"
$outputLine = "$id" + ";" + "(L1)Take ownership of files or other objects is set to Administrators" + ";"
$sidLine = Get-Content $seceditfile |Select-String "SeTakeOwnershipPrivilege" 
$sidLine = $sidLine.line
$policyValue = "SeTakeOwnershipPrivilege" + ":"
$policyValue += Reverse-SID $sidLine

$outputLine += $policyValue
$outputLine>> $fname


Write-Host "#########>Begin Accounts audit<#########" -ForegroundColor DarkGreen

$id = "AA" + "2.3.1.1"
$outputLine = "$id" + ";" + "(L1)Accounts: Block Microsoft accounts is set to Users cannot add or log on with Microsoft accounts Value must be 3 " + ";"
$exist = Test-Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System | Select-Object NoConnectedUser
 $policyValue = $policyValue.NoConnectedUser
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "AA" + "2.3.1.2"
$outputLine = "$id" + ";" + "(L1)Ensure Accounts: Guest account status is set to 'Disabled" + ";"
$policyValue = "Default guest Account:" + $guestAccountName + ",status : $guestStatus"



$outputLine += $policyValue
$outputLine>> $fname



$id = "AA" + "2.3.1.3"
$outputLine = "$id" + ";" + "(L1)Accounts: Limit local account use of blank passwords to console logon only is set to Enabled, Value must be 1 " + ";"
$exist = Test-Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa |Select-Object LimitBlankPasswordUse
 $policyValue = $policyValue.LimitBlankPasswordUse
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "AA" + "2.3.1.4"
$outputLine = "$id" + ";" + "(L1)Accounts: Rename administrator account" + ";"
$policyValue = "Default local admin Account:" + $adminAccountName 


$outputLine += $policyValue
$outputLine>> $fname





$id = "AA" + "2.3.1.5"
$outputLine = "$id" + ";" + "(L1)Accounts: Rename guest account" + ";"
$policyValue = "Default guest Account:" + $guestAccountName

$outputLine += $policyValue
$outputLine>> $fname

Write-Host "#########>Begin audit policy audit<#########" -ForegroundColor DarkGreen



$id = "APA" + "2.3.2.1"
$outputLine = "$id" + ";" + "(L1)Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings is set to Enabled, Value must be 1 " + ";"
$exist = Test-Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa |Select-Object SCENoApplyLegacyAuditPolicy
 $policyValue = $policyValue.SCENoApplyLegacyAuditPolicy
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname



$id = "APA" + "2.3.2.2"
$outputLine = "$id" + ";" + "(L1)Audit: Shut down system immediately if unable to log security audits is set to Disabled, Value must be 0 " + ";"
$exist = Test-Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa |Select-Object CrashOnAuditFail
 $policyValue = $policyValue.CrashOnAuditFail
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname


Write-Host "#########>Begin devices policy audit<#########" -ForegroundColor DarkGreen


$id = "DEVP" + "2.3.4.1"
$outputLine = "$id" + ";" + "(L1)Ensure Devices: Allowed to format and eject removable media is set to Administrators and Interactive Users' " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" |Select-Object AllocateDASD
 $policyValue = $policyValue.AllocateDASD
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname



$id = "DEVP" + "2.3.4.1"
$outputLine = "$id" + ";" + "(L2)Devices: Prevent users from installing printer drivers is set to Enabled, Value must be 1 " + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" |Select-Object AddPrinterDrivers
 $policyValue = $policyValue.AddPrinterDrivers
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname



Write-Host "#########>Begin Domain member policy audit<#########" -ForegroundColor DarkGreen


$id = "DMP" + "2.3.6.1"
$outputLine = "$id" + ";" + "(L1)Domain member: Digitally encrypt or sign secure channel data (always) is set to Enabled, Value must be 1 " + ";"
$exist = Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters |Select-Object RequireSignOrSeal
 $policyValue = $policyValue.RequireSignOrSeal
}
else {
 $policyValue = "no configuration"
}


$id = "DMP" + "2.3.6.2"
$outputLine = "$id" + ";" + "(L1)Domain member: Digitally encrypt secure channel data (when possible) is set to Enabled, Value must be 1 " + ";"
$exist = Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters |Select-Object SealSecureChannel
 $policyValue = $policyValue.SealSecureChannel
}
else {
 $policyValue = "no configuration"
}


$outputLine += $policyValue
$outputLine>> $fname

$id = "DMP" + "2.3.6.3"
$outputLine = "$id" + ";" + "(L1)Domain member: Domain member: Digitally sign secure channel data (when possible) is set to Enabled, Value must be 1 " + ";"
$exist = Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters |Select-Object SignSecureChannel
 $policyValue = $policyValue.SealSecureChannel
}
else {
 $policyValue = "no configuration"
}


$outputLine += $policyValue
$outputLine>> $fname



$id = "DMP" + "2.3.6.4"
$outputLine = "$id" + ";" + "(L1)Domain member: Disable machine account password changes is set to Disabled, Value must be 0 " + ";"
$exist = Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters
if ( $exist -eq $true) {
				$policyValue = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters |Select-Object DisablePasswordChange
 $policyValue = $policyValue.DisablePasswordChange
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname

$id = "DMP" + "2.3.6.5"
$outputLine = "$id" + ";" + "(L1)Domain member: Maximum machine account password age is set to 30 or fewer days, but not 0 " + ";"
$exist = Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters
if ( $exist -eq $true) {
				$policyValue = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters |Select-Object MaximumPasswordAge
 $policyValue = $policyValue.MaximumPasswordAge
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname



$id = "DMP" + "2.3.6.6"
$outputLine = "$id" + ";" + "(L1)Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled,value must 1 " + ";"
$exist = Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters |Select-Object RequireStrongKey
 $policyValue = $policyValue.RequireStrongKey
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname


Write-Host "#########>Begin Interactive logon audit<#########" -ForegroundColor DarkGreen


$id = "IL" + "2.3.7.1"
$outputLine = "$id" + ";" + "(L1)Ensure Interactive logon: Do not require CTRL+ALT+DEL' is set to Disabled,value must 0 " + ";"
$exist = Test-Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System |Select-Object DisableCAD
 $policyValue = $policyValue.DisableCAD
}
else {
 $policyValue = "no configuration"
}


$outputLine += $policyValue
$outputLine>> $fname






$id = "IL" + "2.3.7.2"
$outputLine = "$id" + ";" + "(L1)Ensure Interactive logon: Do not display last user name is set to Enabled,value must 1 " + ";"
$exist = Test-Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System |Select-Object DontDisplayLastUserName
 $policyValue = $policyValue.DontDisplayLastUserName
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname







$id = "IL" + "2.3.7.3"
$outputLine = "$id" + ";" + "(L1)Ensure Interactive logon: Machine account lockout threshold' is set to '10 or fewer invalid logon attempts, but not 0',value must 0 " + ";"
$exist = Test-Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System |Select-Object MaxDevicePasswordFailedAttempts
 $policyValue = $policyValue.MaxDevicePasswordFailedAttempts
}
else {
 $policyValue = "no configuration"
}


$outputLine += $policyValue
$outputLine>> $fname





$id = "IL" + "2.3.7.4"
$outputLine = "$id" + ";" + "(L1)Ensure Interactive logon: Machine inactivity limit' is set to 900 or fewer second(s), but not 0 " + ";"
$exist = Test-Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System |Select-Object InactivityTimeoutSecs
 $policyValue = $policyValue.InactivityTimeoutSecs
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname





$id = "IL" + "2.3.7.5"
$outputLine = "$id" + ";" + "(L1)Configure 'Interactive logon: Message text for users attempting to log on, but not empty " + ";"
$exist = Test-Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System |Select-Object LegalNoticeText
 $policyValue = $policyValue.LegalNoticeText
}
else {
 $policyValue = "no configuration"
}




$id = "IL" + "2.3.7.6"
$outputLine = "$id" + ";" + "(L1)Configure Interactive logon: Message title for users attempting to log on, but not empty " + ";"
$exist = Test-Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System |Select-Object LegalNoticeCaption
 $policyValue = $policyValue.LegalNoticeCaption
}
else {
 $policyValue = "no configuration"
}




$id = "IL" + "2.3.7.7"
$outputLine = "$id" + ";" + "(L2)Ensure interactive logon: Number of previous logons to cache (in case domain controller is not available) is set to 4 or fewer logon(s) " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" |Select-Object CachedLogonsCount
 $policyValue = $policyValue.CachedLogonsCount
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "IL" + "2.3.7.8"
$outputLine = "$id" + ";" + "(L1)Ensure Interactive logon: Prompt user to change password before expiration is set to between 5 and 14 days " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" |Select-Object PasswordExpiryWarning
 $policyValue = $policyValue.PasswordExpiryWarning
}
else {
 $policyValue = "no configuration"
}


$outputLine += $policyValue
$outputLine>> $fname





$id = "IL" + "2.3.7.9"
$outputLine = "$id" + ";" + "(L1)Ensure Interactive logon: Smart card removal behavior is set to Lock Workstation or higher,value must be 1 (Lock Workstation) or 2 (Force Logoff) " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" |Select-Object ScRemoveOption
 $policyValue = $policyValue.ScRemoveOption
}
else {
 $policyValue = "no configuration"
}


$outputLine += $policyValue
$outputLine>> $fname



Write-Host "#########>Begin Microsoft network client audit<#########" -ForegroundColor DarkGreen



$id = "MNC" + "2.3.8.1"
$outputLine = "$id" + ";" + "(L1)Ensure Microsoft network client: Digitally sign communications (always) is set to Enabled,value must be 1 " + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" |Select-Object RequireSecuritySignature
 $policyValue = $policyValue.RequireSecuritySignature
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname





$id = "MNC" + "2.3.8.2"
$outputLine = "$id" + ";" + "(L1)Ensure Microsoft network client: Digitally sign communications (if server agrees) is set to Enabled,value must be 1 " + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" |Select-Object EnableSecuritySignature
 $policyValue = $policyValue.EnableSecuritySignature
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "MNC" + "2.3.8.3"
$outputLine = "$id" + ";" + "(L1)Ensure Microsoft network client: Send unencrypted password to third-party SMB servers is set to Disabled,value must be 0 " + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" |Select-Object EnablePlainTextPassword
 $policyValue = $policyValue.EnablePlainTextPassword
}
else {
 $policyValue = "no configuration"
}


$outputLine += $policyValue
$outputLine>> $fname


Write-Host "#########>Begin Microsoft network server audit<#########" -ForegroundColor DarkGreen

$id = "MNS" + "2.3.9.1"
$outputLine = "$id" + ";" + "(L1)Microsoft network server: Amount of idle time required before suspending session is set to 15 or fewer minute(s) but not 0, " + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" |Select-Object AutoDisconnect
 $policyValue = $policyValue.AutoDisconnect
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname


$id = "MNS" + "2.3.9.2"
$outputLine = "$id" + ";" + "(L1)Ensure Microsoft network server: Digitally sign communications (always) is set to Enabled,must be 1 " + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" |Select-Object RequireSecuritySignature
 $policyValue = $policyValue.RequireSecuritySignature
}
else {
 $policyValue = "no configuration"
}




$id = "MNS" + "2.3.9.3"
$outputLine = "$id" + ";" + "(L1)Ensure Microsoft network server: Digitally sign communications (if client agrees) is set to Enabled,must be 1 " + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" |Select-Object EnableSecuritySignature
 $policyValue = $policyValue.EnableSecuritySignature
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname




$id = "MNS" + "2.3.9.4"
$outputLine = "$id" + ";" + "(L1)Ensure Microsoft network server: Disconnect clients when logon hours expire is set to Enabled,must be 1 " + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" |Select-Object EnableForcedLogoff
 $policyValue = $policyValue.EnableForcedLogoff
}
else {
 $policyValue = "no configuration"
}


$outputLine += $policyValue
$outputLine>> $fname





$id = "MNS" + "2.3.9.5"
$outputLine = "$id" + ";" + "(L1)Microsoft network server: Server SPN target name validation level is set to Accept if provided by client or higher,must be 1 or highter " + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" |Select-Object SMBServerNameHardeningLevel
 $policyValue = $policyValue.SMBServerNameHardeningLevel
}
else {
 $policyValue = "no configuration"
}




Write-Host "#########>Begin Network access audit<#########" -ForegroundColor DarkGreen


$id = "NA" + "2.3.10.1"
$outputLine = "$id" + ";" + "(L1)Ensure Network access: Allow anonymous SID/Name translation is set to Disabled,must be 0 " + ";"
$exist = Test-Path HKLM:\System\CurrentControlSet\Control\Lsa
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa |Select-Object AnonymousNameLookup
 $policyValue = $policyValue.AnonymousNameLookup
}
else {
 $policyValue = "no configuration"
}


$outputLine += $policyValue
$outputLine>> $fname



$id = "NA" + "2.3.10.2"
$outputLine = "$id" + ";" + "(L1)Ensure Network access: Do not allow anonymous enumeration of SAM accounts is set to Enabled,must be 1 " + ";"
$policyValue = Get-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa |Select-Object RestrictAnonymousSAM
$policyValue = $policyValue.RestrictAnonymousSAM
$outputLine += $policyValue
$outputLine>> $fname



$id = "NA" + "2.3.10.3"
$outputLine = "$id" + ";" + "(L1)Ensure Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled',must be 1 " + ";"
$policyValue = Get-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa |Select-Object RestrictAnonymous
$policyValue = $policyValue.RestrictAnonymous
$outputLine += $policyValue
$outputLine>> $fname




$id = "NA" + "2.3.10.4"
$outputLine = "$id" + ";" + "(L1)Network access: Do not allow storage of passwords and credentials for network authentication is set to Enabled,must be 1 " + ";"
$exist = Test-Path HKLM:\System\CurrentControlSet\Control\Lsa
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa |Select-Object DisableDomainCreds
 $policyValue = $policyValue.DisableDomainCreds
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname


$id = "NA" + "2.3.10.5"
$outputLine = "$id" + ";" + "(L1)Ensure Network access: Let Everyone permissions apply to anonymous users is set to Disabled,must be 0 " + ";"
$exist = Test-Path HKLM:\System\CurrentControlSet\Control\Lsa
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa |Select-Object EveryoneIncludesAnonymous
 $policyValue = $policyValue.EveryoneIncludesAnonymous
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname


$id = "NA" + "2.3.10.6"
$outputLine = "$id" + ";" + "(L1)Configure Network access: Named Pipes that can be accessed anonymously,must be empty " + ";"
$exist = Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters |Select-Object NullSessionPipes
 $policyValue = $policyValue.NullSessionPipes
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname



$id = "NA" + "2.3.10.7"
$outputLine = "$id" + ";" + "(L1)Network access: Remotely accessible registry paths, musbe System\CurrentControlSet\Control\ProductOptions | System\CurrentControlSet\Control\Server Applications |Software\Microsoft\Windows NT\CurrentVersion " + ";"
$exist = Test-Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths |Select-Object Machine
 $policyValue = $policyValue.Machine
}
else {
 $policyValue = "no configuration"
}


$outputLine += $policyValue
$outputLine>> $fname


$id = "NA" + "2.3.10.8"
$outputLine = "$id" + ";" + "(L1)Network access: Remotely accessible registry paths and sub-paths:, check 2.3.10.8 part for the liste" + ";"
$exist = Test-Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths |Select-Object Machine
 $policyValue = $policyValue.Machine
}
else {
 $policyValue = "no configuration"
}
$policyValue > "NetworkAcces-Allowpath.txt"
$outputLine += "Check NetworkAcces-Allowpath.txt"
$outputLine>> $fname


$id = "NA" + "2.3.10.9"
$outputLine = "$id" + ";" + "Ensure Network access: Restrict anonymous access to Named Pipes and Shares is set to Enabled,value must be 1" + ";"
$exist = Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters |Select-Object RestrictNullSessAccess
 $policyValue = $policyValue.RestrictNullSessAccess
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname


$id = "NA" + "2.3.10.10"
$outputLine = "$id" + ";" + "(L1)Ensure Network access: Restrict clients allowed to make remote calls to SAM is set to Administrators: Remote Access: Allow" + ";"
$exist = Test-Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa |Select-Object restrictremotesam
 $policyValue = $policyValue.restrictremotesam
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname



$id = "NA" + "2.3.10.11"
$outputLine = "$id" + ";" + "(L1)Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None, value must be empty or {}" + ";"
$exist = Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters |Select-Object NullSessionShares
 $policyValue = $policyValue.NullSessionShares
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname



$id = "NA" + "2.3.10.12"
$outputLine = "$id" + ";" + "(L1)Ensure Network access: Sharing and security model for local accounts is set to Classic - local users authenticate as themselves,value must be 0" + ";"
$exist = Test-Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa |Select-Object ForceGuest
 $policyValue = $policyValue.ForceGuest
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

Write-Host "#########>Begin Network security audit<#########" -ForegroundColor DarkGreen


$id = "NS" + "2.3.11.1"
$outputLine = "$id" + ";" + "(L1)Network security: Allow Local System to use computer identity for NTLM is set to 'Enabled,value must be 1" + ";"
$exist = Test-Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa |Select-Object UseMachineId
 $policyValue = $policyValue.UseMachineId
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname



$id = "NS" + "2.3.11.2"
$outputLine = "$id" + ";" + "(L1)Ensure Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled,value must be 0" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"|Select-Object AllowNullSessionFallback
 $policyValue = $policyValue.AllowNullSessionFallback
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname




$id = "NS" + "2.3.11.3"
$outputLine = "$id" + ";" + "(L1)Network Security: Allow PKU2U authentication requests to this computer to use online identities is set to Disabled,value must be 0" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u"|Select-Object AllowOnlineID
 $policyValue = $policyValue.AllowOnlineID
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname



$id = "NS" + "2.3.11.4"
$outputLine = "$id" + ";" + "(L1)Ensure Network security: Configure encryption types allowed for Kerberos is set to AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"|Select-Object SupportedEncryptionTypes
 $policyValue = $policyValue.SupportedEncryptionTypes
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname



$id = "NS" + "2.3.11.5"
$outputLine = "$id" + ";" + "(L1)Network security: Do not store LAN Manager hash value on next password change is set to Enabled,value must be 1" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"|Select-Object NoLMHash
 $policyValue = $policyValue.NoLMHash
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname



$id = "NS" + "2.3.11.6"
$outputLine = "$id" + ";" + "(L1)Network security: Force logoff when logon hours expire is set to Enabled,value must be 1" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"|Select-Object EnableForcedLogOff
 $policyValue = $policyValue.EnableForcedLogOff
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "NS" + "2.3.11.7"
$outputLine = "$id" + ";" + "(L1)Ensure Network security: LAN Manager authentication level is set to Send NTLMv2 response only. Refuse LM & NTLM,value must be 5" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"|Select-Object LmCompatibilityLevel
 $policyValue = $policyValue.LmCompatibilityLevel
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "NS" + "2.3.11.8"
$outputLine = "$id" + ";" + "(L1)Ensure Network security: LDAP client signing requirements is set to Negotiate signing or higher,value must be 1 or highter" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP"|Select-Object LDAPClientIntegrity
 $policyValue = $policyValue.LDAPClientIntegrity
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname




$id = "NS" + "2.3.11.9"
$outputLine = "$id" + ";" + "(L1)Ensure Network security: Minimum session security for NTLM SSP based (including secure RPC) clients is set to Require NTLMv2 session security, Require 128-bit encryption,value must be 537395200" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"|Select-Object NTLMMinClientSec
 $policyValue = $policyValue.NTLMMinClientSec
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname



$id = "NS" + "2.3.11.10"
$outputLine = "$id" + ";" + "(L1)Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption', Require 128-bit encryption,value must be 537395200" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"|Select-Object NTLMMinServerSec
 $policyValue = $policyValue.NTLMMinServerSec
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


Write-Host "#########>Begin System cryptography<#########" -ForegroundColor DarkGreen




$id = "SC" + "2.3.14.1"
$outputLine = "$id" + ";" + "(L2)System cryptography: Force strong key protection for user keys stored on the computer' is set to 'User is prompted when the key is first used' or higher,value must be 2 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography"|Select-Object ForceKeyProtection
 $policyValue = $policyValue.ForceKeyProtection
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname



Write-Host "#########>Begin System objects audit<#########" -ForegroundColor DarkGreen




$id = "SO" + "2.3.15.1"
$outputLine = "$id" + ";" + "(L1)Ensure System objects: Require case insensitivity for non-Windows subsystems is set to Enabled,value must be 1" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel"|Select-Object ObCaseInsensitive
 $policyValue = $policyValue.ObCaseInsensitive
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname






$id = "SO" + "2.3.15.2"
$outputLine = "$id" + ";" + "(L1)Ensure System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links) is set to Enabled,value must be 1" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"|Select-Object ProtectionMode
 $policyValue = $policyValue.ProtectionMode
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname



Write-Host "#########>Begin User Account Control(UAC) audit<#########" -ForegroundColor DarkGreen


$id = "UAC" + "2.3.17.1"
$outputLine = "$id" + ";" + "(L1)Ensure User Account Control: Admin Approval Mode for the Built-in Administrator account is set to Enabled,value must be 1" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"|Select-Object FilterAdministratorToken
 $policyValue = $policyValue.FilterAdministratorToken
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname





$id = "UAC" + "2.3.17.2"
$outputLine = "$id" + ";" + "(L1)Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode is set to Prompt for consent on the secure desktop,value must be 2(The value of 2 displays the UAC prompt that needs to be permitted or denied on a secure desktop. No authentication is required) or 1(A value of 1 requires the admin to enter username and password when operations require elevated privileges on a secure desktop)" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"|Select-Object ConsentPromptBehaviorAdmin
 $policyValue = $policyValue.ConsentPromptBehaviorAdmin
}
else {
 $policyValue = "no configuration"
}


$outputLine += $policyValue
$outputLine>> $fname






$id = "UAC" + "2.3.17.3"
$outputLine = "$id" + ";" + "(L1)Ensure User Account Control: Behavior of the elevation prompt for standard users is set to Automatically deny elevation requests, value must be 0(A value of 0 will automatically deny any operation that requires elevated privileges if executed by standard users)." + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"|Select-Object ConsentPromptBehaviorUser
 $policyValue = $policyValue.ConsentPromptBehaviorUser
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "UAC" + "2.3.17.4"
$outputLine = "$id" + ";" + "(L1)Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to Enabled, value must be 1" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"|Select-Object EnableInstallerDetection
 $policyValue = $policyValue.EnableInstallerDetection
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname




$id = "UAC" + "2.3.17.5"
$outputLine = "$id" + ";" + "(L1)Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled, value must be 1" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"|Select-Object EnableSecureUIAPaths
 $policyValue = $policyValue.EnableSecureUIAPaths
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname




$id = "UAC" + "2.3.17.6"
$outputLine = "$indextest" + ";" + "(L1)Ensure 'User Account Control: Run all administrators in Admin Approval Mode is set to Enabled, value must be 1" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"|Select-Object EnableLUA
 $policyValue = $policyValue.EnableLUA
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname




$id = "UAC" + "2.3.17.7"
$outputLine = "$id" + ";" + "(L1)Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"|Select-Object PromptOnSecureDesktop
 $policyValue = $policyValue.PromptOnSecureDesktop
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "UAC" + "2.3.17.8"
$outputLine = "$id" + ";" + "(L1)Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled, value must be 1" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"|Select-Object EnableVirtualization
 $policyValue = $policyValue.EnableVirtualization
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname

Write-Host "#########>Begin System Services audit<#########" -ForegroundColor DarkGreen


$id = "SS" + "5.1"
$outputLine = "$id" + ";" + "Ensure 'Bluetooth Audio Gateway Service (BTAGService)' is set to 'Disabled', value must be 4" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\BTAGService"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\BTAGService"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed "
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "SS" + "5.2"
$outputLine = "$id" + ";" + "(L2)Ensure Bluetooth Support Service (bthserv)' is set to 'Disabled', value must be 4" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\bthserv"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\bthserv"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "SS" + "5.3"
$outputLine = "$id" + ";" + "(L1)Ensure 'Computer Browser (Browser)' is set to 'Disabled' or 'Not Installed'', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Browser"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Browser"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname



$id = "SS" + "5.4"
$outputLine = "$id" + ";" + "(L2)Ensure 'Downloaded Maps Manager (MapsBroker)' is set to 'Disabled', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\MapsBroker"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\MapsBroker"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname



$id = "SS" + "5.5"
$outputLine = "$id" + ";" + "(L2)Ensure 'Geolocation Service (lfsvc)' is set to 'Disabled', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname





$id = "SS" + "5.6"
$outputLine = "$id" + ";" + "(L1)Ensure 'IIS Admin Service (IISADMIN)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\IISADMIN"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\IISADMIN"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname



$id = "SS" + "5.7"
$outputLine = "$id" + ";" + "(L1)Ensure 'Infrared monitor service (irmon)' is set to 'Disabled', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\irmon"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\irmon"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname



$id = "SS" + "5.8"
$outputLine = "$id" + ";" + "(L1)Ensure 'Internet Connection Sharing (ICS) (SharedAccess) ' is set to 'Disabled', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname



$id = "SS" + "5.9"
$outputLine = "$id" + ";" + "(L2)Ensure 'Link-Layer Topology Discovery Mapper (lltdsvc)' is set to 'Disabled', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\lltdsvc"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\lltdsvc"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname



$id = "SS" + "5.10"
$outputLine = "$id" + ";" + "(L1)Ensure 'LxssManager (LxssManager)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LxssManager"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LxssManager"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "SS" + "5.11"
$outputLine = "$id" + ";" + "(L1)Ensure 'Microsoft FTP Service (FTPSVC)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\FTPSVC"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\FTPSVC"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname



$id = "SS" + "5.12"
$outputLine = "$id" + ";" + "(L2)Ensure 'Microsoft iSCSI Initiator Service (MSiSCSI)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\MSiSCSI"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\MSiSCSI"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname



$id = "SS" + "5.13"
$outputLine = "$id" + ";" + "(L1)Ensure 'OpenSSH SSH Server (sshd)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\sshd"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\sshd"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}



$id = "SS" + "5.14"
$outputLine = "$id" + ";" + "(L2)Ensure 'Peer Name Resolution Protocol (PNRPsvc)' is set to 'Disabled'or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\PNRPsvc"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\PNRPsvc"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "SS" + "5.15"
$outputLine = "$id" + ";" + "(L2)Ensure 'Peer Networking Grouping (p2psvc)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\p2psvc"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\p2psvc"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "SS" + "5.16"
$outputLine = "$id" + ";" + "Ensure 'Peer Networking Identity Manager (p2pimsvc)' is set to 'Disabled or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\p2pimsvc"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\p2pimsvc"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "SS" + "5.17"
$outputLine = "$id" + ";" + "(L2)Ensure 'PNRP Machine Name Publication Service (PNRPAutoReg)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\PNRPAutoReg"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\PNRPAutoReg"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "SS" + "5.18"
$outputLine = "$id" + ";" + "(L2)Ensure 'Print Spooler (Spooler)' is set to 'Disabled' (Automated), value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Spooler"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Spooler"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname






$id = "SS" + "5.19"
$outputLine = "$id" + ";" + "(L2)Ensure 'Problem Reports and Solutions Control Panel Support (wercplsupport)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\wercplsupport"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\wercplsupport"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "SS" + "5.20"
$outputLine = "$id" + ";" + "(L2)Ensure 'Remote Access Auto Connection Manager (RasAuto)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\RasAuto"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\RasAuto"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname



$id = "SS" + "5.21"
$outputLine = "$id" + ";" + "(L2)Ensure 'Remote Desktop Configuration (SessionEnv)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\SessionEnv"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\SessionEnv"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "SS" + "5.22"
$outputLine = "$id" + ";" + "(L2)Ensure 'Remote Desktop Services (TermService)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\TermService"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\TermService"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "SS" + "5.23"
$outputLine = "$id" + ";" + "(L2)Ensure 'Remote Desktop Services UserMode Port Redirector (UmRdpService) is set to Disabled or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\UmRdpService"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\UmRdpService"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "SS" + "5.24"
$outputLine = "$id" + ";" + "sshdEnsure 'Remote Procedure Call (RPC) Locator (RpcLocator)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\RpcLocator"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\RpcLocator"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname



$id = "SS" + "5.25"
$outputLine = "$id" + ";" + "(L2)Ensure 'Remote Registry (RemoteRegistry)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "SS" + "5.26"
$outputLine = "$id" + ";" + "(L1)Ensure 'Routing and Remote Access (RemoteAccess)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "SS" + "5.27"
$outputLine = "$id" + ";" + "(L2)Ensure 'Server (LanmanServer)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "SS" + "5.28"
$outputLine = "$id" + ";" + "(L1)Ensure 'Simple TCP/IP Services (simptcp)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\simptcp"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\simptcp"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname





$id = "SS" + "5.29"
$outputLine = "$id" + ";" + "(L2)Ensure 'SNMP Service (SNMP)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "SS" + "5.30"
$outputLine = "$id" + ";" + "(L1)Ensure 'Special Administration Console Helper (sacsvr)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\sacsvr"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\sacsvr"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname






$id = "SS" + "5.31"
$outputLine = "$id" + ";" + "(L1)Ensure 'SSDP Discovery (SSDPSRV)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\SSDPSRV"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\SSDPSRV"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname



$id = "SS" + "5.32"
$outputLine = "$id" + ";" + "(L1)Ensure 'UPnP Device Host (upnphost)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\upnphost"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\upnphost"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "SS" + "5.33"
$outputLine = "$id" + ";" + "(L1)Ensure 'Web Management Service (WMSvc)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\WMSvc"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WMSvc"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "SS" + "5.34"
$outputLine = "$id" + ";" + "(L2)Ensure 'Windows Error Reporting Service (WerSvc) is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\WerSvc"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WerSvc"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "SS" + "5.35"
$outputLine = "$id" + ";" + "(L2)Ensure 'Windows Event Collector (Wecsvc)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Wecsvc"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Wecsvc"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "SS" + "5.36"
$outputLine = "$id" + ";" + "(L1)Ensure 'Windows Media Player Network Sharing Service (WMPNetworkSvc)'''' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname



$id = "SS" + "5.37"
$outputLine = "$id" + ";" + "(L1)Ensure Windows Mobile Hotspot Service (icssvc)'' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\icssvc"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\icssvc"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname



$id = "SS" + "5.38"
$outputLine = "$id" + ";" + "(L2)Ensure Windows Push Notifications System Service (WpnService)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\WpnService"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WpnService"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname



$id = "SS" + "5.39"
$outputLine = "$id" + ";" + "(L2)Ensure 'Windows PushToInstall Service (PushToInstall)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\PushToInstall"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\PushToInstall"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "SS" + "5.40"
$outputLine = "$id" + ";" + "(L2)Ensure Windows Remote Management (WS-Management) (WinRM) is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinRM"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WinRM"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname






$id = "SS" + "5.41"
$outputLine = "$id" + ";" + "(L1)Ensure World Wide Web Publishing Service (W3SVC)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname


$id = "SS" + "5.42"
$outputLine = "$id" + ";" + "(L1)Ensure Xbox Accessory Management Service (XboxGipSvc) is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\XboxGipSvc"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\XboxGipSvc"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "SS" + "5.43"
$outputLine = "$id" + ";" + "(L1)Ensure Xbox Live Auth Manager (XblAuthManager) s set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\XblAuthManager"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\XblAuthManager"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname



$id = "SS" + "5.44"
$outputLine = "$id" + ";" + "(L1)Ensure Xbox Live Game Save (XblGameSave) is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\XblGameSave"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\XblGameSave"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "SS" + "5.45"
$outputLine = "$id" + ";" + "(L1)Ensure Xbox Live Networking Service (XboxNetApiSvc) is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "It s not installed"
}

$outputLine += $policyValue
$outputLine>> $fname


Write-Host "#########>Begin Firewall Domain Profile audit<#########" -ForegroundColor DarkGreen





$id = "WFDP" + "9.1.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On, value must be True" + ";"
$policyValue = Get-NetFirewallProfile -Name "Domain" |Select-Object Enabled
$policyValue = $policyValue.Enabled

$outputLine += $policyValue
$outputLine>> $fname




$id = "WFDP" + "9.1.2"
$outputLine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default), value must be Block" + ";"
$policyValue = Get-NetFirewallProfile -Name "Domain" |Select-Object DefaultInboundAction
$policyValue = $policyValue.DefaultInboundAction

$outputLine += $policyValue
$outputLine>> $fname



$id = "WFDP" + "9.1.3"
$outputLine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow (default), value must be Allow but if it's block it s fucking badass" + ";"
$policyValue = Get-NetFirewallProfile -Name "Domain" |Select-Object DefaultOutboundAction
$policyValue = $policyValue.DefaultOutboundAction

$outputLine += $policyValue
$outputLine>> $fname



$id = "WFDP" + "9.1.4"
$outputLine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No', value must false " + ";"
$policyValue = Get-NetFirewallProfile -Name "Domain" |Select-Object NotifyOnListen
$policyValue = $policyValue.NotifyOnListen

$outputLine += $policyValue
$outputLine>> $fname





$id = "WFDP" + "9.1.5"

$outputLine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Domain: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log " + ";"
$policyValue = Get-NetFirewallProfile -Name "Domain" |Select-Object LogFileName
$policyValue = $policyValue.LogFileName

$outputLine += $policyValue
$outputLine>> $fname



$id = "WFDP" + "9.1.6"
$outputLine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16,384 KB or greater, value must 16384 or higthter " + ";"
$policyValue = Get-NetFirewallProfile -Name "Domain" |Select-Object LogMaxSizeKilobytes
$policyValue = $policyValue.LogMaxSizeKilobytes

$outputLine += $policyValue
$outputLine>> $fname




$id = "WFDP" + "9.1.7"
$outputLine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes',value must be true " + ";"
$policyValue = Get-NetFirewallProfile -Name "Domain" |Select-Object LogBlocked
$policyValue = $policyValue.LogBlocked

$outputLine += $policyValue
$outputLine>> $fname



$id = "WFDP" + "9.1.8"
$outputLine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes,value must be true " + ";"
$policyValue = Get-NetFirewallProfile -Name "Domain" |Select-Object LogAllowed
$policyValue = $policyValue.LogAllowed
$outputLine += $policyValue
$outputLine>> $fname


Write-Host "#########>Begin Firewall Private Profile audit<#########" -ForegroundColor DarkGreen




$id = "WFPPRIP" + "9.2.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Private: Firewall state' is set to 'On, value must be True" + ";"
$policyValue = Get-NetFirewallProfile -Name "Private" |Select-Object Enabled
$policyValue = $policyValue.Enabled
$outputLine += $policyValue
$outputLine>> $fname




$id = "WFPPRIP" + "9.2.2"
$outputLine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default, value must be Block" + ";"
$policyValue = Get-NetFirewallProfile -Name "Private" |Select-Object DefaultInboundAction
$policyValue = $policyValue.DefaultInboundAction
$outputLine += $policyValue
$outputLine>> $fname




$id = "WFPPRIP" + "9.2.3"
$outputLine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)', value must be Allow but if it's block it s fucking badass" + ";"
$policyValue = Get-NetFirewallProfile -Name "Private" |Select-Object DefaultOutboundAction
$policyValue = $policyValue.DefaultOutboundAction

$outputLine += $policyValue
$outputLine>> $fname



$id = "WFPPRIP" + "9.2.4"
$outputLine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No, value must false " + ";"
$policyValue = Get-NetFirewallProfile -Name "Private" |Select-Object NotifyOnListen
$policyValue = $policyValue.NotifyOnListen

$outputLine += $policyValue
$outputLine>> $fname





$id = "WFPPRIP" + "9.2.5"
$outputLine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\privatefw.log " + ";"
$policyValue = Get-NetFirewallProfile -Name "Private" |Select-Object LogFileName
$policyValue = $policyValue.LogFileName

$outputLine += $policyValue
$outputLine>> $fname





$id = "WFPPRIP" + "9.2.6"
$outputLine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater, value must 16384 or higthter " + ";"
$policyValue = Get-NetFirewallProfile -Name "Private" |Select-Object LogMaxSizeKilobytes
$policyValue = $policyValue.LogMaxSizeKilobytes

$outputLine += $policyValue
$outputLine>> $fname




$id = "WFPPRIP" + "9.2.7"
$outputLine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes',value must be true " + ";"
$policyValue = Get-NetFirewallProfile -Name "Private" |Select-Object LogBlocked
$policyValue = $policyValue.LogBlocked

$outputLine += $policyValue
$outputLine>> $fname




$id = "WFPPRIP" + "9.2.8"
$outputLine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes',value must be true " + ";"
$policyValue = Get-NetFirewallProfile -Name "Domain" |Select-Object LogAllowed
$policyValue = $policyValue.LogAllowed
$outputLine += $policyValue
$outputLine>> $fname




Write-Host "#########>Begin Firewall Public Profile audit<#########" -ForegroundColor DarkGreen




$id = "WFPPUBP" + "9.3.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Public: Firewall state' is set to 'On, value must be True" + ";"
$policyValue = Get-NetFirewallProfile -Name "Public" |Select-Object Enabled
$policyValue = $policyValue.Enabled

$outputLine += $policyValue
$outputLine>> $fname



$id = "WFPPUBP" + "9.3.2"
$outputLine = "$id" + ";" + "(L1)Windows Firewall: Public: Inbound connections' is set to 'Block , value must be Block" + ";"
$policyValue = Get-NetFirewallProfile -Name "Public" |Select-Object DefaultInboundAction
$policyValue = $policyValue.DefaultInboundAction

$outputLine += $policyValue
$outputLine>> $fname




$id = "WFPPUBP" + "9.3.3"
$outputLine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default), value must be Allow but if it's block it s fucking badass" + ";"
$policyValue = Get-NetFirewallProfile -Name "Public" |Select-Object DefaultOutboundAction
$policyValue = $policyValue.DefaultOutboundAction

$outputLine += $policyValue
$outputLine>> $fname





$id = "WFPPUBP" + "9.3.4"
$outputLine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'Yes, value must false " + ";"
$policyValue = Get-NetFirewallProfile -Name "Public" |Select-Object NotifyOnListen
$policyValue = $policyValue.NotifyOnListen

$outputLine += $policyValue
$outputLine>> $fname




$id = "WFPPUBP" + "9.3.5"
$outputLine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No, value must 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"|Select-Object AllowLocalPolicyMerge
 $policyValue = $policyValue.AllowLocalPolicyMerge
}
else {
 $policyValue = "no configuration"
}


$outputLine += $policyValue
$outputLine>> $fname




$id = "WFPPUBP" + "9.3.6"
$outputLine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No', value must 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"|Select-Object AllowLocalIPsecPolicyMerge
 $policyValue = $policyValue.AllowLocalIPsecPolicyMerge
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "WFPPUBP" + "9.3.7"
$outputLine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\publicfw.log" + ";"
$policyValue = Get-NetFirewallProfile -Name "Public" |Select-Object LogFileName
$policyValue = $policyValue.LogFileName

$outputLine += $policyValue
$outputLine>> $fname




$id = "WFPPUBP" + "9.3.8"
$outputLine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater" + ";"
$policyValue = Get-NetFirewallProfile -Name "Public" |Select-Object LogMaxSizeKilobytes
$policyValue = $policyValue.LogMaxSizeKilobytes

$outputLine += $policyValue
$outputLine>> $fname




$id = "WFPPUBP" + "9.3.9"
$outputLine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes',value must be true " + ";"
$policyValue = Get-NetFirewallProfile -Name "Public" |Select-Object LogBlocked
$policyValue = $policyValue.LogBlocked

$outputLine += $policyValue
$outputLine>> $fname



$id = "WFPPUBP" + "9.3.10"
$outputLine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes',value must be true " + ";"
$policyValue = Get-NetFirewallProfile -Name "Public" |Select-Object LogAllowed
$policyValue = $policyValue.LogAllowed

$outputLine += $policyValue
$outputLine>> $fname


Write-Host "#########>Begin Advanced Audit Policy audit<#########" -ForegroundColor DarkGreen

$auditPolicyLookup = @{}
Get-AuditPolicy -Subcategory * | ForEach-Object {
 $auditPolicyLookup[$_.Subcategory] = $_.Setting
}
function Get-AuditPolicySummary {
 param(
  [string]$Subcategory,
  [string]$Label
 )
 if (-not $Label) {
  $Label = $Subcategory
 }
 $setting = $auditPolicyLookup[$Subcategory]
 if ([string]::IsNullOrEmpty($setting)) {
  $setting = "NotConfigured"
 }
 return ("{0}:{1}" -f $Label, $setting)
}

$id = "AAAL" + "17.1.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Audit Credential Validation' is set to 'Success and Failure" + ";"
$policyValue = Get-AuditPolicySummary -Subcategory "Credential Validation"

$outputLine += $policyValue
$outputLine>> $fname




$id = "AAGM" + "17.2.2"
$outputLine = "$id" + ";" + "(L1)Ensure 'Audit Security Group Management' is set to 'Success and Failure'" + ";"
$policyValue = Get-AuditPolicySummary -Subcategory "Security Group Management"

$outputLine += $policyValue
$outputLine>> $fname



$id = "AAGM" + "17.2.3"
$outputLine = "$indextest" + ";" + "(L1)Ensure 'Audit User Account Management' is set to 'Success and Failure" + ";"
$policyValue = Get-AuditPolicySummary -Subcategory "User Account Management"

$outputLine += $policyValue
$outputLine>> $fname



$id = "AADT" + "17.3.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Audit PNP Activity' is set to 'Success'" + ";"
$policyValue = Get-AuditPolicySummary -Subcategory "Plug and Play Events" -Label "PNP Activity"

$outputLine += $policyValue
$outputLine>> $fname



$id = "AADT" + "17.3.2"
$outputLine = "$id" + ";" + "(L1)Ensure 'Audit Process Creation' is set to 'Success" + ";"
$policyValue = Get-AuditPolicySummary -Subcategory "Process Creation"

$outputLine += $policyValue
$outputLine>> $fname




$id = "AALL" + "17.5.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Audit Account Lockout' is set to Failure'" + ";"
$policyValue = Get-AuditPolicySummary -Subcategory "Account Lockout"

$outputLine += $policyValue
$outputLine>> $fname




$id = "AALL" + "17.5.2"
$outputLine = "$id" + ";" + "(L1)Ensure 'Audit Group Membership' is set to 'Success" + ";"
$policyValue = Get-AuditPolicySummary -Subcategory "Group Membership"
$outputLine += $policyValue
$outputLine>> $fname





$id = "AALL" + "17.5.3"
$outputLine = "$id" + ";" + "(L1)Ensure 'Audit Logoff' is set to 'Success'" + ";"
$policyValue = Get-AuditPolicySummary -Subcategory "Logoff"

$outputLine += $policyValue
$outputLine>> $fname



$id = "AALL" + "17.5.4"
$outputLine = "$id" + ";" + "(L1)Ensure 'Audit Logon' is set to 'Success and Failure'" + ";"
$policyValue = Get-AuditPolicySummary -Subcategory "Logon"

$outputLine += $policyValue
$outputLine>> $fname



$id = "AALL" + "17.5.5"
$outputLine = "$id" + ";" + "(L1)Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'" + ";"
$policyValue = Get-AuditPolicySummary -Subcategory "Other Logon/Logoff Events"

$outputLine += $policyValue
$outputLine>> $fname




$id = "AALL" + "17.5.6"
$outputLine = "$id" + ";" + "(L1)Ensure 'Audit Special Logon' is set to 'Success'" + ";"
$policyValue = Get-AuditPolicySummary -Subcategory "Special Logon"

$outputLine += $policyValue
$outputLine>> $fname



$id = "AAOA" + "17.6.1"
$outputLine = "$id" + ";" + "(L1)Encdsure Audit Detailed File Share is set to Failure'" + ";"
$policyValue = Get-AuditPolicySummary -Subcategory "Detailed File Share"

$outputLine += $policyValue
$outputLine>> $fname






$id = "AAOA" + "17.6.2"
$outputLine = "$id" + ";" + "(L1)Ensure 'Audit File Share'''' is set to 'Success and Failure'" + ";"
$policyValue = Get-AuditPolicySummary -Subcategory "File Share"

$outputLine += $policyValue
$outputLine>> $fname



$id = "AAOA" + "17.6.3"
$outputLine = "$id" + ";" + "(L1)Ensure 'Audit Other Object Access Events''''' is set to 'Success and Failure'" + ";"
$policyValue = Get-AuditPolicySummary -Subcategory "Other Object Access Events"

$outputLine += $policyValue
$outputLine>> $fname



$id = "AAOA" + "17.6.4"
$outputLine = "$id" + ";" + "(L1)Ensure 'Audit Removable Storage' is set to 'Success and Failure'" + ";"
$policyValue = Get-AuditPolicySummary -Subcategory "Removable Storage"

$outputLine += $policyValue
$outputLine>> $fname




$id = "AAPC" + "17.7.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Audit Audit Policy Change' is set to 'Success and Failure'" + ";"
$policyValue = Get-AuditPolicySummary -Subcategory "Audit Policy Change"

$outputLine += $policyValue
$outputLine>> $fname



$id = "AAPC" + "17.7.2"
$outputLine = "$id" + ";" + "(L1)Ensure 'Audit Authentication Policy Change' is set to 'Success''" + ";"
$policyValue = Get-AuditPolicySummary -Subcategory "Authentication Policy Change"

$outputLine += $policyValue
$outputLine>> $fname




$id = "AAPC" + "17.7.3"
$outputLine = "$id" + ";" + "Ensure 'Audit Authorization Policy Change' is set to 'Success''" + ";"
$policyValue = Get-AuditPolicySummary -Subcategory "Authorization Policy Change"

$outputLine += $policyValue
$outputLine>> $fname



$id = "AAPU" + "17.7.4"
$outputLine = "$id" + ";" + "(L1)Ensure 'Audit MPSSVC Rule-Level Policy Change is set to 'Success and Failure'" + ";"
$policyValue = Get-AuditPolicySummary -Subcategory "MPSSVC Rule-Level Policy Change"

$outputLine += $policyValue
$outputLine>> $fname




$id = "AAPU" + "17.7.5"
$outputLine = "$id" + ";" + "(L1)Ensure 'Audit Other Policy Change Events' is set to include 'Failure'" + ";"
$policyValue = Get-AuditPolicySummary -Subcategory "Other Policy Change Events"

$outputLine += $policyValue
$outputLine>> $fname




$id = "AAPU" + "17.8.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure'" + ";"
$policyValue = Get-AuditPolicySummary -Subcategory "Sensitive Privilege Use"

$outputLine += $policyValue
$outputLine>> $fname




$id = "AAS" + "17.9.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Audit IPsec Driver' is set to 'Success and Failure'" + ";"
$policyValue = Get-AuditPolicySummary -Subcategory "IPsec Driver"

$outputLine += $policyValue
$outputLine>> $fname




$id = "AAS" + "17.9.2"
$outputLine = "$id" + ";" + "(L1)Ensure 'Audit Other System Events' is set to 'Success and Failure'" + ";"
$policyValue = Get-AuditPolicySummary -Subcategory "Other System Events"
  
$outputLine += $policyValue
$outputLine>> $fname



$id = "AAS" + "17.9.3"
$outputLine = "$id" + ";" + "(L1)Ensure 'Audit Security State Change' is set to 'Success" + ";"
$policyValue = Get-AuditPolicySummary -Subcategory "Security State Change"

$outputLine += $policyValue
$outputLine>> $fname



$id = "AAS" + "17.9.4"
$outputLine = "$id" + ";" + "(L1)Ensure 'Audit Security System Extension' is set to 'Success and Failure" + ";"
$policyValue = Get-AuditPolicySummary -Subcategory "Security System Extension"

$outputLine += $policyValue
$outputLine>> $fname




$id = "AAS" + "17.9.5"
$outputLine = "$id" + ";" + "(L1)Ensure 'Audit System Integrity' is set to 'Success and Failure'" + ";"
$policyValue = Get-AuditPolicySummary -Subcategory "System Integrity"

$outputLine += $policyValue
$outputLine>> $fname



Write-Host "#########>Begin Personalization audit<#########" -ForegroundColor DarkGreen



$id = "PA" + "18.1.1.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Prevent enabling lock screen camera' is set to 'Enabled, value must 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"|Select-Object NoLockScreenCamera
 $policyValue = $policyValue.NoLockScreenCamera
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "PA" + "18.1.1.2"
$outputLine = "$id" + ";" + "(L1)Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled', value must 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"|Select-Object NoLockScreenSlideshow
 $policyValue = $policyValue.NoLockScreenSlideshow
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname




$id = "PA" + "18.1.2.2"
$outputLine = "$id" + ";" + "(L1)Ensure 'Allow users to enable online speech recognition services' is set to 'Disabled', value must 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"|Select-Object AllowInputPersonalization
 $policyValue = $policyValue.AllowInputPersonalization
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname



$id = "PA" + "18.1.3"
$outputLine = "$id" + ";" + "(L2)Ensure Allow Online Tips'' is set to 'Disabled', value must 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"|Select-Object AllowOnlineTips
 $policyValue = $policyValue.AllowOnlineTips
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname






Write-Host "#########>Begin LAPS audit<#########" -ForegroundColor DarkGreen


$id = "LAPS" + "18.3.1"
$outputLine = "$id" + ";" + "(L1)Ensure LAPS AdmPwd GPO Extension / CSE is installed, value must true " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}"
if ( $exist -eq $true) {
 $policyValue = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}"|Select-Object DllName
 $policyValue = $policyValue.DllName
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname






$id = "LAPS" + "18.3.2"

$outputLine = "$id" + ";" + "(L1)Ensure 'Do not allow password expiration time longer than required by policy' is set to 'Enabled, value must 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"|Select-Object PwdExpirationProtectionEnabled
 $policyValue = $policyValue.PwdExpirationProtectionEnabled
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname






$id = "LAPS" + "18.3.3"
$outputLine = "$id" + ";" + "(L1)Ensure 'Enable Local Admin Password Management' is set to 'Enabled', value must 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"|Select-Object AdmPwdEnabled
 $policyValue = $policyValue.AdmPwdEnabled
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname





$id = "LAPS" + "18.3.4"
$outputLine = "$id" + ";" + "(L1)Ensure 'Password Settings: Password Complexity' is set to 'Enabled: Large letters + small letters + numbers + special characters, value must 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"|Select-Object PasswordComplexity
 $policyValue = $policyValue.PasswordComplexity
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname





$id = "LAPS" + "18.3.5"
$outputLine = "$id" + ";" + "(L1)Ensure 'Password Settings: Password Length' is set to 'Enabled: 15 or more, value must greater than 15 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"|Select-Object PasswordLength
 $policyValue = $policyValue.PasswordLength
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "LAPS" + "18.3.6"

$outputLine = "$id" + ";" + "(L1)Ensure 'Password Settings: Password Age (Days)' is set to 'Enabled: 30 or fewer', value must less than 30 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"|Select-Object PasswordAgeDays
 $policyValue = $policyValue.PasswordAgeDays
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname



Write-Host "#########>Begin MS Security Guide audit<#########" -ForegroundColor DarkGreen



$id = "MSSG" + "18.4.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled', value must be 0" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"|Select-Object LocalAccountTokenFilterPolicy
 $policyValue = $policyValue.LocalAccountTokenFilterPolicy
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname



$id = "MSSG" + "18.4.2"
$outputLine = "$id" + ";" + "(L1)Ensure 'Configure RPC packet level privacy setting for incoming connections' is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Print"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Print"|Select-Object RpcAuthnLevelPrivacyEnabled
 $policyValue = $policyValue.RpcAuthnLevelPrivacyEnabled
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname





$id = "MSSG" + "18.4.3"
$outputLine = "$id" + ";" + "(L1)Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver', value must be 4" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10"|Select-Object Start
 $policyValue = $policyValue.Start
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname







$id = "MSSG" + "18.4.4"
$outputLine = "$id" + ";" + "(L1)Ensure Configure SMB v1 server' is set to 'Disabled', value must be 0" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"|Select-Object SMB1
 $policyValue = $policyValue.SMB1
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "MSSG" + "18.4.5"
$outputLine = "$id" + ";" + "(L1)Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled', value must be 0" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"|Select-Object DisableExceptionChainValidation
 $policyValue = $policyValue.DisableExceptionChainValidation
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "MSSG" + "18.4.6"
$outputLine = "$id" + ";" + "(L1)Ensure 'NetBT NodeType configuration' is set to 'Enabled: P-node (recommended), value must be 2" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"|Select-Object NodeType
 $policyValue = $policyValue.NodeType
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname






$id = "MSSG" + "18.4.7"
$outputLine = "$id" + ";" + "(L1)Ensure 'WDigest Authentication' is set to 'Disabled', value must be 0" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"|Select-Object UseLogonCredential
 $policyValue = $policyValue.UseLogonCredential
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname




Write-Host "#########>Begin MSS (Legacy) audit<#########" -ForegroundColor DarkGreen



$id = "MSSL" + "18.5.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled, value must be 0 or empty" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"|Select-Object AutoAdminLogon
 $policyValue = $policyValue.AutoAdminLogon
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "MSSL" + "18.5.2"
$outputLine = "$id" + ";" + "(L1)Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled, value must be 2" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"|Select-Object disableIPSourceRouting
 $policyValue = $policyValue.disableIPSourceRouting
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "MSSL" + "18.5.3"
$outputLine = "$id" + ";" + "(L1)Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled, value must be 2" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"|Select-Object disableIPSourceRouting
 $policyValue = $policyValue.disableIPSourceRouting
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname




$id = "MSSL" + "18.5.4"
$outputLine = "$id" + ";" + "(L2)Ensure 'MSS: (DisableSavePassword) Prevent the dial-up password from being saved' is set to 'Enabled', source routing is completely disabled, value must be 1" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters"|Select-Object DisableSavePassword
 $policyValue = $policyValue.DisableSavePassword
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname




$id = "MSSL" + "18.5.5"
$outputLine = "$id" + ";" + "(L1)Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled, value must be 0" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"|Select-Object EnableICMPRedirect
 $policyValue = $policyValue.EnableICMPRedirect
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname




$id = "MSSL" + "18.5.6"
$outputLine = "$id" + ";" + "(L2)Ensure 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes, value must be 300000" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"|Select-Object KeepAliveTime
 $policyValue = $policyValue.KeepAliveTime
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname





$id = "MSSL" + "18.5.7"
$outputLine = "$id" + ";" + "(L1)Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled, value must be 1" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\\Parameters"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" |Select-Object NoNameReleaseOnDemand
 $policyValue = $policyValue.NoNameReleaseOnDemand
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "MSSL" + "18.5.8"
$outputLine = "$id" + ";" + "(L2)Ensure MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)', value must be 0" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\\Parameters"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" |Select-Object PerformRouterDiscovery
 $policyValue = $policyValue.PerformRouterDiscovery
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname





$id = "MSSL" + "18.5.9"
$outputLine = "$id" + ";" + "(L1)Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' is set to 'Enabled, value must be 1" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
if ( $exist -eq $true) {
				$policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" |Select-Object SafeDllSearchMode
 $policyValue = $policyValue.SafeDllSearchMode
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname



$id = "MSSL" + "18.5.10"
$outputLine = "$id" + ";" + "(L1)Ensure MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires 'is set to 'Enabled: 5 or fewer seconds (0 recommended)', value must be 5 or less " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" |Select-Object ScreenSaverGracePeriod
 $policyValue = $policyValue.ScreenSaverGracePeriod
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "MSSL" + "18.5.11"
$outputLine = "$id" + ";" + "(L2)Ensure 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3: value must be 3 " + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" |Select-Object tcpMaxDataRetransmissions
 $policyValue = $policyValue.tcpMaxDataRetransmissions
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname



$id = "MSSL" + "18.5.12"
$outputLine = "$id" + ";" + "(L2)Ensure 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3: value must be 3 " + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP\Parameters" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP\Parameters" |Select-Object tcpMaxDataRetransmissions
 $policyValue = $policyValue.tcpMaxDataRetransmissions
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname




$id = "MSSL" + "18.5.13"
$outputLine = "$id" + ";" + "(L1)Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less " + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security" |Select-Object WarningLevel
 $policyValue = $policyValue.WarningLevel
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname



Write-Host "#########>Begin DNS Client audit<#########" -ForegroundColor DarkGreen




$id = "DNSCA" + "18.6.4.1"
$outputLine = "$id" + ";" + "(L1) Ensure 'Configure DNS over HTTPS (DoH) name resolution' is set to 'Enabled: Allow DoH' or higher, value must be 2 OR 3 could cause issue in domain joined environment " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" |Select-Object DoHPolicy
 $policyValue = $policyValue.DoHPolicy
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname






$id = "DNSCA" + "18.6.4.2"
$outputLine = "$id" + ";" + "(L1) Ensure 'Configure NetBIOS settings' is set to 'Enabled: Disable NetBIOS name resolution on public networks, value must be 0" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" |Select-Object EnableNetbios
 $policyValue = $policyValue.EnableNetbios
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname






$id = "DNSCA" + "18.6.4.3"
$outputLine = "$id" + ";" + "(L1)Ensure 'Turn off multicast name resolution' is set to 'Enabled' (MS Only), value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" |Select-Object EnableMulticast
 $policyValue = $policyValue.EnableMulticast
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname


Write-Host "#########>Begin Fonts audit<#########" -ForegroundColor DarkGreen



$id = "FONT" + "18.6.5.1"
$outputLine = "$id" + ";" + "(L2)Ensure 'Enable Font Providers' is set to 'Disabled, value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" |Select-Object EnableFontProviders
 $policyValue = $policyValue.EnableFontProviders
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname



Write-Host "#########>Begin Lanman Workstation audit<#########" -ForegroundColor DarkGreen



$id = "LW" + "18.6.8.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Enable insecure guest logons' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" |Select-Object AllowInsecureGuestAuth
 $policyValue = $policyValue.AllowInsecureGuestAuth
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname



Write-Host "#########>Begin Link-Layer Topology Discovery audit<#########" -ForegroundColor DarkGreen


$id = "LLTDIO" + "18.6.9.1"
$outputLine = "$id" + ";" + "(L2)Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" |Select-Object AllowLLTDIOOnDomain
 $policyValue = $policyValue.AllowLLTDIOOnDomain
 $policyValueBuffer = "AllowLLTDIOOnDomain" + ":" + "$policyValue" + "|"
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" |Select-Object AllowLLTDIOOnPublicNet
 $policyValue = $policyValue.AllowLLTDIOOnPublicNet
 $policyValueBuffer += "AllowLLTDIOOnPublicNet" + ":" + "$policyValue" + "|"
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" |Select-Object EnableLLTDIO
 $policyValue = $policyValue.EnableLLTDIO
 $policyValueBuffer += "EnableLLTDIO" + ":" + "$policyValue" + "|"
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" |Select-Object ProhibitLLTDIOOnPrivateNet
 $policyValue = $policyValue.ProhibitLLTDIOOnPrivateNet
 $policyValueBuffer += "ProhibitLLTDIOOnPrivateNet" + ":" + "$policyValue" + "|"
}
else {
 $policyValueBuffer = "no configuration"
}

$outputLine += $policyValueBuffer
$outputLine>> $fname




$id = "LLTDIO" + "18.6.9.2"
$outputLine = "$id" + ";" + "(L2)Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" |Select-Object AllowRspndrOnDomain
 $policyValue = $policyValue.AllowRspndrOnDomain
 $policyValueBuffer = "AllowRspndrOnDomain" + ":" + "$policyValue" + "|"
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" |Select-Object AllowRspndrOnPublicNet
 $policyValue = $policyValue.AllowRspndrOnPublicNet
 $policyValueBuffer += "AllowRspndrOnPublicNet" + ":" + "$policyValue" + "|"
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" |Select-Object EnableRspndr
 $policyValue = $policyValue.EnableRspndr
 $policyValueBuffer += "EnableRspndr" + ":" + "$policyValue" + "|"
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" |Select-Object ProhibitRspndrOnPrivateNet
 $policyValue = $policyValue.ProhibitRspndrOnPrivateNet
 $policyValueBuffer += "ProhibitRspndrOnPrivateNet" + ":" + "$policyValue" + "|"
}
else {
 $policyValueBuffer = "no configuration"
}

$outputLine += $policyValueBuffer
$outputLine>> $fname



Write-Host "#########>Begin Microsoft Peer-to-Peer Networking Service saudit<#########" -ForegroundColor DarkGreen



$id = "PPNS" + "18.6.10.2"

$outputLine = "$id" + ";" + "(L2)Ensure 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Peernet" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Peernet" |Select-Object Disabled
 $policyValue = $policyValue.Disabled
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

Write-Host "#########>Begin Network Connections audit<#########" -ForegroundColor DarkGreen


$id = "NC" + "18.6.11.2"
$outputLine = "$id" + ";" + "(L1)Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" |Select-Object NC_AllowNetBridge_NLA
 $policyValue = $policyValue.NC_AllowNetBridge_NLA
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname



$id = "NC" + "18.6.11.3"
$outputLine = "$id" + ";" + "(L1)Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" |Select-Object NC_ShowSharedAccessUI
 $policyValue = $policyValue.NC_ShowSharedAccessUI
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname




$id = "NC" + "18.6.11.4"
$outputLine = "$id" + ";" + "(L1)Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" |Select-Object NC_StdDomainUserSetLocation
 $policyValue = $policyValue.NC_StdDomainUserSetLocation
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname



$id = "NP" + "18.6.14.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Hardened UNC Paths' is set to 'Enabled, with Require Mutual Authentication and Require Integrity set for all NETLOGON and SYSVOL shares', RequireMutualAuthentication=1, RequireIntegrity=1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider" |Select-Object "\\*\NETLOGON"
 $policyValue = $policyValue."\\*\NETLOGON"
 $policyValueBuffer = "\\*\NETLOGON" + ":" + "$policyValue" + "|"
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider" |Select-Object "\\*\SYSVOL"
 $policyValue = $policyValue."\\*\SYSVOL"
 $policyValueBuffer = "\\*\SYSVOL" + ":" + "$policyValue" + "|"
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValueBuffer
$outputLine>> $fname






$id = "IPV6" + "18.6.19.2.1"

$outputLine = "$id" + ";" + "(L2)Disable IPv6 (Ensure TCPIP6 Parameter 'DisabledComponents' is set to '0xff (255)'), value must be 255 " + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" |Select-Object disabledComponents
 $policyValue = $policyValue.disabledComponents
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname





$id = "WCN" + "18.6.20.1"
$outputLine = "$id" + ";" + "(L2)Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" |Select-Object EnableRegistrars
 $policyValue = $policyValue.EnableRegistrars
 $policyValueBuffer = "EnableRegistrars" + ":" + "$policyValue" + "|"
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" |Select-Object DisableUPnPRegistrar
 $policyValue = $policyValue.DisableUPnPRegistrar
 $policyValueBuffer += "DisableUPnPRegistrar" + ":" + "$policyValue" + "|"
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" |Select-Object disableInBand802DOT11Registrar
 $policyValue = $policyValue.disableInBand802DOT11Registrar
 $policyValueBuffer += "disableInBand802DOT11Registrar" + ":" + "$policyValue" + "|"
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" |Select-Object DisableFlashConfigRegistrar
 $policyValue = $policyValue.DisableFlashConfigRegistrar
 $policyValueBuffer += "DisableFlashConfigRegistrar" + ":" + "$policyValue" + "|"
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" |Select-Object DisableWPDRegistrar
 $policyValue = $policyValue.DisableWPDRegistrar
 $policyValueBuffer += "DisableWPDRegistrar" + ":" + "$policyValue" + "|"
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValueBuffer
$outputLine>> $fname



$id = "WCN" + "18.6.20.2"
$outputLine = "$id" + ";" + "(L2)Ensure 'Prohibit access of the Windows Connect Now wizards' is set to 'Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI" |Select-Object DisableWcnUi
 $policyValue = $policyValue.DisableWcnUi
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname



$id = "WCM" + "18.6.21.1"
$outputLine = "$id" + ";" + "(L1)Ensure Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled: 3 = Prevent Wi-Fi when on Ethernet', value must be 3 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" |Select-Object fMinimizeConnections
 $policyValue = $policyValue.fMinimizeConnections
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname



$id = "WCM" + "18.6.21.2"
$outputLine = "$id" + ";" + "(L1)Ensure 'Prohibit connection to non-domain networks when connected to domain authenticated network' is set to 'Enabled'', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" |Select-Object fBlockNonDomain
 $policyValue = $policyValue.fBlockNonDomain
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname





Write-Host "#########>Begin WLAN Settings audit<#########" -ForegroundColor DarkGreen

$id = "WLAN" + "18.6.23.2.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Allow Windows to automatically connect to suggested open hotspots, to networks shared by contacts, and to hotspots offering paid services' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" |Select-Object AutoConnectAllowedOEM
 $policyValue = $policyValue.AutoConnectAllowedOEM
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname




Write-Host "#########>Begin Printer Settings audit<#########" -ForegroundColor DarkGreen

$id = "PRINT" + "18.7.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Allow Print Spooler to accept client connections' is set to 'Disabled'', value must be 2 " + ";"
$exist = Test-Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" |Select-Object RegisterSpoolerRemoteRpcEndPoint
 $policyValue = $policyValue.RegisterSpoolerRemoteRpcEndPoint
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname


$id = "PRINT" + "18.7.2"
$outputLine = "$id" + ";" + "Ensure 'Configure Redirection Guard' is set to 'Enabled: Redirection Guard Enabled', value must be 1 , 2 mean audit mode " + ";"
$exist = Test-Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" |Select-Object RedirectionguardPolicy
 $policyValue = $policyValue.RedirectionguardPolicy
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname



$id = "PRINT" + "18.7.3"
$outputLine = "$id" + ";" + "(L1) Ensure 'Configure RPC connection settings: Protocol to use for outgoing RPC connections' is set to 'Enabled: RPC over TCP', value must be 1 " + ";"
$exist = Test-Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC" |Select-Object RpcUseNamedPipeProtocol
 $policyValue = $policyValue.RpcUseNamedPipeProtocol
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname


$id = "PRINT" + "18.7.4"
$outputLine = "$id" + ";" + "(L1) (L1) Ensure 'Configure RPC connection settings: Use authentication for outgoing RPC connections' is set to 'Enabled: Default', value must be 1 " + ";"
$exist = Test-Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC" |Select-Object RpcAuthentication
 $policyValue = $policyValue.RpcAuthentication
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname



$id = "PRINT" + "18.7.5"
$outputLine = "$id" + ";" + "(L1) Ensure 'Configure RPC listener settings: Protocols to allow for incoming RPC connections' is set to 'Enabled: RPC over TCP', value must be 0x7 " + ";"
$exist = Test-Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC" |Select-Object RpcProtocols
 $policyValue = $policyValue.RpcProtocols
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname



$id = "PRINT" + "18.7.7"
$outputLine = "$id" + ";" + "(L1) Ensure 'Configure RPC over TCP port' is set to 'Enabled: 0' (Automated) value must be 0 " + ";"
$exist = Test-Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC" |Select-Object RpcTcpPort
 $policyValue = $policyValue.RpcTcpPort
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname



$id = "PRINT" + "18.7.8"
$outputLine = "$id" + ";" + "(L1) Ensure 'Configure RPC over TCP port' is set to 'Enabled: 0' (Automated) value must be 1 " + ";"
$exist = Test-Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" |Select-Object RestrictDriverInstallationToAdministrators
 $policyValue = $policyValue.RestrictDriverInstallationToAdministrators
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname


$id = "PRINT" + "18.7.9"
$outputLine = "$id" + ";" + "(L1)Ensure 'Manage processing of Queue-specific files' is set to 'Enabled: Limit Queue-specific files to Color profiles' value must be 1 " + ";"
$exist = Test-Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" |Select-Object CopyFilesPolicy
 $policyValue = $policyValue.CopyFilesPolicy
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname



$id = "PRINT" + "18.7.10"
$outputLine = "$id" + ";" + "(L1)Ensure 'Point and Print Restrictions: When installing drivers for a new connection' is set to 'Enabled: Show warning and elevation prompt',value must be 1 " + ";"
$exist = Test-Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" |Select-Object NoWarningNoElevationOnInstall
 $policyValue = $policyValue.NoWarningNoElevationOnInstall
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname



$id = "PRINT" + "18.7.11"
$outputLine = "$id" + ";" + "(L1)Ensure 'Point and Print Restrictions: When updating drivers for an existing connection' is set to 'Enabled: Show warning and elevation prompt',value must be 0 " + ";"
$exist = Test-Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" |Select-Object UpdatePromptSettings
 $policyValue = $policyValue.UpdatePromptSettings
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname


Write-Host "#########>Begin Notification Settings audit<#########" -ForegroundColor DarkGreen

$id = "NOTI" + "18.8.1.1"
$outputLine = "$id" + ";" + "(L2) Ensure 'Turn off notifications network usage' is set to 'Enabled',value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" |Select-Object NoCloudApplicationNotification
 $policyValue = $policyValue.NoCloudApplicationNotification
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname



Write-Host "#########>Begin Audit Process Creation audit<#########" -ForegroundColor DarkGreen
$id = "APC" + "18.9.3.1"
$outputLine = "$id" + ";" + "(L1) Ensure 'Include command line in process creation events' is set to 'Enabled',value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" |Select-Object ProcessCreationIncludeCmdLine_Enabled
 $policyValue = $policyValue.ProcessCreationIncludeCmdLine_Enabled
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname






Write-Host "#########>Begin Credential Delegation audit<#########" -ForegroundColor DarkGreen




$id = "CD" + "18.9.4.1"
$outputLine = "$indextest" + ";" + "(L1) Ensure 'Encryption Oracle Remediation' is set to 'Enabled: Force Updated Clients', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" |Select-Object AllowEncryptionOracle
 $policyValue = $policyValue.AllowEncryptionOracle
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname



$id = "CD" + "$indextest"
$outputLine = "$indextest" + ";" + "(L1) Ensure 'Remote host allows delegation of non-exportable credentials' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" |Select-Object AllowProtectedCreds
 $policyValue = $policyValue.AllowProtectedCreds
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname




Write-Host "#########>Begin Device Guard audit<#########" -ForegroundColor DarkGreen


$id = "DG" + "18.9.5.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Turn On Virtualization Based Security' is set to 'Enabled' (Scored), value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" |Select-Object EnableVirtualizationBasedSecurity
 $policyValue = $policyValue.EnableVirtualizationBasedSecurity
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname



$id = "DG" + "18.9.5.2"
$outputLine = "$id" + ";" + "(L1)Ensure 'Turn On Virtualization Based Security: Select Platform Security Level' is set to 'Secure Boot and DMA Protection', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" |Select-Object RequirePlatformSecurityFeatures
 $policyValue = $policyValue.RequirePlatformSecurityFeatures
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname



$id = "DG" + "18.9.5.3"
$outputLine = "$id" + ";" + "(L1)Ensure 'Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity' is set to 'Enabled with UEFI lock' (Scored), value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" |Select-Object HypervisorEnforcedCodeIntegrity
 $policyValue = $policyValue.HypervisorEnforcedCodeIntegrity
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "DG" + "18.9.5.4"
$outputLine = "$id" + ";" + "(L1)Ensure 'Turn On Virtualization Based Security: Require UEFI Memory Attributes Table' is set to 'True (checked)', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" |Select-Object HVCIMATRequired
 $policyValue = $policyValue.HVCIMATRequired
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname



$id = "DG" + "18.9.5.5"
$outputLine = "$id" + ";" + "(L1)Ensure 'Turn On Virtualization Based Security: Credential Guard Configuration' is set to 'Enabled with UEFI lock', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" |Select-Object LsaCfgFlags
 $policyValue = $policyValue.LsaCfgFlags
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname



$id = "DG" + "18.9.5.6"
$outputLine = "$id" + ";" + "(L1)Ensure 'Turn On Virtualization Based Security: Credential Guard Configuration' is set to 'Enabled with UEFI lock', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" |Select-Object ConfigureSystemGuardLaunch
 $policyValue = $policyValue.ConfigureSystemGuardLaunch
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "DG" + "18.9.5.7"
$outputLine = "$id" + ";" + "(L1)Ensure 'Turn On Virtualization Based Security: Kernel-mode Hardware-enforced Stack Protection' is set to 'Enabled: Enabled in enforcement mode', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" |Select-Object ConfigureKernelShadowStacksLaunch
 $policyValue = $policyValue.ConfigureKernelShadowStacksLaunch
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname




Write-Host "#########>Begin Device Installation Restrictions audit<#########" -ForegroundColor DarkGreen


$id = "DIR" + "18.9.7.1.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Prevent installation of devices that match any of these device IDs' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" |Select-Object DenyDeviceIDs
 $policyValue = $policyValue.DenyDeviceIDs
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "DIR" + "18.9.7.1.2"
$outputLine = "$id" + ";" + "Ensure 'Prevent installation of devices that match any of these device IDs' is set to 'Enabled', value must be PCI\CC_0C0A " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs" |Select-Object 1
 $policyValue = $policyValue.1
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "DIR" + "18.9.7.1.3"
$outputLine = "$id" + ";" + "(L1)Ensure 'Prevent installation of devices that match any of these device IDs' is set to 'Enabled', value must be PCI\CC_0C0A " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" |Select-Object DenyDeviceIDsRetroactive
 $policyValue = $policyValue.DenyDeviceIDsRetroactive
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "DIR" + "18.9.7.1.4"
$outputLine = "$id" + ";" + "(L1)Ensure 'Prevent installation of devices using drivers that match these device setup classes' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" |Select-Object DenyDeviceClasses
 $policyValue = $policyValue.DenyDeviceClasses
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "DIR" + "18.9.7.1.5"
$outputLine = "$id" + ";" + "(L1)Ensure 'Prevent installation of devices using drivers that match these device setup classes: Prevent installation of devices using drivers for these device setup' is set to 'IEEE 1394 device setup classes, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses" |Select-Object "{d48179be-ec20-11d1-b6b8-00c04fa372a7}"
 $policyValue = $policyValue."{d48179be-ec20-11d1-b6b8-00c04fa372a7}"
 $policyValueBuffer = "{d48179be-ec20-11d1-b6b8-00c04fa372a7}" + ":" + "$policyValue" + "|"
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses" |Select-Object "{7ebefbc0-3200-11d2-b4c2-00a0C9697d07}"
 $policyValue = $policyValue."{7ebefbc0-3200-11d2-b4c2-00a0C9697d07}"
 $policyValueBuffer += "{7ebefbc0-3200-11d2-b4c2-00a0C9697d07}" + ":" + "$policyValue" + "|"
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses" |Select-Object "{c06ff265-ae09-48f0-812c-16753d7cba83}"
 $policyValue = $policyValue."{c06ff265-ae09-48f0-812c-16753d7cba83}"
 $policyValueBuffer += "{c06ff265-ae09-48f0-812c-16753d7cba83}" + ":" + "$policyValue" + "|"
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses" |Select-Object "{6bdd1fc1-810f-11d0-bec7-08002be2092f}"
 $policyValue = $policyValue."{6bdd1fc1-810f-11d0-bec7-08002be2092f}"
 $policyValueBuffer += "{6bdd1fc1-810f-11d0-bec7-08002be2092f}" + ":" + "$policyValue" + "|"
 $policyValue = $policyValueBuffer 
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname




$id = "DIR" + "18.9.7.1.6"
$outputLine = "$id" + ";" + "(L1)Ensure 'Prevent installation of devices using drivers that match these device setup classes: Also apply to matching devices that are already installed.' is set to 'True', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" |Select-Object DenyDeviceClassesRetroactive
 $policyValue = $policyValue.DenyDeviceClassesRetroactive
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname



$id = "DIR" + "18.9.7.2"
$outputLine = "$id" + ";" + "(L1)Ensure 'Prevent device metadata retrieval from the Internet' is set to 'Enabled'''' is set to 'True', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" |Select-Object PreventDeviceMetadataFromNetwork
 $policyValue = $policyValue.PreventDeviceMetadataFromNetwork
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname




Write-Host "#########>Begin Early Launch Antimalware audit<#########" -ForegroundColor DarkGreen


$id = "ELA" + "18.9.13.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical, value must be 3 " + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" |Select-Object driverLoadPolicy
 $policyValue = $policyValue.driverLoadPolicy
}
else {
 $policyValue = "no configuration"
}

$outputLine += $policyValue
$outputLine>> $fname


Write-Host "#########>Begin Logging and tracing audit<#########" -ForegroundColor DarkGreen



$id = "LT" + "18.9.19.2"
$outputLine = "$id" + ";" + "(L1)Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" |Select-Object NoBackgroundPolicy
 $policyValue = $policyValue.NoBackgroundPolicy
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname



$id = "LT" + "18.9.19.3"
$outputLine = "$id" + ";" + "(L1)Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" |Select-Object NoGPOListChanges
 $policyValue = $policyValue.NoGPOListChanges
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "LT" + "18.9.19.4"
$outputLine = "$id" + ";" + "(L1)Ensure 'Continue experiences on this device' is set to 'Disabled, value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" |Select-Object EnableCdp
 $policyValue = $policyValue.EnableCdp
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname





$id = "LT" + "18.9.19.5"
$outputLine = "$id" + ";" + "(L1)Ensure 'Turn off background refresh of Group Policy' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" |Select-Object DisableBkGndGroupPolicy
 $policyValue = $policyValue.DisableBkGndGroupPolicy
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

Write-Host "#########>Begin Internet Communication Management audit<#########" -ForegroundColor DarkGreen


$id = "ICS" + "18.9.20.1.1"
$outputLine = "$id" + ";" + "(L1)Ensure Turn off access to the Store is set to Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" |Select-Object NoUseStoreOpenWith
 $policyValue = $policyValue.NoUseStoreOpenWith
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "ICS" + "18.9.20.1.2"
$outputLine = "$id" + ";" + "(L1)Ensure Turn off downloading of print drivers over HTTP, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" |Select-Object DisableWebPnPDownload
 $policyValue = $policyValue.DisableWebPnPDownload
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "ICS" + "18.9.20.1.3"
$outputLine = "$id" + ";" + "(L2)Ensure Turn off handwriting personalization data sharing is set to Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" |Select-Object PreventHandwritingDataSharing
 $policyValue = $policyValue.PreventHandwritingDataSharing
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "ICS" + "18.9.20.1.4"
$outputLine = "$id" + ";" + "(L2)Ensure Turn off handwriting recognition error reporting is set to Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" |Select-Object PreventHandwritingErrorReports
 $policyValue = $policyValue.PreventHandwritingErrorReports
}
else {
 $policyValue = "no configuration"
}

$id = "ICS" + "18.9.20.1.5"

$outputLine = "$id" + ";" + "(L2)Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com is set to Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard" |Select-Object ExitOnMSICW
 $policyValue = $policyValue.ExitOnMSICW
}
else {
 $policyValue = "no configuration"
}




$id = "ICS" + "18.9.20.1.6"


$outputLine = "$id" + ";" + "(L1)Ensure Turn off Internet download for Web publishing and online ordering wizards is set to 'Enabled' , value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" |Select-Object NoWebServices
 $policyValue = $policyValue.NoWebServices
}
else {
 $policyValue = "no configuration"
}

$id = "ICS" + "18.9.20.1.7"

$outputLine = "$id" + ";" + "(L2)Ensure Turn off printing over HTTP is set to Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" |Select-Object DisableHTTPPrinting
 $policyValue = $policyValue.DisableHTTPPrinting
}
else {
 $policyValue = "no configuration"
}

$id = "ICS" + "18.9.20.1.8"

$outputLine = "$id" + ";" + "(L2)Ensure Turn off Registration if URL connection is referring to Microsoft.com is set to Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control" |Select-Object NoRegistration
 $policyValue = $policyValue.NoRegistration
}
else {
 $policyValue = "no configuration"
}



$id = "ICS" + "18.9.20.1.9"

$outputLine = "$id" + ";" + "(L2)Ensure Turn off Search Companion content file updates is set to Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion" |Select-Object DisableContentFileUpdates
 $policyValue = $policyValue.DisableContentFileUpdates
}
else {
 $policyValue = "no configuration"
}


$id = "ICS" + "18.9.20.1.10"

$outputLine = "$id" + ";" + "(L2)Ensure Turn off the Order Prints picture task is set to Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" |Select-Object NoOnlinePrintsWizard
 $policyValue = $policyValue.NoOnlinePrintsWizard
}
else {
 $policyValue = "no configuration"
}


$id = "ICS" + "18.9.20.1.11"

$outputLine = "$id" + ";" + "(L2)Ensure 'Turn off the Publish to Web task for files and folders is set to Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" |Select-Object NoPublishingWizard
 $policyValue = $policyValue.NoPublishingWizard
}
else {
 $policyValue = "no configuration"
}


$id = "ICS" + "18.9.20.1.12"

$outputLine = "$id" + ";" + "(L2)Ensure Turn off the Windows Messenger Customer Experience Improvement Program is set to Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client" |Select-Object CEIP
 $policyValue = $policyValue.CEIP
}
else {
 $policyValue = "no configuration"
}

$id = "ICS" + "18.9.20.1.13"

$outputLine = "$id" + ";" + "(L2)Ensure Turn off Windows Customer Experience Improvement Program is set to Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" |Select-Object CEIPEnable
 $policyValue = $policyValue.CEIPEnable
}
else {
 $policyValue = "no configuration"
}

$id = "ICS" + "18.9.20.1.14"

$outputLine = "$id" + ";" + "(L2)Ensure Turn off Windows Error Reporting is set to Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" |Select-Object Disabled
 $policyValue = $policyValue.Disabled
}
else {
 $policyValue = "no configuration"
}

Write-Host "#########>Begin Kerberos audit<#########" -ForegroundColor DarkGreen

$id = "KER" + "18.9.23.1"

$outputLine = "$id" + ";" + "(L2)Ensure 'Support device authentication using certificate' is set to 'Enabled: Automatic, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters" |Select-Object DevicePKInitBehavior
 $policyValue = $policyValue.DevicePKInitBehavior
 $policyValueBuffer = "DevicePKInitBehavior" + ":" + "$policyValue" + "|"
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters" |Select-Object DevicePKInitEnabled
 $policyValue = $policyValue.DevicePKInitEnabled
 $policyValueBuffer = "DevicePKInitEnabled" + ":" + "$policyValue" + "|"
}
else {
 $policyValueBuffer = "no configuration"
}

Write-Host "#########>Begin Kernel DMA Protection audit<#########" -ForegroundColor DarkGreen


$id = "KDP" + "18.9.24.1"

$outputLine = "$id" + ";" + "(L1)Ensure 'Enumeration policy for external devices incompatible with Kernel DMA Protection' is set to 'Enabled: Block All', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection" |Select-Object DeviceEnumerationPolicy
 $policyValue = $policyValue.DeviceEnumerationPolicy
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

Write-Host "#########>Begin Local Security Authority audit<#########" -ForegroundColor DarkGreen

$id = "LSA" + "18.9.25.1"

$outputLine = "$id" + ";" + "(L1) Ensure 'Allow Custom SSPs and APs to be loaded into LSASS' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" |Select-Object AllowCustomSSPsAPs
 $policyValue = $policyValue.AllowCustomSSPsAPs
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "LSA" + "18.9.25.2"

$outputLine = "$id" + ";" + "(L1) Ensure 'Configures LSASS to run as a protected process' is set to 'Enabled: Enabled with UEFI Lock', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" |Select-Object RunAsPPL
 $policyValue = $policyValue.RunAsPPL
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

Write-Host "#########>Begin Locale Services audit<#########" -ForegroundColor DarkGreen


$id = "LS" + "18.9.26.1"

$outputLine = "$id" + ";" + "(L2)Ensure Disallow copying of user input methods to the system account for sign-in is set to Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International" |Select-Object BlockUserInputMethodsForSignIn
 $policyValue = $policyValue.BlockUserInputMethodsForSignIn
}
else {
 $policyValue = "no configuration"
}


Write-Host "#########>Begin Logon audit<#########" -ForegroundColor DarkGreen


$id = "LOGON" + "18.9.27.1"

$outputLine = "$id" + ";" + "(L1)Ensure Block user from showing account details on sign-in is set to Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" |Select-Object BlockUserFromShowingAccountDetailsOnSignin
 $policyValue = $policyValue.BlockUserFromShowingAccountDetailsOnSignin
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "LOGON" + "18.9.27.2"

$outputLine = "$id" + ";" + "(L1)Ensure Do not display network selection UI is set to Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" |Select-Object DontDisplayNetworkSelectionUI
 $policyValue = $policyValue.DontDisplayNetworkSelectionUI
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "LOGON" + "18.9.27.3"

$outputLine = "$id" + ";" + "Ensure Do not enumerate connected users on domain-joined computers is set to Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" |Select-Object DontEnumerateConnectedUsers
 $policyValue = $policyValue.DontEnumerateConnectedUsers
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "LOGON" + "18.9.27.4"
$outputLine = "$id" + ";" + "(L1)Ensure 'Enumerate local users on domain-joined computers' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" |Select-Object EnumerateLocalUsers
 $policyValue = $policyValue.EnumerateLocalUsers
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname



$id = "LOGON" + "18.9.27.5"
$outputLine = "$id" + ";" + "(L1)Ensure Turn off app notifications on the lock screen is set to Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" |Select-Object DisableLockScreenAppNotifications
 $policyValue = $policyValue.DisableLockScreenAppNotifications
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "LOGON" + "18.9.27.6"

$outputLine = "$id" + ";" + "(L1)Ensure 'Turn off picture password sign-in' is set to 'Enabled', value must be1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" |Select-Object BlockDomainPicturePassword
 $policyValue = $policyValue.BlockDomainPicturePassword
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "LOGON" + "18.9.27.7"
$outputLine = "$id" + ";" + "(L1)Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" |Select-Object AllowDomainPINLogon
 $policyValue = $policyValue.AllowDomainPINLogon
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


Write-Host "#########>Begin OS Policies audit<#########" -ForegroundColor DarkGreen

$id = "OP" + "18.9.30.1"
$outputLine = "$id" + ";" + "(L2) Ensure 'Allow Clipboard synchronization across devices' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" |Select-Object AllowCrossDeviceClipboard
 $policyValue = $policyValue.AllowCrossDeviceClipboard
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "OP" + "18.9.30.2"
$outputLine = "$id" + ";" + "(L2) Ensure 'Allow upload of User Activities' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" |Select-Object UploadUserActivities
 $policyValue = $policyValue.UploadUserActivities
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname



Write-Host "#########>Begin Sleep Settings audit<#########" -ForegroundColor DarkGreen

$id = "SLEEP" + "18.9.32.6.1"
$outputLine = "$id" + ";" + "(L1) Ensure 'Allow network connectivity during connected-standby (on battery)' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" |Select-Object DCSettingIndex
 $policyValue = $policyValue.DCSettingIndex
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "SLEEP" + "18.9.32.6.2"
$outputLine = "$id" + ";" + "(L1) Ensure 'Allow network connectivity during connected-standby (plugged in)' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" |Select-Object ACSettingIndex
 $policyValue = $policyValue.ACSettingIndex
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "SLEEP" + "18.9.32.6.3"
$outputLine = "$id" + ";" + "(L1) Ensure 'Allow standby states (S1-S3) when sleeping (on battery)' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab" |Select-Object DCSettingIndex
 $policyValue = $policyValue.DCSettingIndex
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "SLEEP" + "18.9.32.6.4"
$outputLine = "$id" + ";" + "(L1) Ensure 'Allow standby states (S1-S3) when sleeping (plugged in)' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab" |Select-Object ACSettingIndex
 $policyValue = $policyValue.ACSettingIndex
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "SLEEP" + "18.9.32.6.5"
$outputLine = "$id" + ";" + "(L1) Ensure 'Require a password when a computer wakes (on battery)' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" |Select-Object DCSettingIndex
 $policyValue = $policyValue.DCSettingIndex
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "SLEEP" + "18.9.32.6.6"
$outputLine = "$id" + ";" + "(L1) Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" |Select-Object ACSettingIndex
 $policyValue = $policyValue.ACSettingIndex
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname



Write-Host "#########>Begin Remote Assistance audit<#########" -ForegroundColor DarkGreen

$id = "RA" + "18.9.34.1"
$outputLine = "$id" + ";" + "(L1) Ensure 'Configure Offer Remote Assistance' is set to 'Disabled, value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |Select-Object fAllowUnsolicited
 $policyValue = $policyValue.fAllowUnsolicited
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "RA" + "18.9.34.2"
$outputLine = "$id" + ";" + "(L1) Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |Select-Object fAllowToGetHelp
 $policyValue = $policyValue.fAllowToGetHelp
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

Write-Host "#########>Begin Remote Procedure Call audit<#########" -ForegroundColor DarkGreen

$id = "RPC" + "18.9.35.1"
$outputLine = "$id" + ";" + "(L1) Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" |Select-Object EnableAuthEpResolution
 $policyValue = $policyValue.EnableAuthEpResolution
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "RPC" + "18.9.35.2"
$outputLine = "$id" + ";" + "(L1) Ensure 'Restrict Unauthenticated RPC clients' is set to 'Enabled: Authenticated', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" |Select-Object RestrictRemoteClients
 $policyValue = $policyValue.RestrictRemoteClients
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

Write-Host "#########>Begin Microsoft Support Diagnostic Tool audit<#########" -ForegroundColor DarkGreen


$id = "MSDT" + "18.9.46.5.1"
$outputLine = "$id" + ";" + "(L2) Ensure 'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider' is set to 'Disabled, value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" |Select-Object DisableQueryRemoteServer
 $policyValue = $policyValue.DisableQueryRemoteServer
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


Write-Host "#########>Begin Windows Performance PerfTrack audit<#########" -ForegroundColor DarkGreen


$id = "WPP" + "18.9.46.11.1"
$outputLine = "$id" + ";" + "(L2) Ensure 'Enable/Disable PerfTrack' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" |Select-Object ScenarioExecutionEnabled
 $policyValue = $policyValue.ScenarioExecutionEnabled
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


Write-Host "#########>Begin User Profiles audit<#########" -ForegroundColor DarkGreen


$id = "UP" + "18.9.48.1"
$outputLine = "$id" + ";" + "(L2) Ensure 'Turn off the advertising ID' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\policies\Microsoft\Windows\AdvertisingInfo" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\policies\Microsoft\Windows\AdvertisingInfo" |Select-Object DisabledByGroupPolicy
 $policyValue = $policyValue.DisabledByGroupPolicy
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


Write-Host "#########>Begin Time Providers audit<#########" -ForegroundColor DarkGreen


$id = "TP" + "18.9.50.1.1"
$outputLine = "$id" + ";" + "(L2) Ensure 'Enable Windows NTP Client' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient" |Select-Object Enabled
 $policyValue = $policyValue.Enabled
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "TP" + "18.9.50.1.2"
$outputLine = "$id" + ";" + "(L2) Ensure 'Enable Windows NTP Server' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer" |Select-Object Enabled
 $policyValue = $policyValue.Enabled
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

Write-Host "#########>Begin App Package Deployment audit<#########" -ForegroundColor DarkGreen


$id = "APD" + "18.10.3.1"
$outputLine = "$id" + ";" + "(L2) Ensure Allow a Windows app to share application data between users, value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager" |Select-Object AllowSharedLocalAppData
 $policyValue = $policyValue.AllowSharedLocalAppData
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "APD" + "18.10.3.2"
$outputLine = "$id" + ";" + "Ensure 'Prevent non-admin users from installing packaged Windows apps' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx" |Select-Object BlockNonAdminUserInstall
 $policyValue = $policyValue.BlockNonAdminUserInstall
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

Write-Host "#########>Begin App Privacy audit<#########" -ForegroundColor DarkGreen

$id = "APP" + "18.10.4.1"
$outputLine = "$id" + ";" + "(L1) Ensure 'Let Windows apps activate with voice while the system is locked' is set to 'Enabled: Force Deny', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" |Select-Object LetAppsActivateWithVoiceAboveLock
 $policyValue = $policyValue.LetAppsActivateWithVoiceAboveLock
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


Write-Host "#########>Begin App runtime audit<#########" -ForegroundColor DarkGreen


$id = "AR" + "18.10.5.1"

$outputLine = "$id" + ";" + "(L1) Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" |Select-Object MSAOptional
 $policyValue = $policyValue.MSAOptional
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "AR" + "18.10.5.2"
$outputLine = "$id" + ";" + "(L2)Ensure 'Block launching Windows Store apps with Windows Runtime API access from hosted content.' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" |Select-Object BlockHostedAppAccessWinRT
 $policyValue = $policyValue.BlockHostedAppAccessWinRT
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

Write-Host "#########>Begin AutoPlay Policies audit<#########" -ForegroundColor DarkGreen


$id = "AP" + "18.10.7.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" |Select-Object NoAutoplayfornonVolume
 $policyValue = $policyValue.NoAutoplayfornonVolume
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname
$id = "AP" + "18.10.7.2"
$outputLine = "$id" + ";" + "(L1)Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" |Select-Object NoAutorun
 $policyValue = $policyValue.NoAutorun
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "AP" + "18.10.7.3"
$outputLine = "$id" + ";" + "(L1)Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'', value must be B5 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" |Select-Object NoDriveTypeAutoRun
 $policyValue = $policyValue.NoDriveTypeAutoRun
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


Write-Host "#########>Begin Facial Features audit<#########" -ForegroundColor DarkGreen


$id = "FF" + "18.10.8.1.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Use enhanced anti-spoofing when available' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" |Select-Object EnhancedAntiSpoofing
 $policyValue = $policyValue.EnhancedAntiSpoofing
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

Write-Host "#########>Begin BitLocker Drive Encryption audit<#########" -ForegroundColor DarkGreen


$id = "BDE" + "18.10.9.1.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Allow access to BitLocker-protected fixed data drives from earlier versions of Windows' is set to 'Disabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object FDVDiscoveryVolumeType
 $policyValue = $policyValue.FDVDiscoveryVolumeType
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "BDE" + "18.10.9.1.2"
$outputLine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected fixed drives can be recovered' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object FDVRecovery
 $policyValue = $policyValue.FDVRecovery
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname



$id = "BDE" + "18.10.9.1.3"
$outputLine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Allow data recovery agent' is set to 'Enabled: True', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object FDVManageDRA
 $policyValue = $policyValue.FDVManageDRA
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "BDE" + "18.10.9.1.4"
$outputLine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Recovery Password' is set to 'Enabled: Allow 48-digit recovery password', value must be 2 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object FDVRecoveryPassword
 $policyValue = $policyValue.FDVRecoveryPassword
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "BDE" + "18.10.9.1.5"
$outputLine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Recovery Key' is set to 'Enabled: Allow 256-bit recovery key', value must be 2 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object FDVRecoveryKey
 $policyValue = $policyValue.FDVRecoveryKey
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname



$id = "BDE" + "18.10.9.1.6"
$outputLine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Omit recovery options from the BitLocker setup wizard' is set to 'Enabled: True', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object FDVHideRecoveryPage
 $policyValue = $policyValue.FDVHideRecoveryPage
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "BDE" + "18.10.9.1.7"
$outputLine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Save BitLocker recovery information to AD DS for fixed data drives' is set to 'Enabled: False', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object FDVActiveDirectoryBackup
 $policyValue = $policyValue.FDVActiveDirectoryBackup
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "BDE" + "18.10.9.1.8"
$outputLine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Configure storage of BitLocker recovery information to AD DS' is set to 'Enabled: Backup recovery passwords and key packages', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object FDVActiveDirectoryBackup
 $policyValue = $policyValue.FDVActiveDirectoryBackup
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "BDE" + "18.10.9.1.9"
$outputLine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Do not enable BitLocker until recovery information is stored to AD DS for fixed data drives' is set to 'Enabled: False', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object FDVRequireActiveDirectoryBackup
 $policyValue = $policyValue.FDVRequireActiveDirectoryBackup
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "BDE" + "18.10.9.1.10"
$outputLine = "$id" + ";" + "(L1)Ensure 'Configure use of hardware-based encryption for fixed data drives' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object FDVHardwareEncryption
 $policyValue = $policyValue.FDVHardwareEncryption
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "BDE" + "18.10.9.1.11"
$outputLine = "$id" + ";" + "(L1)Ensure 'Configure use of passwords for fixed data drives' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object FDVPassphrase
 $policyValue = $policyValue.FDVPassphrase
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname




$id = "BDE" + "18.10.9.1.12"
$outputLine = "$id" + ";" + "(L1)Ensure 'Configure use of smart cards on fixed data drives' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object FDVAllowUserCert
 $policyValue = $policyValue.FDVAllowUserCert
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname



$id = "BDE" + "18.10.9.1.13"
$outputLine = "$id" + ";" + "(L1)Ensure 'Configure use of smart cards on fixed data drives: Require use of smart cards on fixed data drives' is set to 'Enabled: True', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object FDVEnforceUserCert
 $policyValue = $policyValue.FDVEnforceUserCert
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

Write-Host "#########>Begin Operating System Drivesn audit<#########" -ForegroundColor DarkGreen


$id = "OSD" + "18.10.9.2.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Allow enhanced PINs for startup' is set to 'Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object UseEnhancedPin
 $policyValue = $policyValue.UseEnhancedPin
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "OSD" + "18.10.9.2.2"
$outputLine = "$id" + ";" + "(L1)Ensure 'Allow Secure Boot for integrity validation' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object OSAllowSecureBootForIntegrity
 $policyValue = $policyValue.OSAllowSecureBootForIntegrity
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "OSD" + "18.10.9.2.3"
$outputLine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected operating system drives can be recovered' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object OSRecovery
 $policyValue = $policyValue.OSRecovery
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "OSD" + "18.10.9.2.4"
$outputLine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Allow data recovery agent' is set to 'Enabled: False', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object OSManageDRA
 $policyValue = $policyValue.OSManageDRA
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "OSD" + "18.10.9.2.5"
$outputLine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Recovery Password' is set to 'Enabled: Require 48-digit recovery password', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object OSRecoveryPassword
 $policyValue = $policyValue.OSRecoveryPassword
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "OSD" + "18.10.9.2.6"
$outputLine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Recovery Key' is set to 'Enabled: Do not allow 256-bit recovery key', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object OSRecoveryKey
 $policyValue = $policyValue.OSRecoveryKey
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "OSD" + "18.10.9.2.7"
$outputLine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Omit recovery options from the BitLocker setup wizard' is set to 'Enabled: True', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object OSHideRecoveryPage
 $policyValue = $policyValue.OSHideRecoveryPage
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "OSD" + "18.10.9.2.8"
$outputLine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Save BitLocker recovery information to AD DS for operating system drives' is set to 'Enabled: True', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object OSActiveDirectoryBackup
 $policyValue = $policyValue.OSActiveDirectoryBackup
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "OSD" + "18.10.9.2.9"
$outputLine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Configure storage of BitLocker recovery information to AD DS:' is set to 'Enabled: Store recovery passwords and key packages'', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object OSActiveDirectoryInfoToStore
 $policyValue = $policyValue.OSActiveDirectoryInfoToStore
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "OSD" + "18.10.9.2.10"
$outputLine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Do not enable BitLocker until recovery information is stored to AD DS for operating system drives', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object OSRequireActiveDirectoryBackup
 $policyValue = $policyValue.OSRequireActiveDirectoryBackup
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "OSD" + "18.10.9.2.11"
$outputLine = "$id" + ";" + "(L1)Ensure 'Configure use of hardware-based encryption for operating system drives' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object OSHardwareEncryption
 $policyValue = $policyValue.OSHardwareEncryption
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "OSD" + "18.10.9.2.12"
$outputLine = "$id" + ";" + "(L1)Ensure 'Configure use of passwords for operating system drives' is set to 'Disabled'', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object OSPassphrase
 $policyValue = $policyValue.OSPassphrase
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname




$id = "OSD" + "18.10.9.2.13"
$outputLine = "$id" + ";" + "Ensure 'Require additional authentication at startup' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object UseAdvancedStartup
 $policyValue = $policyValue.UseAdvancedStartup
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname



$id = "OSD" + "18.10.9.2.14"
$outputLine = "$id" + ";" + "Ensure 'Require additional authentication at startup: Allow BitLocker without a compatible TPM' is set to 'Enabled: False', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object EnableBDEWithNoTPM
 $policyValue = $policyValue.EnableBDEWithNoTPM
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


Write-Host "#########>Begin Removable Data Drives audit<#########" -ForegroundColor DarkGreen


$id = "RDD" + "18.10.9.3.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Allow access to BitLocker-protected removable data drives from earlier versions of Windows' is set to 'Disabled', value must be empty " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object RDVDiscoveryVolumeType
 $policyValue = $policyValue.RDVDiscoveryVolumeType
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "RDD" + "18.10.9.3.2"
$outputLine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected removable drives can be recovered' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object RDVRecovery
 $policyValue = $policyValue.RDVRecovery
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "RDD" + "18.10.9.3.3"
$outputLine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected removable drives can be recovered: Allow data recovery agent' is set to 'Enabled: True', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object RDVManageDRA
 $policyValue = $policyValue.RDVManageDRA
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "RDD" + "18.10.9.3.4"
$outputLine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected removable drives can be recovered: Recovery Password' is set to 'Enabled: Do not allow 48-digit recovery password', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object RDVRecoveryPassword
 $policyValue = $policyValue.RDVRecoveryPassword
}
else {
 $policyValue = "no configuration"
}



$id = "RDD" + "18.10.9.3.5"
$outputLine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected removable drives can be recovered: Recovery Key' is set to 'Enabled: Do not allow 256-bit recovery key', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object RDVRecoveryKey
 $policyValue = $policyValue.RDVRecoveryKey
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname



$id = "RDD" + "18.10.9.3.6"
$outputLine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected removable drives can be recovered: Omit recovery options from the BitLocker setup wizard' is set to 'Enabled: True', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object RDVHideRecoveryPage
 $policyValue = $policyValue.RDVHideRecoveryPage
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "RDD" + "18.10.9.3.7"
$outputLine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected removable drives can be recovered: Save BitLocker recovery information to AD DS for removable data drives' is set to 'Enabled: False', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object RDVActiveDirectoryBackup
 $policyValue = $policyValue.RDVActiveDirectoryBackup
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "RDD" + "18.10.9.3.8"
$outputLine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected removable drives can be recovered: Configure storage of BitLocker recovery information to AD DS:' is set to 'Enabled: Backup recovery passwords and key packages', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object RDVActiveDirectoryInfoToStore
 $policyValue = $policyValue.RDVActiveDirectoryInfoToStore
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname



$id = "RDD" + "18.10.9.3.9"
$outputLine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected removable drives can be recovered: Do not enable BitLocker until recovery information is stored to AD DS for removable data drives' is set to 'Enabled: False', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object RDVRequireActiveDirectoryBackup
 $policyValue = $policyValue.RDVRequireActiveDirectoryBackup
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "RDD" + "18.10.9.3.10"
$outputLine = "$id" + ";" + "(L1)Ensure 'Ensure 'Configure use of hardware-based encryption for removable data drives' is set to 'Disabled'', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object RDVHardwareEncryption
 $policyValue = $policyValue.RDVHardwareEncryption
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "RDD" + "18.10.9.3.11"
$outputLine = "$id" + ";" + "(L1)Ensure 'Configure use of passwords for removable data drives' is set to 'Disable, value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object RDVPassphrase
 $policyValue = $policyValue.RDVPassphrase
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "RDD" + "18.10.9.3.12"
$outputLine = "$id" + ";" + "(L1)Ensure 'Configure use of smart cards on removable data drives' is set to 'Enabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object RDVAllowUserCert
 $policyValue = $policyValue.RDVAllowUserCert
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "RDD" + "18.10.9.3.13"
$outputLine = "$id" + ";" + "(L1)Ensure 'Configure use of smart cards on removable data drives: Require use of smart cards on removable data drives' is set to 'Enabled: True', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object RDVEnforceUserCert
 $policyValue = $policyValue.RDVEnforceUserCert
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "RDD" + "18.10.9.3.14"
$outputLine = "$id" + ";" + "(L1)Ensure 'Deny write access to removable drives not protected by BitLocker' is set to 'Enabled'', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object RDVDenyWriteAccess
 $policyValue = $policyValue.RDVDenyWriteAccess
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "RDD" + "18.10.9.3.15"
$outputLine = "$id" + ";" + "(L1)Ensure 'Deny write access to removable drives not protected by BitLocker: Do not allow write access to devices configured in another organization' is set to 'Enabled: False', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object RDVDenyCrossOrg
 $policyValue = $policyValue.RDVDenyCrossOrg
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname



$id = "RDD" + "18.10.9.4"
$outputLine = "$id" + ";" + "(L1)Ensure 'Disable new DMA devices when this computer is locked' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object DisableExternalDMAUnderLock
 $policyValue = $policyValue.DisableExternalDMAUnderLock
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


Write-Host "#########>Begin Camera audit<#########" -ForegroundColor DarkGreen


$id = "CAM" + "18.10.10.1"
$outputLine = "$id" + ";" + "(L2)Ensure 'Allow Use of Camera' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Camera"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Camera" |Select-Object AllowCamera
 $policyValue = $policyValue.AllowCamera
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

Write-Host "#########>Begin Cloud Content audit<#########" -ForegroundColor DarkGreen



$id = "CLOUD" + "18.10.12.1"
$outputLine = "$id" + ";" + "(L2)Ensure 'Turn off cloud consumer account state content' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" |Select-Object DisableConsumerAccountStateContent
 $policyValue = $policyValue.DisableConsumerAccountStateContent
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "CLOUD" + "18.10.12.2"
$outputLine = "$id" + ";" + "(L2)Ensure 'Turn off cloud optimized content' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" |Select-Object DisableCloudOptimizedContent
 $policyValue = $policyValue.DisableCloudOptimizedContent
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "CLOUD" + "18.10.12.3"
$outputLine = "$id" + ";" + "(L1)Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" |Select-Object DisableWindowsConsumerFeatures
 $policyValue = $policyValue.DisableWindowsConsumerFeatures
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname



Write-Host "#########>Begin Connect audit<#########" -ForegroundColor DarkGreen



$id = "CONNECT" + "18.10.13.1"
$outputLine = "$id" + ";" + "(L1)Ensure Require pin for pairing is set to Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect" |Select-Object RequirePinForPairing
 $policyValue = $policyValue.RequirePinForPairing
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


Write-Host "#########>Begin Credential User Interface audit<#########" -ForegroundColor DarkGreen



$id = "CUI" + "18.10.14.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Do not display the password reveal button' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI" |Select-Object DisablePasswordReveal
 $policyValue = $policyValue.DisablePasswordReveal
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "CUI" + "18.10.14.2"
$outputLine = "$id" + ";" + "(L1)Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" |Select-Object EnumerateAdministrators
 $policyValue = $policyValue.EnumerateAdministrators
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "CUI" + "18.10.14.3"
$outputLine = "$id" + ";" + "(L1)Ensure 'Prevent the use of security questions for local accounts' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" |Select-Object NoLocalPasswordResetQuestions
 $policyValue = $policyValue.NoLocalPasswordResetQuestions
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


Write-Host "#########>Begin Data Collection and Preview Builds audit<#########" -ForegroundColor DarkGreen

$id = "DCPB" + "18.10.15.1"

$outputLine = "$id" + ";" + "(L1)Ensure'Allow Diagnostic Data' is set to 'Enabled: Diagnostic data off (not recommended)' or 'Enabled: Send required diagnostic data'' , value must be 0(recommended) or 1" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" |Select-Object AllowTelemetry
 $policyValue = $policyValue.AllowTelemetry
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname




$id = "DCPB" + "18.10.15.2"
$outputLine = "$id" + ";" + "(L2)Ensure 'Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service' is set to 'Enabled: Disable Authenticated Proxy usage', value must be 1" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" |Select-Object DisableEnterpriseAuthProxy
 $policyValue = $policyValue.DisableEnterpriseAuthProxy
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname



$id = "DCPB" + "18.10.15.3"
$outputLine = "$id" + ";" + "(L1) Ensure 'Disable OneSettings Downloads' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" |Select-Object DisableOneSettingsDownloads
 $policyValue = $policyValue.DisableOneSettingsDownloads
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname



$id = "DCPB" + "18.10.15.4"
$outputLine = "$id" + ";" + "(L1)Ensure 'Do not show feedback notifications' is set to 'Enabled, value must be 1" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" |Select-Object DoNotShowFeedbackNotifications
 $policyValue = $policyValue.DoNotShowFeedbackNotifications
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "DCPB" + "18.10.15.5"
$outputLine = "$id" + ";" + "(L1)Ensure 'Enable OneSettings Auditing' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" |Select-Object EnableOneSettingsAuditing
 $policyValue = $policyValue.EnableOneSettingsAuditing
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "DCPB" + "18.10.15.6"
$outputLine = "$id" + ";" + "(L1)Ensure 'Limit Diagnostic Log Collection is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" |Select-Object LimitDiagnosticLogCollection
 $policyValue = $policyValue.LimitDiagnosticLogCollection
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "DCPB" + "18.10.15.7"
$outputLine = "$id" + ";" + "(L1)Ensure 'Limit Dump Collection' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" |Select-Object LimitDumpCollection
 $policyValue = $policyValue.LimitDumpCollection
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "DCPB" + "18.10.15.8"
$outputLine = "$id" + ";" + "(L1)Ensure 'Toggle user control over Insider builds'is set to 'Disabled, value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" |Select-Object AllowBuildPreview
 $policyValue = $policyValue.AllowBuildPreview
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname



Write-Host "#########>Begin Delivery Optimization audit<#########" -ForegroundColor DarkGreen

$id = "DO" + "18.10.16"
$outputLine = "$id" + ";" + "Ensure 'Download Mode' is NOT set to 'Enabled: Internet' , value must be anything other than 3" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" |Select-Object DODownloadMode
 $policyValue = $policyValue.DODownloadMode
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

Write-Host "#########>Begin Desktop App Installer audit<#########" -ForegroundColor DarkGreen

$id = "DAI" + "18.10.17.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Enable App Installer' is set to 'Disabled, value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" |Select-Object EnableAppInstaller
 $policyValue = $policyValue.EnableAppInstaller
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "DAI" + "18.10.17.2"
$outputLine = "$id" + ";" + "Ensure Ensure 'Enable App Installer Experimental Features' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" |Select-Object EnableExperimentalFeatures
 $policyValue = $policyValue.EnableExperimentalFeatures
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "DAI" + "18.10.17.3"
$outputLine = "$id" + ";" + "Ensure Ensure 'Enable App Installer Hash Override' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" |Select-Object EnableHashOverride
 $policyValue = $policyValue.EnableHashOverride
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "DAI" + "18.10.17.4"
$outputLine = "$id" + ";" + "Ensure Ensure 'Enable App Installer Hash Override' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" |Select-Object EnableMSAppInstallerProtocol
 $policyValue = $policyValue.EnableMSAppInstallerProtocol
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


Write-Host "#########>Begin Application Log audit<#########" -ForegroundColor DarkGreen



$id = "APP" + "18.10.26.1.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" |Select-Object Retention
 $policyValue = $policyValue.Retention
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "APP" + "18.10.26.1.2"
$outputLine = "$id" + ";" + "(L1)Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater', value must be 32,768 or greater " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" |Select-Object MaxSize
 $policyValue = $policyValue.MaxSize
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


Write-Host "#########>Begin Security Log audit<#########" -ForegroundColor DarkGreen


$id = "SECL" + "18.10.26.2.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" |Select-Object Retention
 $policyValue = $policyValue.Retention
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "SECL" + "18.10.26.2.2"
$outputLine = "$id" + ";" + "(L1)Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater', value must be 196,608 or greater " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" |Select-Object MaxSize
 $policyValue = $policyValue.MaxSize
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

Write-Host "#########>Begin Setup Log audit<#########" -ForegroundColor DarkGreen



$id = "SETL" + "18.10.26.3.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled, value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" |Select-Object Retention
 $policyValue = $policyValue.Retention
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname



$id = "SETL" + "18.10.26.3.2"
$outputLine = "$id" + ";" + "(L1)Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater', value must be 32,768 or greater " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" |Select-Object MaxSize
 $policyValue = $policyValue.MaxSize
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname



Write-Host "#########>Begin System Log audit<#########" -ForegroundColor DarkGreen



$id = "SYSL" + "18.10.26.4.1"

$outputLine = "$id" + ";" + "(L1)Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" |Select-Object Retention
 $policyValue = $policyValue.Retention
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname



$id = "SYSL" + "18.10.26.4.2"
$outputLine = "$id" + ";" + "(L1)Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater', value must be 32,768 or greater " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" |Select-Object MaxSize
 $policyValue = $policyValue.MaxSize
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


Write-Host "#########>Begin File Explorer audit<#########" -ForegroundColor DarkGreen


$id = "FE" + "18.10.29.2"
$outputLine = "$id" + ";" + "(L1)Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" |Select-Object NoDataExecutionPrevention
 $policyValue = $policyValue.NoDataExecutionPrevention
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "FE" + "18.10.29.3"
$outputLine = "$id" + ";" + "(L2)Ensure 'Turn off files from Office.com in Quick access view' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" |Select-Object DisableGraphRecentItems
 $policyValue = $policyValue.DisableGraphRecentItems
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname



$id = "FE" + "18.10.29.4"
$outputLine = "$id" + ";" + "(L1)Ensure 'Turn off heap termination on corruption' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" |Select-Object NoHeapTerminationOnCorruption
 $policyValue = $policyValue.NoHeapTerminationOnCorruption
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "FE" + "18.10.29.5"
$outputLine = "$id" + ";" + "(L1)Ensure 'Turn off shell protocol protected mode' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" |Select-Object PreXPSP2ShellProtocolBehavior
 $policyValue = $policyValue.PreXPSP2ShellProtocolBehavior
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

Write-Host "#########>Begin HomeGroup audit<#########" -ForegroundColor DarkGreen


$id = "HOME" + "18.10.33.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Prevent the computer from joining a homegroup' is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HomeGroup"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HomeGroup" |Select-Object DisableHomeGroup
 $policyValue = $policyValue.DisableHomeGroup
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname



Write-Host "#########>Begin Windows Location Provider audit<#########" -ForegroundColor DarkGreen



$id = "WLP" + "18.10.37.2"
$outputLine = "$id" + ";" + "(L2)Ensure 'Turn off location' is set to 'Enabled'', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" |Select-Object DisableLocation
 $policyValue = $policyValue.DisableLocation
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

Write-Host "#########>Begin Messaging audit<#########" -ForegroundColor DarkGreen


$id = "MES" + "18.10.41.1"
$outputLine = "$id" + ";" + "(L2)Ensure 'Allow Message Service Cloud Sync' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging" |Select-Object AllowMessageSync
 $policyValue = $policyValue.AllowMessageSync
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


Write-Host "#########>Begin Microsoft account audit<#########" -ForegroundColor DarkGreen


$id = "MA" + "18.10.42.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Block all consumer Microsoft account user authentication' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount" |Select-Object DisableUserAuth
 $policyValue = $policyValue.DisableUserAuth
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


Write-Host "#########>Begin Microsoft Defender Antivirus <#########" -ForegroundColor DarkGreen
$id = "MDA" + "18.10.43.5.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Configure local setting override for reporting to Microsoft MAPS' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" |Select-Object LocalSettingOverrideSpynetReporting
 $policyValue = $policyValue.LocalSettingOverrideSpynetReporting
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "MDA" + "18.10.43.5.2"
$outputLine = "$id" + ";" + " (L2)Ensure 'Join Microsoft MAPS' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" |Select-Object SpynetReporting
 $policyValue = $policyValue.SpynetReporting
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "MDA" + "18.10.43.6.1.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Configure Attack Surface Reduction rules' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" |Select-Object ExploitGuard_ASR_Rules
 $policyValue = $policyValue.ExploitGuard_ASR_Rules
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "MDA" + "18.10.43.6.1.2"
$outputLine = "$id" + ";" + "(L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is 'configured', value must be 1 foreach key " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" |Select-Object "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84"
 $policyValue = $policyValue."75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84"
 $policyValueBuffer = "Block Office applications from injecting code into other processes" + ":" + "$policyValue" + "|"
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" |Select-Object "3b576869-a4ec-4529-8536-b80a7769e899"
 $policyValue = $policyValue."3b576869-a4ec-4529-8536-b80a7769e899"
 $policyValueBuffer += "Block Office applications from creating executable content" + ":" + "$policyValue" + "|"
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" |Select-Object "d4f940ab-401b-4efc-aadc-ad5f3c50688a"
 $policyValue = $policyValue."d4f940ab-401b-4efc-aadc-ad5f3c50688a"
 $policyValueBuffer += "Block Office applications from creating child processes" + ":" + "$policyValue" + "|"
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" |Select-Object "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b"
 $policyValue = $policyValue."92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b"
 $policyValueBuffer += "Block Win32 API calls from Office macro" + ":" + "$policyValue" + "|"
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" |Select-Object "5beb7efe-fd9a-4556-801d-275e5ffc04cc"
 $policyValue = $policyValue."5beb7efe-fd9a-4556-801d-275e5ffc04cc"
 $policyValueBuffer += "Block execution of potentially obfuscated scripts" + ":" + "$policyValue" + "|"
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" |Select-Object "d3e037e1-3eb8-44c8-a917-57927947596d"
 $policyValue = $policyValue."d3e037e1-3eb8-44c8-a917-57927947596d"
 $policyValueBuffer += "Block JavaScript or VBScript from launching downloaded executable content" + ":" + "$policyValue" + "|"
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" |Select-Object "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"
 $policyValue = $policyValue."be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"
 $policyValueBuffer += "Block executable content from email client and webmail" + ":" + "$policyValue" + "|"
 }
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValueBuffer
$outputLine>> $fname


$id = "MDA" + "18.10.43.6.3.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Prevent users and apps from accessing dangerous websites' is set to 'Enabled: Block', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" |Select-Object EnableNetworkProtection
 $policyValue = $policyValue.EnableNetworkProtection
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "MDA" + "18.10.43.6.3.1"
$outputLine = "$id" + ";" + "(L2)Ensure 'Enable file hash computation feature' is set to 'Enabled' value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" |Select-Object EnableFileHashComputation
 $policyValue = $policyValue.EnableFileHashComputation
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "MDA" + "18.10.43.10.1"
$outputLine = "$id" + ";" + "(L1) Ensure 'Scan all downloaded files and attachments' is set to 'Enabled', value must be 1 or disable if you have another EPP" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" |Select-Object DisableIOAVProtection
 $policyValue = $policyValue.DisableIOAVProtection
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "MDA" + "18.10.43.10.2"
$outputLine = "$id" + ";" + "(L1) Ensure 'Turn off real-time protection' is set to 'Disabled' (Automated), value must be 0 or disable if you have another EPP" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" |Select-Object DisableRealtimeMonitoring
 $policyValue = $policyValue.DisableRealtimeMonitoring
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname



$id = "MDA" + "18.10.43.10.3"
$outputLine = "$id" + ";" + "(L1) Ensure 'Turn on behavior monitoring' is set to 'Enabled', value must be 0  or disable if you have another EPP " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" |Select-Object DisableBehaviorMonitoring
 $policyValue = $policyValue.DisableBehaviorMonitoring
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "MDA" + "18.10.43.10.4"
$outputLine = "$id" + ";" + "(L1) Ensure 'Turn on script scanning' is set to 'Enabled', value must be 0  or disable if you have another EPP " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" |Select-Object DisableScriptScanning
 $policyValue = $policyValue.DisableScriptScanning
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname



$id = "MDA" + "18.10.43.12.1"
$outputLine = "$id" + ";" + "(L2)Ensure 'Configure Watson events' is set to 'Disabled, value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" |Select-Object DisableGenericRePorts
 $policyValue = $policyValue.DisableGenericRePorts
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname




$id = "MDA" + "18.10.43.13.1"
$outputLine = "$id" + ";" + "(L1) Ensure 'Scan removable drives' is set to 'Enabled', value must be 0 or disable if you have another EPP" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" |Select-Object DisableRemovableDriveScanning
 $policyValue = $policyValue.DisableRemovableDriveScanning
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "MDA" + "18.10.43.13.2"
$outputLine = "$id" + ";" + "(L1) Ensure 'Turn on e-mail scanning' is set to 'Enabled', value must be 0 or disable if you have another EPP" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" |Select-Object DisableEmailScanning
 $policyValue = $policyValue.DisableEmailScanning
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "MDA" + "18.10.43.16"
$outputLine = "$id" + ";" + "(L1) Ensure 'Configure detection for potentially unwanted applications' is set to 'Enabled: Block', value must be 1 or disable if you have another EPP " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" |Select-Object PUAProtection
 $policyValue = $policyValue.PUAProtection
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "MDA" + "18.10.43.17"
$outputLine = "$id" + ";" + "(L1)Ensure 'Turn off Windows Defender AntiVirus' is set to 'Disabled', value must be 0 or disable if you have another EPP" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" |Select-Object DisableAntiSpyware
 $policyValue = $policyValue.DisableAntiSpyware
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "MDA" + "18.10.44.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Allow auditing events in Windows Defender Application Guard' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" |Select-Object AuditApplicationGuard
 $policyValue = $policyValue.AuditApplicationGuard
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname




$id = "MDA" + "18.10.44.2"
$outputLine = "$id" + ";" + "(L1)Ensure 'Allow camera and microphone access in Windows Defender Application Guard' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" |Select-Object AllowCameraMicrophoneRedirection
 $policyValue = $policyValue.AllowCameraMicrophoneRedirection
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "MDA" + "18.10.44.3"
$outputLine = "$id" + ";" + "(L1)Ensure 'Allow data persistence for Windows Defender Application Guard' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" |Select-Object AllowPersistence
 $policyValue = $policyValue.AllowPersistence
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "MDA" + "18.10.44.4"
$outputLine = "$id" + ";" + "(L1)Ensure 'Allow files to download and save to the host operating system from Windows Defender Application Guard' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" |Select-Object SaveFilesToHost
 $policyValue = $policyValue.SaveFilesToHost
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname



$id = "MDA" + "18.10.44.5"
$outputLine = "$id" + ";" + "(L1)Ensure 'Configure Windows Defender Application Guard clipboard settings: Clipboard behavior setting' is set to 'Enabled: Enable clipboard operation from an isolated session to the host', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" |Select-Object AppHVSIClipboardSettings
 $policyValue = $policyValue.AppHVSIClipboardSettings
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "MDA" + "18.10.44.6"
$outputLine = "$id" + ";" + "(L1)Ensure 'Turn on Windows Defender Application Guard in Enterprise Mode' is set to 'Enabled', value must be 3 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" |Select-Object AllowAppHVSI_ProviderSet
 $policyValue = $policyValue.AllowAppHVSI_ProviderSet
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

Write-Host "#########>Begin News and interests audit<#########" -ForegroundColor DarkGreen

$id = "NI" + "18.10.50.1"
$outputLine = "$id" + ";" + "(L2)Ensure 'Enable news and interests on the taskbar' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds:"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds:" |Select-Object EnableFeeds
 $policyValue = $policyValue.EnableFeeds
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


Write-Host "#########>Begin OneDrive audit<#########" -ForegroundColor DarkGreen



$id = "OD" + "18.10.50.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Prevent the usage of OneDrive for file storage' is set to 'Enabled'', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" |Select-Object DisableFileSyncNGSC
 $policyValue = $policyValue.DisableFileSyncNGSC
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname



Write-Host "#########>Begin Push To Install audit<#########" -ForegroundColor DarkGreen




$id = "PTI" + "18.10.56.1"
$outputLine = "$id" + ";" + "(L2)Ensure 'Turn off Push To Install service' is set to 'Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\PushToInstall"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\PushToInstall" |Select-Object DisablePushToInstall
 $policyValue = $policyValue.DisablePushToInstall
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


Write-Host "#########>Begin Remote Desktop Services audit<#########" -ForegroundColor DarkGreen


$id = "RDS" + "18.10.57.2.2"
$outputLine = "$id" + ";" + "(L2)Ensure 'Disable Cloud Clipboard integration for server-to-client data transfer' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |Select-Object DisableCloudClipboardIntegration
 $policyValue = $policyValue.DisableCloudClipboardIntegration
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "RDS" + "18.10.57.2.3"
$outputLine = "$id" + ";" + "(L1)Ensure 'Do not allow passwords to be saved' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |Select-Object DisablePasswordSaving
 $policyValue = $policyValue.DisablePasswordSaving
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "RDS" + "18.10.57.3.2.1"
$outputLine = "$id" + ";" + "(L2)Ensure 'Allow users to connect remotely by using Remote Desktop Services' is set to 'Disabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |Select-Object fDenyTSConnections
 $policyValue = $policyValue.fDenyTSConnections
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "RDS" + "18.10.57.3.3.1"
$outputLine = "$id" + ";" + "(L2)Ensure 'Allow UI Automation redirection' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |Select-Object EnableUiaRedirection
 $policyValue = $policyValue.EnableUiaRedirection
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "RDS" + "18.10.57.3.3.2"
$outputLine = "$id" + ";" + "(L2)Ensure 'Do not allow COM port redirection' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |Select-Object fDisableCcm
 $policyValue = $policyValue.fDisableCcm
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "RDS" + "18.10.57.3.3.3"
$outputLine = "$id" + ";" + "(L1)Ensure 'Do not allow drive redirection' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |Select-Object fDisableCdm
 $policyValue = $policyValue.fDisableCdm
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "RDS" + "18.10.57.3.3.4"
$outputLine = "$id" + ";" + "(L1)Ensure 'Do not allow location redirection' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |Select-Object fDisableLocationRedir
 $policyValue = $policyValue.fDisableLocationRedir
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "RDS" + "18.10.57.3.3.5"
$outputLine = "$id" + ";" + "(L2)Ensure 'Do not allow LPT port redirection' is set to 'Enabled'', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |Select-Object fDisableLPT
 $policyValue = $policyValue.fDisableLPT
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "RDS" + "18.10.57.3.3.6"
$outputLine = "$id" + ";" + "(L2)Ensure 'Do not allow supported Plug and Play device redirection' is set to 'Enabled'', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |Select-Object fDisablePNPRedir
 $policyValue = $policyValue.fDisablePNPRedir
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "RDS" + "18.10.57.3.3.7"
$outputLine = "$id" + ";" + "(L2)Ensure 'Do not allow WebAuthn redirection' is set to 'Enabled'', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |Select-Object fDisableWebAuthn
 $policyValue = $policyValue.fDisableWebAuthn
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname



$id = "RDS" + "18.10.57.3.9.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Always prompt for password upon connection' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |Select-Object fPromptForPassword
 $policyValue = $policyValue.fPromptForPassword
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "RDS" + "18.10.57.3.9.2"
$outputLine = "$id" + ";" + "(L1)Ensure 'Require secure RPC communication' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |Select-Object fEncryptRPCTraffic
 $policyValue = $policyValue.fEncryptRPCTraffic
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "RDS" + "18.10.57.3.9.2"
$outputLine = "$id" + ";" + "(L1)Ensure 'Require secure RPC communication' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |Select-Object fEncryptRPCTraffic
 $policyValue = $policyValue.fEncryptRPCTraffic
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "RDS" + "18.10.57.3.9.3"
$outputLine = "$id" + ";" + "(L1)Ensure 'Require use of specific security layer for remote (RDP) connections' is set to 'Enabled: SSL', value must be 2 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |Select-Object SecurityLayer
 $policyValue = $policyValue.SecurityLayer
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "RDS" + "18.10.57.3.9.4"
$outputLine = "$id" + ";" + "(L1)Ensure 'Require user authentication for remote connections by using Network Level Authentication' is set to 'Enabled'', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |Select-Object UserAuthentication
 $policyValue = $policyValue.UserAuthentication
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "RDS" + "18.10.57.3.9.5"
$outputLine = "$id" + ";" + "(L1)Ensure 'Set client connection encryption level' is set to 'Enabled: High Level', value must be 3 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |Select-Object MinEncryptionLevel
 $policyValue = $policyValue.MinEncryptionLevel
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "RDS" + "18.10.57.3.10.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Set time limit for active but idle Remote Desktop Services sessions' is set to 'Enabled: 15 minutes or less', value must be 15 or less " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |Select-Object MaxIdleTime
 $policyValue = $policyValue.MaxIdleTime
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "RDS" + "18.10.57.3.10.2"
$outputLine = "$id" + ";" + "(L2)Ensure 'Set time limit for disconnected sessions' is set to 'Enabled: 1 minute', value must 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |Select-Object MaxDisconnectionTime
 $policyValue = $policyValue.MaxDisconnectionTime
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "RDS" + "18.10.57.3.11.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Do not delete temp folders upon exit' is set to 'Disabled', value must 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |Select-Object DeleteTempDirsOnExit
 $policyValue = $policyValue.DeleteTempDirsOnExit
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


Write-Host "#########>Begin RSS Feeds audit<#########" -ForegroundColor DarkGreen




$id = "RSS" + "18.10.58.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Prevent downloading of enclosures' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" |Select-Object DisableEnclosureDownload
 $policyValue = $policyValue.DisableEnclosureDownload
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


Write-Host "#########>Begin OCR audit<#########" -ForegroundColor DarkGreen




$id = "OCR" + "18.10.59.2"
$outputLine = "$id" + ";" + "(L2)Ensure 'Allow Cloud Search' is set to 'Enabled: Disable Cloud Search', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" |Select-Object AllowCloudSearch
 $policyValue = $policyValue.AllowCloudSearch
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "OCR" + "18.10.59.3"
$outputLine = "$id" + ";" + "(L1)Ensure 'Allow Cortana' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" |Select-Object AllowCortana
 $policyValue = $policyValue.AllowCortana
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "OCR" + "18.10.59.4"
$outputLine = "$id" + ";" + "(L1)Ensure 'Allow Cortana above lock screen' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" |Select-Object AllowCortanaAboveLock
 $policyValue = $policyValue.AllowCortanaAboveLock
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "OCR" + "18.10.59.5"
$outputLine = "$id" + ";" + "(L1)Ensure 'Allow indexing of encrypted files' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" |Select-Object AllowIndexingEncryptedStoresOrItems
 $policyValue = $policyValue.AllowIndexingEncryptedStoresOrItems
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "OCR" + "18.10.59.6"
$outputLine = "$id" + ";" + "(L1)Ensure 'Allow search and Cortana to use location' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" |Select-Object AllowSearchToUseLocation
 $policyValue = $policyValue.AllowSearchToUseLocation
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "OCR" + "18.10.59.7"
$outputLine = "$id" + ";" + "(L2)'Ensure 'Allow search highlights' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" |Select-Object EnableDynamicContentInWSB
 $policyValue = $policyValue.EnableDynamicContentInWSB
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname





Write-Host "#########>Begin Software Protection Platform audit<#########" -ForegroundColor DarkGreen



$id = "SPP" + "18.10.63.1"
$outputLine = "$id" + ";" + "(L2)Ensure 'Turn off KMS Client Online AVS Validation' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" |Select-Object NoGenTicket
 $policyValue = $policyValue.NoGenTicket
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

Write-Host "#########>Begin Store audit<#########" -ForegroundColor DarkGreen



$id = "STORE" + "18.10.66.1"
$outputLine = "$id" + ";" + "(L2)Ensure 'Disable all apps from Windows Store' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" |Select-Object DisableStoreApps
 $policyValue = $policyValue.DisableStoreApps
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "STORE" + "18.10.66.2"
$outputLine = "$id" + ";" + "(L1) Ensure 'Only display the private store within the Microsoft Store' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" |Select-Object RequirePrivateStoreOnly
 $policyValue = $policyValue.RequirePrivateStoreOnly
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "STORE" + "18.10.66.3"
$outputLine = "$id" + ";" + "(L1) Ensure 'Turn off Automatic Download and Install of updates' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" |Select-Object AutoDownload
 $policyValue = $policyValue.AutoDownload
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "STORE" + "18.10.66.4"
$outputLine = "$id" + ";" + " (L1)Ensure 'Turn off the offer to update to the latest version of Windows' is set to 'Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" |Select-Object DisableOSUpgrade
 $policyValue = $policyValue.DisableOSUpgrade
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "STORE" + "18.10.66.5"
$outputLine = "$id" + ";" + "(L2)Ensure 'Turn off the Store application' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" |Select-Object RemoveWindowsStore
 $policyValue = $policyValue.RemoveWindowsStore
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

Write-Host "#########>Begin Widgets audit<#########" -ForegroundColor DarkGreen

$id = "WID" + "18.10.72.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Allow widgets' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" |Select-Object AllowNewsAndInterests
 $policyValue = $policyValue.AllowNewsAndInterests
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


Write-Host "#########>Begin Windows Defender SmartScreen audit<#########" -ForegroundColor DarkGreen

$id = "WDS" + "18.10.72.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Notify Malicious' is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" |Select-Object NotifyMalicious
 $policyValue = $policyValue.NotifyMalicious
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "WDS" + "18.10.72.2"
$outputLine = "$id" + ";" + "(L1)Ensure 'Notify Password Reuse' is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" |Select-Object NotifyPasswordReuse
 $policyValue = $policyValue.NotifyPasswordReuse
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "WDS" + "18.10.72.3"
$outputLine = "$id" + ";" + "(L1)Ensure 'Notify Unsafe App'''' is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" |Select-Object NotifyUnsafeApp
 $policyValue = $policyValue.NotifyUnsafeApp
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "WDS" + "18.10.72.3"
$outputLine = "$id" + ";" + "(L1)Ensure 'Service Enabled' is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" |Select-Object ServiceEnabled
 $policyValue = $policyValue.ServiceEnabled
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "WDS" + "18.10.76.2.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass, value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" |Select-Object EnableSmartScreen
 $policyValue = $policyValue.EnableSmartScreen
 $policyValueBuffer = "EnableSmartScreen" + ":" + "$policyValue" + "|"
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" |Select-Object ShellSmartScreenLevel
 $policyValue = $policyValue.ShellSmartScreenLevel
 $policyValueBuffer += "ShellSmartScreenLevel" + ":" + "$policyValue" + "|"

 
}
else {
 $policyValueBuffer = "no configuration"
}
$outputLine += $policyValueBuffer
$outputLine>> $fname

Write-Host "#########>Begin Microsoft Edge audit<#########" -ForegroundColor DarkGreen

$id = "ME" + "18.10.76.3.1"
$outputLine = "$id" + ";" + "(L1)Ensure Configure Windows Defender SmartScreen is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" |Select-Object EnabledV9
 $policyValue = $policyValue.EnabledV9
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "ME" + "18.10.76.3.1"
$outputLine = "$id" + ";" + "(L1)Ensure Prevent bypassing Windows Defender SmartScreen prompts for sites is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" |Select-Object PreventOverride
 $policyValue = $policyValue.PreventOverride
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

Write-Host "#########>Begin Windows Game Recording and Broadcasting audit<#########" -ForegroundColor DarkGreen



$id = "WGRB" + "18.10.78.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Enables or disables Windows Game Recording and Broadcasting' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" |Select-Object AllowGameDVR
 $policyValue = $policyValue.AllowGameDVR
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


Write-Host "#########>Begin Windows Hello for Business audit<#########" -ForegroundColor DarkGreen



$id = "WGRB" + "18.10.78.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Enable ESS with Supported Peripherals' is set to 'Enabled: 1', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Policies\PassportForWork\Biometrics"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Policies\PassportForWork\Biometrics" |Select-Object EnableESSwithSupportedPeripherals
 $policyValue = $policyValue.EnableESSwithSupportedPeripherals
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


Write-Host "#########>Begin Windows Ink Workspace audit<#########" -ForegroundColor DarkGreen



$id = "WIW" + "18.10.80.1"
$outputLine = "$id" + ";" + "(L2)Ensure 'Allow suggested apps in Windows Ink Workspace' is set to 'Disabled, value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" |Select-Object AllowSuggestedAppsInWindowsInkWorkspace
 $policyValue = $policyValue.AllowSuggestedAppsInWindowsInkWorkspace
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "WIW" + "18.10.80.2"
$outputLine = "$id" + ";" + "(L1) Ensure 'Allow Windows Ink Workspace' is set to 'Enabled: On, but disallow access above lock' OR 'Disabled' but not 'Enabled: On', value must be 0 or 1 but not 2 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" |Select-Object AllowWindowsInkWorkspace
 $policyValue = $policyValue.AllowWindowsInkWorkspace
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname



Write-Host "#########>Begin Windows Installer audit<#########" -ForegroundColor DarkGreen


$id = "WI" + "18.10.81.1"
$outputLine = "$id" + ";" + "Ensure 'Allow user control over installs' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" |Select-Object EnableUserControl
 $policyValue = $policyValue.EnableUserControl
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "WI" + "18.10.81.2"
$outputLine = "$id" + ";" + "(L1)Ensure 'Always install with elevated privileges' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" |Select-Object AlwaysInstallElevated
 $policyValue = $policyValue.AlwaysInstallElevated
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "WI" + "18.10.81.3"
$outputLine = "$id" + ";" + "(L2)Ensure 'Prevent Internet Explorer security prompt for Windows Installer scripts' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" |Select-Object SafeForScripting
 $policyValue = $policyValue.SafeForScripting
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


Write-Host "#########>Begin Windows Logon Options audit<#########" -ForegroundColor DarkGreen


$id = "WLO" + "18.10.82.1"
$outputLine = "$id" + ";" + "(L1)Ensure ''Enable MPR notifications for the system' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" |Select-Object EnableMPR
 $policyValue = $policyValue.EnableMPR
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname





$id = "WLO" + "18.10.82.2"
$outputLine = "$id" + ";" + "(L1)Ensure 'Sign-in last interactive user automatically after a system-initiated restart' is set to 'Disabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" |Select-Object DisableAutomaticRestartSignOn
 $policyValue = $policyValue.DisableAutomaticRestartSignOn
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname




Write-Host "#########>Begin Windows PowerShell audit<#########" -ForegroundColor DarkGreen


$id = "WP" + "18.10.87.1"
$outputLine = "$id" + ";" + "Ensure 'Turn on PowerShell Script Block Logging' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" |Select-Object EnableScriptBlockLogging
 $policyValue = $policyValue.EnableScriptBlockLogging
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname
$id = "WP" + "18.10.87.2"
$outputLine = "$id" + ";" + "Ensure 'urn on PowerShell Transcription' is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" |Select-Object EnableTranscripting
 $policyValue = $policyValue.EnableTranscripting
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname



Write-Host "#########>Begin Windows Remote Management audit<#########" -ForegroundColor DarkGreen


$id = "WRR" + "18.10.89.1.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Allow Basic authentication' is set to 'Disabled', value must be 0" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" |Select-Object AllowBasic
 $policyValue = $policyValue.AllowBasic
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "WRR" + "18.10.89.1.2"
$outputLine = "$id" + ";" + "(L1)Ensure 'Allow unencrypted traffic' is set to 'Disabled', value must be 0" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" |Select-Object AllowUnencryptedTraffic
 $policyValue = $policyValue.AllowUnencryptedTraffic
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "WRR" + "18.10.89.1.3"
$outputLine = "$id" + ";" + "(L1)Ensure 'Disallow Digest authentication' is set to 'Enabled', value must be 0" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" |Select-Object AllowDigest
 $policyValue = $policyValue.AllowDigest
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

Write-Host "#########>Begin WinRM Service audit<#########" -ForegroundColor DarkGreen

$id = "WRR" + "18.10.89.2.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Allow Basic authentication' is set to 'Disabled', value must be 0" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" |Select-Object AllowBasic
 $policyValue = $policyValue.AllowBasic
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "WRR" + "18.10.89.2.2"
$outputLine = "$id" + ";" + "(L2)Ensure 'Allow remote server management through WinRM' is set to 'Disabled', value must be 0" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" |Select-Object AllowAutoConfig
 $policyValue = $policyValue.AllowAutoConfig
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "WRR" + "18.10.89.2.3"
$outputLine = "$id" + ";" + "(L1)Ensure 'Allow unencrypted traffic' is set to 'Disabled', value must be 0" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" |Select-Object AllowUnencryptedTraffic
 $policyValue = $policyValue.AllowUnencryptedTraffic
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "WRR" + "18.10.89.2.4"
$outputLine = "$id" + ";" + "(L1)Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" |Select-Object DisableRunAs
 $policyValue = $policyValue.DisableRunAs
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


Write-Host "#########>Begin Windows Remote Shell audit<#########" -ForegroundColor DarkGreen


$id = "WRS" + "18.10.90.1"
$outputLine = "$id" + ";" + "(L2)Ensure 'Allow Remote Shell Access' is set to 'Disabled, value must be 0" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" |Select-Object AllowRemoteShellAccess
 $policyValue = $policyValue.AllowRemoteShellAccess
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


Write-Host "#########>Begin Windows Sandbox audit<#########" -ForegroundColor DarkGreen


$id = "WS" + "18.10.90.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Allow clipboard sharing with Windows Sandbox' is set to 'Disabled' value must be 0" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" |Select-Object AllowClipboardRedirection
 $policyValue = $policyValue.AllowClipboardRedirection
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "WS" + "18.10.90.2"
$outputLine = "$id" + ";" + "(L1)Ensure 'Allow networking in Windows Sandbox' is set to 'Disabled', value must be 0" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" |Select-Object AllowNetworking
 $policyValue = $policyValue.AllowNetworking
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname



Write-Host "#########>Begin App and browser protection audit<#########" -ForegroundColor DarkGreen


$id = "ABP" + "18.10.92.2.1"
$outputLine = "$id" + ";" + "(L1) Ensure 'Prevent users from modifying settings' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" |Select-Object DisallowExploitProtectionOverride
 $policyValue = $policyValue.DisallowExploitProtectionOverride
 }
$outputLine += $policyValue
$outputLine>> $fname



Write-Host "#########>Begin Windows Update audit<#########" -ForegroundColor DarkGreen




$id = "WU" + "18.10.93.2.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Configure Automatic Updates' is set to 'Enabled', value must be 0" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" |Select-Object NoAutoUpdate
 $policyValue = $policyValue.NoAutoUpdate
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname



$id = "WU" + "18.10.93.2.2"
$outputLine = "$id" + ";" + "(L1)Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day'', value must be 0" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" |Select-Object ScheduledInstallDay
 $policyValue = $policyValue.ScheduledInstallDay
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname



$id = "WU" + "18.10.93.2.3"
$outputLine = "$id" + ";" + "(L1)Ensure 'Remove access to AAAasAA...aPause updatesAAAasAAA feature' is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" |Select-Object SetDisablePauseUXAccess
 $policyValue = $policyValue.SetDisablePauseUXAccess
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname




$id = "WU" + "18.10.93.4.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Manage preview builds' is set to 'Enabled: Disable preview builds' value must be 0 foreach key" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" |Select-Object ManagePreviewBuilds
 $policyValue = $policyValue.ManagePreviewBuilds
 $policyValueBuffer = "ManagePreviewBuilds" + ":" + "$policyValue" + "|"
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" |Select-Object ManagePreviewBuildsPolicyValue
 $policyValue = $policyValue.ManagePreviewBuildsPolicyValue
 $policyValueBuffer += "ManagePreviewBuildsPolicyValue" + ":" + "$policyValue" + "|"
}
else {
 $policyValueBuffer = "no configuration"
}
$outputLine += $policyValueBuffer
$outputLine>> $fname

$id = "WU" + "18.10.93.4.2"
$outputLine = "$id" + ";" + "(L2)Ensure 'Select when Feature Updates are received' is set to 'Enabled: Current Branch for Business, 180 days' " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" |Select-Object DeferFeatureUpdates
 $policyValue = $policyValue.DeferFeatureUpdates
 $policyValueBuffer = "DeferFeatureUpdates" + ":" + "$policyValue" + "|"
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" |Select-Object DeferFeatureUpdatesPeriodInDays
 $policyValue = $policyValue.DeferFeatureUpdatesPeriodInDays
 $policyValueBuffer += "DeferFeatureUpdatesPeriodInDays" + ":" + "$policyValue" + "|"
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" |Select-Object BranchReadinessLevel
 $policyValue = $policyValue.BranchReadinessLevel
 $policyValueBuffer += "BranchReadinessLevel" + ":" + "$policyValue" + "|"
}
else {
 $policyValueBuffer = "no configuration"
}
$outputLine += $policyValueBuffer
$outputLine>> $fname



$id = "WU" + "18.10.93.4.3"
$outputLine = "$id" + ";" + "(L1)Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days''''' " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" |Select-Object DeferQualityUpdates
 $policyValue = $policyValue.DeferQualityUpdates
 $policyValueBuffer = "DeferQualityUpdates" + ":" + "$policyValue" + "|"
 $policyValue = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" |Select-Object DeferQualityUpdatesPeriodInDays
 $policyValue = $policyValue.DeferQualityUpdatesPeriodInDays
 $policyValueBuffer += "DeferQualityUpdatesPeriodInDays" + ":" + "$policyValue" + "|"
}
else {
 $policyValueBuffer = "no configuration"
}
$outputLine += $policyValueBuffer
$outputLine>> $fname


Write-Host "#########>Begin Personalization audit<#########" -ForegroundColor DarkGreen


$id = "PERS" + "19.1.3.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Enable screen saver' is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" |Select-Object ScreenSaveActive
 $policyValue = $policyValue.ScreenSaveActive
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "PERS" + "19.1.3.2"
$outputLine = "$id" + ";" + "(L1)Ensure 'Password protect the screen saver' is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" |Select-Object ScreenSaverIsSecure
 $policyValue = $policyValue.ScreenSaverIsSecure
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "PERS" + "19.1.3.3"
$outputLine = "$id" + ";" + "(L1)Ensure 'Screen saver timeout' is set to 'Enabled: 900 seconds or fewer, but not 0', value must be 900 or less but not 0" + ";"
$exist = Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" |Select-Object ScreenSaveTimeOut
 $policyValue = $policyValue.ScreenSaveTimeOut
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


Write-Host "#########>Begin Notifications audit<#########" -ForegroundColor DarkGreen

$id = "NOTIF" + "19.5.1.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Turn off toast notifications on the lock screen' is set to 'Enabled, value must be 1" + ";"
$exist = Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" |Select-Object NoToastApplicationNotificationOnLockScreen
 $policyValue = $policyValue.NoToastApplicationNotificationOnLockScreen
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname



Write-Host "#########>Begin Internet Communication Management audit<#########" -ForegroundColor DarkGreen


$id = "ICC" + "19.6.6.1.1"
$outputLine = "$id" + ";" + "(L2)Ensure 'Turn off Help Experience Improvement Program' is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" |Select-Object NoImplicitFeedback
 $policyValue = $policyValue.NoImplicitFeedback
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


Write-Host "#########>Begin Attachment Manager audit<#########" -ForegroundColor DarkGreen


$id = "ATTM" + "19.7.4.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Do not preserve zone information in file attachments' is set to 'Disabled', value must be 0" + ";"
$exist = Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" |Select-Object SaveZoneInformation
 $policyValue = $policyValue.SaveZoneInformation
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "ATTM" + "19.7.4.2"
$outputLine = "$id" + ";" + "(L1)Ensure 'Notify antivirus programs when opening attachments' is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" |Select-Object ScanWithAntiVirus
 $policyValue = $policyValue.ScanWithAntiVirus
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname



Write-Host "#########>Begin Cloud Content audit<#########" -ForegroundColor DarkGreen


$id = "CLOUDC" + "19.7.7.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Configure Windows spotlight on lock screen' is set to Disabled, value must be 0" + ";"
$exist = Test-Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" |Select-Object ConfigureWindowsSpotlight
 $policyValue = $policyValue.ConfigureWindowsSpotlight
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "CLOUDC" + "19.7.7.2"
$outputLine = "$id" + ";" + "(L1)Ensure 'Do not suggest third-party content in Windows spotlight' is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" |Select-Object DisableThirdPartySuggestions
 $policyValue = $policyValue.DisableThirdPartySuggestions
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


$id = "CLOUDC" + "19.7.7.3"
$outputLine = "$id" + ";" + "(L2)Ensure 'Do not use diagnostic data for tailored experiences' is set to 'Enabled'', value must be 1" + ";"
$exist = Test-Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" |Select-Object DisableTailoredExperiencesWithDiagnosticData
 $policyValue = $policyValue.DisableTailoredExperiencesWithDiagnosticData
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "CLOUDC" + "19.7.7.4"
$outputLine = "$id" + ";" + "(L2)Ensure 'Turn off all Windows spotlight features' is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" |Select-Object DisableWindowsSpotlightFeatures
 $policyValue = $policyValue.DisableWindowsSpotlightFeatures
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname

$id = "CLOUDC" + "19.7.7.5"
$outputLine = "$id" + ";" + "(L1)Ensure 'Turn off Spotlight collection on Desktop' is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" 
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" |Select-Object DisableSpotlightCollectionOnDesktop
 $policyValue = $policyValue.DisableSpotlightCollectionOnDesktop
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname






Write-Host "#########>Begin Network Sharing audit<#########" -ForegroundColor DarkGreen


$id = "NSHARE" + "19.7.25.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Prevent users from sharing files within their profile.' is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" |Select-Object NoInplaceSharing
 $policyValue = $policyValue.NoInplaceSharing
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname




Write-Host "#########>Begin User Windows Installer audit<#########" -ForegroundColor DarkGreen


$id = "UWI" + "19.7.40.1"
$outputLine = "$id" + ";" + "(L1)Ensure 'Always install with elevated privileges' is set to 'Disabled', value must be 0" + ";"
$exist = Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" |Select-Object AlwaysInstallElevated
 $policyValue = $policyValue.AlwaysInstallElevated
}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname


Write-Host "#########>Begin Playback audit<#########" -ForegroundColor DarkGreen


$id = "PLB" + "19.7.42.2.1"
$outputLine = "$id" + ";" + "(L2)Ensure 'Prevent Codec Download' is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer"
if ( $exist -eq $true) {
 $policyValue = Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" |Select-Object PreventCodecDownload
 $policyValue = $policyValue.PreventCodecDownload

}
else {
 $policyValue = "no configuration"
}
$outputLine += $policyValue
$outputLine>> $fname
Write-Host "#########>END Audit<#########" -ForegroundColor DarkGreen
Set-Location ..





