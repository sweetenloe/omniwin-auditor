#Requires -RunAsAdministrator
#Requires -Version 4.0
$ErrorActionPreference = 'silentlycontinue'

Write-Host "#########>Install & Load Powershell Module for audit <#########" -ForegroundColor DarkGreen
# Section
$MAAD =Get-InstalledModule -Name AzureAD
 if($MAAD -eq $null){
   $MAADI = Read-Host "It seem AzureAD module isnot installed, do you want to installed it [Y/N]"
   switch($MAADI.ToLower()) 
{     {($_ -eq "y") -or ($_ -eq "yes") -or ($_ -eq "o")-or ($_ -eq "oui") } {Install-Module -Name AzureAD} 
    default { "You entered No, the script may not work" } 
}
    
 }
Import-Module -Name AzureAD
Connect-AzureAD
$MMSO =Get-InstalledModule -Name MSOnline
 if($MMSO -eq $null){
   $MMSOI = Read-Host "It seem MSOnline module isnot installed, do you want to installed it [Y/N]"
   switch($MMSOI.ToLower()) 
        {     {($_ -eq "y") -or ($_ -eq "yes") -or ($_ -eq "o")-or ($_ -eq "oui") } {Install-Module -Name MSOnline} 
    default { "You entered No, the script may not work" } 
}
    
 }
 Import-Module -Name MSOnline
 Connect-MsolService

 $MMGS =Get-InstalledModule -Name MicrosoftGraphSecurity 
 if( $MMGS -eq $null){
  $MMGSI = Read-Host "It seem MicrosoftGraphSecurity module isnot installed, do you want to installed it [Y/N]"
   switch( $MMGSI.ToLower()) 
        {     {($_ -eq "y") -or ($_ -eq "yes") -or ($_ -eq "o")-or ($_ -eq "oui") } {Install-Module -Name MicrosoftGraphSecurity} 
    default { "You entered No, the script may not work" } 
}
    
 }
 Import-Module  -Name MicrosoftGraphSecurity 
 $cert = New-SelfSignedCertificate -Subject "CN=MSGraph_ReportingAPI" -CertStoreLocation "Cert:\CurrentUser\My" -KeyExportPolicy Exportable -KeySpec Signature -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA25
 
$Date = Get-Date -U %d%m%Y


$nomfichier = "audit" + $date + ".txt"

Write-Host "#########>Create Audit directory<#########" -ForegroundColor DarkGreen

$nomdossier = "Audit_CONF_O365" + $date


New-Item -ItemType Directory -Name $nomdossier

Set-Location $nomdossier




Write-Host "#########>Begin CIS audit<#########" -ForegroundColor Green
Write-Host "#########>Begin Account / Authentication audit<#########" -ForegroundColor DarkGreen


$indextest += 1
$id = "AA" + "$indextest"
$chaine = "$id" + ";" + "E3 : (L1)Ensure multifactor authentication is enabled for all users in administrative roles" + ";"
$allgroupadmin = Get-MsolRole |Where {$_.name -match "administrator" -or $_.name -match "administrateurs"}|Select Name, ObjectId
"Group;UserPrincipalName;StrongPasswordRequired;PasswordNeverExpires;LastPasswordChangeTimestamp">alladmins.csv
$nbadmins = 0
$nbMFAdmins =0

foreach ( $groupadmin in $allgroupadmin){
  $admins = Get-MsolRoleMember -RoleObjectId $groupadmin.ObjectId | Select  EmailAddress
  
  foreach ( $useradmin in $admins){
    $adminlist = Get-MsolUser | Where {$_.UserPrincipalName -eq $useradmin.EmailAddress} | Select  UserPrincipalName, StrongPasswordRequired , PasswordNeverExpires, LastPasswordChangeTimestamp
    
  $line= $null
  $line += $groupadmin | Select -ExpandProperty Name
  $line += ";"
  $line += $adminlist | Select -ExpandProperty UserPrincipalName
  $line += ";"
  $line += $adminlist | Select -ExpandProperty StrongPasswordRequired
  $line += ";"
  $line += $adminlist | Select -ExpandProperty PasswordNeverExpires
  $line += ";"
  $line += $adminlist | Select -ExpandProperty LastPasswordChangeTimestamp
  $line >>alladmins.csv
    
    $nbadmins +=1
    if($adminlist.StrongPasswordRequired -ne $null){
      $nbMFAdmins += 1
  }
  }
}
$traitement = "$nbMFAdmins / $nbadmins | Details list in alladmins.csv "

$chaine += $traitement

$chaine>> $nomfichier
$indextest += 1
$id = "AA" + "$indextest"
$chaine = "$id" + ";" + "E3 : (L2) Ensure multifactor authentication is enabled for all users in all roles" + ";"
$allroleuser = Get-MsolRole |Select Name, ObjectId
"Group;UserPrincipalName;StrongPasswordRequired;PasswordNeverExpires;LastPasswordChangeTimestamp">alluserrole.csv
$nbadmins = 0
$nbMFAdmins =0

foreach ( $groupuser in $allroleuser){
  $users = Get-MsolRoleMember -RoleObjectId $groupuser.ObjectId | Select  EmailAddress
  
  foreach ( $user in $users){
    $userlist = Get-MsolUser | Where {$_.UserPrincipalName -eq $user.EmailAddress} | Select  UserPrincipalName, StrongPasswordRequired , PasswordNeverExpires, LastPasswordChangeTimestamp
    
  $line= $null
  $line += $groupuser | Select -ExpandProperty Name
  $line += ";"
  $line += $userlist | Select -ExpandProperty UserPrincipalName
  $line += ";"
  $line += $userlist | Select -ExpandProperty StrongPasswordRequired
  $line += ";"
  $line += $userlist | Select -ExpandProperty PasswordNeverExpires
  $line += ";"
  $line += $userlist | Select -ExpandProperty LastPasswordChangeTimestamp
  $line >>alluserrole.csv
    
    $nbuser +=1
    if($userlist.StrongPasswordRequired -ne $null){
      $nbMFAuser += 1
  }
  }
}
$traitement = "$nbMFAuser / $nbuser | Details list in alluserrole.csv"

$chaine += $traitement

$chaine>> $nomfichier

$indextest += 1
$id = "AA" + "$indextest"
$chaine = "$id" + ";" + "E3 : (L1) Ensure that between two and four global admins are designated" + ";"
$GlobalAdminsGroup = Get-MsolRole |Where {$_.name -match "Company Administrator" -or $_.name -match "Administrateurs global"}
$GlobalAdmin = Get-MsolRoleMember -RoleObjectId $GlobalAdminsGroup.objectid
$GlobalAdmin | Export-Csv -NoTypeInformation ListGlobalAdmin.csv
$nombreGlobalAdmin = $GlobalAdmin | Measure-Object
$nombreGlobalAdmin = $nombreGlobalAdmin.count

$traitement = "$nombreGlobalAdmin"

$chaine += $traitement

$chaine>> $nomfichier

$indextest += 1
$id = "AA" + "$indextest"
$chaine = "$id" + ";" + "E3 : (L1) Ensure self-service password reset is enabled, But if disabled less risk" + ";"
Write-Host "Work-in progess, this Check require an API KEY, so please check https://aad.portal.azure.com/#blade/Microsoft_AAD_IAM/UsersManagementMenuBlade/PasswordReset"
$traitement = "What is the value Disabled/Limited/ ALL ?"

$chaine += $traitement

$chaine>> $nomfichier

$indextest += 1
$id = "AA" + "$indextest"
$chaine = "$id" + ";" + "E3 : (L1) Ensure that password protection is enabled for Active Directory" + ";"
Write-Host "Work-in progess, this Check require an API KEY, so please check https://aad.portal.azure.com/#blade/Microsoft_AAD_IAM/UsersManagementMenuBlade/PasswordReset"
$traitement = Read-Host "What is the value Disabled/Limited/ ALL ?"


$chaine += $traitement

$chaine>> $nomfichier

$indextest += 1
$id = "AA" + "$indextest"
$chaine = "$id" + ";" + "E3 : (L1)Enable Conditional Access policies to block legacy authentication (Automated)" + ";"


$AllPolicies = Get-AzureADMSConditionalAccessPolicy

foreach ($Policy in $AllPolicies) {
    Write-Host "Export $($Policy.DisplayName)"
    $PolicyJSON = $Policy | ConvertTo-Json -Depth 6
    $PolicyJSON | Out-File "./Accesspolicy/$($Policy.Id).json"
}
$traitement = "Check the Accesspolicy directory"
$chaine += $traitement

$chaine>> $nomfichier

$indextest += 1
$id = "AA" + "$indextest"
$chaine = "$id" + ";" + "E3 : (L1) Ensure that password hash sync is enabled for resiliency and leaked credential detection, Mode should be Managed and not federated " + ";"


$traitement =  Get-MsolDomain | Select Authentication

$traitement = $traitement.Authentication

$chaine += $traitement

$chaine>> $nomfichier

$indextest += 1
$id = "AA" + "$indextest"
$chaine = "$id" + ";" + "E5 (L1) Enabled Identity Protection to identify anomalous logon behavior " + ";"


$traitement =  Get-MsolDomain | Select Authentication

$traitement = $traitement.Authentication

$chaine += $traitement

$chaine>> $nomfichier


Write-Host "#########>END Audit<#########" -ForegroundColor DarkGreen
Set-Location ..


