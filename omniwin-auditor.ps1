param([switch]$Debug)

Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$script:DebugEnabled=[bool]$Debug
$script:DebugFile=$null

function Ensure-DebugFolder{
  $d=Join-Path $PSScriptRoot 'logs\.debug'
  if(-not(Test-Path -LiteralPath $d)){[void](New-Item -ItemType Directory -Path $d)}
  $d
}
function New-DebugLog{
  if(-not $script:DebugEnabled){return $null}
  $dir=Ensure-DebugFolder
  $ts=Get-Date -AsUTC -Format 'yyyyMMdd_HHmmssZ'
  $script:DebugFile=Join-Path $dir ("debug_$ts.log")
  "OwO Debug Log started: $(Get-Date -AsUTC -Format 'u')"|Set-Content -LiteralPath $script:DebugFile -Encoding UTF8
  $script:DebugFile
}
function DebugLog([string]$Message){
  if(-not $script:DebugEnabled){return}
  if(-not $script:DebugFile){New-DebugLog|Out-Null}
  ("[$(Get-Date -AsUTC -Format 'u')] "+$Message)|Add-Content -LiteralPath $script:DebugFile -Encoding UTF8
}

function Get-OsInfo{
  $os=Get-CimInstance Win32_OperatingSystem
  $caption=$os.Caption.Trim()
  $normalized=switch -Regex($caption){
    'Windows\s+11'{'WIN11';break}
    'Windows\s+10'{'WIN10';break}
    'Windows Server 2025'{'WIN2025';break}
    'Windows Server 2022'{'WIN2022';break}
    'Windows Server 2019'{'WIN2019';break}
    'Windows Server 2016'{'WIN2016';break}
    default{'UNKNOWN'}
  }
  [pscustomobject]@{
    Caption=$caption
    Version=$os.Version.Trim()
    Arch=$os.OSArchitecture.Trim()
    Normal=$normalized
  }
}

function Get-AvailableModules{
  $root=Join-Path $PSScriptRoot 'Modules'
  if(-not(Test-Path -LiteralPath $root)){return @()}
  Get-ChildItem -LiteralPath $root -Directory|ForEach-Object{
    $group=$_.Name
    Get-ChildItem -LiteralPath $_.FullName -File -Filter *.ps1|ForEach-Object{
      [pscustomobject]@{Group=$group;Name=$_.Name;Path=$_.FullName}
    }
  }|Sort-Object Group,Name
}

function Get-RecommendedModulePath($osTag){
  $map=@{
    'WIN11'='Modules/Windows_PC/Windows_11_H-P-E.ps1'
    'WIN10'='Modules/Windows_PC/Windows_10_H-P-E.ps1'
    'WIN2016'='Modules/Windows_Server/Windows_Server_2022.ps1'
    'WIN2019'=$null; 'WIN2022'=$null; 'WIN2025'=$null
  }
  $p=$map[$osTag]
  if($p -and (Test-Path -LiteralPath (Join-Path $PSScriptRoot $p))){return (Join-Path $PSScriptRoot $p)}
  $null
}

function Ensure-ModuleNamingAndComments{
  try{
    $renames=@{
      (Join-Path $PSScriptRoot 'Modules/DomesticEnv/WIN10-CISv4.0.ps1')=(Join-Path $PSScriptRoot 'Modules/Windows_PC/Windows_10_H-P-E.ps1')
      (Join-Path $PSScriptRoot 'Modules/DomesticEnv/WIN11-CISv4.0.ps1')=(Join-Path $PSScriptRoot 'Modules/Windows_PC/Windows_11_H-P-E.ps1')
      (Join-Path $PSScriptRoot 'Modules/DomesticEnv/WIN2016-CISv3.0.ps1')=(Join-Path $PSScriptRoot 'Modules/Windows_Server/Windows_Server_2022.ps1')
      (Join-Path $PSScriptRoot 'Modules/OrgEnv/WIN2016DC-CISv3.0.ps1')=(Join-Path $PSScriptRoot 'Modules/Windows_Server/Windows_Server_2025.ps1')
      (Join-Path $PSScriptRoot 'Modules/O365/O365-CISv5.0.ps1')=(Join-Path $PSScriptRoot 'Modules/O365/Microsoft_O365_2025.ps1')
    }
    foreach($k in $renames.Keys){$src=$k;$dst=$renames[$k];if((Test-Path -LiteralPath $src)-and -not(Test-Path -LiteralPath $dst)){Move-Item -LiteralPath $src -Destination $dst -Force}}
  }catch{}
  function MapCommentToMarker([string]$t){
    $t=$t.ToLowerInvariant()
    if($t -match 'firewall'){return '# Firewall rules'}
    if($t -match 'antivirus|defender'){return '# Antivirus info'}
    if($t -match 'registry'){return '# Registry export'}
    if($t -match 'share'){return '# Shares audit'}
    if($t -match 'optional feature|feature'){return '# Optional features'}
    if($t -match 'software|installed'){return '# Installed software'}
    if($t -match 'system information|systeminfo'){return '# System info'}
    if($t -match 'update|qfe|patch'){return '# Windows updates'}
    if($t -match 'service'){return '# Services'}
    if($t -match 'scheduled task|task'){return '# Scheduled tasks'}
    if($t -match 'account'){return '# Account policies'}
    if($t -match 'port|listen'){return '# Listening ports'}
    if($t -match 'user|administrator'){return '# Local users'}
    if($t -match 'gpo|group policy|secedit'){return '# Policy exports'}
    $null
  }
  $moduleRoot=Join-Path $PSScriptRoot 'Modules'
  if(-not(Test-Path -LiteralPath $moduleRoot)){return}
  Get-ChildItem -LiteralPath $moduleRoot -Recurse -File -Include *.ps1,*.psm1|ForEach-Object{
    $path=$_.FullName
    $lines=Get-Content -LiteralPath $path
    $out=[System.Collections.Generic.List[string]]::new()
    $pending=[System.Collections.Generic.List[string]]::new()
    $toggle=$true
    foreach($line in $lines){
      $trim=$line.TrimStart()
      if($trim.StartsWith('#Requires')){$out.Add($line);continue}
      if($trim.StartsWith('#')){$pending.Add($line);continue}
      if($pending.Count -gt 0){
        if($toggle){
          $marker=$null
          foreach($c in $pending){$m=MapCommentToMarker $c;if($m){$marker=$m;break}}
          if(-not $marker){$marker='# Section'}
          $out.Add($marker)
        }
        $pending.Clear();$toggle=-not $toggle
      }
      $out.Add($line)
    }
    if($out.Count -gt 0){Set-Content -LiteralPath $path -Value $out -Encoding UTF8}
  }
}

function Ensure-LogFolder{
  $logDir=Join-Path $PSScriptRoot 'logs'
  if(-not(Test-Path -LiteralPath $logDir)){[void](New-Item -ItemType Directory -Path $logDir)}
  $logDir
}
function New-LogFile{
  $dir=Ensure-LogFolder
  Join-Path $dir ("audit_"+(Get-Date -Format 'yyyyMMdd_HHmmss')+".log")
}

function Draw-Box([string[]]$Lines,[ConsoleColor]$BorderColor='Green',[ConsoleColor]$TextColor='Gray'){
  $maxLen=($Lines|Measure-Object -Property Length -Maximum).Maximum
  $top="+"+("-"*($maxLen+2))+"+"
  Write-Host $top -ForegroundColor $BorderColor
  foreach($l in $Lines){$pad=' '*($maxLen-$l.Length);Write-Host ("| "+$l+$pad+" |") -ForegroundColor $TextColor}
  Write-Host $top -ForegroundColor $BorderColor
}

function Render-List([string]$Title,[string[]]$Items,[int]$Selected){
  Clear-Host
  $hdr=@("","                     _          _                         __ _  __            ",
" ___   __ _   ___   (_)_    __ (_)___     ___ _ __ __ ___/ /(_)/ /_ ___   ____",
"/ _ \ /  ' \ / _ \ / /| |/|/ // // _ \   / _ `// // // _  // // __// _ \ / __/",
"\___//_/_/_//_//_//_/ |__,__//_//_//_/   \_,_/ \_,_/ \_,_//_/ \__/ \___//_/   ",
"","Use Up/Down to navigate, Space/Enter to select, Esc/Backspace to go back.")
  Draw-Box $hdr 'White' 'Green';Write-Host
  $box=[System.Collections.Generic.List[string]]::new()
  $box.Add($Title);$box.Add('')
  for($i=0;$i -lt $Items.Count;$i++){ $prefix= if($i -eq $Selected){'>> '}else{'   '};$box.Add($prefix+$Items[$i]) }
  Draw-Box $box 'Green' 'White'
}

function Read-MenuSelection([string]$Title,[string[]]$Items,[int]$DefaultIndex=0){
  if(-not $Items -or $Items.Count -eq 0){return -1}
  $idx=[Math]::Max([Math]::Min($DefaultIndex,$Items.Count-1),0);$needsRender=$true
  while($true){
    if($needsRender){Render-List $Title $Items $idx;$needsRender=$false}
    $key=$Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    switch($key.VirtualKeyCode){
      38{if($idx -gt 0){$idx--;$needsRender=$true}}
      40{if($idx -lt $Items.Count-1){$idx++;$needsRender=$true}}
      13{return $idx}
      32{return $idx}
      27{return -2}
      8 {return -2}
    }
  }
}

function Show-ErrorBox([string]$Message){Draw-Box @('Error','',$Message) 'Red' 'White';[void]$Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')}
function Show-InfoBox([string[]]$Lines){Draw-Box $Lines 'DarkCyan' 'White';[void]$Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')}

function Run-AuditScript([string]$ScriptPath,[string]$Mode='Full',[string[]]$Categories){
  if(-not(Test-Path -LiteralPath $ScriptPath)){Show-ErrorBox "Module not found: $ScriptPath";return}
  $log=New-LogFile
  $global:OwO_LastHtml=$null;$global:OwO_LastAudit=$null
  $invokeArgs=@();if($Mode -eq 'Category' -and $Categories -and $Categories.Count -gt 0){$invokeArgs+=('-Category',($Categories -join ','))}
  Clear-Host;Draw-Box @("Running audit...",'',"Module: $ScriptPath","Log: $log") 'Magenta' 'Green';Write-Host
  try{
    $startTime=Get-Date
    $arguments=@('-NoProfile','-ExecutionPolicy','Bypass','-File',$ScriptPath);if($invokeArgs.Count -gt 0){$arguments+=$invokeArgs}
    & 'pwsh.exe' @arguments 2>&1|Tee-Object -FilePath $log
    $exitCode=$LASTEXITCODE
    try{
      $candidate=Get-ChildItem -Path $PSScriptRoot -Recurse -File -Filter 'audit*.txt' -ErrorAction SilentlyContinue|
        Where-Object{$_.LastWriteTime -ge $startTime.AddSeconds(-30)}|Sort-Object LastWriteTime -Descending|Select-Object -First 1
      if($candidate){
        $global:OwO_LastAudit=$candidate.FullName
        $htmlTarget=Join-Path (Ensure-LogFolder)(([IO.Path]::GetFileNameWithoutExtension($candidate.Name))+'.html')
        OwO-ConvertAuditToHtml -InputPath $candidate.FullName -OutputPath $htmlTarget -Title ("Omniwin-Auditor - "+(Split-Path -Leaf $ScriptPath)) -IncludeCode
        $global:OwO_LastHtml=$htmlTarget
      }
    }catch{$global:OwO_LastHtml=$null}
    $lines=@("Audit completed.",'',"ExitCode: $exitCode","Log saved: $log");if($global:OwO_LastHtml){$lines+=("HTML: "+$global:OwO_LastHtml)};$lines+=@('','Press any key to continue...')
    Draw-Box $lines 'DarkGreen' 'White';[void]$Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');Post-AuditActions $log
  }catch{Show-ErrorBox("Audit failed: "+$_.Exception.Message)}
}

function Post-AuditActions([string]$LogPath){
  $items=@('Back to Menu','Open HTML Report','List Categories','Open Log Folder')
  while($true){
    $sel=Read-MenuSelection "Post-Audit Options" $items 0
    switch($sel){
      0{return}
      1{try{if($global:OwO_LastHtml -and (Test-Path -LiteralPath $global:OwO_LastHtml)){Invoke-Item -LiteralPath $global:OwO_LastHtml}else{Show-ErrorBox 'No HTML report from last run.'}}catch{}}
      2{try{
          if($global:OwO_LastAudit -and (Test-Path -LiteralPath $global:OwO_LastAudit)){
            $cats=OwO-ListCategories -InputPath $global:OwO_LastAudit
            Clear-Host;Draw-Box @('Categories','','Press any key to return') 'DarkCyan' 'White';Write-Host
            $cats|ForEach-Object{Write-Host ("- "+$_)}
            [void]$Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
          }else{Show-ErrorBox 'No audit input found.'}
        }catch{Show-ErrorBox("Failed to list categories: "+$_.Exception.Message)}}
      3{try{Invoke-Item -LiteralPath (Split-Path -Parent $LogPath)}catch{}}
      default{return}
    }
  }
}

function Show-Recommended{
  $os=Get-OsInfo;$rec=Get-RecommendedModulePath $os.Normal
  $title="Recommended Audit for: $($os.Caption) ($($os.Version), $($os.Arch))"
  if(-not $rec){Show-ErrorBox "No recommended module mapped for this OS.";return}
  $items=@('Full Audit','Audit by Category','Back')
  while($true){
    $sel=Read-MenuSelection $title $items 0
    switch($sel){
      0{Run-AuditScript -ScriptPath $rec -Mode 'Full';return}
      1{$cats=@('AccountPolicies','LocalPolicies','EventLog','AdvancedAudit','UserRights','SecurityOptions')
        $cSel=Read-MenuSelection "Select a category (placeholder)" ($cats+'Back') 0
        if($cSel -ge 0 -and $cSel -lt $cats.Count){Run-AuditScript -ScriptPath $rec -Mode 'Category' -Categories @($cats[$cSel])}else{return}}
      -2{return}
      default{return}
    }
  }
}

function Show-Browse{
  $mods=Get-AvailableModules
  if(-not $mods){Show-ErrorBox 'No modules found under ./Modules';return}
  $groups=$mods|Group-Object Group|Sort-Object Name
  $friendly=@{'Windows_PC'='Workstations';'Windows_Server'='Servers & AD';'O365'='Office365'}
  $display=@();foreach($g in $groups){$label=$friendly[$g.Name];if(-not $label){$label=$g.Name};$display+=$label}
  $gSel=Read-MenuSelection 'Select a module group' ($display+'Back') 0
  if($gSel -lt 0 -or $gSel -ge $display.Count){return}
  $group=$groups[$gSel]
  $names=@($group.Group|ForEach-Object{$_.Name})
  $mSel=Read-MenuSelection "Select a module in '$($group.Name)'" ($names+@('Back')) 0
  if($mSel -lt 0 -or $mSel -ge $group.Group.Count){return}
  $mod=$group.Group[$mSel]
  $items=@('Full Audit','Audit by Category','Back')
  while($true){
    $sel=Read-MenuSelection "Module: $($mod.Name)" $items 0
    switch($sel){
      0{Run-AuditScript -ScriptPath $mod.Path -Mode 'Full';return}
      1{$cats=@('AccountPolicies','LocalPolicies','EventLog','AdvancedAudit','UserRights','SecurityOptions')
        $cSel=Read-MenuSelection "Select a category (placeholder)" ($cats+'Back') 0
        if($cSel -ge 0 -and $cSel -lt $cats.Count){Run-AuditScript -ScriptPath $mod.Path -Mode 'Category' -Categories @($cats[$cSel])}else{return}}
      -2{return}
      default{return}
    }
  }
}

function Show-AuditCoverage{
  $items=@('O365','Windows PC','Windows Server','Back')
  $sel=Read-MenuSelection 'View Audit Coverage' $items 0
  $c=@{}
  $c['O365']=@(
'* Microsoft 365 admin center: admin accounts, emergency access, role limits, licenses, groups, mailbox access, password policies, session timeouts, external sharing',
'* Microsoft 365 Defender: Safe Links/Attachments, anti-phishing, SPF/DKIM/DMARC, spam, cloud app monitoring, audit, priority accounts, ZAP for Teams',
'* Microsoft Purview: audit search, DLP, sensitivity labels',
'* Intune: compliance policies, unmanaged device blocks, secure enrollment',
'* Entra: per-user MFA, app restrictions, tenant creation limits, guest governance, PHS, CA policies, phishing-resistant MFA, device trust, banned passwords, PIM/access reviews',
'* Exchange Online: mailbox auditing, block forwarding, mail flow policies, modern auth, disable SMTP AUTH',
'* SharePoint/OneDrive: modern auth, external sharing restrictions, guest expiration, secure link defaults, block custom scripts, sync restrictions',
'* Teams: restrict external collaboration, unmanaged/Skype controls, anonymous meeting controls, chat/file restrictions, app/device permissions',
'* Fabric/Power BI: restrict guests/invitations/publish-to-web, sensitivity labels, API access control',
'* Cross-service: MFA, encryption, auditing, restricted collaboration, secure admin practices, monitoring'
  )
  $c['Windows PC']=@(
'* Account policies: complexity, age, lockout',
'* Local policies: audit, rights, UAC',
'* Event logs: size, retention, critical events',
'* Services: disable high-risk',
'* Registry/FS: NTFS protections',
'* Firewall/network: profiles, anonymous/NTLM controls',
'* Advanced audit: logon, object, privilege, system, policy changes',
'* Admin templates: control panel, components, telemetry',
'* Encryption/credentials: BitLocker, LSASS, Kerberos, VBS',
'* Misc: removable storage, remote assistance, diagnostics, legacy protocols'
  )
  $c['Windows Server']=@(
'* Account policies: complexity, age, history, lockout',
'* Local policies: audit, rights, DC settings',
'* Event logs: size, retention',
'* Services: spooler, remote registry',
'* Registry/FS: secure permissions',
'* Firewall/network: domain/private/public profiles, logging',
'* Advanced audit: account logon/management/object/privilege/policy/system',
'* Admin templates: apps, protocols, SMB, telemetry',
'* Encryption/credentials: Kerberos/NTLM restrictions, LSASS, BitLocker, VBS',
'* Misc: removable storage, remote assistance, diagnostics, insecure protocols'
  )
  switch($sel){
    0{Show-InfoBox @("Audit Coverage for O365",'')+$c['O365']}
    1{Show-InfoBox @("Audit Coverage for Windows PC",'')+$c['Windows PC']}
    2{Show-InfoBox @("Audit Coverage for Windows Server",'')+$c['Windows Server']}
    default{return}
  }
}

function Show-Help{
  $items=@('Credits','Open README.md','Quick Tips','View Audit Coverage','Exit Help')
  while($true){
    $sel=Read-MenuSelection 'Help' $items 0
    switch($sel){
      0{
        $packet=@(
"                ____ _ _ _ ____ ____ ___ ____ _  _ _    ____ ____",
"             :  [__  | | | |___ |___  |  |___ |\ | |    |  | |___",
"                ___] |_|_| |___ |___  |  |___ | \| |___ |__| |___"

        )
        foreach($line in $packet){Write-Host $line -ForegroundColor Magenta}
        [void]$Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
      }
      1{
        try{
          $p=Join-Path $PSScriptRoot 'README.md'
          if(Test-Path -LiteralPath $p){Invoke-Item -LiteralPath $p;Show-InfoBox @('README.md opened.','','Close the editor and press any key.')}
          else{Show-ErrorBox 'README.md not found.'}
        }catch{Show-ErrorBox("Failed to open README.md: "+$_.Exception.Message)}
      }
      2{Show-InfoBox @('Quick Tips:','','- Run Recommended Audit first.','- Use arrow keys and Space/Enter.','- Check ./logs after runs.','- Open HTML report from Post-Audit.')}
      3{Show-AuditCoverage}
      default{return}
    }
  }
}

function HtmlEscape([string]$s){if($null -eq $s){return ''};$s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;' -replace "'",'&#39;'}
function Get-DefaultTitle([string]$path){
  try{$first=Get-Content -LiteralPath $path -TotalCount 10;$nameLine=$first|Where-Object{$_ -like 'Machine name*'}|Select-Object -First 1;if($nameLine){$mn=($nameLine -split ':',2)[1].Trim();if($mn){return "Audit Report - $mn"}}}catch{}
  'Audit Report'
}
function Get-CodeParts([string]$code){
  $lettersArr=($code -replace "[^A-Za-z]",' ').Split(' ',[System.StringSplitOptions]::RemoveEmptyEntries)
  $letters=if($lettersArr.Length -gt 0){$lettersArr[0]}else{''}
  $numStart=$code.IndexOfAny(("0123456789".ToCharArray()))
  $numbers=if($numStart -ge 0){$code.Substring($numStart)}else{''}
  [pscustomobject]@{Letters=$letters;Numbers=$numbers;Full=$code}
}
function Load-Mapping([string]$mapPath){
  $mapping=[ordered]@{};$prefixes=@()
  if($mapPath -and (Test-Path -LiteralPath $mapPath)){
    try{$csv=Import-Csv -LiteralPath $mapPath;foreach($row in $csv){if($row.Code -and $row.Name){$mapping[$row.Code]=$row.Name}elseif($row.Prefix -and $row.Name){$prefixes+=[pscustomobject]@{Prefix=$row.Prefix;Name=$row.Name}}}}catch{}
  }
  $builtin=@(
    @{Prefix='PP';Name='Password Policy'},
    @{Prefix='ALP';Name='Account Lockout Policy'},
    @{Prefix='URA';Name='User Rights Assignment'},
    @{Prefix='WFDP';Name='Windows Firewall: Domain Profile'},
    @{Prefix='WFPPRIP';Name='Windows Firewall: Private Profile'},
    @{Prefix='WFPPUBP';Name='Windows Firewall: Public Profile'},
    @{Prefix='AA';Name='Advanced Audit Policy'},
    @{Prefix='WU';Name='Windows Update'},
    @{Prefix='WRR';Name='WinRM'},
    @{Prefix='WP';Name='PowerShell'},
    @{Prefix='WRS';Name='Remote Shell / WinRS'},
    @{Prefix='WS';Name='Windows Sandbox'},
    @{Prefix='WIW';Name='Windows Ink Workspace'},
    @{Prefix='CLOUDC';Name='Windows Spotlight / Cloud Content'},
    @{Prefix='NOTIF';Name='Notifications'},
    @{Prefix='PERS';Name='Personalization'}
  )
  $prefixes=@($prefixes+($builtin|ForEach-Object{[pscustomobject]$_}))
  [pscustomobject]@{Exact=$mapping;Prefixes=$prefixes}
}
function Get-FriendlyHeader([string]$code,$map,[switch]$IncludeCode){
  $parts=Get-CodeParts $code
  if($map -and $map.Exact.Contains($parts.Full)){ $name=$map.Exact[$parts.Full];return ($IncludeCode) ? "$name ($($parts.Full))" : $name }
  if($map -and $parts.Letters){
    $match=$map.Prefixes|Where-Object{$parts.Letters -like ("$($_.Prefix)*")}|Select-Object -First 1
    if($match){$suffix=if($parts.Numbers){" $($parts.Numbers)"}else{''};$name="$($match.Name)$suffix";return ($IncludeCode) ? "$name ($($parts.Full))" : $name}
  }
  $code
}
function Parse-Line([string]$line){
  $i=$line.IndexOf(';');if($i -lt 0){return $null}
  $code=$line.Substring(0,$i).Trim();$rest=$line.Substring($i+1)
  $j=$rest.LastIndexOf(';');$desc=$rest.Trim();$evidence=''
  if($j -gt 0){$desc=$rest.Substring(0,$j).Trim();$evidence=$rest.Substring($j+1).Trim()}
  $level='';$m=[regex]::Match($desc,'\(L(\d)\)');if($m.Success){$level='L'+$m.Groups[1].Value}
  [pscustomobject]@{Code=$code;Desc=$desc;Evidence=$evidence;Level=$level}
}
function Rank-Importance($item){if($item.Level -eq 'L1'){return 'High'};if($item.Level -eq 'L2'){return 'Medium'};if($item.Desc -match 'password|firewall|audit|winrm|remote shell|update'){return 'High'};'Low'}
function Extract-RecommendedNumber([string]$d,[int]$fallback){
  $m=[regex]::Match($d,'(?i)value\s+must\s+be\s+(\d+)');if($m.Success){return [int]$m.Groups[1].Value}
  $m=[regex]::Match($d,'(?i)(\d+)\s+or\s+more');if($m.Success){return [int]$m.Groups[1].Value}
  $m=[regex]::Match($d,'(?i)(\d+)\s+or\s+fewer|less');if($m.Success){return [int]$m.Groups[1].Value}
  $fallback
}
function Get-Remediation($item){
  $desc=$item.Desc;$parts=Get-CodeParts $item.Code;$prefix=$parts.Letters;$cmd='';$gui=''
  switch -Regex($prefix){
    '^PP'{
      $gui='Local Security Policy -> Account Policies -> Password Policy'
      if($desc -match '(?i)Enforce password history'){$n=Extract-RecommendedNumber $desc 24;$cmd="net accounts /uniquepw:$n"}
      elseif($desc -match '(?i)Maximum password age'){$n=Extract-RecommendedNumber $desc 365;$cmd="net accounts /maxpwage:$n"}
      elseif($desc -match '(?i)Minimum password age'){$n=Extract-RecommendedNumber $desc 1;$cmd="net accounts /minpwage:$n"}
      elseif($desc -match '(?i)Minimum password length'){$n=Extract-RecommendedNumber $desc 14;$cmd="net accounts /minpwlen:$n"}
      elseif($desc -match '(?i)Password must meet complexity requirements'){ $val= if($desc -match '(?i)Enabled'){1}else{0};$cmd=("`$inf=[IO.Path]::GetTempFileName().Replace('.tmp','.inf)';@'[System Access]`nPasswordComplexity = $val`n'@|Set-Content -Path `$inf -Encoding ASCII;secedit /configure /db secedit.sdb /cfg `"`$inf`" /areas SECURITYPOLICY") }
      elseif($desc -match '(?i)reversible encryption'){ $val= if($desc -match '(?i)Disabled'){0}else{1};$cmd=("`$inf=[IO.Path]::GetTempFileName().Replace('.tmp','.inf)';@'[System Access]`nClearTextPassword = $val`n'@|Set-Content -Path `$inf -Encoding ASCII;secedit /configure /db secedit.sdb /cfg `"`$inf`" /areas SECURITYPOLICY") }
    }
    '^ALP'{
      $gui='Local Security Policy -> Account Policies -> Account Lockout Policy'
      if($desc -match '(?i)duration'){$n=Extract-RecommendedNumber $desc 15;$cmd="net accounts /lockoutduration:$n"}
      elseif($desc -match '(?i)threshold'){$n=Extract-RecommendedNumber $desc 5;$cmd="net accounts /lockoutthreshold:$n"}
      elseif($desc -match '(?i)counter|observation window'){$n=Extract-RecommendedNumber $desc 15;$cmd="net accounts /lockoutwindow:$n"}
    }
    '^URA'{
      $gui='Local Security Policy -> Local Policies -> User Rights Assignment'
      $priv='';if($item.Evidence -match '(Se\w+)'){$priv=$Matches[1]};if(-not $priv -and $desc -match '(Se\w+)'){$priv=$Matches[1]}
      $principals='';$m=[regex]::Match($desc,'(?<=,).*$');if($m.Success){$principals=($m.Value -replace ';.*$','').Trim()}
      if($priv){$cmd=("`$inf=[IO.Path]::GetTempFileName().Replace('.tmp','.inf)';@'[Privilege Rights]`n$priv = $principals`n'@|Set-Content -Path `$inf -Encoding ASCII;secedit /configure /db secedit.sdb /cfg `"`$inf`" /areas USER_RIGHTS")}
    }
    '^(WFDP|WFPPRIP|WFPPUBP)$'{
      $profile=if($prefix -eq 'WFDP'){'Domain'}elseif($prefix -eq 'WFPPRIP'){'Private'}else{'Public'}
      $gui='Windows Defender Firewall with Advanced Security -> Windows Defender Firewall Properties -> '+$profile+' Profile'
      if($desc -match '(?i)Firewall state'){$cmd="Set-NetFirewallProfile -Profile $profile -Enabled True"}
      elseif($desc -match '(?i)Inbound connections'){$cmd="Set-NetFirewallProfile -Profile $profile -DefaultInboundAction Block"}
      elseif($desc -match '(?i)Outbound connections'){$cmd="Set-NetFirewallProfile -Profile $profile -DefaultOutboundAction Allow"}
      elseif($desc -match '(?i)Logging: Name'){$path='%systemroot%\system32\LogFiles\Firewall\pfirewall.log';if($item.Evidence -match '(?i)[A-Z]:\\[^;]+'){$path=$Matches[0]};$cmd="Set-NetFirewallProfile -Profile $profile -LogFileName `"$path`""}
      elseif($desc -match '(?i)Size limit'){$n=Extract-RecommendedNumber $desc 16384;$cmd="Set-NetFirewallProfile -Profile $profile -LogMaxSizeKilobytes $n"}
      elseif($desc -match '(?i)Log dropped packets'){$cmd="Set-NetFirewallProfile -Profile $profile -LogBlocked True"}
      elseif($desc -match '(?i)Log successful connections'){$cmd="Set-NetFirewallProfile -Profile $profile -LogAllowed True"}
    }
    '^AA'{
      $gui='Local Security Policy -> Advanced Audit Policy Configuration -> Audit Policies'
      $m=[regex]::Match($desc,"'([^']+)'");$sub= if($m.Success){$m.Groups[1].Value}else{''}
      $success=($desc -match '(?i)Success');$failure=($desc -match '(?i)Failure')
      if($sub){$s= if($success){'enable'}else{'disable'};$f= if($failure){'enable'}else{'disable'};$cmd="auditpol /set /subcategory:'$sub' /success:$s /failure:$f"}
    }
    Default{$gui='gpedit.msc -> Computer Configuration -> Administrative Templates -> (search policy)'}
  }
  if(-not $cmd){$cmd='# Review policy manually; remediation not auto-generated.'}
  [pscustomobject]@{Command=$cmd;GuiPath=$gui}
}

function OwO-ConvertAuditToHtml{
  param(
    [Parameter(Mandatory=$true)][string]$InputPath,
    [Parameter(Mandatory=$true)][string]$OutputPath,
    [string]$Title='Audit Report',
    [switch]$UseFriendlyNames,
    [string]$MappingPath,
    [switch]$IncludeCode
  )
  if(-not(Test-Path -LiteralPath $InputPath)){throw "Input file not found: $InputPath"}
  if(-not $PSBoundParameters.ContainsKey('Title') -or [string]::IsNullOrWhiteSpace($Title)){$Title=Get-DefaultTitle -path $InputPath}

  $lines=Get-Content -LiteralPath $InputPath|Where-Object{$_ -match ';'}
  $items=@();foreach($line in $lines){$p=Parse-Line $line;if($null -ne $p){$items+=$p}}
  $map=$null;if($UseFriendlyNames){$map=Load-Mapping -mapPath $MappingPath}
  $groups=[ordered]@{};foreach($it in $items){if(-not $groups.Contains($it.Code)){$groups[$it.Code]=[System.Collections.Generic.List[object]]::new()};$null=$groups[$it.Code].Add($it)}

  $findings=@()
  foreach($code in $groups.Keys){
    $bucket=$groups[$code]
    if($bucket.Count -eq 0){continue}
    $header= if($UseFriendlyNames){Get-FriendlyHeader -code $code -map $map -includeCode:$IncludeCode}else{$code}
    $importance=Rank-Importance $bucket[0]
    $findings+=[pscustomobject]@{Code=$code;Header=$header;Importance=$importance;Items=$bucket}
  }

  $counts=@{High=0;Medium=0;Low=0}
  foreach($f in $findings){
    if($counts.ContainsKey($f.Importance)){$counts[$f.Importance]++}else{$counts[$f.Importance]=1}
  }
  foreach($key in @('High','Medium','Low')){if(-not $counts.ContainsKey($key)){$counts[$key]=0}}

  $totalFindings=$findings.Count
  $totalItems=$items.Count
  $weighted=($counts.High*25)+($counts.Medium*15)+($counts.Low*8)
  if($totalFindings -gt 0 -and $weighted -le 0){
    $weighted=[math]::Round((($counts.High*3)+($counts.Medium*2)+$counts.Low)*100.0/($totalFindings*3),0)
  }
  $riskScore=[math]::Min(100,[math]::Round([double]$weighted,0))
  $riskLabel=if($riskScore -ge 80){'Severe Exposure'}elseif($riskScore -ge 55){'Elevated Exposure'}elseif($riskScore -ge 35){'Guarded'}elseif($riskScore -gt 0){'Low Exposure'}else{'Stable'}
  $riskProgress=if($riskScore -gt 0){$riskScore}else{5}

  $fileInfo=Get-Item -LiteralPath $InputPath
  $generatedAt=Get-Date
  $reportId=[IO.Path]::GetFileNameWithoutExtension($OutputPath)
  $inputName=$fileInfo.Name
  $outputName=[IO.Path]::GetFileName($OutputPath)
  $profileName=''
  if($Title -match '-\s*(.+)$'){$profileName=$Matches[1].Trim()}
  if(-not $profileName){$profileName=Split-Path -Leaf $InputPath}
  $defaultTitle=Get-DefaultTitle -path $InputPath
  $machineName=''
  if($defaultTitle -match 'Audit Report -\s*(.+)'){$machineName=$Matches[1].Trim()}
  if(-not $machineName){$machineName='Target host not captured'}
  $auditDateUtc=$fileInfo.LastWriteTimeUtc
  $auditDateDisplay=try{$auditDateUtc.ToString('yyyy-MM-dd HH:mm')}catch{'--'}
  $auditDateDisplay+=$auditDateDisplay -ne '--' ? ' UTC' : ''

  $friendlyMode=if($UseFriendlyNames){'Enabled'}else{'Disabled'}
  $codeMode=if($IncludeCode){'Included inline'}else{'Hidden'}

  $bySeverity=@{
    High=[System.Collections.Generic.List[object]]::new()
    Medium=[System.Collections.Generic.List[object]]::new()
    Low=[System.Collections.Generic.List[object]]::new()
  }
  foreach($finding in $findings){
    if(-not $bySeverity.ContainsKey($finding.Importance)){
      $bySeverity[$finding.Importance]=[System.Collections.Generic.List[object]]::new()
    }
    $null=$bySeverity[$finding.Importance].Add($finding)
  }

  $resolveCategory={
    param($code,$mapping)
    $parts=Get-CodeParts $code
    if($mapping -and $mapping.Prefixes){
      $match=$mapping.Prefixes|Where-Object{$parts.Letters -and ($parts.Letters -like ("$($_.Prefix)*"))}|Select-Object -First 1
      if($match){return $match.Name}
    }
    if($parts.Letters){return $parts.Letters.ToUpperInvariant()}
    'General'
  }

  $filterChips=[System.Collections.Generic.List[string]]::new()
  if($bySeverity.High.Count -gt 0){$filterChips.Add("<a class='chip high' href='#high-findings'>High ($($bySeverity.High.Count))</a>")}
  if($bySeverity.Medium.Count -gt 0){$filterChips.Add("<a class='chip medium' href='#medium-findings'>Medium ($($bySeverity.Medium.Count))</a>")}
  if($bySeverity.Low.Count -gt 0){$filterChips.Add("<a class='chip low' href='#low-findings'>Low ($($bySeverity.Low.Count))</a>")}
  $filterChips.Add("<a class='chip timeline' href='#timeline'>Timeline</a>")
  $filterMarkup=[string]::Join([Environment]::NewLine,$filterChips)

  $validCreation=$fileInfo.CreationTimeUtc
  $timeline=@()
  if($validCreation -gt [datetime]'2000-01-01'){
    $timeline+=[pscustomobject]@{Time=$validCreation;Desc="Source log captured (`$inputName`)"}
  }
  $timeline+=[pscustomobject]@{Time=$fileInfo.LastWriteTimeUtc;Desc="$totalItems finding record(s) parsed and grouped"}
  $timeline+=[pscustomobject]@{Time=$generatedAt.ToUniversalTime();Desc="HTML report generated (`$outputName`)"}
  $fmtTime={param($ts)if(-not $ts){return '--:--'};try{return ($ts.ToLocalTime()).ToString('HH:mm')}catch{return $ts.ToString()}}

  $css=@"
:root{
  color-scheme: light dark;
  --bg:#f3f4f9;
  --surface:#ffffff;
  --surface-soft:#f8f9fc;
  --border:#d8dde7;
  --text:#1f2937;
  --muted:#5f6b7d;
  --accent:#2563eb;
  --accent-dark:#1d4ed8;
  --high:#e11d48;
  --medium:#f97316;
  --low:#059669;
  --info:#0ea5e9;
  --masthead-gradient:linear-gradient(135deg,#111827 0%,#1e3a8a 55%,#2563eb 100%);
  --masthead-text:#e2e8f0;
  --subtitle:rgba(226,232,240,0.8);
  --masthead-meta-bg:rgba(15,23,42,0.4);
  --risk-label-bg:rgba(225,29,72,0.12);
  --risk-score-glow:radial-gradient(circle at top right,rgba(37,99,235,0.1),transparent 55%);
  --pre-bg:#0f172a;
  --pre-text:#e2e8f0;
  --shadow:0 12px 30px rgba(15,23,42,0.12);
  --legend-bg:#f8faff;
  --legend-border:rgba(148,163,184,0.38);
  --chip-bg:#e0e7ff;
  --chip-border:rgba(37,99,235,0.35);
  --chip-text:#1d4ed8;
  --chip-hover-bg:rgba(37,99,235,0.08);
  --badge-bg:rgba(226,232,240,0.18);
  --badge-border:rgba(148,163,184,0.45);
  --badge-text:#f8fafc;
  --table-divider:#e5e7eb;
  font-family:"Segoe UI","Inter","Roboto",system-ui,-apple-system,sans-serif;
}
*{box-sizing:border-box}
body{
  margin:0;
  background:var(--bg);
  color:var(--text);
  line-height:1.6;
}
.page{
  max-width:960px;
  margin:48px auto;
  padding:0 32px 64px;
}
.masthead{
  background:var(--masthead-gradient);
  color:var(--masthead-text);
  border-radius:18px;
  padding:32px 36px;
  box-shadow:var(--shadow);
  display:grid;
  grid-template-columns:minmax(260px,1fr) minmax(220px,auto);
  gap:28px;
  align-items:start;
}
.brand{
  display:flex;
  align-items:center;
  gap:20px;
  min-width:260px;
}
.brand-mark{
  width:60px;
  height:60px;
  border-radius:16px;
  background:rgba(226,232,240,0.12);
  display:grid;
  place-items:center;
  font-weight:600;
  font-size:1.35rem;
  letter-spacing:1px;
}
.brand h1{
  margin:0;
  font-size:1.65rem;
}
.brand .subtitle{
  margin:6px 0 0;
  font-size:0.95rem;
  color:var(--subtitle);
}
.brand .tagline{
  margin:10px 0 0;
  font-size:0.9rem;
  color:var(--subtitle);
  letter-spacing:0.01em;
}
.masthead-meta{
  display:grid;
  gap:6px;
  font-size:0.95rem;
  margin-left:auto;
  min-width:220px;
}
.masthead-meta span{
  background:var(--masthead-meta-bg);
  padding:6px 10px;
  border-radius:10px;
}
.masthead-badges{
  grid-column:1 / -1;
  display:flex;
  flex-wrap:wrap;
  gap:10px;
  justify-content:flex-end;
}
.report-badge{
  border:1px solid var(--badge-border);
  background:var(--badge-bg);
  color:var(--badge-text);
  font-size:0.8rem;
  letter-spacing:0.08em;
  text-transform:uppercase;
  padding:6px 14px;
  border-radius:999px;
  display:inline-flex;
  align-items:center;
  gap:6px;
}
.report-badge::before{
  content:"";
  width:8px;
  height:8px;
  border-radius:50%;
  background:var(--info);
  box-shadow:0 0 8px rgba(14,165,233,0.35);
}
.report-badge.draft::before{background:var(--medium);}
.section-title{
  margin:48px 0 16px;
  font-size:1.35rem;
  font-weight:600;
  letter-spacing:0.025em;
  text-transform:uppercase;
  color:var(--text);
}
.summary-grid{
  display:grid;
  grid-template-columns:repeat(auto-fit,minmax(220px,1fr));
  gap:20px;
}
.summary-subgrid{
  margin-top:20px;
  display:grid;
  grid-template-columns:repeat(auto-fit,minmax(280px,1fr));
  gap:20px;
}
.card{
  background:var(--surface);
  border:1px solid var(--border);
  border-radius:16px;
  padding:24px;
  box-shadow:0 2px 12px rgba(15,23,42,0.05);
}
.card h3{
  margin:0;
  font-size:1.1rem;
  font-weight:600;
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:12px;
}
.risk-score{
  position:relative;
  overflow:hidden;
}
.risk-score::after{
  content:"";
  position:absolute;
  inset:0;
  background:var(--risk-score-glow);
  pointer-events:none;
}
.risk-value{
  margin:16px 0 4px;
  font-size:2.25rem;
  font-weight:700;
  letter-spacing:0.02em;
}
.risk-label{
  display:inline-flex;
  align-items:center;
  gap:8px;
  padding:6px 12px;
  border-radius:999px;
  font-size:0.95rem;
  background:var(--risk-label-bg);
  color:var(--high);
}
.risk-label::before{
  content:"";
  width:10px;
  height:10px;
  border-radius:50%;
  background:var(--high);
}
.progress-bar{
  background:var(--surface-soft);
  border-radius:999px;
  margin-top:18px;
  height:10px;
  overflow:hidden;
}
.progress-bar span{
  display:block;
  height:100%;
  background:linear-gradient(90deg,var(--accent),var(--accent-dark));
}
.badge{
  display:inline-flex;
  align-items:center;
  gap:8px;
  font-size:0.9rem;
  font-weight:600;
  padding:4px 12px;
  border-radius:999px;
  color:#fff;
}
.badge.high{background:var(--high)}
.badge.medium{background:var(--medium)}
.badge.low{background:var(--low)}
.badge.info{background:var(--info)}
.metrics{
  display:grid;
  gap:12px;
  margin-top:18px;
}
.metrics-row{
  display:flex;
  justify-content:space-between;
  align-items:center;
  font-size:0.95rem;
}
.metrics-bar{
  width:55%;
  min-width:180px;
  height:8px;
  border-radius:999px;
  background:var(--surface-soft);
  overflow:hidden;
}
.metrics-bar span{
  display:block;
  height:100%;
}
.metrics-card .badge{font-size:0.75rem;padding:3px 10px;}
.metrics-table{
  width:100%;
  border-collapse:collapse;
  margin-top:12px;
}
.metrics-table tr + tr{border-top:1px solid var(--table-divider);}
.metrics-table th{
  text-align:left;
  font-size:0.85rem;
  font-weight:600;
  color:var(--muted);
  padding:8px 0;
  text-transform:uppercase;
  letter-spacing:0.05em;
}
.metrics-table td{
  font-size:0.95rem;
  padding:8px 0;
  color:var(--text);
}
.legend-card{
  background:var(--legend-bg);
  border:1px solid var(--legend-border);
}
.legend-list{
  list-style:none;
  margin:12px 0 0;
  padding:0;
  display:grid;
  gap:10px;
}
.legend-list li{
  display:flex;
  align-items:center;
  gap:12px;
  font-size:0.95rem;
  color:var(--muted);
}
.legend-swatch{
  width:16px;
  height:16px;
  border-radius:4px;
  flex-shrink:0;
}
.legend-swatch.high{background:var(--high);}
.legend-swatch.medium{background:var(--medium);}
.legend-swatch.low{background:var(--low);}
.legend-swatch.info{background:var(--info);}
.filter-chips{
  margin-top:18px;
  display:flex;
  flex-wrap:wrap;
  gap:10px;
}
.chip{
  display:inline-flex;
  align-items:center;
  gap:8px;
  padding:6px 14px;
  border-radius:999px;
  text-decoration:none;
  font-size:0.85rem;
  font-weight:600;
  border:1px solid var(--chip-border);
  background:var(--chip-bg);
  color:var(--chip-text);
  transition:background 0.2s ease, transform 0.2s ease;
}
.chip::before{
  content:"";
  width:8px;
  height:8px;
  border-radius:50%;
  background:currentColor;
}
.chip:hover{
  background:var(--chip-hover-bg);
  transform:translateY(-1px);
}
.chip.high{
  border-color:rgba(225,29,72,0.45);
  background:rgba(225,29,72,0.14);
  color:var(--high);
}
.chip.medium{
  border-color:rgba(249,115,22,0.4);
  background:rgba(249,115,22,0.14);
  color:var(--medium);
}
.chip.low{
  border-color:rgba(5,150,105,0.35);
  background:rgba(5,150,105,0.12);
  color:var(--low);
}
.chip.timeline{
  border-color:rgba(14,165,233,0.4);
  background:rgba(14,165,233,0.12);
  color:var(--info);
}
.finding{
  background:var(--surface);
  border:1px solid var(--border);
  border-radius:18px;
  padding:24px;
  margin-bottom:18px;
  position:relative;
  box-shadow:0 3px 16px rgba(15,23,42,0.06);
}
.finding .heading{
  display:flex;
  flex-wrap:wrap;
  gap:16px;
  align-items:flex-start;
}
.finding h4{
  margin:0;
  font-size:1.1rem;
  font-weight:600;
}
.finding .controls{
  margin-left:auto;
  display:flex;
  gap:10px;
  flex-wrap:wrap;
}
.pill{
  border-radius:999px;
  border:1px solid var(--border);
  padding:6px 12px;
  font-size:0.85rem;
  color:var(--muted);
}
.finding p{
  margin:14px 0 12px;
  color:var(--muted);
}
.finding pre{
  margin:0;
  background:var(--pre-bg);
  color:var(--pre-text);
  padding:16px;
  border-radius:12px;
  font-size:0.9rem;
  overflow-x:auto;
}
.finding footer{
  margin-top:14px;
  font-size:0.85rem;
  color:var(--muted);
  display:flex;
  flex-wrap:wrap;
  gap:16px;
}
.timeline{
  background:var(--surface-soft);
  border-radius:16px;
  padding:20px 26px;
  border:1px dashed var(--border);
}
.timeline-item{
  display:flex;
  gap:14px;
  align-items:flex-start;
  padding:10px 0;
}
.timeline-item time{
  font-weight:600;
  font-size:0.95rem;
  min-width:120px;
  color:var(--muted);
}
.timeline-item p{
  margin:0;
  font-size:0.95rem;
}
.footnote{
  margin-top:48px;
  font-size:0.85rem;
  color:var(--muted);
  text-align:center;
}
@media (max-width:720px){
  .page{padding:0 20px 48px}
  .masthead{padding:28px;grid-template-columns:1fr}
  .brand{flex:1 1 100%}
  .masthead-meta{width:100%;margin-left:0}
  .masthead-badges{justify-content:flex-start}
  .finding .controls{width:100%;justify-content:flex-start}
  .summary-subgrid{grid-template-columns:1fr}
}
@media print{
  body{background:#fff}
  .page{margin:24px auto;padding:0}
  .masthead{box-shadow:none}
  .masthead-badges{justify-content:flex-start}
  .filter-chips{display:none}
  .finding, .card{page-break-inside:avoid;box-shadow:none}
}
"@

  $html=[System.Text.StringBuilder]::new()
  [void]$html.AppendLine('<!doctype html>')
  [void]$html.AppendLine("<html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'><title>$(HtmlEscape $Title)</title><style>$css</style></head><body>")
  [void]$html.AppendLine('<div class="page">')
  [void]$html.AppendLine('  <header class="masthead">')
  [void]$html.AppendLine('    <div class="brand">')
  [void]$html.AppendLine('      <div class="brand-mark">OW</div>')
  [void]$html.AppendLine('      <div>')
  [void]$html.AppendLine("        <h1>$(HtmlEscape $Title)</h1>")
  [void]$html.AppendLine("        <p class='subtitle'>System: $(HtmlEscape $machineName)</p>")
  [void]$html.AppendLine("        <p class='tagline'>Profile: $(HtmlEscape $profileName)</p>")
  [void]$html.AppendLine('      </div>')
  [void]$html.AppendLine('    </div>')
  [void]$html.AppendLine('    <div class="masthead-meta">')
  [void]$html.AppendLine("      <span>Audit Date: $(HtmlEscape $auditDateDisplay)</span>")
  [void]$html.AppendLine("      <span>Auditor: OmniWin Auditor (PowerShell)</span>")
  [void]$html.AppendLine("      <span>Report ID: $(HtmlEscape $reportId)</span>")
  [void]$html.AppendLine('    </div>')
  [void]$html.AppendLine('    <div class="masthead-badges">')
  [void]$html.AppendLine('      <span class="report-badge">Confidential</span>')
  [void]$html.AppendLine('      <span class="report-badge draft">Automated Scan</span>')
  [void]$html.AppendLine('    </div>')
  [void]$html.AppendLine('  </header>')

  [void]$html.AppendLine('  <section>')
  [void]$html.AppendLine('    <h2 class="section-title">Executive Summary</h2>')
  [void]$html.AppendLine('    <div class="summary-grid">')
  [void]$html.AppendLine('      <article class="card risk-score">')
  [void]$html.AppendLine('        <h3>Overall Risk Score</h3>')
  [void]$html.AppendLine("        <div class='risk-value'>$riskScore</div>")
  [void]$html.AppendLine("        <span class='risk-label'>$(HtmlEscape $riskLabel)</span>")
  [void]$html.AppendLine("        <div class='progress-bar'><span style='width:$riskProgress%'></span></div>")
  [void]$html.AppendLine('      </article>')
  [void]$html.AppendLine('      <article class="card">')
  [void]$html.AppendLine('        <h3>Findings by Severity</h3>')
  [void]$html.AppendLine('        <div class="metrics">')
  [void]$html.AppendLine("          <div class='metrics-row'><span class='badge high'>High · $($counts.High)</span><div class='metrics-bar'><span style='width:$([math]::Min(100,[math]::Max(5,[math]::Round(($counts.High*100)/[math]::Max($totalFindings,1)))) )%;background:rgba(225,29,72,0.65)'></span></div></div>")
  [void]$html.AppendLine("          <div class='metrics-row'><span class='badge medium'>Medium · $($counts.Medium)</span><div class='metrics-bar'><span style='width:$([math]::Min(100,[math]::Max(5,[math]::Round(($counts.Medium*100)/[math]::Max($totalFindings,1)))) )%;background:rgba(249,115,22,0.55)'></span></div></div>")
  [void]$html.AppendLine("          <div class='metrics-row'><span class='badge low'>Low · $($counts.Low)</span><div class='metrics-bar'><span style='width:$([math]::Min(100,[math]::Max(5,[math]::Round(($counts.Low*100)/[math]::Max($totalFindings,1)))) )%;background:rgba(5,150,105,0.45)'></span></div></div>")
  [void]$html.AppendLine('        </div>')
  [void]$html.AppendLine('      </article>')
  $focusText=if($counts.High -gt 0){"Prioritize $($counts.High) high severity control$(if($counts.High -gt 1){'s'}) across $($bySeverity.High.Count) category scope(s)."}elseif($counts.Medium -gt 0){"Address $($counts.Medium) medium findings during the next maintenance window."}elseif($totalFindings -gt 0){"Review remaining low-risk configuration drift and document risk acceptance."}else{"No deviations detected in this pass."}
  [void]$html.AppendLine('      <article class="card">')
  [void]$html.AppendLine('        <h3>Coverage Status</h3>')
  [void]$html.AppendLine("        <p>Findings recorded: $totalItems record$(if($totalItems -eq 1){''}else{'s'}) across $totalFindings control grouping$(if($totalFindings -eq 1){''}else{'s'}).</p>")
  [void]$html.AppendLine("        <p>$(HtmlEscape $focusText)</p>")
  [void]$html.AppendLine('      </article>')
  [void]$html.AppendLine('    </div>')
  [void]$html.AppendLine('  </section>')

  [void]$html.AppendLine('  <section class="summary-aux">')
  [void]$html.AppendLine('    <div class="summary-subgrid">')
  [void]$html.AppendLine("      <article class='card metrics-card'><h3>Key Metrics <span class='badge info'>Snapshot</span></h3>")
  [void]$html.AppendLine('        <table class="metrics-table"><tbody>')
  [void]$html.AppendLine("          <tr><th scope='row'>Input Source</th><td>$(HtmlEscape $inputName)</td></tr>")
  [void]$html.AppendLine("          <tr><th scope='row'>Profile</th><td>$(HtmlEscape $profileName)</td></tr>")
  [void]$html.AppendLine("          <tr><th scope='row'>Friendly Names</th><td>$friendlyMode</td></tr>")
  [void]$html.AppendLine("          <tr><th scope='row'>Control IDs</th><td>$codeMode</td></tr>")
  [void]$html.AppendLine("          <tr><th scope='row'>Unique Categories</th><td>$($groups.Keys.Count)</td></tr>")
  [void]$html.AppendLine("          <tr><th scope='row'>Total Findings</th><td>$totalFindings grouping$(if($totalFindings -eq 1){''}else{'s'}) / $totalItems record$(if($totalItems -eq 1){''}else{'s'})</td></tr>")
  [void]$html.AppendLine('        </tbody></table>')
  [void]$html.AppendLine('      </article>')
  [void]$html.AppendLine('      <article class="card legend-card">')
  [void]$html.AppendLine('        <h3>Severity Legend &amp; Filters</h3>')
  [void]$html.AppendLine('        <ul class="legend-list">')
  [void]$html.AppendLine('          <li><span class="legend-swatch high"></span>High · Immediate mitigation recommended</li>')
  [void]$html.AppendLine('          <li><span class="legend-swatch medium"></span>Medium · Address during next maintenance window</li>')
  [void]$html.AppendLine('          <li><span class="legend-swatch low"></span>Low · Monitor or accept with documented rationale</li>')
  [void]$html.AppendLine('          <li><span class="legend-swatch info"></span>Informational · Track for documentation or exception</li>')
  [void]$html.AppendLine('        </ul>')
  [void]$html.AppendLine("        <div class='filter-chips'>$filterMarkup</div>")
  [void]$html.AppendLine('      </article>')
  [void]$html.AppendLine('    </div>')
  [void]$html.AppendLine('  </section>')

  $severitySections=@(
    @{Key='High';Id='high-findings';Title='Critical &amp; High Priority Findings';BadgeClass='high'}
    @{Key='Medium';Id='medium-findings';Title='Medium Priority Findings';BadgeClass='medium'}
    @{Key='Low';Id='low-findings';Title='Low Priority &amp; Advisory Items';BadgeClass='low'}
  )
  foreach($section in $severitySections){
    $sev=$section.Key
    $entries=$bySeverity[$sev]
    if(-not $entries -or $entries.Count -eq 0){continue}
    [void]$html.AppendLine("  <section id='$($section.Id)'>")
    [void]$html.AppendLine("    <h2 class='section-title'>$($section.Title)</h2>")
    foreach($finding in $entries){
      $cat=& $resolveCategory $finding.Code $map
      [void]$html.AppendLine('    <article class="finding">')
      [void]$html.AppendLine('      <div class="heading">')
      [void]$html.AppendLine("        <h4>$(HtmlEscape $finding.Header)</h4>")
      [void]$html.AppendLine("        <span class='badge $($section.BadgeClass)'>$sev</span>")
      [void]$html.AppendLine('        <div class="controls">')
      [void]$html.AppendLine("          <span class='pill'>Category: $(HtmlEscape $cat)</span>")
      if(-not $IncludeCode){[void]$html.AppendLine("          <span class='pill'>Control: $(HtmlEscape $finding.Code)</span>")}
      [void]$html.AppendLine('        </div>')
      [void]$html.AppendLine('      </div>')
      foreach($item in $finding.Items){
        $rem=Get-Remediation $item
        $descEsc=HtmlEscape $item.Desc
        $eviEsc=HtmlEscape $item.Evidence
        $guiEsc=HtmlEscape $rem.GuiPath
        $cmdEsc=HtmlEscape $rem.Command
        [void]$html.AppendLine("      <p>$descEsc</p>")
        [void]$html.AppendLine("      <pre>$cmdEsc</pre>")
        [void]$html.AppendLine('      <footer>')
        if($item.Evidence){[void]$html.AppendLine("        <span>Evidence: $eviEsc</span>")}
        [void]$html.AppendLine("        <span>GUI: $guiEsc</span>")
        [void]$html.AppendLine("        <span>Code ID: $(HtmlEscape $finding.Code)</span>")
        [void]$html.AppendLine('      </footer>')
      }
      [void]$html.AppendLine('    </article>')
    }
    [void]$html.AppendLine('  </section>')
  }

  [void]$html.AppendLine("  <section id='timeline'>")
  [void]$html.AppendLine('    <h2 class="section-title">Audit Timeline &amp; Notes</h2>')
  [void]$html.AppendLine('    <div class="timeline">')
  foreach($entry in $timeline){
    $time=& $fmtTime $entry.Time
    $desc=HtmlEscape $entry.Desc
    [void]$html.AppendLine('      <div class="timeline-item">')
    [void]$html.AppendLine("        <time>$time</time>")
    [void]$html.AppendLine("        <p>$desc</p>")
    [void]$html.AppendLine('      </div>')
  }
  [void]$html.AppendLine('    </div>')
  [void]$html.AppendLine('  </section>')

  [void]$html.AppendLine("  <p class='footnote'>Report generated $(HtmlEscape ($generatedAt.ToString('yyyy-MM-dd HH:mm'))) local time. Review remediation commands carefully before execution.</p>")
  [void]$html.AppendLine('</div>')
  [void]$html.AppendLine('</body></html>')

  [IO.File]::WriteAllText($OutputPath,$html.ToString(),[Text.Encoding]::UTF8)
}

function OwO-ListCategories{
  param([Parameter(Mandatory=$true)][string]$InputPath)
  if(-not(Test-Path -LiteralPath $InputPath)){throw "Input not found: $InputPath"}
  $set=[System.Collections.Generic.HashSet[string]]::new()
  foreach($l in (Get-Content -LiteralPath $InputPath)){
    if(-not($l -like '*;*')){continue}
    $code=($l -split ';',2)[0].Trim();if(-not $code){continue}
    $m=[regex]::Match($code,'^[A-Za-z]+');if($m.Success){[void]$set.Add($m.Value)}
  }
  $set|Sort-Object
}

function Show-MainMenu{
  $os=Get-OsInfo
  while($true){
    Clear-Host
    Draw-Box @("Detected OS: $($os.Caption) ($($os.Version), $($os.Arch))",'Use Up/Down to navigate, Space/Enter to select.') 'DarkCyan' 'White'
    $items=@('Recommended Audit for Your OS','Browse Other OS Audits','Help','Exit')
    $sel=Read-MenuSelection 'Main Menu' $items 0
    switch($sel){
      0{Show-Recommended}
      1{Show-Browse}
      2{Show-Help}
      default{return}
    }
  }
}

function Show-Banner{
  $banner=@(
'~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~',
'~ _______  _______  _       _________         _________ _       ~',
'~(  ___  )(       )( (    /|\__   __/|\     /|\__   __/( (    /|~',
'~| (   ) || () () ||  \  ( |   ) (   | )   ( |   ) (   |  \  ( |~',
'~| |   | || || || ||   \ | |   | |   | | _ | |   | |   |   \ | |~',
'~| |   | || |(_)| || (\ \) |   | |   | |( )| |   | |   | (\ \) |~',
'~| |   | || |   | || | \   |   | |   | || || |   | |   | | \   |~',
'~| (___) || )   ( || )  \  |___) (___| () () |___) (___| )  \  |~',
'~(_______)|/     \||/    )_)\_______/(_______)\_______/|/    )_)~',
'~ _______           ______  __________________ _______  _______ ~',
'~(  ___  )|\     /|(  __  \ \__   __/\__   __/(  ___  )(  ____ )~',
'~| (   ) || )   ( || (  \  )   ) (      ) (   | (   ) || (    )|~',
'~| (___) || |   | || |   ) |   | |      | |   | |   | || (____)|~',
'~|  ___  || |   | || |   | |   | |      | |   | |   | ||     __)~',
'~| (   ) || |   | || |   ) |   | |      | |   | |   | || (\ (   ~',
'~| )   ( || (___) || (__/  )___) (___   | |   | (___) || ) \ \__~',
'~|/     \|(_______)(______/ \_______/   )_(   (_______)|/   \__/~',
'~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~'
  )
  $delay=1.5/$banner.Count
  foreach($line in $banner){Write-Host $line -ForegroundColor Green;Start-Sleep -Seconds $delay}
  Write-Host '                    Press any key to continue...' -ForegroundColor DarkGreen
}

try{
  Ensure-ModuleNamingAndComments
  $matrix=Get-CisPdfVersionMatrix
  if($matrix){
    $logDir=Ensure-LogFolder;$sum=Join-Path $logDir 'cis_versions_summary.txt'
    '# CIS PDF Versions'|Set-Content -LiteralPath $sum -Encoding UTF8
    foreach($row in $matrix){("- "+$row.Product+": "+([string]::Join(', ',$row.Versions)))|Add-Content -LiteralPath $sum -Encoding UTF8}
  }
}catch{}

Show-Banner
[void]$Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
Show-MainMenu
