param([string]$ReportPath = (Join-Path $PSScriptRoot 'logs/audit-LINTELSOUP.html'))
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:HistoryPath = Join-Path $PSScriptRoot 'logs/resolution-history.json'
$script:AppliedHistory = $null
function LoadHistory {
    param([string]$Path)
    $list = [System.Collections.Generic.List[object]]::new()
    if (-not $Path) { return $list }
    if (Test-Path $Path) {
        try {
            $raw = Get-Content -Path $Path -Raw
            if (-not [string]::IsNullOrWhiteSpace($raw)) {
                $data = $raw | ConvertFrom-Json -Depth 6 -ErrorAction Stop
                if ($null -ne $data) {
                    if ($data -is [System.Collections.IEnumerable] -and -not ($data -is [string])) {
                        foreach ($item in $data) { $list.Add([pscustomobject]$item) }
                    }
                    else { $list.Add([pscustomobject]$data) }
                }
            }
        }
        catch {
            Write-Host "Note: Unable to load undo history ($($_.Exception.Message)). Starting fresh." -ForegroundColor Yellow
        }
    }
    $list
}
function EnsureHistoryList {
    if (-not $script:AppliedHistory) {
        $script:AppliedHistory = [System.Collections.Generic.List[object]]::new()
    }
    $script:AppliedHistory
}
function SaveHistory {
    EnsureHistoryList | Out-Null
    $dir = Split-Path -Path $script:HistoryPath -Parent
    if (-not (Test-Path $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
    $json = if ($script:AppliedHistory.Count -gt 0) {
        $script:AppliedHistory | ConvertTo-Json -Depth 6
    }
    else { '[]' }
    Set-Content -Path $script:HistoryPath -Value $json -Encoding UTF8
}
function DecodeHtml {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    [System.Net.WebUtility]::HtmlDecode($Value).Trim()
}
function GetSeverityLabel {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return 'Unknown' }
    switch ($Value.Trim()) {
        'Critical' { 'Critical' }
        'High' { 'High' }
        'Medium' { 'Medium' }
        'Low' { 'Low' }
        default { 'Unknown' }
    }
}
function GetSeverityRank {
    param([string]$Severity)
    if ([string]::IsNullOrWhiteSpace($Severity)) { return 4 }
    switch ($Severity.ToLowerInvariant()) {
        'critical' { 0 }
        'high' { 1 }
        'medium' { 2 }
        'low' { 3 }
        default { 4 }
    }
}
function GetUndoKeyValueFromCurrent {
    param([string]$Current)
    if (-not $Current) { return $null }
    $trimmed = $Current.Trim()
    if (-not $trimmed) { return $null }
    $equalsMatch = [regex]::Match($trimmed, '^\s*([^:=]+)\s*=\s*(.+)$')
    if ($equalsMatch.Success) {
        return [pscustomobject]@{
            Key = $equalsMatch.Groups[1].Value.Trim()
            Value = $equalsMatch.Groups[2].Value.Trim()
        }
    }
    $colonMatch = [regex]::Match($trimmed, '^\s*([^:=]+)\s*:\s*(.*)$')
    if ($colonMatch.Success) {
        $raw = $colonMatch.Groups[2].Value
        $parts = @()
        foreach ($piece in ($raw -split '\|')) {
            $segment = $piece.Trim()
            if ($segment) { $parts += $segment }
        }
        return [pscustomobject]@{
            Key = $colonMatch.Groups[1].Value.Trim()
            Value = ($parts -join ',')
        }
    }
    $null
}
function BuildNetAccountsUndo {
    param(
        [string]$Command,
        [string]$Current
    )
    $match = [regex]::Match($Command, '/([^\s:]+):')
    if (-not $match.Success) { return $null }
    $kv = GetUndoKeyValueFromCurrent $Current
    if (-not $kv) { return $null }
    $value = $kv.Value
    if (-not $value) { return $null }
    "net accounts /$($match.Groups[1].Value):$value"
}
function BuildSeceditUndo {
    param(
        [string]$Command,
        [string]$Current
    )
    $infMatch = [regex]::Match($Command, "@'(?<body>.*?)'@", [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if (-not $infMatch.Success) { return $null }
    $bodyLines = ($infMatch.Groups['body'].Value -replace "`r", '').Split("`n")
    if ($bodyLines.Count -lt 2) { return $null }
    $sectionLine = $bodyLines[0].Trim()
    $sectionMatch = [regex]::Match($sectionLine, '^\[(?<name>[^\]]+)\]$')
    if (-not $sectionMatch.Success) { return $null }
    $keyLine = ($bodyLines | Select-Object -Skip 1 | Where-Object { $_ -match '=' } | Select-Object -First 1)
    if (-not $keyLine) { return $null }
    $key = ($keyLine -split '=', 2)[0].Trim()
    $kv = GetUndoKeyValueFromCurrent $Current
    if (-not $kv -or $kv.Key -ne $key) { return $null }
    $areaMatch = [regex]::Match($Command, "/areas\s+([^\s""'``]+)")
    $area = if ($areaMatch.Success) { $areaMatch.Groups[1].Value } else { 'USER_RIGHTS' }
    $infBody = "[{0}]`n{1} = {2}" -f $sectionMatch.Groups['name'].Value.Trim(), $key, $kv.Value
    "$inf=[IO.Path]::GetTempFileName().Replace('.tmp','.inf');@'$infBody'@|Set-Content -Path $inf -Encoding ASCII;secedit /configure /db secedit.sdb /cfg `"$inf`" /areas $area"
}
function GetUndoCommand {
    param($Policy)
    if (-not $Policy) { return $null }
    $current = $Policy.CurrentState
    if (-not $current -or $current -eq 'no configuration') { return $null }
    $command = $Policy.Command
    if (-not $command) { return $null }
    if ($command -match '^\s*net\s+accounts\s+/') { return BuildNetAccountsUndo -Command $command -Current $current }
    if ($command -match 'secedit\s+/configure') { return BuildSeceditUndo -Command $command -Current $current }
    $null
}
function AddHistoryEntry {
    param(
        $Policy,
        [string]$UndoCommand,
        [bool]$Succeeded
    )
    if (-not $Succeeded) { return }
    $history = EnsureHistoryList
    $entry = [pscustomobject]@{
        Id = $Policy.Id
        Description = $Policy.Description
        Severity = $Policy.Severity
        Category = $Policy.Category
        Command = $Policy.Command
        CurrentState = $Policy.CurrentState
        UndoCommand = $UndoCommand
        ExecutedAt = (Get-Date).ToString('o')
        Undone = $false
    }
    $history.Add($entry)
    SaveHistory
}
function ManageUndo {
    $history = EnsureHistoryList
    $pending = @($history | Where-Object { -not $_.Undone })
    if (-not $pending -or $pending.Count -eq 0) {
        Write-Host "No applied policy changes recorded yet." -ForegroundColor Yellow
        Start-Sleep 1.5
        return
    }
    $items = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in $pending) {
        $items.Add([pscustomobject]@{
            Entry = $entry
            Selected = $false
        })
    }
    while ($true) {
        Clear-Host
        Write-Host "=== Undo Applied Policies ===`n"
        for ($i = 0; $i -lt $items.Count; $i++) {
            $wrapper = $items[$i]
            $entry = $wrapper.Entry
            $flag = if ($wrapper.Selected) { '[X]' } else { '[ ]' }
            $status = if ($entry.UndoCommand) { 'auto' } else { 'manual' }
            $desc = $entry.Description
            if ($desc.Length -gt 60) { $desc = $desc.Substring(0, 57) + '...' }
            Write-Host (" {0,2}. {1} {2} ({3}) {4}" -f ($i+1), $flag, $entry.Id, $status, $desc)
        }
        Write-Host "`nOptions: numbers to toggle, A toggle all auto, R run undo, V# view details, B back."
        $resp = (Read-Host "Selection").Trim()
        if (-not $resp) { continue }
        $upper = $resp.ToUpper()
        switch -Regex ($upper) {
            '^B$' { return }
            '^A$' {
                $auto = $items | Where-Object { $_.Entry.UndoCommand }
                if (-not $auto) { Write-Host "No auto-undo items available." -ForegroundColor Yellow; Start-Sleep 1; continue }
                $allSelected = ($auto | Where-Object { $_.Selected }).Count -eq $auto.Count
                foreach ($item in $auto) { $item.Selected = -not $allSelected }
            }
            '^R$' {
                $targets = @($items | Where-Object { $_.Selected })
                if (-not $targets -or $targets.Count -eq 0) {
                    Write-Host "No items selected for undo." -ForegroundColor Yellow
                    Start-Sleep 1
                    continue
                }
                Clear-Host
                Write-Host "=== Undo Execution ===`n" -ForegroundColor Green
                foreach ($item in $targets) {
                    $entry = $item.Entry
                    Write-Host ">> Reverting [$($entry.Id)] $($entry.Description)" -ForegroundColor Green
                    if (-not $entry.UndoCommand) {
                        Write-Host "   No stored undo command. Please revert manually (original state: $($entry.CurrentState))." -ForegroundColor Yellow
                        Write-Host ""
                        continue
                    }
                    Write-Host $entry.UndoCommand -ForegroundColor DarkGray
                    $success = $false
                    try {
                        Invoke-Expression $entry.UndoCommand
                        $success = $true
                        Write-Host "   Reverted." -ForegroundColor Green
                    }
                    catch {
                        Write-Host "   Failed: $($_.Exception.Message)" -ForegroundColor Red
                    }
                    if ($success) {
                        $entry.Undone = $true
                        $entry.UndoneAt = (Get-Date).ToString('o')
                    }
                    Write-Host ""
                }
                SaveHistory
                $items = [System.Collections.Generic.List[object]]::new()
                foreach ($entry in ($history | Where-Object { -not $_.Undone })) {
                    $items.Add([pscustomobject]@{
                        Entry = $entry
                        Selected = $false
                    })
                }
                Write-Host "Undo processing complete. Press Enter to continue..."
                [void][Console]::ReadLine()
                if ($items.Count -eq 0) { return }
            }
            '^V(\d+)$' {
                $index = [int]$matches[1] - 1
                if ($index -lt 0 -or $index -ge $items.Count) {
                    Write-Host "Invalid entry." -ForegroundColor Yellow
                    Start-Sleep 1
                    continue
                }
                $entry = $items[$index].Entry
                Clear-Host
                Write-Host "=== Policy Detail ===`n"
                Write-Host ("Id         : {0}" -f $entry.Id)
                Write-Host ("Description: {0}" -f $entry.Description)
                Write-Host ("Severity   : {0}" -f $entry.Severity)
                Write-Host ("Category   : {0}" -f $entry.Category)
                Write-Host ("Applied    : {0}" -f $entry.ExecutedAt)
                Write-Host ("Original   : {0}" -f $entry.CurrentState)
                Write-Host ("Undo Cmd   : {0}" -f ($entry.UndoCommand ?? 'Requires manual rollback'))
                Write-Host "`nPress Enter to return..."
                [void][Console]::ReadLine()
            }
            '^\d+(,\d+)*$' {
                $nums = $resp -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
                foreach ($n in $nums) {
                    $idx = [int]$n - 1
                    if ($idx -ge 0 -and $idx -lt $items.Count) {
                        $items[$idx].Selected = -not $items[$idx].Selected
                    }
                }
            }
            default {
                Write-Host "Invalid selection." -ForegroundColor Yellow
                Start-Sleep 1
            }
        }
    }
}
if (-not (Test-Path $ReportPath)) { throw "Report not found: $ReportPath" }
$script:AppliedHistory = LoadHistory $script:HistoryPath
EnsureHistoryList | Out-Null
$policies = foreach ($block in ((Get-Content $ReportPath -Raw) -split "<div class='policy'>")) {
    if (-not $block.Trim()) { continue }
    $titleRaw = [regex]::Match($block, "<div class='title'>([^<]+)</div>").Groups[1].Value
    $descRaw  = [regex]::Match($block, "<div class='desc'>([^<]+)</div>").Groups[1].Value
    $severityRaw = [regex]::Match($block, "<div class='badge\s+([^']+)'>").Groups[1].Value
    $cmdRaw   = [regex]::Match($block, "<div class='cmd'>(.+?)</div>", 'Singleline').Groups[1].Value
    $currentRaw = [regex]::Match($block, "<div class='meta'><b>Current:</b>\s*([^<]*)</div>").Groups[1].Value
    $title = DecodeHtml $titleRaw
    $cmd = DecodeHtml $cmdRaw
    if (-not $title -or -not $cmd -or $cmd -like '# Review*') { continue }
    $severity = GetSeverityLabel $severityRaw
    [pscustomobject]@{
        Id = $title
        Description = DecodeHtml $descRaw
        Severity = $severity
        SeverityRank = GetSeverityRank $severity
        Command = $cmd
        CurrentState = DecodeHtml $currentRaw
        Selected = $false
    }
}
function Categorize($cmd) {
    if ($cmd -match '(?m)^\s*net\s+accounts') { return 'Password Policy' }
    if ($cmd -match 'secedit') { return 'Security Template' }
    if ($cmd -match '(?m)^\s*(New-ItemProperty|Set-ItemProperty|reg\s)') { return 'Registry' }
    if ($cmd -match '(?m)^\s*\$inf') { return 'User Rights Assignment' }
    if ($cmd -match '(?m)^\s*(Set-Service|sc\s)') { return 'Services' }
    if ($cmd -match '(?m)^\s*(dism\.exe|dism\s)') { return 'DISM / Features' }
    if ($cmd -match '(?m)^\s*Enable-WindowsOptionalFeature') { return 'Windows Features' }
    if ($cmd -match '(?m)^\s*(Remove-Item|New-Item|Copy-Item)') { return 'File System' }
    return 'Other Remediation'
}
$categories = [ordered]@{}
foreach ($policy in $policies) {
    $cat = Categorize $policy.Command
    if (-not $categories.Contains($cat)) { $categories[$cat] = [System.Collections.Generic.List[object]]::new() }
    if ($policy.PSObject.Properties.Match('Category').Count -eq 0) {
        $policy | Add-Member -NotePropertyName Category -NotePropertyValue $cat
    }
    else {
        $policy.Category = $cat
    }
    $categories[$cat].Add($policy)
}
foreach ($catKey in @($categories.Keys)) {
    $sorted = $categories[$catKey] | Sort-Object SeverityRank, Id
    $replacement = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $sorted) { $replacement.Add($item) }
    $categories[$catKey] = $replacement
}
function ShowMenu {
    param($categories)
    Clear-Host
    Write-Host "=== OmniWin-Resolve Assistant ===`n"
    $i = 1
    foreach ($cat in $categories.Keys) {
        $items = $categories[$cat]
        $sel = @($items | Where-Object Selected).Count
        Write-Host (" {0}. {1} [{2}/{3}]" -f $i, $cat, $sel, $items.Count)
        $i++
    }
    Write-Host "`n R. Run selected commands"
    Write-Host " U. Undo applied policies"
    Write-Host " Q. Quit`n"
}
function ToggleCategory {
    param($catName, $items)
:ItemLoop while ($true) {
        Clear-Host
        Write-Host "=== $catName ===`n"
        for ($i = 0; $i -lt $items.Count; $i++) {
            $flag = if ($items[$i].Selected) { '[X]' } else { '[ ]' }
            $desc = $items[$i].Description
            if ($desc.Length -gt 68) { $desc = $desc.Substring(0, 65) + '...' }
            Write-Host (" {0,2}. {1} {2} ({3})" -f ($i+1), $flag, $desc, $items[$i].Severity)
        }
        Write-Host "`nEnter numbers to toggle (comma separated), A to toggle all, B to go back."
        $respRaw = Read-Host "Selection"
        $respTrim = $respRaw.Trim()
        $resp = $respTrim.ToUpper()
        switch -Regex ($resp) {
            '^B$' { return }
            '^A$' {
                $allSelected = @($items | Where-Object Selected).Count -eq $items.Count
                foreach ($item in $items) { $item.Selected = -not $allSelected }
                continue ItemLoop
            }
            '^\d+(,\d+)*$' {
                $nums = $respTrim -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
                $invalid = @()
                foreach ($n in $nums) {
                    $value = 0
                    if (-not [int]::TryParse($n, [ref]$value)) {
                        $invalid += $n
                        continue
                    }
                    $idx = $value - 1
                    if ($idx -ge 0 -and $idx -lt $items.Count) {
                        $items[$idx].Selected = -not $items[$idx].Selected
                    }
                    else {
                        $invalid += $n
                    }
                }
                if ($invalid.Count -gt 0) {
                    Write-Host ("Invalid item number(s): {0}" -f ($invalid -join ', ')) -ForegroundColor Yellow
                    Start-Sleep 1.2
                }
                continue ItemLoop
            }
            default {
                Write-Host "Invalid selection." -ForegroundColor Yellow
                Start-Sleep 1
                continue ItemLoop
            }
        }
    }
}
function GetSelected($categories) {
    $selected = [System.Collections.Generic.List[object]]::new()
    foreach ($cat in $categories.Keys) {
        foreach ($item in $categories[$cat]) { if ($item.Selected) { $selected.Add($item) } }
    }
    $selected
}
function RunCommands($commands) {
    if (-not $commands -or $commands.Count -eq 0) {
        Write-Host "No commands selected." -ForegroundColor Yellow
        Start-Sleep 1.5
        return
    }
    $queue = [System.Collections.Generic.List[object]]::new()
    foreach ($item in ($commands | Sort-Object SeverityRank, Id)) { $queue.Add($item) }
    Clear-Host
    Write-Host "=== Commands Ready for Execution ===`n" -ForegroundColor Green
    for ($i = 0; $i -lt $queue.Count; $i++) {
        $cmd = $queue[$i]
        Write-Host ("[{0}] {1} - {2}" -f ($i+1), $cmd.Id, $cmd.Description) -ForegroundColor Cyan
        Write-Host (" Severity : {0}" -f $cmd.Severity)
        Write-Host (" Command  : {0}`n" -f $cmd.Command)
    }
    $confirm = Read-Host "Type RUN to execute or anything else to cancel"
    if ($confirm -ne 'RUN') { Write-Host "Execution cancelled."; Start-Sleep 1.5; return }
    foreach ($cmd in $queue) {
        Write-Host ">> Executing [$($cmd.Id)] $($cmd.Description)" -ForegroundColor Green
        Write-Host $cmd.Command -ForegroundColor DarkGray
        $success = $false
        try {
            Invoke-Expression $cmd.Command
            $success = $true
            Write-Host "   Succeeded." -ForegroundColor Green
        }
        catch {
            Write-Host "   Failed: $($_.Exception.Message)" -ForegroundColor Red
        }
        if ($success) {
            $undoCommand = GetUndoCommand $cmd
            AddHistoryEntry -Policy $cmd -UndoCommand $undoCommand -Succeeded $true
            if ($undoCommand) {
                Write-Host "   Undo command recorded." -ForegroundColor DarkGreen
            }
            else {
                Write-Host "   Original state saved for manual rollback." -ForegroundColor Yellow
            }
        }
        $cmd.Selected = $false
        Write-Host ""
    }
    Write-Host "Execution complete. Press Enter to continue..."
    [void][Console]::ReadLine()
}
:MenuLoop while ($true) {
    ShowMenu $categories
    $choice = (Read-Host "Select option").Trim().ToUpper()
    switch ($choice) {
        'Q' { break MenuLoop }
        'R' { RunCommands (GetSelected $categories) }
        'U' { ManageUndo }
        default {
            if ($choice -match '^\d+$') {
                $idx = [int]$choice
                $keys = $categories.Keys
                if ($idx -ge 1 -and $idx -le $keys.Count) {
                    $key = $keys[$idx - 1]
                    ToggleCategory $key $categories[$key]
                }
                else { Write-Host "Invalid category."; Start-Sleep 1 }
            }
            else { Write-Host "Unknown option."; Start-Sleep 1 }
        }
    }
}
Write-Host "OmniWin resolution helper exited." -ForegroundColor Cyan
