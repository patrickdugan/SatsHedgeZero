# Run a command, sample its peak working set, append "<label> peak_working_set_mib=<n> exit=<code>" to a log.
# Usage: powershell -File scripts\peak_mem.ps1 <log> <label> <exe> <args...>
param([string]$Log, [string]$Label, [string]$Exe, [Parameter(ValueFromRemainingArguments = $true)][string[]]$ArgList)
$p = Start-Process -FilePath $Exe -ArgumentList $ArgList -PassThru -NoNewWindow -RedirectStandardError "$Log.$Label.stderr.txt"
$null = $p.Handle  # keeps the exit code readable after exit
$peak = 0
while (-not $p.HasExited) {
    try { $p.Refresh(); if ($p.PeakWorkingSet64 -gt $peak) { $peak = $p.PeakWorkingSet64 } } catch {}
    Start-Sleep -Milliseconds 500
}
$p.WaitForExit()
$mib = [math]::Round($peak / 1MB)
Add-Content -Path $Log -Value "$Label peak_working_set_mib=$mib exit=$($p.ExitCode)"
