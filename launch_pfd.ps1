Add-Type -AssemblyName System.Windows.Forms

$AppFolder = "$env:LOCALAPPDATA\PFDCompanion"
# Worker URL comes from config.json (copy config.example.json and fill it in).
$WorkerUrl = ""
$configFile = "$AppFolder\config.json"
if (Test-Path $configFile) {
    $WorkerUrl = ((Get-Content $configFile -Raw) | ConvertFrom-Json).worker_url
}

# A relaunch (Windows Startup at login, or just double-clicking the shortcut
# again while it's already running) should always fully take over rather
# than run alongside whatever's already there - two tray icons each thinking
# they own "the" bridge is exactly how duplicate bridges happened before.
# /T also takes down that older instance's own tracked bridge/cloudflared
# children, so the cleanup below is defense-in-depth, not the only layer.
Get-CimInstance Win32_Process -Filter "Name='PFDCompanion.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.ProcessId -ne $PID } |
    ForEach-Object { Start-Process "taskkill" -ArgumentList "/PID $($_.ProcessId) /T /F" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue }

# Kills every python.exe actually running msfs_bridge.py, found by command
# line rather than a single tracked PID. bridge.pid can go stale (a crash
# before it was written, two launches racing) and leave an orphaned bridge
# still bound to :5000 that a PID-only kill would miss entirely - that
# exact scenario once left two bridges racing to write auth_token.txt,
# corrupting it to null bytes and breaking login for both the phone and the
# tray's own status polling. /T also kills each one's SimConnect/X-Plane
# worker subprocesses since they're children of it.
function Stop-StrayBridgeProcesses {
    Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='pythonw.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -like "*msfs_bridge.py*" } |
        ForEach-Object { Start-Process "taskkill" -ArgumentList "/PID $($_.ProcessId) /T /F" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue }
}

# NOTE: the compiled msfs_bridge.exe is stale until a final recompile — always
# run msfs_bridge.py directly with Python so bridge fixes take effect.
Get-Process msfs_bridge -ErrorAction SilentlyContinue | Stop-Process -Force
Get-Process cloudflared -ErrorAction SilentlyContinue | Stop-Process -Force
Stop-StrayBridgeProcesses
$pidFile = "$AppFolder\bridge.pid"
Start-Sleep -Seconds 1

$bridgeLogFile = "$AppFolder\bridge.log"
$bridgeErrFile = "$AppFolder\bridge.err.log"
Remove-Item $bridgeLogFile, $bridgeErrFile -ErrorAction SilentlyContinue
# Unbuffered: without this, stdout is block-buffered once redirected to a
# file (not a TTY) — including inside the SimConnect worker's separate OS
# process, since it inherits the environment — so log lines can sit unflushed
# for a long time instead of showing up promptly in the console panel below.
$env:PYTHONUNBUFFERED = "1"
$bridgeProc = Start-Process "python" -ArgumentList "`"$AppFolder\msfs_bridge.py`"" -WindowStyle Hidden -PassThru `
    -RedirectStandardOutput $bridgeLogFile -RedirectStandardError $bridgeErrFile
$bridgeProc.Id | Out-File $pidFile
Start-Sleep -Seconds 2

$tokenFile = "$AppFolder\auth_token.txt"
$authToken = ""
$tokenTries = 0
while ($authToken -eq "" -and $tokenTries -lt 10) {
    if (Test-Path $tokenFile) {
        $authToken = (Get-Content $tokenFile -ErrorAction SilentlyContinue | Select-Object -First 1).Trim()
    }
    if ($authToken -eq "") { Start-Sleep -Seconds 1; $tokenTries++ }
}

# The bridge's own status endpoints now require a session cookie (see
# msfs_bridge.py's /login) - this window is itself just another client, so it
# logs in locally the same way a phone would, and reuses that session for
# every status poll below via -WebSession. Retried since the bridge may not
# have finished binding its port yet at this exact moment.
$script:bridgeSession = $null
$loginTries = 0
while (-not $script:bridgeSession -and $loginTries -lt 10) {
    try {
        Invoke-RestMethod -Uri "http://localhost:5000/login" -Method POST -ContentType "application/json" `
            -Body (@{ password = $authToken } | ConvertTo-Json) -SessionVariable sessResult -TimeoutSec 2 | Out-Null
        $script:bridgeSession = $sessResult
    } catch {
        Start-Sleep -Seconds 1; $loginTries++
    }
}

$logFile = "$AppFolder\tunnel.log"
if (Test-Path $logFile) { Remove-Item $logFile }

Start-Process "$AppFolder\cloudflared.exe" `
    -ArgumentList "tunnel --url http://localhost:5000" `
    -WindowStyle Hidden `
    -RedirectStandardError $logFile

$url = ""
$tries = 0
while ($url -eq "" -and $tries -lt 30) {
    Start-Sleep -Seconds 1
    $tries++
    if (Test-Path $logFile) {
        $lines = Get-Content $logFile -ErrorAction SilentlyContinue
        foreach ($line in $lines) {
            if ($line -match "https://[a-z0-9\-]+\.trycloudflare\.com") {
                $url = $matches[0]
                break
            }
        }
    }
}

if ($url -eq "") {
    [System.Windows.Forms.MessageBox]::Show("Could not get tunnel URL.", "PFD Companion", "OK", "Error")
    exit 1
}

try {
    # X-Update-Secret is checked by the reverse-proxy Worker
    # (cloudflare-worker.js) against its own UPDATE_SECRET, separate from the
    # bridge's login check below - it's what lets the Worker know which
    # tunnel to proxy to. Sent as a header rather than a &secret= query-string
    # param (as this used to do) so it can't end up cached/logged by an
    # intermediate proxy or Cloudflare's own edge access logs - the URL being
    # registered isn't sensitive, only the secret is. This used to fail
    # silently (empty catch) - if UPDATE_SECRET in the Worker's dashboard ever
    # drifts out of sync with auth_token.txt (e.g. the token got
    # regenerated), every launch would silently keep the Worker pointed at
    # whatever tunnel was last registered successfully, which eventually goes
    # dead and the mobile bookmark breaks with no visible cause.
    try {
        Invoke-RestMethod -Uri "$WorkerUrl/update?url=$url" -Method GET -Headers @{ "X-Update-Secret" = $authToken } -ErrorAction Stop | Out-Null
    } catch {
        # Fallback for a Worker deployment still running the older
        # ?secret=... query-string variant (2026-08-18: found the dashboard
        # had drifted to that older code while this file already expected
        # the header). Only fires if the header attempt above actually
        # failed, so once the dashboard is redeployed with the current
        # cloudflare-worker.js this branch stops being reachable and the
        # secret goes back to never appearing in a URL.
        Invoke-RestMethod -Uri "$WorkerUrl/update?url=$url&secret=$authToken" -Method GET -ErrorAction Stop | Out-Null
    }
} catch {
    [System.Windows.Forms.MessageBox]::Show(
        "Could not register this session's tunnel with the Worker (mobile bookmark won't reach this PC until this is fixed).`n`nThis usually means the Worker's UPDATE_SECRET (Cloudflare dashboard) no longer matches auth_token.txt. Current token:`n$authToken`n`nError: $($_.Exception.Message)",
        "PFD Companion", "OK", "Warning") | Out-Null
}

# The bridge now uses a real login (POST /login -> session cookie) instead of
# a key baked into the bookmark URL - the bookmark itself is just $WorkerUrl,
# permanently, and $authToken is only ever needed once per device as the
# password typed into the app's own login screen.
if ($authToken -eq "") {
    [System.Windows.Forms.MessageBox]::Show("Could not read the bridge's auth token - the login screen won't accept any password until this is fixed. Check bridge.err.log.", "PFD Companion", "OK", "Warning")
}

[System.Windows.Forms.Clipboard]::SetText($WorkerUrl)

function New-Divider($y) {
    $d = New-Object System.Windows.Forms.Panel
    $d.BackColor = [System.Drawing.Color]::FromArgb(35, 35, 35)
    $d.Location = New-Object System.Drawing.Point(24, $y)
    $d.Size = New-Object System.Drawing.Size(512, 1)
    return $d
}

$form = New-Object System.Windows.Forms.Form
$form.Text = "PFD Companion"
$form.Size = New-Object System.Drawing.Size(560, 520)
$form.StartPosition = "CenterScreen"
$form.TopMost = $true
$form.BackColor = [System.Drawing.Color]::FromArgb(15, 15, 15)
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false
$form.ShowInTaskbar = $true
# DoubleBuffered is `protected` on Control, not settable directly - without
# it, this dark-themed form erases to the default white background on every
# repaint before redrawing its own BackColor, which reads as a white flash.
# Only visible while the window is actually on screen, which matches: the
# two timers below (status poll, log tail) keep updating labels/text the
# whole time it's open, each update triggering another erase-then-redraw.
$doubleBufferedProp = [System.Windows.Forms.Control].GetProperty("DoubleBuffered", [System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic)
$doubleBufferedProp.SetValue($form, $true, $null)
if (Test-Path "$AppFolder\pfd.ico") {
    $form.Icon = New-Object System.Drawing.Icon("$AppFolder\pfd.ico")
}

$lbl = New-Object System.Windows.Forms.Label
$lbl.Text = "Open on your iPhone (bookmark this, it never changes):"
$lbl.ForeColor = [System.Drawing.Color]::FromArgb(120, 120, 120)
$lbl.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$lbl.Location = New-Object System.Drawing.Point(24, 16)
$lbl.Size = New-Object System.Drawing.Size(512, 18)
$form.Controls.Add($lbl)

$urlBox = New-Object System.Windows.Forms.TextBox
$urlBox.Text = $WorkerUrl
$urlBox.ReadOnly = $true
$urlBox.Font = New-Object System.Drawing.Font("Consolas", 10)
$urlBox.ForeColor = [System.Drawing.Color]::FromArgb(20, 190, 255)
$urlBox.BackColor = [System.Drawing.Color]::FromArgb(15, 15, 15)
$urlBox.BorderStyle = "None"
$urlBox.Location = New-Object System.Drawing.Point(24, 40)
$urlBox.Size = New-Object System.Drawing.Size(512, 26)
$form.Controls.Add($urlBox)

$lblPw = New-Object System.Windows.Forms.Label
$lblPw.Text = "Login password (type once per device, at the app's login screen):"
$lblPw.ForeColor = [System.Drawing.Color]::FromArgb(120, 120, 120)
$lblPw.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$lblPw.Location = New-Object System.Drawing.Point(24, 74)
$lblPw.Size = New-Object System.Drawing.Size(512, 18)
$form.Controls.Add($lblPw)

$pwBox = New-Object System.Windows.Forms.TextBox
$pwBox.Text = $authToken
$pwBox.ReadOnly = $true
$pwBox.Font = New-Object System.Drawing.Font("Consolas", 10)
$pwBox.ForeColor = [System.Drawing.Color]::FromArgb(20, 190, 255)
$pwBox.BackColor = [System.Drawing.Color]::FromArgb(15, 15, 15)
$pwBox.BorderStyle = "None"
$pwBox.Location = New-Object System.Drawing.Point(24, 96)
$pwBox.Size = New-Object System.Drawing.Size(512, 24)
$form.Controls.Add($pwBox)

$form.Controls.Add((New-Divider 128))

$lbl2 = New-Object System.Windows.Forms.Label
$lbl2.Text = "Current tunnel:"
$lbl2.ForeColor = [System.Drawing.Color]::FromArgb(90, 90, 90)
$lbl2.Font = New-Object System.Drawing.Font("Segoe UI", 8)
$lbl2.Location = New-Object System.Drawing.Point(24, 140)
$lbl2.Size = New-Object System.Drawing.Size(94, 18)
$form.Controls.Add($lbl2)

$tunnelBox = New-Object System.Windows.Forms.TextBox
$tunnelBox.Text = $url
$tunnelBox.ReadOnly = $true
$tunnelBox.Font = New-Object System.Drawing.Font("Consolas", 8)
$tunnelBox.ForeColor = [System.Drawing.Color]::FromArgb(90, 90, 90)
$tunnelBox.BackColor = [System.Drawing.Color]::FromArgb(15, 15, 15)
$tunnelBox.BorderStyle = "None"
$tunnelBox.Location = New-Object System.Drawing.Point(122, 140)
$tunnelBox.Size = New-Object System.Drawing.Size(414, 18)
$form.Controls.Add($tunnelBox)

$btn = New-Object System.Windows.Forms.Button
$btn.Text = "Copy URL"
$btn.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$btn.ForeColor = [System.Drawing.Color]::White
$btn.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 255)
$btn.FlatStyle = "Flat"
$btn.FlatAppearance.BorderSize = 0
$btn.Location = New-Object System.Drawing.Point(24, 162)
$btn.Size = New-Object System.Drawing.Size(110, 30)
$copyResetTimer = New-Object System.Windows.Forms.Timer
$copyResetTimer.Interval = 1500
$copyResetTimer.Add_Tick({ $btn.Text = "Copy URL"; $copyResetTimer.Stop() })
$btn.Add_Click({
    [System.Windows.Forms.Clipboard]::SetText($WorkerUrl)
    $btn.Text = "Copied!"
    $copyResetTimer.Stop(); $copyResetTimer.Start()
})
$form.Controls.Add($btn)

$btnPw = New-Object System.Windows.Forms.Button
$btnPw.Text = "Copy Password"
$btnPw.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$btnPw.ForeColor = [System.Drawing.Color]::White
$btnPw.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
$btnPw.FlatStyle = "Flat"
$btnPw.FlatAppearance.BorderSize = 0
$btnPw.Location = New-Object System.Drawing.Point(142, 162)
$btnPw.Size = New-Object System.Drawing.Size(130, 30)
$copyPwResetTimer = New-Object System.Windows.Forms.Timer
$copyPwResetTimer.Interval = 1500
$copyPwResetTimer.Add_Tick({ $btnPw.Text = "Copy Password"; $copyPwResetTimer.Stop() })
$btnPw.Add_Click({
    [System.Windows.Forms.Clipboard]::SetText($authToken)
    $btnPw.Text = "Copied!"
    $copyPwResetTimer.Stop(); $copyPwResetTimer.Start()
})
$form.Controls.Add($btnPw)

$liveStatus = New-Object System.Windows.Forms.Label
$liveStatus.Text = "* Checking bridge..."
$liveStatus.ForeColor = [System.Drawing.Color]::FromArgb(150, 150, 150)
$liveStatus.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$liveStatus.Location = New-Object System.Drawing.Point(284, 167)
$liveStatus.Size = New-Object System.Drawing.Size(252, 20)
$form.Controls.Add($liveStatus)

$form.Controls.Add((New-Divider 206))

$lbl3 = New-Object System.Windows.Forms.Label
$lbl3.Text = "ACTIVITY"
$lbl3.ForeColor = [System.Drawing.Color]::FromArgb(90, 90, 90)
$lbl3.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
$lbl3.Location = New-Object System.Drawing.Point(24, 218)
$lbl3.Size = New-Object System.Drawing.Size(200, 16)
$form.Controls.Add($lbl3)

$consoleBox = New-Object System.Windows.Forms.TextBox
$consoleBox.Multiline = $true
$consoleBox.ReadOnly = $true
$consoleBox.ScrollBars = "Vertical"
$consoleBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$consoleBox.ForeColor = [System.Drawing.Color]::FromArgb(130, 215, 145)
$consoleBox.BackColor = [System.Drawing.Color]::FromArgb(8, 8, 8)
$consoleBox.BorderStyle = "FixedSingle"
$consoleBox.Location = New-Object System.Drawing.Point(24, 238)
$consoleBox.Size = New-Object System.Drawing.Size(512, 170)
$consoleBox.Text = "Waiting for bridge activity..."
$form.Controls.Add($consoleBox)

$status = New-Object System.Windows.Forms.Label
$status.Text = "Closing this window keeps the bridge running in the tray."
$status.ForeColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
$status.Font = New-Object System.Drawing.Font("Segoe UI", 8)
$status.TextAlign = "MiddleCenter"
$status.Location = New-Object System.Drawing.Point(24, 420)
$status.Size = New-Object System.Drawing.Size(512, 18)
$form.Controls.Add($status)

# ── System tray icon ──────────────────────────────────────────────────────
$notifyIcon = New-Object System.Windows.Forms.NotifyIcon
$notifyIcon.Icon = if (Test-Path "$AppFolder\pfd.ico") {
    New-Object System.Drawing.Icon("$AppFolder\pfd.ico")
} else {
    [System.Drawing.SystemIcons]::Application
}
$notifyIcon.Text = "PFD Companion"
$notifyIcon.Visible = $true

$openForm = {
    $form.Show()
    $form.WindowState = "Normal"
    $form.Activate()
}

$menu = New-Object System.Windows.Forms.ContextMenuStrip

$restartBridgeAction = {
    # Only the bridge process restarts here, not cloudflared — the tunnel
    # just proxies whatever's listening on localhost:5000, so leaving it
    # running means the tunnel URL (and the Worker's pointer to it) never
    # changes and doesn't need updating. This is specifically for picking up
    # msfs_bridge.py code changes, which the live process never hot-reloads.
    $liveStatus.Text = "* Restarting bridge..."
    $liveStatus.ForeColor = [System.Drawing.Color]::FromArgb(230, 170, 0)
    $notifyIcon.Text = "PFD Companion - restarting bridge..."

    if ($script:bridgeProc) {
        Start-Process "taskkill" -ArgumentList "/PID $($script:bridgeProc.Id) /T /F" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
    }
    Stop-StrayBridgeProcesses
    Start-Sleep -Seconds 1

    Remove-Item $bridgeLogFile, $bridgeErrFile -ErrorAction SilentlyContinue
    $script:bridgeProc = Start-Process "python" -ArgumentList "`"$AppFolder\msfs_bridge.py`"" -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput $bridgeLogFile -RedirectStandardError $bridgeErrFile
    $script:bridgeProc.Id | Out-File $pidFile
    $script:lastConsoleText = ""  # forces the Activity panel to refresh on the next tick instead of showing stale text
}

$quitAction = {
    $statusTimer.Stop()
    $consoleTimer.Stop()
    $copyResetTimer.Stop()
    # /T kills the whole process tree (see note above about launcher shims).
    if ($bridgeProc) { Start-Process "taskkill" -ArgumentList "/PID $($bridgeProc.Id) /T /F" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue }
    Stop-StrayBridgeProcesses
    Remove-Item $pidFile -ErrorAction SilentlyContinue
    Get-Process cloudflared -ErrorAction SilentlyContinue | Stop-Process -Force
    # Hide immediately — a lingering tray icon after the process exits is a
    # common WinForms rough edge (it stays until the mouse moves over it).
    $notifyIcon.Visible = $false
    [System.Windows.Forms.Application]::Exit()
}
$menu.Items.Add("Open PFD Companion", $null, $openForm) | Out-Null
$menu.Items.Add("Copy URL", $null, { [System.Windows.Forms.Clipboard]::SetText($WorkerUrl) }) | Out-Null
$menu.Items.Add("Copy Password", $null, { [System.Windows.Forms.Clipboard]::SetText($authToken) }) | Out-Null
$menu.Items.Add("Restart Bridge", $null, $restartBridgeAction) | Out-Null
$menu.Items.Add("-") | Out-Null
$menu.Items.Add("Quit", $null, $quitAction) | Out-Null

$notifyIcon.ContextMenuStrip = $menu
$notifyIcon.Add_DoubleClick($openForm)

# Closing the window (the [X] button) hides it back to the tray instead of
# quitting — only the tray menu's Quit actually stops the bridge/tunnel now
# that the window isn't what keeps them alive.
$form.Add_FormClosing({
    param($sender, $e)
    if ($e.CloseReason -eq [System.Windows.Forms.CloseReason]::UserClosing) {
        $e.Cancel = $true
        $form.Hide()
    }
})

# Poll the bridge's own /data endpoint so the dialog (and now the tray
# tooltip) shows real proof it's alive and talking to the sim, instead of
# making you go check Task Manager (where it just shows up as an anonymous
# "python.exe").
$statusTimer = New-Object System.Windows.Forms.Timer
$statusTimer.Interval = 2000
# Set-NotifyText only actually touches the property (and so only fires the
# underlying Shell_NotifyIcon NIM_MODIFY call) when the text really changed.
# Confirmed by instrumenting live window creation: assigning $notifyIcon.Text
# unconditionally on every 2s tick - even to the exact same string - was
# spawning and destroying a real top-level "PFD Companion" window every
# single tick, which is the flash reported while this window is open. This
# is a known Windows 11 shell quirk with repeated identical NIM_MODIFY calls.
$script:lastNotifyText = $null
function Set-NotifyText([string]$text) {
    if ($script:lastNotifyText -ne $text) {
        $notifyIcon.Text = $text
        $script:lastNotifyText = $text
    }
}
$statusTimer.Add_Tick({
    try {
        # Invoke-RestMethod, not Invoke-WebRequest - confirmed by isolated
        # repro that Invoke-WebRequest, called on a timer inside a
        # ps2exe-compiled no-console host, spawns and destroys a real
        # top-level window (titled after the exe) on every single call. That
        # IS the flash reported while this status window is open - not a
        # console, not a separate process, just this one call. Also parses
        # JSON directly, so no separate ConvertFrom-Json needed.
        $reqArgs = @{ Uri = "http://localhost:5000/data"; TimeoutSec = 2 }
        if ($script:bridgeSession) { $reqArgs.WebSession = $script:bridgeSession }
        $d = Invoke-RestMethod @reqArgs
        if ($d.connected -and $d.sim_running) {
            $liveStatus.Text = "* Bridge running - connected to sim"
            $liveStatus.ForeColor = [System.Drawing.Color]::FromArgb(0, 200, 0)
            Set-NotifyText "PFD Companion - connected to sim"
        } else {
            $liveStatus.Text = "* Bridge running - waiting for MSFS..."
            $liveStatus.ForeColor = [System.Drawing.Color]::FromArgb(230, 170, 0)
            Set-NotifyText "PFD Companion - waiting for MSFS..."
        }
    } catch {
        $liveStatus.Text = "* Bridge not responding"
        $liveStatus.ForeColor = [System.Drawing.Color]::FromArgb(230, 60, 60)
        Set-NotifyText "PFD Companion - bridge not responding"
    }
})
$statusTimer.Start()

# Tails the bridge's own log output into the Activity panel, filtered down to
# just the tagged "[SimConnect] ..." / "[Supervisor] ..." / "[SimBrief] ..."
# lines — Flask's raw per-request access log and startup banner never start
# with "[", so they're naturally excluded without needing a fussier filter.
$script:lastConsoleText = ""
$consoleTimer = New-Object System.Windows.Forms.Timer
$consoleTimer.Interval = 1000
$consoleTimer.Add_Tick({
    try {
        $lines = @()
        if (Test-Path $bridgeLogFile) { $lines += @(Get-Content $bridgeLogFile -Tail 100 -ErrorAction SilentlyContinue) }
        if (Test-Path $bridgeErrFile) { $lines += @(Get-Content $bridgeErrFile -Tail 100 -ErrorAction SilentlyContinue) }
        $tagged = $lines | Where-Object { $_ -match '^\[' } | Select-Object -Last 8
        $text = if ($tagged) { $tagged -join "`r`n" } else { "Waiting for bridge activity..." }
        if ($text -ne $script:lastConsoleText) {
            $script:lastConsoleText = $text
            $consoleBox.Text = $text
            $consoleBox.SelectionStart = $consoleBox.Text.Length
            $consoleBox.ScrollToCaret()
        }
    } catch {}
})
$consoleTimer.Start()

# Keeps the process alive as a tray-only app — no window is shown by
# default; Open/double-click on the tray icon shows $form on demand, and
# Quit (the only thing that stops the message loop) is wired above.
$appContext = New-Object System.Windows.Forms.ApplicationContext
[System.Windows.Forms.Application]::Run($appContext)
