<#
====================================================================
 LAPS HOST MANAGER  —  single-file combined build
====================================================================
 This ONE file contains:
   1) The original LAPS_WEB_PORTAL_V4_MultiThreaded.ps1 logic, embedded
      verbatim inside a script block below (only two lines were touched —
      see the note right above $Global:PortalServerScriptBlock — so that
      Settings can override hostname/port without editing the file after
      you compile it to an .exe).
   2) A WinForms GUI wrapper (login screen, Start/Stop/Restart/Test/Open/
      Settings buttons, system tray icon).

 HOW IT RUNS:
   - Double-click / run normally  -> shows the GUI.
   - The GUI's "Start" button relaunches THIS SAME FILE (or, once you
     convert it to an .exe, this same .exe) as a hidden background
     process with the -RunServer switch, which skips the GUI entirely
     and just runs the embedded portal server. This is what lets it
     stay ONE file/exe instead of two.
====================================================================
#>
param([switch]$RunServer)

# ---------------------------------------------------------------
# Hide this process's own console window (harmless once you compile
# with ps2exe -noConsole too — this just becomes a no-op then)
# ---------------------------------------------------------------
Add-Type -Name Win -Namespace ConsoleUtil -MemberDefinition @'
[DllImport("kernel32.dll")]
public static extern IntPtr GetConsoleWindow();
[DllImport("user32.dll")]
public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
'@
try {
    $hWndConsole = [ConsoleUtil.Win]::GetConsoleWindow()
    if ($hWndConsole -ne [IntPtr]::Zero) { [ConsoleUtil.Win]::ShowWindow($hWndConsole, 0) | Out-Null } # 0 = SW_HIDE
} catch { }

# ======================================================================
# EMBEDDED PORTAL SERVER
# (original LAPS_WEB_PORTAL_V4_MultiThreaded.ps1, unmodified except for
#  the $ListenIP / $Port lines, which now optionally read from
#  LAPS_LISTEN_IP / LAPS_PORT environment variables — set by the GUI's
#  Settings screen when it launches this in -RunServer mode. If those
#  env vars aren't set, they fall back to the exact same hardcoded
#  defaults the script originally had.)
# ======================================================================
$Global:PortalServerScriptBlock = {
#requires -Modules LAPS
#requires -Version 5.1

[CmdletBinding()]
param()

# ==================== NO-POPUP OUTPUT OVERRIDE ====================
# When this script is compiled with ps2exe (especially with -noConsole),
# the default Write-Host / Read-Host implementations are backed by a
# custom PSHostUserInterface that shows a blocking MessageBox / InputBox
# popup for every single call instead of writing to the console streams.
# Since this whole block only ever runs as a HIDDEN background process
# (launched by the GUI with -RunServer and RedirectStandardOutput=$true),
# we override both cmdlets here so everything goes straight to stdout,
# which the GUI already captures and streams into the Live Activity Log.
# This override only applies inside this script block (and everything
# it calls), so the GUI's own Write-LiveLog / MessageBox usage elsewhere
# in the file is completely unaffected.
function Write-Host {
    param(
        [Parameter(Position = 0, ValueFromPipeline = $true)]
        [object]$Object = "",
        [switch]$NoNewline,
        [System.ConsoleColor]$ForegroundColor,
        [System.ConsoleColor]$BackgroundColor,
        [object]$Separator = " "
    )
    process {
        $text = if ($null -eq $Object) { "" } else { [string]$Object }
        if ($NoNewline) { [Console]::Out.Write($text) }
        else { [Console]::Out.WriteLine($text) }
    }
}

function Read-Host {
    param([Parameter(Position = 0)][string]$Prompt, [switch]$AsSecureString)
    # Headless process — there is no one to answer a prompt, so just log
    # it (if given) and fall through immediately instead of blocking or
    # popping up an InputBox.
    if ($Prompt) { [Console]::Out.WriteLine($Prompt) }
    return ""
}

# ==================== CONFIGURATION ====================
$ListenIP   = if ($env:LAPS_LISTEN_IP) { $env:LAPS_LISTEN_IP } else { "10.209.110.220" }
$Port       = if ($env:LAPS_PORT) { [int]$env:LAPS_PORT } else { 8080 }
$ServerUrl  = "http://" + $ListenIP + ":" + $Port + "/"
$DNSName    = "LAPS_WEB_PORTAL"

# ==================== MULTI-THREADING CONFIGURATION ====================
# Maximum number of requests processed simultaneously via RunspacePool.
# Increase for more concurrent users; each runspace is lightweight.
if (-not (Get-Variable -Name MaxConcurrentRequests -Scope Global -ErrorAction SilentlyContinue)) {
    $Global:MaxConcurrentRequests = 50
}
$MinConcurrentRequests = 1

# ==================== LOGGING CONFIGURATION ====================
$BaseLogPath = "D:\LAPS_WEB_PORTAL"
$LogPath = Join-Path $BaseLogPath "Logs"
$UserDetailsPath = Join-Path $BaseLogPath "user_details"
$PortalStatusPath = Join-Path $BaseLogPath "PortalStatus"

# Create necessary directories if they don't exist
foreach ($dir in @($BaseLogPath, $LogPath, $UserDetailsPath, $PortalStatusPath)) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

# ==================== VALIDATION ====================
Write-Host "Checking LAPS Module..." -ForegroundColor Cyan
try {
    Import-Module LAPS -Force -ErrorAction Stop
    $lapsCmd = Get-Command Get-LapsADPassword -ErrorAction Stop
    Write-Host "[OK] LAPS module loaded: $($lapsCmd.ModuleName)" -ForegroundColor Green
} catch {
    Write-Host "[FAIL] LAPS module not found." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# ==================== GLOBAL STATE ====================
$Global:SessionData = @{}
$Global:AuthorizedUsers = @{}
$Global:LoginAttempts = @{}
$Global:SessionLock = [System.Object]::new()
$Global:LoginLock = [System.Object]::new()
$Global:LogLock = [System.Object]::new()

$MAX_LOGIN_ATTEMPTS = 5
$LOCKOUT_MINUTES = 15
$SESSION_TIMEOUT_MINUTES = 15

# ==================== INITIALIZATION ====================
Write-Host "Initializing Portal..." -ForegroundColor Cyan

# Add built-in admin
$Global:AuthorizedUsers["ADMIN"] = @{
    username = "ADMIN"
    name     = "Administrator"
    authorized = $true
    addedBy  = "SYSTEM"
    addedDate = Get-Date
}

# Load authorized users from file
function LoadAuthorizedUsersFromFile {
    try {
        $userFile = Join-Path $UserDetailsPath "authorized_users.json"
        if (Test-Path $userFile) {
            $content = Get-Content $userFile -Raw -ErrorAction SilentlyContinue
            if ($content) {
                $loaded = $content | ConvertFrom-Json -ErrorAction SilentlyContinue
                if ($loaded) {
                    [System.Threading.Monitor]::Enter($Global:AuthorizedUsers)
                    try {
                        $Global:AuthorizedUsers.Clear()
                        $loaded.PSObject.Properties | ForEach-Object {
                            $Global:AuthorizedUsers[$_.Name] = @{
                                username   = $_.Value.username
                                name       = $_.Value.name
                                authorized = $_.Value.authorized
                                addedBy    = $_.Value.addedBy
                                addedDate  = $_.Value.addedDate
                            }
                        }
                    } finally {
                        [System.Threading.Monitor]::Exit($Global:AuthorizedUsers)
                    }
                }
            }
        }
    } catch {
        Write-Host "Warning: Could not load authorized users: $_" -ForegroundColor Yellow
    }
}

# Save authorized users to file
function SaveAuthorizedUsersToFile {
    try {
        $userFile = Join-Path $UserDetailsPath "authorized_users.json"
        [System.Threading.Monitor]::Enter($Global:AuthorizedUsers)
        try {
            $json = $Global:AuthorizedUsers | ConvertTo-Json -ErrorAction SilentlyContinue
            Set-Content -Path $userFile -Value $json -Encoding UTF8 -Force -ErrorAction SilentlyContinue
        } finally {
            [System.Threading.Monitor]::Exit($Global:AuthorizedUsers)
        }
    } catch {
        Write-Host "Warning: Could not save authorized users: $_" -ForegroundColor Yellow
    }
}

LoadAuthorizedUsersFromFile

# ==================== SESSION MANAGEMENT ====================
function CreateSession {
    param([string]$Username, [string]$UserFullName, [bool]$IsAdmin, [string]$IPAddress)
    
    try {
        $sessionId = [System.Convert]::ToBase64String((1..32 | ForEach-Object { [byte](Get-Random -Minimum 0 -Maximum 256) })) -replace '\+', '-' -replace '/', '_' -replace '=', ''
        
        [System.Threading.Monitor]::Enter($Global:SessionLock)
        try {
            $Global:SessionData[$sessionId] = @{
                User         = $Username
                UserName     = $UserFullName
                IsAdmin      = $IsAdmin
                LoginTime    = Get-Date
                LastActivity = Get-Date
                IPAddress    = $IPAddress
            }
        } finally {
            [System.Threading.Monitor]::Exit($Global:SessionLock)
        }
        
        return $sessionId
    } catch {
        Write-Host "[SESSION_ERROR] Failed to create session: $_" -ForegroundColor Red
        return $null
    }
}

function IsSessionValid {
    param([string]$SessionId)
    
    try {
        if ([string]::IsNullOrEmpty($SessionId)) { return $false }
        
        [System.Threading.Monitor]::Enter($Global:SessionLock)
        try {
            if (-not $Global:SessionData.ContainsKey($SessionId)) { return $false }
            
            $session = $Global:SessionData[$SessionId]
            $elapsed = (Get-Date) - $session.LastActivity
            
            if ($elapsed.TotalMinutes -ge $SESSION_TIMEOUT_MINUTES) {
                $Global:SessionData.Remove($SessionId)
                return $false
            }
            
            $session.LastActivity = Get-Date
            return $true
        } finally {
            [System.Threading.Monitor]::Exit($Global:SessionLock)
        }
    } catch {
        return $false
    }
}

function GetSessionUser {
    param([string]$SessionId)
    try {
        if ([string]::IsNullOrEmpty($SessionId)) { return "" }
        
        [System.Threading.Monitor]::Enter($Global:SessionLock)
        try {
            if ($Global:SessionData.ContainsKey($SessionId)) {
                return $Global:SessionData[$SessionId].User
            }
        } finally {
            [System.Threading.Monitor]::Exit($Global:SessionLock)
        }
        return ""
    } catch {
        return ""
    }
}

function GetSessionUserName {
    param([string]$SessionId)
    try {
        if ([string]::IsNullOrEmpty($SessionId)) { return "" }
        
        [System.Threading.Monitor]::Enter($Global:SessionLock)
        try {
            if ($Global:SessionData.ContainsKey($SessionId)) {
                return $Global:SessionData[$SessionId].UserName
            }
        } finally {
            [System.Threading.Monitor]::Exit($Global:SessionLock)
        }
        return ""
    } catch {
        return ""
    }
}

function IsSessionAdmin {
    param([string]$SessionId)
    try {
        if ([string]::IsNullOrEmpty($SessionId)) { return $false }
        
        [System.Threading.Monitor]::Enter($Global:SessionLock)
        try {
            if ($Global:SessionData.ContainsKey($SessionId)) {
                return $Global:SessionData[$SessionId].IsAdmin
            }
        } finally {
            [System.Threading.Monitor]::Exit($Global:SessionLock)
        }
        return $false
    } catch {
        return $false
    }
}

# ==================== LOGIN PROTECTION ====================
function IsIPLocked {
    param([string]$IPAddress)
    
    try {
        [System.Threading.Monitor]::Enter($Global:LoginLock)
        try {
            if ($Global:LoginAttempts.ContainsKey($IPAddress)) {
                $attempt = $Global:LoginAttempts[$IPAddress]
                $timeSinceLastAttempt = (Get-Date) - $attempt.LastAttempt
                
                if ($timeSinceLastAttempt.TotalMinutes -gt $LOCKOUT_MINUTES) {
                    $Global:LoginAttempts.Remove($IPAddress)
                    return $false
                }
                
                return $attempt.FailureCount -ge $MAX_LOGIN_ATTEMPTS
            }
            return $false
        } finally {
            [System.Threading.Monitor]::Exit($Global:LoginLock)
        }
    } catch {
        return $false
    }
}

function RecordFailedLogin {
    param([string]$IPAddress)
    
    try {
        [System.Threading.Monitor]::Enter($Global:LoginLock)
        try {
            if ($Global:LoginAttempts.ContainsKey($IPAddress)) {
                $attempt = $Global:LoginAttempts[$IPAddress]
                $attempt.FailureCount++
                $attempt.LastAttempt = Get-Date
            } else {
                $Global:LoginAttempts[$IPAddress] = @{
                    IPAddress    = $IPAddress
                    FailureCount = 1
                    LastAttempt  = Get-Date
                }
            }
        } finally {
            [System.Threading.Monitor]::Exit($Global:LoginLock)
        }
    } catch {
        # Silent fail
    }
}

function ClearFailedLogins {
    param([string]$IPAddress)
    
    try {
        [System.Threading.Monitor]::Enter($Global:LoginLock)
        try {
            if ($Global:LoginAttempts.ContainsKey($IPAddress)) {
                $Global:LoginAttempts.Remove($IPAddress)
            }
        } finally {
            [System.Threading.Monitor]::Exit($Global:LoginLock)
        }
    } catch {
        # Silent fail
    }
}

# ==================== LOGGING ====================
function LogActivity {
    param(
        [string]$ActivityType,
        [string]$Username,
        [string]$IPAddress,
        [string]$Details,
        [string]$Status = "SUCCESS",
        [string]$Hostname = ""
    )
    
    try {
        [System.Threading.Monitor]::Enter($Global:LogLock)
        try {
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            $dateForFile = Get-Date -Format "yyyy-MM-dd"
            
            # Activity log
            $activityLogFile = Join-Path $LogPath "LAPS_Activity_$dateForFile.log"
            $logEntry = @{
                Timestamp    = $timestamp
                ActivityType = $ActivityType
                Username     = $Username
                IPAddress    = $IPAddress
                Hostname     = $Hostname
                Details      = $Details
                Status       = $Status
            } | ConvertTo-Json -Compress
            
            Add-Content -Path $activityLogFile -Value $logEntry -Encoding UTF8 -ErrorAction SilentlyContinue
            
            # Portal status log for LOGIN/LOGOUT tracking
            if ($ActivityType -in @("LOGIN", "LOGOUT", "LOGIN_FAILED", "LOGIN_BLOCKED")) {
                $statusLogFile = Join-Path $PortalStatusPath "Portal_Status_$dateForFile.log"
                $statusEntry = "[$timestamp] [$ActivityType] User: $Username | IP: $IPAddress | Status: $Status"
                
                if ($ActivityType -eq "LOGIN") {
                    $statusEntry += " | EVENT: Portal Opened and Active"
                } elseif ($ActivityType -eq "LOGOUT") {
                    $statusEntry += " | EVENT: Portal Closed/Logged Out"
                }
                
                Add-Content -Path $statusLogFile -Value $statusEntry -Encoding UTF8 -ErrorAction SilentlyContinue
            }
            
            Write-Host "[ACTIVITY] [$timestamp] [$ActivityType] User: $Username | IP: $IPAddress | Status: $Status | Details: $Details" -ForegroundColor Cyan
        } finally {
            [System.Threading.Monitor]::Exit($Global:LogLock)
        }
    } catch {
        # Silent fail for logging
    }
}

# ==================== AUTHENTICATION ====================
function IsUserAuthorized {
    param([string]$Username)
    
    try {
        [System.Threading.Monitor]::Enter($Global:AuthorizedUsers)
        try {
            return $Global:AuthorizedUsers.ContainsKey($Username.ToUpper())
        } finally {
            [System.Threading.Monitor]::Exit($Global:AuthorizedUsers)
        }
    } catch {
        return $false
    }
}

function AuthenticateWithDomain {
    param([string]$Username, [string]$Password)
    
    try {
        [System.DirectoryServices.DirectoryEntry]$entry = New-Object System.DirectoryServices.DirectoryEntry(
            "LDAP://IDPBGTN.COM",
            "IDPBGTN\$Username",
            $Password
        )
        
        # Force authentication
        $null = $entry.NativeObject
        $entry.Dispose()
        return $true
    } catch {
        return $false
    }
}

# ==================== UTILITY FUNCTIONS ====================
function SafeHtmlEncode {
    param([string]$Text)
    try {
        if ([string]::IsNullOrEmpty($Text)) { return $Text }
        return $Text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' -replace "'", '&#39;'
    } catch {
        return ""
    }
}

function ParseFormData {
    param([string]$Body)
    
    $result = @{}
    try {
        if ([string]::IsNullOrEmpty($Body)) { return $result }
        
        $pairs = $Body -split '&'
        foreach ($pair in $pairs) {
            if ([string]::IsNullOrEmpty($pair)) { continue }
            $kv = $pair -split '=', 2
            if ($kv.Count -eq 2) {
                $key = [System.Web.HttpUtility]::UrlDecode($kv[0])
                $value = [System.Web.HttpUtility]::UrlDecode($kv[1])
                $result[$key] = $value
            }
        }
    } catch { }
    
    return $result
}

function ParseCookies {
    param([string]$CookieHeader)
    
    $result = @{}
    try {
        if ([string]::IsNullOrEmpty($CookieHeader)) { return $result }
        
        $cookies = $CookieHeader -split '; '
        foreach ($cookie in $cookies) {
            if ([string]::IsNullOrEmpty($cookie)) { continue }
            $parts = $cookie -split '=', 2
            if ($parts.Count -eq 2) {
                $result[$parts[0].Trim()] = $parts[1].Trim()
            }
        }
    } catch { }
    
    return $result
}

function GetSessionCookie {
    param([System.Net.HttpListenerRequest]$Request)
    
    try {
        $cookieHeader = $Request.Headers["Cookie"]
        if (-not [string]::IsNullOrEmpty($cookieHeader)) {
            $cookies = ParseCookies $cookieHeader
            if ($cookies.ContainsKey("LAPS_SESSION")) {
                return $cookies["LAPS_SESSION"]
            }
        }
    } catch { }
    
    return $null
}

# ==================== HTML PAGE BUILDERS ====================
function BuildLoginPage {
    param([string]$Message)
    
    $messageHtml = ""
    if (-not [string]::IsNullOrEmpty($Message)) {
        $msgClass = if ($Message -like "*successfully*") { "alert-success" } else { "alert-error" }
        $messageHtml = "<div class='alert $msgClass'>$(SafeHtmlEncode $Message)</div>"
    }
    
    $body = @"
<div class='card'>
    <div class='card-header text-center'>
        <h1>LAPS Password Portal</h1>
        <p>Secure Access to Local Administrator Passwords</p>
    </div>
    $messageHtml
    <form method='POST' action='/login'>
        <div class='form-group'>
            <label for='username'>Username</label>
            <input type='text' id='username' name='username' style='text-transform:uppercase;' placeholder='domain EMP ID' required autofocus>
            <small class='help-hint'>User: Use your domain EMP ID</small>
        </div>
        <div class='form-group'>
            <label for='password'>Password</label>
            <input type='password' id='password' name='password' placeholder='Password' required>
            <small class='help-hint'>Use your domain password</small>
        </div>
        <button type='submit' class='btn btn-primary'>Login</button>
    </form>
</div>
"@
    
    return GetPageTemplate $body
}

function BuildMainPage {
    param(
        [string]$Message,
        [string]$MessageType,
        [string]$PrefillHostname,
        [string]$Username,
        [string]$UserDisplayName,
        [bool]$IsAdmin
    )
    
    $statusHtml = ""
    if (-not [string]::IsNullOrEmpty($Message)) {
        $statusHtml = "<div class='alert alert-$MessageType'>$(SafeHtmlEncode $Message)</div>"
    }
    
    $hostValue = ""
    if (-not [string]::IsNullOrEmpty($PrefillHostname)) {
        $hostValue = " value='$(SafeHtmlEncode $PrefillHostname)'"
    }
    
    $adminLink = if ($IsAdmin) { "<a href='/admin' class='btn btn-secondary btn-small'>Settings</a>" } else { "" }
    
    $body = @"
<div class='card'>
    <div class='card-header'>
        <div class='header-top'>
            <div>
                <h1>LAPS Password Retrieval</h1>
                <p>Enter computer hostname to retrieve local administrator password</p>
            </div>
            <div class='user-section'>
                <div>User: <span class='user-name'>$(SafeHtmlEncode $UserDisplayName)</span></div>
                <div class='button-group'>
                    <a href='/logout-page' class='btn btn-secondary btn-small'>Logout</a>
                    $adminLink
                </div>
            </div>
        </div>
    </div>
    $statusHtml
    <form method='POST' action='/get-laps' id='lapsForm'>
        <div class='form-group'>
            <label for='hostname'>Computer Hostname</label>
            <input type='text' id='hostname' name='hostname' style='text-transform:uppercase;' placeholder='WKSTN-IT-001.idpbgtn.com' required autofocus autocomplete='off'$hostValue>
        </div>
        <button type='submit' class='btn btn-primary'>
            <span class='btn-text'>Retrieve Password</span>
            <span class='btn-loader' style='display:none;'>Querying AD...</span>
        </button>
    </form>
    <div class='help-text'><strong>Tip:</strong> Use the full FQDN for best results. LAPS passwords expire periodically.</div>
</div>
<script>
document.getElementById('lapsForm').addEventListener('submit', function(e) { 
    var btn = this.querySelector('button'); 
    btn.disabled = true; 
    btn.querySelector('.btn-text').style.display = 'none'; 
    btn.querySelector('.btn-loader').style.display = 'inline'; 
});
</script>
"@
    
    return GetPageTemplate $body
}

function BuildResultPage {
    param(
        [string]$Computer,
        [string]$Password,
        [string]$ExpiryHtml,
        [string]$Username,
        [string]$UserDisplayName,
        [bool]$IsAdmin
    )
    
    $adminLink = if ($IsAdmin) { "<a href='/admin' class='btn btn-secondary' style='margin: 0 6px;'>Settings</a>" } else { "" }
    
    $body = @"
<div class='card'>
    <div class='card-header'>
        <div class='header-top'>
            <div>
                <h1>Password Retrieved</h1>
            </div>
            <div class='user-section'>
                <div>User: <span class='user-name'>$(SafeHtmlEncode $UserDisplayName)</span></div>
                <div class='button-group'>
                    <a href='/logout-page' class='btn btn-secondary btn-small'>Logout</a>
                </div>
            </div>
        </div>
    </div>
    <div class='result-grid'>
        <div class='result-item'>
            <span class='result-label'>Computer</span>
            <span class='result-value'>$(SafeHtmlEncode $Computer)</span>
        </div>
        <div class='result-item'>
            <span class='result-label'>Password</span>
            <div class='password-container'>
                <span id='pwd' class='password-blur' onclick='toggleReveal()'>$(SafeHtmlEncode $Password)</span>
                <button type='button' class='btn btn-small btn-secondary' onclick='copyPassword()' id='copyBtn'>Copy</button>
            </div>
            <small class='hint'>Click password to reveal, Click Copy to copy</small>
        </div>
        <div class='result-item'>
            <span class='result-label'>Expiration</span>
            <span class='result-value'>$ExpiryHtml</span>
        </div>
    </div>
    <div class='actions'>
        <a href='/' class='btn btn-secondary'>Query Another</a>
        $adminLink
    </div>
</div>
<script>
function toggleReveal() { 
    var el = document.getElementById('pwd'); 
    el.classList.toggle('password-blur'); 
    el.classList.toggle('password-clear'); 
}

function copyPassword() { 
    var pwd = document.getElementById('pwd').innerText; 
    var btn = document.getElementById('copyBtn');
    var originalText = btn.innerHTML;
    
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(pwd).then(function() { 
            btn.innerHTML = 'Copied!'; 
            btn.classList.add('copied');
            setTimeout(function() { btn.innerHTML = originalText; btn.classList.remove('copied'); }, 2000); 
        }).catch(function() {
            fallbackCopy(pwd, btn, originalText);
        });
    } else {
        fallbackCopy(pwd, btn, originalText);
    }
}

function fallbackCopy(text, btn, originalText) {
    var textarea = document.createElement('textarea');
    textarea.value = text;
    document.body.appendChild(textarea);
    textarea.select();
    try {
        document.execCommand('copy');
        btn.innerHTML = 'Copied!'; 
        btn.classList.add('copied');
        setTimeout(function() { btn.innerHTML = originalText; btn.classList.remove('copied'); }, 2000);
    } catch (err) {
        alert('Failed to copy password');
    }
    document.body.removeChild(textarea);
}
</script>
"@
    
    return GetPageTemplate $body
}

function BuildAdminPage {
    param(
        [string]$Message,
        [string]$Username,
        [string]$UserDisplayName
    )
    
    $messageHtml = ""
    if (-not [string]::IsNullOrEmpty($Message)) {
        $msgClass = if ($Message -like "*successfully*") { "alert-success" } else { "alert-error" }
        $messageHtml = "<div class='alert $msgClass'>$(SafeHtmlEncode $Message)</div>"
    }
    
    $body = @"
<div class='card' style='max-width: 700px;'>
    <div class='card-header'>
        <div class='header-top'>
            <div>
                <h1>Settings</h1>
                <p>Manage authorized users</p>
            </div>
            <div class='user-section'>
                <div>Admin: <span class='user-name'>$(SafeHtmlEncode $UserDisplayName)</span></div>
                <div class='button-group'>
                    <a href='/' class='btn btn-secondary btn-small'>Back</a>
                    <a href='/logout-page' class='btn btn-secondary btn-small'>Logout</a>
                </div>
            </div>
        </div>
    </div>
    $messageHtml
    <div class='admin-section'>
        <div class='admin-subsection'>
            <h2>Add Domain User</h2>
            <form id='addUserForm'>
                <div class='form-group'>
                    <label for='new_username'>Domain Username</label>
                    <input type='text' id='new_username' name='new_username' placeholder='john.doe' required autocomplete='off'>
                    <small class='help-hint'>User's domain login ID</small>
                </div>
                <div class='form-group'>
                    <label for='new_user_name'>Full Name</label>
                    <input type='text' id='new_user_name' name='new_user_name' placeholder='John Doe' required autocomplete='off'>
                    <small class='help-hint'>User's display name</small>
                </div>
                <button type='submit' class='btn btn-primary btn-small'>Add User</button>
            </form>
        </div>
        <div class='admin-subsection'>
            <h2>Authorized Users</h2>
            <div class='search-box'>
                <input type='text' id='searchUsers' placeholder='Search users...' autocomplete='off'>
            </div>
            <div id='usersList' class='users-list'>
                <p>Loading...</p>
            </div>
        </div>
    </div>
    <div id='editModal' class='modal' style='display:none;'>
        <div class='modal-content'>
            <span class='close' onclick='closeEditModal()'>&times;</span>
            <h2>Edit User</h2>
            <form id='editUserForm'>
                <input type='hidden' id='edit_username' name='edit_username'>
                <div class='form-group'>
                    <label for='edit_user_name'>Full Name</label>
                    <input type='text' id='edit_user_name' name='edit_user_name' required autocomplete='off'>
                </div>
                <div class='form-group' style='display:flex; gap:10px;'>
                    <button type='submit' class='btn btn-primary btn-small'>Save Changes</button>
                    <button type='button' class='btn btn-secondary btn-small' onclick='closeEditModal()'>Cancel</button>
                </div>
            </form>
        </div>
    </div>
</div>
<script>
var allUsers = [];

function loadUsers() {
    fetch('/admin/get-users')
        .then(function(r) { return r.json(); })
        .then(function(data) {
            allUsers = data.users || [];
            renderUsers(allUsers);
        })
        .catch(function(err) { console.error('Error loading users:', err); });
}

function renderUsers(users) {
    var html = '';
    if (users && users.length > 0) {
        users.forEach(function(u) {
            var isAdmin = u.username === 'ADMIN' ? ' (Built-in)' : '';
            var displayName = u.name || u.username;
            html += '<div class=user-item>';
            html += '<div class=user-info>';
            html += '<div class=username>' + SafeHtmlEncode(u.username) + '</div>';
            html += '<div class=username-display>' + SafeHtmlEncode(displayName) + isAdmin + '</div>';
            html += '</div>';
            html += '<div class=user-actions>';
            if (u.username !== 'ADMIN') {
                html += '<button type=button class=btn class=btn-edit onclick=openEditModal(\"' + u.username + '\",\"' + SafeHtmlEncode(u.name) + '\")>Edit</button>';
                html += '<button type=button class=btn class=btn-remove onclick=removeUser(\"' + u.username + '\")>Remove</button>';
            }
            html += '</div>';
            html += '</div>';
        });
    } else {
        html = '<p>No users found</p>';
    }
    document.getElementById('usersList').innerHTML = html;
}

function SafeHtmlEncode(s) {
    if (!s) return '';
    var div = document.createElement('div');
    div.textContent = s;
    return div.innerHTML;
}

function filterUsers() {
    var searchTerm = document.getElementById('searchUsers').value.toLowerCase();
    var filtered = allUsers.filter(function(u) {
        return (u.username.toLowerCase().indexOf(searchTerm) > -1 || 
                (u.name && u.name.toLowerCase().indexOf(searchTerm) > -1));
    });
    renderUsers(filtered);
}

function openEditModal(username, displayName) {
    document.getElementById('edit_username').value = username;
    document.getElementById('edit_user_name').value = displayName;
    document.getElementById('editModal').style.display = 'block';
}

function closeEditModal() {
    document.getElementById('editModal').style.display = 'none';
    document.getElementById('editUserForm').reset();
}

window.onclick = function(event) {
    var modal = document.getElementById('editModal');
    if (event.target == modal) {
        modal.style.display = 'none';
    }
}

document.getElementById('searchUsers').addEventListener('keyup', filterUsers);

function removeUser(username) {
    if (!confirm('Remove user ' + username + '?')) return;
    fetch('/admin/remove-user', {
        method: 'POST',
        body: 'username=' + encodeURIComponent(username)
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        alert(data.message);
        loadUsers();
        document.getElementById('searchUsers').value = '';
    })
    .catch(function(err) { console.error('Error removing user:', err); alert('Error removing user'); });
}

document.getElementById('editUserForm').addEventListener('submit', function(e) {
    e.preventDefault();
    var username = document.getElementById('edit_username').value;
    var displayName = document.getElementById('edit_user_name').value;
    
    if (!displayName.trim()) {
        alert('Display name cannot be empty');
        return;
    }
    
    fetch('/admin/edit-user', {
        method: 'POST',
        body: 'username=' + encodeURIComponent(username) + '&display_name=' + encodeURIComponent(displayName)
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        alert(data.message);
        if (data.success) {
            closeEditModal();
            loadUsers();
            document.getElementById('searchUsers').value = '';
        }
    })
    .catch(function(err) { console.error('Error updating user:', err); alert('Error updating user'); });
});

document.getElementById('addUserForm').addEventListener('submit', function(e) {
    e.preventDefault();
    var username = document.getElementById('new_username').value;
    var userName = document.getElementById('new_user_name').value;
    fetch('/admin/add-user', {
        method: 'POST',
        body: 'new_username=' + encodeURIComponent(username) + '&new_user_name=' + encodeURIComponent(userName)
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        alert(data.message);
        if (data.success) {
            document.getElementById('new_username').value = '';
            document.getElementById('new_user_name').value = '';
            loadUsers();
            document.getElementById('searchUsers').value = '';
        }
    })
    .catch(function(err) { console.error('Error adding user:', err); alert('Error adding user'); });
});

loadUsers();
</script>
"@
    
    return GetPageTemplate $body
}

function GetPageTemplate {
    param([string]$BodyContent)
    
    $faviconHtml = ""
    if (-not [string]::IsNullOrEmpty($env:LAPS_LOGO_BASE64)) {
        $faviconHtml = "<link rel='icon' href='data:image/png;base64,$($env:LAPS_LOGO_BASE64)'>"
    }
    
    return @"
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>LAPS Password Portal</title>
    $faviconHtml
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
        .card { background: white; border-radius: 16px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); width: 100%; max-width: 480px; overflow: hidden; }
        .card-header { background: linear-gradient(90deg, #667eea 0%, #764ba2 100%); color: white; padding: 28px; }
        .card-header.text-center { text-align: center; }
        .card-header.text-center h1 { margin-bottom: 8px; }
        .header-top { display: flex; justify-content: space-between; align-items: flex-start; gap: 20px; }
        .card-header h1 { font-size: 1.5rem; font-weight: 600; margin-bottom: 6px; }
        .card-header p { opacity: 0.9; font-size: 0.875rem; }
        .user-section { text-align: right; white-space: nowrap; }
        .user-section > div:first-child { color: #e0e0e0; font-size: 0.85rem; margin-bottom: 8px; }
        .user-name { font-weight: 600; color: #ffffff; }
        .button-group { display: flex; gap: 8px; flex-wrap: wrap; justify-content: flex-end; }
        .card > *:not(.card-header) { padding: 24px 28px; }
        .alert { padding: 14px 18px; border-radius: 8px; margin-bottom: 20px; font-size: 0.875rem; line-height: 1.5; }
        .alert-error { background: #fee2e2; color: #991b1b; border: 1px solid #fecaca; }
        .alert-success { background: #dcfce7; color: #166534; border: 1px solid #bbf7d0; }
        .form-group { margin-bottom: 20px; }
        label { display: block; font-size: 0.875rem; font-weight: 600; color: #374151; margin-bottom: 6px; }
        input[type='text'], input[type='password'], input[type='hidden'] { width: 100%; padding: 12px 16px; border: 2px solid #e5e7eb; border-radius: 8px; font-size: 1rem; transition: all 0.2s; }
        input[type='text']:focus, input[type='password']:focus { outline: none; border-color: #667eea; box-shadow: 0 0 0 3px rgba(102,126,234,0.1); }
        .help-hint { display: block; margin-top: 6px; font-size: 0.75rem; color: #9ca3af; font-style: italic; }
        .btn { display: inline-flex; align-items: center; justify-content: center; padding: 12px 24px; border: none; border-radius: 8px; font-size: 1rem; font-weight: 600; cursor: pointer; transition: all 0.2s; text-decoration: none; }
        .btn-primary { background: linear-gradient(90deg, #667eea 0%, #764ba2 100%); color: white; width: 100%; }
        .btn-primary:hover:not(:disabled) { transform: translateY(-1px); box-shadow: 0 8px 20px rgba(102,126,234,0.4); }
        .btn-primary:disabled { opacity: 0.7; cursor: not-allowed; }
        .btn-secondary { background: #f3f4f6; color: #374151; border: none; }
        .btn-secondary:hover { background: #e5e7eb; }
        .btn-small { padding: 6px 12px; font-size: 0.875rem; width: auto; }
        .btn-edit { padding: 6px 12px; font-size: 0.875rem; width: auto; background: #dbeafe; color: #1e40af; border: none; margin-right: 4px; }
        .btn-edit:hover { background: #bfdbfe; }
        .btn-remove { padding: 6px 12px; font-size: 0.875rem; width: auto; background: #fee2e2; color: #991b1b; border: none; }
        .btn-remove:hover { background: #fecaca; }
        .btn.copied { background: linear-gradient(90deg, #10b981 0%, #059669 100%); color: white; }
        .help-text { margin-top: 20px; padding-top: 20px; border-top: 1px solid #e5e7eb; font-size: 0.875rem; color: #6b7280; }
        .result-grid { display: flex; flex-direction: column; gap: 20px; }
        .result-item { padding: 16px; background: #f9fafb; border-radius: 8px; }
        .result-label { display: block; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: #6b7280; margin-bottom: 8px; }
        .result-value { font-size: 1rem; color: #111827; word-break: break-all; }
        .password-container { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
        .password-blur { filter: blur(6px); user-select: none; cursor: pointer; font-family: 'Consolas','Monaco',monospace; font-size: 1.125rem; letter-spacing: 0.05em; transition: filter 0.2s; flex: 1; min-width: 200px; }
        .password-clear { filter: none; user-select: all; cursor: pointer; font-family: 'Consolas','Monaco',monospace; font-size: 1.125rem; letter-spacing: 0.05em; flex: 1; min-width: 200px; }
        .hint { display: block; margin-top: 8px; color: #9ca3af; font-size: 0.75rem; }
        .actions { padding-top: 20px; border-top: 1px solid #e5e7eb; display: flex; gap: 12px; }
        .actions .btn { margin: 0; }
        .expiry-ok { color: #166534; font-weight: 600; }
        .expiry-warning { color: #92400e; font-weight: 600; }
        .expiry-critical { color: #991b1b; font-weight: 600; animation: pulse 2s infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.6; } }
        .admin-section { display: flex; flex-direction: column; gap: 30px; }
        .admin-subsection { padding: 20px; background: #f9fafb; border-radius: 8px; }
        .admin-subsection h2 { font-size: 1.125rem; margin-bottom: 16px; color: #111827; }
        .search-box { margin-bottom: 16px; }
        .search-box input { width: 100%; padding: 10px 14px; border: 2px solid #e5e7eb; border-radius: 6px; font-size: 0.95rem; }
        .search-box input:focus { outline: none; border-color: #667eea; box-shadow: 0 0 0 3px rgba(102,126,234,0.1); }
        .users-list { display: flex; flex-direction: column; gap: 10px; max-height: 400px; overflow-y: auto; padding-right: 8px; }
        .users-list::-webkit-scrollbar { width: 8px; }
        .users-list::-webkit-scrollbar-track { background: #f1f1f1; border-radius: 10px; }
        .users-list::-webkit-scrollbar-thumb { background: #888; border-radius: 10px; }
        .users-list::-webkit-scrollbar-thumb:hover { background: #555; }
        .user-item { display: flex; justify-content: space-between; align-items: center; padding: 12px; background: white; border-radius: 6px; border: 1px solid #e5e7eb; }
        .user-info { flex: 1; min-width: 0; }
        .user-actions { display: flex; gap: 6px; }
        .username { font-weight: 600; color: #374151; font-size: 0.95rem; }
        .username-display { font-size: 0.85rem; color: #6b7280; margin-top: 2px; }
        .modal { position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.5); }
        .modal-content { background-color: white; margin: 10% auto; padding: 30px; border-radius: 12px; width: 90%; max-width: 400px; box-shadow: 0 10px 40px rgba(0,0,0,0.3); animation: slideIn 0.3s ease-out; }
        @keyframes slideIn { from { transform: translateY(-50px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
        .modal-content h2 { margin-bottom: 20px; color: #111827; }
        .close { color: #9ca3af; float: right; font-size: 28px; font-weight: bold; cursor: pointer; }
        .close:hover { color: #374151; }
        @media (max-width: 600px) {
            .header-top { flex-direction: column; }
            .user-section { text-align: left; }
            .button-group { justify-content: flex-start; }
            .card { max-width: 100%; }
            .user-item { flex-direction: column; align-items: flex-start; }
            .user-actions { width: 100%; margin-top: 10px; }
            .btn-edit, .btn-remove { width: 100%; }
        }
    </style>
</head>
<body>
    $BodyContent
</body>
</html>
"@
}

# ==================== REQUEST HANDLERS ====================
function HandleLogin {
    param(
        [System.Net.HttpListenerRequest]$Request,
        [System.Net.HttpListenerResponse]$Response,
        [string]$ClientIP
    )
    
    try {
        if (IsIPLocked $ClientIP) {
            LogActivity "LOGIN_BLOCKED" "Unknown" $ClientIP "IP blocked due to multiple failed attempts" "BLOCKED"
            $html = BuildLoginPage "Too many failed login attempts. Please try again in 15 minutes."
            SendHtml $Response $html $null
            return
        }
        
        $body = $null
        if ($Request.ContentLength64 -gt 0) {
            $reader = New-Object System.IO.StreamReader($Request.InputStream, $Request.ContentEncoding)
            $body = $reader.ReadToEnd()
            $reader.Close()
        }
        
        $formData = ParseFormData $body
        $username = if ($formData["username"]) { $formData["username"] } else { "" }
        $username = $username.Trim()
        $password = if ($formData["password"]) { $formData["password"] } else { "" }
        $password = $password.Trim()
        
        if ([string]::IsNullOrEmpty($username) -or [string]::IsNullOrEmpty($password)) {
            RecordFailedLogin $ClientIP
            LogActivity "LOGIN_FAILED" "Unknown" $ClientIP "Empty username or password" "FAILED"
            $html = BuildLoginPage "Invalid credentials"
            SendHtml $Response $html $null
            return
        }
        
        $authSuccess = $false
        $isAdmin = $false
        $userDisplayName = ""
        
        # Check admin hardcoded credentials
        if ($username -eq "HH0010520" -and $password -eq "nkg@12345.") {
            $authSuccess = $true
            $isAdmin = $true
            $userDisplayName = "Administrator"
            ClearFailedLogins $ClientIP
            LogActivity "LOGIN" $username $ClientIP "Admin login successful" "SUCCESS"
        }
        # Check authorized domain user
        elseif (IsUserAuthorized $username) {
            if (AuthenticateWithDomain $username $password) {
                $authSuccess = $true
                $isAdmin = $false
                
                [System.Threading.Monitor]::Enter($Global:AuthorizedUsers)
                try {
                    if ($Global:AuthorizedUsers.ContainsKey($username.ToUpper())) {
                        $userDisplayName = $Global:AuthorizedUsers[$username.ToUpper()].name
                    } else {
                        $userDisplayName = $username
                    }
                } finally {
                    [System.Threading.Monitor]::Exit($Global:AuthorizedUsers)
                }
                
                ClearFailedLogins $ClientIP
                LogActivity "LOGIN" $username $ClientIP "Domain user login successful" "SUCCESS"
            } else {
                RecordFailedLogin $ClientIP
                LogActivity "LOGIN_FAILED" $username $ClientIP "Invalid domain credentials" "FAILED"
                $html = BuildLoginPage "Invalid credentials"
                SendHtml $Response $html $null
                return
            }
        } else {
            RecordFailedLogin $ClientIP
            LogActivity "LOGIN_FAILED" $username $ClientIP "Unauthorized user attempted login" "FAILED"
            $html = BuildLoginPage "Invalid credentials"
            SendHtml $Response $html $null
            return
        }
        
        if (-not $authSuccess) {
            RecordFailedLogin $ClientIP
            LogActivity "LOGIN_FAILED" $username $ClientIP "Authentication failed" "FAILED"
            $html = BuildLoginPage "Invalid credentials"
            SendHtml $Response $html $null
            return
        }
        
        $sessionId = CreateSession $username $userDisplayName $isAdmin $ClientIP
        $html = BuildMainPage $null $null $null $username $userDisplayName $isAdmin
        SendHtml $Response $html $sessionId
    } catch {
        RecordFailedLogin $ClientIP
        LogActivity "LOGIN_ERROR" "Unknown" $ClientIP "Request parsing error: $_" "ERROR"
        $html = BuildLoginPage "Request error"
        SendHtml $Response $html $null
    }
}

function HandleLapsQuery {
    param(
        [System.Net.HttpListenerRequest]$Request,
        [System.Net.HttpListenerResponse]$Response,
        [string]$SessionId,
        [string]$ClientIP
    )
    
    try {
        $body = $null
        if ($Request.ContentLength64 -gt 0) {
            $reader = New-Object System.IO.StreamReader($Request.InputStream, $Request.ContentEncoding)
            $body = $reader.ReadToEnd()
            $reader.Close()
        }
        
        $formData = ParseFormData $body
        $hostname = if ($formData["hostname"]) { $formData["hostname"] } else { "" }
        $hostname = $hostname.Trim()
        
        $username = GetSessionUser $SessionId
        $userDisplayName = GetSessionUserName $SessionId
        $isAdmin = IsSessionAdmin $SessionId
        
        if ([string]::IsNullOrEmpty($hostname)) {
            LogActivity "LAPS_QUERY_FAILED" $username $ClientIP "Empty hostname" "FAILED" $hostname
            $html = BuildMainPage "Hostname is required" "error" $null $username $userDisplayName $isAdmin
            SendHtml $Response $html $SessionId
            return
        }
        
        if ($hostname.Length -gt 63 -or $hostname -notmatch "^[a-zA-Z0-9\-\.]+$") {
            LogActivity "LAPS_QUERY_FAILED" $username $ClientIP "Invalid hostname format: $hostname" "FAILED" $hostname
            $html = BuildMainPage "Invalid hostname format" "error" $null $username $userDisplayName $isAdmin
            SendHtml $Response $html $SessionId
            return
        }
        
        try {
            $result = Get-LapsADPassword -Identity $hostname -AsPlainText -ErrorAction Stop
            
            $computerName = if ($result.ComputerName) { $result.ComputerName } else { $hostname }
            $password = $result.Password
            $expiration = $result.ExpirationTimestamp
            
            if ([string]::IsNullOrEmpty($password)) {
                LogActivity "LAPS_QUERY_FAILED" $username $ClientIP "No password returned for: $hostname" "FAILED" $hostname
                $html = BuildMainPage "No LAPS password retrieved. Verify LAPS deployment." "error" $hostname $username $userDisplayName $isAdmin
                SendHtml $Response $html $SessionId
                return
            }
            
            LogActivity "LAPS_QUERY_SUCCESS" $username $ClientIP "Password retrieved for: $computerName" "SUCCESS" $computerName
            
            $expiryDisplay = "N/A"
            if (-not [string]::IsNullOrEmpty($expiration)) {
                try {
                    $dt = [DateTime]::Parse($expiration)
                    $daysRemaining = ($dt - (Get-Date)).TotalDays
                    
                    if ($daysRemaining -lt 1) {
                        $colorClass = "expiry-critical"
                    } elseif ($daysRemaining -lt 7) {
                        $colorClass = "expiry-warning"
                    } else {
                        $colorClass = "expiry-ok"
                    }
                    
                    $expiryDisplay = "<span class='$colorClass'>$($dt.ToString('yyyy-MM-dd HH:mm')) ($([Math]::Round($daysRemaining, 1)) days)</span>"
                } catch {
                    $expiryDisplay = SafeHtmlEncode $expiration
                }
            }
            
            $html = BuildResultPage $computerName $password $expiryDisplay $username $userDisplayName $isAdmin
            SendHtml $Response $html $SessionId
        } catch {
            $errorMsg = "LAPS query failed"
            if ($_.Exception.Message -match "NotFound|Cannot find") {
                $errorMsg = "Computer not found or LAPS not configured"
            } elseif ($_.Exception.Message -match "permission|access") {
                $errorMsg = "Permission denied. Verify your AD/LAPS permissions."
            } else {
                $errorMsg = "Error: $($_.Exception.Message)"
            }
            
            LogActivity "LAPS_QUERY_FAILED" $username $ClientIP "Query error for $hostname : $($_.Exception.Message)" "FAILED" $hostname
            $html = BuildMainPage $errorMsg "error" $hostname $username $userDisplayName $isAdmin
            SendHtml $Response $html $SessionId
        }
    } catch {
        $username = GetSessionUser $SessionId
        $userDisplayName = GetSessionUserName $SessionId
        $isAdmin = IsSessionAdmin $SessionId
        
        LogActivity "LAPS_QUERY_ERROR" $username $ClientIP "Exception: $_" "ERROR" ""
        $html = BuildMainPage "An error occurred during query" "error" "" $username $userDisplayName $isAdmin
        SendHtml $Response $html $SessionId
    }
}

function HandleAddUser {
    param(
        [System.Net.HttpListenerRequest]$Request,
        [System.Net.HttpListenerResponse]$Response,
        [string]$SessionId,
        [string]$ClientIP
    )
    
    try {
        $body = $null
        if ($Request.ContentLength64 -gt 0) {
            $reader = New-Object System.IO.StreamReader($Request.InputStream, $Request.ContentEncoding)
            $body = $reader.ReadToEnd()
            $reader.Close()
        }
        
        $formData = ParseFormData $body
        $newUsername = if ($formData["new_username"]) { $formData["new_username"] } else { "" }
        $newUsername = $newUsername.Trim().ToUpper()
        $newUserDisplayName = if ($formData["new_user_name"]) { $formData["new_user_name"] } else { "" }
        $newUserDisplayName = $newUserDisplayName.Trim()
        
        $admin = GetSessionUser $SessionId
        
        if ([string]::IsNullOrEmpty($newUsername)) {
            LogActivity "ADD_USER_FAILED" $admin $ClientIP "Empty username" "FAILED"
            $json = @{ success = $false; message = "Username required" } | ConvertTo-Json
            SendJson $Response $json
            return
        }
        
        if ([string]::IsNullOrEmpty($newUserDisplayName)) {
            LogActivity "ADD_USER_FAILED" $admin $ClientIP "Empty user name" "FAILED"
            $json = @{ success = $false; message = "User name required" } | ConvertTo-Json
            SendJson $Response $json
            return
        }
        
        if ($newUsername.Length -gt 20 -or $newUsername -notmatch "^[a-zA-Z0-9\-\.]+$") {
            LogActivity "ADD_USER_FAILED" $admin $ClientIP "Invalid username format: $newUsername" "FAILED"
            $json = @{ success = $false; message = "Invalid username format" } | ConvertTo-Json
            SendJson $Response $json
            return
        }
        
        [System.Threading.Monitor]::Enter($Global:AuthorizedUsers)
        try {
            if ($Global:AuthorizedUsers.ContainsKey($newUsername)) {
                LogActivity "ADD_USER_FAILED" $admin $ClientIP "User already exists: $newUsername" "FAILED"
                $json = @{ success = $false; message = "User already authorized" } | ConvertTo-Json
                SendJson $Response $json
                return
            }
            
            $Global:AuthorizedUsers[$newUsername] = @{
                username   = $newUsername
                name       = $newUserDisplayName
                authorized = $true
                addedBy    = $admin
                addedDate  = Get-Date
            }
        } finally {
            [System.Threading.Monitor]::Exit($Global:AuthorizedUsers)
        }
        
        SaveAuthorizedUsersToFile
        LogActivity "ADD_USER" $admin $ClientIP "Added user: $newUsername" "SUCCESS"
        $json = @{ success = $true; message = "User $newUsername added successfully" } | ConvertTo-Json
        SendJson $Response $json
    } catch {
        $admin = GetSessionUser $SessionId
        LogActivity "ADD_USER_ERROR" $admin $ClientIP "Exception: $_" "ERROR"
        $json = @{ success = $false; message = "An error occurred" } | ConvertTo-Json
        SendJson $Response $json
    }
}

function HandleEditUser {
    param(
        [System.Net.HttpListenerRequest]$Request,
        [System.Net.HttpListenerResponse]$Response,
        [string]$SessionId,
        [string]$ClientIP
    )
    
    try {
        $body = $null
        if ($Request.ContentLength64 -gt 0) {
            $reader = New-Object System.IO.StreamReader($Request.InputStream, $Request.ContentEncoding)
            $body = $reader.ReadToEnd()
            $reader.Close()
        }
        
        $formData = ParseFormData $body
        $username = if ($formData["username"]) { $formData["username"] } else { "" }
        $username = $username.Trim().ToUpper()
        $displayName = if ($formData["display_name"]) { $formData["display_name"] } else { "" }
        $displayName = $displayName.Trim()
        
        $admin = GetSessionUser $SessionId
        
        if ([string]::IsNullOrEmpty($username)) {
            LogActivity "EDIT_USER_FAILED" $admin $ClientIP "Empty username" "FAILED"
            $json = @{ success = $false; message = "Username required" } | ConvertTo-Json
            SendJson $Response $json
            return
        }
        
        if ([string]::IsNullOrEmpty($displayName)) {
            LogActivity "EDIT_USER_FAILED" $admin $ClientIP "Empty display name" "FAILED"
            $json = @{ success = $false; message = "Display name required" } | ConvertTo-Json
            SendJson $Response $json
            return
        }
        
        if ($username -eq "ADMIN") {
            LogActivity "EDIT_USER_FAILED" $admin $ClientIP "Attempted to edit ADMIN user" "FAILED"
            $json = @{ success = $false; message = "Cannot edit ADMIN user" } | ConvertTo-Json
            SendJson $Response $json
            return
        }
        
        [System.Threading.Monitor]::Enter($Global:AuthorizedUsers)
        try {
            if (-not $Global:AuthorizedUsers.ContainsKey($username)) {
                LogActivity "EDIT_USER_FAILED" $admin $ClientIP "User not found: $username" "FAILED"
                $json = @{ success = $false; message = "User not found" } | ConvertTo-Json
                SendJson $Response $json
                return
            }
            
            $Global:AuthorizedUsers[$username].name = $displayName
        } finally {
            [System.Threading.Monitor]::Exit($Global:AuthorizedUsers)
        }
        
        SaveAuthorizedUsersToFile
        LogActivity "EDIT_USER" $admin $ClientIP "Updated user: $username to display name: $displayName" "SUCCESS"
        $json = @{ success = $true; message = "User $username updated successfully" } | ConvertTo-Json
        SendJson $Response $json
    } catch {
        $admin = GetSessionUser $SessionId
        LogActivity "EDIT_USER_ERROR" $admin $ClientIP "Exception: $_" "ERROR"
        $json = @{ success = $false; message = "An error occurred" } | ConvertTo-Json
        SendJson $Response $json
    }
}

function HandleRemoveUser {
    param(
        [System.Net.HttpListenerRequest]$Request,
        [System.Net.HttpListenerResponse]$Response,
        [string]$SessionId,
        [string]$ClientIP
    )
    
    try {
        $body = $null
        if ($Request.ContentLength64 -gt 0) {
            $reader = New-Object System.IO.StreamReader($Request.InputStream, $Request.ContentEncoding)
            $body = $reader.ReadToEnd()
            $reader.Close()
        }
        
        $formData = ParseFormData $body
        $username = if ($formData["username"]) { $formData["username"] } else { "" }
        $username = $username.Trim().ToUpper()
        $admin = GetSessionUser $SessionId
        
        if ($username -eq "ADMIN") {
            LogActivity "REMOVE_USER_FAILED" $admin $ClientIP "Attempted to remove ADMIN" "FAILED"
            $json = @{ success = $false; message = "Cannot remove ADMIN user" } | ConvertTo-Json
            SendJson $Response $json
            return
        }
        
        [System.Threading.Monitor]::Enter($Global:AuthorizedUsers)
        try {
            if ($Global:AuthorizedUsers.ContainsKey($username)) {
                $Global:AuthorizedUsers.Remove($username)
                SaveAuthorizedUsersToFile
                LogActivity "REMOVE_USER" $admin $ClientIP "Removed user: $username" "SUCCESS"
                $json = @{ success = $true; message = "User $username removed successfully" } | ConvertTo-Json
                SendJson $Response $json
            } else {
                LogActivity "REMOVE_USER_FAILED" $admin $ClientIP "User not found: $username" "FAILED"
                $json = @{ success = $false; message = "User not found" } | ConvertTo-Json
                SendJson $Response $json
            }
        } finally {
            [System.Threading.Monitor]::Exit($Global:AuthorizedUsers)
        }
    } catch {
        $admin = GetSessionUser $SessionId
        LogActivity "REMOVE_USER_ERROR" $admin $ClientIP "Exception: $_" "ERROR"
        $json = @{ success = $false; message = "An error occurred" } | ConvertTo-Json
        SendJson $Response $json
    }
}

function HandleGetUsers {
    param([System.Net.HttpListenerResponse]$Response)
    
    try {
        $users = @()
        [System.Threading.Monitor]::Enter($Global:AuthorizedUsers)
        try {
            foreach ($kvp in $Global:AuthorizedUsers.GetEnumerator()) {
                $users += @{
                    username = $kvp.Value.username
                    name     = $kvp.Value.name
                }
            }
        } finally {
            [System.Threading.Monitor]::Exit($Global:AuthorizedUsers)
        }
        
        $json = @{ users = $users } | ConvertTo-Json
        SendJson $Response $json
    } catch {
        $json = @{ users = @() } | ConvertTo-Json
        SendJson $Response $json
    }
}

# ==================== RESPONSE FUNCTIONS ====================
function SendHtml {
    param(
        [System.Net.HttpListenerResponse]$Response,
        [string]$Html,
        [string]$SessionId
    )
    
    try {
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($Html)
        $Response.ContentType = "text/html; charset=utf-8"
        $Response.ContentLength64 = $buffer.Length
        
        if (-not [string]::IsNullOrEmpty($SessionId)) {
            $cookie = New-Object System.Net.Cookie("LAPS_SESSION", $SessionId)
            $cookie.Path = "/"
            $cookie.HttpOnly = $true
            $cookie.Secure = $false
            $Response.SetCookie($cookie)
        }
        
        $Response.OutputStream.Write($buffer, 0, $buffer.Length)
        $Response.OutputStream.Close()
    } catch {
        try { $Response.Close() } catch { }
    }
}

function SendJson {
    param(
        [System.Net.HttpListenerResponse]$Response,
        [string]$Json
    )
    
    try {
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($Json)
        $Response.ContentType = "application/json; charset=utf-8"
        $Response.ContentLength64 = $buffer.Length
        $Response.OutputStream.Write($buffer, 0, $buffer.Length)
        $Response.OutputStream.Close()
    } catch {
        try { $Response.Close() } catch { }
    }
}

# ==================== MULTI-THREADED REQUEST PROCESSING ====================
# This function runs inside its own runspace (worker thread) for every
# incoming HTTP request, so multiple users querying LAPS passwords at the
# same time are handled in parallel instead of waiting in a single queue.
# All shared state (sessions, authorized users, login attempts, locks) is
# injected into each runspace as the SAME object references, so the
# existing Monitor-based locking inside the helper functions above keeps
# everything thread-safe exactly as it did before.
function ProcessRequestContext {
    param([System.Net.HttpListenerContext]$Context)

    $req = $Context.Request
    $res = $Context.Response

    $path = $req.Url.AbsolutePath.ToLower()
    $method = $req.HttpMethod
    $sessionId = GetSessionCookie $req
    $clientIp = $req.RemoteEndPoint.Address.ToString()

    try {
        if ($method -eq "GET" -and ($path -eq "/" -or $path -eq "/index.html")) {
            if ([string]::IsNullOrEmpty($sessionId) -or -not (IsSessionValid $sessionId)) {
                LogActivity "PAGE_ACCESS" "Anonymous" $clientIp "Accessed login page" "INFO"
                $html = BuildLoginPage $null
                SendHtml $res $html $null
            } else {
                $html = BuildMainPage $null $null $null (GetSessionUser $sessionId) (GetSessionUserName $sessionId) (IsSessionAdmin $sessionId)
                SendHtml $res $html $sessionId
            }
        }
        elseif ($method -eq "POST" -and $path -eq "/login") {
            HandleLogin $req $res $clientIp
        }
        elseif ($method -eq "GET" -and $path -eq "/logout-page") {
            $user = GetSessionUser $sessionId
            LogActivity "LOGOUT" $user $clientIp "User logged out" "SUCCESS"
            [System.Threading.Monitor]::Enter($Global:SessionLock)
            try {
                if (-not [string]::IsNullOrEmpty($sessionId) -and $Global:SessionData.ContainsKey($sessionId)) {
                    $Global:SessionData.Remove($sessionId)
                }
            } finally {
                [System.Threading.Monitor]::Exit($Global:SessionLock)
            }
            $html = BuildLoginPage "Logged out successfully"
            SendHtml $res $html $null
        }
        elseif ($method -eq "POST" -and $path -eq "/get-laps") {
            if (-not (IsSessionValid $sessionId)) {
                $res.StatusCode = 401
                SendJson $res '{"error":"Unauthorized"}'
                return
            }
            HandleLapsQuery $req $res $sessionId $clientIp
        }
        elseif ($method -eq "GET" -and $path -eq "/admin") {
            if (-not (IsSessionValid $sessionId) -or -not (IsSessionAdmin $sessionId)) {
                $res.StatusCode = 403
                $html = BuildLoginPage "Access denied"
                SendHtml $res $html $null
                return
            }
            $html = BuildAdminPage $null (GetSessionUser $sessionId) (GetSessionUserName $sessionId)
            SendHtml $res $html $sessionId
        }
        elseif ($method -eq "POST" -and $path -eq "/admin/add-user") {
            if (-not (IsSessionValid $sessionId) -or -not (IsSessionAdmin $sessionId)) {
                $res.StatusCode = 403
                SendJson $res '{"error":"Unauthorized"}'
                return
            }
            HandleAddUser $req $res $sessionId $clientIp
        }
        elseif ($method -eq "POST" -and $path -eq "/admin/edit-user") {
            if (-not (IsSessionValid $sessionId) -or -not (IsSessionAdmin $sessionId)) {
                $res.StatusCode = 403
                SendJson $res '{"error":"Unauthorized"}'
                return
            }
            HandleEditUser $req $res $sessionId $clientIp
        }
        elseif ($method -eq "POST" -and $path -eq "/admin/remove-user") {
            if (-not (IsSessionValid $sessionId) -or -not (IsSessionAdmin $sessionId)) {
                $res.StatusCode = 403
                SendJson $res '{"error":"Unauthorized"}'
                return
            }
            HandleRemoveUser $req $res $sessionId $clientIp
        }
        elseif ($method -eq "GET" -and $path -eq "/admin/get-users") {
            if (-not (IsSessionValid $sessionId) -or -not (IsSessionAdmin $sessionId)) {
                $res.StatusCode = 403
                SendJson $res '{"error":"Unauthorized"}'
                return
            }
            HandleGetUsers $res
        }
        else {
            $res.StatusCode = 404
            $html = "<h1>404 Not Found</h1>"
            SendHtml $res $html $null
        }
    } catch {
        try {
            $res.StatusCode = 500
            $errorHtml = "<h1>Server Error</h1><pre>$(SafeHtmlEncode $_)</pre>"
            SendHtml $res $errorHtml $null
        } catch {
            # Silent fail
        }
    } finally {
        try {
            $res.Close()
        } catch {
            # Silent fail
        }
    }
}

# ==================== HTTP SERVER ====================
Write-Host "Starting HTTP Server on $ListenIP`:$Port..." -ForegroundColor Cyan

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://$ListenIP`:$Port/")

try {
    $listener.Start()
    Write-Host "[OK] Server listening on http://$ListenIP`:$Port/" -ForegroundColor Green
} catch {
    Write-Host "[FAIL] Cannot bind to $ListenIP`:$Port" -ForegroundColor Red
    Write-Host "Error: $_" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# ==================== RUNSPACE POOL SETUP (MULTI-THREADING) ====================
Write-Host "Initializing multi-threaded request engine..." -ForegroundColor Cyan

# Names of every function the worker runspaces are allowed to call. Anything
# not listed here will NOT be visible inside a worker thread.
$WorkerFunctionNames = @(
    'LoadAuthorizedUsersFromFile','SaveAuthorizedUsersToFile',
    'CreateSession','IsSessionValid','GetSessionUser','GetSessionUserName','IsSessionAdmin',
    'IsIPLocked','RecordFailedLogin','ClearFailedLogins',
    'LogActivity','IsUserAuthorized','AuthenticateWithDomain',
    'SafeHtmlEncode','ParseFormData','ParseCookies','GetSessionCookie',
    'BuildLoginPage','BuildMainPage','BuildResultPage','BuildAdminPage','GetPageTemplate',
    'HandleLogin','HandleLapsQuery','HandleAddUser','HandleEditUser','HandleRemoveUser','HandleGetUsers',
    'SendHtml','SendJson','ProcessRequestContext'
)

$InitialSessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()

# Make sure the LAPS module is loaded automatically inside every worker runspace
$InitialSessionState.ImportPSModule(@('LAPS')) | Out-Null

foreach ($fnName in $WorkerFunctionNames) {
    $cmdInfo = Get-Command -Name $fnName -CommandType Function -ErrorAction Stop
    $fnEntry = New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry($fnName, $cmdInfo.ScriptBlock)
    $InitialSessionState.Commands.Add($fnEntry)
}

# Shared state pushed into every worker runspace by REFERENCE. Because these
# are the exact same .NET objects (hashtables / lock objects) used by the
# main thread, the existing [System.Threading.Monitor] locks inside the
# functions above continue to correctly serialize access across ALL threads.
$WorkerSharedVariables = @{
    SessionData             = $Global:SessionData
    AuthorizedUsers         = $Global:AuthorizedUsers
    LoginAttempts           = $Global:LoginAttempts
    SessionLock             = $Global:SessionLock
    LoginLock               = $Global:LoginLock
    LogLock                 = $Global:LogLock
    MAX_LOGIN_ATTEMPTS      = $MAX_LOGIN_ATTEMPTS
    LOCKOUT_MINUTES         = $LOCKOUT_MINUTES
    SESSION_TIMEOUT_MINUTES = $SESSION_TIMEOUT_MINUTES
    BaseLogPath             = $BaseLogPath
    LogPath                 = $LogPath
    UserDetailsPath         = $UserDetailsPath
    PortalStatusPath        = $PortalStatusPath
}
foreach ($varName in $WorkerSharedVariables.Keys) {
    $varEntry = New-Object System.Management.Automation.Runspaces.SessionStateVariableEntry($varName, $WorkerSharedVariables[$varName], "Shared portal state")
    $InitialSessionState.Variables.Add($varEntry)
}

$Global:RunspacePool = [runspacefactory]::CreateRunspacePool($MinConcurrentRequests, $Global:MaxConcurrentRequests, $InitialSessionState, $Host)
$Global:RunspacePool.ThreadOptions = [System.Management.Automation.Runspaces.PSThreadOptions]::ReuseThread
$Global:RunspacePool.Open()

# Tracks in-flight worker PowerShell instances so they can be cleaned up
# (EndInvoke + Dispose) once each request finishes, without ever blocking
# the accept loop below.
$Global:ActiveWorkers = [System.Collections.Generic.List[hashtable]]::new()
$Global:WorkersLock = [System.Object]::new()

function DispatchRequest {
    param([System.Net.HttpListenerContext]$Context)

    $worker = [powershell]::Create()
    $worker.RunspacePool = $Global:RunspacePool
    [void]$worker.AddCommand('ProcessRequestContext').AddArgument($Context)
    $handle = $worker.BeginInvoke()

    [System.Threading.Monitor]::Enter($Global:WorkersLock)
    try {
        $Global:ActiveWorkers.Add(@{ Worker = $worker; Handle = $handle })
    } finally {
        [System.Threading.Monitor]::Exit($Global:WorkersLock)
    }
}

function CleanupFinishedWorkers {
    [System.Threading.Monitor]::Enter($Global:WorkersLock)
    try {
        for ($i = $Global:ActiveWorkers.Count - 1; $i -ge 0; $i--) {
            $item = $Global:ActiveWorkers[$i]
            if ($item.Handle.IsCompleted) {
                try {
                    $item.Worker.EndInvoke($item.Handle)
                } catch {
                    Write-Host "[WORKER_ERROR] $_" -ForegroundColor Red
                } finally {
                    $item.Worker.Dispose()
                }
                $Global:ActiveWorkers.RemoveAt($i)
            }
        }
    } finally {
        [System.Threading.Monitor]::Exit($Global:WorkersLock)
    }
}

Write-Host "[OK] Multi-threading engine ready ($MinConcurrentRequests-$($Global:MaxConcurrentRequests) concurrent workers)" -ForegroundColor Green

# Graceful shutdown
$null = Register-ObjectEvent -InputObject ([System.Console]) -EventName "CancelKeyPress" -Action {
    Write-Host "`n[SHUTDOWN] Stopping server..." -ForegroundColor Yellow
    try {
        $listener.Stop()
        $listener.Close()
    } catch { }
    try {
        if ($Global:RunspacePool) {
            $Global:RunspacePool.Close()
            $Global:RunspacePool.Dispose()
        }
    } catch { }
    Start-Sleep -Seconds 1
    Write-Host "[SHUTDOWN] Server stopped successfully" -ForegroundColor Cyan
    exit 0
}

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Add-Content -Path (Join-Path $PortalStatusPath "Portal_Status_$(Get-Date -Format 'yyyy-MM-dd').log") -Value "[$timestamp] [SERVER_START] Portal service started on $ServerUrl" -Encoding UTF8 -ErrorAction SilentlyContinue

try {
    Write-Host "`n" -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host "                LAPS Web Portal Server" -ForegroundColor Green
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host "" -ForegroundColor Cyan
    Write-Host "URL:                http://$ListenIP`:$Port/" -ForegroundColor White
    Write-Host "DNS:                $DNSName" -ForegroundColor White
    Write-Host "Admin Login:        HH0010520 / nkg@12345." -ForegroundColor Yellow
    Write-Host "Activity Logs:      $LogPath" -ForegroundColor Cyan
    Write-Host "User Details:       $UserDetailsPath" -ForegroundColor Cyan
    Write-Host "Portal Status:      $PortalStatusPath" -ForegroundColor Cyan
    Write-Host "Brute Protection:   5 attempts = 15 min lockout" -ForegroundColor Magenta
    Write-Host "Multi-Threading:    Enabled ($MinConcurrentRequests-$($Global:MaxConcurrentRequests) concurrent workers)" -ForegroundColor Magenta
    Write-Host "" -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host "  Press Ctrl+C to stop" -ForegroundColor Gray
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host "`n" -ForegroundColor Cyan
    
    # Open browser
    Write-Host "Opening portal in browser..." -ForegroundColor Cyan
    Start-Process "chrome.exe" -ArgumentList "$ServerUrl" -ErrorAction SilentlyContinue
    
    Write-Host "Portal is live! Check your browser." -ForegroundColor Green
    Write-Host "=========================== LIVE ACTIVITY LOG ===========================" -ForegroundColor Yellow
    
    # Main accept loop.
    # GetContext() blocks only until the NEXT request arrives - as soon as
    # one is accepted it is immediately handed off to a background runspace
    # via DispatchRequest, and this loop goes right back to accepting the
    # next connection. That is what gives true concurrent processing: many
    # users can query LAPS passwords at the same time and each gets served
    # by its own worker thread instead of waiting behind the others.
    while ($listener.IsListening) {
        try {
            $context = $listener.GetContext()
            DispatchRequest $context
            CleanupFinishedWorkers
        } catch [System.Net.HttpListenerException] {
            # Server stopped
            break
        } catch {
            Write-Host "[REQUEST_ERROR] $_" -ForegroundColor Red
        }
    }

} catch {
    Write-Host "`n[FAIL] Server failed: $_" -ForegroundColor Red
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path (Join-Path $PortalStatusPath "Portal_Status_$(Get-Date -Format 'yyyy-MM-dd').log") -Value "[$timestamp] [SERVER_ERROR] Server failed: $_" -Encoding UTF8 -ErrorAction SilentlyContinue
    Read-Host "Press Enter to exit"
    exit 1
} finally {
    try {
        if ($listener) {
            $listener.Stop()
            $listener.Close()
        }
    } catch { }
    try {
        if ($Global:RunspacePool) {
            $Global:RunspacePool.Close()
            $Global:RunspacePool.Dispose()
        }
    } catch { }
    Write-Host "[SHUTDOWN] Portal service stopped" -ForegroundColor Cyan
    Start-Sleep -Seconds 2
}
} # <-- end of $Global:PortalServerScriptBlock (embedded original portal script)

if ($RunServer) {
    # We were relaunched by the GUI to actually run the portal server.
    & $Global:PortalServerScriptBlock
    return
}

# ======================================================================
# GUI WRAPPER — LAPS HOST MANAGER
# ======================================================================
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
[System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false)

# ---------------------------------------------------------------
# 1. SETTINGS (persisted per-user; only Hostname/Port are read by the
#    embedded server via environment variables at launch time)
# ---------------------------------------------------------------
$ConfigDir  = "D:\LAPS_WEB_PORTAL\Configuration"
$ConfigFile = Join-Path $ConfigDir "settings.json"
if (-not (Test-Path $ConfigDir)) { New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null }

# ---- Paste your logo's Base64 string between the quotes below ----
# (leave empty to show a text-only title bar / login header)
$Global:LogoBase64 = "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"

function Load-Settings {
    $defaults = [ordered]@{
        Hostname = "10.209.110.220"
        Port     = 8080
    }
    if (Test-Path $ConfigFile) {
        try {
            $loaded = Get-Content $ConfigFile -Raw | ConvertFrom-Json
            if ($loaded.Hostname) { $defaults.Hostname = $loaded.Hostname }
            if ($loaded.Port)     { $defaults.Port     = [int]$loaded.Port }
        } catch { }
    }
    return $defaults
}

function Save-Settings($settings) {
    $settings | ConvertTo-Json | Set-Content -Path $ConfigFile -Encoding UTF8
}

$Global:Settings = Load-Settings

function Get-ServerUrl {
    return "http://$($Global:Settings.Hostname):$($Global:Settings.Port)/"
}

function Get-LogoImage {
    if ($Global:LogoBase64 -and $Global:LogoBase64.Trim().Length -gt 0) {
        try {
            $bytes = [Convert]::FromBase64String($Global:LogoBase64)
            $ms = New-Object System.IO.MemoryStream(,$bytes)
            return [System.Drawing.Image]::FromStream($ms)
        } catch { return $null }
    }
    return $null
}

# ---------------------------------------------------------------
# 2. LOGIN CREDENTIALS
# ---------------------------------------------------------------
$Global:ValidUser = "HH0010520"
$Global:ValidPass = "Foxconn-FXCN-IT"

# ---------------------------------------------------------------
# 3. SELF-RELAUNCH HELPER (works both as a .ps1 and after ps2exe)
# ---------------------------------------------------------------
function Get-SelfLaunchInfo {
    $currentExePath = [System.Diagnostics.Process]::GetCurrentProcess().Path
    $hostName = [System.IO.Path]::GetFileNameWithoutExtension($currentExePath)

    if ($hostName -match '^(powershell|pwsh)$') {
        # Still running as a plain .ps1 under the normal PowerShell host.
        # Wrapped with *>&1 so Write-Host / Write-Output / errors all merge
        # onto stdout, which we redirect and stream into the Live Log panel.
        $scriptFile = $PSCommandPath
        if (-not $scriptFile) { $scriptFile = $MyInvocation.MyCommand.Path }
        $escaped = $scriptFile.Replace("'", "''")
        return @{
            FileName  = $currentExePath
            Arguments = "-NoProfile -ExecutionPolicy Bypass -Command `"& '$escaped' -RunServer *>&1`""
        }
    } else {
        # Already running as a compiled .exe (e.g. via ps2exe) — relaunch the same exe
        return @{
            FileName  = $currentExePath
            Arguments = "-RunServer"
        }
    }
}

# ---------------------------------------------------------------
# 4. PROCESS CONTROL + LIVE LOG STREAMING
# ---------------------------------------------------------------
$Global:ServerProcess = $null
$Global:LogEventSubs  = @()
$Global:UI_LogBox     = $null

function Test-ServerRunning {
    if ($null -eq $Global:ServerProcess) { return $false }
    try { return -not $Global:ServerProcess.HasExited } catch { return $false }
}

function Write-LiveLog {
    param([string]$Line)
    if (-not $Line) { return }
    if ($Global:UI_LogBox -and $Global:UI_LogBox.IsHandleCreated) {
        try {
            $Global:UI_LogBox.Invoke([Action]{
                $stamp = Get-Date -Format "HH:mm:ss"
                $Global:UI_LogBox.AppendText("[$stamp] $Line`r`n")
                $Global:UI_LogBox.SelectionStart = $Global:UI_LogBox.TextLength
                $Global:UI_LogBox.ScrollToCaret()
            })
        } catch { }
    }
}

function Clear-EventSubs {
    foreach ($sub in $Global:LogEventSubs) {
        try { Unregister-Event -SourceIdentifier $sub.Name -ErrorAction SilentlyContinue } catch { }
        try { Remove-Job -Name $sub.Name -Force -ErrorAction SilentlyContinue } catch { }
    }
    $Global:LogEventSubs = @()
}

function Start-Portal {
    if (Test-ServerRunning) {
        Write-LiveLog "Start requested, but the portal is already running."
        return
    }
    try {
        $launch = Get-SelfLaunchInfo
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName  = $launch.FileName
        $psi.Arguments = $launch.Arguments
        $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
        $psi.CreateNoWindow = $true
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError  = $true
        $psi.EnvironmentVariables["LAPS_LISTEN_IP"] = $Global:Settings.Hostname
        $psi.EnvironmentVariables["LAPS_PORT"] = "$($Global:Settings.Port)"
        $psi.EnvironmentVariables["LAPS_LOGO_BASE64"] = $Global:LogoBase64

        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo = $psi
        $proc.EnableRaisingEvents = $true

        $outSub = Register-ObjectEvent -InputObject $proc -EventName OutputDataReceived -Action {
            if ($EventArgs.Data) { Write-LiveLog $EventArgs.Data }
        }
        $errSub = Register-ObjectEvent -InputObject $proc -EventName ErrorDataReceived -Action {
            if ($EventArgs.Data) { Write-LiveLog $EventArgs.Data }
        }
        $Global:LogEventSubs = @($outSub, $errSub)

        [void]$proc.Start()
        $proc.BeginOutputReadLine()
        $proc.BeginErrorReadLine()
        $Global:ServerProcess = $proc

        Write-LiveLog "Portal starting (PID $($proc.Id)) — $(Get-ServerUrl)"
        Update-StatusDisplay
    } catch {
        Write-LiveLog "FAILED to start portal: $_"
        [System.Windows.Forms.MessageBox]::Show("Failed to start portal:`n$_", "LAPS Host Manager", "OK", "Error") | Out-Null
    }
}

function Stop-Portal {
    if (-not (Test-ServerRunning)) {
        Write-LiveLog "Stop requested, but the portal is not running."
        return
    }
    try {
        Stop-Process -Id $Global:ServerProcess.Id -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 300
        Write-LiveLog "Portal stopped."
        $Global:ServerProcess = $null
        Clear-EventSubs
        Update-StatusDisplay
    } catch {
        Write-LiveLog "FAILED to stop portal: $_"
        [System.Windows.Forms.MessageBox]::Show("Failed to stop portal:`n$_", "LAPS Host Manager", "OK", "Error") | Out-Null
    }
}

function Restart-Portal {
    Write-LiveLog "Restarting portal..."
    Stop-Portal
    Start-Sleep -Milliseconds 500
    Start-Portal
}

function Test-PortalConnection {
    $url = Get-ServerUrl
    Write-LiveLog "Testing connection to $url ..."
    try {
        $resp = Invoke-WebRequest -Uri $url -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
        Write-LiveLog "Test succeeded — HTTP $($resp.StatusCode)"
        [System.Windows.Forms.MessageBox]::Show("Success - portal responded with HTTP $($resp.StatusCode) at:`n$url", "Connection Test", "OK", "Information") | Out-Null
    } catch {
        Write-LiveLog "Test failed: $_"
        [System.Windows.Forms.MessageBox]::Show("Could not reach the portal at:`n$url`n`n$_", "Connection Test", "OK", "Warning") | Out-Null
    }
}

function Open-PortalInBrowser {
    Start-Process (Get-ServerUrl) | Out-Null
}

# ---------------------------------------------------------------
# 5. SHARED UI HELPERS
# ---------------------------------------------------------------
function New-FlatTextBox {
    param($x, $y, $w, $h, [bool]$isPassword = $false)
    $panel = New-Object System.Windows.Forms.Panel
    $panel.Location = New-Object System.Drawing.Point($x, $y)
    $panel.Size = New-Object System.Drawing.Size($w, $h)
    $panel.BackColor = [System.Drawing.Color]::FromArgb(45, 49, 58)

    $tb = New-Object System.Windows.Forms.TextBox
    $tb.BorderStyle = "None"
    $tb.BackColor = [System.Drawing.Color]::FromArgb(45, 49, 58)
    $tb.ForeColor = [System.Drawing.Color]::WhiteSmoke
    $tb.Font = New-Object System.Drawing.Font("Segoe UI", 11)
    $tb.Location = New-Object System.Drawing.Point(10, [int](($h - 20) / 2))
    $tb.Width = $w - 20
    if ($isPassword) { $tb.UseSystemPasswordChar = $true }
    $panel.Controls.Add($tb)

    $bottomBar = New-Object System.Windows.Forms.Panel
    $bottomBar.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
    $bottomBar.Size = New-Object System.Drawing.Size($w, 2)
    $bottomBar.Location = New-Object System.Drawing.Point(0, ($h - 2))
    $panel.Controls.Add($bottomBar)

    return @{ Panel = $panel; TextBox = $tb }
}

function New-PrimaryButton {
    param($text, $x, $y, $w, $h, $backColor)
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $text
    $b.Size = New-Object System.Drawing.Size($w, $h)
    $b.Location = New-Object System.Drawing.Point($x, $y)
    $b.Font = New-Object System.Drawing.Font("Segoe UI Semibold", 10)
    $b.BackColor = $backColor
    $b.ForeColor = [System.Drawing.Color]::White
    $b.FlatStyle = "Flat"
    $b.FlatAppearance.BorderSize = 0
    $b.Cursor = [System.Windows.Forms.Cursors]::Hand
    return $b
}

# ---------------------------------------------------------------
# 6. LOGIN FORM (professional dark theme)
# ---------------------------------------------------------------
function Show-LoginForm {
    $formW = 400; $formH = 480
    $loginForm = New-Object System.Windows.Forms.Form
    $loginForm.Text = "LAPS Host Manager - Login"
    $loginForm.ClientSize = New-Object System.Drawing.Size($formW, $formH)
    $loginForm.StartPosition = "CenterScreen"
    $loginForm.FormBorderStyle = "FixedDialog"
    $loginForm.MaximizeBox = $false
    $loginForm.MinimizeBox = $false
    $loginForm.BackColor = [System.Drawing.Color]::FromArgb(24, 26, 32)

    $iconImg = Get-LogoImage
    if ($iconImg) {
        $bmp = New-Object System.Drawing.Bitmap($iconImg)
        $loginForm.Icon = [System.Drawing.Icon]::FromHandle($bmp.GetHicon())
    }

    # Top accent bar
    $accentBar = New-Object System.Windows.Forms.Panel
    $accentBar.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
    $accentBar.Size = New-Object System.Drawing.Size($formW, 6)
    $accentBar.Location = New-Object System.Drawing.Point(0, 0)
    $loginForm.Controls.Add($accentBar)

    # Logo (or fallback badge)
    $logoImg = Get-LogoImage
    $picLogo = New-Object System.Windows.Forms.PictureBox
    $picLogo.Size = New-Object System.Drawing.Size(76, 76)
    $picLogo.Location = New-Object System.Drawing.Point((($formW - 76) / 2), 36)
    $picLogo.SizeMode = "Zoom"
    $picLogo.BackColor = [System.Drawing.Color]::Transparent
    if ($logoImg) {
        $picLogo.Image = $logoImg
    } else {
        $picLogo.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
        $badgeLabel = New-Object System.Windows.Forms.Label
        $badgeLabel.Text = "LH"
        $badgeLabel.Font = New-Object System.Drawing.Font("Segoe UI", 22, [System.Drawing.FontStyle]::Bold)
        $badgeLabel.ForeColor = [System.Drawing.Color]::White
        $badgeLabel.TextAlign = "MiddleCenter"
        $badgeLabel.Dock = "Fill"
        $picLogo.Controls.Add($badgeLabel)
    }
    $loginForm.Controls.Add($picLogo)

    $lblTitle = New-Object System.Windows.Forms.Label
    $lblTitle.Text = "LAPS HOST MANAGER"
    $lblTitle.Font = New-Object System.Drawing.Font("Segoe UI", 15, [System.Drawing.FontStyle]::Bold)
    $lblTitle.ForeColor = [System.Drawing.Color]::White
    $lblTitle.TextAlign = "MiddleCenter"
    $lblTitle.Size = New-Object System.Drawing.Size($formW, 30)
    $lblTitle.Location = New-Object System.Drawing.Point(0, 122)
    $loginForm.Controls.Add($lblTitle)

    $lblSubtitle = New-Object System.Windows.Forms.Label
    $lblSubtitle.Text = "Secure Local Administrator Password Solution"
    $lblSubtitle.Font = New-Object System.Drawing.Font("Segoe UI", 8.5)
    $lblSubtitle.ForeColor = [System.Drawing.Color]::FromArgb(150, 155, 165)
    $lblSubtitle.TextAlign = "MiddleCenter"
    $lblSubtitle.Size = New-Object System.Drawing.Size($formW, 18)
    $lblSubtitle.Location = New-Object System.Drawing.Point(0, 152)
    $loginForm.Controls.Add($lblSubtitle)

    $fieldW = 320; $fieldX = ($formW - $fieldW) / 2
    $labelX = $fieldX + 8

    $lblUser = New-Object System.Windows.Forms.Label
    $lblUser.Text = "LOGIN ID"
    $lblUser.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
    $lblUser.ForeColor = [System.Drawing.Color]::FromArgb(130, 135, 145)
    $lblUser.Location = New-Object System.Drawing.Point($fieldX, 190)
    $lblUser.AutoSize = $true
    $loginForm.Controls.Add($lblUser)

    $userField = New-FlatTextBox -x $fieldX -y 210 -w $fieldW -h 38
    $loginForm.Controls.Add($userField.Panel)

    $lblPass = New-Object System.Windows.Forms.Label
    $lblPass.Text = "PASSWORD"
    $lblPass.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
    $lblPass.ForeColor = [System.Drawing.Color]::FromArgb(130, 135, 145)
    $lblPass.Location = New-Object System.Drawing.Point($fieldX, 265)
    $lblPass.AutoSize = $true
    $loginForm.Controls.Add($lblPass)

    $passField = New-FlatTextBox -x $fieldX -y 285 -w $fieldW -h 38 -isPassword $true
    $loginForm.Controls.Add($passField.Panel)

    $lblError = New-Object System.Windows.Forms.Label
    $lblError.Text = ""
    $lblError.Font = New-Object System.Drawing.Font("Segoe UI", 8.5)
    $lblError.ForeColor = [System.Drawing.Color]::FromArgb(230, 90, 90)
    $lblError.Location = New-Object System.Drawing.Point($fieldX, 332)
    $lblError.Size = New-Object System.Drawing.Size($fieldW, 18)
    $lblError.TextAlign = "MiddleCenter"
    $loginForm.Controls.Add($lblError)

    $btnLogin = New-PrimaryButton -text "LOGIN" -x $fieldX -y 360 -w $fieldW -h 42 -backColor ([System.Drawing.Color]::FromArgb(0, 120, 215))
    $btnLogin.Font = New-Object System.Drawing.Font("Segoe UI Semibold", 11)
    $loginForm.Controls.Add($btnLogin)
    $loginForm.AcceptButton = $btnLogin

    $lblFooter = New-Object System.Windows.Forms.Label
    $lblFooter.Text = "© LAPS Host Manager"
    $lblFooter.Font = New-Object System.Drawing.Font("Segoe UI", 7.5)
    $lblFooter.ForeColor = [System.Drawing.Color]::FromArgb(90, 95, 105)
    $lblFooter.TextAlign = "MiddleCenter"
    $lblFooter.Size = New-Object System.Drawing.Size($formW, 16)
    $lblFooter.Location = New-Object System.Drawing.Point(0, ($formH - 40))
    $loginForm.Controls.Add($lblFooter)

    $script:LoginSucceeded = $false

    $doLogin = {
        if ($userField.TextBox.Text -eq $Global:ValidUser -and $passField.TextBox.Text -eq $Global:ValidPass) {
            $script:LoginSucceeded = $true
            $loginForm.Close()
        } else {
            $lblError.Text = "Invalid Login ID or Password"
            $passField.TextBox.Clear()
            $passField.TextBox.Focus()
        }
    }
    $btnLogin.Add_Click($doLogin)
    $passField.TextBox.Add_KeyDown({
        param($s, $e)
        if ($e.KeyCode -eq "Enter") { & $doLogin }
    })

    $loginForm.ShowDialog() | Out-Null
    return $script:LoginSucceeded
}

# ---------------------------------------------------------------
# 7. SETTINGS FORM
# ---------------------------------------------------------------
function Show-SettingsForm {
    $formW = 380
    $settingsForm = New-Object System.Windows.Forms.Form
    $settingsForm.Text = "Settings"
    $settingsForm.Size = New-Object System.Drawing.Size($formW, 260)
    $settingsForm.StartPosition = "CenterParent"
    $settingsForm.FormBorderStyle = "FixedDialog"
    $settingsForm.MaximizeBox = $false
    $settingsForm.MinimizeBox = $false
    $settingsForm.BackColor = [System.Drawing.Color]::White

    $lblHost = New-Object System.Windows.Forms.Label
    $lblHost.Text = "Hostname / IP"
    $lblHost.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $lblHost.Location = New-Object System.Drawing.Point(25, 20)
    $lblHost.AutoSize = $true
    $settingsForm.Controls.Add($lblHost)

    $txtHost = New-Object System.Windows.Forms.TextBox
    $txtHost.Location = New-Object System.Drawing.Point(25, 42)
    $txtHost.Size = New-Object System.Drawing.Size(200, 25)
    $txtHost.Text = $Global:Settings.Hostname
    $settingsForm.Controls.Add($txtHost)

    $lblPort = New-Object System.Windows.Forms.Label
    $lblPort.Text = "Port"
    $lblPort.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $lblPort.Location = New-Object System.Drawing.Point(240, 20)
    $lblPort.AutoSize = $true
    $settingsForm.Controls.Add($lblPort)

    $txtPort = New-Object System.Windows.Forms.TextBox
    $txtPort.Location = New-Object System.Drawing.Point(240, 42)
    $txtPort.Size = New-Object System.Drawing.Size(100, 25)
    $txtPort.Text = $Global:Settings.Port
    $settingsForm.Controls.Add($txtPort)

    $lblNote = New-Object System.Windows.Forms.Label
    $lblNote.Text = "Restart the portal after changing these for the new hostname/port to take effect."
    $lblNote.Location = New-Object System.Drawing.Point(25, 85)
    $lblNote.Size = New-Object System.Drawing.Size(330, 45)
    $lblNote.ForeColor = [System.Drawing.Color]::DimGray
    $settingsForm.Controls.Add($lblNote)

    $btnSave = New-PrimaryButton -text "Save" -x 165 -y 155 -w 90 -h 34 -backColor ([System.Drawing.Color]::FromArgb(0, 120, 215))
    $btnSave.DialogResult = "OK"
    $settingsForm.Controls.Add($btnSave)

    $btnCancel = New-PrimaryButton -text "Cancel" -x 265 -y 155 -w 90 -h 34 -backColor ([System.Drawing.Color]::FromArgb(120, 124, 132))
    $btnCancel.DialogResult = "Cancel"
    $settingsForm.Controls.Add($btnCancel)

    $settingsForm.AcceptButton = $btnSave
    $settingsForm.CancelButton = $btnCancel

    if ($settingsForm.ShowDialog() -eq "OK") {
        $portVal = 0
        if (-not [int]::TryParse($txtPort.Text, [ref]$portVal)) {
            [System.Windows.Forms.MessageBox]::Show("Port must be a number.", "Invalid Input", "OK", "Error") | Out-Null
            return
        }
        $Global:Settings.Hostname = $txtHost.Text
        $Global:Settings.Port     = $portVal
        Save-Settings $Global:Settings
        Write-LiveLog "Settings updated -> $($txtHost.Text):$portVal"
        [System.Windows.Forms.MessageBox]::Show("Settings saved.", "LAPS Host Manager", "OK", "Information") | Out-Null
    }
}

# ---------------------------------------------------------------
# 8. MAIN GUI FORM (professional layout + live log panel)
# ---------------------------------------------------------------
function Show-MainForm {

    $formW = 900; $formH = 640
    $mainForm = New-Object System.Windows.Forms.Form
    $mainForm.Text = "LAPS Host Manager"
    $mainForm.ClientSize = New-Object System.Drawing.Size($formW, $formH)
    $mainForm.MinimumSize = New-Object System.Drawing.Size(760, 520)
    $mainForm.StartPosition = "CenterScreen"
    $mainForm.FormBorderStyle = "Sizable"
    $mainForm.MaximizeBox = $true
    $mainForm.BackColor = [System.Drawing.Color]::FromArgb(240, 242, 245)


    # ---- Title bar panel (space reserved for logo) ----
        # ---- Title bar panel (space reserved for logo) ----
    $panelTitle = New-Object System.Windows.Forms.Panel
    $panelTitle.Size = New-Object System.Drawing.Size($formW, 72)
    $panelTitle.Location = New-Object System.Drawing.Point(0, 0)
    $panelTitle.Anchor = "Top, Left, Right"
    $panelTitle.BackColor = [System.Drawing.Color]::FromArgb(16, 40, 68)
    $mainForm.Controls.Add($panelTitle)

    $logoImg = Get-LogoImage
    
    # Apply to Main Form Icon
    if ($logoImg) {
        $bmp = New-Object System.Drawing.Bitmap($logoImg)
        $mainForm.Icon = [System.Drawing.Icon]::FromHandle($bmp.GetHicon())
    }

    $picLogoMain = New-Object System.Windows.Forms.PictureBox

    $picLogoMain.Size = New-Object System.Drawing.Size(48, 48)
    $picLogoMain.Location = New-Object System.Drawing.Point(18, 12)
    $picLogoMain.SizeMode = "Zoom"
    $picLogoMain.BackColor = [System.Drawing.Color]::Transparent
    if ($logoImg) {
        $picLogoMain.Image = $logoImg
    } else {
        $picLogoMain.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
        $badgeLabel2 = New-Object System.Windows.Forms.Label
        $badgeLabel2.Text = "LH"
        $badgeLabel2.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
        $badgeLabel2.ForeColor = [System.Drawing.Color]::White
        $badgeLabel2.TextAlign = "MiddleCenter"
        $badgeLabel2.Dock = "Fill"
        $picLogoMain.Controls.Add($badgeLabel2)
    }
    $panelTitle.Controls.Add($picLogoMain)

    $lblMainTitle = New-Object System.Windows.Forms.Label
    $lblMainTitle.Text = "LAPS HOST MANAGER"
    $lblMainTitle.Font = New-Object System.Drawing.Font("Segoe UI", 15, [System.Drawing.FontStyle]::Bold)
    $lblMainTitle.ForeColor = [System.Drawing.Color]::White
    $lblMainTitle.AutoSize = $false
    $lblMainTitle.Size = New-Object System.Drawing.Size(400, 26)
    $lblMainTitle.Location = New-Object System.Drawing.Point(78, 14)
    $lblMainTitle.TextAlign = "MiddleLeft"
    $panelTitle.Controls.Add($lblMainTitle)

    $lblMainSubtitle = New-Object System.Windows.Forms.Label
    $lblMainSubtitle.Text = "Local Administrator Password Solution — Web Portal Control"
    $lblMainSubtitle.Font = New-Object System.Drawing.Font("Segoe UI", 8.5)
    $lblMainSubtitle.ForeColor = [System.Drawing.Color]::FromArgb(160, 190, 215)
    $lblMainSubtitle.AutoSize = $false
    $lblMainSubtitle.Size = New-Object System.Drawing.Size(400, 18)
    $lblMainSubtitle.Location = New-Object System.Drawing.Point(78, 40)
    $panelTitle.Controls.Add($lblMainSubtitle)

    # ---- Status strip ----
    $panelStatus = New-Object System.Windows.Forms.Panel
    $panelStatus.Size = New-Object System.Drawing.Size($formW, 46)
    $panelStatus.Location = New-Object System.Drawing.Point(0, 72)
    $panelStatus.Anchor = "Top, Left, Right"
    $panelStatus.BackColor = [System.Drawing.Color]::White
    $mainForm.Controls.Add($panelStatus)

    $dotStatus = New-Object System.Windows.Forms.Label
    $dotStatus.Text = "●"
    $dotStatus.Font = New-Object System.Drawing.Font("Segoe UI", 14)
    $dotStatus.ForeColor = [System.Drawing.Color]::Firebrick
    $dotStatus.Location = New-Object System.Drawing.Point(20, 10)
    $dotStatus.AutoSize = $true
    $panelStatus.Controls.Add($dotStatus)

    $lblStatusValue = New-Object System.Windows.Forms.Label
    $lblStatusValue.Text = "Stopped"
    $lblStatusValue.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $lblStatusValue.ForeColor = [System.Drawing.Color]::FromArgb(60, 63, 70)
    $lblStatusValue.Location = New-Object System.Drawing.Point(42, 13)
    $lblStatusValue.AutoSize = $true
    $panelStatus.Controls.Add($lblStatusValue)

    $lblUrlValue = New-Object System.Windows.Forms.Label
    $lblUrlValue.Text = Get-ServerUrl
    $lblUrlValue.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $lblUrlValue.ForeColor = [System.Drawing.Color]::SteelBlue
    $lblUrlValue.Location = New-Object System.Drawing.Point(220, 13)
    $lblUrlValue.AutoSize = $true
    $panelStatus.Controls.Add($lblUrlValue)

    $sep1 = New-Object System.Windows.Forms.Panel
    $sep1.BackColor = [System.Drawing.Color]::FromArgb(225, 227, 230)
    $sep1.Size = New-Object System.Drawing.Size($formW, 1)
    $sep1.Location = New-Object System.Drawing.Point(0, 45)
    $sep1.Anchor = "Top, Left, Right"
    $panelStatus.Controls.Add($sep1)

    $Global:UI_StatusLabel = $lblStatusValue
    $Global:UI_UrlLabel    = $lblUrlValue
    $Global:UI_StatusDot   = $dotStatus

    # ---- Buttons row ----
    $panelButtons = New-Object System.Windows.Forms.Panel
    $panelButtons.Size = New-Object System.Drawing.Size($formW, 70)
    $panelButtons.Location = New-Object System.Drawing.Point(0, 118)
    $panelButtons.Anchor = "Top, Left, Right"
    $panelButtons.BackColor = [System.Drawing.Color]::FromArgb(240, 242, 245)
    $mainForm.Controls.Add($panelButtons)

    $btnDefs = @(
        @{ Text = "Start";    Color = [System.Drawing.Color]::FromArgb(46, 160, 67) }
        @{ Text = "Stop";     Color = [System.Drawing.Color]::FromArgb(200, 55, 55) }
        @{ Text = "Restart";  Color = [System.Drawing.Color]::FromArgb(230, 140, 30) }
        @{ Text = "Test";     Color = [System.Drawing.Color]::FromArgb(90, 96, 105) }
        @{ Text = "Open";     Color = [System.Drawing.Color]::FromArgb(0, 120, 215) }
        @{ Text = "Settings"; Color = [System.Drawing.Color]::FromArgb(105, 110, 120) }
    )
    $margin = 20; $gap = 12
    $btnCount = $btnDefs.Count
    $btnWidth = [int]((($formW - (2 * $margin) - (($btnCount - 1) * $gap))) / $btnCount)
    $buttons = @{}
    for ($i = 0; $i -lt $btnCount; $i++) {
        $bx = $margin + ($i * ($btnWidth + $gap))
        $btn = New-PrimaryButton -text $btnDefs[$i].Text -x $bx -y 10 -w $btnWidth -h 46 -backColor $btnDefs[$i].Color
        $btn.Anchor = "Top, Left"
        $panelButtons.Controls.Add($btn)
        $buttons[$btnDefs[$i].Text] = $btn
    }

    # ---- Live log panel ----
    $panelLog = New-Object System.Windows.Forms.Panel
    $panelLog.Location = New-Object System.Drawing.Point(20, 198)
    $panelLog.Size = New-Object System.Drawing.Size(($formW - 40), ($formH - 260))
    $panelLog.Anchor = "Top, Bottom, Left, Right"
    $panelLog.BackColor = [System.Drawing.Color]::FromArgb(18, 20, 24)
    $mainForm.Controls.Add($panelLog)

    $panelLogHeader = New-Object System.Windows.Forms.Panel
    $panelLogHeader.Dock = "Top"
    $panelLogHeader.Height = 34
    $panelLogHeader.BackColor = [System.Drawing.Color]::FromArgb(28, 31, 38)
    $panelLog.Controls.Add($panelLogHeader)

    $lblLogTitle = New-Object System.Windows.Forms.Label
    $lblLogTitle.Text = "LIVE ACTIVITY LOG"
    $lblLogTitle.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $lblLogTitle.ForeColor = [System.Drawing.Color]::FromArgb(150, 200, 255)
    $lblLogTitle.Location = New-Object System.Drawing.Point(12, 8)
    $lblLogTitle.AutoSize = $true
    $panelLogHeader.Controls.Add($lblLogTitle)

    $btnClearLog = New-Object System.Windows.Forms.Button
    $btnClearLog.Text = "Clear"
    $btnClearLog.Size = New-Object System.Drawing.Size(70, 24)
    $btnClearLog.Location = New-Object System.Drawing.Point(($formW - 40 - 82), 5)
    $btnClearLog.Anchor = "Top, Right"
    $btnClearLog.FlatStyle = "Flat"
    $btnClearLog.FlatAppearance.BorderSize = 0
    $btnClearLog.BackColor = [System.Drawing.Color]::FromArgb(45, 49, 58)
    $btnClearLog.ForeColor = [System.Drawing.Color]::Gainsboro
    $btnClearLog.Font = New-Object System.Drawing.Font("Segoe UI", 8.5)
    $panelLogHeader.Controls.Add($btnClearLog)

    $txtLog = New-Object System.Windows.Forms.RichTextBox
    $txtLog.Dock = "Fill"
    $txtLog.BackColor = [System.Drawing.Color]::FromArgb(18, 20, 24)
    $txtLog.ForeColor = [System.Drawing.Color]::FromArgb(210, 215, 220)
    $txtLog.Font = New-Object System.Drawing.Font("Consolas", 9.5)
    $txtLog.BorderStyle = "None"
    $txtLog.ReadOnly = $true
    $txtLog.WordWrap = $true
    $panelLog.Controls.Add($txtLog)
    $txtLog.BringToFront()

    $Global:UI_LogBox = $txtLog
    $btnClearLog.Add_Click({ $txtLog.Clear() })

    Write-LiveLog "LAPS Host Manager ready. Click Start to launch the portal."

    # ---- Status refresh ----
    function Update-StatusDisplay {
        if (Test-ServerRunning) {
            $Global:UI_StatusLabel.Text = "Running (PID $($Global:ServerProcess.Id))"
            $Global:UI_StatusLabel.ForeColor = [System.Drawing.Color]::FromArgb(46, 140, 60)
            $Global:UI_StatusDot.ForeColor = [System.Drawing.Color]::FromArgb(46, 160, 67)
        } else {
            $Global:UI_StatusLabel.Text = "Stopped"
            $Global:UI_StatusLabel.ForeColor = [System.Drawing.Color]::FromArgb(60, 63, 70)
            $Global:UI_StatusDot.ForeColor = [System.Drawing.Color]::Firebrick
        }
        $Global:UI_UrlLabel.Text = Get-ServerUrl
    }

    $buttons["Start"].Add_Click({ Start-Portal; Update-StatusDisplay })
    $buttons["Stop"].Add_Click({ Stop-Portal; Update-StatusDisplay })
    $buttons["Restart"].Add_Click({ Restart-Portal; Update-StatusDisplay })
    $buttons["Test"].Add_Click({ Test-PortalConnection })
    $buttons["Open"].Add_Click({ Open-PortalInBrowser })
    $buttons["Settings"].Add_Click({ Show-SettingsForm; Update-StatusDisplay })

    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 3000
    $timer.Add_Tick({ Update-StatusDisplay })
    $timer.Start()

    # ---- System tray icon ----
        # ---- System tray icon ----
    $trayIcon = New-Object System.Windows.Forms.NotifyIcon
    $trayIcon.Text = "LAPS Host Manager"
    
    if ($iconImg) {
        $trayIcon.Icon = [System.Drawing.Icon]::FromHandle($bmp.GetHicon())
    } else {
        $trayIcon.Icon = [System.Drawing.SystemIcons]::Shield
    }
    
    $trayIcon.Visible = $true


    $trayMenu = New-Object System.Windows.Forms.ContextMenuStrip
    $miShow = $trayMenu.Items.Add("Show")
    $miStart = $trayMenu.Items.Add("Start")
    $miStop = $trayMenu.Items.Add("Stop")
    $miRestart = $trayMenu.Items.Add("Restart")
    $miOpen = $trayMenu.Items.Add("Open Portal")
    $trayMenu.Items.Add("-") | Out-Null
    $miExit = $trayMenu.Items.Add("Exit")
    $trayIcon.ContextMenuStrip = $trayMenu

    $miShow.Add_Click({ $mainForm.Show(); $mainForm.WindowState = "Normal"; $mainForm.Activate() })
    $miStart.Add_Click({ Start-Portal; Update-StatusDisplay })
    $miStop.Add_Click({ Stop-Portal; Update-StatusDisplay })
    $miRestart.Add_Click({ Restart-Portal; Update-StatusDisplay })
    $miOpen.Add_Click({ Open-PortalInBrowser })
        $miExit.Add_Click({
        $trayIcon.Visible = $false
        
        if ($null -ne $Global:ServerProcess) {
            Stop-Process -Id $Global:ServerProcess.Id -Force -ErrorAction SilentlyContinue
        }
        
        [Environment]::Exit(0)
    })

    $trayIcon.Add_DoubleClick({ $mainForm.Show(); $mainForm.WindowState = "Normal"; $mainForm.Activate() })

    $mainForm.Add_Resize({
        if ($mainForm.WindowState -eq "Minimized") {
            $mainForm.Hide()
            $trayIcon.ShowBalloonTip(1500, "LAPS Host Manager", "Running in the background.", "Info")
        }
    })

        $mainForm.Add_FormClosing({
        param($s, $e)
        
        # 1. Hide the tray icon immediately
        $trayIcon.Visible = $false
        
        # 2. Hard-kill the background web server process if it exists
        if ($null -ne $Global:ServerProcess) {
            Stop-Process -Id $Global:ServerProcess.Id -Force -ErrorAction SilentlyContinue
        }
        
        # 3. Forcefully terminate the entire PowerShell process and all threads
        [Environment]::Exit(0)
    })


    Update-StatusDisplay
    [System.Windows.Forms.Application]::Run($mainForm)
    $trayIcon.Visible = $false
    $trayIcon.Dispose()
}

# ---------------------------------------------------------------
# 9. ENTRY POINT (GUI mode)
# ---------------------------------------------------------------
if (Show-LoginForm) {
    Show-MainForm
}
