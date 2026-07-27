#requires -Modules LAPS
#requires -Version 5.1

[CmdletBinding()]
param()

# ==================== CONFIGURATION ====================
$ListenIP   = "10.209.110.220"
$Port       = 8080
$ServerUrl  = "http://" + $ListenIP + ":" + $Port + "/"
$DNSName    = "LAPS_WEB_PORTAL"

# ==================== LOGGING CONFIGURATION ====================
$BaseLogPath = "D:\LAPS_WEB_PORTAL"
$LogPath = Join-Path $BaseLogPath "Logs"
$UserDetailsPath = Join-Path $BaseLogPath "user_details"
$PortalStatusPath = Join-Path $BaseLogPath "PortalStatus"
$BulkImportPath = Join-Path $BaseLogPath "bulk_imports"

# Create necessary directories if they don't exist
foreach ($dir in @($BaseLogPath, $LogPath, $UserDetailsPath, $PortalStatusPath, $BulkImportPath)) {
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
    username   = "ADMIN"
    name       = "Administrator"
    authorized = $true
    addedBy    = "SYSTEM"
    addedDate  = Get-Date
    bulkImport = $true
}

# Load authorized users from file
function LoadAuthorizedUsersFromFile {
    try {
        $userFile = Join-Path $UserDetailsPath "authorized_users.json"
        if (Test-Path $userFile) {
            $content = Get-Content $userFile -Raw
            $loaded = $content | ConvertFrom-Json
            if ($loaded) {
                [System.Threading.Monitor]::Enter($Global:AuthorizedUsers)
                try {
                    $Global:AuthorizedUsers.Clear()
                    $loaded.PSObject.Properties | ForEach-Object {
                        $bulkImportFlag = if ($_.Value.bulkImport) { $_.Value.bulkImport } else { $false }
                        $Global:AuthorizedUsers[$_.Name] = @{
                            username   = $_.Value.username
                            name       = $_.Value.name
                            authorized = $_.Value.authorized
                            addedBy    = $_.Value.addedBy
                            addedDate  = $_.Value.addedDate
                            bulkImport = $bulkImportFlag
                        }
                    }
                } finally {
                    [System.Threading.Monitor]::Exit($Global:AuthorizedUsers)
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
            $json = $Global:AuthorizedUsers | ConvertTo-Json
            Set-Content -Path $userFile -Value $json -Encoding UTF8 -Force
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
}

function IsSessionValid {
    param([string]$SessionId)
    
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
}

function GetSessionUser {
    param([string]$SessionId)
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
}

function GetSessionUserName {
    param([string]$SessionId)
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
}

function IsSessionAdmin {
    param([string]$SessionId)
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
}

# ==================== LOGIN PROTECTION ====================
function IsIPLocked {
    param([string]$IPAddress)
    
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
}

function RecordFailedLogin {
    param([string]$IPAddress)
    
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
}

function ClearFailedLogins {
    param([string]$IPAddress)
    
    [System.Threading.Monitor]::Enter($Global:LoginLock)
    try {
        if ($Global:LoginAttempts.ContainsKey($IPAddress)) {
            $Global:LoginAttempts.Remove($IPAddress)
        }
    } finally {
        [System.Threading.Monitor]::Exit($Global:LoginLock)
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
    
    [System.Threading.Monitor]::Enter($Global:AuthorizedUsers)
    try {
        return $Global:AuthorizedUsers.ContainsKey($Username.ToUpper())
    } finally {
        [System.Threading.Monitor]::Exit($Global:AuthorizedUsers)
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

function HasBulkImportPrivilege {
    param([string]$Username)
    
    [System.Threading.Monitor]::Enter($Global:AuthorizedUsers)
    try {
        $upperUser = $Username.ToUpper()
        if ($Global:AuthorizedUsers.ContainsKey($upperUser)) {
            return $Global:AuthorizedUsers[$upperUser].bulkImport
        }
        return $false
    } finally {
        [System.Threading.Monitor]::Exit($Global:AuthorizedUsers)
    }
}

# ==================== UTILITY FUNCTIONS ====================
function SafeHtmlEncode {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    return $Text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;'
}

function ParseFormData {
    param([string]$Body)
    
    $result = @{}
    if ([string]::IsNullOrEmpty($Body)) { return $result }
    
    try {
        $pairs = $Body -split '&'
        foreach ($pair in $pairs) {
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
    if ([string]::IsNullOrEmpty($CookieHeader)) { return $result }
    
    $cookies = $CookieHeader -split '; '
    foreach ($cookie in $cookies) {
        $parts = $cookie -split '=', 2
        if ($parts.Count -eq 2) {
            $result[$parts[0].Trim()] = $parts[1].Trim()
        }
    }
    
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
        [bool]$IsAdmin,
        [bool]$HasBulkPrivilege
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
    $bulkButton = if ($HasBulkPrivilege) { "<button type='button' class='btn btn-secondary btn-small' onclick='showBulkImportModal()'>Bulk Import</button>" } else { "" }
    
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
                    $bulkButton
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

<!-- Bulk Import Modal -->
<div id='bulkImportModal' class='modal'>
    <div class='modal-content'>
        <span class='close' onclick='closeBulkImportModal()'>&times;</span>
        <h2>Bulk Import / Export</h2>
        <div class='bulk-actions'>
            <button type='button' class='btn btn-primary btn-small' onclick='downloadTemplate()'>Download Template</button>
            <button type='button' class='btn btn-primary btn-small' onclick='document.getElementById(\"fileInput\").click()'>Import CSV/XLSX</button>
            <button type='button' class='btn btn-secondary btn-small' onclick='exportResults()'>Export Results</button>
        </div>
        <input type='file' id='fileInput' accept='.csv,.xlsx' style='display:none;' onchange='handleFileUpload(event)'>
        <div id='bulkStatus' style='margin-top:20px; min-height:100px; padding:10px; background:#f9fafb; border-radius:8px; display:none;'>
            <p id='bulkStatusText'></p>
            <div id='bulkResults' style='margin-top:10px;'></div>
        </div>
    </div>
</div>

<script>
var bulkResults = [];

function showBulkImportModal() {
    document.getElementById('bulkImportModal').style.display = 'block';
}

function closeBulkImportModal() {
    document.getElementById('bulkImportModal').style.display = 'none';
    document.getElementById('bulkStatus').style.display = 'none';
}

function downloadTemplate() {
    var csv = 'Hostname\n';
    var blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    var link = document.createElement('a');
    var url = URL.createObjectURL(blob);
    link.setAttribute('href', url);
    link.setAttribute('download', 'LAPS_Template.csv');
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

function handleFileUpload(event) {
    var file = event.target.files[0];
    if (!file) return;
    
    var reader = new FileReader();
    reader.onload = function(e) {
        var content = e.target.result;
        var lines = content.split('\n');
        var hostnames = [];
        
        for (var i = 1; i < lines.length; i++) {
            var line = lines[i].trim();
            if (line) {
                hostnames.push(line.toUpperCase());
            }
        }
        
        bulkResults = [];
        document.getElementById('bulkStatus').style.display = 'block';
        document.getElementById('bulkStatusText').innerHTML = 'Processing ' + hostnames.length + ' hostnames...';
        
        processBulkHostnames(hostnames, 0);
    };
    reader.readAsText(file);
}

function processBulkHostnames(hostnames, index) {
    if (index >= hostnames.length) {
        document.getElementById('bulkStatusText').innerHTML = 'Processing complete! ' + bulkResults.length + ' passwords retrieved.';
        displayBulkResults();
        return;
    }
    
    var hostname = hostnames[index];
    
    fetch('/get-laps', {
        method: 'POST',
        body: 'hostname=' + encodeURIComponent(hostname)
    })
    .then(function(r) { return r.text(); })
    .then(function(html) {
        if (html.includes('Password Retrieved')) {
            bulkResults.push({
                hostname: hostname,
                status: 'Success',
                retrieved: true
            });
        } else {
            bulkResults.push({
                hostname: hostname,
                status: 'Failed',
                retrieved: false
            });
        }
        document.getElementById('bulkStatusText').innerHTML = 'Processing ' + (index + 1) + ' of ' + hostnames.length + '...';
        setTimeout(function() { processBulkHostnames(hostnames, index + 1); }, 500);
    })
    .catch(function(err) {
        bulkResults.push({
            hostname: hostname,
            status: 'Error: ' + err,
            retrieved: false
        });
        setTimeout(function() { processBulkHostnames(hostnames, index + 1); }, 500);
    });
}

function displayBulkResults() {
    var html = '<table style="width:100%; border-collapse:collapse;"><tr style="background:#e0e0e0;"><th style="border:1px solid #ccc; padding:8px;">Hostname</th><th style="border:1px solid #ccc; padding:8px;">Status</th></tr>';
    
    bulkResults.forEach(function(result) {
        var rowColor = result.retrieved ? '#dcfce7' : '#fee2e2';
        html += '<tr style="background:' + rowColor + ';">';
        html += '<td style="border:1px solid #ccc; padding:8px;">' + result.hostname + '</td>';
        html += '<td style="border:1px solid #ccc; padding:8px;">' + result.status + '</td>';
        html += '</tr>';
    });
    
    html += '</table>';
    document.getElementById('bulkResults').innerHTML = html;
}

function exportResults() {
    if (bulkResults.length === 0) {
        alert('No results to export. Please import and process hostnames first.');
        return;
    }
    
    var csv = 'Hostname,Status\n';
    bulkResults.forEach(function(result) {
        csv += result.hostname + ',' + result.status + '\n';
    });
    
    var blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    var link = document.createElement('a');
    var url = URL.createObjectURL(blob);
    link.setAttribute('href', url);
    link.setAttribute('download', 'LAPS_Results_' + new Date().getTime() + '.csv');
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

window.onclick = function(event) {
    var modal = document.getElementById('bulkImportModal');
    if (event.target == modal) {
        modal.style.display = 'none';
    }
}

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
        [bool]$IsAdmin,
        [bool]$HasBulkPrivilege
    )
    
    $adminLink = if ($IsAdmin) { "<a href='/admin' class='btn btn-secondary' style='margin: 0 6px;'>Settings</a>" } else { "" }
    $bulkButton = if ($HasBulkPrivilege) { "<button type='button' class='btn btn-secondary' style='margin: 0 6px;' onclick='showBulkImportModal()'>Bulk Import</button>" } else { "" }
    
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
        $bulkButton
    </div>
</div>

<!-- Bulk Import Modal (same as in BuildMainPage) -->
<div id='bulkImportModal' class='modal'>
    <div class='modal-content'>
        <span class='close' onclick='closeBulkImportModal()'>&times;</span>
        <h2>Bulk Import / Export</h2>
        <div class='bulk-actions'>
            <button type='button' class='btn btn-primary btn-small' onclick='downloadTemplate()'>Download Template</button>
            <button type='button' class='btn btn-primary btn-small' onclick='document.getElementById(\"fileInput\").click()'>Import CSV/XLSX</button>
            <button type='button' class='btn btn-secondary btn-small' onclick='exportResults()'>Export Results</button>
        </div>
        <input type='file' id='fileInput' accept='.csv,.xlsx' style='display:none;' onchange='handleFileUpload(event)'>
        <div id='bulkStatus' style='margin-top:20px; min-height:100px; padding:10px; background:#f9fafb; border-radius:8px; display:none;'>
            <p id='bulkStatusText'></p>
            <div id='bulkResults' style='margin-top:10px;'></div>
        </div>
    </div>
</div>

<script>
var bulkResults = [];

function showBulkImportModal() {
    document.getElementById('bulkImportModal').style.display = 'block';
}

function closeBulkImportModal() {
    document.getElementById('bulkImportModal').style.display = 'none';
    document.getElementById('bulkStatus').style.display = 'none';
}

function downloadTemplate() {
    var csv = 'Hostname\n';
    var blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    var link = document.createElement('a');
    var url = URL.createObjectURL(blob);
    link.setAttribute('href', url);
    link.setAttribute('download', 'LAPS_Template.csv');
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

function handleFileUpload(event) {
    var file = event.target.files[0];
    if (!file) return;
    
    var reader = new FileReader();
    reader.onload = function(e) {
        var content = e.target.result;
        var lines = content.split('\n');
        var hostnames = [];
        
        for (var i = 1; i < lines.length; i++) {
            var line = lines[i].trim();
            if (line) {
                hostnames.push(line.toUpperCase());
            }
        }
        
        bulkResults = [];
        document.getElementById('bulkStatus').style.display = 'block';
        document.getElementById('bulkStatusText').innerHTML = 'Processing ' + hostnames.length + ' hostnames...';
        
        processBulkHostnames(hostnames, 0);
    };
    reader.readAsText(file);
}

function processBulkHostnames(hostnames, index) {
    if (index >= hostnames.length) {
        document.getElementById('bulkStatusText').innerHTML = 'Processing complete! ' + bulkResults.length + ' passwords retrieved.';
        displayBulkResults();
        return;
    }
    
    var hostname = hostnames[index];
    
    fetch('/get-laps', {
        method: 'POST',
        body: 'hostname=' + encodeURIComponent(hostname)
    })
    .then(function(r) { return r.text(); })
    .then(function(html) {
        if (html.includes('Password Retrieved')) {
            bulkResults.push({
                hostname: hostname,
                status: 'Success',
                retrieved: true
            });
        } else {
            bulkResults.push({
                hostname: hostname,
                status: 'Failed',
                retrieved: false
            });
        }
        document.getElementById('bulkStatusText').innerHTML = 'Processing ' + (index + 1) + ' of ' + hostnames.length + '...';
        setTimeout(function() { processBulkHostnames(hostnames, index + 1); }, 500);
    })
    .catch(function(err) {
        bulkResults.push({
            hostname: hostname,
            status: 'Error: ' + err,
            retrieved: false
        });
        setTimeout(function() { processBulkHostnames(hostnames, index + 1); }, 500);
    });
}

function displayBulkResults() {
    var html = '<table style="width:100%; border-collapse:collapse;"><tr style="background:#e0e0e0;"><th style="border:1px solid #ccc; padding:8px;">Hostname</th><th style="border:1px solid #ccc; padding:8px;">Status</th></tr>';
    
    bulkResults.forEach(function(result) {
        var rowColor = result.retrieved ? '#dcfce7' : '#fee2e2';
        html += '<tr style="background:' + rowColor + ';">';
        html += '<td style="border:1px solid #ccc; padding:8px;">' + result.hostname + '</td>';
        html += '<td style="border:1px solid #ccc; padding:8px;">' + result.status + '</td>';
        html += '</tr>';
    });
    
    html += '</table>';
    document.getElementById('bulkResults').innerHTML = html;
}

function exportResults() {
    if (bulkResults.length === 0) {
        alert('No results to export. Please import and process hostnames first.');
        return;
    }
    
    var csv = 'Hostname,Status\n';
    bulkResults.forEach(function(result) {
        csv += result.hostname + ',' + result.status + '\n';
    });
    
    var blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    var link = document.createElement('a');
    var url = URL.createObjectURL(blob);
    link.setAttribute('href', url);
    link.setAttribute('download', 'LAPS_Results_' + new Date().getTime() + '.csv');
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

window.onclick = function(event) {
    var modal = document.getElementById('bulkImportModal');
    if (event.target == modal) {
        modal.style.display = 'none';
    }
}

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
                <div class='form-group'>
                    <label><input type='checkbox' id='bulkImportCheck' name='bulkImport'> Enable Bulk Import/Export</label>
                    <small class='help-hint'>Allow this user to import and export bulk hostnames</small>
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
</div>

<!-- Edit User Modal -->
<div id='editUserModal' class='modal'>
    <div class='modal-content'>
        <span class='close' onclick='closeEditModal()'>&times;</span>
        <h2>Edit User</h2>
        <form id='editUserForm'>
            <div class='form-group'>
                <label for='edit_username'>Domain Username</label>
                <input type='text' id='edit_username' name='edit_username' readonly style='background:#f0f0f0;'>
            </div>
            <div class='form-group'>
                <label for='edit_user_name'>Full Name</label>
                <input type='text' id='edit_user_name' name='edit_user_name' required>
            </div>
            <div class='form-group'>
                <label><input type='checkbox' id='edit_bulkImport' name='bulkImport'> Enable Bulk Import/Export</label>
            </div>
            <button type='submit' class='btn btn-primary btn-small'>Save Changes</button>
            <button type='button' class='btn btn-secondary btn-small' onclick='closeEditModal()'>Cancel</button>
        </form>
    </div>
</div>

<script>
var allUsers = [];
var editingUser = null;

function loadUsers() {
    fetch('/admin/get-users')
        .then(function(r) { return r.json(); })
        .then(function(data) {
            allUsers = data.users || [];
            renderUsers(allUsers);
        });
}

function renderUsers(users) {
    var html = '';
    if (users && users.length > 0) {
        users.forEach(function(u) {
            var isAdmin = u.username === 'ADMIN' ? ' (Built-in)' : '';
            var bulkIcon = u.bulkImport ? ' ✓ Bulk' : '';
            var displayName = u.name || u.username;
            html += '<div class=user-item>';
            html += '<div class=user-info>';
            html += '<div class=username>' + SafeHtmlEncode(u.username) + bulkIcon + '</div>';
            html += '<div class=username-display>' + SafeHtmlEncode(displayName) + isAdmin + '</div>';
            html += '</div>';
            html += '<div class=user-actions>';
            if (u.username !== 'ADMIN') {
                html += '<button type=button class=btn class=btn-edit onclick=openEditModal("' + u.username + '","' + u.name + '",' + (u.bulkImport ? 'true' : 'false') + ')>Edit</button>';
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
    });
}

function openEditModal(username, name, bulkImport) {
    editingUser = username;
    document.getElementById('edit_username').value = username;
    document.getElementById('edit_user_name').value = name;
    document.getElementById('edit_bulkImport').checked = bulkImport;
    document.getElementById('editUserModal').style.display = 'block';
}

function closeEditModal() {
    document.getElementById('editUserModal').style.display = 'none';
    editingUser = null;
}

document.getElementById('editUserForm').addEventListener('submit', function(e) {
    e.preventDefault();
    var username = document.getElementById('edit_username').value;
    var name = document.getElementById('edit_user_name').value;
    var bulkImport = document.getElementById('edit_bulkImport').checked;
    
    fetch('/admin/edit-user', {
        method: 'POST',
        body: 'username=' + encodeURIComponent(username) + 
              '&name=' + encodeURIComponent(name) +
              '&bulkImport=' + bulkImport
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        alert(data.message);
        if (data.success) {
            loadUsers();
            closeEditModal();
            document.getElementById('searchUsers').value = '';
        }
    });
});

document.getElementById('addUserForm').addEventListener('submit', function(e) {
    e.preventDefault();
    var username = document.getElementById('new_username').value;
    var userName = document.getElementById('new_user_name').value;
    var bulkImport = document.getElementById('bulkImportCheck').checked;
    
    fetch('/admin/add-user', {
        method: 'POST',
        body: 'new_username=' + encodeURIComponent(username) + 
              '&new_user_name=' + encodeURIComponent(userName) +
              '&bulkImport=' + bulkImport
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        alert(data.message);
        if (data.success) {
            document.getElementById('new_username').value = '';
            document.getElementById('new_user_name').value = '';
            document.getElementById('bulkImportCheck').checked = false;
            loadUsers();
            document.getElementById('searchUsers').value = '';
        }
    });
});

window.onclick = function(event) {
    var modal = document.getElementById('editUserModal');
    if (event.target == modal) {
        modal.style.display = 'none';
    }
}

loadUsers();
</script>
"@
    
    return GetPageTemplate $body
}

function GetPageTemplate {
    param([string]$BodyContent)
    
    return @"
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>LAPS Password Portal</title>
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
        input[type='text'], input[type='password'] { width: 100%; padding: 12px 16px; border: 2px solid #e5e7eb; border-radius: 8px; font-size: 1rem; transition: all 0.2s; }
        input[type='text']:focus, input[type='password']:focus { outline: none; border-color: #667eea; box-shadow: 0 0 0 3px rgba(102,126,234,0.1); }
        input[type='checkbox'] { margin-right: 8px; }
        .help-hint { display: block; margin-top: 6px; font-size: 0.75rem; color: #9ca3af; font-style: italic; }
        .btn { display: inline-flex; align-items: center; justify-content: center; padding: 12px 24px; border: none; border-radius: 8px; font-size: 1rem; font-weight: 600; cursor: pointer; transition: all 0.2s; text-decoration: none; }
        .btn-primary { background: linear-gradient(90deg, #667eea 0%, #764ba2 100%); color: white; width: 100%; }
        .btn-primary:hover:not(:disabled) { transform: translateY(-1px); box-shadow: 0 8px 20px rgba(102,126,234,0.4); }
        .btn-primary:disabled { opacity: 0.7; cursor: not-allowed; }
        .btn-secondary { background: #f3f4f6; color: #374151; border: none; }
        .btn-secondary:hover { background: #e5e7eb; }
        .btn-small { padding: 6px 12px; font-size: 0.875rem; width: auto; }
        .btn-edit { padding: 6px 12px; font-size: 0.875rem; width: auto; background: #dbeafe; color: #0c4a6e; border: none; margin-right: 4px; }
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
        .actions { padding-top: 20px; border-top: 1px solid #e5e7eb; display: flex; gap: 12px; flex-wrap: wrap; }
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
        .user-actions { display: flex; gap: 4px; }
        .username { font-weight: 600; color: #374151; font-size: 0.95rem; }
        .username-display { font-size: 0.85rem; color: #6b7280; margin-top: 2px; }
        .modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.5); }
        .modal-content { background-color: white; margin: 10% auto; padding: 30px; border-radius: 12px; width: 90%; max-width: 500px; box-shadow: 0 4px 20px rgba(0,0,0,0.3); }
        .close { color: #aaa; float: right; font-size: 28px; font-weight: bold; cursor: pointer; }
        .close:hover { color: #000; }
        .bulk-actions { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 20px; }
        @media (max-width: 600px) {
            .header-top { flex-direction: column; }
            .user-section { text-align: left; }
            .button-group { justify-content: flex-start; }
            .card { max-width: 100%; }
            .user-actions { flex-wrap: wrap; }
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
        $hasBulkPrivilege = HasBulkImportPrivilege $username
        $html = BuildMainPage $null $null $null $username $userDisplayName $isAdmin $hasBulkPrivilege
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
        $hostname = $hostname.Trim().ToUpper()
        
        $username = GetSessionUser $SessionId
        $userDisplayName = GetSessionUserName $SessionId
        $isAdmin = IsSessionAdmin $SessionId
        $hasBulkPrivilege = HasBulkImportPrivilege $username
        
        if ([string]::IsNullOrEmpty($hostname)) {
            LogActivity "LAPS_QUERY_FAILED" $username $ClientIP "Empty hostname" "FAILED" $hostname
            $html = BuildMainPage "Hostname is required" "error" $null $username $userDisplayName $isAdmin $hasBulkPrivilege
            SendHtml $Response $html $SessionId
            return
        }
        
        if ($hostname.Length -gt 63 -or $hostname -notmatch "^[a-zA-Z0-9\-\.]+$") {
            LogActivity "LAPS_QUERY_FAILED" $username $ClientIP "Invalid hostname format: $hostname" "FAILED" $hostname
            $html = BuildMainPage "Invalid hostname format" "error" $null $username $userDisplayName $isAdmin $hasBulkPrivilege
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
                $html = BuildMainPage "No LAPS password retrieved. Verify LAPS deployment." "error" $hostname $username $userDisplayName $isAdmin $hasBulkPrivilege
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
            
            $html = BuildResultPage $computerName $password $expiryDisplay $username $userDisplayName $isAdmin $hasBulkPrivilege
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
            $html = BuildMainPage $errorMsg "error" $hostname $username $userDisplayName $isAdmin $hasBulkPrivilege
            SendHtml $Response $html $SessionId
        }
    } catch {
        $username = GetSessionUser $SessionId
        $userDisplayName = GetSessionUserName $SessionId
        $isAdmin = IsSessionAdmin $SessionId
        $hasBulkPrivilege = HasBulkImportPrivilege $username
        
        LogActivity "LAPS_QUERY_ERROR" $username $ClientIP "Exception: $_" "ERROR" ""
        $html = BuildMainPage "An error occurred during query" "error" "" $username $userDisplayName $isAdmin $hasBulkPrivilege
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
        $bulkImportFlag = if ($formData["bulkImport"]) { $true } else { $false }
        
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
                bulkImport = $bulkImportFlag
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
        $name = if ($formData["name"]) { $formData["name"] } else { "" }
        $name = $name.Trim()
        $bulkImportFlag = if ($formData["bulkImport"] -eq "true") { $true } else { $false }
        
        $admin = GetSessionUser $SessionId
        
        if ($username -eq "ADMIN") {
            LogActivity "EDIT_USER_FAILED" $admin $ClientIP "Attempted to edit ADMIN" "FAILED"
            $json = @{ success = $false; message = "Cannot edit ADMIN user" } | ConvertTo-Json
            SendJson $Response $json
            return
        }
        
        [System.Threading.Monitor]::Enter($Global:AuthorizedUsers)
        try {
            if ($Global:AuthorizedUsers.ContainsKey($username)) {
                $Global:AuthorizedUsers[$username].name = $name
                $Global:AuthorizedUsers[$username].bulkImport = $bulkImportFlag
            } else {
                LogActivity "EDIT_USER_FAILED" $admin $ClientIP "User not found: $username" "FAILED"
                $json = @{ success = $false; message = "User not found" } | ConvertTo-Json
                SendJson $Response $json
                return
            }
        } finally {
            [System.Threading.Monitor]::Exit($Global:AuthorizedUsers)
        }
        
        SaveAuthorizedUsersToFile
        LogActivity "EDIT_USER" $admin $ClientIP "Edited user: $username" "SUCCESS"
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
                $bulkFlag = if ($kvp.Value.bulkImport) { $true } else { $false }
                $users += @{
                    username   = $kvp.Value.username
                    name       = $kvp.Value.name
                    bulkImport = $bulkFlag
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
    } catch {
        # Silent fail
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
    } catch {
        # Silent fail
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
    exit 1
}

# Graceful shutdown
$null = Register-ObjectEvent -InputObject ([System.Console]) -EventName "CancelKeyPress" -Action {
    Write-Host "`n[SHUTDOWN] Stopping server..." -ForegroundColor Yellow
    $listener.Stop()
    $listener.Close()
    Start-Sleep -Seconds 1
    Write-Host "[SHUTDOWN] Server stopped successfully" -ForegroundColor Cyan
    exit 0
}

try {
    Write-Host "`n" -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host "                LAPS Web Portal Server" -ForegroundColor Green
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host "" -ForegroundColor Cyan
    Write-Host "URL:                http://$ListenIP`:$Port/" -ForegroundColor White
    Write-Host "DNS:                $DNSName" -ForegroundColor White
    Write-Host "Admin Login:        ADMIN / ADMIN123" -ForegroundColor Yellow
    Write-Host "Activity Logs:      $LogPath" -ForegroundColor Cyan
    Write-Host "User Details:       $UserDetailsPath" -ForegroundColor Cyan
    Write-Host "Portal Status:      $PortalStatusPath" -ForegroundColor Cyan
    Write-Host "Brute Protection:   5 attempts = 15 min lockout" -ForegroundColor Magenta
    Write-Host "" -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host "  Press Ctrl+C to stop" -ForegroundColor Gray
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host "`n" -ForegroundColor Cyan
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path (Join-Path $PortalStatusPath "Portal_Status_$(Get-Date -Format 'yyyy-MM-dd').log") -Value "[$timestamp] [SERVER_START] Portal service started on $ServerUrl" -Encoding UTF8 -ErrorAction SilentlyContinue
    
    # Open browser
    Write-Host "Opening portal in browser..." -ForegroundColor Cyan
    Start-Process "chrome.exe" -ArgumentList "$ServerUrl" -ErrorAction SilentlyContinue
    
    Write-Host "Portal is live! Check your browser." -ForegroundColor Green
    Write-Host "=========================== LIVE ACTIVITY LOG ===========================" -ForegroundColor Yellow
    
    # Main request loop
    while ($listener.IsListening) {
        try {
            $context = $listener.GetContext()
            
            $req = $context.Request
            $res = $context.Response
            
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
                        $username = GetSessionUser $sessionId
                        $hasBulkPrivilege = HasBulkImportPrivilege $username
                        $html = BuildMainPage $null $null $null $username (GetSessionUserName $sessionId) (IsSessionAdmin $sessionId) $hasBulkPrivilege
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
                        $res.Close()
                        continue
                    }
                    HandleLapsQuery $req $res $sessionId $clientIp
                }
                elseif ($method -eq "GET" -and $path -eq "/admin") {
                    if (-not (IsSessionValid $sessionId) -or -not (IsSessionAdmin $sessionId)) {
                        $res.StatusCode = 403
                        $html = BuildLoginPage "Access denied"
                        SendHtml $res $html $null
                        $res.Close()
                        continue
                    }
                    $html = BuildAdminPage $null (GetSessionUser $sessionId) (GetSessionUserName $sessionId)
                    SendHtml $res $html $sessionId
                }
                elseif ($method -eq "POST" -and $path -eq "/admin/add-user") {
                    if (-not (IsSessionValid $sessionId) -or -not (IsSessionAdmin $sessionId)) {
                        $res.StatusCode = 403
                        SendJson $res '{"error":"Unauthorized"}'
                        $res.Close()
                        continue
                    }
                    HandleAddUser $req $res $sessionId $clientIp
                }
                elseif ($method -eq "POST" -and $path -eq "/admin/edit-user") {
                    if (-not (IsSessionValid $sessionId) -or -not (IsSessionAdmin $sessionId)) {
                        $res.StatusCode = 403
                        SendJson $res '{"error":"Unauthorized"}'
                        $res.Close()
                        continue
                    }
                    HandleEditUser $req $res $sessionId $clientIp
                }
                elseif ($method -eq "POST" -and $path -eq "/admin/remove-user") {
                    if (-not (IsSessionValid $sessionId) -or -not (IsSessionAdmin $sessionId)) {
                        $res.StatusCode = 403
                        SendJson $res '{"error":"Unauthorized"}'
                        $res.Close()
                        continue
                    }
                    HandleRemoveUser $req $res $sessionId $clientIp
                }
                elseif ($method -eq "GET" -and $path -eq "/admin/get-users") {
                    if (-not (IsSessionValid $sessionId) -or -not (IsSessionAdmin $sessionId)) {
                        $res.StatusCode = 403
                        SendJson $res '{"error":"Unauthorized"}'
                        $res.Close()
                        continue
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
    exit 1
} finally {
    if ($listener) {
        $listener.Stop()
        $listener.Close()
    }
}
