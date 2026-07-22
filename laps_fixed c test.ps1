#requires -Modules LAPS
#requires -Version 5.1

[CmdletBinding()]
param()

# ==================== CONFIGURATION ====================
$ListenIP   = "10.209.110.220"
$Port       = 8080
$ServerUrl  = "http://" + $ListenIP + ":" + $Port + "/"

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

# ==================== C# WEB SERVER ====================
Write-Host "Compiling C# Web Server..." -ForegroundColor Cyan

# CRITICAL FIX: Using single-quoted C# string with explicit escaping
# to prevent PowerShell from interpreting $ variables

$CSharpCode = @'
using System;
using System.Net;
using System.Text;
using System.IO;
using System.Collections.Generic;
using System.Threading;
using System.Diagnostics;
using System.Web;

public class LapsWebServer
{
    private HttpListener listener;
    private readonly string ip;
    private readonly int port;
    private volatile bool running = true;

    public LapsWebServer(string serverIp, int serverPort)
    {
        ip = serverIp;
        port = serverPort;
    }

    public void Start()
    {
        listener = new HttpListener();
        string prefix = "http://" + ip + ":" + port.ToString() + "/";
        listener.Prefixes.Add(prefix);
        
        try
        {
            listener.Start();
            Console.WriteLine("[SERVER] Listening on " + prefix);
        }
        catch (HttpListenerException ex)
        {
            Console.WriteLine("[FATAL] Cannot bind to " + ip + ":" + port.ToString());
            Console.WriteLine("        Error: " + ex.Message);
            Console.WriteLine("");
            Console.WriteLine("=== RESOLUTION (run as Administrator once) ===");
            Console.WriteLine("  netsh http add urlacl url=http://" + ip + ":" + port.ToString() + "/ user=\"DOMAIN\\\\YourUsername\"");
            Console.WriteLine("  netsh http add urlacl url=http://+:" + port.ToString() + "/ user=\"Everyone\"");
            Console.WriteLine("");
            throw;
        }

        while (running)
        {
            try
            {
                HttpListenerContext context = listener.GetContext();
                ThreadPool.QueueUserWorkItem(new WaitCallback(ProcessRequestCallback), context);
            }
            catch (HttpListenerException) { }
            catch (ObjectDisposedException) { }
        }
    }

    public void Stop()
    {
        running = false;
        if (listener != null)
        {
            listener.Stop();
            listener.Close();
        }
    }

    private void ProcessRequestCallback(object state)
    {
        HttpListenerContext context = (HttpListenerContext)state;
        ProcessRequest(context);
    }

    private void ProcessRequest(HttpListenerContext context)
    {
        HttpListenerRequest req = context.Request;
        HttpListenerResponse res = context.Response;

        try
        {
            string path = req.Url.AbsolutePath.ToLower();
            string method = req.HttpMethod;

            if (method == "GET" && (path == "/" || path == "/index.html"))
            {
                SendHtml(res, BuildMainPage(null, null, null));
            }
            else if (method == "POST" && path == "/get-laps")
            {
                HandleLapsQuery(req, res);
            }
            else
            {
                res.StatusCode = 404;
                SendHtml(res, "<h1>404 Not Found</h1>");
            }
        }
        catch (Exception ex)
        {
            res.StatusCode = 500;
            SendHtml(res, "<h1>Server Error</h1><pre>" + SafeHtmlEncode(ex.ToString()) + "</pre>");
        }
        finally
        {
            res.Close();
        }
    }

    private void HandleLapsQuery(HttpListenerRequest req, HttpListenerResponse res)
    {
        string hostname = "";
        using (StreamReader reader = new StreamReader(req.InputStream, req.ContentEncoding))
        {
            string body = reader.ReadToEnd();
            Dictionary<string, string> formData = ParseFormData(body);
            if (formData.ContainsKey("hostname"))
            {
                hostname = formData["hostname"];
            }
        }

        hostname = (hostname ?? "").Trim();

        if (string.IsNullOrEmpty(hostname))
        {
            SendHtml(res, BuildMainPage("Hostname is required", "error", null));
            return;
        }

        if (hostname.Length > 63 || !System.Text.RegularExpressions.Regex.IsMatch(hostname, "^[a-zA-Z0-9\\-\\.]+$"))
        {
            SendHtml(res, BuildMainPage("Invalid hostname format", "error", null));
            return;
        }

        string escapedHost = hostname.Replace("'", "''");
        
        // CRITICAL FIX: Build PowerShell command with proper escaping
        // Using string concatenation to avoid any interpolation issues
        string psCommand = "-NoProfile -NonInteractive -Command \"Import-Module LAPS; try { $r = Get-LapsADPassword -Identity '" 
            + escapedHost 
            + "' -AsPlainText -ErrorAction Stop; [PSCustomObject]@{ ComputerName = $r.ComputerName; Password = $r.Password; ExpirationTimestamp = $r.ExpirationTimestamp } | ConvertTo-Json -Compress } catch { @{ Error = $_.Exception.Message; Type = $_.Exception.GetType().Name } | ConvertTo-Json -Compress }\"";

        ProcessStartInfo psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = psCommand,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = Environment.GetFolderPath(Environment.SpecialFolder.System)
        };

        string output = "";
        string error = "";
        int exitCode = 0;

        using (Process proc = new Process { StartInfo = psi })
        {
            proc.Start();
            output = proc.StandardOutput.ReadToEnd();
            error = proc.StandardError.ReadToEnd();
            proc.WaitForExit(30000);
            exitCode = proc.ExitCode;
            
            if (!proc.HasExited)
            {
                try { proc.Kill(); } catch { }
                SendHtml(res, BuildMainPage("Query timed out (30s). Check AD connectivity.", "error", hostname));
                return;
            }
        }

        if (exitCode != 0 && !string.IsNullOrEmpty(error))
        {
            string friendlyError = "LAPS query failed";
            if (error.Contains("NotFound") || error.Contains("Cannot find"))
                friendlyError = "Computer '" + hostname + "' not found or LAPS not configured";
            else if (error.Contains("permission") || error.Contains("access") || error.Contains("unauthorized"))
                friendlyError = "Permission denied. Verify your AD/LAPS read permissions.";
            else
                friendlyError = "Error: " + error.Trim();

            SendHtml(res, BuildMainPage(friendlyError, "error", hostname));
            return;
        }

        var serializer = new System.Web.Script.Serialization.JavaScriptSerializer();
        Dictionary<string, object> dict = serializer.Deserialize<Dictionary<string, object>>(output);

        if (dict.ContainsKey("Error"))
        {
            string errorMsg = dict["Error"].ToString();
            if (errorMsg.Contains("NotFound") || errorMsg.Contains("Cannot find"))
                errorMsg = "Computer '" + hostname + "' not found or LAPS not configured";
            SendHtml(res, BuildMainPage(errorMsg, "error", hostname));
            return;
        }

        string computerName = dict.ContainsKey("ComputerName") ? dict["ComputerName"]?.ToString() : null;
        string password = dict.ContainsKey("Password") ? dict["Password"]?.ToString() : null;
        string expiry = dict.ContainsKey("ExpirationTimestamp") ? dict["ExpirationTimestamp"]?.ToString() : null;

        if (string.IsNullOrEmpty(password))
        {
            SendHtml(res, BuildMainPage("No LAPS password retrieved. Verify LAPS is deployed on this computer.", "error", hostname));
            return;
        }

        string expiryDisplay = "N/A";
        if (!string.IsNullOrEmpty(expiry))
        {
            DateTime dt;
            if (DateTime.TryParse(expiry, out dt))
            {
                double daysRemaining = (dt - DateTime.Now).TotalDays;
                string colorClass = "expiry-ok";
                if (daysRemaining < 1) colorClass = "expiry-critical";
                else if (daysRemaining < 7) colorClass = "expiry-warning";
                
                expiryDisplay = "<span class='" + colorClass + "'>" + dt.ToString("yyyy-MM-dd HH:mm") + " (" + daysRemaining.ToString("F1") + " days)</span>";
            }
            else
            {
                expiryDisplay = SafeHtmlEncode(expiry);
            }
        }

        SendHtml(res, BuildResultPage(computerName ?? hostname, password, expiryDisplay));
    }

    private Dictionary<string, string> ParseFormData(string body)
    {
        Dictionary<string, string> result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrEmpty(body)) return result;

        string[] pairs = body.Split('&');
        foreach (string pair in pairs)
        {
            string[] kv = pair.Split(new char[] { '=' }, 2);
            if (kv.Length == 2)
                result[System.Web.HttpUtility.UrlDecode(kv[0])] = System.Web.HttpUtility.UrlDecode(kv[1]);
        }
        return result;
    }

    private Dictionary<string, string> ParseSimpleJson(string json)
    {
        Dictionary<string, string> result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(json)) return result;
        
        json = json.Trim();
        if (json.StartsWith("{")) json = json.Substring(1);
        if (json.EndsWith("}")) json = json.Substring(0, json.Length - 1);
        
        bool inString = false;
        bool escape = false;
        StringBuilder currentKey = new StringBuilder();
        StringBuilder currentValue = new StringBuilder();
        bool isKey = true;

        for (int i = 0; i < json.Length; i++)
        {
            char c = json[i];
            
            if (escape)
            {
                if (isKey) currentKey.Append(c);
                else currentValue.Append(c);
                escape = false;
                continue;
            }

            if (c == '\\')
            {
                escape = true;
                continue;
            }

            if (c == '"')
            {
                inString = !inString;
                continue;
            }

            if (!inString && c == ':')
            {
                isKey = false;
                continue;
            }

            if (!inString && c == ',')
            {
                result[currentKey.ToString().Trim()] = currentValue.ToString().Trim();
                currentKey.Clear();
                currentValue.Clear();
                isKey = true;
                continue;
            }

            if (isKey) currentKey.Append(c);
            else currentValue.Append(c);
        }

        if (currentKey.Length > 0)
            result[currentKey.ToString().Trim()] = currentValue.ToString().Trim();

        return result;
    }

    private void SendHtml(HttpListenerResponse res, string html)
    {
        byte[] buffer = Encoding.UTF8.GetBytes(html);
        res.ContentType = "text/html; charset=utf-8";
        res.ContentLength64 = buffer.Length;
        res.OutputStream.Write(buffer, 0, buffer.Length);
    }

    private string SafeHtmlEncode(string s)
    {
        if (string.IsNullOrEmpty(s)) return s;
        return s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");
    }

    private string SafeHtmlAttributeEncode(string s)
    {
        if (string.IsNullOrEmpty(s)) return s;
        return s.Replace("&", "&amp;").Replace("\"", "&quot;");
    }

    private string BuildMainPage(string message, string messageType, string prefillHostname)
    {
        string statusHtml = "";
        if (!string.IsNullOrEmpty(message))
        {
            statusHtml = "<div class='alert alert-" + messageType + "'>" + SafeHtmlEncode(message) + "</div>";
        }

        string hostValue = "";
        if (!string.IsNullOrEmpty(prefillHostname))
        {
            hostValue = " value='" + SafeHtmlAttributeEncode(prefillHostname) + "'";
        }

        string body = @"
<div class='card'>
    <div class='card-header'>
        <h1>&#128274; LAPS Password Retrieval</h1>
        <p>Enter computer hostname to retrieve local administrator password</p>
    </div>
    " + statusHtml + @"
    <form method='POST' action='/get-laps' id='lapsForm'>
        <div class='form-group'>
            <label for='hostname'>Computer Hostname</label>
            <input type='text' id='hostname' name='hostname' placeholder='WKSTN-IT-001.idpbgtn.com' required autofocus autocomplete='off'" + hostValue + @">
        </div>
        <button type='submit' class='btn btn-primary'>
            <span class='btn-text'>Retrieve Password</span>
            <span class='btn-loader' style='display:none;'>&#9203; Querying AD...</span>
        </button>
    </form>
    <div class='help-text'><strong>Tip:</strong> Use the full FQDN for best results. LAPS passwords expire periodically.</div>
</div>
<script>document.getElementById('lapsForm').addEventListener('submit', function(e) { var btn = this.querySelector('button'); btn.disabled = true; btn.querySelector('.btn-text').style.display = 'none'; btn.querySelector('.btn-loader').style.display = 'inline'; });</script>";
        
        return GetPageTemplate(body);
    }

    private string BuildResultPage(string computer, string password, string expiryHtml)
    {
        string body = @"
<div class='card'>
    <div class='card-header'>
        <h1>&#9989; Password Retrieved</h1>
    </div>
    <div class='result-grid'>
        <div class='result-item'>
            <span class='result-label'>Computer</span>
            <span class='result-value'>" + SafeHtmlEncode(computer) + @"</span>
        </div>
        <div class='result-item'>
            <span class='result-label'>Password</span>
            <div class='password-container'>
                <span id='pwd' class='password-blur' onclick='toggleReveal()'>" + SafeHtmlEncode(password) + @"</span>
                <button type='button' class='btn btn-small btn-secondary' onclick='copyPassword()'>&#128203; Copy</button>
            </div>
            <small class='hint'>Click password to reveal &#8226; Click again to hide</small>
        </div>
        <div class='result-item'>
            <span class='result-label'>Expiration</span>
            <span class='result-value'>" + expiryHtml + @"</span>
        </div>
    </div>
    <div class='actions'><a href='/' class='btn btn-secondary'>&#8592; Query Another</a></div>
</div>
<script>
function toggleReveal() { var el = document.getElementById('pwd'); el.classList.toggle('password-blur'); el.classList.toggle('password-clear'); }
function copyPassword() { var pwd = document.getElementById('pwd').innerText; navigator.clipboard.writeText(pwd).then(function() { var btn = event.target; var orig = btn.innerText; btn.innerText = '&#10003; Copied!'; setTimeout(function() { btn.innerText = orig; }, 2000); }); }
</script>";
        
        return GetPageTemplate(body);
    }

    private string GetPageTemplate(string bodyContent)
    {
        return @"<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>LAPS Password Portal</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
        .card { background: white; border-radius: 16px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); width: 100%; max-width: 480px; overflow: hidden; }
        .card-header { background: linear-gradient(90deg, #667eea 0%, #764ba2 100%); color: white; padding: 28px; text-align: center; }
        .card-header h1 { font-size: 1.5rem; font-weight: 600; margin-bottom: 6px; }
        .card-header p { opacity: 0.9; font-size: 0.875rem; }
        .card > *:not(.card-header) { padding: 24px 28px; }
        .alert { padding: 14px 18px; border-radius: 8px; margin-bottom: 20px; font-size: 0.875rem; line-height: 1.5; }
        .alert-error { background: #fee2e2; color: #991b1b; border: 1px solid #fecaca; }
        .form-group { margin-bottom: 20px; }
        label { display: block; font-size: 0.875rem; font-weight: 600; color: #374151; margin-bottom: 6px; }
        input[type='text'] { width: 100%; padding: 12px 16px; border: 2px solid #e5e7eb; border-radius: 8px; font-size: 1rem; transition: border-color 0.2s, box-shadow 0.2s; }
        input[type='text']:focus { outline: none; border-color: #667eea; box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1); }
        .btn { display: inline-flex; align-items: center; justify-content: center; padding: 12px 24px; border: none; border-radius: 8px; font-size: 1rem; font-weight: 600; cursor: pointer; transition: all 0.2s; text-decoration: none; width: 100%; }
        .btn-primary { background: linear-gradient(90deg, #667eea 0%, #764ba2 100%); color: white; }
        .btn-primary:hover:not(:disabled) { transform: translateY(-1px); box-shadow: 0 8px 20px rgba(102, 126, 234, 0.4); }
        .btn-primary:disabled { opacity: 0.7; cursor: not-allowed; }
        .btn-secondary { background: #f3f4f6; color: #374151; }
        .btn-secondary:hover { background: #e5e7eb; }
        .btn-small { padding: 6px 12px; font-size: 0.875rem; width: auto; }
        .help-text { margin-top: 20px; padding-top: 20px; border-top: 1px solid #e5e7eb; font-size: 0.875rem; color: #6b7280; }
        .result-grid { display: flex; flex-direction: column; gap: 20px; }
        .result-item { padding: 16px; background: #f9fafb; border-radius: 8px; }
        .result-label { display: block; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: #6b7280; margin-bottom: 8px; }
        .result-value { font-size: 1rem; color: #111827; word-break: break-all; }
        .password-container { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
        .password-blur { filter: blur(6px); user-select: none; cursor: pointer; font-family: 'Consolas', 'Monaco', monospace; font-size: 1.125rem; letter-spacing: 0.05em; transition: filter 0.2s; flex: 1; min-width: 200px; }
        .password-clear { filter: none; user-select: all; cursor: pointer; font-family: 'Consolas', 'Monaco', monospace; font-size: 1.125rem; letter-spacing: 0.05em; flex: 1; min-width: 200px; }
        .hint { display: block; margin-top: 8px; color: #9ca3af; font-size: 0.75rem; }
        .actions { padding-top: 20px; border-top: 1px solid #e5e7eb; }
        .expiry-ok { color: #166534; font-weight: 600; }
        .expiry-warning { color: #92400e; font-weight: 600; }
        .expiry-critical { color: #991b1b; font-weight: 600; animation: pulse 2s infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.6; } }
    </style>
</head>
<body>" + bodyContent + @"</body></html>";
    }
}
'@

# ==================== COMPILE & START ====================
try {
    Add-Type -TypeDefinition $CSharpCode -Language CSharp -ReferencedAssemblies "System.Web", "System.Net.Http" -ErrorAction Stop
    Write-Host "[OK] C# server compiled successfully" -ForegroundColor Green
} catch {
    Write-Host "[FAIL] Compilation failed: $($_.Exception.Message)" -ForegroundColor Red
    
    # Try without System.Net.Http reference
    try {
        Write-Host "Retrying with minimal references..." -ForegroundColor Yellow
        Add-Type -TypeDefinition $CSharpCode -Language CSharp -ReferencedAssemblies "System.Web" -ErrorAction Stop
        Write-Host "[OK] C# server compiled successfully (minimal)" -ForegroundColor Green
    } catch {
        Write-Host "[FAIL] Retry also failed: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

# Instantiate and start
$server = New-Object LapsWebServer($ListenIP, $Port)

# Handle graceful shutdown
$null = Register-ObjectEvent -InputObject ([System.Console]) -EventName "CancelKeyPress" -Action {
    Write-Host "`n[SHUTDOWN] Stopping server..." -ForegroundColor Yellow
    $server.Stop()
    exit 0
}

# Start server
try {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  LAPS Web Server Active" -ForegroundColor Green
    Write-Host "  URL: $ServerUrl" -ForegroundColor White
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "`nPress Ctrl+C to stop`n" -ForegroundColor Gray
    $server.Start()
} catch {
    Write-Host "`n[FAIL] Server failed to start: $($_.Exception.Message)" -ForegroundColor Red
    
    # Last resort: try localhost
    if ($ListenIP -ne "localhost" -and $ListenIP -ne "127.0.0.1") {
        Write-Host "`nAttempting fallback to localhost:8080..." -ForegroundColor Yellow
        Write-Host "Access via: http://localhost:8080/" -ForegroundColor Cyan
        
        $server = New-Object LapsWebServer("localhost", $Port)
        try {
            $server.Start()
        } catch {
            Write-Host "[FAIL] localhost also failed." -ForegroundColor Red
        }
    }
}
