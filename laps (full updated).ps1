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

$CSharpCode = @'
using System;
using System.Net;
using System.Text;
using System.IO;
using System.Collections.Generic;
using System.Threading;
using System.Diagnostics;
using System.Web;
using System.Web.Script.Serialization;
using System.DirectoryServices.AccountManagement;

public class LapsWebServer
{
    private HttpListener listener;
    private readonly string ip;
    private readonly int port;
    private volatile bool running = true;
    
    // Auth & Logging State
    private Dictionary<string, string> sessions = new Dictionary<string, string>();
    private List<string> authorizedUsers = new List<string>();
    private string usersFilePath = "laps_authorized_users.txt";
    private string logFilePath = "laps_audit.log";
    private string domainName = "idpbgtn.com";

    public LapsWebServer(string serverIp, int serverPort)
    {
        ip = serverIp;
        port = serverPort;
        LoadUsers();
    }

    private void LoadUsers()
    {
        authorizedUsers.Clear();
        if (File.Exists(usersFilePath))
        {
            foreach (string line in File.ReadAllLines(usersFilePath))
            {
                if (!string.IsNullOrWhiteSpace(line)) authorizedUsers.Add(line.Trim().ToLower());
            }
        }
    }

    private void SaveUsers()
    {
        File.WriteAllLines(usersFilePath, authorizedUsers.ToArray());
    }

    private void LogActivity(string user, string host, string result, string expiry)
    {
        try
        {
            string logLine = string.Format("[{0:yyyy-MM-dd HH:mm:ss}] User: {1} | Hostname: {2} | Result: {3} | Expire Date: {4}{5}", 
                DateTime.Now, user, host, result, expiry, Environment.NewLine);
            File.AppendAllText(logFilePath, logLine);
            Console.WriteLine(logLine.TrimEnd());
        }
        catch { }
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

    private string GetSessionUser(HttpListenerRequest req)
    {
        if (req.Cookies["session"] != null)
        {
            string token = req.Cookies["session"].Value;
            if (sessions.ContainsKey(token)) return sessions[token];
        }
        return null;
    }

    private void ProcessRequest(HttpListenerContext context)
    {
        HttpListenerRequest req = context.Request;
        HttpListenerResponse res = context.Response;

        try
        {
            string path = req.Url.AbsolutePath.ToLower();
            string method = req.HttpMethod;
            string currentUser = GetSessionUser(req);

            // Require login for everything except the login page itself
            if (string.IsNullOrEmpty(currentUser) && path != "/login")
            {
                res.RedirectLocation = "/login";
                res.StatusCode = 302;
                return;
            }

            if (path == "/login" && method == "GET")
            {
                SendHtml(res, BuildLoginPage(""));
            }
            else if (path == "/login" && method == "POST")
            {
                HandleLogin(req, res);
            }
            else if (path == "/logout")
            {
                if (req.Cookies["session"] != null) sessions.Remove(req.Cookies["session"].Value);
                Cookie c = new Cookie("session", "") { Expires = DateTime.Now.AddDays(-1), Path = "/" };
                res.Cookies.Add(c);
                res.RedirectLocation = "/login";
                res.StatusCode = 302;
            }
            else if (path == "/admin")
            {
                if (currentUser != "admin")
                {
                    res.RedirectLocation = "/";
                    res.StatusCode = 302;
                    return;
                }
                HandleAdminPage(req, res);
            }
            else if (method == "GET" && (path == "/" || path == "/index.html"))
            {
                SendHtml(res, BuildMainPage(null, null, null, currentUser));
            }
            else if (method == "POST" && path == "/get-laps")
            {
                HandleLapsQuery(req, res, currentUser);
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

    private void HandleLogin(HttpListenerRequest req, HttpListenerResponse res)
    {
        string body = new StreamReader(req.InputStream, req.ContentEncoding).ReadToEnd();
        var formData = ParseFormData(body);
        string username = formData.ContainsKey("username") ? formData["username"].Trim().ToLower() : "";
        string password = formData.ContainsKey("password") ? formData["password"] : "";

        if (username == "admin" && password == "admin123")
        {
            CreateSession("admin", res);
            return;
        }

        LoadUsers();
        if (!authorizedUsers.Contains(username))
        {
            SendHtml(res, BuildLoginPage("Access denied. Your Domain Emp ID is not authorized by the Admin."));
            return;
        }

        if (ValidateADUser(username, password))
        {
            CreateSession(username, res);
        }
        else
        {
            SendHtml(res, BuildLoginPage("Invalid domain credentials."));
        }
    }

    private bool ValidateADUser(string username, string password)
    {
        try
        {
            using (PrincipalContext pc = new PrincipalContext(ContextType.Domain, domainName))
            {
                return pc.ValidateCredentials(username, password);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("[AUTH ERROR] " + ex.Message);
            return false;
        }
    }

    private void CreateSession(string username, HttpListenerResponse res)
    {
        string token = Guid.NewGuid().ToString();
        sessions[token] = username;
        Cookie c = new Cookie("session", token, "/");
        res.Cookies.Add(c);
        res.RedirectLocation = "/";
        res.StatusCode = 302;
    }

    private void HandleAdminPage(HttpListenerRequest req, HttpListenerResponse res)
    {
        if (req.HttpMethod == "POST")
        {
            string body = new StreamReader(req.InputStream, req.ContentEncoding).ReadToEnd();
            var form = ParseFormData(body);
            string action = form.ContainsKey("action") ? form["action"] : "";
            string empId = form.ContainsKey("emp_id") ? form["emp_id"].Trim().ToLower() : "";

            if (!string.IsNullOrEmpty(empId))
            {
                LoadUsers();
                if (action == "add" && !authorizedUsers.Contains(empId))
                {
                    authorizedUsers.Add(empId);
                    SaveUsers();
                }
                else if (action == "remove" && authorizedUsers.Contains(empId))
                {
                    authorizedUsers.Remove(empId);
                    SaveUsers();
                }
            }
            res.RedirectLocation = "/admin";
            res.StatusCode = 302;
            return;
        }

        LoadUsers();
        StringBuilder userListHtml = new StringBuilder();
        foreach (string u in authorizedUsers)
        {
            userListHtml.AppendFormat("<li><span class='emp-id'>{0}</span> <form method='POST' style='display:inline;'><input type='hidden' name='action' value='remove'><input type='hidden' name='emp_id' value='{0}'><button class='btn btn-small btn-danger' type='submit'>Remove</button></form></li>", SafeHtmlEncode(u));
        }

        string html = @"
<div class='card admin-card'>
    <div class='card-header'>
        <h1>&#128101; Admin Portal</h1>
        <p>Manage authorized users for idpbgtn.com</p>
    </div>
    <div class='content-pad'>
        <form method='POST' class='add-user-form'>
            <input type='hidden' name='action' value='add'>
            <div class='form-group'>
                <label>Add User (Domain Emp ID)</label>
                <div style='display:flex; gap:10px;'>
                    <input type='text' name='emp_id' placeholder='e.g., emp12345' required>
                    <button type='submit' class='btn btn-primary btn-small'>Add User</button>
                </div>
            </div>
        </form>
        <hr style='margin:20px 0; border:0; border-top:1px solid #e5e7eb;' />
        <h3>Authorized Users</h3>
        <ul class='user-list'>
            " + (authorizedUsers.Count > 0 ? userListHtml.ToString() : "<li class='text-muted'>No users added yet.</li>") + @"
        </ul>
        <div class='actions' style='margin-top:20px;'><a href='/' class='btn btn-secondary'>&#8592; Back to Portal</a></div>
    </div>
</div>";
        SendHtml(res, GetPageTemplate(html, "admin"));
    }

    private void HandleLapsQuery(HttpListenerRequest req, HttpListenerResponse res, string currentUser)
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
            LogActivity(currentUser, hostname, "Failed: Empty Hostname", "N/A");
            SendHtml(res, BuildMainPage("Hostname is required", "error", null, currentUser));
            return;
        }

        if (hostname.Length > 63 || !System.Text.RegularExpressions.Regex.IsMatch(hostname, "^[a-zA-Z0-9\-\.]+$"))
        {
            LogActivity(currentUser, hostname, "Failed: Invalid Format", "N/A");
            SendHtml(res, BuildMainPage("Invalid hostname format", "error", null, currentUser));
            return;
        }

        string escapedHost = hostname.Replace("'", "''");
        
        string psCommand = "-NoProfile -NonInteractive -Command "Import-Module LAPS; try { $r = Get-LapsADPassword -Identity '" 
            + escapedHost 
            + "' -AsPlainText -ErrorAction Stop; [PSCustomObject]@{ ComputerName = $r.ComputerName; Password = $r.Password; ExpirationTimestamp = $r.ExpirationTimestamp } | ConvertTo-Json -Compress } catch { @{ Error = $_.Exception.Message; Type = $_.Exception.GetType().Name } | ConvertTo-Json -Compress }"";

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
                LogActivity(currentUser, hostname, "Failed: Query Timeout", "N/A");
                SendHtml(res, BuildMainPage("Query timed out (30s). Check AD connectivity.", "error", hostname, currentUser));
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

            LogActivity(currentUser, hostname, "Failed: " + friendlyError, "N/A");
            SendHtml(res, BuildMainPage(friendlyError, "error", hostname, currentUser));
            return;
        }

        Dictionary<string, string> dict = ParseSimpleJson(output);

        if (dict.ContainsKey("Error"))
        {
            string errorMsg = dict["Error"];
            if (errorMsg.Contains("NotFound") || errorMsg.Contains("Cannot find"))
                errorMsg = "Computer '" + hostname + "' not found or LAPS not configured";
            
            LogActivity(currentUser, hostname, "Failed: " + errorMsg, "N/A");
            SendHtml(res, BuildMainPage(errorMsg, "error", hostname, currentUser));
            return;
        }

        string password = null;
        string expiry = null;
        string computerName = null;

        dict.TryGetValue("ComputerName", out computerName);
        dict.TryGetValue("Password", out password);
        dict.TryGetValue("ExpirationTimestamp", out expiry);

        if (string.IsNullOrEmpty(password))
        {
            LogActivity(currentUser, hostname, "Failed: No Password Retrieved", "N/A");
            SendHtml(res, BuildMainPage("No LAPS password retrieved. Verify LAPS is deployed on this computer.", "error", hostname, currentUser));
            return;
        }

        string expiryDisplayHtml = "N/A";
        string logExpiryDate = "N/A";
        
        if (!string.IsNullOrEmpty(expiry))
        {
            DateTime dt;
            if (DateTime.TryParse(expiry, out dt))
            {
                logExpiryDate = dt.ToString("yyyy-MM-dd HH:mm");
                double daysRemaining = (dt - DateTime.Now).TotalDays;
                string colorClass = "expiry-ok";
                if (daysRemaining < 1) colorClass = "expiry-critical";
                else if (daysRemaining < 7) colorClass = "expiry-warning";
                
                expiryDisplayHtml = "<span class='" + colorClass + "'>" + dt.ToString("yyyy-MM-dd HH:mm") + " (" + daysRemaining.ToString("F1") + " days)</span>";
            }
            else
            {
                expiryDisplayHtml = SafeHtmlEncode(expiry);
                logExpiryDate = expiry;
            }
        }

        LogActivity(currentUser, computerName ?? hostname, "Success", logExpiryDate);
        SendHtml(res, BuildResultPage(computerName ?? hostname, password, expiryDisplayHtml, currentUser));
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
        
        try
        {
            JavaScriptSerializer serializer = new JavaScriptSerializer();
            var dict = serializer.Deserialize<Dictionary<string, object>>(json);
            if (dict != null)
            {
                foreach (var kvp in dict)
                {
                    result[kvp.Key] = kvp.Value != null ? kvp.Value.ToString() : "";
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("[DEBUG] JSON Parse Error: " + ex.Message);
        }

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
        return s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace(""", "&quot;");
    }

    private string SafeHtmlAttributeEncode(string s)
    {
        if (string.IsNullOrEmpty(s)) return s;
        return s.Replace("&", "&amp;").Replace(""", "&quot;");
    }

    private string BuildLoginPage(string errorMessage)
    {
        string statusHtml = "";
        if (!string.IsNullOrEmpty(errorMessage))
        {
            statusHtml = "<div class='alert alert-error'>" + SafeHtmlEncode(errorMessage) + "</div>";
        }

        string body = @"
<div class='card'>
    <div class='card-header'>
        <h1>&#128272; LAPS Portal Login</h1>
        <p>Login with your <b>idpbgtn.com</b> domain credentials</p>
    </div>
    <div class='content-pad'>
        " + statusHtml + @"
        <form method='POST' action='/login'>
            <div class='form-group'>
                <label>Username / Emp ID</label>
                <input type='text' name='username' required autofocus autocomplete='off'>
            </div>
            <div class='form-group'>
                <label>Password</label>
                <input type='password' name='password' required>
            </div>
            <button type='submit' class='btn btn-primary'>Login</button>
        </form>
    </div>
</div>";
        return GetPageTemplate(body, "");
    }

    private string BuildTopNav(string currentUser)
    {
        string adminLink = currentUser == "admin" ? "<a href='/admin'>Admin Panel</a> | " : "";
        return "<div class='top-nav'>Logged in as: <b>" + SafeHtmlEncode(currentUser) + "</b> | " + adminLink + "<a href='/logout'>Logout</a></div>";
    }

    private string BuildMainPage(string message, string messageType, string prefillHostname, string currentUser)
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

        string body = BuildTopNav(currentUser) + @"
<div class='card'>
    <div class='card-header'>
        <h1>&#128274; LAPS Password Retrieval</h1>
        <p>Enter computer hostname to retrieve local administrator password</p>
    </div>
    <div class='content-pad'>
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
</div>
<script>document.getElementById('lapsForm').addEventListener('submit', function(e) { var btn = this.querySelector('button'); btn.disabled = true; btn.querySelector('.btn-text').style.display = 'none'; btn.querySelector('.btn-loader').style.display = 'inline'; });</script>";
        
        return GetPageTemplate(body, currentUser);
    }

    private string BuildResultPage(string computer, string password, string expiryHtml, string currentUser)
    {
        string body = BuildTopNav(currentUser) + @"
<div class='card'>
    <div class='card-header'>
        <h1>&#9989; Password Retrieved</h1>
    </div>
    <div class='content-pad'>
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
</div>
<script>
function toggleReveal() { var el = document.getElementById('pwd'); el.classList.toggle('password-blur'); el.classList.toggle('password-clear'); }
function copyPassword() { var pwd = document.getElementById('pwd').innerText; navigator.clipboard.writeText(pwd).then(function() { var btn = event.target; var orig = btn.innerText; btn.innerText = '&#10003; Copied!'; setTimeout(function() { btn.innerText = orig; }, 2000); }); }
</script>";
        
        return GetPageTemplate(body, currentUser);
    }

    private string GetPageTemplate(string bodyContent, string pageType)
    {
        return @"<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>LAPS Password Portal</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 20px; }
        .top-nav { color: white; margin-bottom: 15px; width: 100%; max-width: 480px; text-align: right; font-size: 0.9rem; }
        .top-nav a { color: #f3f4f6; text-decoration: underline; }
        .top-nav a:hover { color: white; }
        .card { background: white; border-radius: 16px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); width: 100%; max-width: 480px; overflow: hidden; }
        .card-header { background: linear-gradient(90deg, #667eea 0%, #764ba2 100%); color: white; padding: 28px; text-align: center; }
        .card-header h1 { font-size: 1.5rem; font-weight: 600; margin-bottom: 6px; }
        .card-header p { opacity: 0.9; font-size: 0.875rem; }
        .content-pad { padding: 24px 28px; }
        .alert { padding: 14px 18px; border-radius: 8px; margin-bottom: 20px; font-size: 0.875rem; line-height: 1.5; }
        .alert-error { background: #fee2e2; color: #991b1b; border: 1px solid #fecaca; }
        .form-group { margin-bottom: 20px; }
        label { display: block; font-size: 0.875rem; font-weight: 600; color: #374151; margin-bottom: 6px; }
        input[type='text'], input[type='password'] { width: 100%; padding: 12px 16px; border: 2px solid #e5e7eb; border-radius: 8px; font-size: 1rem; transition: border-color 0.2s, box-shadow 0.2s; }
        input[type='text']:focus, input[type='password']:focus { outline: none; border-color: #667eea; box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1); }
        .btn { display: inline-flex; align-items: center; justify-content: center; padding: 12px 24px; border: none; border-radius: 8px; font-size: 1rem; font-weight: 600; cursor: pointer; transition: all 0.2s; text-decoration: none; width: 100%; }
        .btn-primary { background: linear-gradient(90deg, #667eea 0%, #764ba2 100%); color: white; }
        .btn-primary:hover:not(:disabled) { transform: translateY(-1px); box-shadow: 0 8px 20px rgba(102, 126, 234, 0.4); }
        .btn-primary:disabled { opacity: 0.7; cursor: not-allowed; }
        .btn-secondary { background: #f3f4f6; color: #374151; }
        .btn-secondary:hover { background: #e5e7eb; }
        .btn-danger { background: #fee2e2; color: #991b1b; }
        .btn-danger:hover { background: #fecaca; }
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
        .user-list { list-style: none; padding: 0; max-height: 250px; overflow-y: auto; }
        .user-list li { display: flex; justify-content: space-between; align-items: center; padding: 10px; border-bottom: 1px solid #eee; }
        .user-list li:last-child { border-bottom: none; }
        .emp-id { font-family: monospace; font-size: 1.1rem; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.6; } }
    </style>
</head>
<body>" + bodyContent + @"</body></html>";
    }
}
'@

# ==================== COMPILE & START ====================
try {
    # Added System.DirectoryServices.AccountManagement for AD Auth
    Add-Type -TypeDefinition $CSharpCode -Language CSharp -ReferencedAssemblies "System.Web", "System.Net.Http", "System", "System.Web.Extensions", "System.DirectoryServices.AccountManagement" -ErrorAction Stop
    Write-Host "[OK] C# server compiled successfully" -ForegroundColor Green
} catch {
    Write-Host "[FAIL] Compilation failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
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
}
