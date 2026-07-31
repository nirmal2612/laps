# === CREATE ENCRYPTED STANDALONE EXE ===

# 1. Settings
$original = "C:\Users\HH0010520\Desktop\LAPS\LAPS_Host_Manager.ps1"
$outputEXE = "C:\Users\HH0010520\Desktop\LAPS\LAPS_Host_Manager.exe"
$password = "26122001@nG"  # Change this!

# 2. Read and encrypt script
$script = Get-Content $original -Raw
$bytes = [System.Text.Encoding]::UTF8.GetBytes($script)

# AES encryption
$salt = [byte[]](1..16)
$kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($password, $salt, 10000)
$key = $kdf.GetBytes(32)
$iv = $kdf.GetBytes(16)

$aes = [System.Security.Cryptography.Aes]::Create()
$aes.Key = $key
$aes.IV = $iv
$encryptor = $aes.CreateEncryptor()
$encrypted = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length)

# Combine: salt + iv + ciphertext
$payload = $salt + $iv + $encrypted
$base64 = [System.Convert]::ToBase64String($payload)

# 3. Create launcher script with EMBEDDED encrypted data
$launcher = @"
`$encryptedData = '$base64'
`$password = '$password'

try {
    `$payload = [System.Convert]::FromBase64String(`$encryptedData)
    `$salt = `$payload[0..15]
    `$iv = `$payload[16..31]
    `$cipher = `$payload[32..(`$payload.Length-1)]
    
    `$kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(`$password, `$salt, 10000)
    `$key = `$kdf.GetBytes(32)
    
    `$aes = [System.Security.Cryptography.Aes]::Create()
    `$aes.Key = `$key
    `$aes.IV = `$iv
    `$decryptor = `$aes.CreateDecryptor()
    `$decrypted = `$decryptor.TransformFinalBlock(`$cipher, 0, `$cipher.Length)
    `$script = [System.Text.Encoding]::UTF8.GetString(`$decrypted)

    # IMPORTANT: Invoke-Expression runs text in the current scope and does
    # NOT bind command-line arguments to a param() block inside that text.
    # This script relies on -RunServer being passed through to its own
    # param([switch]`$RunServer) so it knows whether to run as the GUI or
    # as the headless background server. Turning the decrypted text into
    # a real scriptblock and invoking it with the launcher's own $args
    # forwarded (@args) makes parameter binding work exactly like running
    # the .ps1 file directly with -RunServer.
    #
    # IMPORTANT #2: this MUST be dot-sourced ( . $sb ), not called ( & $sb ).
    # The call operator (&) runs the scriptblock in a new CHILD scope, so
    # every function defined inside it (Write-LiveLog, Start-Portal, etc.)
    # only exists in that nested scope. That breaks Register-ObjectEvent's
    # -Action blocks used for streaming the server's output into the Live
    # Activity Log: those blocks execute later, in a separate event-
    # subscriber pipeline that only has access to true GLOBAL scope, not
    # the caller's lexical scope. If Write-LiveLog isn't global, those
    # -Action blocks fail silently and the Live Activity Log stops
    # updating after the first couple of lines. Dot-sourcing merges the
    # scriptblock's scope into the caller's scope (global, here), which
    # keeps parameter binding with @args working exactly the same while
    # fixing the log streaming.
    `$sb = [ScriptBlock]::Create(`$script)
    . `$sb @args

} catch {
    [System.Windows.MessageBox]::Show("Error: `$_", "PC Audit Tool", "OK", "Error")
}
"@

# 4. Save temporary launcher
$tempLauncher = "C:\Users\hh0010520\Desktop\launcher_temp.ps1"
$launcher | Set-Content $tempLauncher -Encoding UTF8

# 5. Convert to EXE
try {
    Import-Module ps2exe -ErrorAction Stop
} catch {
    Install-Module ps2exe -Force -Scope CurrentUser
    Import-Module ps2exe
}

$iconPath = "C:\Users\HH0010520\Desktop\LAPS\lock.ico"
$iconParam = if (Test-Path $iconPath) { @{ IconFile = $iconPath } } else { @{} }

Invoke-PS2EXE `
    -InputFile $tempLauncher `
    -OutputFile $outputEXE `
    -NoConsole `
    -Title "LAPS_HOST_MANAGER" `
    -Version "1.0.0" `
    -Product "LAPS_WEB_PORTAL_HOST_MANAGER" `
    -Description "LAPS_WEB_PORTAL_HOST_MANAGER" `
    -Company "FOXCONN-IT" `
    -Copyright "HH0010520" `
    @iconParam

# Cleanup
Remove-Item $tempLauncher -Force

Write-Host "`n=== DONE ===" -ForegroundColor Green
Write-Host "Encrypted EXE: $outputEXE"
Write-Host "`nThis single file works on any PC. Just double-click to run."
Pause
