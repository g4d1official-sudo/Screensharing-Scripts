<#
.SYNOPSIS
    Identifies and extracts basic info from Prefetch files that do not originate from .exe files.
.DESCRIPTION
    Checks C:\Windows\Prefetch for any .pf files where the base executable name 
    does not end in .exe (e.g., VALEX.TXT-8A9B1C2D.pf).
#>

# 1. Check for Administrator Privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "Access Denied. You must run this script as an Administrator to read C:\Windows\Prefetch."
    break
}

$prefetchPath = "$env:windir\Prefetch"
$suspiciousFiles = @()

Write-Host "Scanning $prefetchPath for anomalous prefetch files..." -ForegroundColor Cyan

# 2. Grab all .pf files
$pfFiles = Get-ChildItem -Path $prefetchPath -Filter "*.pf" -File

foreach ($file in $pfFiles) {
    # Windows Prefetch format is typically [EXECUTABLE_NAME]-[HASH].pf
    # We find the last hyphen to separate the name from the hash.
    $lastDashIndex = $file.Name.LastIndexOf('-')
    
    if ($lastDashIndex -gt 0) {
        $originalName = $file.Name.Substring(0, $lastDashIndex)
        
        # 3. Filter: Check if the original name does NOT end with .exe (Case-Insensitive)
        # Note: You can add other valid extensions here if needed, like '(?i)\.(exe|scr|com)$'
        if ($originalName -notmatch '(?i)\.exe$') {
            $suspiciousFiles += $file
        }
    }
}

# 4. Output and Basic "Parsing"
if ($suspiciousFiles.Count -eq 0) {
    Write-Host "Clean: No non-executable prefetch files found." -ForegroundColor Green
} else {
    Write-Host "`nFound $($suspiciousFiles.Count) anomalous prefetch files:`n" -ForegroundColor Yellow
    
    foreach ($sus in $suspiciousFiles) {
        Write-Host "---------------------------------------------------"
        Write-Host "Suspicious File : $($sus.Name)" -ForegroundColor Red
        Write-Host "Full Path       : $($sus.FullName)"
        Write-Host "File Size       : $($sus.Length) bytes"
        Write-Host "Created         : $($sus.CreationTime)"
        Write-Host "Last Modified   : $($sus.LastWriteTime)"
        
        # Basic parsing attempt: Extracting readable strings
        Write-Host "`nAttempting to extract readable strings (Path/DLL indicators)..." -ForegroundColor Gray
        try {
            $bytes = [System.IO.File]::ReadAllBytes($sus.FullName)
            
            # Convert bytes to Unicode and ASCII strings to look for paths
            $unicodeStr = [System.Text.Encoding]::Unicode.GetString($bytes)
            $asciiStr = [System.Text.Encoding]::ASCII.GetString($bytes)
            $combined = $unicodeStr + " " + $asciiStr

            # Use regex to find things that look like Windows file paths (C:\... or \Device\...)
            $paths = [regex]::Matches($combined, '([a-zA-Z]:\\[^\0]+|\\Device\\[^\0]+)') | 
                     ForEach-Object { $_.Value -replace '[^\x20-\x7E]', '' } | 
                     Where-Object { $_.Length -gt 5 } | 
                     Select-Object -Unique | 
                     Select-Object -First 5

            if ($paths) {
                foreach ($path in $paths) {
                    Write-Host "  -> $path" -ForegroundColor DarkCyan
                }
            } else {
                Write-Host "  -> [No clear paths extracted. File may be heavily compressed.]" -ForegroundColor DarkGray
            }
        } catch {
            Write-Warning "  -> Failed to read file for string extraction."
        }
        Write-Host "---------------------------------------------------`n"
    }
}
