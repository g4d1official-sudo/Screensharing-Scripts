<#
.SYNOPSIS
    Identifies anomalous Prefetch files and outputs the results to an interactive GUI window.
#>

# 1. Check for Administrator Privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "Access Denied. You must run this script as an Administrator."
    break
}

$prefetchPath = "$env:windir\Prefetch"
$suspiciousFiles = @()
$parsedResults = @() # Array to hold our structured objects for the GUI

Write-Host "Scanning $prefetchPath for anomalous prefetch files..." -ForegroundColor Cyan

# 2. Grab all .pf files
$pfFiles = Get-ChildItem -Path $prefetchPath -Filter "*.pf" -File

foreach ($file in $pfFiles) {
    $lastDashIndex = $file.Name.LastIndexOf('-')
    
    if ($lastDashIndex -gt 0) {
        $originalName = $file.Name.Substring(0, $lastDashIndex)
        
        # Filter: Check if the original name does NOT end with .exe (Case-Insensitive)
        if ($originalName -notmatch '(?i)\.exe$') {
            $suspiciousFiles += $file
        }
    }
}

# 3. Parse and Structure the Data
if ($suspiciousFiles.Count -gt 0) {
    Write-Host "Found $($suspiciousFiles.Count) anomalous files. Extracting data and launching viewer..." -ForegroundColor Yellow

    foreach ($sus in $suspiciousFiles) {
        $extractedPathsString = ""

        # Basic parsing attempt: Extracting readable strings
        try {
            $bytes = [System.IO.File]::ReadAllBytes($sus.FullName)
            $unicodeStr = [System.Text.Encoding]::Unicode.GetString($bytes)
            $asciiStr = [System.Text.Encoding]::ASCII.GetString($bytes)
            $combined = $unicodeStr + " " + $asciiStr

            $paths = [regex]::Matches($combined, '([a-zA-Z]:\\[^\0]+|\\Device\\[^\0]+)') | 
                     ForEach-Object { $_.Value -replace '[^\x20-\x7E]', '' } | 
                     Where-Object { $_.Length -gt 5 } | 
                     Select-Object -Unique | 
                     Select-Object -First 5

            if ($paths) {
                # Join the paths together with a pipe for easier reading in the grid
                $extractedPathsString = $paths -join "  |  "
            } else {
                $extractedPathsString = "[No clear paths. File is likely MAM compressed.]"
            }
        } catch {
            $extractedPathsString = "[Error reading file bytes]"
        }

        # Create a custom object for the GridView
        $parsedResults += [PSCustomObject]@{
            "Suspicious File" = $sus.Name
            "File Size (Bytes)" = $sus.Length
            "Creation Time"   = $sus.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")
            "Extracted Paths" = $extractedPathsString
            "Full Path"       = $sus.FullName
        }
    }

    # 4. Output to GridView
    $parsedResults | Out-GridView -Title "Anomalous Prefetch Files Analysis"

} else {
    # Pop up a clean message box if nothing is found
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.MessageBox]::Show("System appears clean. No non-executable prefetch files found.", "Prefetch Scan", "OK", "Information")
}
