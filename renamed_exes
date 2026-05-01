param (
    # The drive you want to scan. Change this to "D:\" or another letter if needed.
    [string]$DriveToScan = "C:\"
)

Write-Host "Phase 1: Discovering all .exe files on $DriveToScan..." -ForegroundColor Cyan
Write-Host "(This might take a few minutes depending on your drive size and speed)"

# Gather all .exe files first. This is required to know the total count for a REAL progress bar.
# -ErrorAction SilentlyContinue prevents the console from flooding with "Access Denied" errors.
$allExes = Get-ChildItem -Path $DriveToScan -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue -Force

$totalFiles = $allExes.Count
if ($totalFiles -eq 0) {
    Write-Host "No executables found on $DriveToScan." -ForegroundColor Yellow
    exit
}

Write-Host "Phase 1 Complete. Found $totalFiles executables." -ForegroundColor Green
Write-Host "Phase 2: Scanning internal metadata for renamed files..." -ForegroundColor Cyan

$renamedFiles = @()
$counter = 0

foreach ($file in $allExes) {
    $counter++
    
    # Calculate the percentage for the progress bar
    $percentComplete = [math]::Round(($counter / $totalFiles) * 100, 1)

    # Render the native Windows PowerShell progress bar
    Write-Progress -Activity "Scanning for renamed Executables" `
                   -Status "Processing: $($file.Name)" `
                   -PercentComplete $percentComplete `
                   -CurrentOperation "$counter / $totalFiles files checked"

    try {
        # Extract the embedded internal metadata from the executable
        $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($file.FullName)
        $originalName = $versionInfo.OriginalFilename

        # Check if the file actually has the OriginalFilename property embedded
        if (![string]::IsNullOrWhiteSpace($originalName)) {
            
            # Strip the extensions for a clean comparison 
            # (e.g. comparing "Valex" to "notcheats")
            $origBase = [System.IO.Path]::GetFileNameWithoutExtension($originalName)
            $currBase = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)

            # If they don't match, we caught a renamed file
            if ($origBase -ne $currBase) {
                $renamedFiles += [PSCustomObject]@{
                    CurrentFileName = $file.Name
                    OriginalName    = $originalName
                    Directory       = $file.DirectoryName
                }
            }
        }
    } catch {
        # Skip files that are locked by the system or cannot be read
    }
}

# Close the progress bar once finished
Write-Progress -Activity "Scanning for renamed Executables" -Completed

# Display the final results
if ($renamedFiles.Count -gt 0) {
    Write-Host "`nScan Complete. Found $($renamedFiles.Count) renamed executables:" -ForegroundColor Red
    $renamedFiles | Format-Table -AutoSize
} else {
    Write-Host "`nScan Complete. No renamed executables found." -ForegroundColor Green
}
