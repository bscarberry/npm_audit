#Requires -Version 5.0
<#
.SYNOPSIS
    Runs npm audit at scale across Windows workstations
.DESCRIPTION
    Searches the entire C:\ drive for package.json files and runs npm audit on each project,
    reporting vulnerabilities in a pipe-delimited format.
.NOTES
    Version: 1.3
    Author: Security Audit Script
    Requires: npm installed and available in PATH
#>

[CmdletBinding()]
param(
    # Optional: Add parallel execution support in future versions
    [int]$ThrottleLimit = 1,
    
    # Optional: Exclude certain paths for performance
    [string[]]$ExcludePaths = @(
        'C:\Windows',
        'C:\Program Files\Windows*',
        'C:\$Recycle.Bin'
    ),
    
    # Show verbose debug output for troubleshooting JSON parsing issues
    [switch]$ShowDebugOutput
)

# Initialize summary counters
$script:TotalSummary = @{
    Total = 0
    Low = 0
    Moderate = 0
    High = 0
    Critical = 0
}

$script:ProcessedProjects = 0
$script:FailedProjects = 0
$script:SkippedProjects = 0

function Test-NpmAvailable {
    <#
    .SYNOPSIS
        Checks if npm is available in the system
    #>
    try {
        $null = & npm --version 2>&1
        return $true
    }
    catch {
        Write-Error "npm is not installed or not in PATH. Please install Node.js/npm first."
        return $false
    }
}

function Get-PackageJsonFiles {
    <#
    .SYNOPSIS
        Recursively searches for package.json files on C:\ drive
    #>
    [CmdletBinding()]
    param()
    
    #Write-Host "Searching for package.json files on C:\ drive..." -ForegroundColor Cyan
    #Write-Host "This may take several minutes depending on drive size..." -ForegroundColor Yellow
    
    $searchParams = @{
        Path = 'C:\'
        Filter = 'package.json'
        Recurse = $true
        ErrorAction = 'SilentlyContinue'
        File = $true
    }
    
    # Build exclude filter if paths specified
    $excludeFilter = {
        $currentPath = $_.FullName
        $excluded = $false
        foreach ($excludePath in $ExcludePaths) {
            if ($currentPath -like "$excludePath*") {
                $excluded = $true
                break
            }
        }
        # Also exclude node_modules folders to avoid nested package.json files
        if ($currentPath -match '\\node_modules\\') {
            $excluded = $true
        }
        return -not $excluded
    }
    
    try {
        $packageFiles = Get-ChildItem @searchParams | Where-Object $excludeFilter
        
        $count = ($packageFiles | Measure-Object).Count
        #Write-Host "Found $count package.json file(s)" -ForegroundColor Green
        
        return $packageFiles
    }
    catch {
        Write-Error "Error searching for package.json files: $_"
        return @()
    }
}

function Invoke-NpmAudit {
    <#
    .SYNOPSIS
        Runs npm audit on a specific project directory
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ProjectPath
    )
    
    $auditResult = @{
        Success = $false
        Total = 0
        Low = 0
        Moderate = 0
        High = 0
        Critical = 0
        RawOutput = $null
        Error = $null
    }
    
    try {
        # Change to project directory
        Push-Location -Path $ProjectPath
        
        # Check if node_modules exists (npm audit requires it)
        if (-not (Test-Path "node_modules" -PathType Container)) {
            $auditResult.Error = "No node_modules folder"
            return $auditResult
        }
        
        # Check if package-lock.json exists (npm audit works better with it)
        $hasLockFile = Test-Path "package-lock.json" -PathType Leaf
        
        # Run npm audit with JSON output
        # Using cmd.exe to properly execute npm.cmd on Windows
        # This avoids the "%1 is not a valid Win32 application" error
        
        # Build the command - use cmd /c to run npm.cmd properly
        # Redirect stderr to NUL to avoid mixing error messages with JSON output
        $npmCommand = "cmd.exe /c npm audit --json 2>NUL"
        
        # Execute the command and capture output
        $npmOutput = Invoke-Expression $npmCommand
        
        # Convert array output to single string if needed
        if ($npmOutput -is [array]) {
            $npmOutput = $npmOutput -join "`n"
        }
        
        if ($ShowDebugOutput) {
            #Write-Host "DEBUG - Raw npm output length: $($npmOutput.Length)" -ForegroundColor Magenta
            if ($npmOutput.Length -lt 500) {
                #Write-Host "DEBUG - Raw output: $npmOutput" -ForegroundColor Magenta
            }
        }
        
        if ($npmOutput) {
                # Clean the output - sometimes npm includes non-JSON text
                # Find the first { and last } to extract just the JSON
                $jsonStart = $npmOutput.IndexOf('{')
                $jsonEnd = $npmOutput.LastIndexOf('}')
                
                if ($jsonStart -ge 0 -and $jsonEnd -gt $jsonStart) {
                    $jsonText = $npmOutput.Substring($jsonStart, $jsonEnd - $jsonStart + 1)
                    
                    try {
                        $jsonOutput = $jsonText | ConvertFrom-Json
                        $auditResult.RawOutput = $jsonOutput
                        
                        # Parse vulnerabilities - handle different npm versions
                        # Newer npm versions use metadata.vulnerabilities
                        if ($jsonOutput.metadata -and $jsonOutput.metadata.vulnerabilities) {
                            $vulns = $jsonOutput.metadata.vulnerabilities
                            $auditResult.Low = [int]$vulns.low
                            $auditResult.Moderate = [int]$vulns.moderate
                            $auditResult.High = [int]$vulns.high
                            $auditResult.Critical = [int]$vulns.critical
                            
                            # Some npm versions include "info" severity
                            if ($vulns.info) {
                                # We don't count info as a vulnerability
                            }
                            
                            # Calculate total (excluding info)
                            $auditResult.Total = $auditResult.Low + $auditResult.Moderate + $auditResult.High + $auditResult.Critical
                            $auditResult.Success = $true
                        }
                        # Older npm versions use advisories
                        elseif ($jsonOutput.advisories) {
                            foreach ($advisory in $jsonOutput.advisories.PSObject.Properties.Value) {
                                switch ($advisory.severity.ToLower()) {
                                    'low' { $auditResult.Low++ }
                                    'moderate' { $auditResult.Moderate++ }
                                    'high' { $auditResult.High++ }
                                    'critical' { $auditResult.Critical++ }
                                }
                            }
                            $auditResult.Total = $auditResult.Low + $auditResult.Moderate + $auditResult.High + $auditResult.Critical
                            $auditResult.Success = $true
                        }
                        # Handle npm 7+ format with vulnerabilities object
                        elseif ($jsonOutput.vulnerabilities) {
                            foreach ($vuln in $jsonOutput.vulnerabilities.PSObject.Properties.Value) {
                                # Get the highest severity from the vulnerability
                                $severity = $vuln.severity
                                if (-not $severity -and $vuln.via) {
                                    # Sometimes severity is in the via array
                                    foreach ($via in $vuln.via) {
                                        if ($via.severity) {
                                            $severity = $via.severity
                                            break
                                        }
                                    }
                                }
                                
                                switch ($severity.ToLower()) {
                                    'low' { $auditResult.Low++ }
                                    'moderate' { $auditResult.Moderate++ }
                                    'high' { $auditResult.High++ }
                                    'critical' { $auditResult.Critical++ }
                                }
                            }
                            $auditResult.Total = $auditResult.Low + $auditResult.Moderate + $auditResult.High + $auditResult.Critical
                            $auditResult.Success = $true
                        }
                        # Handle case where audit passes with no vulnerabilities
                        elseif ($jsonOutput.auditReportVersion -or $jsonOutput.runId) {
                            # This is a valid audit report with no vulnerabilities
                            $auditResult.Success = $true
                            # All counts remain at 0
                        }
                        else {
                            $auditResult.Error = "Unrecognized npm audit JSON format"
                            if ($ShowDebugOutput) {
                                #Write-Host "DEBUG - JSON structure: $($jsonOutput | ConvertTo-Json -Depth 2)" -ForegroundColor Magenta
                            }
                        }
                    }
                    catch {
                        $auditResult.Error = "Failed to parse JSON: $_"
                        if ($ShowDebugOutput) {
                            #Write-Host "DEBUG - JSON parse error. Text: $($jsonText.Substring(0, [Math]::Min(200, $jsonText.Length)))" -ForegroundColor Red
                        }
                    }
                }
                else {
                    # No valid JSON found in output
                    # This might be an "up to date" message or error
                    if ($npmOutput -match "found 0 vulnerabilities" -or 
                        $npmOutput -match "up to date" -or
                        $npmOutput -match "no vulnerabilities") {
                        $auditResult.Success = $true
                        # All counts remain at 0
                    }
                    else {
                        $auditResult.Error = "No valid JSON in npm audit output"
                        if ($ShowDebugOutput) {
                            #Write-Host "DEBUG - No JSON found. Output: $($npmOutput.Substring(0, [Math]::Min(200, $npmOutput.Length)))" -ForegroundColor Red
                        }
                    }
                }
            }
        else {
            $auditResult.Error = "No output from npm audit"
        }
    }
    catch {
        $auditResult.Error = "Error running npm audit: $_"
    }
    finally {
        Pop-Location
    }
    
    return $auditResult
}

function Format-AuditResult {
    <#
    .SYNOPSIS
        Formats audit result as pipe-delimited string
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        
        [Parameter(Mandatory)]
        [hashtable]$AuditResult
    )
    
    if ($AuditResult.Success) {
        return "$Path|$($AuditResult.Total)|$($AuditResult.Low)|$($AuditResult.Moderate)|$($AuditResult.High)|$($AuditResult.Critical)"
    }
    else {
        # Return zeros on failure but still report the path
        return "$Path|0|0|0|0|0"
    }
}

function Start-WorkstationAudit {
    <#
    .SYNOPSIS
        Main function to coordinate the audit process
    #>
    [CmdletBinding()]
    param()
    
    #Write-Host "`n=== NPM Security Audit Scanner ===" -ForegroundColor Cyan
    #Write-Host "Starting workstation-wide npm audit...`n" -ForegroundColor Yellow
    
    # Check npm availability
    if (-not (Test-NpmAvailable)) {
        return
    }
    
    # Find all package.json files
    $packageFiles = Get-PackageJsonFiles
    
    if ($packageFiles.Count -eq 0) {
        #Write-Warning "No package.json files found on C:\ drive"
        return
    }
    
    #Write-Host "`nProcessing $($packageFiles.Count) projects...`n" -ForegroundColor Cyan
    
    # Process each project
    foreach ($packageFile in $packageFiles) {
        $projectPath = $packageFile.DirectoryName
        $script:ProcessedProjects++
        
        #Write-Host "[$script:ProcessedProjects/$($packageFiles.Count)] Auditing: $projectPath" -ForegroundColor Gray
        
        # Run audit
        $auditResult = Invoke-NpmAudit -ProjectPath $projectPath
        
        # Format and output result
        $formattedResult = Format-AuditResult -Path $projectPath -AuditResult $auditResult
        #Write-Output $formattedResult
        
        # Update summary totals
        if ($auditResult.Success) {
            $script:TotalSummary.Total += $auditResult.Total
            $script:TotalSummary.Low += $auditResult.Low
            $script:TotalSummary.Moderate += $auditResult.Moderate
            $script:TotalSummary.High += $auditResult.High
            $script:TotalSummary.Critical += $auditResult.Critical
            
            if ($auditResult.Total -gt 0) {
                #Write-Host "  Found $($auditResult.Total) vulnerabilities" -ForegroundColor Yellow
            }
            else {
                #Write-Host "  No vulnerabilities found" -ForegroundColor Green
            }
        }
        else {
            if ($auditResult.Error -eq "No node_modules folder") {
                $script:SkippedProjects++
                #Write-Host "  Skipped: No node_modules folder" -ForegroundColor DarkGray
            }
            else {
                $script:FailedProjects++
                #Write-Host "  Failed: $($auditResult.Error)" -ForegroundColor Red
            }
        }
    }
    
    # Output summary line
    #Write-Host "`n=== SUMMARY ===" -ForegroundColor Cyan
    #Write-Host "Processed: $script:ProcessedProjects projects" -ForegroundColor Green
    #Write-Host "Skipped (no node_modules): $script:SkippedProjects projects" -ForegroundColor DarkGray
    #Write-Host "Failed: $script:FailedProjects projects" -ForegroundColor $(if ($script:FailedProjects -gt 0) { 'Red' } else { 'Green' })
    #Write-Host "Total Vulnerabilities: $($script:TotalSummary.Total)" -ForegroundColor $(if ($script:TotalSummary.Total -gt 0) { 'Yellow' } else { 'Green' })
    
    # Output final summary in required format
    $summaryLine = "$($script:TotalSummary.Total)|$($script:TotalSummary.Low)|$($script:TotalSummary.Moderate)|$($script:TotalSummary.High)|$($script:TotalSummary.Critical)"
    Write-Output "`n$summaryLine"
    
    # Additional statistics
    if ($script:TotalSummary.Total -gt 0) {
        #Write-Host "`nVulnerability Breakdown:" -ForegroundColor Yellow
        #Write-Host "  Low: $($script:TotalSummary.Low)" -ForegroundColor Gray
        #Write-Host "  Moderate: $($script:TotalSummary.Moderate)" -ForegroundColor Yellow
        #Write-Host "  High: $($script:TotalSummary.High)" -ForegroundColor DarkYellow
        #Write-Host "  Critical: $($script:TotalSummary.Critical)" -ForegroundColor Red
    }
}

# Main execution
try {
    # Ensure we're running with appropriate permissions
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        #Write-Warning "Running without Administrator privileges. Some directories may be inaccessible."
    }
    
    # Start the audit
    Start-WorkstationAudit
    
    #Write-Host "`nAudit complete!" -ForegroundColor Green
}
catch {
    #Write-Error "Fatal error during audit: $_"
    exit 1
}