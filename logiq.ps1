

param(
    # Path to the folder that contains log files to analyze.
    # Default is .\sample-logs relative to where this script is run.
    [string]$LogPath = ".\sample-logs",

    # Switch to control whether a JSON report file should be generated.
    [switch]$JsonReport,

    # Switch to control whether an HTML report file should be generated.
    [switch]$HtmlReport,

    # Switch to control CSV export
    [switch]$CsvReport
)

# Print a simple banner so the user knows the tool that is running.
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "                LogIQ – Enterprise Log Analyzer        " -ForegroundColor Green
Write-Host "======================================================" -ForegroundColor Cyan

# -------------------------
# Helper Functions
# -------------------------

function Add-ToMap {
    param(
        [string]$key,
        [string]$line,
        [hashtable]$map
    )
    if (-not $map.ContainsKey($key)) {
        $map[$key] = @()
    }
    $map[$key] += $line
}

function Is-SlowApi {
    param([int]$ms)
    return $ms -gt 300
}

function Write-DebugLine {
    param([string]$msg)
    # Toggle debug logs here if needed
    # Write-Host "DEBUG: $msg"
}

function Build-LogiqHtml {
    param(
        [PSCustomObject]$Report,
        [string[]]$Errors,
        [string[]]$Timeouts,
        [string[]]$SlowApis,
        [string[]]$ServiceHealth
    )

    $errorsBlock        = ($Errors        -join "`n")
    $timeoutsBlock      = ($Timeouts      -join "`n")
    $slowApisBlock      = ($SlowApis      -join "`n")
    $serviceHealthBlock = ($ServiceHealth -join "`n")

    $timestamp       = $Report.Timestamp
    $totalLines      = $Report.TotalLines
    $errorCount      = $Report.ErrorCount
    $timeoutCount    = $Report.TimeoutCount
    $slowApiCount    = $Report.SlowApiCount
    $txnCount        = $Report.Transactions
    $corrCount       = $Report.CorrelationIDs
    $svcHealthIssues = $Report.ServiceHealthIssues

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>LogIQ – Log Analysis Report</title>
<style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background-color: #0f172a; color: #e5e7eb; margin:0; padding:0; }
    .header { padding: 24px 32px; background: linear-gradient(90deg,#0ea5e9,#6366f1); color:white; font-size:26px; font-weight:600; box-shadow:0 2px 8px rgba(0,0,0,0.3);}    
    .subheader { padding:0 32px 16px 32px; font-size:14px; color:#cbd5ff; }
    .container { padding:20px 32px 32px 32px; }
    .kpi-grid { display:grid; grid-template-columns: repeat(auto-fit,minmax(160px,1fr)); gap:16px; margin-bottom:28px; }
    .kpi-card { padding:14px; border-radius:12px; background:#020617; border:1px solid #1e293b; box-shadow:0 1px 3px rgba(0,0,0,0.4);}    
    .kpi-label { font-size:12px; text-transform:uppercase; letter-spacing:0.06em; color:#9ca3af; margin-bottom:6px; }
    .kpi-value { font-size:22px; font-weight:600; }
    .kpi-error { color:#f87171; }
    .kpi-timeout { color:#fb923c; }
    .kpi-slow { color:#fde047; }
    .kpi-ok { color:#4ade80; }
    details { margin-bottom:14px; border-radius:8px; background:#020617; border:1px solid #1e293b; overflow:hidden; }
    summary { padding:12px; cursor:pointer; font-size:14px; background:#020617; }
    summary span.badge { display:inline-block; margin-left:10px; font-size:12px; padding:2px 8px; border-radius:999px; background:#1e293b; color:#e5e7eb; }
    pre { margin:0; padding:14px; font-size:12px; line-height:1.45; white-space:pre-wrap; background:#020617; border-top:1px solid #1f2937; }
</style>
</head>
<body>
<div class="header">LogIQ – Log Analysis Report</div>
<div class="subheader">Generated at $timestamp</div>

<div class="container">
    <div class="kpi-grid">
        <div class="kpi-card"><div class="kpi-label">Total Lines</div><div class="kpi-value kpi-ok">$totalLines</div></div>
        <div class="kpi-card"><div class="kpi-label">Errors</div><div class="kpi-value kpi-error">$errorCount</div></div>
        <div class="kpi-card"><div class="kpi-label">Timeouts</div><div class="kpi-value kpi-timeout">$timeoutCount</div></div>
        <div class="kpi-card"><div class="kpi-label">Slow APIs</div><div class="kpi-value kpi-slow">$slowApiCount</div></div>
        <div class="kpi-card"><div class="kpi-label">Transactions</div><div class="kpi-value kpi-ok">$txnCount</div></div>
        <div class="kpi-card"><div class="kpi-label">Correlation IDs</div><div class="kpi-value kpi-ok">$corrCount</div></div>
        <div class="kpi-card"><div class="kpi-label">Service Health Issues</div><div class="kpi-value kpi-error">$svcHealthIssues</div></div>
    </div>

    <details open><summary>Errors <span class="badge">$errorCount</span></summary><pre>$errorsBlock</pre></details>
    <details><summary>Timeouts <span class="badge">$timeoutCount</span></summary><pre>$timeoutsBlock</pre></details>
    <details><summary>Slow APIs <span class="badge">$slowApiCount</span></summary><pre>$slowApisBlock</pre></details>
    <details><summary>Service Health Issues <span class="badge">$svcHealthIssues</span></summary><pre>$serviceHealthBlock</pre></details>
</div>
</body>
</html>
"@

    return $html
}

# -------------------------
# 1. Load all logs
# -------------------------
# Get all files under $LogPath with extension .log (recursively), then read their contents.
# Get-ChildItem finds files; ForEach-Object + Get-Content reads every line from each file.
$logs = Get-ChildItem -Path $LogPath -Filter *.log -Recurse -File |
        ForEach-Object { Get-Content -Raw $_.FullName } |
        ForEach-Object { $_ -split "`n" }

# -------------------------
# 2. Initialize result buckets
# -------------------------
# These arrays will store the filtered lines we care about:
# - $errors: lines with ERROR
# - $timeouts: lines that indicate screen/API timeouts
# - $slowApis: lines for slow API calls above a threshold
# - $transactions: lines related to transactions (SALE, totals, payment)
# - $correlationMap: maps correlationId -> list of lines with that ID
# - $serviceHealth: lines that indicate service failures or unhealthy states
$errors = @()
$timeouts = @()
$slowApis = @()
$transactions = @()
$correlationMap = @{}
$serviceHealth = @()

# -------------------------
# 3. Define regex patterns we want to match in each line
# -------------------------
# Simple substring match for "ERROR".
$regexError = '\bERROR\b'

# Timeout-related keywords typically seen in logs (case-insensitive).
$regexTimeout = '(?i)timeout|Timedout|SCREEN_TIMEDOUT'

# Pattern to capture the numeric value inside completeReqTTms="123".
# The () defines a capturing group so we can extract just the number.
$regexApi = 'completeReqTTms="(\d+)"'

# Pattern for a standard UUID / GUID (correlation ID) – 8-4-4-4-12 hex (case-insensitive).
$regexCorrelation = '\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b'

# -------------------------
# 4. Process log lines one by one
# -------------------------
foreach ($line in $logs) {

    # A. Capture any line containing ERROR.
    # -match returns $true if the pattern is found.
    if ($line -match $regexError) {
        $errors += $line
    }

    # B. Capture lines that indicate timeouts (screen or network).
    if ($line -match $regexTimeout) {
        $timeouts += $line
    }

    # C. Capture slow API calls.
    # If completeReqTTms="number" exists, -match populates $Matches[1] with the numeric part.
    if ($line -match $regexApi) {
        # Cast the captured string to [int] so we can compare numerically.
        $ms = [int]$Matches[1]
        # Threshold for "slow" APIs is >300 ms (can be tuned later).
        if (Is-SlowApi $ms) {
            # Store both the latency and the full line for context.
            $slowApis += "$ms ms : $line"
        }
    }

    # D. Capture correlation IDs so we can group related log lines.
    if ($line -match $regexCorrelation) {
        # $Matches[0] contains the full GUID that matched.
        $cid = $Matches[0]
        Add-ToMap -key $cid -line $line -map $correlationMap
    }

    # E. Capture lines related to transaction lifecycle and payment.
    # This is a simple OR pattern for key markers.
    if ($line -match '(?i)TransactionType|TotalDetails|payment') {
        $transactions += $line
    }

    # F. Capture lines that look like service health issues.
    # These include failed localhost calls, statusCode="0", and explicit health flags.
    if ($line -match '(?i)Failed to connect|statusCode="0"|Unable to connect|SyncServiceHealthy:false') {
        $serviceHealth += $line
    }
}

# -------------------------
# 5. Build a summary report object
# -------------------------
# Here we package all the counts and raw collections into a single PSCustomObject
# so it can be output, converted to JSON, or turned into HTML in a structured way.
$report = [PSCustomObject]@{
    # When this analysis was run.
    Timestamp           = (Get-Date)

    # Total number of log lines processed.
    TotalLines          = $logs.Count

    # Aggregated counts for quick, high-level view.
    ErrorCount          = $errors.Count
    TimeoutCount        = $timeouts.Count
    SlowApiCount        = $slowApis.Count
    Transactions        = $transactions.Count

    # How many distinct correlation IDs were found.
    CorrelationIDs      = $correlationMap.Keys.Count

    # Number of service health-related log entries.
    ServiceHealthIssues = $serviceHealth.Count

    # Detailed collections – useful for deeper drilldowns.
    Errors              = $errors
    Timeouts            = $timeouts
    SlowApis            = $slowApis
    ServiceHealth       = $serviceHealth
}

# -------------------------
# 6. Emit output in the requested formats
# -------------------------

# If -JsonReport was passed, serialize the report object to JSON
# and write it to a file named logiq-report.json in the current directory.
if ($JsonReport) {
    $report | ConvertTo-Json -Depth 6 | Out-File "logiq-report.json"
    Write-Host "📄 JSON report generated: logiq-report.json"
}

# If -HtmlReport was passed, build the styled HTML dashboard and write it to a file
if ($HtmlReport) {
    $html = Build-LogiqHtml -Report $report -Errors $errors -Timeouts $timeouts -SlowApis $slowApis -ServiceHealth $serviceHealth
    $html | Out-File "logiq-report.html"
    Write-Host "📄 HTML dashboard generated: logiq-report.html"
}

# If -CsvReport was passed, export key collections to CSV files
if ($CsvReport) {
    # Export summary (counts only)
    $report | Select-Object Timestamp,TotalLines,ErrorCount,TimeoutCount,SlowApiCount,Transactions,CorrelationIDs,ServiceHealthIssues |
        Export-Csv -NoTypeInformation -Path "logiq-summary.csv"

    # Export individual collections
    $errors      | Set-Content "logiq-errors.csv"
    $timeouts    | Set-Content "logiq-timeouts.csv"
    $slowApis    | Set-Content "logiq-slowapis.csv"
    $serviceHealth | Set-Content "logiq-servicehealth.csv"

    Write-Host "📄 CSV reports generated: logiq-summary.csv, logiq-errors.csv, logiq-timeouts.csv, logiq-slowapis.csv, logiq-servicehealth.csv"
}


# Default behavior: always print the report object to the console so
# the user (or another script) can see and pipe the results.
Write-Host "✔ LogIQ analysis completed."
$report