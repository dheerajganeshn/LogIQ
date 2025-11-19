<#
=====================================================================================
 LOGIQ — ENTERPRISE LOG ANALYZER
-------------------------------------------------------------------------------------
 This script analyzes ANY kind of application logs:
 - POS logs (7POS, SCO, Retail)
 - JSON logs (Datadog, ELK, Splunk)
 - Windows / Server logs
 - API performance logs
 - Kubernetes / Docker logs when redirected to files

 It extracts:
 - Errors & stack traces
 - Timeouts
 - Slow APIs (durationMs or completeReqTTms)
 - Correlation IDs
 - Service health failures
 - JSON structured logs (Datadog/ELK/Splunk)
 - Error grouping
 - Latency percentiles (P50, P90, P99)
 - HTML, JSON and CSV reports

 It also supports real-time tailing:  ./logiq.ps1 -LogPath app.log -Tail

=====================================================================================
#>

param(
    # Path to either a single log file or a directory containing .log files
    [string]$LogPath = ".",
    # Whether to output a JSON summary report
    [switch]$JsonReport,
    # Whether to output a styled HTML dashboard
    [switch]$HtmlReport,
    # Enable real-time streaming analysis (no final report, just processing as logs arrive)
    [switch]$Tail
)

Write-Host "`n🔍 Starting LogIQ Enterprise Log Analyzer..." -ForegroundColor Cyan

# -----------------------------------------------------------------------------------
# 1. INITIALIZE BUCKETS & REGEX PATTERNS
#    These script-scope variables hold everything we extract from logs.
# -----------------------------------------------------------------------------------

# Will store raw error lines
$script:errors = @()
# Will store timeout-related lines
$script:timeouts = @()
# Will store “slow API” entries (with duration and line)
$script:slowApis = @()
# Map of correlationId -> list of log lines containing that ID
$script:correlationMap = @{}
# Placeholder if later you want transaction analysis
$script:transactions = @()
# Lines that indicate unhealthy services / connectivity issues
$script:serviceHealth = @()
# Parsed JSON objects from JSON logs (Datadog/ELK/etc.)
$script:jsonEntries = @()

# Regex to detect errors in plain text
$script:regexError = "ERROR|Exception|Traceback"
# Regex to detect timeouts
$script:regexTimeout = "timeout|Timedout|SCREEN_TIMEDOUT"
# Regex to capture numeric value from completeReqTTms="644"
$script:regexApi = 'completeReqTTms="(\d+)"'
# Regex to detect UUID-style correlation IDs
$script:regexCorrelation = '\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b'

# ---------------------------
# PAYMENT + TRANSACTION FLOW
# ---------------------------
$script:transactionsFlow = @{}
$script:regexTransactionId = 'transactionId["\:]?\s*"?([0-9a-f-]{36})"?'
$script:regexPapiReq       = "POST https://.*papi.*?/payments"
$script:regexPapiResp      = '"statusCode"\s*:\s*(\d+).*"status"\s*:\s*"(\w+)"'
$script:regexTapiReq       = "POST https://.*risservices.*?/sale/transaction"
$script:regexTapiResp      = '"statusCode"\s*:\s*(\d+).*"SUCCESS"'
$script:regexWsDisconnect  = "Websocket Session Disconnected|websocket disconnected"
$script:regexExceptionTapi = "exceptionOfflineTransaction|Offline Transaction API Payload"
$script:regexScheduler     = "START schedule job"

function Ensure-Transaction($tid) {
    if (-not $script:transactionsFlow.ContainsKey($tid)) {
        $script:transactionsFlow[$tid] = @{
            TransactionId     = $tid
            PapiRequest       = $false
            PapiResponse      = $null
            TapiRequest       = $false
            TapiResponse      = $null
            WebSocketDrop     = $false
            ExceptionOffline  = $false
            SchedulerJobs     = @()
            Lines             = @()
        }
    }
}

# -----------------------------------------------------------------------------------
# 2. PER-LINE PROCESSOR
#    This function does all logic for a SINGLE log line.
#    It is reused by both batch mode and tail mode.
# -----------------------------------------------------------------------------------

function Process-Line {
    param(
        [string]$line  # raw log line
    )

    # Skip empty lines
    if (-not $line) { return }

    # -------------------------
    # A. JSON LOG HANDLING
    # -------------------------
    # If a line looks like JSON (starts with "{"), we try to parse it.
    if ($line.Trim().StartsWith("{")) {
        try {
            $jsonObj = $line | ConvertFrom-Json
            # Store JSON object for possible future queries
            $script:jsonEntries += $jsonObj

            # Treat JSON logs as error if they have level=error or HTTP status=500
            if ($jsonObj.level -eq "error" -or $jsonObj.status -eq 500) {
                $script:errors += $line
            }

            # Some logs use durationMs for latency; classify slow ones > 300ms
            if ($jsonObj.PSObject.Properties.Name -contains "durationMs") {
                if ([int]$jsonObj.durationMs -gt 300) {
                    $script:slowApis += "$($jsonObj.durationMs) ms : $line"
                }
            }

        } catch {
            # If JSON parsing fails, we silently ignore and let other detectors work.
        }
    }

    # -------------------------
    # B. Plain-text errors
    # -------------------------
    # If the line matches generic error keywords, flag it as an error.
    if ($line -match $script:regexError) {
        $script:errors += $line
    }

    # -------------------------
    # C. Timeouts
    # -------------------------
    # Matches lines indicating some form of timeout.
    if ($line -match $script:regexTimeout) {
        $script:timeouts += $line
    }

    # -------------------------
    # D. API latency extraction
    # -------------------------
    # Extracts latency from patterns like completeReqTTms="644".
    if ($line -match $script:regexApi) {
        $ms = [int]$Matches[1]
        # Only consider as “slow” if above our threshold (300ms).
        if ($ms -gt 300) {
            $script:slowApis += "$ms ms : $line"
        }
    }

    # -------------------------
    # E. Correlation ID mapping
    # -------------------------
    # This helps trace a single request across services by grouping lines by ID.
    if ($line -match $script:regexCorrelation) {
        $cid = $Matches[0]

        if (-not $script:correlationMap.ContainsKey($cid)) {
            $script:correlationMap[$cid] = @()
        }
        $script:correlationMap[$cid] += $line
    }

    # -------------------------
    # F. Service health detection
    # -------------------------
    # Any line that looks like connectivity or service health issue.
    if ($line -match "Failed to connect|statusCode=""0""|Unable to connect|SyncServiceHealthy:false") {
        $script:serviceHealth += $line
    }

    # ---------------------------------------------
    # PAYMENT + TRANSACTION ANALYSIS
    # ---------------------------------------------
    $tid = $null
    if ($line -match $script:regexTransactionId) {
        $tid = $Matches[1]
        Ensure-Transaction $tid
        $script:transactionsFlow[$tid].Lines += $line
    }
    if ($tid) {
        if ($line -match $script:regexPapiReq) { $script:transactionsFlow[$tid].PapiRequest = $true }
        if ($line -match $script:regexPapiResp) {
            $code = [int]$Matches[1]; $status = $Matches[2]
            $script:transactionsFlow[$tid].PapiResponse = "$code $status"
        }
        if ($line -match $script:regexTapiReq) { $script:transactionsFlow[$tid].TapiRequest = $true }
        if ($line -match $script:regexTapiResp) { $script:transactionsFlow[$tid].TapiResponse = "201 SUCCESS" }
        if ($line -match $script:regexWsDisconnect) { $script:transactionsFlow[$tid].WebSocketDrop = $true }
        if ($line -match $script:regexExceptionTapi) { $script:transactionsFlow[$tid].ExceptionOffline = $true }
    }
    if ($line -match $script:regexScheduler) {
        foreach ($id in $script:transactionsFlow.Keys) {
            $script:transactionsFlow[$id].SchedulerJobs += $line
        }
    }
}

# -----------------------------------------------------------------------------------
# 3. TAIL MODE (REAL-TIME STREAMING)
#    In tail mode we DON'T generate reports, we continuously analyze new lines.
# -----------------------------------------------------------------------------------

if ($Tail) {
    # Ensure the path exists
    if (-not (Test-Path $LogPath)) {
        Write-Host "❌ Tail mode: Log path '$LogPath' does not exist." -ForegroundColor Red
        exit 1
    }

    Write-Host "📡 Real-time monitoring enabled (tail mode). Press Ctrl+C to stop." -ForegroundColor Yellow

    # Get-Content -Wait -Tail 50 behaves like `tail -f`, streaming new lines.
    Get-Content $LogPath -Wait -Tail 50 | ForEach-Object { Process-Line $_ }

    # No reports at the end; streaming only.
    exit 0
}

# -----------------------------------------------------------------------------------
# 4. LOAD LOGS (BATCH MODE)
#    If LogPath is a directory, we pull all *.log files.
#    If it is a file, we only read that file.
# -----------------------------------------------------------------------------------

if (Test-Path $LogPath -PathType Container) {
    # Directory case: read all .log files under it (recursively).
    $logs = Get-ChildItem -Path $LogPath -Filter *.log -Recurse |
            ForEach-Object { Get-Content $_.FullName }
} elseif (Test-Path $LogPath -PathType Leaf) {
    # Single file case
    $logs = Get-Content $LogPath
} else {
    Write-Host "❌ Log path '$LogPath' not found." -ForegroundColor Red
    exit 1
}

# Process each line via the shared function
foreach ($line in $logs) {
    Process-Line $line
}

# -----------------------------------------------------------------------------------
# 5. LATENCY METRICS (P50 / P90 / P99)
#    Convert slowApi entries into numeric array and compute percentiles.
# -----------------------------------------------------------------------------------

$latencies = @()

foreach ($entry in $script:slowApis) {
    # Each slowApis entry looks like: "393 ms : <original log line>"
    $msText = $entry.Split(" ")[0]
    $ms = 0
    [int]::TryParse($msText, [ref]$ms) | Out-Null
    if ($ms -gt 0) { $latencies += $ms }
}

$p50 = $null; $p90 = $null; $p99 = $null

if ($latencies.Count -gt 0) {
    $sorted = $latencies | Sort-Object
    # Use floor indices capped to last element to avoid out-of-range.
    $p50 = $sorted[ [int]([Math]::Min($sorted.Count - 1, [Math]::Floor($sorted.Count * 0.50))) ]
    $p90 = $sorted[ [int]([Math]::Min($sorted.Count - 1, [Math]::Floor($sorted.Count * 0.90))) ]
    $p99 = $sorted[ [int]([Math]::Min($sorted.Count - 1, [Math]::Floor($sorted.Count * 0.99))) ]
}

# -----------------------------------------------------------------------------------
# 6. ERROR GROUPING
#    Group errors by first 80 chars to find recurring patterns (same message).
# -----------------------------------------------------------------------------------

$groupedErrors = $script:errors |
    Group-Object { $_.Substring(0, [Math]::Min(80, $_.Length)) } |
    Select-Object Name, Count |
    Sort-Object Count -Descending

# -----------------------------------------------------------------------------------
# 7. BUILD MAIN REPORT OBJECT
#    This is the in-memory summary used by JSON/HTML and also returned to console.
# -----------------------------------------------------------------------------------

$report = [PSCustomObject]@{
    Timestamp           = (Get-Date)
    TotalLines          = $logs.Count
    ErrorCount          = $script:errors.Count
    TimeoutCount        = $script:timeouts.Count
    SlowApiCount        = $script:slowApis.Count
    CorrelationIDs      = $script:correlationMap.Keys.Count
    ServiceHealthIssues = $script:serviceHealth.Count
    P50LatencyMs        = $p50
    P90LatencyMs        = $p90
    P99LatencyMs        = $p99
    Errors              = $script:errors
    Timeouts            = $script:timeouts
    SlowApis            = $script:slowApis
    ServiceHealth       = $script:serviceHealth
    GroupedErrors       = $groupedErrors
}

# ---------------------------------------------------------------
# TRANSACTION FLOW SUMMARY
# ---------------------------------------------------------------
$transactionSummaries = @()
foreach ($tid in $script:transactionsFlow.Keys) {
    $t = $script:transactionsFlow[$tid]
    $root = "UNKNOWN"
    if (-not $t.PapiRequest) { $root = "Missing PAPI Request" }
    elseif (-not $t.PapiResponse) { $root = "Missing PAPI Response" }
    elseif ($t.WebSocketDrop) { $root = "WebSocket Disconnect between PAPI & TAPI" }
    elseif (-not $t.TapiRequest) { $root = "Missing TAPI Request" }
    elseif (-not $t.TapiResponse) {
        if ($t.ExceptionOffline) { $root = "TAPI sent to Offline Table" }
        else { $root = "Missing TAPI Response" }
    }
    elseif ($t.TapiResponse -eq "201 SUCCESS") { $root = "OK" }

    $transactionSummaries += [PSCustomObject]@{
        TransactionId    = $tid
        PAPI             = $t.PapiResponse
        TAPI             = $t.TapiResponse
        WebSocket        = if ($t.WebSocketDrop) { "Disconnected" } else { "OK" }
        OfflineHandling  = $t.ExceptionOffline
        SchedulerJobs    = $t.SchedulerJobs.Count
        RootCause        = $root
    }

    # Detect abnormal transactions
    $abnormal = $false
    if ($root -ne "OK") { $abnormal = $true }
    if ($t.SchedulerJobs.Count -eq 0 -and $t.ExceptionOffline) { $abnormal = $true }
    if ($t.PapiResponse -match "^4" -or $t.PapiResponse -match "^5") { $abnormal = $true }
    if ($t.TapiResponse -match "^4" -or $t.TapiResponse -match "^5") { $abnormal = $true }

    $t.Abnormal = $abnormal
}
 $report | Add-Member -MemberType NoteProperty -Name TransactionFlow -Value $transactionSummaries
$report | Add-Member -MemberType NoteProperty -Name AbnormalTransactions -Value ($transactionSummaries | Where-Object { $_.RootCause -ne "OK" })

# -----------------------------------------------------------------------------------
# 8. CSV REPORTS (MATCH YOUR EXISTING STRUCTURE)
#    These produce the .csv files you already see in your repo.
# -----------------------------------------------------------------------------------

# Summary CSV: one row with core metrics
$summaryRow = [PSCustomObject]@{
    Timestamp           = $report.Timestamp
    TotalLines          = $report.TotalLines
    ErrorCount          = $report.ErrorCount
    TimeoutCount        = $report.TimeoutCount
    SlowApiCount        = $report.SlowApiCount
    ServiceHealthIssues = $report.ServiceHealthIssues
    P50LatencyMs        = $report.P50LatencyMs
    P90LatencyMs        = $report.P90LatencyMs
    P99LatencyMs        = $report.P99LatencyMs
}

$summaryRow | Export-Csv "logiq-summary.csv" -NoTypeInformation -Encoding UTF8

# Each error line as a row in logiq-errors.csv
$report.Errors |
    ForEach-Object { [PSCustomObject]@{ Line = $_ } } |
    Export-Csv "logiq-errors.csv" -NoTypeInformation -Encoding UTF8

# Each timeout line in logiq-timeouts.csv
$report.Timeouts |
    ForEach-Object { [PSCustomObject]@{ Line = $_ } } |
    Export-Csv "logiq-timeouts.csv" -NoTypeInformation -Encoding UTF8

# Each slow API line in logiq-slowapis.csv
$report.SlowApis |
    ForEach-Object { [PSCustomObject]@{ Line = $_ } } |
    Export-Csv "logiq-slowapis.csv" -NoTypeInformation -Encoding UTF8

# Each service health issue in logiq-servicehealth.csv
$report.ServiceHealth |
    ForEach-Object { [PSCustomObject]@{ Line = $_ } } |
    Export-Csv "logiq-servicehealth.csv" -NoTypeInformation -Encoding UTF8

# Transaction flow CSV
$transactionSummaries |
    Export-Csv "logiq-transactions.csv" -NoTypeInformation -Encoding UTF8

$transactionSummaries |
    Where-Object { $_.RootCause -ne "OK" } |
    Export-Csv "logiq-abnormal-transactions.csv" -NoTypeInformation -Encoding UTF8

Write-Host "📄 CSV reports generated: logiq-summary/errors/timeouts/slowapis/servicehealth.csv"

# -----------------------------------------------------------------------------------
# 9. JSON REPORT (OPTIONAL)
# -----------------------------------------------------------------------------------

if ($JsonReport) {
    $report | ConvertTo-Json -Depth 6 | Out-File "logiq-report.json"
    Write-Host "📄 JSON report generated: logiq-report.json"
}

# -----------------------------------------------------------------------------------
# 10. STYLED HTML DASHBOARD (OPTION B + C MIX)
#      Uses inline CSS for a dark, SRE-friendly visual summary.
# -----------------------------------------------------------------------------------

if ($HtmlReport) {
    # Build small tables for summary + latency + grouped errors
    $summaryData = @(
        [PSCustomObject]@{ Metric = "Total Lines";      Value = $report.TotalLines }
        [PSCustomObject]@{ Metric = "Errors";           Value = $report.ErrorCount }
        [PSCustomObject]@{ Metric = "Timeouts";         Value = $report.TimeoutCount }
        [PSCustomObject]@{ Metric = "Slow APIs";        Value = $report.SlowApiCount }
        [PSCustomObject]@{ Metric = "Service Issues";   Value = $report.ServiceHealthIssues }
        [PSCustomObject]@{ Metric = "Correlation IDs";  Value = $report.CorrelationIDs }
    )

    $latencyData = @(
        [PSCustomObject]@{ Percentile = "P50"; Value = $report.P50LatencyMs }
        [PSCustomObject]@{ Percentile = "P90"; Value = $report.P90LatencyMs }
        [PSCustomObject]@{ Percentile = "P99"; Value = $report.P99LatencyMs }
    )

    $summaryHtml       = $summaryData        | ConvertTo-Html -Fragment
    $latencyHtml       = $latencyData        | ConvertTo-Html -Fragment
    $groupedErrorsHtml = $report.GroupedErrors | ConvertTo-Html -Fragment
    $timestamp         = $report.Timestamp

    # NOTE: we embed PowerShell variables ($report, etc.) into the here-string.
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>LogIQ Analysis Report</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background-color: #020617;
      color: #e5e7eb;
      margin: 0;
      padding: 0;
    }
    .page {
      max-width: 1200px;
      margin: 0 auto;
      padding: 24px 16px 40px;
    }
    h1, h2, h3 {
      font-weight: 600;
      color: #f9fafb;
    }
    h1 {
      font-size: 28px;
      margin-bottom: 4px;
    }
    h2 {
      font-size: 20px;
      margin-top: 24px;
    }
    .subtitle {
      color: #9ca3af;
      font-size: 13px;
      margin-bottom: 20px;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }
    .card {
      background: radial-gradient(circle at top left, #1d283a, #020617 70%);
      border-radius: 10px;
      padding: 14px 16px;
      border: 1px solid #1f2937;
      box-shadow: 0 10px 25px rgba(0,0,0,0.5);
    }
    .card h3 {
      font-size: 14px;
      margin: 0 0 8px 0;
      color: #e5e7eb;
      text-transform: uppercase;
      letter-spacing: 0.06em;
    }
    .metric {
      font-size: 24px;
      font-weight: 600;
    }
    .metric--error {
      color: #f97373;
    }
    .metric--warn {
      color: #fbbf24;
    }
    .metric--ok {
      color: #4ade80;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
      margin-top: 8px;
    }
    th, td {
      border: 1px solid #111827;
      padding: 6px 8px;
    }
    th {
      background-color: #0f172a;
      color: #e5e7eb;
      text-align: left;
    }
    tr:nth-child(even) td {
      background-color: #020617;
    }
    tr:nth-child(odd) td {
      background-color: #030712;
    }
    .section {
      margin-top: 24px;
    }
    .badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 10px;
      letter-spacing: 0.05em;
      text-transform: uppercase;
      margin-left: 8px;
    }
    .badge-error {
      background-color: rgba(248,113,113,0.12);
      color: #fecaca;
      border: 1px solid rgba(248,113,113,0.5);
    }
    .badge-warn {
      background-color: rgba(234,179,8,0.12);
      color: #fef3c7;
      border: 1px solid rgba(234,179,8,0.5);
    }
    .badge-info {
      background-color: rgba(59,130,246,0.12);
      color: #bfdbfe;
      border: 1px solid rgba(59,130,246,0.5);
    }
    .footer {
      margin-top: 32px;
      font-size: 11px;
      color: #6b7280;
      text-align: center;
    }
  </style>
</head>
<body>
  <div class="page">
    <header>
      <h1>LogIQ Analysis Report</h1>
      <div class="subtitle">
        Generated at $timestamp · SRE-ready summary of log health and anomalies
      </div>
    </header>

    <section class="grid">
      <div class="card">
        <h3>Errors</h3>
        <div class="metric metric--error">$($report.ErrorCount)</div>
        <div class="subtitle">Total error lines detected across all logs.</div>
      </div>
      <div class="card">
        <h3>Timeouts</h3>
        <div class="metric metric--warn">$($report.TimeoutCount)</div>
        <div class="subtitle">User-facing or service timeouts observed.</div>
      </div>
      <div class="card">
        <h3>Slow APIs</h3>
        <div class="metric metric--warn">$($report.SlowApiCount)</div>
        <div class="subtitle">Requests above threshold latency (&gt;300ms).</div>
      </div>
      <div class="card">
        <h3>Service Health</h3>
        <div class="metric $(if ($report.ServiceHealthIssues -gt 0) { 'metric--error' } else { 'metric--ok' })">
          $($report.ServiceHealthIssues)
        </div>
        <div class="subtitle">Connectivity failures or unhealthy dependencies.</div>
      </div>
      <div class="card">
        <h3>Correlation IDs</h3>
        <div class="metric metric--ok">$($report.CorrelationIDs)</div>
        <div class="subtitle">Unique traces discovered across services.</div>
      </div>
      <div class="card">
        <h3>Total Lines</h3>
        <div class="metric metric--ok">$($report.TotalLines)</div>
        <div class="subtitle">Total log volume processed by LogIQ.</div>
      </div>
    </section>

    <section class="grid">
      <div class="card">
        <h3>Latency Percentiles</h3>
        $latencyHtml
      </div>
      <div class="card">
        <h3>Summary Metrics</h3>
        $summaryHtml
      </div>
    </section>

    <section class="section">
      <h2>Grouped Errors <span class="badge badge-error">Top Patterns</span></h2>
      $groupedErrorsHtml
    </section>

    <section class="section">
      <h2>Service Health Issues <span class="badge badge-warn">Dependencies</span></h2>
      @( $report.ServiceHealth | Select-Object -First 50 ) |
        ConvertTo-Html -Fragment |
        Out-String
    </section>

    <section class="section">
      <h2>Slow API Calls <span class="badge badge-info">Top 50</span></h2>
      @( $report.SlowApis | Select-Object -First 50 ) |
        ConvertTo-Html -Fragment |
        Out-String
    </section>

    <section class="section">
      <h2>Raw Errors <span class="badge badge-error">First 50</span></h2>
      @( $report.Errors | Select-Object -First 50 ) |
        ConvertTo-Html -Fragment |
        Out-String
    </section>

    <div class="footer">
      LogIQ · Open-source log intelligence for DevOps &amp; SRE · Generated by PowerShell by DG
    </div>
  </div>
</body>
</html>
"@

    $html | Out-File "logiq-report.html" -Encoding UTF8
    Write-Host "📄 HTML report generated: logiq-report.html"
}

Write-Host "✔ Analysis Completed." -ForegroundColor Green
# Also output the report object to console so pwsh shows a summary object
$report