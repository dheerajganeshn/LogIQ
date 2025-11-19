<#
=====================================================================================
 LOGIQ — ENTERPRISE LOG ANALYZER
=====================================================================================
#>

param(
    [string]$LogPath = ".",
    [switch]$JsonReport,
    [switch]$HtmlReport,
    [switch]$Tail
)

Write-Host "`n🔍 Starting LogIQ Enterprise Log Analyzer..." -ForegroundColor Cyan

# -----------------------------------------------------------------------------------
# 1. INITIALIZE BUCKETS & REGEX PATTERNS
# -----------------------------------------------------------------------------------

$script:errors         = @()
$script:timeouts       = @()
$script:slowApis       = @()
$script:correlationMap = @{}
$script:transactions   = @()
$script:serviceHealth  = @()
$script:jsonEntries    = @()

$script:regexError       = "ERROR|Exception|Traceback"
$script:regexTimeout     = "timeout|Timedout|SCREEN_TIMEDOUT"
$script:regexApi         = 'completeReqTTms="(\d+)"'
$script:regexCorrelation = '\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b'

# ---------------------------
# PAYMENT + TRANSACTION FLOW
# ---------------------------
$script:transactionsFlow   = @{}
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
            TransactionId      = $tid
            PapiRequest        = $false
            PapiResponse       = $null
            TapiRequest        = $false
            TapiResponse       = $null
            TapiKinesisSuccess = $false
            WebSocketDrop      = $false
            ExceptionOffline   = $false
            SchedulerJobs      = @()
            Lines              = @()
            Abnormal           = $false
        }
    }
}

# -----------------------------------------------------------------------------------
# 2. PER-LINE PROCESSOR
# -----------------------------------------------------------------------------------

function Process-Line {
    param([string]$line)

    if (-not $line) { return }

    # JSON logs
    if ($line.Trim().StartsWith("{")) {
        try {
            $jsonObj = $line | ConvertFrom-Json
            $script:jsonEntries += $jsonObj

            if ($jsonObj.level -eq "error" -or $jsonObj.status -eq 500) {
                $script:errors += $line
            }

            if ($jsonObj.PSObject.Properties.Name -contains "durationMs") {
                if ([int]$jsonObj.durationMs -gt 300) {
                    $script:slowApis += "$($jsonObj.durationMs) ms : $line"
                }
            }
        } catch { }
    }

    # Plain errors
    if ($line -match $script:regexError) {
        $script:errors += $line
    }

    # Timeouts
    if ($line -match $script:regexTimeout) {
        $script:timeouts += $line
    }

    # API latency
    if ($line -match $script:regexApi) {
        $ms = [int]$Matches[1]
        if ($ms -gt 300) {
            $script:slowApis += "$ms ms : $line"
        }
    }

    # Correlation IDs
    if ($line -match $script:regexCorrelation) {
        $cid = $Matches[0]
        if (-not $script:correlationMap.ContainsKey($cid)) {
            $script:correlationMap[$cid] = @()
        }
        $script:correlationMap[$cid] += $line
    }

    # Service health
    if ($line -match "Failed to connect|statusCode=""0""|Unable to connect|SyncServiceHealthy:false") {
        $script:serviceHealth += $line
    }

    # ---------------------------------------------
    # PAYMENT + TRANSACTION ANALYSIS
    # ---------------------------------------------
    $tid = $null

    # Case 1: explicit transactionId field
    if ($line -match $script:regexTransactionId) {
        $tid = $Matches[1]
    }
    # Case 2: standalone UUID in line (like 445e188c-...)
    elseif ($line -match $script:regexCorrelation) {
        $tid = $Matches[0]
    }

    if ($tid) {
        Ensure-Transaction $tid
        $script:transactionsFlow[$tid].Lines += $line

        # PAPI Request
        if ($line -match $script:regexPapiReq) {
            $script:transactionsFlow[$tid].PapiRequest = $true
        }

        # PAPI Response
        if ($line -match $script:regexPapiResp) {
            $code   = [int]$Matches[1]
            $status = $Matches[2]
            $script:transactionsFlow[$tid].PapiResponse = "$code $status"
        }

        # TAPI Request
        if ($line -match $script:regexTapiReq) {
            $script:transactionsFlow[$tid].TapiRequest = $true
        }

        # TAPI Response (201)
        if ($line -match $script:regexTapiResp) {
            $script:transactionsFlow[$tid].TapiResponse = "201 SUCCESS"
        }

        # DynamoDB + Kinesis success
        if ($line -match 'Documents successfully sent to kinesis and saved to DynamoDB') {
            $script:transactionsFlow[$tid].TapiKinesisSuccess = $true
        }

        # WebSocket disconnect
        if ($line -match $script:regexWsDisconnect) {
            $script:transactionsFlow[$tid].WebSocketDrop = $true
        }

        # TAPI offline/exception
        if ($line -match $script:regexExceptionTapi) {
            $script:transactionsFlow[$tid].ExceptionOffline = $true
        }
    }

    # Scheduler logs apply globally
    if ($line -match $script:regexScheduler) {
        foreach ($id in $script:transactionsFlow.Keys) {
            $script:transactionsFlow[$id].SchedulerJobs += $line
        }
    }
}

# -----------------------------------------------------------------------------------
# 3. TAIL MODE
# -----------------------------------------------------------------------------------

if ($Tail) {
    if (-not (Test-Path $LogPath)) {
        Write-Host "❌ Tail mode: Log path '$LogPath' does not exist." -ForegroundColor Red
        exit 1
    }

    Write-Host "📡 Real-time monitoring enabled (tail mode). Press Ctrl+C to stop." -ForegroundColor Yellow
    Get-Content $LogPath -Wait -Tail 50 | ForEach-Object { Process-Line $_ }
    exit 0
}

# -----------------------------------------------------------------------------------
# 4. LOAD LOGS (BATCH)
# -----------------------------------------------------------------------------------

if (Test-Path $LogPath -PathType Container) {
    $logs = Get-ChildItem -Path $LogPath -Include *.log, *.txt, *.out, *.json -Recurse |
            ForEach-Object { Get-Content $_.FullName }
} elseif (Test-Path $LogPath -PathType Leaf) {
    $logs = Get-Content $LogPath
} else {
    Write-Host "❌ Log path '$LogPath' not found." -ForegroundColor Red
    exit 1
}

foreach ($line in $logs) {
    Process-Line $line
}

# -----------------------------------------------------------------------------------
# 5. LATENCY METRICS
# -----------------------------------------------------------------------------------

$latencies = @()
foreach ($entry in $script:slowApis) {
    $msText = $entry.Split(" ")[0]
    $ms = 0
    [int]::TryParse($msText, [ref]$ms) | Out-Null
    if ($ms -gt 0) { $latencies += $ms }
}

$p50 = $null; $p90 = $null; $p99 = $null
if ($latencies.Count -gt 0) {
    $sorted = $latencies | Sort-Object
    $p50 = $sorted[ [int]([Math]::Min($sorted.Count - 1, [Math]::Floor($sorted.Count * 0.50))) ]
    $p90 = $sorted[ [int]([Math]::Min($sorted.Count - 1, [Math]::Floor($sorted.Count * 0.90))) ]
    $p99 = $sorted[ [int]([Math]::Min($sorted.Count - 1, [Math]::Floor($sorted.Count * 0.99))) ]
}

# -----------------------------------------------------------------------------------
# 6. ERROR GROUPING
# -----------------------------------------------------------------------------------

$groupedErrors = $script:errors |
    Group-Object { $_.Substring(0, [Math]::Min(80, $_.Length)) } |
    Select-Object Name, Count |
    Sort-Object Count -Descending

# -----------------------------------------------------------------------------------
# 7. TRANSACTION FLOW SUMMARY + PER-TX LOGS
# -----------------------------------------------------------------------------------

$transactionSummaries = @()

foreach ($tid in $script:transactionsFlow.Keys) {
    $t = $script:transactionsFlow[$tid]

    $root = "UNKNOWN"

    if (-not $t.PapiRequest) {
        $root = "Missing PAPI Request"
    }
    elseif (-not $t.PapiResponse) {
        $root = "Missing PAPI Response"
    }
    elseif ($t.WebSocketDrop) {
        $root = "WebSocket Disconnect between PAPI & TAPI"
    }
    elseif (-not $t.TapiRequest) {
        $root = "Missing TAPI Request"
    }
    elseif (-not $t.TapiResponse) {
        if ($t.ExceptionOffline) { $root = "TAPI sent to Offline Table" }
        else { $root = "Missing TAPI Response" }
    }
    elseif ($t.TapiResponse -eq "201 SUCCESS" -and $t.TapiKinesisSuccess) {
        $root = "OK"
    }
    elseif ($t.TapiResponse -eq "201 SUCCESS" -and -not $t.TapiKinesisSuccess) {
        $root = "Missing Kinesis + DynamoDB Success Message"
    }

    $txObj = [PSCustomObject]@{
        TransactionId       = $tid
        PAPI                = $t.PapiResponse
        TAPI                = $t.TapiResponse
        TapiKinesisSuccess  = if ($t.TapiKinesisSuccess) { "YES" } else { "NO" }
        WebSocket           = if ($t.WebSocketDrop) { "Disconnected" } else { "OK" }
        OfflineHandling     = $t.ExceptionOffline
        SchedulerJobs       = $t.SchedulerJobs.Count
        RootCause           = $root
    }

    $abnormal = $false
    if ($root -ne "OK") { $abnormal = $true }
    if ($t.SchedulerJobs.Count -eq 0 -and $t.ExceptionOffline) { $abnormal = $true }
    if ($t.PapiResponse -match '^4' -or $t.PapiResponse -match '^5') { $abnormal = $true }
    if ($t.TapiResponse -match '^4' -or $t.TapiResponse -match '^5') { $abnormal = $true }

    $t.Abnormal = $abnormal
    $transactionSummaries += $txObj
}

# Success / Failed lists (used in CSV + HTML)
$successTx = $transactionSummaries | Where-Object { $_.RootCause -eq "OK" }
$failedTx  = $transactionSummaries | Where-Object { $_.RootCause -ne "OK" }

# Per-transaction grouped logs (TX ID + line)
$transactionLogRows = @()
foreach ($tid in $script:transactionsFlow.Keys) {
    foreach ($l in $script:transactionsFlow[$tid].Lines) {
        $transactionLogRows += [PSCustomObject]@{
            TransactionId = $tid
            Line          = $l
        }
    }
}

# -----------------------------------------------------------------------------------
# 8. BUILD MAIN REPORT OBJECT
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

$report | Add-Member -MemberType NoteProperty -Name TransactionFlow       -Value $transactionSummaries
$report | Add-Member -MemberType NoteProperty -Name AbnormalTransactions -Value $failedTx

# -----------------------------------------------------------------------------------
# 9. CSV REPORTS (SUCCESS, FAILED, PER-TX LOGS)
# -----------------------------------------------------------------------------------

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

$report.Errors |
    ForEach-Object { [PSCustomObject]@{ Line = $_ } } |
    Export-Csv "logiq-errors.csv" -NoTypeInformation -Encoding UTF8

$report.Timeouts |
    ForEach-Object { [PSCustomObject]@{ Line = $_ } } |
    Export-Csv "logiq-timeouts.csv" -NoTypeInformation -Encoding UTF8

$report.SlowApis |
    ForEach-Object { [PSCustomObject]@{ Line = $_ } } |
    Export-Csv "logiq-slowapis.csv" -NoTypeInformation -Encoding UTF8

$report.ServiceHealth |
    ForEach-Object { [PSCustomObject]@{ Line = $_ } } |
    Export-Csv "logiq-servicehealth.csv" -NoTypeInformation -Encoding UTF8

# Per-transaction summary
$transactionSummaries |
    Export-Csv "logiq-transactions.csv" -NoTypeInformation -Encoding UTF8

# Success list
$successTx |
    Export-Csv "logiq-success-transactions.csv" -NoTypeInformation -Encoding UTF8

# Failed list
$failedTx |
    Export-Csv "logiq-failed-transactions.csv" -NoTypeInformation -Encoding UTF8

# Transactions missing DynamoDB+Kinesis success
$transactionSummaries |
    Where-Object { $_.RootCause -eq "Missing Kinesis + DynamoDB Success Message" } |
    Export-Csv "logiq-tapi-missing-dynamodb.csv" -NoTypeInformation -Encoding UTF8

# Per-transaction grouped logs
$transactionLogRows |
    Export-Csv "logiq-transaction-logs.csv" -NoTypeInformation -Encoding UTF8

Write-Host "📄 CSV reports generated: summary/errors/timeouts/slowapis/servicehealth/transactions*.csv"

# -----------------------------------------------------------------------------------
# 10. JSON REPORT (OPTIONAL)
# -----------------------------------------------------------------------------------

if ($JsonReport) {
    $report | ConvertTo-Json -Depth 6 | Out-File "logiq-report.json"
    Write-Host "📄 JSON report generated: logiq-report.json"
}

# -----------------------------------------------------------------------------------
# 11. HTML DASHBOARD (SUCCESS / FAILED / PER-TX LOGS)
# -----------------------------------------------------------------------------------

if ($HtmlReport) {

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

    $summaryHtml        = $summaryData         | ConvertTo-Html -Fragment | Out-String
    $latencyHtml        = $latencyData         | ConvertTo-Html -Fragment | Out-String
    $groupedErrorsHtml  = $report.GroupedErrors | ConvertTo-Html -Fragment | Out-String

    $successCount = $successTx.Count
    $failedCount  = $failedTx.Count
    $totalTx      = $transactionSummaries.Count

    $successTxHtml = if ($successTx.Count -gt 0) {
        ($successTx |
            Select-Object TransactionId,PAPI,TAPI,TapiKinesisSuccess,WebSocket,OfflineHandling,RootCause |
            ConvertTo-Html -Fragment | Out-String)
    } else { "<p>No successful transactions.</p>" }

    $failedTxHtml = if ($failedTx.Count -gt 0) {
        ($failedTx |
            Select-Object TransactionId,PAPI,TAPI,TapiKinesisSuccess,WebSocket,OfflineHandling,RootCause |
            ConvertTo-Html -Fragment | Out-String)
    } else { "<p>No failed transactions.</p>" }

    # Per-transaction logs (first N rows to keep HTML reasonable)
    $txLogsSample = $transactionLogRows | Select-Object TransactionId, Line -First 200
    $transactionLogsHtml = if ($txLogsSample.Count -gt 0) {
        ($txLogsSample | ConvertTo-Html -Fragment | Out-String)
    } else { "<p>No transaction logs captured.</p>" }

    $timestamp = $report.Timestamp

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
    h1 { font-size: 28px; margin-bottom: 4px; }
    h2 { font-size: 20px; margin-top: 24px; }
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
    .metric--error { color: #f97373; }
    .metric--warn  { color: #fbbf24; }
    .metric--ok    { color: #4ade80; }
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
    tr:nth-child(even) td { background-color: #020617; }
    tr:nth-child(odd)  td { background-color: #030712; }
    .section { margin-top: 24px; }
    .badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 10px;
      letter-spacing: 0.05em;
      text-transform: uppercase;
      margin-left: 8px;
    }
    .badge-error { background-color: rgba(248,113,113,0.12); color: #fecaca; border: 1px solid rgba(248,113,113,0.5); }
    .badge-warn  { background-color: rgba(234,179,8,0.12);  color: #fef3c7; border: 1px solid rgba(234,179,8,0.5); }
    .badge-info  { background-color: rgba(59,130,246,0.12); color: #bfdbfe; border: 1px solid rgba(59,130,246,0.5); }
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
        <div class="subtitle">Total error lines detected.</div>
      </div>
      <div class="card">
        <h3>Timeouts</h3>
        <div class="metric metric--warn">$($report.TimeoutCount)</div>
        <div class="subtitle">Timeout-related log entries.</div>
      </div>
      <div class="card">
        <h3>Slow APIs</h3>
        <div class="metric metric--warn">$($report.SlowApiCount)</div>
        <div class="subtitle">Requests above latency threshold.</div>
      </div>
      <div class="card">
        <h3>Service Health</h3>
        <div class="metric $(if ($report.ServiceHealthIssues -gt 0) { 'metric--error' } else { 'metric--ok' })">
          $($report.ServiceHealthIssues)
        </div>
        <div class="subtitle">Connectivity / dependency issues.</div>
      </div>
      <div class="card">
        <h3>Transactions (OK / Failed)</h3>
        <div class="metric metric--ok">$successCount / $failedCount</div>
        <div class="subtitle">$totalTx total transactions traced.</div>
      </div>
      <div class="card">
        <h3>Total Lines</h3>
        <div class="metric metric--ok">$($report.TotalLines)</div>
        <div class="subtitle">Total log volume processed.</div>
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
      <h2>Successful Transactions <span class="badge badge-info">RootCause = OK</span></h2>
      $successTxHtml
    </section>

    <section class="section">
      <h2>Failed Transactions <span class="badge badge-error">RootCause != OK</span></h2>
      $failedTxHtml
    </section>

    <section class="section">
      <h2>Per-Transaction Logs <span class="badge badge-info">First 200 Lines</span></h2>
      $transactionLogsHtml
    </section>

    <div class="footer">
      LogIQ · Log intelligence for DevOps &amp; SRE · Generated by PowerShell
    </div>
  </div>
</body>
</html>
"@

    $html | Out-File "logiq-report.html" -Encoding UTF8
    Write-Host "📄 HTML report generated: logiq-report.html"
}

Write-Host "✔ Analysis Completed." -ForegroundColor Green
$report