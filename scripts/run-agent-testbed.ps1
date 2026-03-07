param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Args
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
$TestbedScript = Join-Path $RepoRoot "examples/agent_testbed.py"

if (-not (Test-Path $TestbedScript)) {
    throw "[run-agent-testbed] Missing testbed script at $TestbedScript"
}

$UsePyLauncher = $false
$PythonCmd = $null

if ($env:MVAR_PYTHON -and (Test-Path $env:MVAR_PYTHON)) {
    $PythonCmd = $env:MVAR_PYTHON
} elseif (Test-Path (Join-Path $RepoRoot ".venv/Scripts/python.exe")) {
    $PythonCmd = Join-Path $RepoRoot ".venv/Scripts/python.exe"
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $UsePyLauncher = $true
} elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
    $PythonCmd = "python3"
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $PythonCmd = "python"
} else {
    throw "[run-agent-testbed] No Python interpreter found. Install Python 3.10+ or create .venv in the repo root."
}

if (-not $Args -or $Args.Count -eq 0) {
    $Args = @("--scenario", "rag_injection")
}

Push-Location $RepoRoot
try {
    if ($UsePyLauncher) {
        & py -3 $TestbedScript @Args
    } else {
        & $PythonCmd $TestbedScript @Args
    }
} finally {
    Pop-Location
}
