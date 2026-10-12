param(
    [int]$TimeoutSeconds = 240
)
# AGV helper: 确保 Docker Desktop 引擎可用。
# 背景：Codex 免安装版启动器会把 LOCALAPPDATA/APPDATA 重定向到含中文和括号的包路径，
# Docker Desktop 4.83 在该路径下无法创建 unix socket（bind: invalid argument）会直接崩溃。
# 因此本脚本显式把两个变量指回纯 ASCII 的标准路径后再启动引擎。
$ErrorActionPreference = 'Stop'

$env:LOCALAPPDATA = 'C:\Users\50506\AppData\Local'
$env:APPDATA      = 'C:\Users\50506\AppData\Roaming'

function Test-Engine {
    $job = Start-Job { docker version --format '{{.Server.Version}}' 2>&1 }
    if (Wait-Job $job -Timeout 10) {
        $out = Receive-Job $job
        Remove-Job $job -Force -ErrorAction SilentlyContinue
        if ("$out" -match '^\d+\.') { return "$out" }
    }
    Stop-Job $job -ErrorAction SilentlyContinue
    Remove-Job $job -Force -ErrorAction SilentlyContinue
    return $null
}

$v = Test-Engine
if ($v) { Write-Host "Docker engine already up: $v"; exit 0 }

Write-Host 'Docker engine not responding. Starting Docker Desktop with clean env...'
Start-Process -FilePath 'C:\Program Files\Docker\Docker\Docker Desktop.exe'
$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 8
    $v = Test-Engine
    if ($v) { Write-Host "Docker engine up: $v"; exit 0 }
}
Write-Error "Docker engine did not come up within $TimeoutSeconds s. Check C:\Users\50506\AppData\Local\Docker\log\host\com.docker.backend.exe.log"
exit 1
