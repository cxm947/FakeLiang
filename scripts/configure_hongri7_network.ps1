#Requires -RunAsAdministrator
# VMware vnetlib usage: https://github.com/hashicorp/vagrant-vmware-desktop/blob/main/VNETLIB.md
$ErrorActionPreference = 'Stop'
$labRoot = 'E:\VMwareLabs\Hongri7'
$labVmware = 'D:\常用软件安装\Vmware'
$labVnet = Join-Path $labVmware 'vnetlib64.exe'
$labVmrun = Join-Path $labVmware 'vmrun.exe'
$labResult = Join-Path $labRoot 'evidence\network-setup-result.json'
$labLog = Join-Path $labRoot 'evidence\network-setup.log'
$labBackup = Join-Path $labRoot ('backups\network-' + (Get-Date -Format 'yyyyMMdd_HHmmss'))
$labServicesStopped = $false
Start-Transcript -Path $labLog -Append | Out-Null

function Invoke-LabVnet {
    param([string[]]$Arguments)
    Write-Output ('vnetlib64 -- ' + ($Arguments -join ' '))
    & $labVnet -- @Arguments
    # vnetlib uses inconsistent exit codes; verify the resulting network state.
    Write-Output ('native exit code: ' + $LASTEXITCODE)
}

try {
    $labRunning = & $labVmrun list
    if ($LASTEXITCODE -ne 0 -or ($labRunning -join "`n") -match '\.vmx') {
        throw 'Power off virtual machines before changing host virtual networks.'
    }
    if (Get-Process vmnetcfg -ErrorAction SilentlyContinue) {
        throw 'Close Virtual Network Editor before running this script.'
    }
    $labBefore = (& $labVmrun listHostNetworks) -join "`n"
    if ($labBefore -notmatch '(?m)^8\s+vmnet8\s+nat\s+true\s+192\.168\.(137|52)\.0\s+255\.255\.255\.0') {
        throw 'VMnet8 differs from the inspected configuration; no changes made.'
    }
    if ($labBefore -match '(?m)^14\s+' -and $labBefore -notmatch '(?m)^14\s+vmnet14\s+hostOnly\s+\w+\s+(192\.168\.93\.0|empty)\s+255\.255\.255\.0') {
        throw 'VMnet14 already exists with another configuration; no changes made.'
    }
    New-Item -ItemType Directory -Path $labBackup -Force | Out-Null
    $labBefore | Set-Content -LiteralPath (Join-Path $labBackup 'host-networks.txt') -Encoding UTF8
    Copy-Item -LiteralPath 'C:\ProgramData\VMware\vmnetnat.conf','C:\ProgramData\VMware\vmnetdhcp.conf' -Destination $labBackup
    & reg.exe export 'HKLM\SOFTWARE\WOW6432Node\VMware, Inc.\VMnetLib' (Join-Path $labBackup 'vmnetlib.reg') /y
    if ($LASTEXITCODE -ne 0) { throw 'Could not back up VMware network registry.' }
    & reg.exe export 'HKLM\SYSTEM\CurrentControlSet\Services\VMnetDHCP\Parameters' (Join-Path $labBackup 'dhcp-parameters.reg') /y
    if ($LASTEXITCODE -ne 0) { throw 'Could not back up VMware DHCP registry.' }

    if ($labBefore -notmatch '(?m)^14\s+') {
        Invoke-LabVnet -Arguments @('add','adapter','vmnet14')
        $labCreated = (& $labVmrun listHostNetworks) -join "`n"
        if ($labCreated -notmatch '(?m)^14\s+vmnet14\s+hostOnly') {
            throw 'VMnet14 creation could not be verified; VMnet8 unchanged.'
        }
    }

    $labServicesStopped = $true
    Stop-Service -Name 'VMnetDHCP','VMware NAT Service'
    Invoke-LabVnet -Arguments @('set','vnet','vmnet14','addr','192.168.93.0')
    Invoke-LabVnet -Arguments @('set','vnet','vmnet14','mask','255.255.255.0')
    Invoke-LabVnet -Arguments @('add','dhcp','vmnet14')
    Invoke-LabVnet -Arguments @('update','adapter','vmnet14')
    Invoke-LabVnet -Arguments @('update','dhcp','vmnet14')
    Invoke-LabVnet -Arguments @('set','vnet','vmnet8','addr','192.168.52.0')
    Invoke-LabVnet -Arguments @('set','vnet','vmnet8','mask','255.255.255.0')
    Invoke-LabVnet -Arguments @('update','adapter','vmnet8')
    Invoke-LabVnet -Arguments @('update','dhcp','vmnet8')
    Invoke-LabVnet -Arguments @('update','nat','vmnet8')
    # This Workstation build updates adapter/registry state but leaves the
    # existing service files unchanged. Align only VMnet8 and the new VMnet14.
    $labNatPath = 'C:\ProgramData\VMware\vmnetnat.conf'
    $labDhcpPath = 'C:\ProgramData\VMware\vmnetdhcp.conf'
    $labNatText = Get-Content -Raw -LiteralPath $labNatPath
    if ($labNatText -notmatch '(?m)^ip\s*=\s*192\.168\.(137|52)\.2/24\s*$') {
        throw 'Unexpected NAT gateway in service configuration.'
    }
    $labNatText = $labNatText -replace '(?m)^ip\s*=\s*192\.168\.(137|52)\.2/24\s*$', 'ip = 192.168.52.2/24'
    [IO.File]::WriteAllText($labNatPath, $labNatText, [Text.Encoding]::ASCII)
    $labDhcpText = Get-Content -Raw -LiteralPath $labDhcpPath
    $labDhcpSegment = '(?ms)^# Virtual ethernet segment 8\r?\n.*?^# End\r?$'
    if ($labDhcpText -notmatch $labDhcpSegment) { throw 'Cannot identify VMnet8 DHCP section.' }
    $labDhcpText = [regex]::Replace($labDhcpText, $labDhcpSegment, {
        param($match)
        $match.Value.Replace('192.168.137.', '192.168.52.')
    })
    if ($labDhcpText -notmatch '(?m)^# Virtual ethernet segment 14\r?$') {
        $labMac14 = (Get-NetAdapter -Name 'VMware Network Adapter VMnet14').MacAddress.Replace('-', ':')
        $labDhcpText += @"

# Virtual ethernet segment 14
# Added for Hongri7
subnet 192.168.93.0 netmask 255.255.255.0 {
range 192.168.93.128 192.168.93.254;
option broadcast-address 192.168.93.255;
option domain-name-servers 192.168.93.1;
option domain-name "localdomain";
default-lease-time 1800;
max-lease-time 7200;
}
host VMnet14 {
    hardware ethernet $labMac14;
    fixed-address 192.168.93.1;
    option domain-name-servers 0.0.0.0;
    option domain-name "";
}
# End
"@
    }
    [IO.File]::WriteAllText($labDhcpPath, $labDhcpText, [Text.Encoding]::ASCII)
    # VMnetDHCP reads interface addresses from its own service registry, too.
    $labDhcpRegistry = 'HKLM:\SYSTEM\CurrentControlSet\Services\VMnetDHCP\Parameters\VirtualEthernetSegments'
    foreach ($labSegment in @(@{id=8;ip='192.168.52.1'}, @{id=14;ip='192.168.93.1'})) {
        $labSegmentKey = Join-Path $labDhcpRegistry ([string]$labSegment.id)
        New-Item -Path $labSegmentKey -Force | Out-Null
        $labIpBytes = [Net.IPAddress]::Parse($labSegment.ip).GetAddressBytes()
        $labIpDword = [BitConverter]::ToUInt32($labIpBytes, 0)
        New-ItemProperty -LiteralPath $labSegmentKey -Name HostIpAddress -PropertyType DWord -Value $labIpDword -Force | Out-Null
        New-ItemProperty -LiteralPath $labSegmentKey -Name ListenTo -PropertyType DWord -Value 1 -Force | Out-Null
    }
    Start-Service -Name 'VMnetDHCP','VMware NAT Service'
    $labServicesStopped = $false

    $labAfter = (& $labVmrun listHostNetworks) -join "`n"
    $labIPs = @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -match 'VMware' } | Select-Object InterfaceAlias,IPAddress,PrefixLength)
    $labNat = Get-Content -Raw -LiteralPath 'C:\ProgramData\VMware\vmnetnat.conf'
    if ($labAfter -notmatch '(?m)^8\s+vmnet8\s+nat\s+true\s+192\.168\.52\.0' -or
        $labAfter -notmatch '(?m)^14\s+vmnet14\s+hostOnly\s+true\s+192\.168\.93\.0' -or
        $labNat -notmatch '(?m)^ip\s*=\s*192\.168\.52\.2/24' -or
        '192.168.52.1' -notin $labIPs.IPAddress -or '192.168.93.1' -notin $labIPs.IPAddress) {
        throw ('Network verification failed: ' + $labAfter)
    }
    @{complete=$true; updated_at=(Get-Date).ToString('o'); backup=$labBackup; networks=$labAfter; addresses=$labIPs} |
        ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $labResult -Encoding UTF8
} catch {
    @{complete=$false; updated_at=(Get-Date).ToString('o'); backup=$labBackup; error=$_.Exception.Message} |
        ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $labResult -Encoding UTF8
    throw
} finally {
    if ($labServicesStopped) { Start-Service -Name 'VMnetDHCP','VMware NAT Service' -ErrorAction Continue }
    Stop-Transcript | Out-Null
}
