param(
    [string]$Container = 'Mulval2',
    [string]$Python = 'D:/Conda/python.exe',
    [string]$Dot = 'D:/Conda/Graphviz/bin/dot.exe'
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$inputDir = Join-Path $projectRoot 'data/inputs/hongri7'
$outputDir = Join-Path $projectRoot 'output/hongri7'
$rules = @{
    'rules5.P' = @{
        path = Join-Path $inputDir 'rules5.P'
        expectedHash = '71D703B26423E84E742E8E91670CB31C81E50AAF984951F283430D961300B6A8'
    }
    'rules5_v2.P' = @{
        path = Join-Path $inputDir 'rules5_v2.P'
        expectedHash = '8DD7B85D25BECAE581BD55013A508364100FF4359604F25358A3523A73E10D8F'
    }
}
$ruleHashes = [ordered]@{}
foreach ($ruleName in $rules.Keys) {
    $ruleHash = (Get-FileHash -LiteralPath $rules[$ruleName].path).Hash
    if ($ruleHash -ne $rules[$ruleName].expectedHash) { throw ($ruleName + ' hash mismatch; rules were not regenerated.') }
    $ruleHashes[$ruleName] = $ruleHash
}
$profiles = @(
    @{ name = 'Hongri7'; rule = 'rules5.P' },
    @{ name = 'Hongri7_compat'; rule = 'rules5.P' },
    @{ name = 'Hongri7_v2'; rule = 'rules5_v2.P' }
)
$containerState = & docker inspect $Container --format '{{.State.Running}}'
if ($LASTEXITCODE -ne 0) { throw 'Mulval2 container not found.' }
if ($containerState -ne 'true') {
    & docker start $Container
    if ($LASTEXITCODE -ne 0) { throw 'Could not start Mulval2.' }
}
$runStamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd_HHmmss') + '_' + [guid]::NewGuid().ToString('N').Substring(0,8)
$containerRoot = '/tmp/agv_hongri7_' + $runStamp
$rawDir = Join-Path $outputDir ('runs/' + $runStamp)
$null = New-Item -ItemType Directory -Path $rawDir -Force
& docker exec $Container mkdir -p $containerRoot
if ($LASTEXITCODE -ne 0) { throw 'Could not prepare generator directory.' }
foreach ($ruleName in $rules.Keys) {
    & docker cp $rules[$ruleName].path ('{0}:{1}/{2}' -f $Container,$containerRoot,$ruleName)
    if ($LASTEXITCODE -ne 0) { throw ('Could not copy rule file: ' + $ruleName) }
}
$results = @()
Push-Location $projectRoot
try {
    foreach ($profile in $profiles) {
        $name = $profile.name
        $ruleName = $profile.rule
        $factPath = Join-Path $inputDir ($name + '.P')
        $containerWork = $containerRoot + '/' + $name
        & docker exec $Container mkdir -p $containerWork
        if ($LASTEXITCODE -ne 0) { throw 'Could not prepare per-graph directory.' }
        & docker cp $factPath ('{0}:{1}/input.P' -f $Container,$containerWork)
        if ($LASTEXITCODE -ne 0) { throw 'Could not copy facts.' }
        $runLog = & docker exec -w $containerWork $Container /root/mulval/utils/graph_gen.sh ($containerWork + '/input.P') -r ($containerRoot + '/' + $ruleName) -l 2>&1
        $generatorExit = $LASTEXITCODE
        $runLog | Set-Content -LiteralPath (Join-Path $rawDir ($name + '.generation.log')) -Encoding utf8
        & docker cp ('{0}:{1}' -f $Container,$containerWork) $rawDir
        if ($LASTEXITCODE -ne 0 -or $generatorExit -ne 0) { throw ('MulVAL failed: ' + $name + '; inspect ' + $rawDir) }
        $txtPath = Join-Path $inputDir ($name + '.txt')
        Copy-Item -LiteralPath (Join-Path $rawDir ($name + '/AttackGraph.txt')) -Destination $txtPath -Force
        & $Python -B -X utf8 scripts/project_graph.py $txtPath --output-dir $outputDir --strict --force --dot-executable $Dot --host-map (Join-Path $inputDir 'host_ip_map.csv') --assets (Join-Path $inputDir 'assets.json')
        if ($LASTEXITCODE -ne 0) { throw ('V1 projection failed: ' + $name) }
        $graph = Get-Content -LiteralPath (Join-Path $outputDir ('json/' + $name + '.action_graph.json')) -Raw | ConvertFrom-Json
        $results += [ordered]@{name=$name;rule=$ruleName;facts_sha256=(Get-FileHash -LiteralPath $factPath).Hash;txt_sha256=(Get-FileHash -LiteralPath $txtPath).Hash;summary=$graph.summary}
    }
    foreach ($ruleName in $rules.Keys) {
        if ((Get-FileHash -LiteralPath $rules[$ruleName].path).Hash -ne $ruleHashes[$ruleName]) { throw ($ruleName + ' changed during generation.') }
    }
    $manifest = [ordered]@{
        generated_at=(Get-Date).ToUniversalTime().ToString('o')
        container=$Container
        image=(& docker inspect $Container --format '{{.Image}}')
        rules_sha256=$ruleHashes
        container_work_dir=$containerRoot
        raw_dir=$rawDir
        results=$results
        note='Graphs are unmeasured models. Hongri7/Hongri7_compat use frozen rules5.P; Hongri7_v2 uses rules5_v2.P for Windows credential remote execution.'
    }
    $manifest | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $outputDir 'generation.json') -Encoding utf8
} finally {
    Pop-Location
}
