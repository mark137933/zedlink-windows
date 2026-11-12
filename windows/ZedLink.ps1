[CmdletBinding()]
param(
    [ValidateSet('Setup', 'Start', 'Stop', 'Pair', 'Status')]
    [string]$Action = 'Status',
    [string]$ProjectPath,
    [string]$CertificatePath,
    [string]$PrivateKeyPath,
    [string]$HttpsOrigin,
    [string]$BindAddress = '127.0.0.1:7443',
    [string]$StateRoot = (Join-Path $PSScriptRoot 'data')
)
$ErrorActionPreference = 'Stop'
$gateway = Join-Path $PSScriptRoot 'zedlink-gateway.exe'
$zed = Join-Path $PSScriptRoot 'Zed.exe'
$StateRoot = [IO.Path]::GetFullPath($StateRoot)
$gatewayState = Join-Path $StateRoot 'gateway'
$configuration = Join-Path $StateRoot 'launch.json'
$profile = Join-Path $StateRoot 'profile'
$listeners = Join-Path $StateRoot 'listeners.json'
$endpoint = Join-Path $StateRoot 'probe/zedlink.sock'
$utf8 = New-Object System.Text.UTF8Encoding($false)

function New-PrivateDirectory([string]$Path) {
    if (Test-Path -LiteralPath $Path) { throw "Setup destination already exists: $Path" }
    [IO.Directory]::CreateDirectory($Path) | Out-Null
    $owner = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetOwner($owner)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($identity in @($owner, $system)) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Write-Json([string]$Path, $Value) {
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 12), $utf8)
    Set-PrivateFile $Path
}

function Set-PrivateFile([string]$Path) {
    $owner = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $acl = New-Object Security.AccessControl.FileSecurity
    $acl.SetOwner($owner)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($identity in @($owner, $system)) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'Allow')))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Test-GatewayReady {
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $gateway
    $start.Arguments = 'admin "{0}" devices' -f $gatewayState
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    try {
        $process.Start() | Out-Null
        $output = $process.StandardOutput.ReadToEndAsync()
        $errors = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(5000)) { $process.Kill(); return $false }
        return $process.ExitCode -eq 0
    } finally { $process.Dispose() }
}

if ($Action -eq 'Setup') {
    foreach ($value in @($ProjectPath, $CertificatePath, $PrivateKeyPath, $HttpsOrigin)) {
        if ([string]::IsNullOrWhiteSpace($value)) { throw 'Setup requires ProjectPath, CertificatePath, PrivateKeyPath and HttpsOrigin.' }
    }
    $project = (Resolve-Path -LiteralPath $ProjectPath).Path
    if (-not (Test-Path -LiteralPath $project -PathType Container)) { throw 'ProjectPath must be an existing test project directory.' }
    $certificate = (Resolve-Path -LiteralPath $CertificatePath).Path
    $key = (Resolve-Path -LiteralPath $PrivateKeyPath).Path
    $origin = [Uri]$HttpsOrigin
    if (-not $origin.IsAbsoluteUri -or $origin.Scheme -ne 'https' -or $origin.UserInfo -or $origin.Query -or $origin.Fragment -or $origin.AbsolutePath -ne '/') {
        throw 'HttpsOrigin must be a plain HTTPS origin with a certificate trusted by the client.'
    }
    New-PrivateDirectory $StateRoot
    foreach ($directory in @($gatewayState, $profile, (Join-Path $profile 'config'), (Join-Path $StateRoot 'probe'), (Join-Path $StateRoot 'tls'))) {
        New-PrivateDirectory $directory
    }
    # Write new files into the protected directory so source ACLs are not copied.
    [IO.File]::WriteAllBytes((Join-Path $StateRoot 'tls/cert.pem'), [IO.File]::ReadAllBytes($certificate))
    [IO.File]::WriteAllBytes((Join-Path $StateRoot 'tls/key.pem'), [IO.File]::ReadAllBytes($key))
    Set-PrivateFile (Join-Path $StateRoot 'tls/cert.pem')
    Set-PrivateFile (Join-Path $StateRoot 'tls/key.pem')
    Write-Json $listeners @{ version=1; listeners=@(@{ id='primary'; bind=$BindAddress; url=$origin.GetLeftPart([UriPartial]::Authority); cert=(Join-Path $StateRoot 'tls/cert.pem'); key=(Join-Path $StateRoot 'tls/key.pem') }) }
    Write-Json $configuration @{ project=$project; origin=$origin.GetLeftPart([UriPartial]::Authority) }
    Write-Json (Join-Path $profile 'config/settings.json') @{ auto_update=$false; telemetry=@{ diagnostics=$false; metrics=$false }; zedlink=@{ enabled=$true; state_directory=$StateRoot; project_root=$project; start_gateway_on_launch=$false; allow_terminal_read=$false; allow_terminal_input=$false; allow_task_start=$false; allow_debugger_start=$false } }
    Write-Host 'Isolated setup created. Configure your model inside this separate Zed profile after Start.'
    exit 0
}

if (-not (Test-Path -LiteralPath $configuration)) { throw 'Run Setup first.' }
if (-not (Test-Path -LiteralPath $gateway)) { throw 'Gateway executable is missing.' }
switch ($Action) {
    'Start' {
        if (-not (Test-Path -LiteralPath $zed)) { throw 'Use the full desktop package to start patched Zed.' }
        $settings = Get-Content -LiteralPath $configuration -Raw | ConvertFrom-Json
        foreach ($argument in @($listeners, $endpoint, $gatewayState, $profile, $settings.project)) {
            if ($argument.Contains('"')) { throw 'Unexpected quote in launch path.' }
        }
        if (-not (Test-GatewayReady)) {
            $arguments = 'serve-routes "{0}" "{1}" "{2}"' -f $listeners, $endpoint, $gatewayState
            Start-Process -FilePath $gateway -ArgumentList $arguments -WindowStyle Hidden -RedirectStandardOutput (Join-Path $StateRoot 'gateway.stdout.log') -RedirectStandardError (Join-Path $StateRoot 'gateway.stderr.log') | Out-Null
            $ready = $false
            for ($attempt=0; $attempt -lt 20; $attempt++) {
                Start-Sleep -Milliseconds 250
                if (Test-GatewayReady) { $ready=$true; break }
            }
            if (-not $ready) { throw 'Gateway did not start. Inspect data/gateway.stderr.log.' }
        }
        $arguments = '--user-data-dir "{0}" "{1}"' -f $profile, $settings.project
        Start-Process -FilePath $zed -ArgumentList $arguments -WindowStyle Normal | Out-Null
        Write-Host "Open $($settings.origin) on the phone, then use Pair and expose a conversation with /remote-control in Zed."
    }
    'Stop' { & $gateway admin $gatewayState shutdown }
    'Pair' { & $gateway admin $gatewayState pair-short-code }
    'Status' { & $gateway admin $gatewayState devices }
}
if ($LASTEXITCODE -ne 0) { throw 'Gateway command failed.' }
