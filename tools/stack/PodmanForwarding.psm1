function Get-SimpleSignPodmanStatePath {
    param([string]$Project)

    $stateDirectory = Join-Path $env:LOCALAPPDATA 'SimpleSign\Stack'
    New-Item -ItemType Directory -Force -Path $stateDirectory | Out-Null
    $hashInput = [Text.Encoding]::UTF8.GetBytes("Podman`n$Project")
    $projectHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($hashInput)).Substring(0, 16).ToLowerInvariant()
    Join-Path $stateDirectory "podman-forwarding-$projectHash.json"
}

function Get-SimpleSignPodmanSshConnection {
    param([string]$Podman)

    $connectionOutput = & $Podman system connection list --format json
    if ($LASTEXITCODE -ne 0) {
        throw "$Podman system connection list failed (exit code $LASTEXITCODE)."
    }

    $connections = @(ConvertFrom-Json -InputObject ($connectionOutput -join [Environment]::NewLine))
    $connection = $connections | Where-Object { $_.Default -and $_.IsMachine } | Select-Object -First 1
    if (-not $connection) {
        throw 'Podman has no default machine SSH connection for localhost forwarding.'
    }

    $uri = [Uri]$connection.URI
    if ($uri.Scheme -ne 'ssh' -or -not $uri.UserInfo -or -not $connection.Identity -or -not (Test-Path -LiteralPath $connection.Identity)) {
        throw "The default Podman connection '$($connection.Name)' does not have a usable SSH URI and identity."
    }

    [pscustomobject]@{
        Host         = $uri.Host
        Port         = $uri.Port
        User         = [Uri]::UnescapeDataString($uri.UserInfo)
        IdentityPath = $connection.Identity
    }
}

function Get-SimpleSignPodmanContainerIp {
    param(
        [string]$Podman,
        [string[]]$ComposeArguments,
        [string]$Service
    )

    $composePsArguments = $ComposeArguments + @('ps', '-q', $Service)
    $containerOutput = & $Podman @composePsArguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Podman compose ps -q $Service failed (exit code $LASTEXITCODE)."
    }

    $containerId = ($containerOutput | Select-Object -First 1)
    if (-not $containerId) {
        throw "Podman Compose did not return a container ID for service '$Service'."
    }

    $ipOutput = & $Podman inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $containerId.Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "$Podman inspect failed for service '$Service' (exit code $LASTEXITCODE)."
    }

    $containerIp = ($ipOutput | Select-Object -First 1).Trim()
    if ($containerIp -notmatch '^(?:\d{1,3}\.){3}\d{1,3}$') {
        throw "Podman did not return an IPv4 container address for service '$Service'."
    }

    $containerIp
}

function Test-SimpleSignLocalTcpPort {
    param([int]$Port)

    $client = [Net.Sockets.TcpClient]::new()
    $connect = $null
    try {
        $connect = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
        if (-not $connect.AsyncWaitHandle.WaitOne(500)) {
            return $false
        }

        $client.EndConnect($connect)
        return $true
    }
    catch [Net.Sockets.SocketException] {
        return $false
    }
    finally {
        if ($connect) {
            $connect.AsyncWaitHandle.Close()
        }

        $client.Dispose()
    }
}

function Start-SimpleSignPodmanForwarding {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Project,
        [string]$Podman,
        [string[]]$ComposeArguments,
        [string]$Service,
        [object[]]$Ports
    )

    $containerIp = Get-SimpleSignPodmanContainerIp -Podman $Podman -ComposeArguments $ComposeArguments -Service $Service
    $connection = Get-SimpleSignPodmanSshConnection -Podman $Podman
    $sshCommand = Get-Command ssh.exe -ErrorAction SilentlyContinue
    if (-not $sshCommand) {
        throw 'Podman Desktop port forwarding requires the Windows OpenSSH Client (ssh.exe) on PATH.'
    }

    $forwardSpecs = @(
        foreach ($port in $Ports) {
            $localPort = [int]$port.LocalPort
            $remotePort = [int]$port.RemotePort
            if ($localPort -lt 1 -or $localPort -gt 65535 -or $remotePort -lt 1 -or $remotePort -gt 65535) {
                throw "Invalid Podman forwarding port: local $localPort, remote $remotePort."
            }

            "127.0.0.1:${localPort}:${containerIp}:${remotePort}"
        }
    )
    if (-not $forwardSpecs) {
        throw "No ports were provided for Podman service '$Service'."
    }

    $sshArguments = @(
        '-q',
        '-N',
        '-o', 'BatchMode=yes',
        '-o', 'ExitOnForwardFailure=yes',
        '-o', 'ConnectTimeout=10',
        '-o', 'ServerAliveInterval=30',
        '-o', 'ServerAliveCountMax=3',
        '-o', 'StrictHostKeyChecking=accept-new',
        '-i', $connection.IdentityPath,
        '-p', [string]$connection.Port
    )
    foreach ($forwardSpec in $forwardSpecs) {
        $sshArguments += @('-L', $forwardSpec)
    }

    $sshArguments += "$($connection.User)@$($connection.Host)"
    if (-not $PSCmdlet.ShouldProcess("Podman service '$Service' ($($forwardSpecs -join ', '))", 'Start SSH tunnel')) {
        return
    }

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $sshCommand.Source
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    foreach ($argument in $sshArguments) {
        [void]$startInfo.ArgumentList.Add($argument)
    }

    $process = [Diagnostics.Process]::Start($startInfo)
    if (-not $process) {
        throw "Could not start the SSH tunnel for Podman service '$Service'."
    }

    try {
        Start-Sleep -Milliseconds 500
        $process.Refresh()
        if ($process.HasExited) {
            throw "The SSH tunnel for Podman service '$Service' exited with code $($process.ExitCode)."
        }

        $statePath = Get-SimpleSignPodmanStatePath -Project $Project
        $entries = @()
        if (Test-Path -LiteralPath $statePath) {
            $entries = @(ConvertFrom-Json -InputObject (Get-Content -LiteralPath $statePath -Raw))
        }

        $entries += [pscustomobject]@{
            ProcessId   = $process.Id
            IdentityPath = $connection.IdentityPath
            Forwards    = $forwardSpecs
        }
        $stateJson = ConvertTo-Json -InputObject @($entries) -Depth 4
        [IO.File]::WriteAllText($statePath, $stateJson, [Text.UTF8Encoding]::new($false))

        [pscustomobject]@{
            ProcessId = $process.Id
            Forwards  = $forwardSpecs
        }
    }
    catch {
        $process.Refresh()
        if (-not $process.HasExited) {
            Stop-Process -Id $process.Id -ErrorAction Stop
        }

        throw
    }
    finally {
        $process.Dispose()
    }
}

function Stop-SimpleSignPodmanForwarding {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Project)

    $statePath = Get-SimpleSignPodmanStatePath -Project $Project
    if (-not (Test-Path -LiteralPath $statePath)) {
        return
    }

    $entries = @(ConvertFrom-Json -InputObject (Get-Content -LiteralPath $statePath -Raw))
    if (-not $PSCmdlet.ShouldProcess("Podman SSH tunnels for project '$Project'", 'Stop')) {
        return
    }

    foreach ($entry in $entries) {
        $processId = [int]$entry.ProcessId
        $processInfo = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $processId" -ErrorAction SilentlyContinue
        if (-not $processInfo) {
            continue
        }

        $matchesTunnel = $processInfo.Name -ieq 'ssh.exe' -and $processInfo.CommandLine.Contains([string]$entry.IdentityPath)
        foreach ($forwardSpec in @($entry.Forwards)) {
            $matchesTunnel = $matchesTunnel -and $processInfo.CommandLine.Contains([string]$forwardSpec)
        }

        if (-not $matchesTunnel) {
            throw "Refusing to stop process $processId because it no longer matches the recorded Podman SSH tunnel."
        }

        Stop-Process -Id $processId -ErrorAction Stop
    }

    Remove-Item -LiteralPath $statePath -Force
}

Export-ModuleMember -Function Start-SimpleSignPodmanForwarding, Stop-SimpleSignPodmanForwarding, Test-SimpleSignLocalTcpPort
