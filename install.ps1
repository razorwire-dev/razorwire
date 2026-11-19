# Install Razorwire on Windows from a GitHub release.
#
#   irm https://raw.githubusercontent.com/razorwire-dev/razorwire/main/install.ps1 | iex
#
# $env:GITHUB_TOKEN is only needed to install from a private copy of the
# repository: set it to a token that can read that copy (a fine-grained token
# with "Contents: read" is enough), and fetch this script with it too.
#
# Settings, all optional:
#   $env:RAZORWIRE_VERSION       a release tag like v0.2.0 (default: the latest)
#   $env:RAZORWIRE_INSTALL_DIR   where razorwire.exe goes
#                                (default: %LOCALAPPDATA%\Programs\razorwire)
#   $env:RAZORWIRE_NO_PATH       set to 1 to leave your PATH alone
#   $env:GITHUB_TOKEN            only for a private copy of the repository
#
# The download is checked against the release's SHA256SUMS before anything
# is installed.

& {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    function Get-Setting($name, $default) {
        $value = [Environment]::GetEnvironmentVariable($name)
        if ($value) { $value } else { $default }
    }
    $repo = Get-Setting 'RAZORWIRE_REPO' 'razorwire-dev/razorwire'
    $api = Get-Setting 'RAZORWIRE_API' 'https://api.github.com'
    $web = Get-Setting 'RAZORWIRE_WEB' 'https://github.com'
    $version = Get-Setting 'RAZORWIRE_VERSION' 'latest'
    $dir = Get-Setting 'RAZORWIRE_INSTALL_DIR' (Join-Path $env:LOCALAPPDATA 'Programs\razorwire')
    $token = $env:GITHUB_TOKEN

    if (-not [Environment]::Is64BitOperatingSystem) {
        throw 'razorwire install: there is only a 64-bit Windows build.'
    }
    $target = 'x86_64-pc-windows-msvc'
    $asset = "razorwire-$target.zip"
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('razorwire-' + [guid]::NewGuid())
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        if ($token) {
            # A private repository's release files can only be fetched through the API.
            $release = if ($version -eq 'latest') { "$api/repos/$repo/releases/latest" } else { "$api/repos/$repo/releases/tags/$version" }
            try {
                $info = Invoke-RestMethod -Uri $release -Headers @{ Authorization = "Bearer $token"; Accept = 'application/vnd.github+json' }
            } catch {
                throw 'razorwire install: cannot read the release from GitHub. Check GITHUB_TOKEN and RAZORWIRE_VERSION.'
            }
            $fetch = {
                param($name, $destination)
                $found = $info.assets | Where-Object { $_.name -eq $name } | Select-Object -First 1
                if (-not $found) { throw "razorwire install: the release has no $name." }
                # The token is not passed on when GitHub redirects to its storage.
                Invoke-WebRequest -UseBasicParsing -Uri $found.url -OutFile $destination `
                    -Headers @{ Authorization = "Bearer $token"; Accept = 'application/octet-stream' }
            }
        } else {
            $base = if ($version -eq 'latest') { "$web/$repo/releases/latest/download" } else { "$web/$repo/releases/download/$version" }
            $fetch = {
                param($name, $destination)
                try {
                    Invoke-WebRequest -UseBasicParsing -Uri "$base/$name" -OutFile $destination
                } catch {
                    throw "razorwire install: cannot download $name. Check your internet connection and RAZORWIRE_VERSION."
                }
            }
        }

        Write-Host "Downloading $asset ($version)"
        $zip = Join-Path $tmp $asset
        $sums = Join-Path $tmp 'SHA256SUMS'
        & $fetch $asset $zip
        & $fetch 'SHA256SUMS' $sums
        $expected = Get-Content $sums | ForEach-Object {
            $parts = $_ -split '\s+'
            if ($parts.Count -ge 2 -and ($parts[1] -eq $asset -or $parts[1] -eq "*$asset")) { $parts[0].ToLower() }
        } | Select-Object -First 1
        if (-not $expected) { throw "razorwire install: SHA256SUMS does not list $asset, so it was not installed." }
        $actual = (Get-FileHash -Algorithm SHA256 -Path $zip).Hash.ToLower()
        if ($expected -ne $actual) { throw "razorwire install: $asset does not match its checksum, so it was not installed." }

        Expand-Archive -Path $zip -DestinationPath $tmp
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $exe = Join-Path $dir 'razorwire.exe'
        Copy-Item -Path (Join-Path $tmp "razorwire-$target\razorwire.exe") -Destination $exe -Force
        $installed = & $exe --version
        Write-Host "Installed $installed at $exe"

        $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
        $onPath = ($userPath -split ';') -contains $dir
        if ($onPath) {
        } elseif ($env:RAZORWIRE_NO_PATH -eq '1') {
            Write-Host "$dir is not on your PATH."
        } else {
            $newPath = if ($userPath) { "$userPath;$dir" } else { $dir }
            [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
            Write-Host "Added $dir to your PATH. Open a new terminal to use razorwire."
        }
        Write-Host 'Next: razorwire help. The example policy and executor are in the release archive and the repository.'
    } finally {
        Remove-Item -Recurse -Force -Path $tmp -ErrorAction SilentlyContinue
    }
}
