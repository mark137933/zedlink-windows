$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$repositoryRoot = Split-Path $PSScriptRoot -Parent
Set-Location $repositoryRoot
$package = Join-Path $repositoryRoot 'work/package'
New-Item -ItemType Directory -Path $package -Force | Out-Null
Copy-Item "$env:CARGO_TARGET_DIR/release/zedlink-gateway.exe" $package
Copy-Item 'README.md' "$package/README.md"
Copy-Item 'LICENSE' "$package/LICENSE-zedlink"
Copy-Item 'THIRD_PARTY.md' "$package/THIRD_PARTY.md"
Copy-Item 'windows/ZedLink.ps1' "$package/ZedLink.ps1"
$manifests = @('work/source/gateway/Cargo.toml')
if ($env:BUILD_ZED -eq 'true') {
    $native = "$env:CARGO_TARGET_DIR/x86_64-pc-windows-msvc/release"
    Copy-Item "$native/zed.exe" "$package/Zed.exe"
    New-Item -ItemType Directory -Path "$package/bin", "$package/tools" -Force | Out-Null
    Copy-Item "$native/cli.exe" "$package/bin/zed.exe"
    Copy-Item "$native/auto_update_helper.exe" "$package/tools/auto_update_helper.exe"
    Copy-Item 'work/source/zed-source/LICENSE-GPL' "$package/LICENSE-Zed-GPL"
    Copy-Item 'work/source/zed-source/LICENSE-APACHE' "$package/LICENSE-Zed-APACHE"
    $manifests += 'work/source/zed-source/Cargo.toml'
    Copy-Item 'work/source/zed-source/script/licenses/template.md.hbs' "$package/UPSTREAM-ADDITIONAL-NOTICES.txt"
    Copy-Item 'work/source/zed-source/assets/themes/LICENSES' "$package/THEME-LICENSES.txt"
    Copy-Item 'work/source/zed-source/assets/icons/LICENSES' "$package/ICON-LICENSES.txt"
    Invoke-WebRequest 'https://codeload.github.com/GPUOpen-LibrariesAndSDKs/AGS_SDK/zip/refs/tags/v6.3.0' -OutFile 'work/ags.zip'
    Expand-Archive 'work/ags.zip' 'work/ags'
    Copy-Item 'work/ags/AGS_SDK-6.3.0/ags_lib/lib/amd_ags_x64.dll' $package
    Copy-Item 'work/ags/AGS_SDK-6.3.0/LICENSE.txt' "$package/LICENSE-AGS.txt"
    Invoke-WebRequest 'https://github.com/microsoft/terminal/releases/download/v1.25.1912.0/Microsoft.Windows.Console.ConPTY.1.25.260710002-preview.nupkg' -OutFile 'work/conpty.zip'
    Expand-Archive 'work/conpty.zip' 'work/conpty'
    New-Item -ItemType Directory -Path "$package/x64", "$package/arm64" -Force | Out-Null
    Copy-Item 'work/conpty/build/native/runtimes/x64/OpenConsole.exe' "$package/x64/OpenConsole.exe"
    Copy-Item 'work/conpty/build/native/runtimes/arm64/OpenConsole.exe' "$package/arm64/OpenConsole.exe"
    Copy-Item 'work/conpty/runtimes/win-x64/native/conpty.dll' $package
    Invoke-WebRequest 'https://raw.githubusercontent.com/microsoft/terminal/v1.25.1912.0/LICENSE' -OutFile "$package/LICENSE-ConPTY.txt"
}
python scripts/collect-licenses.py "$package/dependency-notices" @manifests
$zedVersion = 'NOT BUILT'
$cliVersion = 'NOT BUILT'
if ($env:BUILD_ZED -eq 'true') {
    if (-not (Test-Path -LiteralPath "$package/Zed.exe" -PathType Leaf)) { throw 'Zed.exe was not found in the package directory.' }
    $zedVersion = 'sha256:' + (Get-FileHash -LiteralPath "$package/Zed.exe" -Algorithm SHA256).Hash.ToLowerInvariant()
    $cliVersion = (& "$package/bin/zed.exe" --version | Out-String).Trim()
    if (-not $cliVersion) { throw 'CLI version check returned no output.' }
    Write-Host "Zed.exe integrity: $zedVersion"
    Write-Host $cliVersion
}
$expandedBytes = (Get-ChildItem -LiteralPath $package -Recurse -File | Measure-Object Length -Sum).Sum
$metadata = @{ sourceCommit=$env:GITHUB_SHA; zedVersion=$zedVersion; cliVersion=$cliVersion; approximateExpandedBytes=$expandedBytes; nativeDesktopLaunch='NOT RUN'; physicalPhoneRoundtrip='NOT RUN' }
$metadata | ConvertTo-Json | Set-Content "$package/build-validation.json"
$label = if ($env:BUILD_ZED -eq 'true') { 'zedlink-windows-x64' } else { 'zedlink-gateway-windows-x64' }
$archive = Join-Path $repositoryRoot "work/$label.zip"
Compress-Archive -Path "$package/*" -DestinationPath $archive
if ((Get-Item $archive).Length -ge 2GB) { throw 'Release asset exceeds the free release size limit.' }
$downloadMiB = [math]::Round((Get-Item $archive).Length / 1MB, 1)
$expandedMiB = [math]::Round($expandedBytes / 1MB, 1)
$shaFile = "$archive.sha256"
"$((Get-FileHash $archive -Algorithm SHA256).Hash.ToLowerInvariant())  $label.zip" | Set-Content $shaFile
$notes = Join-Path $repositoryRoot 'work/release-notes.md'
@"
Unsigned experimental Windows build. Transport tests and compilation ran in this workflow.
Download: $downloadMiB MiB. Expanded files: approximately $expandedMiB MiB before runtime caches.
Native executable integrity (SHA-256) and CLI version checks run when the full desktop build is selected. The Windows singleton uses a separate ZedLink identity; use ZedLink.ps1 for its isolated settings profile.
Physical-phone control of a native Zed conversation is not yet validated.
Source revisions and reproducible patch: README.md and patches/zed-windows.patch at $env:GITHUB_SHA.
Standard public Windows runner; no Actions artifacts or caches.
"@ | Set-Content $notes
$tag = "build-$env:GITHUB_RUN_ID-$env:GITHUB_RUN_ATTEMPT"
if ((gh api "repos/$env:GITHUB_REPOSITORY/git/ref/tags/$tag" --jq .object.sha) -ne $env:GITHUB_SHA) { throw 'Release tag does not match the compiled source.' }
gh release upload $tag $archive $shaFile "$package/build-validation.json" --repo $env:GITHUB_REPOSITORY
gh release edit $tag --repo $env:GITHUB_REPOSITORY --draft=false --prerelease --title "$label (experimental)" --notes-file $notes