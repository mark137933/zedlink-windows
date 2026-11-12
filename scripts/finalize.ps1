$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$repositoryRoot = Split-Path $PSScriptRoot -Parent
Set-Location $repositoryRoot
if ($env:BUILD_TAG -notmatch '^build-[0-9]+-[0-9]+$') { throw 'Expected a build release tag.' }
if ((gh api repos/$env:GITHUB_REPOSITORY --jq .visibility) -ne 'public') { throw 'Public repository required.' }
$buildCommit = gh release view $env:BUILD_TAG --repo $env:GITHUB_REPOSITORY --json targetCommitish --jq .targetCommitish
if ($buildCommit -notmatch '^[0-9a-f]{40}$') { throw 'Expected an exact source commit.' }
New-Item -ItemType Directory -Path 'work/download','work/original' -Force | Out-Null
gh release download $env:BUILD_TAG --repo $env:GITHUB_REPOSITORY --pattern 'zedlink-windows-x64.zip*' --dir work/download
$archive = Join-Path $repositoryRoot 'work/download/zedlink-windows-x64.zip'
$checksum = (Get-Content "$archive.sha256" -Raw).Trim().Split(' ')[0]
if ((Get-FileHash $archive -Algorithm SHA256).Hash -ne $checksum) { throw 'Original build SHA-256 mismatch.' }
$package = Join-Path $repositoryRoot 'work/package'
Expand-Archive -LiteralPath $archive -DestinationPath $package
git -C work/original init
git -C work/original remote add origin "https://github.com/$env:GITHUB_REPOSITORY.git"
git -C work/original fetch --depth 1 origin $buildCommit
git -C work/original checkout --detach FETCH_HEAD
& "$repositoryRoot/work/original/scripts/prepare.ps1"
Set-Location $repositoryRoot
rustup toolchain install 1.98.1 --profile minimal
$originalSource = Join-Path $repositoryRoot 'work/original/work/source'
foreach ($manifest in @("$originalSource/gateway/Cargo.toml", "$originalSource/zed-source/Cargo.toml")) {
    cargo +1.98.1 metadata --format-version 1 --filter-platform x86_64-pc-windows-msvc --manifest-path $manifest | Out-Null
}
python scripts/collect-licenses.py "$package/dependency-notices" "$originalSource/gateway/Cargo.toml" "$originalSource/zed-source/Cargo.toml"
Copy-Item windows/ZedLink.ps1 "$package/ZedLink.ps1" -Force
Copy-Item README.md "$package/README.md" -Force
Copy-Item "$originalSource/zed-source/assets/themes/LICENSES" "$package/THEME-LICENSES.txt"
Copy-Item "$originalSource/zed-source/assets/icons/LICENSES" "$package/ICON-LICENSES.txt"
Copy-Item "$originalSource/zed-source/script/licenses/template.md.hbs" "$package/UPSTREAM-ADDITIONAL-NOTICES.txt"
Invoke-WebRequest 'https://raw.githubusercontent.com/microsoft/terminal/v1.25.1912.0/LICENSE' -OutFile "$package/LICENSE-ConPTY.txt"
& "$package/Zed.exe" --version
& "$package/bin/zed.exe" --version
$metadata = @{ binarySourceCommit=$buildCommit; packagingSourceCommit=$env:GITHUB_SHA; originalArchiveSha256=$checksum; nativeDesktopLaunch='NOT RUN'; physicalPhoneRoundtrip='NOT RUN' }
$metadata | ConvertTo-Json | Set-Content "$package/build-validation.json"
$finalArchive = Join-Path $repositoryRoot 'work/zedlink-windows-x64.zip'
Compress-Archive -Path "$package/*" -DestinationPath $finalArchive
if ((Get-Item $finalArchive).Length -ge 2GB) { throw 'Package exceeds release asset limit.' }
"$((Get-FileHash $finalArchive -Algorithm SHA256).Hash.ToLowerInvariant())  zedlink-windows-x64.zip" | Set-Content "$finalArchive.sha256"
$notes = Join-Path $repositoryRoot 'work/final-notes.md'
@"
Experimental Windows package with native Zed, gateway, isolated launcher, dependency notices and SHA-256 checksum.
Native binaries are unchanged from $($env:BUILD_TAG), built from $buildCommit. Packaging source: $env:GITHUB_SHA.
Transport/protocol/gateway tests and native compilation passed in the original build. Executable version checks ran during packaging.
Interactive desktop launch and physical-phone shared-thread behavior still require verification. Do not replace a stock Zed installation.
All build and packaging work ran on free standard Windows runners for this public repository. No local build dependencies are required.
"@ | Set-Content $notes
gh release create "windows-$env:GITHUB_RUN_ID" $finalArchive "$finalArchive.sha256" --repo $env:GITHUB_REPOSITORY --target $env:GITHUB_SHA --prerelease --title 'ZedLink Windows x64 (experimental)' --notes-file $notes
