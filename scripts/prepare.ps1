$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$repositoryRoot = Split-Path $PSScriptRoot -Parent
Set-Location $repositoryRoot
New-Item -ItemType Directory -Path 'work/source' -Force | Out-Null
git -C work/source init
git -C work/source remote add origin https://github.com/tjnull/zedlink.git
git -C work/source fetch --depth 1 origin 87e9dd3de766601ba667f3e05eadc136779f65e5
git -C work/source checkout --detach FETCH_HEAD
Copy-Item -Path 'overlay/*' -Destination 'work/source' -Recurse -Force
New-Item -ItemType Directory -Path 'work/source/zed-source' -Force | Out-Null
git -C work/source/zed-source init
git -C work/source/zed-source remote add origin https://github.com/tjnull/zed.git
git -C work/source/zed-source fetch --depth 1 origin 96ca63880edeeddd8f27ccbbebd2e5b475652c1e
git -C work/source/zed-source checkout --detach FETCH_HEAD
git -C work/source/zed-source apply --check "$repositoryRoot/patches/zed-windows.patch"
git -C work/source/zed-source apply "$repositoryRoot/patches/zed-windows.patch"
Write-Host 'Pinned public sources and Windows patch prepared.'

