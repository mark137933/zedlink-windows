param([string]$Tag = "build-$env:GITHUB_RUN_ID-$env:GITHUB_RUN_ATTEMPT")
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
if ($Tag -notmatch '^(build-[0-9]+-[0-9]+|windows-[0-9]+)$') { throw 'Invalid build tag.' }
if ((gh api repos/$env:GITHUB_REPOSITORY --jq .visibility) -ne 'public') { throw 'Public repository required.' }
$currentMain = gh api repos/$env:GITHUB_REPOSITORY/commits/main --jq .sha
if ($currentMain -ne $env:GITHUB_SHA) { throw 'Start the build from the current main revision.' }
# Pin the source reference before a later workflow edit can move main.
gh api --method POST repos/$env:GITHUB_REPOSITORY/git/refs -f "ref=refs/tags/$Tag" -f "sha=$env:GITHUB_SHA" --silent
gh release create $Tag --repo $env:GITHUB_REPOSITORY --verify-tag --target $env:GITHUB_SHA --draft --prerelease --title 'ZedLink Windows (build in progress)' --notes 'Build in progress. No verified binaries are available yet.'
