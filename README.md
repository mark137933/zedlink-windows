# ZedLink for Windows (experimental)

Windows adaptation of [tjnull/zedlink](https://github.com/tjnull/zedlink). The phone controls an explicitly exposed conversation in the patched native Zed application, using that application's configured model and approvals.

This repository contains source overlays, a native Zed patch, and a manual cloud build. It does not contain private configuration or credentials. Compilation and physical-device verification are separate: successful compilation alone does not establish working phone control.

## Reproducible sources

- ZedLink: `87e9dd3de766601ba667f3e05eadc136779f65e5`
- Maintained native Zed fork: `96ca63880edeeddd8f27ccbbebd2e5b475652c1e`
- Native Windows changes: `patches/zed-windows.patch`
- Gateway and shared transport: `overlay/`

Windows uses per-user named pipes with an explicit owner/SYSTEM ACL and remote pipe clients disabled. Unix retains private local sockets. TLS, device pairing, explicit thread exposure, and native approval checks remain required. No new remote shell is added.

## Free cloud build

Run **Actions → Windows build (free public runner) → Run workflow**. Leave **build_zed** enabled for the complete desktop build; disable it to validate the transport and gateway first.

The workflow runs only manually, only in this public repository, and only on the standard `windows-2022` runner. It has no paid-runner fallback, no Actions cache, and no Actions artifact uploads. Successful builds are attached to prereleases with SHA-256 hashes. The workflow stops if the free runner lacks sufficient disk space.

[GitHub's billing documentation](https://docs.github.com/en/billing/concepts/product-billing/github-actions) states that standard hosted runners in public repositories remain free. [Release assets](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases) must be smaller than 2 GiB each.

Build dependencies and caches stay on the disposable cloud runner. Local setup does not require Rust, Visual Studio, SDKs, or a local build cache. Downloading the finished desktop archive is optional.

## Current limits

This is an unsigned experimental build. Windows IPC tests, gateway compilation, native Zed compilation, desktop launch, and a real phone round trip are tracked separately. Use an isolated test project/profile. Do not replace an existing Zed installation or copy personal model credentials into this repository.

The initial Windows launch path uses a separate launcher; automatic gateway startup defaults off. Existing Unix Python management scripts are not Windows launchers.

## Licensing

ZedLink and the new transport code use Apache-2.0. The native Zed patch modifies the maintained Zed fork, whose original GPL/Apache licensing applies to the corresponding code. See `THIRD_PARTY.md` for pinned source locations and notices.
Windows adaptation of tjnull/zedlink. Manual builds on free standard GitHub-hosted runners for this public repository.
