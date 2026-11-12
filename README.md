# ZedLink for Windows (experimental)

Windows adaptation of [tjnull/zedlink](https://github.com/tjnull/zedlink). The phone controls an explicitly exposed conversation in the patched native Zed application, using that application's configured model and approvals.

This repository contains source overlays, a native Zed patch, and a manual cloud build. It does not contain private configuration or credentials. Compilation and physical-device verification are separate: successful compilation alone does not establish working phone control.

## Reproducible sources

- ZedLink: `87e9dd3de766601ba667f3e05eadc136779f65e5`
- Maintained native Zed fork: `96ca63880edeeddd8f27ccbbebd2e5b475652c1e`
- Native Windows changes: `patches/zed-windows.patch`
- Gateway and shared transport: `overlay/`

Windows uses per-user named pipes with an explicit owner/SYSTEM ACL and remote pipe clients disabled. Unix retains private local sockets. TLS, device pairing, explicit thread exposure, and native approval checks remain required. No new remote shell is added.

The native Windows instance mutex and command pipe use a separate ZedLink identifier, so starting this build does not hand the project to an already running stock Zed. Use the launcher below to keep settings and conversation storage in its separate profile.

## Free cloud build

Run **Actions → Windows build (free public runner) → Run workflow**. Leave **build_zed** enabled for the complete desktop build; disable it to validate the transport and gateway first.

The workflow runs only manually, only in this public repository, and only on the standard `windows-2022` runner. It has no paid-runner fallback, no Actions cache, and no Actions artifact uploads. Successful builds are attached to prereleases with SHA-256 hashes. The workflow stops if the free runner lacks sufficient disk space.

[GitHub's billing documentation](https://docs.github.com/en/billing/concepts/product-billing/github-actions) states that standard hosted runners in public repositories remain free. [Release assets](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases) must be smaller than 2 GiB each.

Build dependencies and caches stay on the disposable cloud runner. Local setup does not require Rust, Visual Studio, SDKs, or a local build cache. Downloading the finished desktop archive is optional.

## Current limits

This is an unsigned experimental build. Windows IPC tests, gateway compilation, native Zed compilation, desktop launch, and a real phone round trip are tracked separately. Use an isolated test project/profile. Do not replace an existing Zed installation or copy personal model credentials into this repository.

The Windows launch path uses `ZedLink.ps1`; automatic gateway startup defaults off. The optional in-app connection-management buttons still depend on the upstream Unix Python manager and are not validated on Windows. Use the PowerShell launcher for setup, pairing, status and shutdown.

After downloading and extracting a complete desktop build, run this in Windows PowerShell using a disposable project and your trusted HTTPS certificate:

```powershell
.\ZedLink.ps1 -Action Setup -ProjectPath 'D:\test-project' -CertificatePath 'D:\certs\cert.pem' -PrivateKeyPath 'D:\certs\key.pem' -HttpsOrigin 'https://computer.example-tailnet.ts.net:7443' -BindAddress '100.64.10.20:7443'
.\ZedLink.ps1 -Action Start
.\ZedLink.ps1 -Action Pair
```

Replace the example address and certificate paths with your own. The certificate must already be trusted by the phone and match the hostname. Setup creates a protected `data` directory beside the extracted program and refuses to overwrite an existing setup. Start uses an isolated Zed profile; configure the model there, open an Agent conversation, and type `/remote-control` to expose it. Pairing codes are credentials: enter them on your own device, not in issues or logs. Use `-Action Stop` to stop this gateway; it does not terminate Zed.

## Licensing

ZedLink and the new transport code use Apache-2.0. The native Zed patch modifies the maintained Zed fork, whose original GPL/Apache licensing applies to the corresponding code. See `THIRD_PARTY.md` for pinned source locations and notices.
Windows adaptation of tjnull/zedlink. Manual builds on free standard GitHub-hosted runners for this public repository.
