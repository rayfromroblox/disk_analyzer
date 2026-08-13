# Distribution

End users should install a release artifact, not build the project from source.

## Release artifacts

| Platform | Recommended artifact | Notes |
| --- | --- | --- |
| Windows | `*-setup.exe` | Standard NSIS installer; `.msi` is also supplied for managed deployment. |
| Apple Silicon macOS | `*aarch64.dmg` | For M-series Macs. |
| Intel macOS | `*x64.dmg` | For Intel Macs. |
| Linux | `*.AppImage` | Broad distribution compatibility. |
| Debian/Ubuntu Linux | `*.deb` | Native package installation. |

Pushing a tag that begins with `v` starts the release workflow. It builds the
desktop application on each platform and publishes the artifacts to a public
GitHub Release. The workflow also attaches CLI and TUI archives for advanced
users.

## Trust and first-run prompts

The artifacts are buildable without paid certificates, but production releases
should use code signing:

- Windows Authenticode signing reduces SmartScreen warnings.
- macOS Developer ID signing and notarization avoid Gatekeeper quarantine.

The release workflow deliberately separates this from application functionality:
the app remains usable on every supported platform, while signing credentials
can be added as repository secrets when available.
