# LAN Guard

**English** · [Русский](README.ru.md)

LAN Guard helps administrators discover devices on a local network and inventory remote-access software on managed Windows computers.

- **On-demand LAN discovery.** The Windows 10/11 x64 desktop app finds devices on the selected network segment and checks common TCP ports. With the current Windows account's permissions, it can read installed-software entries from the Remote Registry and retrieve device details through SMB and WMI. [Desktop guide (Russian)](docs/desktop.md)
- **Scheduled endpoint inventory.** A Windows service checks installed-software registry entries, running processes, services, Run and RunOnce entries, and executable paths in scheduled tasks. It queues reports locally and sends them over HTTPS. The Russian-language dashboard shows each finding's source, match confidence, scan coverage, and change history.

An open port indicates a reachable network service. Use registry evidence or the agent's inventory to confirm a software installation.

## Windows desktop app

Install the .NET 10 SDK and NSIS 3.13. Make `makensis.exe` available on `PATH`, then run this command from the repository root.

```powershell
.\deploy\windows-desktop\Build-Installer.ps1
```

Run `artifacts/LAN-Guard-Setup-x64.exe` and open **LAN Guard** from the Start menu.

## Dashboard demo

The demo includes four synthetic devices and uses a separate SQLite database. Install Docker Compose and [create a trusted PFX certificate for `localhost`](docs/deployment.md#tls-и-база-данных). Set your paths and passwords in PowerShell and start the demo.

```powershell
$env:LAN_GUARD_DEMO = 'true'
$env:LAN_GUARD_ADMIN_PASSWORD = '<your 16–256 character password>'
$env:LAN_GUARD_TLS_PFX = (Resolve-Path '.\certs\localhost.pfx').Path
$env:LAN_GUARD_TLS_PASSWORD = '<your PFX password>'
docker compose -f deploy/docker-compose.yml up --build
```

Open the dashboard at `https://localhost:7443` and sign in as `admin`. For managed networks, see the [deployment guide (Russian)](docs/deployment.md) for TLS, PostgreSQL, and Windows service setup.

## Windows agent

Build the agent and check which inventory sources are available on a Windows test computer.

```powershell
dotnet publish src/LanGuard.Agent -c Release -r win-x64 --self-contained true -o artifacts/agent
.\artifacts\agent\LanGuard.Agent.exe --inventory-only
```

In the dashboard, generate an enrollment token using **Токен агента**. Run the installer from an elevated PowerShell session and enter the token when prompted.

```powershell
.\deploy\windows-agent\Install-Agent.ps1 -PublishDirectory .\artifacts\agent -Server https://lan-guard.example.test:7443 -ScanMinutes 5
Get-Service LanGuardAgent
```

Use the server name from its TLS certificate and configure the Windows computer to trust the issuing CA. The installer starts the service automatically.

## Build and test

Use the .NET 10 SDK and Node.js 24. Run the inventory checks on Windows.

```powershell
dotnet test LanGuard.slnx
npm.cmd ci --prefix src/LanGuard.Web
npm.cmd run build --prefix src/LanGuard.Web
```

| Path | Contents |
| --- | --- |
| `src/LanGuard.Desktop` | WinForms app for on-demand LAN discovery |
| `src/LanGuard.Agent` | Windows service, endpoint inventory, and report delivery |
| `src/LanGuard.Server` | ASP.NET Core API, authentication, and database migrations |
| `src/LanGuard.Shared` | Protocol models and detection rules engine |
| `src/LanGuard.Web` | React dashboard |
| `signatures` | Versioned detection rules |
| `tests` | Detection and API tests, plus synthetic demo fixtures |
| `deploy` | Docker Compose configuration and Windows installer tooling |

[Architecture](docs/architecture.md) · [API](docs/api.md) · [Threat model](docs/threat-model.md) · [Manual testing](docs/testing.md) (Russian)
