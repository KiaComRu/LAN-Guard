# LAN Guard

[English](README.md) · **Русский**

LAN Guard помогает администраторам находить устройства в локальной сети и вести инвентаризацию ПО удалённого доступа на управляемых Windows-компьютерах.

- **Разовая проверка сети.** Приложение для Windows 10/11 x64 находит устройства в выбранном сегменте и показывает, какие распространённые TCP-порты доступны. С правами текущей учётной записи оно может прочитать записи об установленных программах из удалённого реестра и показать сведения об устройстве из SMB и WMI. [Использование приложения](docs/desktop.md)
- **Регулярная инвентаризация.** Служба Windows проверяет реестр, процессы, службы, ключи автозапуска Run и RunOnce и пути к исполняемым файлам в заданиях планировщика. Агент отправляет результаты по HTTPS. В русскоязычной веб-панели видны источники данных, уверенность совпадения, покрытие проверки и история изменений.

Открытый порт служит сетевым признаком. Для подтверждения установки программы проверьте данные реестра или отчёт агента.

## Приложение для Windows

Для сборки установщика понадобятся .NET 10 SDK и NSIS 3.13 с `makensis.exe` в `PATH`.

```powershell
.\deploy\windows-desktop\Build-Installer.ps1
```

Запустите `artifacts/LAN-Guard-Setup-x64.exe` и откройте **LAN Guard** в меню «Пуск».

## Запуск демо

Понадобятся Docker Compose и доверенный PFX-сертификат для `localhost`. [Как создать сертификат для демо](docs/deployment.md#tls-и-база-данных). В PowerShell из корня репозитория задайте пути и свои пароли.

```powershell
$env:LAN_GUARD_DEMO = 'true'
$env:LAN_GUARD_ADMIN_PASSWORD = '<ваш пароль из 16–256 символов>'
$env:LAN_GUARD_TLS_PFX = (Resolve-Path '.\certs\localhost.pfx').Path
$env:LAN_GUARD_TLS_PASSWORD = '<пароль PFX>'
docker compose -f deploy/docker-compose.yml up --build
```

Откройте [панель](https://localhost:7443) и войдите как `admin`. В демо четыре вымышленных устройства, включая компьютер без агента и компьютер с частичной проверкой. Демо использует отдельную SQLite БД и принимает только синтетические записи.

Для LAN используйте [инструкцию по развёртыванию](docs/deployment.md) с настройкой TLS, PostgreSQL и подготовкой Windows-агента.

## Сборка и установка службы

```powershell
dotnet publish src/LanGuard.Agent -c Release -r win-x64 --self-contained true -o artifacts/agent
.\artifacts\agent\LanGuard.Agent.exe --inventory-only
```

На тестовом ПК откройте PowerShell от имени администратора. В рабочем режиме панели нажмите **Токен агента** и введите выданный токен по запросу установщика.

```powershell
.\deploy\windows-agent\Install-Agent.ps1 -PublishDirectory .\artifacts\agent -Server https://lan-guard.example.test:7443 -ScanMinutes 5
Get-Service LanGuardAgent
```

Замените `lan-guard.example.test` именем сервера, указанным в его сертификате. Доверие к выдающему УЦ должно быть настроено на тестовом ПК для учётной записи службы. Установка запускает службу автоматически.

## Проверки

```powershell
dotnet test LanGuard.slnx
npm.cmd ci --prefix src/LanGuard.Web
npm.cmd run build --prefix src/LanGuard.Web
```

Сборка требует .NET 10 SDK и Node.js 24. Инвентаризация проверяется на Windows. [Сценарии ручной проверки](docs/testing.md)

## Код

| Путь | Содержимое |
| --- | --- |
| `src/LanGuard.Server` | ASP.NET Core API, аутентификация, хранение и миграции |
| `src/LanGuard.Agent` | Windows Service, инвентаризация, очередь и доставка |
| `src/LanGuard.Desktop` | Приложение WinForms для проверки локальной сети |
| `src/LanGuard.Shared` | Модели протокола и сопоставление наблюдений с правилами |
| `src/LanGuard.Web` | Русскоязычная панель React |
| `signatures` | Версионируемые правила обнаружения |
| `tests` | Тесты детектора, интеграционные тесты API и демо-фикстуры |
| `deploy` | Docker Compose, установщик службы и сборка установщика приложения |

Чтение журналов запуска, проверка Authenticode и [управление запуском приложений](docs/windows-enforcement.md) запланированы на следующие этапы.

[Архитектура](docs/architecture.md) · [Модель угроз](docs/threat-model.md) · [Контракт API и поведение статусов](docs/api.md)
