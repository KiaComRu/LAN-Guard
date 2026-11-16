# Управление запуском Windows

В текущем агенте `IPolicyProvider` задаёт контракт проверки доступности режима аудита. Реализация изменения системной политики и маршруты команд агенту отсутствуют.

Отдельный релиз должен начинаться с проверки редакций Windows и чтения журналов App Control for Business или AppLocker на выделенном тестовом ПК. Затем можно проверять dry-run правил, штатный аудит, восстановление последней рабочей политики, ограниченные исключения и их отзыв. Подтверждать успешную блокировку следует по наблюдениям Windows на тестовом стенде.

[Планирование развёртывания App Control](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/appcontrol-deployment-guide)
