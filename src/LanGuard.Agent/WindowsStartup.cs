using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace LanGuard.Agent;

public sealed partial class WindowsInventory
{
    private static void ReadAutoruns(Source source)
    {
        foreach (var view in Views())
        {
            using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            using var users = RegistryKey.OpenBaseKey(RegistryHive.Users, view);
            ReadRunKeys(machine, "", source);
            var profiles = users.GetSubKeyNames().Where(IsLoadedProfile).ToArray();
            if (profiles.Length == 0)
                source.Warn("Нет загруженных пользовательских профилей");
            foreach (var profile in profiles)
                ReadRunKeys(users, profile + @"\", source);
        }
    }

    private static void ReadRunKeys(RegistryKey root, string prefix, Source source)
    {
        foreach (var keyName in new[] { "Run", "RunOnce" })
        {
            source.Try(() =>
            {
                using var run = root.OpenSubKey(prefix + @"Software\Microsoft\Windows\CurrentVersion\" + keyName);
                if (run is null)
                    return;
                foreach (var name in run.GetValueNames())
                {
                    if (!source.CanRead())
                        break;
                    if (run.GetValue(name) is string command)
                        AddStartup("autorun", command, source);
                }
            });
        }
    }

    private static void ReadScheduledTasks(Source source)
    {
        var type = Type.GetTypeFromProgID("Schedule.Service") ?? throw new NotSupportedException();
        dynamic scheduler = Activator.CreateInstance(type) ?? throw new NotSupportedException();
        try
        {
            scheduler.Connect();
            var budget = 2000;
            ReadTaskFolder(scheduler.GetFolder("\\"), source, ref budget, 0);
        }
        finally
        {
            ReleaseCom(scheduler);
        }
    }

    private static void ReadTaskFolder(dynamic folder, Source source, ref int budget, int depth)
    {
        try
        {
            if (depth >= 32 || budget <= 0 || !source.CanRead())
            {
                source.Warn("Достигнут лимит проверки планировщика");
                return;
            }
            budget--;
            dynamic tasks = folder.GetTasks(1);
            try
            {
                for (var index = 1; index <= (int)tasks.Count; index++)
                {
                    if (budget <= 0 || !source.CanRead())
                    {
                        source.Warn("Достигнут лимит проверки планировщика");
                        return;
                    }
                    budget--;
                    var taskIndex = index;
                    source.Try(() => ReadTask(tasks.Item(taskIndex), source));
                }
            }
            finally
            {
                ReleaseCom(tasks);
            }

            dynamic folders = folder.GetFolders(0);
            try
            {
                for (var index = 1; index <= (int)folders.Count; index++)
                {
                    if (budget <= 0 || !source.CanRead())
                    {
                        source.Warn("Достигнут лимит проверки планировщика");
                        return;
                    }
                    ReadTaskFolder(folders.Item(index), source, ref budget, depth + 1);
                }
            }
            finally
            {
                ReleaseCom(folders);
            }
        }
        catch (COMException)
        {
            source.Warn("Часть заданий планировщика недоступна");
        }
        finally
        {
            ReleaseCom(folder);
        }
    }

    private static void ReadTask(dynamic task, Source source)
    {
        dynamic? definition = null;
        dynamic? actions = null;
        try
        {
            definition = task.Definition;
            actions = definition.Actions;
            for (var index = 1; index <= (int)actions.Count && source.CanRead(); index++)
            {
                dynamic action = actions.Item(index);
                try
                {
                    if ((int)action.Type == 0 && action.Path is string executable)
                        AddStartup("task", executable, source);
                }
                finally
                {
                    ReleaseCom(action);
                }
            }
        }
        finally
        {
            ReleaseCom(actions);
            ReleaseCom(definition);
            ReleaseCom(task);
        }
    }

    private static void AddStartup(string kind, string command, Source source)
    {
        var path = GetExecutable(command);
        var name = Path.GetFileName(path);
        if (!string.IsNullOrWhiteSpace(name))
            source.Add(ReadFileMetadata(kind, name, path, source));
    }

    private static void ReleaseCom(object? value)
    {
        if (value is not null)
            Marshal.ReleaseComObject(value);
    }
}
