using System;
using System.IO;
using System.Text.Json;

namespace Mac2WinReceiver.App.Services;

/// <summary>Typed, persisted settings (SPEC §8: Settings screen).</summary>
public sealed class ReceiverSettings
{
    public string DestinationRoot { get; set; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Mac2WinTransfers");
    public int Port { get; set; } = 48600;
    public string DeviceName { get; set; } = Environment.MachineName;
    public string DefaultConflictPolicy { get; set; } = "ASK";
    public bool VerifyAfterWrite { get; set; } = true;
    public int ChunkSize { get; set; } = 1024 * 1024;
    public string Theme { get; set; } = "System"; // System | Light | Dark
}

public sealed class SettingsStore
{
    private readonly string _path;
    private ReceiverSettings _settings;
    private static readonly JsonSerializerOptions Json =
        new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public ReceiverSettings Current => _settings;

    public SettingsStore(string path)
    {
        _path = path;
        if (File.Exists(_path))
        {
            try
            {
                _settings = System.Text.Json.JsonSerializer.Deserialize<ReceiverSettings>(
                    File.ReadAllText(_path), Json) ?? new ReceiverSettings();
            }
            catch
            {
                _settings = new ReceiverSettings();
            }
        }
        else
        {
            _settings = new ReceiverSettings();
        }
    }

    public void Save()
    {
        var tmp = _path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(_settings, Json));
        File.Move(tmp, _path, overwrite: true);
    }

    public void Update(Action<ReceiverSettings> mutate)
    {
        mutate(_settings);
        Save();
    }
}
