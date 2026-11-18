using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using Mac2WinReceiver.Core.Server;

namespace Mac2WinReceiver.App.Services;

/// <summary>Transfer history rows: date, device, size, status (SPEC §8).</summary>
public sealed class HistoryRow
{
    public DateTimeOffset Date { get; init; }
    public string DeviceName { get; init; } = string.Empty;
    public long TotalBytes { get; init; }
    public string Status { get; init; } = string.Empty;
    public string SessionId { get; init; } = string.Empty;
}

public sealed class HistoryStore
{
    private readonly string _path;
    private List<HistoryRow> _rows = new();
    private static readonly JsonSerializerOptions Json =
        new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public IReadOnlyList<HistoryRow> Rows => _rows;

    public HistoryStore(string path)
    {
        _path = path;
        Load();
    }

    private void Load()
    {
        if (!File.Exists(_path)) return;
        try
        {
            var rows = JsonSerializer.Deserialize<List<HistoryRow>>(File.ReadAllText(_path), Json);
            if (rows is not null) _rows = rows;
        }
        catch { /* corrupt history → start fresh */ }
    }

    public void Add(SessionReport report, string deviceName)
    {
        _rows.Insert(0, new HistoryRow
        {
            Date = DateTimeOffset.UtcNow,
            DeviceName = deviceName,
            TotalBytes = report.Totals.BytesVerified,
            Status = report.Status,
            SessionId = report.SessionId,
        });
        Save();
    }

    public void Clear()
    {
        _rows.Clear();
        Save();
    }

    private void Save()
    {
        var tmp = _path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(_rows, Json));
        File.Move(tmp, _path, overwrite: true);
    }
}
