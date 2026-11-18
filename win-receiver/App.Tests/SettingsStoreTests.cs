using System.IO;
using Mac2WinReceiver.App.Services;
using Xunit;

namespace Mac2WinReceiver.App.Tests;

/// <summary>SettingsStore unit tests.</summary>
public sealed class SettingsStoreTests
{
    [Fact]
    public void SaveAndReload_PersistsSettings()
    {
        var path = Path.Combine(Path.GetTempPath(), $"m2w-settings-test-{Guid.NewGuid()}.json");
        try
        {
            var store = new SettingsStore(path);
            store.Update(s =>
            {
                s.DestinationRoot = @"C:\Users\test\Downloads";
                s.Port = 48601;
                s.DefaultConflictPolicy = "REPLACE";
            });

            var store2 = new SettingsStore(path);
            Assert.Equal(@"C:\Users\test\Downloads", store2.Current.DestinationRoot);
            Assert.Equal(48601, store2.Current.Port);
            Assert.Equal("REPLACE", store2.Current.DefaultConflictPolicy);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void MissingFile_ReturnsDefaults()
    {
        var path = Path.Combine(Path.GetTempPath(), $"m2w-settings-missing-{Guid.NewGuid()}.json");
        try
        {
            var store = new SettingsStore(path);
            Assert.Equal("ASK", store.Current.DefaultConflictPolicy);
            Assert.Equal(48600, store.Current.Port);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }
}
