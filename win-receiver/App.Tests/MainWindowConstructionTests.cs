using System.Windows;
using Mac2WinReceiver.App.Views;
using Xunit;

namespace Mac2WinReceiver.App.Tests;

/// <summary>
/// Constructs the real MainWindow XAML. Two shipped crashes were invisible to every other test
/// because none of them ever built this window:
/// (1) an undefined <c>BooleanToVisibilityConverter</c> StaticResource (XamlParseException at
/// construction, Event Viewer 2026-11-19) and (2) resources living only in App.xaml, which no
/// test instantiates. The window now merges Themes/AppResources.xaml itself.
/// </summary>
public sealed class MainWindowConstructionTests
{
    [Fact]
    public void MainWindow_Constructs_WithAllResourcesResolved()
    {
        StaRunner.Run(() =>
        {
            var window = new MainWindow();
            try
            {
                Assert.Equal("Mac2Win Transfer — Receiver", window.Title);
                Assert.Equal(900, (int)window.Width);
                Assert.NotNull(window.Resources);
                // every key MainWindow binds against must resolve from the merged dictionary
                Assert.NotNull(window.Resources["CardPanel"]);
                Assert.NotNull(window.Resources["PrimaryButton"]);
                Assert.NotNull(window.Resources["TextMuted"]);
                Assert.NotNull(window.Resources["WarningBrush"]);
                Assert.NotNull(window.Resources["Base64ToImageConverter"]);
                Assert.NotNull(window.Resources["BooleanToVisibilityConverter"]);
                Assert.NotNull(window.Resources["InverseBooleanToVisibilityConverter"]);
            }
            finally
            {
                window.Close();
            }
        });
    }

    /// <summary>The window has no DataContext until App.OnStartup sets it; resource-only
    /// construction must still work (this is exactly the path that crashed in the wild).</summary>
    [Fact]
    public void MainWindow_WithoutDataContext_Constructs()
    {
        StaRunner.Run(() =>
        {
            var window = new MainWindow();
            try
            {
                Assert.Null(window.DataContext);
                Assert.True(window.IsInitialized);
            }
            finally
            {
                window.Close();
            }
        });
    }
}
