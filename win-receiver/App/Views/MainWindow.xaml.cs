using System.Windows;
using System.Windows.Input;

namespace Mac2WinReceiver.App.Views;

/// <summary>Code-behind for MainWindow: handles the global Close command.</summary>
public sealed partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
    }

    private void OnCloseExecuted(object sender, ExecutedRoutedEventArgs e)
    {
        Close();
    }
}
