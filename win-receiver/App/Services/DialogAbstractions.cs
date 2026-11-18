namespace Mac2WinReceiver.App.Services;

/// <summary>Folder-picker abstraction — production uses WinForms OpenFolderDialog;
/// tests inject a fake so no real dialog appears.</summary>
public interface IFolderPicker
{
    string? PickFolder(string initialDirectory, string title);
}

/// <summary>File-save abstraction — production uses WinForms SaveFileDialog; tests inject a fake.</summary>
public interface IFileSaver
{
    string? SaveFile(string initialDirectory, string fileName, string filter, out string selectedFilter);
}

/// <summary>Shell launcher abstraction — production opens explorer; tests record the call.</summary>
public interface IShellLauncher
{
    void OpenFolder(string path);
}
