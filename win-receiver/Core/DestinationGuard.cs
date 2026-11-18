namespace Mac2WinReceiver.Core;

/// <summary>
/// Keeps the receiver from ever writing into Windows system locations (SPEC §6.2
/// "Block system directories (Windows, Program Files)"). The check is boundary-aware:
/// the comparison is done on canonical full paths, so <c>C:\Windows2</c> and
/// <c>C:\Windows.old</c> are NOT blocked while <c>C:\Windows</c> and everything below it
/// are. Called from <c>ReceiverServer.StartAsync</c> before any directory is created.
/// </summary>
public static class DestinationGuard
{
    /// <summary>The real system directories protected by default.</summary>
    public static IReadOnlyList<string> SystemRoots()
    {
        var roots = new List<string>(4);
        foreach (var folder in new[]
                 {
                     Environment.SpecialFolder.Windows,
                     Environment.SpecialFolder.ProgramFiles,
                     Environment.SpecialFolder.ProgramFilesX86,
                     Environment.SpecialFolder.CommonApplicationData,
                 })
        {
            var path = Environment.GetFolderPath(folder);
            if (!string.IsNullOrWhiteSpace(path))
                roots.Add(path);
        }
        return roots;
    }

    /// <summary>
    /// Throws <see cref="InvalidOperationException"/> when <paramref name="destinationRoot"/>
    /// is (or resolves into) one of <paramref name="protectedRoots"/>; otherwise returns.
    /// Null <paramref name="protectedRoots"/> ⇒ <see cref="SystemRoots"/>. Purely lexical
    /// (<see cref="Path.GetFullPath"/> only) — it never touches the filesystem, so tests
    /// can use synthetic roots that do not exist.
    /// </summary>
    public static void EnsureAllowed(string destinationRoot, IReadOnlyList<string>? protectedRoots = null)
    {
        if (string.IsNullOrWhiteSpace(destinationRoot))
            throw new InvalidOperationException("destination root is empty");

        string full;
        try
        {
            full = Normalize(destinationRoot);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new InvalidOperationException($"destination root is not a valid path: {destinationRoot}", ex);
        }

        foreach (var candidate in protectedRoots ?? SystemRoots())
        {
            if (string.IsNullOrWhiteSpace(candidate)) continue;
            string protectedRoot;
            try { protectedRoot = Normalize(candidate); }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
            {
                throw new InvalidOperationException($"protected root is not a valid path: {candidate}", ex);
            }

            if (string.Equals(full, protectedRoot, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException(
                    $"destination {destinationRoot} is the protected system directory {protectedRoot}");

            // boundary-aware prefix: protected root + separator, so C:\Windows2 passes
            if (full.StartsWith(protectedRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException(
                    $"destination {destinationRoot} is inside the protected system directory {protectedRoot}");
        }
    }

    private static string Normalize(string path)
    {
        var full = Path.GetFullPath(path);
        // keep drive roots ("C:\") intact but trim separators elsewhere for prefix math
        if (full.Length > 1 && full.EndsWith(Path.DirectorySeparatorChar))
            full = full.TrimEnd(Path.DirectorySeparatorChar);
        if (full.Length == 2 && full[1] == ':') // "C:" ⇒ "C:\"
            full += Path.DirectorySeparatorChar;
        return full;
    }
}
