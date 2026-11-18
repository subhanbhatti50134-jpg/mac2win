using Mac2WinReceiver.Core;
using Mac2WinReceiver.Core.Server;
using Xunit;

namespace Mac2WinReceiver.Core.Tests.Unit;

/// <summary>
/// DestinationGuard unit tests (SPEC §6.2 "Block system directories (Windows,
/// Program Files)"). Synthetic roots are injected so the policy is verifiable without
/// touching real system directories; the guard is purely lexical (Path.GetFullPath
/// only, no filesystem access), so the synthetic paths need not exist.
/// </summary>
public sealed class DestinationGuardTests
{
    // one rooted path per platform so Path.GetFullPath semantics are exercised natively
    private static readonly string SysRoot =
        Path.DirectorySeparatorChar == '\\' ? @"C:\m2w-sysroot" : "/m2w-sysroot";

    private static readonly string[] Roots = { SysRoot };

    private static string InsideSysRoot =>
        Path.Combine(SysRoot, "Users", "alice", "Downloads");

    [Fact]
    public void Destination_InsideProtectedRoot_IsRejected()
    {
        var ex = Assert.Throws<InvalidOperationException>(
            () => DestinationGuard.EnsureAllowed(InsideSysRoot, Roots));
        Assert.Contains("protected", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Destination_EqualToProtectedRoot_IsRejected()
    {
        var ex = Assert.Throws<InvalidOperationException>(
            () => DestinationGuard.EnsureAllowed(SysRoot, Roots));
        Assert.Contains("protected", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void BoundaryIsRespected_SiblingPrefixPasses()
    {
        // "C:\m2w-sysroot2" and "C:\m2w-sysroot.old" share a string prefix with the
        // protected root but are NOT inside it — a naive StartsWith check would false-positive
        var sibling1 = SysRoot + "2";
        var sibling2 = SysRoot + ".old";
        DestinationGuard.EnsureAllowed(sibling1, Roots); // must not throw
        DestinationGuard.EnsureAllowed(sibling2, Roots); // must not throw
    }

    [Fact]
    public void SiblingWithSeparatorSuffix_IsNotMistakenForInside()
    {
        // root + "2" + separator + leaf resolves INSIDE the sibling m2w-sysroot2,
        // not inside m2w-sysroot — the guard must allow it (boundary-aware prefix)
        var insideSibling = SysRoot + "2" + Path.DirectorySeparatorChar + "data";
        DestinationGuard.EnsureAllowed(insideSibling, Roots); // must not throw

        // while a real child of the protected root is rejected
        var insideRoot = SysRoot + Path.DirectorySeparatorChar + "data";
        var ex = Assert.Throws<InvalidOperationException>(
            () => DestinationGuard.EnsureAllowed(insideRoot, Roots));
        Assert.Contains("protected", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TrailingAndForwardSlashes_AreNormalizedBeforeComparison()
    {
        var withTrailing = SysRoot + Path.DirectorySeparatorChar;
        var withForward = SysRoot.Replace(Path.DirectorySeparatorChar, '/');
        var mixed = withForward + "/Users/bob";

        var exTrailing = Assert.Throws<InvalidOperationException>(
            () => DestinationGuard.EnsureAllowed(withTrailing, Roots));
        Assert.Contains("protected", exTrailing.Message, StringComparison.OrdinalIgnoreCase);

        var exMixed = Assert.Throws<InvalidOperationException>(
            () => DestinationGuard.EnsureAllowed(mixed, Roots));
        Assert.Contains("protected", exMixed.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void NormalDestination_IsAllowed()
    {
        var elsewhere = Path.Combine(Path.GetTempPath(), "m2w-allowed-dest");
        DestinationGuard.EnsureAllowed(elsewhere, Roots); // must not throw
        DestinationGuard.EnsureAllowed(elsewhere + Path.DirectorySeparatorChar, Roots);
    }

    [Fact]
    public void EmptyOrWhitespaceDestination_IsRejected()
    {
        Assert.Throws<InvalidOperationException>(() => DestinationGuard.EnsureAllowed("", Roots));
        Assert.Throws<InvalidOperationException>(() => DestinationGuard.EnsureAllowed("   ", Roots));
    }

    [Fact]
    public void MultipleProtectedRoots_AllEnforced()
    {
        var roots = new[] { SysRoot, SysRoot + "-programfiles" };
        Assert.Throws<InvalidOperationException>(
            () => DestinationGuard.EnsureAllowed(SysRoot + "-programfiles" + Path.DirectorySeparatorChar + "x", roots));
    }

    [Fact]
    public void CaseInsensitiveComparison()
    {
        if (!OperatingSystem.IsWindows())
            return; // case folding of paths is a Windows property; skip elsewhere

        var differentCase = SysRoot.ToUpperInvariant();
        Assert.Throws<InvalidOperationException>(
            () => DestinationGuard.EnsureAllowed(differentCase, Roots));
    }

    [Fact]
    public void SystemRoots_ContainRealWindowsFolders_WhenOnWindows()
    {
        if (!OperatingSystem.IsWindows())
            return; // SpecialFolder.Windows is empty on other platforms

        var roots = DestinationGuard.SystemRoots();
        Assert.NotEmpty(roots);
        Assert.All(roots, r => Assert.True(Path.IsPathRooted(r)));

        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        Assert.Contains(windows, roots, StringComparer.OrdinalIgnoreCase);

        // the real Windows folder must be blocked with the default (null) root list
        Assert.Throws<InvalidOperationException>(
            () => DestinationGuard.EnsureAllowed(Path.Combine(windows, "System32"), null));
        // but a sibling like C:\Windows.old must not be
        var sibling = windows + ".old";
        DestinationGuard.EnsureAllowed(sibling, null);
    }

    [Fact]
    public async Task StartAsync_RejectsProtectedDestination()
    {
        // synthetic protected root + a destination that resolves inside it
        var baseDir = Path.Combine(Path.GetTempPath(),
            "m2w-sysroot-" + Guid.NewGuid().ToString("N"));
        var protectedRoot = Path.Combine(baseDir, "Windows");
        var destination = Path.Combine(protectedRoot, "System32", "mac2win");

        var options = new ReceiverOptions
        {
            DestinationRoot = destination,
            Port = 0,
            DeviceName = "GUARD-TEST",
            FixedTestPin = "123456",
            ProtectedDestinationRoots = new[] { protectedRoot },
        };

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => ReceiverServer.StartAsync(options));
        Assert.Contains("protected", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.False(Directory.Exists(destination), "guard must run before any mkdir");
    }
}
